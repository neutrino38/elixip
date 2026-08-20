defmodule Kelix.Mod.AuthDb do
  @moduledoc """
  Digest authentication backed by a MariaDB/MySQL `subscriber` table
  (design §7.4, §12.3). It **decides**, it never composes a SIP response
  (§11.1): the verdict is what the script maps onto a 401, a 407 or a 403.

  The secret is stored as **HA1** (`H(user:realm:password)`); the hash `H` is
  `password_hash = "md5" | "sha256"` (default `md5`). The realm is the domain's
  nominal name.

  Facades:

    * `authenticate/3`         — verdict for **any** request, with the identity it
      proved; the general form;
    * `do_registration_auth/3` — `authenticate/3` for a REGISTER, answering the bare
      `:ok` the registrar scripts match on;
    * `challengeable?/1`       — is this request one to authenticate at all;
    * `fetch_credential/3`     — the secret, and the one function a different backend
      would rewrite (see docs/design/evolution-auth-db.md);
    * `lookup_ha1/2`, `challenge_algorithm/0`.

  The DB connection is the module's supervised service (`child_spec/2`); the
  verdict logic is pure apart from the credential lookup, which is injectable for
  tests (`:ha1_lookup`).

  The link itself — a permanent pool, opened over **TLS first** and only falling
  back to cleartext when `allow_insecure_db_connection` says so — belongs to
  `Kelix.Mod.AuthDb.Pool`, which is also what `kelictl auth_db show` reports.
  """
  @behaviour Kelix.Module
  require Logger

  alias Kelix.Mod.AuthDb.Pool

  @doc """
  Take this module's verbs into a scenario: the alias, and the service building
  blocks it publishes (`Kelix.Mod.AuthDb.SBB`).

      use Kelix.Mod.AuthDb

      state authenticate_caller do
        AuthDb.SBB.authenticate()
        ...
      end

  The alias is on the **module**, not on `SBB`: two modules publishing blocks
  would both want the bare `SBB`, and the second `use` would win — a script using
  `registrar` and `auth_db` together is the ordinary case, not a corner one. The
  prefix a reader wants is which module provides the verb anyway.

  This does not replace `config(uses_modules: [:auth_db])`, which checks a
  different thing: the `use` says the **code** is installed (it does not compile
  otherwise), the declaration says a **configured instance** exists. A `.beam` in
  `module_dir` with no `[module.auth_db]` block passes the first and fails the
  second, which is exactly the case the preflight is there to catch.
  """
  defmacro __using__(_opts) do
    # Teach the scenario that `:auth` is a block namespace, so `on_events`
    # classifies the block's returns as scenario events even in a state written
    # before the call site — see docs/design/DESIGN-SBB.md#21-the-shape-of-a-return.
    SIP.Scenario.register_namespace(__CALLER__.module, :auth)

    quote do
      alias Kelix.Mod.AuthDb
      require Kelix.Mod.AuthDb.SBB
    end
  end

  @typedoc """
  The secret an authentication needs, as the backend holds it.

  A tagged tuple rather than a bare HA1 string, because the shape is what will
  differ the day a second backend lands: a Diameter Cx `MAA` answers with the H(A1)
  under `Digest-MD5` (this shape) but with a RAND/AUTN/XRES vector under AKA (a
  different one). Naming the shape now is what keeps `fetch_credential/2` a
  contract rather than a MariaDB detail.
  """
  @type credential :: {:ha1, algorithm :: String.t(), hex :: String.t()}

  @typedoc "Who the digest proved the sender to be. `user` is the subscriber key, not the claim."
  @type identity :: %{user: String.t(), realm: String.t()}

  @type verdict :: :ok | {:requireauth, boolean} | {:reject, integer, String.t()}
  @type auth_verdict ::
          {:ok, identity} | {:requireauth, boolean} | {:reject, integer, String.t()}

  # `password_hash` → { spelling advertised in the challenge, token SIP.Auth
  # computes with }. The stored HA1 was salted with exactly one hash, so THAT is
  # the algorithm — not whatever the client puts in its Authorization header.
  # SIP clients spell it the RFC 8760 way (`SHA-256`); `SIP.Auth` wants `SHA256`.
  #
  # Anything outside this table must be refused *before* reaching
  # `SIP.Auth.algo2atom/1`, which raises — and an exception in a facade kills the
  # scenario instance, leaving the REGISTER unanswered (§8.2).
  @hash_algorithms %{"md5" => {"MD5", "MD5"}, "sha256" => {"SHA-256", "SHA256"}}

  # Every key a [module.auth_db] block may carry. `module` is the generic
  # module-resolution key handled by Kelix.ModuleSupervisor.
  @config_keys ~w(module host port database username password table ha1_column
                  user_column domain_column password_hash identity_check
                  call_timeout_ms pool_size connect_timeout_ms ssl ssl_ca_cert_file
                  allow_insecure_db_connection)

  # What to do when the digest proves one identity and the request claims another
  # (see check_identity/3). `warn` is the default on purpose: `strict` is the safe
  # answer but it refuses deployments that are legitimate — a trunk account
  # asserting many From identities, a subscriber registering an AOR that is not its
  # username — and turning those into 403s on upgrade would be an ambush. Run in
  # `warn`, read the logs, then decide.
  @identity_checks ~w(strict warn off)
  @default_identity_check "warn"

  # ── Kelix.Module behaviour ───────────────────────────────────────────────────

  @doc """
  Supervised child spec: the connection pool to the subscriber DB, opened by
  `Kelix.Mod.AuthDb.Pool` (which negotiates the transport — TLS first).
  `child_spec/2` also stashes the facade config (table/columns/hash) into app env,
  so the stateless facades resolve it without the pid.
  """
  @impl Kelix.Module
  def child_spec(_name, config) do
    configure(config)

    %{id: __MODULE__, start: {Pool, :start_link, [config]}}
  end

  @impl Kelix.Module
  def validate_config(config) when is_map(config) do
    with :ok <- reject_unknown_keys(config),
         {:ok, _} <- req_string(config, "database"),
         {:ok, _} <- req_string(config, "username"),
         :ok <- hash_ok(config),
         :ok <- identity_check_ok(config),
         :ok <- identifiers_ok(config),
         :ok <- bool_ok(config, "ssl"),
         :ok <- bool_ok(config, "allow_insecure_db_connection"),
         :ok <- cleartext_confirmed(config),
         :ok <- pos_int_ok(config, "port"),
         :ok <- pos_int_ok(config, "call_timeout_ms"),
         :ok <- pos_int_ok(config, "pool_size"),
         :ok <- pos_int_ok(config, "connect_timeout_ms") do
      :ok
    end
  end

  def validate_config(_), do: {:error, "block must be a table"}

  @impl Kelix.Module
  def describe(),
    do: %{
      version: "1.2",
      exports: [
        authenticate: 3,
        challengeable?: 1,
        challenge_algorithm: 0,
        do_registration_auth: 3,
        fetch_credential: 2,
        lookup_ha1: 2
      ]
    }

  # ── control surface (§8.1, §10) ──────────────────────────────────────────────

  @impl Kelix.Module
  def describe_control() do
    [
      %{
        name: "show",
        rest: {:get, "/db"},
        rw: :r,
        args: [],
        render: %{
          kind: :detail,
          fields: ~w(state host port database username table tls certificate transport
                     pool_size query_timeout_ms error)
        },
        help: "The subscriber-DB link: does it answer, where does it point, is it encrypted"
      }
    ]
  end

  @doc """
  Run a declared control command.

  `show` never fails on a base that is down — "down, and here is why" is its
  answer, not its error. What it does refuse is an argument: it takes none, and
  silently ignoring one would let `kelictl auth_db show verbose` read as a
  different view.
  """
  @impl Kelix.Module
  def handle_control("show", args) when is_map(args) do
    case extra_args(args) do
      [] -> {:ok, Pool.describe()}
      extra -> {:error, "show takes no argument, got: #{Enum.join(extra, ", ")}"}
    end
  end

  def handle_control(command, _args), do: {:error, {:unknown_command, command}}

  # `kelictl` hands the leftover tokens under "args"; REST merges the path, query
  # and body keys at the top level. A command with no argument reduces both shapes
  # to the same question: is there anything here we did not ask for?
  defp extra_args(args) do
    tokens = args |> Map.get("args", []) |> List.wrap() |> Enum.map(&to_string/1)
    tokens ++ (Map.keys(args) -- ["args"])
  end

  defp req_string(config, key) do
    case Map.get(config, key) do
      v when is_binary(v) and v != "" -> {:ok, v}
      _ -> {:error, "#{key} is required (non-empty string)"}
    end
  end

  defp hash_ok(config) do
    case Map.get(config, "password_hash") do
      nil -> :ok
      h when is_map_key(@hash_algorithms, h) -> :ok
      _ -> {:error, "password_hash must be one of #{Enum.join(Map.keys(@hash_algorithms), "|")}"}
    end
  end

  defp identity_check_ok(config) do
    case Map.get(config, "identity_check") do
      nil -> :ok
      v when v in @identity_checks -> :ok
      _ -> {:error, "identity_check must be one of #{Enum.join(@identity_checks, "|")}"}
    end
  end

  defp bool_ok(config, key) do
    case Map.get(config, key) do
      nil -> :ok
      v when is_boolean(v) -> :ok
      _ -> {:error, "#{key} must be a boolean"}
    end
  end

  # `allow_insecure_db_connection` is the ONE gate to a cleartext link, so `ssl =
  # false` — which asks for exactly that, directly — goes through it too. Two
  # independent ways to end up unencrypted would make the key mean nothing, and
  # `kelictl auth_db show` could no longer be read as "cleartext ⇒ somebody
  # confirmed it".
  defp cleartext_confirmed(config) do
    if Map.get(config, "ssl") == false and not Pool.insecure_allowed?(config) do
      {:error,
       "ssl = false asks for a CLEARTEXT link to the subscriber DB: confirm it with " <>
         "allow_insecure_db_connection = true, or drop the key to let TLS be negotiated"}
    else
      :ok
    end
  end

  defp pos_int_ok(config, key) do
    case Map.get(config, key) do
      nil -> :ok
      v when is_integer(v) and v > 0 -> :ok
      _ -> {:error, "#{key} must be a positive integer"}
    end
  end

  # Fail fast on a typo. Without this, `ha1_colum = "ha1b"` is silently ignored,
  # the lookup falls back to the default column and every REGISTER gets a 403 that
  # nothing in the logs explains.
  defp reject_unknown_keys(config) do
    case Map.keys(config) -- @config_keys do
      [] -> :ok
      extra -> {:error, "unknown key(s): #{Enum.join(Enum.sort(extra), ", ")}"}
    end
  end

  # Table/column names are interpolated into the SQL (they cannot be bound as
  # parameters). The config file is root-owned, so this is defence in depth rather
  # than an injection fix — but it costs nothing and turns a corrupted config into
  # a boot error instead of a syntax error on every query.
  @identifier ~r/\A[A-Za-z0-9_]+\z/
  @identifier_keys ~w(table ha1_column user_column domain_column)

  defp identifiers_ok(config) do
    Enum.reduce_while(@identifier_keys, :ok, fn key, :ok ->
      case Map.get(config, key) do
        nil ->
          {:cont, :ok}

        v when is_binary(v) ->
          if Regex.match?(@identifier, v),
            do: {:cont, :ok},
            else: {:halt, {:error, "#{key} must be a plain SQL identifier, got #{inspect(v)}"}}

        _ ->
          {:halt, {:error, "#{key} must be a string"}}
      end
    end)
  end

  # config the facades need (table / columns / hash / timeout), kept in app env
  # under the module name so lookup_ha1/do_registration_auth read it without the pid.
  defp auth_cfg(config) do
    %{
      table: config["table"] || "subscriber",
      ha1_column: config["ha1_column"] || "ha1",
      user_column: config["user_column"] || "username",
      domain_column: config["domain_column"] || "domain",
      password_hash: config["password_hash"] || "md5",
      identity_check: config["identity_check"] || @default_identity_check,
      call_timeout_ms: config["call_timeout_ms"] || Kelix.Module.default_call_timeout_ms()
    }
  end

  @doc "Store the facade config in app env (also done by `child_spec/2`)."
  def configure(config), do: Application.put_env(:kelixip, __MODULE__, auth_cfg(config))

  @default_cfg %{
    ha1_column: "ha1",
    table: "subscriber",
    user_column: "username",
    domain_column: "domain",
    password_hash: "md5",
    identity_check: @default_identity_check
  }

  # Anything but a map (unset, or explicitly set to nil) means "not configured".
  defp cfg() do
    case Application.get_env(:kelixip, __MODULE__) do
      %{} = cfg -> cfg
      _ -> Map.put(@default_cfg, :call_timeout_ms, Kelix.Module.default_call_timeout_ms())
    end
  end

  @doc """
  The digest algorithm this backend accepts, in the spelling to advertise in the
  `WWW-Authenticate` challenge (`MD5` / `SHA-256`).

  It follows `password_hash`, because the stored HA1 was salted with that hash
  and no other: the script asks for it so the challenge names the algorithm the
  base can actually verify (§11.1 — the module decides, the script composes).
  """
  @spec challenge_algorithm() :: String.t()
  def challenge_algorithm() do
    {advertised, _compute} = hash_algorithm(cfg())
    advertised
  end

  defp hash_algorithm(cfg) do
    Map.get(@hash_algorithms, Map.get(cfg, :password_hash) || "md5") ||
      Map.fetch!(@hash_algorithms, "md5")
  end

  # A client's `algorithm` param → the canonical token, tolerating both spellings
  # and any case. nil when we cannot compute it at all.
  defp canonical_algorithm(algorithm) do
    case String.upcase(algorithm) do
      "MD5" -> "MD5"
      "SHA-256" -> "SHA256"
      "SHA256" -> "SHA256"
      _ -> nil
    end
  end

  # ── facades ──────────────────────────────────────────────────────────────────

  @doc "HA1 for `username`@`realm` from the subscriber table. `{:ok, ha1}` / `:notfound` / `{:error, r}`."
  @spec lookup_ha1(String.t(), String.t()) :: {:ok, String.t()} | :notfound | {:error, term}
  def lookup_ha1(username, realm) do
    c = cfg()
    conn = Pool.conn()

    # non-blocking guarantee (§8.2): a down pool yields {:error, :down}, a slow
    # query is bounded by call_timeout_ms — the facade never hangs the instance.
    if Process.whereis(conn) == nil do
      {:error, :down}
    else
      sql =
        "SELECT #{c.ha1_column} FROM #{c.table} WHERE #{c.user_column} = ? AND #{c.domain_column} = ? LIMIT 1"

      timeout = Map.get(c, :call_timeout_ms, Kelix.Module.default_call_timeout_ms())

      case MyXQL.query(conn, sql, [username, realm], timeout: timeout) do
        {:ok, %MyXQL.Result{rows: [[ha1]]}} -> {:ok, ha1}
        {:ok, %MyXQL.Result{rows: []}} -> :notfound
        {:error, reason} -> {:error, reason}
      end
    end
  rescue
    e -> {:error, e}
  end

  @doc """
  The secret for `username`@`realm`, in the shape the authentication needs.

  The **abstraction point of the backend**: everything above it — nonce, digest,
  identity — is method- and storage-agnostic, and a second backend (LDAP, an HTTP
  endpoint, Diameter Cx under `Digest-MD5`) is this one function rewritten. What is
  *not* here is deliberate: the algorithm is the backend's, not the client's, since
  the stored secret was salted with one hash and no other.

  `{:ok, credential}` / `:notfound` / `{:error, reason}`.
  """
  @spec fetch_credential(String.t() | nil, String.t(), keyword) ::
          {:ok, credential} | :notfound | {:error, term}
  def fetch_credential(username, realm, opts \\ []) do
    {_advertised, algorithm} = hash_algorithm(cfg())

    case lookup(username, realm, opts) do
      {:ok, ha1} -> {:ok, {:ha1, algorithm, normalize_hex(ha1)}}
      other -> other
    end
  end

  # ACK has no response to carry a challenge (RFC 3261 §17.1.1.3); CANCEL must be
  # accepted for the transaction it cancels (§22.1); OPTIONS is what liveness
  # probing uses, and challenging it makes this node look down to its own
  # infrastructure (see Kelix.Options).
  @never_challenged [:ACK, :CANCEL, :OPTIONS]

  @doc """
  Should this request be authenticated at all?

  The rule is **"an initial request, other than ACK, CANCEL and OPTIONS"** — not
  "creates a dialog", which would need a per-method list to maintain and would miss
  MESSAGE / PUBLISH. An in-dialog request is excluded because the dialog was
  authenticated when it was created: re-challenging mid-call breaks UAs and proves
  nothing new.
  """
  @spec challengeable?(map) :: boolean
  def challengeable?(req) when is_map(req) do
    Map.get(req, :method) not in @never_challenged and not SIP.Msg.Ops.in_dialog?(req)
  end

  @doc """
  Authentication verdict for **any** request against `realm`. Never builds a SIP
  message (§11.1) — the script composes the 401 or the 407 from the verdict.

    * `{:ok, identity}` — the digest checks out; `identity.user` is the subscriber
      it proved, which a script can bill or log;
    * `{:requireauth, stale?}` — challenge (`stale = true` ⇒ old or replayed nonce,
      so the client replays transparently);
    * `{:reject, code, reason}` — 403 (bad password / unknown user / wrong realm),
      500 (the backend could not answer).

  `realm` is the realm to **require**, and it is the caller's decision because the
  two differ by method: a REGISTER authenticates the holder of the AOR in `To`, an
  INVITE authenticates the *caller*, whose realm is the domain of its `From` — which
  is not necessarily the domain that routed the request. A script serving one domain
  passes `sip_ctx.domain` and is right in both cases.

  `opts`:

    * `:identity_check` — `:strict | :warn | :off`, overriding `[module.auth_db]
      identity_check` (default `warn`). See below.
    * `:identity` — which claim to compare against: `:auto` (default — `To` for a
      REGISTER, `From` otherwise), `:to`, `:from`, or `:none`.
    * `:ha1_lookup` — `fn user, realm -> {:ok, ha1} | :notfound | {:error, r}`, for
      tests; `:now` / `:max_age` / `:secret` are forwarded to `SIP.Auth.Nonce`.

  **On the identity check.** A valid digest proves who holds the password — it does
  **not** prove the `From` is theirs. Without this check Alice authenticates with her
  own credentials and places a call as `From: Bob`: identity spoofing, and in a
  metered deployment, fraud. It is the rule SIP servers most often omit, which is
  why it is here rather than left to each script.
  """
  @spec authenticate(map, String.t(), keyword) :: auth_verdict
  def authenticate(req, realm, opts \\ []) do
    case auth_header(req) do
      nil ->
        {:requireauth, false}

      auth when is_map(auth) ->
        if auth["realm"] == realm do
          verify(req, realm, auth, opts)
        else
          # Not "the password is wrong" but "this credential was minted for someone
          # else's server" — a probe, or a misprovisioned phone. Logged as such: the
          # two have opposite fixes and the same 403 on the wire.
          reject(
            req,
            :bad_realm,
            "credential minted for realm #{inspect(auth["realm"])}, not #{realm}"
          )
        end
    end
  rescue
    # A verdict is the contract (§8.2): whatever goes wrong below — a malformed
    # auth param, a driver blowing up — this must not raise. An exception here
    # would kill the scenario instance and the request would go UNANSWERED,
    # which is strictly worse for the client than any error response.
    e ->
      Logger.error(module: __MODULE__, message: "auth crashed: #{Exception.message(e)}")

      {:reject, 500, "Server Internal Error"}
  end

  @doc """
  Authentication verdict for a REGISTER — `authenticate/3` with the registrar's
  reading of who is being authenticated (`To`), answering the bare `:ok` the
  registrar scripts match on.
  """
  @spec do_registration_auth(map, String.t(), keyword) :: verdict
  def do_registration_auth(req, domain, opts \\ []) do
    case authenticate(req, domain, Keyword.put_new(opts, :identity, :to)) do
      {:ok, _identity} -> :ok
      other -> other
    end
  end

  defp verify(req, domain, auth, opts) do
    {_advertised, expected_algorithm} = hash_algorithm(cfg())

    if canonical_algorithm(algorithm(auth)) == expected_algorithm do
      case SIP.Auth.Nonce.validate(auth["nonce"] || "", domain, nonce_opts(opts)) do
        :invalid -> {:requireauth, false}
        :stale -> {:requireauth, true}
        :ok -> check_credentials(req, domain, auth, expected_algorithm, opts)
      end
    else
      # The stored HA1 only verifies under `password_hash`; trying to honour the
      # client's choice would either fail obscurely or reach the raising
      # algo2atom/1. Re-challenge instead — our challenge names the algorithm we
      # want, so a sane client comes back with it. Never a raise, never silence.
      Logger.info(
        module: __MODULE__,
        message:
          "digest algorithm #{inspect(algorithm(auth))} does not match the stored " <>
            "#{expected_algorithm} hash; re-challenging"
      )

      {:requireauth, false}
    end
  end

  defp check_credentials(req, domain, auth, _algorithm, opts) do
    user = subscriber_of(auth["username"])

    with :ok <- check_nc(auth),
         # The algorithm comes back WITH the credential: it is a property of the
         # stored secret, not of the request. `verify/4` has already refused a
         # client asking for another one.
         {:ok, {:ha1, algorithm, ha1}} <- fetch_credential(user, domain, opts),
         expected =
           SIP.Auth.expected_response_from_ha1(algorithm, ha1, req_method(req), auth),
         true <- secure_equal?(normalize_hex(expected), normalize_hex(auth["response"])) do
      check_identity(req, %{user: user, realm: domain}, opts)
    else
      :replay ->
        {:requireauth, true}

      # Told apart in the log and NOT on the wire: both answer 403, so nothing
      # leaks whether the account exists, while an operator (and, later, a
      # fail2ban jail) can treat 5 wrong passwords and 5 unknown users very
      # differently — nobody mistypes a username five times.
      :notfound ->
        reject(req, :unknown_user, "no subscriber #{inspect(user)}@#{domain}")

      false ->
        reject(req, :bad_password, "digest mismatch for #{inspect(user)}@#{domain}")

      {:error, reason} ->
        Logger.error(module: __MODULE__, message: "credential lookup failed: #{inspect(reason)}")
        {:reject, 500, "Server Internal Error"}
    end
  end

  # The digest proved `identity.user`. Does the request claim to be someone else?
  defp check_identity(req, identity, opts) do
    mode = Keyword.get(opts, :identity_check, configured_identity_check())

    case {mode, claimed_identity(req, opts)} do
      {:off, _} ->
        {:ok, identity}

      # Nothing to compare with (no From/To user part): not a mismatch.
      {_mode, nil} ->
        {:ok, identity}

      {mode, claimed} ->
        if String.downcase(claimed) == String.downcase(identity.user) do
          {:ok, identity}
        else
          Logger.warning(
            module: __MODULE__,
            message:
              "#{req_method(req)} authenticated as #{inspect(identity.user)} but asserts " <>
                "#{inspect(claimed)} (identity_check: #{mode})"
          )

          if mode == :strict,
            do: {:reject, 403, "Forbidden"},
            else: {:ok, identity}
        end
    end
  end

  # Which claim to hold the authenticated user against. A REGISTER binds the AOR in
  # To; everything else asserts its sender in From. Read through SIP.Msg.Ops, the
  # stack's single reading of both (CLAUDE.md, Message Layer) — `:to` in particular
  # arrives as a RAW header string on a parsed message, not as a %SIP.Uri{}.
  defp claimed_identity(req, opts) do
    case Keyword.get(opts, :identity, :auto) do
      :none -> nil
      :to -> SIP.Msg.Ops.to_username(req)
      :from -> SIP.Msg.Ops.from_username(req)
      :auto -> claimed_identity(req, identity: default_claim(req))
    end
  end

  defp default_claim(req), do: if(req_method(req) == :REGISTER, do: :to, else: :from)

  defp configured_identity_check() do
    case Map.get(cfg(), :identity_check) do
      "strict" -> :strict
      "off" -> :off
      _ -> :warn
    end
  end

  # One 403 on the wire, one named cause in the log. The cause is what tells a
  # misprovisioned phone from a scanner, and it exists nowhere else: until now a
  # refused REGISTER produced no log line at all.
  defp reject(req, cause, detail) do
    Logger.warning(
      module: __MODULE__,
      message: "#{req_method(req)} refused (#{cause}): #{detail}"
    )

    {:reject, 403, "Forbidden"}
  end

  # ── internals ────────────────────────────────────────────────────────────────

  defp auth_header(req), do: Map.get(req, :authorization) || Map.get(req, :proxyauthorization)

  defp algorithm(auth) do
    case auth["algorithm"] do
      a when is_binary(a) and a != "" -> String.upcase(a)
      _ -> "MD5"
    end
  end

  @doc """
  The subscriber-table key for a digest username.

  Two credential conventions coexist in the wild, and the difference is *only* in
  how HA1 was salted — the table row is keyed on the bare user in both:

    * `ha1`  = `H(user:realm:password)`          — the client authenticates as `user`
    * `ha1b` = `H(user@domain:realm:password)`   — the client authenticates as `user@domain`

  So the `@domain` part, when present, is stripped for the **row lookup** while the
  HA1 compared stays whatever `ha1_column` holds — which is what makes an `ha1b`
  deployment work at all. Not stripping it meant an `ha1b` base could never
  authenticate anyone: the only username form it is valid for is the one the
  lookup could not resolve.

  The domain part is deliberately not checked against the realm: it may legally be
  an alias of the served domain. A mismatch simply fails the HA1 comparison, since
  the client hashed a different A1.
  """
  @spec subscriber_of(String.t() | nil) :: String.t() | nil
  def subscriber_of(username) when is_binary(username) do
    case String.split(username, "@", parts: 2) do
      [user, _domain] -> user
      [user] -> user
    end
  end

  def subscriber_of(other), do: other

  # Digest responses are hex; RFC 7616 lets an implementation emit either case and
  # a provisioning tool may well have stored an upper-case HA1.
  defp normalize_hex(v) when is_binary(v), do: String.downcase(v)
  defp normalize_hex(_), do: ""

  defp req_method(req), do: Map.get(req, :method, :REGISTER)

  # HA1 source: explicit opt, else an app-env override (tests), else the DB.
  defp lookup(username, realm, opts) do
    fun = Keyword.get(opts, :ha1_lookup) || Application.get_env(:kelixip, :authdb_ha1_lookup)

    case fun do
      f when is_function(f, 2) -> f.(username, realm)
      _ -> lookup_ha1(username, realm)
    end
  end

  # anti-replay: only meaningful with qop; parse the hex nc and check the cache
  defp check_nc(%{"qop" => qop, "nonce" => nonce, "nc" => nc})
       when is_binary(qop) and qop != "" do
    case Integer.parse(nc || "", 16) do
      {n, _} ->
        if Process.whereis(Kelix.NonceCache), do: Kelix.NonceCache.check_nc(nonce, n), else: :ok

      :error ->
        :ok
    end
  end

  defp check_nc(_auth), do: :ok

  defp nonce_opts(opts) do
    Keyword.take(opts, [:now, :max_age, :secret])
  end

  defp secure_equal?(a, b) when is_binary(a) and is_binary(b) and byte_size(a) == byte_size(b),
    do: :crypto.hash_equals(a, b)

  defp secure_equal?(_, _), do: false
end
