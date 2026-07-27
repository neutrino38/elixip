defmodule Kelix.Mod.AuthDb do
  @moduledoc """
  Registrar authentication backed by a MariaDB/MySQL `subscriber` table
  (design §7.4, §12.3). It **decides**, it never composes a SIP response
  (§11.1): `do_registration_auth/3` returns a verdict the registrar script maps
  onto the `SIP.Session.Registrar.*` helpers.

  The secret is stored as **HA1** (`H(user:realm:password)`); the hash `H` is
  `password_hash = "md5" | "sha256"` (default `md5`). The realm is the domain's
  nominal name.

  Facades (imported by the script): `do_registration_auth/3`, `lookup_ha1/2`.
  The DB connection is the module's supervised service (`child_spec/2`); the
  verdict logic is pure apart from the HA1 lookup, which is injectable for tests
  (`:ha1_lookup`).
  """
  @behaviour Kelix.Module
  require Logger

  @conn __MODULE__.Conn

  @type verdict :: :ok | {:requireauth, boolean} | {:reject, integer, String.t()}

  @valid_hashes ~w(md5 sha256)

  # Digest algorithms `SIP.Auth` can actually compute. Anything else — including
  # the RFC 8760 spellings (`SHA-256`, `SHA-512-256`) — must be refused *here*:
  # `SIP.Auth.algo2atom/1` raises on an unknown one, and an exception in a facade
  # kills the scenario instance and leaves the REGISTER unanswered (§8.2).
  @supported_algorithms ~w(MD5 SHA1 SHA256)

  # Every key a [module.auth_db] block may carry. `module` is the generic
  # module-resolution key handled by Kelix.ModuleSupervisor.
  @config_keys ~w(module host port database username password table ha1_column
                  user_column domain_column password_hash call_timeout_ms)

  # ── Kelix.Module behaviour ───────────────────────────────────────────────────

  @doc """
  Supervised child spec: a MyXQL connection to the subscriber DB. `child_spec/2`
  also stashes the facade config (table/columns/hash) into app env, so the
  stateless facades resolve it without the pid.
  """
  @impl Kelix.Module
  def child_spec(_name, config) do
    configure(config)

    myxql_opts =
      [
        name: @conn,
        hostname: config["host"] || "127.0.0.1",
        port: config["port"] || 3306,
        database: config["database"],
        username: config["username"],
        password: config["password"]
      ]

    %{id: __MODULE__, start: {MyXQL, :start_link, [myxql_opts]}}
  end

  @impl Kelix.Module
  def validate_config(config) when is_map(config) do
    with :ok <- reject_unknown_keys(config),
         {:ok, _} <- req_string(config, "database"),
         {:ok, _} <- req_string(config, "username"),
         :ok <- hash_ok(config),
         :ok <- identifiers_ok(config),
         :ok <- pos_int_ok(config, "port"),
         :ok <- pos_int_ok(config, "call_timeout_ms") do
      :ok
    end
  end

  def validate_config(_), do: {:error, "block must be a table"}

  @impl Kelix.Module
  def describe(), do: %{version: "1.0", exports: [do_registration_auth: 3, lookup_ha1: 2]}

  defp req_string(config, key) do
    case Map.get(config, key) do
      v when is_binary(v) and v != "" -> {:ok, v}
      _ -> {:error, "#{key} is required (non-empty string)"}
    end
  end

  defp hash_ok(config) do
    case Map.get(config, "password_hash") do
      nil -> :ok
      h when h in @valid_hashes -> :ok
      _ -> {:error, "password_hash must be one of #{Enum.join(@valid_hashes, "|")}"}
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
      call_timeout_ms: config["call_timeout_ms"] || Kelix.Module.default_call_timeout_ms()
    }
  end

  @doc "Store the facade config in app env (also done by `child_spec/2`)."
  def configure(config), do: Application.put_env(:kelixip, __MODULE__, auth_cfg(config))

  defp cfg(),
    do:
      Application.get_env(:kelixip, __MODULE__, %{
        ha1_column: "ha1",
        table: "subscriber",
        user_column: "username",
        domain_column: "domain",
        call_timeout_ms: Kelix.Module.default_call_timeout_ms()
      })

  # ── facades ──────────────────────────────────────────────────────────────────

  @doc "HA1 for `username`@`realm` from the subscriber table. `{:ok, ha1}` / `:notfound` / `{:error, r}`."
  @spec lookup_ha1(String.t(), String.t()) :: {:ok, String.t()} | :notfound | {:error, term}
  def lookup_ha1(username, realm) do
    c = cfg()

    # non-blocking guarantee (§8.2): a down pool yields {:error, :down}, a slow
    # query is bounded by call_timeout_ms — the facade never hangs the instance.
    if Process.whereis(@conn) == nil do
      {:error, :down}
    else
      sql =
        "SELECT #{c.ha1_column} FROM #{c.table} WHERE #{c.user_column} = ? AND #{c.domain_column} = ? LIMIT 1"

      timeout = Map.get(c, :call_timeout_ms, Kelix.Module.default_call_timeout_ms())

      case MyXQL.query(@conn, sql, [username, realm], timeout: timeout) do
        {:ok, %MyXQL.Result{rows: [[ha1]]}} -> {:ok, ha1}
        {:ok, %MyXQL.Result{rows: []}} -> :notfound
        {:error, reason} -> {:error, reason}
      end
    end
  rescue
    e -> {:error, e}
  end

  @doc """
  Authentication verdict for a REGISTER against `domain` (the realm):
  `:ok`, `{:requireauth, stale?}` (challenge; `stale=true` ⇒ old/replayed nonce),
  or `{:reject, code, reason}`. Never builds a SIP message.

  `opts`: `:ha1_lookup` (a `fn user, realm -> {:ok, ha1} | :notfound | {:error, r}`
  for tests), plus `:now` / `:max_age` forwarded to `SIP.Auth.Nonce.validate`.
  """
  @spec do_registration_auth(map, String.t(), keyword) :: verdict
  def do_registration_auth(req, domain, opts \\ []) do
    case auth_header(req) do
      nil ->
        {:requireauth, false}

      auth when is_map(auth) ->
        if auth["realm"] == domain do
          verify(req, domain, auth, opts)
        else
          {:reject, 403, "Forbidden"}
        end
    end
  rescue
    # A verdict is the contract (§8.2): whatever goes wrong below — a malformed
    # auth param, a driver blowing up — this must not raise. An exception here
    # would kill the scenario instance and the REGISTER would go UNANSWERED,
    # which is strictly worse for the client than any error response.
    e ->
      Logger.error(
        module: __MODULE__,
        message: "registration auth crashed: #{Exception.message(e)}"
      )

      {:reject, 500, "Server Internal Error"}
  end

  defp verify(req, domain, auth, opts) do
    algorithm = algorithm(auth)

    cond do
      algorithm not in @supported_algorithms ->
        # Re-challenge rather than reject: our challenge names the algorithm we
        # want, so a client that picked another one (or the RFC 8760 `SHA-256`
        # spelling) gets a chance to come back with it. Never a raise, never
        # silence.
        Logger.info(
          module: __MODULE__,
          message: "unsupported digest algorithm #{inspect(algorithm)}; re-challenging"
        )

        {:requireauth, false}

      true ->
        case SIP.Auth.Nonce.validate(auth["nonce"] || "", domain, nonce_opts(opts)) do
          :invalid -> {:requireauth, false}
          :stale -> {:requireauth, true}
          :ok -> check_credentials(req, domain, auth, algorithm, opts)
        end
    end
  end

  defp check_credentials(req, domain, auth, algorithm, opts) do
    with :ok <- check_nc(auth),
         {:ok, ha1} <- lookup(subscriber_of(auth["username"]), domain, opts),
         # HA1 is an *input* to the digest, so its case matters: a base holding
         # upper-case hex would otherwise fail every authentication silently.
         expected =
           SIP.Auth.expected_response_from_ha1(
             algorithm,
             normalize_hex(ha1),
             req_method(req),
             auth
           ),
         true <- secure_equal?(normalize_hex(expected), normalize_hex(auth["response"])) do
      :ok
    else
      :replay ->
        {:requireauth, true}

      :notfound ->
        {:reject, 403, "Forbidden"}

      false ->
        {:reject, 403, "Forbidden"}

      {:error, reason} ->
        Logger.error(module: __MODULE__, message: "HA1 lookup failed: #{inspect(reason)}")
        {:reject, 500, "Server Internal Error"}
    end
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
