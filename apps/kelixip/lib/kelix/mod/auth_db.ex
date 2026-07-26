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
    with {:ok, _} <- req_string(config, "database"),
         {:ok, _} <- req_string(config, "username"),
         :ok <- hash_ok(config),
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
  for tests), plus `:now` / `:max_age` forwarded to `Kelix.Nonce.validate`.
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
  end

  defp verify(req, domain, auth, opts) do
    case Kelix.Nonce.validate(auth["nonce"] || "", domain, nonce_opts(opts)) do
      :invalid -> {:requireauth, false}
      :stale -> {:requireauth, true}
      :ok -> check_credentials(req, domain, auth, opts)
    end
  end

  defp check_credentials(req, domain, auth, opts) do
    with :ok <- check_nc(auth),
         {:ok, ha1} <- lookup(auth["username"], domain, opts),
         expected =
           SIP.Auth.expected_response_from_ha1(algorithm(auth), ha1, req_method(req), auth),
         true <- secure_equal?(expected, auth["response"] || "") do
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

  defp algorithm(auth), do: auth["algorithm"] || "MD5"

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
