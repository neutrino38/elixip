defmodule Kelix.DB.Pool do
  @moduledoc """
  How a kelixip module opens its SQL link: which driver, on which transport, and
  what its `show` command reports about it. Written once, for every module that
  keeps data in SQL (`auth_db`, the Silo, the `conversation` store).

  The code is shared, **the connection never is**: each module starts a pool of
  its own, under a name of its own, on its own account —

      Kelix.DB.Pool.child_spec(config, name: Kelix.Mod.AuthDb.Conn, label: "auth_db")
      Kelix.DB.Pool.child_spec(config, name: Kelix.Mod.Silo.Conn, label: "silo")

  — because the databases may differ, the grants must (the subscriber base is
  read-only, the Silo writes), and one module's load must not queue another's
  queries (DESIGN-CHAT.md, *Horizontal scale*).

  The link is a **permanent MyXQL or Postgrex `DBConnection` pool**. Its
  `pool_size` connections are opened once, kept open (DBConnection pings the idle
  ones), and re-established with backoff — a query never connects.

  ## Which driver

  `driver` in the module's block selects the engine: `"mysql"` (default,
  MariaDB/MySQL, `MyXQL`) or `"postgres"` (PostgreSQL, `Postgrex`) — `driver/1`
  reads the block, `driver_module/1` resolves it to the module. Both drivers take
  the same connection options (`hostname`, `port`, `database`, `username`,
  `password`, `connect_timeout`, and the merged `ssl:` keyword form below), so
  everything from here down is written once and dispatches on the resolved
  module rather than branching on the driver directly. Only the default port
  (`3306` / `5432`) and the SQL placeholder syntax (`?` vs `$1`) differ.

  ## Defaults from `[database]`

  An optional `[database]` block in `config.toml` says **where and how** —
  `driver`, `host`, `port`, `ssl`, `ssl_ca_cert_file`,
  `allow_insecure_db_connection`, `connect_timeout_ms` — and every SQL module's
  block inherits it, key by key, its own keys winning (`with_defaults/1`). It
  never says **who**: `database`, `username` and `password` are each module's,
  since one account for two modules is the grant the design refuses. Nor
  `pool_size`, which sizes one module's load.

  ## TLS first, cleartext only when the block says so

  TLS is **always tried first**, whether or not the block mentions it: an operator
  who configured nothing gets an encrypted link. Cleartext happens only with
  `allow_insecure_db_connection = true`, and only after TLS has actually been
  refused.

  The choice is made by **probing**, not by hoping, because DBConnection opens its
  connections asynchronously and retries them for ever: a pool that *started* says
  nothing about whether the server accepted TLS. So `negotiate/2` opens one
  throwaway connection and runs `SELECT 1` on it, which distinguishes the three
  cases that must not be confused:

    * the server speaks TLS → TLS, and that is the end of it;
    * the server refuses TLS but answers in clear → the fallback case, taken only
      when the block allows it, and logged as the downgrade it is;
    * the server answers on **neither** transport → it is unreachable, not
      TLS-less. The preferred transport is kept and DBConnection retries in the
      background. Downgrading here would turn a transient outage into a permanent
      cleartext link, since the transport is decided once, here.

  The transport is therefore decided at **start**, which is also what a
  `systemctl restart kelixip` or a `kelictl module reload <name>` re-does.

  ## Certificate verification

  `ssl_ca_cert_file` is what turns the encrypted link into an *authenticated* one
  (`verify_peer` against that CA, with hostname checking). Without it the link is
  encrypted but the server is unverified — usable against a self-signed dev
  server, said out loud in the logs and in `show`, so nobody mistakes it for a
  secure link.
  """
  require Logger

  @default_pool_size 4
  @default_connect_timeout_ms 5_000
  @default_port_mysql 3306
  @default_port_postgres 5432

  # The probe's own query bound. Deliberately shorter than `call_timeout_ms`: this
  # is a `SELECT 1` on a fresh connection, and it runs on the boot path.
  @probe_query_timeout_ms 2_000

  @doc """
  The keys a `[database]` block may carry: where the server is and how to reach
  it, never whose account it is.
  """
  @spec default_keys() :: [String.t()]
  def default_keys,
    do: ~w(driver host port ssl ssl_ca_cert_file allow_insecure_db_connection connect_timeout_ms)

  @typedoc """
  What the negotiation settled on. The two `tls_*` verdicts say which transport the
  pool USES — not that it is currently working: a TLS server that is down leaves
  `:tls_*` here and `state: :down` in `describe/3`.
  """
  @type verdict :: :tls_verified | :tls_unverified | :cleartext_fallback | :cleartext_configured

  @typedoc """
  How a module names its pool:

    * `:name` — the registered name its queries use (required);
    * `:label` — the module's name, in the log lines and in the block they point
      at (`[module.<label>]`); `"db"` by default;
    * `:publish_as` — the application-env key the descriptor is published under,
      which `describe/3` reads back (`:name` by default);
    * `:descriptor` — `fn config, verdict -> map end`, to add the module's own
      fields to `descriptor/2`'s (default: `descriptor/2` alone).
  """
  @type opts :: keyword

  # ── configuration ────────────────────────────────────────────────────────────

  @doc """
  A module's block with the `[database]` defaults under it: each key of
  `default_keys/0` the block does not set is taken from `[database]`.

  `defaults` is the `[database]` block, read from the running `Kelix.Config`
  when not given; with none running (a unit test, a preflight) the block is
  returned as it is.
  """
  @spec with_defaults(map, map) :: map
  def with_defaults(block, defaults \\ defaults()) when is_map(block) and is_map(defaults) do
    defaults
    |> Map.take(default_keys())
    |> Map.merge(block)
  end

  defp defaults do
    if Process.whereis(Kelix.Config),
      do: Map.get(Kelix.Config.current(), :database, %{}),
      else: %{}
  end

  @doc "Which SQL driver the block asks for: `:mysql` (default) or `:postgres`."
  @spec driver(map) :: :mysql | :postgres
  def driver(config) do
    case Map.get(config, "driver") do
      "postgres" -> :postgres
      _ -> :mysql
    end
  end

  @doc "The driver module `driver/1`'s result resolves to."
  @spec driver_module(:mysql | :postgres) :: module
  def driver_module(:mysql), do: MyXQL
  def driver_module(:postgres), do: Postgrex

  @doc "Does the block allow a cleartext link?"
  @spec insecure_allowed?(map) :: boolean
  def insecure_allowed?(config), do: Map.get(config, "allow_insecure_db_connection") == true

  # ── starting ─────────────────────────────────────────────────────────────────

  @doc "A supervised child spec for the pool `opts` names (see `t:opts/0`)."
  @spec child_spec(map, opts) :: Supervisor.child_spec()
  def child_spec(config, opts) do
    name = Keyword.fetch!(opts, :name)
    %{id: name, start: {__MODULE__, :start_link, [config, opts]}}
  end

  @doc """
  Negotiate the transport, publish the descriptor `show` reads, and start the pool.

  Returns whatever the resolved driver's `start_link/1` returns — including
  `{:ok, pid}` when the database is unreachable, which is deliberate: a base that
  is down must not abort the node's boot, it must make the module's queries fail
  until it comes back.
  """
  @spec start_link(map, opts) :: {:ok, pid} | {:error, term}
  def start_link(config, opts) do
    name = Keyword.fetch!(opts, :name)
    {verdict, transport_opts} = negotiate(config, opts)
    describe_fun = Keyword.get(opts, :descriptor, &descriptor/2)

    Application.put_env(
      :kelixip,
      Keyword.get(opts, :publish_as, name),
      describe_fun.(config, verdict)
    )

    driver_module(driver(config)).start_link(
      [name: name, pool_size: pool_size(config)] ++ driver_opts(config, transport_opts)
    )
  end

  @doc """
  Which transport to open the pool on, as `{verdict, driver_opts}` (see the
  moduledoc for the decision procedure).

  `opts[:probe]` replaces the live probe with `fn config, driver_opts -> :ok |
  {:error, reason} end` — what lets every branch of the decision be tested
  without a server that refuses TLS on demand. `opts[:label]` names the module in
  the log lines.
  """
  @spec negotiate(map, keyword) :: {verdict, keyword}
  def negotiate(config, opts \\ []) do
    label = Keyword.get(opts, :label, "db")

    if Map.get(config, "ssl") == false do
      # An operator asking for cleartext outright. The module's `validate_config/1`
      # has already refused this unless `allow_insecure_db_connection` confirms it,
      # so there is nothing left to negotiate — and nothing to probe either.
      {:cleartext_configured, []}
    else
      tls = tls_opts(config)

      case run_probe(config, tls, opts) do
        :ok -> {tls_verdict(config), tls}
        {:error, reason} -> after_tls_failed(config, tls, reason, opts, label)
      end
    end
  end

  defp run_probe(config, transport_opts, opts) do
    case Keyword.get(opts, :probe) do
      fun when is_function(fun, 2) -> fun.(config, transport_opts)
      _ -> probe(config, transport_opts)
    end
  end

  # TLS did not work. Whether that means "fall back" takes a second probe, and the
  # right to run one at all takes the operator's confirmation — probing in clear
  # sends the DB password over an unencrypted socket, which is the very thing
  # `allow_insecure_db_connection` consents to.
  defp after_tls_failed(config, tls, tls_error, opts, label) do
    cond do
      not insecure_allowed?(config) ->
        log_no_fallback(label, tls_error)
        {tls_verdict(config), tls}

      run_probe(config, [], opts) == :ok ->
        log_fallback(label, tls_error)
        {:cleartext_fallback, []}

      true ->
        log_unreachable(label, tls_error)
        {tls_verdict(config), tls}
    end
  end

  defp log_fallback(label, tls_error) do
    Logger.warning(
      module: __MODULE__,
      message:
        "#{label}: the database refused TLS (#{reason_text(tls_error)}) but answers " <>
          "in clear — falling back to a CLEARTEXT link, as allow_insecure_db_connection " <>
          "permits. The DB password and everything the base returns cross the network " <>
          "unencrypted."
    )
  end

  # Unreachable, not TLS-less: keep the preferred transport and let DBConnection
  # retry — see the moduledoc on why this must not downgrade.
  defp log_unreachable(label, tls_error) do
    Logger.error(
      module: __MODULE__,
      message:
        "#{label}: the database answered on neither transport " <>
          "(#{reason_text(tls_error)}) — keeping TLS and retrying in the background"
    )
  end

  defp log_no_fallback(label, tls_error) do
    Logger.error(
      module: __MODULE__,
      message:
        "#{label}: TLS to the database failed (#{reason_text(tls_error)}) and no " <>
          "fallback is allowed — every query fails until it works. If the server " <>
          "speaks no TLS, set allow_insecure_db_connection = true in " <>
          "[module.#{label}] or [database] to accept a CLEARTEXT link instead."
    )
  end

  # ── probing ──────────────────────────────────────────────────────────────────

  # Prove a transport with one throwaway connection and a `SELECT 1`.
  #
  # It runs in a process of its own so the connection it opens is LINKED to that
  # process: `DBConnection.ConnectionPool` stops on any linked EXIT and closes its
  # connections in `terminate/2`, so the prober's death is the teardown — there is
  # nothing to unlink and nothing that can outlive this function.
  defp probe(config, transport_opts) do
    # The bound is a backstop, not what normally applies: the driver bounds both
    # the connect and the query below. Reaching it means the driver hung past its
    # own timeouts.
    case bounded(fn -> do_probe(config, transport_opts) end, probe_bound(config)) do
      {:ok, verdict} -> verdict
      {:exit, reason} -> {:error, {:probe_died, reason}}
      :timeout -> {:error, :timeout}
    end
  end

  defp do_probe(config, transport_opts) do
    driver = driver(config)
    mod = driver_module(driver)

    case mod.start_link([pool_size: 1] ++ driver_opts(config, transport_opts)) do
      {:ok, pool} ->
        case mod.query(pool, "SELECT 1", [], timeout: @probe_query_timeout_ms) do
          {:ok, _result} ->
            :ok

          # The server answered with its OWN error, so the TRANSPORT worked: bad
          # credentials or a missing database is not something another transport
          # would fix, and probing cleartext for it would downgrade the link over a
          # password typo. The pool stays as it is; the reason reaches the operator
          # through `show` and the failing queries.
          {:error, reason} ->
            if server_answered?(driver, reason), do: :ok, else: {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, e}
  end

  defp server_answered?(:mysql, %MyXQL.Error{mysql: mysql}), do: is_map(mysql)
  defp server_answered?(:postgres, %Postgrex.Error{postgres: pg}), do: is_map(pg)
  defp server_answered?(_driver, _reason), do: false

  defp probe_bound(config), do: connect_timeout(config) + @probe_query_timeout_ms + 2_000

  # Run `fun` in a process of its own, bounded, with nothing linked back to us:
  # whatever it does — block for ever, exit — cannot take the caller with it.
  # `{:ok, result}` / `{:exit, reason}` / `:timeout`.
  defp bounded(fun, timeout) do
    parent = self()
    ref = make_ref()
    {pid, mon} = spawn_monitor(fn -> send(parent, {ref, fun.()}) end)

    receive do
      {^ref, result} ->
        Process.demonitor(mon, [:flush])
        {:ok, result}

      {:DOWN, ^mon, :process, ^pid, reason} ->
        {:exit, reason}
    after
      timeout ->
        Process.exit(pid, :kill)
        Process.demonitor(mon, [:flush])
        :timeout
    end
  end

  # ── what `show` reports ───────────────────────────────────────────────────────

  @doc """
  What the link IS, as a module's `show` reports it: where it points and how it
  is protected.

  Deliberately **not** the password — this map is printed by `kelictl` and
  returned by the REST API, and a secret that is never put in it cannot leak out
  of it.
  """
  @spec descriptor(map, verdict) :: map
  def descriptor(config, verdict) do
    %{
      host: host(config),
      port: port(config),
      database: config["database"],
      username: config["username"],
      driver: driver(config),
      tls: tls?(verdict),
      certificate: certificate(verdict),
      transport: transport_text(verdict),
      pool_size: pool_size(config),
      query_timeout_ms: query_timeout(config)
    }
  end

  @doc """
  The running link published under `key`, queried through the pool `conn`:
  where it points, whether it is encrypted, and whether it answers **right now**.

  The state is a live `SELECT 1`, not a cached flag — "is the base answering" is
  the question the command exists for, and a flag would answer it as of boot. It
  is bounded by the query timeout plus a small margin, so the command answers
  even when the pool does not. `label` names the module when it is not loaded.
  """
  @spec describe(term, atom, String.t()) :: map
  def describe(key, conn, label) do
    case Application.get_env(:kelixip, key) do
      %{} = descriptor -> Map.merge(descriptor, state(descriptor, conn))
      _ -> %{state: :down, error: "the #{label} module is not loaded"}
    end
  end

  defp state(descriptor, conn) do
    timeout = descriptor.query_timeout_ms

    if Process.whereis(conn) == nil do
      %{state: :down, error: "the connection pool is not running"}
    else
      # Bounded from the outside, and deliberately not by the driver's `:timeout`
      # alone: that one covers a slow SERVER, while a checkout waits on the POOL
      # PROCESS and that wait has no deadline of its own
      # (`DBConnection.Holder.checkout_call/5` blocks until the pool answers).
      # `show` is the command an operator runs when things are stuck, so it must
      # answer "down, and here is why" rather than join whatever is stuck.
      case bounded(fn -> query(descriptor.driver, conn, timeout) end, timeout + 500) do
        {:ok, {:ok, _result}} -> %{state: :up}
        {:ok, {:error, reason}} -> %{state: :down, error: reason_text(reason)}
        {:exit, reason} -> %{state: :down, error: reason_text(reason)}
        :timeout -> %{state: :down, error: "the pool did not answer within #{timeout} ms"}
      end
    end
  end

  defp query(driver, conn, timeout) do
    driver_module(driver).query(conn, "SELECT 1", [], timeout: timeout)
  rescue
    e -> {:error, e}
  end

  defp tls?(verdict), do: verdict in [:tls_verified, :tls_unverified]

  defp certificate(:tls_verified), do: "verified"
  defp certificate(:tls_unverified), do: "not verified"
  defp certificate(_cleartext), do: "-"

  defp transport_text(:tls_verified), do: "TLS, server certificate verified"

  defp transport_text(:tls_unverified),
    do: "TLS, server certificate NOT verified (no ssl_ca_cert_file)"

  defp transport_text(:cleartext_fallback),
    do: "cleartext — the server refused TLS, allowed by allow_insecure_db_connection"

  defp transport_text(:cleartext_configured), do: "cleartext — configured (ssl = false)"

  # ── driver options (MyXQL and Postgrex agree on all of this) ────────────────

  defp driver_opts(config, transport_opts) do
    [
      hostname: host(config),
      port: port(config),
      database: config["database"],
      username: config["username"],
      password: config["password"],
      connect_timeout: connect_timeout(config)
    ] ++ transport_opts
  end

  # TLS options in MyXQL's and Postgrex's CURRENT shared spelling: a keyword list
  # under `:ssl`. MyXQL's old `ssl: true` + `ssl_opts:` pair logs a deprecation
  # warning on every connect, and a bare `ssl: true` raises a MatchError inside
  # MyXQL 0.8.2 — so the list form is the only one to use. Both drivers merge
  # `verify_peer` + the hostname match under it, and what we pass wins.
  defp tls_opts(config) do
    case config["ssl_ca_cert_file"] do
      path when is_binary(path) and path != "" ->
        [
          ssl: [
            verify: :verify_peer,
            cacertfile: path,
            server_name_indication: String.to_charlist(host(config)),
            depth: 3,
            customize_hostname_check: [
              match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
            ]
          ]
        ]

      _ ->
        [ssl: [verify: :verify_none]]
    end
  end

  defp tls_verdict(config) do
    case config["ssl_ca_cert_file"] do
      path when is_binary(path) and path != "" -> :tls_verified
      _ -> :tls_unverified
    end
  end

  defp host(config), do: config["host"] || "127.0.0.1"

  defp port(config) do
    config["port"] ||
      case driver(config) do
        :mysql -> @default_port_mysql
        :postgres -> @default_port_postgres
      end
  end

  defp pool_size(config), do: config["pool_size"] || @default_pool_size
  defp connect_timeout(config), do: config["connect_timeout_ms"] || @default_connect_timeout_ms

  defp query_timeout(config),
    do: config["call_timeout_ms"] || Kelix.Module.default_call_timeout_ms()

  # One line, bounded: a DBConnection error message is a paragraph of advice, and
  # `show` is a status view, not a log.
  defp reason_text(reason) do
    reason
    |> message()
    |> String.split("\n")
    |> hd()
    |> String.slice(0, 200)
  end

  defp message(%{__exception__: true} = e), do: Exception.message(e)
  defp message(reason), do: inspect(reason)
end
