defmodule Kelix.Mod.AuthDb.Pool do
  @moduledoc """
  The subscriber-DB link of `Kelix.Mod.AuthDb`: how it is opened, on which
  transport, and what `kelictl auth_db show` reports about it.

  The link is a **permanent MyXQL/DBConnection pool**, registered as
  `Kelix.Mod.AuthDb.Conn` and supervised by `Kelix.ModuleSupervisor`. Its
  `pool_size` connections are opened once, kept open (DBConnection pings the idle
  ones), and re-established with backoff — a query never connects.

  ## TLS first, cleartext only when the block says so

  TLS is **always tried first**, whether or not the block mentions it: an operator
  who configured nothing gets an encrypted link to the base holding every
  subscriber's HA1. Cleartext happens only with
  `allow_insecure_db_connection = true`, and only after TLS has actually been
  refused.

  The choice is made by **probing**, not by hoping, because DBConnection opens its
  connections asynchronously and retries them for ever: a pool that *started* says
  nothing about whether the server accepted TLS. So `negotiate/1` opens one
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
  `systemctl restart kelixip` or a `kelictl module reload auth_db` re-does (the
  module has no `reload/2`, so its child is restarted cleanly).

  ## Certificate verification

  `ssl_ca_cert_file` is what turns the encrypted link into an *authenticated* one
  (`verify_peer` against that CA, with hostname checking). Without it the link is
  encrypted but the server is unverified — usable against a self-signed dev
  server, said out loud in the logs and in `show`, so nobody mistakes it for a
  secure link.
  """
  require Logger

  # The pool's registered name — the one `Kelix.Mod.AuthDb.lookup_ha1/2` queries.
  @conn Kelix.Mod.AuthDb.Conn

  @default_pool_size 4
  @default_connect_timeout_ms 5_000
  @default_port 3306

  # The probe's own query bound. Deliberately shorter than `call_timeout_ms`: this
  # is a `SELECT 1` on a fresh connection, and it runs on the boot path.
  @probe_query_timeout_ms 2_000

  @typedoc """
  What the negotiation settled on. The two `tls_*` verdicts say which transport the
  pool USES — not that it is currently working: a TLS server that is down leaves
  `:tls_*` here and `state: :down` in `describe/0`.
  """
  @type verdict :: :tls_verified | :tls_unverified | :cleartext_fallback | :cleartext_configured

  @doc "The pool's registered name."
  @spec conn() :: atom
  def conn(), do: @conn

  @doc """
  Negotiate the transport, publish the descriptor `show` reads, and start the pool.

  This is `Kelix.Mod.AuthDb.child_spec/2`'s start MFA. It returns whatever
  `MyXQL.start_link/1` returns — including `{:ok, pid}` when the database is
  unreachable, which is deliberate: a base that is down must not abort the node's
  boot, it must make authentication answer 500 until it comes back.
  """
  @spec start_link(map) :: {:ok, pid} | {:error, term}
  def start_link(config) do
    {verdict, transport_opts} = negotiate(config)
    publish(config, verdict)

    MyXQL.start_link([name: @conn, pool_size: pool_size(config)] ++ opts(config, transport_opts))
  end

  @doc """
  Which transport to open the pool on, as `{verdict, myxql_opts}` (see the
  moduledoc for the decision procedure).

  `opts[:probe]` replaces the live probe with `fn config, myxql_opts -> :ok |
  {:error, reason} end` — the same injection idiom as `authenticate/3`'s
  `:ha1_lookup`, and what lets every branch of the decision be tested without a
  server that refuses TLS on demand.
  """
  @spec negotiate(map, keyword) :: {verdict, keyword}
  def negotiate(config, opts \\ []) do
    if Map.get(config, "ssl") == false do
      # An operator asking for cleartext outright. `validate_config/1` has already
      # refused this unless `allow_insecure_db_connection` confirms it, so there is
      # nothing left to negotiate — and nothing to probe either.
      {:cleartext_configured, []}
    else
      tls = tls_opts(config)

      case run_probe(config, tls, opts) do
        :ok -> {tls_verdict(config), tls}
        {:error, reason} -> after_tls_failed(config, tls, reason, opts)
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
  defp after_tls_failed(config, tls, tls_error, opts) do
    cond do
      not insecure_allowed?(config) ->
        log_no_fallback(tls_error)
        {tls_verdict(config), tls}

      cleartext_answers?(config, opts) ->
        log_fallback(tls_error)
        {:cleartext_fallback, []}

      true ->
        log_unreachable(tls_error)
        {tls_verdict(config), tls}
    end
  end

  defp cleartext_answers?(config, opts), do: run_probe(config, [], opts) == :ok

  defp log_fallback(tls_error) do
    Logger.warning(
      module: __MODULE__,
      message:
        "auth_db: the subscriber DB refused TLS (#{reason_text(tls_error)}) but answers " <>
          "in clear — falling back to a CLEARTEXT link, as allow_insecure_db_connection " <>
          "permits. The DB password and every HA1 it returns cross the network unencrypted."
    )
  end

  # Unreachable, not TLS-less: keep the preferred transport and let DBConnection
  # retry — see the moduledoc on why this must not downgrade.
  defp log_unreachable(tls_error) do
    Logger.error(
      module: __MODULE__,
      message:
        "auth_db: the subscriber DB answered on neither transport " <>
          "(#{reason_text(tls_error)}) — keeping TLS and retrying in the background"
    )
  end

  defp log_no_fallback(tls_error) do
    Logger.error(
      module: __MODULE__,
      message:
        "auth_db: TLS to the subscriber DB failed (#{reason_text(tls_error)}) and no " <>
          "fallback is allowed — every authentication answers 500 until it works. If " <>
          "the server speaks no TLS, set allow_insecure_db_connection = true in " <>
          "[module.auth_db] to accept a CLEARTEXT link instead."
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
    # The bound is a backstop, not what normally applies: MyXQL bounds both the
    # connect and the query below. Reaching it means the driver hung past its own
    # timeouts.
    case bounded(fn -> do_probe(config, transport_opts) end, probe_bound(config)) do
      {:ok, verdict} -> verdict
      {:exit, reason} -> {:error, {:probe_died, reason}}
      :timeout -> {:error, :timeout}
    end
  end

  defp do_probe(config, transport_opts) do
    case MyXQL.start_link([pool_size: 1] ++ opts(config, transport_opts)) do
      {:ok, pool} ->
        case MyXQL.query(pool, "SELECT 1", [], timeout: @probe_query_timeout_ms) do
          {:ok, _result} ->
            :ok

          # A server ERROR packet came back, so the TRANSPORT worked: bad
          # credentials or a missing database is not something another transport
          # would fix, and probing cleartext for it would downgrade the link over a
          # password typo. The pool stays as it is; the reason reaches the operator
          # through `show` and the 500s.
          {:error, %MyXQL.Error{mysql: mysql}} when is_map(mysql) ->
            :ok

          {:error, reason} ->
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, e}
  end

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

  # ── the descriptor `show` reads ───────────────────────────────────────────────

  # Published at every (re)start, which is also when the transport is negotiated.
  defp publish(config, verdict) do
    Application.put_env(:kelixip, __MODULE__, descriptor(config, verdict))
  end

  @doc """
  What the link IS, as `show` reports it: where it points and how it is protected.

  Deliberately **not** the password — this map is printed by `kelictl auth_db show`
  and returned by `GET /modules/auth_db/db`, and a secret that is never put in it
  cannot leak out of it.
  """
  @spec descriptor(map, verdict) :: map
  def descriptor(config, verdict) do
    %{
      host: host(config),
      port: port(config),
      database: config["database"],
      username: config["username"],
      table: config["table"] || "subscriber",
      tls: tls?(verdict),
      certificate: certificate(verdict),
      transport: transport_text(verdict),
      pool_size: pool_size(config),
      query_timeout_ms: query_timeout(config)
    }
  end

  @doc """
  The running link: where it points, whether it is encrypted, and whether it
  answers **right now** (`kelictl auth_db show`).

  The state is a live `SELECT 1`, not a cached flag — "is the base answering" is the
  question the command exists for, and a flag would answer it as of boot. It is
  bounded by `call_timeout_ms` plus a small margin, so the command answers even when
  the pool does not.
  """
  @spec describe() :: map
  def describe() do
    case Application.get_env(:kelixip, __MODULE__) do
      %{} = descriptor -> Map.merge(descriptor, state(descriptor))
      _ -> %{state: :down, error: "the auth_db module is not loaded"}
    end
  end

  defp state(descriptor) do
    timeout = descriptor.query_timeout_ms

    if Process.whereis(@conn) == nil do
      %{state: :down, error: "the connection pool is not running"}
    else
      # Bounded from the outside, and deliberately not by MyXQL's `:timeout` alone:
      # that one covers a slow SERVER, while a checkout waits on the POOL PROCESS
      # and that wait has no deadline of its own (`DBConnection.Holder.checkout_call/5`
      # blocks until the pool answers). `show` is the command an operator runs when
      # things are stuck, so it must answer "down, and here is why" rather than join
      # whatever is stuck.
      case bounded(fn -> query(timeout) end, timeout + 500) do
        {:ok, {:ok, _result}} -> %{state: :up}
        {:ok, {:error, reason}} -> %{state: :down, error: reason_text(reason)}
        {:exit, reason} -> %{state: :down, error: reason_text(reason)}
        :timeout -> %{state: :down, error: "the pool did not answer within #{timeout} ms"}
      end
    end
  end

  defp query(timeout) do
    MyXQL.query(@conn, "SELECT 1", [], timeout: timeout)
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

  # ── MyXQL options ────────────────────────────────────────────────────────────

  defp opts(config, transport_opts) do
    [
      hostname: host(config),
      port: port(config),
      database: config["database"],
      username: config["username"],
      password: config["password"],
      connect_timeout: connect_timeout(config)
    ] ++ transport_opts
  end

  # TLS options in MyXQL's CURRENT spelling: a keyword list under `:ssl`. The old
  # `ssl: true` + `ssl_opts:` pair logs a deprecation warning on every connect, and
  # a bare `ssl: true` raises a MatchError inside MyXQL 0.8.2 — so the list form is
  # the only one to use. MyXQL merges `verify_peer` + the https hostname match under
  # it, and what we pass wins.
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

  @doc "Does `[module.auth_db]` allow a cleartext link to the subscriber DB?"
  @spec insecure_allowed?(map) :: boolean
  def insecure_allowed?(config), do: Map.get(config, "allow_insecure_db_connection") == true

  defp host(config), do: config["host"] || "127.0.0.1"
  defp port(config), do: config["port"] || @default_port
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
