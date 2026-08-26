defmodule Kelix.Listener.Supervisor do
  @moduledoc """
  Supervises the inbound SIP listeners — **one child per `[[listen]]` entry** of
  `config.toml` (design §2.1, §3.1).

  Until now `[[listen]]` was parsed and validated by `Kelix.Config` but nothing
  consumed it: the server bound no SIP port at all. This supervisor closes that
  gap. It is started **last** in the root tree, after `Kelix.Router` has been
  registered as the processing module — a listener must not accept before the
  router is ready.

  Per protocol:

    * `udp` — the bidirectional `SIP.Transport.UDP` instance, which binds the
      entry's own address and port. It is registered in `Registry.SIPTransport`
      under `SIP.Transport.Selector.unreliable_instance_name/2`, i.e. **the name
      the selector looks up for an outbound datagram of that family**, so
      outbound requests reuse this socket instead of trying to bind the same port
      a second time.
    * `tcp` / `tls` / `wss` — the matching `SIP.Transport.*Listener`, which binds
      the socket and spawns one transport process per accepted connection.
      `tls`/`wss` receive their **per-listener** cert/key (design §3.1) as
      `:certfile`/`:keyfile` opts, instead of the framework-wide `:tls_certfile`
      default.

  A listener that fails to bind (port busy, unreadable cert) aborts the boot —
  fail fast, like an invalid config, so systemd reports a failed start rather than
  a half-deaf server.

  **One UDP socket per family**: a datagram leaves only through a socket of its
  destination's family, and the two share a port (step 4 of
  docs/design/multi-interface.md). A second `udp` entry of a family already bound
  is logged and skipped.

  The `:elixip2` app env keys `:udp_local_port` / `:udp_local_addr` still name the
  node's **primary** UDP socket — the first `udp` entry. Nothing binds from them
  any more; they answer `SIP.NetUtils.preferred_family/0`, which orders the two
  DNS queries of a name resolution. Both families being bound, that order now
  costs at most one extra query rather than a failure.
  """
  use Supervisor
  require Logger

  @udp_proto "UDP"

  @type listener :: Kelix.Config.listener()

  @spec start_link(keyword) :: Supervisor.on_start()
  def start_link(opts \\ []), do: Supervisor.start_link(__MODULE__, opts, name: __MODULE__)

  @doc """
  The listeners actually brought up: one map per running child (`Kelix.Control`
  surfaces it in `status/0`). Empty when the supervisor is not running — the
  `elixipp` tool and the tests bring their own listeners up.
  """
  @spec status(Supervisor.supervisor()) :: [%{proto: atom, addr: String.t(), port: pos_integer}]
  def status(sup \\ __MODULE__) do
    if is_pid(sup) or Process.whereis(sup) do
      for {{proto, addr, port}, pid, _type, _mods} <- Supervisor.which_children(sup) do
        %{proto: proto, addr: addr, port: port, up: is_pid(pid)}
      end
    else
      []
    end
  end

  @impl true
  def init(opts) do
    listeners = Keyword.get(opts, :listen) || listen_from_config()
    Supervisor.init(child_specs(listeners), strategy: :one_for_one)
  end

  # ── child specs ──────────────────────────────────────────────────────────────

  @spec child_specs([listener]) :: [Supervisor.child_spec()]
  defp child_specs(listeners) do
    # The env first: udp_family/1 falls back to preferred_family/0 for an entry
    # that names no address, and that reads what this sets.
    configure_udp_env(listeners)

    listeners
    |> drop_extra_udp()
    |> Enum.map(&child_spec_for/1)
  end

  defp child_spec_for(%{proto: :udp, addr: addr, port: port} = l) do
    name = SIP.Transport.Selector.unreliable_instance_name(@udp_proto, udp_family(l))

    %{
      id: {:udp, addr, port},
      start:
        {__MODULE__, :start_listener,
         [
           :udp,
           addr,
           port,
           {GenServer, :start_link,
            [
              SIP.Transport.UDP,
              {:bind, bind_addr(l), port, [family: udp_family(l)]},
              [name: {:via, Registry, {Registry.SIPTransport, name}}]
            ]}
         ]},
      type: :worker,
      restart: :permanent
    }
  end

  defp child_spec_for(%{proto: proto, addr: addr, port: port} = l) do
    %{
      id: {proto, addr, port},
      start:
        {__MODULE__, :start_listener,
         [
           proto,
           addr,
           port,
           {listener_module(proto), :start_link, [{bind_addr(l), port, listener_opts(l)}]}
         ]},
      type: :worker,
      restart: :permanent
    }
  end

  @doc """
  Start one listener, and on failure say so on **stderr** as well as in the log.

  A listener that cannot bind aborts the boot — and a release dying during boot
  flushes no Logger output, so the operator would only see "Runtime terminating
  during boot" with no cause. Same reasoning (and same remedy) as
  `Kelix.Config`'s fail-fast: journald must record *why* the start failed.
  """
  @spec start_listener(atom, String.t(), pos_integer, {module, atom, [term]}) ::
          Supervisor.on_start_child()
  def start_listener(proto, addr, port, {module, fun, args}) do
    case apply(module, fun, args) do
      {:error, reason} = err ->
        IO.puts(
          :stderr,
          "kelixip: cannot bind the #{proto} listener on #{SIP.NetUtils.sip_host(addr)}:#{port}: #{inspect(reason)}"
        )

        err

      other ->
        other
    end
  end

  defp listener_module(:tcp), do: SIP.Transport.TCPListener
  defp listener_module(:tls), do: SIP.Transport.TLSListener
  defp listener_module(:wss), do: SIP.Transport.WSSListener

  # tls/wss carry their own cert/key (design §3.1); Kelix.Config guarantees both
  # are present for those protocols and absent for udp/tcp.
  defp listener_opts(%{cert: cert, key: key}) when is_binary(cert) and is_binary(key),
    do: [certfile: cert, keyfile: key]

  defp listener_opts(_l), do: []

  # "0.0.0.0" (the default) means "every interface" — the listeners spell that
  # `:all`, and then resolve a local IP themselves for Via/Contact.
  defp bind_addr(%{addr: "0.0.0.0"}), do: :all

  defp bind_addr(%{addr: addr}) do
    {:ok, ip} = :inet.parse_address(String.to_charlist(addr))
    ip
  end

  # The family an entry binds. An entry naming an address states it; one naming
  # none takes the node's, as the transport itself does.
  defp udp_family(l) do
    case bind_addr(l) do
      :all -> SIP.NetUtils.preferred_family()
      ip -> SIP.NetUtils.address_family(ip)
    end
  end

  # The app env names the node's PRIMARY udp socket — the first entry, in config
  # order. Only preferred_family/0 reads it now; the sockets bind from their own
  # entry.
  defp configure_udp_env(listeners) do
    case Enum.find(listeners, &(&1.proto == :udp)) do
      nil ->
        :ok

      %{port: port} = first ->
        Application.put_env(:elixip2, :udp_local_port, port)

        case bind_addr(first) do
          :all -> :ok
          ip -> Application.put_env(:elixip2, :udp_local_addr, ip)
        end
    end
  end

  # One UDP socket per family: two entries of the same family would claim one
  # registry name, and the second would abort the boot on {:already_started, _}.
  # Keep the first of each, and say which were dropped.
  defp drop_extra_udp(listeners) do
    {udp, others} = Enum.split_with(listeners, &(&1.proto == :udp))
    kept = Enum.uniq_by(udp, &udp_family/1)

    case udp -- kept do
      [] ->
        :ok

      extra ->
        Logger.warning(
          module: __MODULE__,
          message:
            "one udp listener per family; ignoring " <>
              Enum.map_join(extra, ", ", &"udp:#{&1.addr}:#{&1.port} (#{udp_family(&1)})")
        )
    end

    kept ++ others
  end

  defp listen_from_config() do
    if Process.whereis(Kelix.Config), do: Kelix.Config.current().listen, else: []
  end
end
