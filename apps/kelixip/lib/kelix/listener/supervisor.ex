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

    * `udp` — the bidirectional `SIP.Transport.UDP` instance. It binds the port
      read from the `:elixip2` app env (`:udp_local_port` / `:udp_local_addr`),
      which this supervisor sets from the entry before starting the child. It is
      registered in `Registry.SIPTransport` under `"UDP"`, i.e. **the name
      `SIP.Transport.Selector` looks up for outbound UDP**, so outbound requests
      reuse this socket instead of trying to bind the same port a second time.
    * `tcp` / `tls` / `wss` — the matching `SIP.Transport.*Listener`, which binds
      the socket and spawns one transport process per accepted connection.
      `tls`/`wss` receive their **per-listener** cert/key (design §3.1) as
      `:certfile`/`:keyfile` opts, instead of the framework-wide `:tls_certfile`
      default.

  A listener that fails to bind (port busy, unreadable cert) aborts the boot —
  fail fast, like an invalid config, so systemd reports a failed start rather than
  a half-deaf server.

  **One UDP socket per node** for now: the framework binds a single UDP port
  (`:udp_local_port`), so extra `udp` entries are logged and skipped.
  """
  use Supervisor
  require Logger

  @udp_registry_key "UDP"

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
    listeners
    |> drop_extra_udp()
    |> Enum.map(&child_spec_for/1)
  end

  defp child_spec_for(%{proto: :udp, addr: addr, port: port} = l) do
    # The UDP transport reads its bind port/addr from the app env (it is also the
    # outbound transport, so the socket is shared). Set them before it starts.
    Application.put_env(:elixip2, :udp_local_port, port)
    if bind_addr(l) != :all, do: Application.put_env(:elixip2, :udp_local_addr, bind_addr(l))

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
              {bind_addr(l), port},
              [name: {:via, Registry, {Registry.SIPTransport, @udp_registry_key}}]
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
          "kelixip: cannot bind the #{proto} listener on #{addr}:#{port}: #{inspect(reason)}"
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

  # One UDP socket per node (framework limitation): keep the first udp entry.
  defp drop_extra_udp(listeners) do
    {udp, others} = Enum.split_with(listeners, &(&1.proto == :udp))

    case udp do
      [_first | [_ | _] = extra] ->
        Logger.warning(
          module: __MODULE__,
          message:
            "only one udp listener is supported (one socket per node); ignoring " <>
              Enum.map_join(extra, ", ", &"udp:#{&1.addr}:#{&1.port}")
        )

      _ ->
        :ok
    end

    Enum.take(udp, 1) ++ others
  end

  defp listen_from_config() do
    if Process.whereis(Kelix.Config), do: Kelix.Config.current().listen, else: []
  end
end
