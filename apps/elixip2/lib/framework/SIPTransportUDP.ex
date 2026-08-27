defmodule SIP.Transport.UDP do
  use GenServer
  require Logger
  require Socket.UDP
  require SIP.Transport.ImplHelpers

  @transport_str "udp"
  @default_local_port 5060
  def transport_str, do: @transport_str

  @spec is_reliable() :: boolean()
  def is_reliable, do: false

  @doc """
  Two start shapes.

    * `{:bind, bind_ip, port, opts}` — an explicit socket: a kelixip `[[listen]]
      udp` block, an elixipp `--listen udp:PORT`. `bind_ip` is an address or
      `:all`; with `:all` the family comes from `opts[:family]`.
    * `{dest_ip, dest_port}` — what `SIP.Transport.Selector` starts for an
      outbound request. Only the destination's **family** is read from it: it
      names which socket can source the datagram. The bind address and port come
      from the app env.

  A node holds one socket per family, registered under distinct names
  (`SIP.Transport.Selector.unreliable_instance_name/2`), so both shapes can be
  live at once.
  """
  @impl true
  def init({:bind, bind_ip, port, opts}) do
    family =
      SIP.NetUtils.address_family(bind_ip) || Keyword.get(opts, :family) ||
        SIP.NetUtils.preferred_family()

    open_socket(
      if(bind_ip == :all, do: nil, else: bind_ip),
      port,
      family,
      Keyword.get(opts, :advertise)
    )
  end

  def init({dest_ip, dest_port, _domain}), do: init({dest_ip, dest_port})

  def init({dest_ip, _dest_port}) do
    # Local bind port and address are configurable via the application env (set
    # by elixipp's --listen / --local-port options and by kelixip's [[listen]]
    # block), so two instances can coexist on one host (e.g. a UAS on 5060 and
    # a UAC on 5070 for a loopback test). :udp_local_addr binds the socket AND
    # is the address advertised in Via/Contact; without it the socket binds
    # every interface of the family and advertises the first local address.
    port = Application.get_env(:elixip2, :udp_local_port, @default_local_port)
    configured_ip = Application.get_env(:elixip2, :udp_local_addr)
    family = SIP.NetUtils.address_family(dest_ip) || SIP.NetUtils.preferred_family()

    # The configured address binds this socket only when it is of the destination's
    # family. A node given one address still has to source the other family from
    # somewhere, and that somewhere is the wildcard.
    bind_ip = if SIP.NetUtils.address_family(configured_ip) == family, do: configured_ip

    open_socket(bind_ip, port, family)
  end

  # `advertise` is the address this socket PUBLISHES when it is not the one it
  # binds — a 1:1 NAT, where the host holds a private address and peers reach a
  # public one. It changes `localip`, which is what Via and Contact are built from
  # and what the media layer reads as the address a peer reached, and nothing else:
  # the socket still binds `bind_ip`.
  defp open_socket(bind_ip, port, family, advertise \\ nil) do
    try do
      ips = SIP.NetUtils.get_local_ips([family])

      case advertise || bind_ip || List.first(ips) do
        nil ->
          Logger.error(
            module: __MODULE__,
            message:
              "Could not find any local #{family} address to advertise. " <>
                "Check your network connection."
          )

          {:stop, :networkdown}

        localip ->
          initial_state = %{
            t_isreliable: false,
            localip: localip,
            localips: ips,
            localport: port,
            upperlayer: nil
          }

          case Socket.UDP.open(port, open_options(bind_ip, family)) do
            {:ok, socket} ->
              :ok = Socket.UDP.process(socket, self())

              # Say so, like the three connection-oriented listeners do. This socket
              # announces the address every Via and Contact of its family will carry,
              # so an operator reading the boot log must be able to see which address
              # and which family it took.
              Logger.info(
                module: __MODULE__,
                message: "UDP transport bound on #{SIP.NetUtils.sip_host(localip)}:#{port}"
              )

              {:ok, Map.put(initial_state, :socket, socket)}

            {:error, err} ->
              Logger.error(
                module: __MODULE__,
                message: "Failed to bind UDP socket on port #{port}: #{bind_error(err)}"
              )

              {:stop, err}
          end
      end
    rescue
      err in RuntimeError ->
        Logger.error("Failed to start UDP transport.")
        Logger.error(Exception.format(:error, err, __STACKTRACE__))
        {:stop, :failedtostart}
    end
  end

  # `v6only` keeps a wildcard v6 socket from also accepting IPv4 as `::ffff:`
  # mapped addresses, which every place that writes an address into a SIP message
  # would then carry. It is also what lets the two families share a port at all:
  # a dual-stack v6 wildcard claims the v4 port too, so the second bind of a
  # node's pair comes back :eaddrinuse.
  defp open_options(bind_ip, family) do
    [as: :binary, mode: :active] ++ family_options(family) ++ bind_options(bind_ip)
  end

  defp family_options(:ipv6), do: [version: 6, v6only: true]
  defp family_options(_family), do: [version: 4]

  defp bind_options(nil), do: []
  defp bind_options(bind_ip), do: [local: [address: bind_ip]]

  # A bind failure aborts the boot, so the log line is the operator's whole
  # diagnosis: spell the posix reason out instead of leaving a bare atom, and for
  # the overwhelmingly common one say what to look for. Without `:udp_local_addr`
  # the socket binds EVERY interface, so it collides with another process even
  # when that one bound a single address.
  defp bind_error(:eaddrinuse) do
    ":eaddrinuse (address already in use) — another process holds this UDP port. " <>
      "Without a configured local address this socket binds every interface, so it " <>
      "also collides with a process bound to one specific address on that port " <>
      "(check `ss -ulnp`)."
  end

  defp bind_error(reason) when is_atom(reason) do
    "#{inspect(reason)} (#{:inet.format_error(reason)})"
  end

  defp bind_error(reason), do: inspect(reason)

  @impl true
  @spec handle_call({:sendmsg, binary(), :inet.ip_address(), :inet.port_number()}, any(), map()) ::
          {:reply, :ok, map()}
  def handle_call({:sendmsg, msgstr, destip, dest_port}, _from, state) do
    destipstr =
      case SIP.NetUtils.ip2string(destip) do
        {:error, :einval} ->
          Logger.error(
            module: SIP.Test.Transport.UDP,
            message: "sendmsg: invalid destination address."
          )

          IO.inspect(destip)
          raise "UDP: invalid IP address"

        ipstr when is_binary(ipstr) ->
          ipstr
      end

    Logger.debug(
      "UDP: Message sent to #{destipstr}:#{dest_port} ---->\r\n" <>
        msgstr <> "\r\n-----------------"
    )

    case Socket.Datagram.send(state.socket, msgstr, {destip, dest_port}) do
      :ok ->
        {:reply, :ok, state}

      {:error, reason} ->
        Logger.debug("UDP: failed to send message. Error: #{reason}")
        {:reply, :transporterror, state}
    end
  end

  def handle_call(:getlocalipandport, _from, state) do
    {:reply, {:ok, state.localip, state.localport}, state}
  end

  # Set the upper layer handler for transactions to process
  def handle_call({:setupperlayer, ul_pid}, _from, state) when is_pid(ul_pid) do
    {:reply, :ok, Map.put(state, :upperlayer, ul_pid)}
  end

  def handle_call({:setupperlayer, ul_func}, _from, state) when is_function(ul_func, 2) do
    {:reply, :ok, Map.put(state, :upperlayer, ul_func)}
  end

  def handle_call({:setupperlayer, nil}, _from, state) do
    {:reply, :ok, Map.put(state, :upperlayer, nil)}
  end

  # Receving an UDP datagram
  @impl true
  def handle_info({:udp, socket, ip, port, message}, state) do
    SIP.Transport.ImplHelpers.process_incoming_message(
      state,
      message,
      @transport_str,
      __MODULE__,
      socket,
      ip,
      port
    )
  end

  @impl true
  def terminate(_reason, state) do
    if not is_nil(state.socket) do
      Socket.close(state.socket)
    end
  end
end
