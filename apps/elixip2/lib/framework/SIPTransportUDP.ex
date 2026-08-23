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

  @impl true
  def init({_dest_ip, _dest_port}) do
    try do
      # Local bind port and advertised local IP are configurable via the
      # application env (set by elixipp's --listen / --local-port options), so
      # two instances can coexist on one host (e.g. a UAS on 5060 and a UAC on
      # 5070 for a loopback test). Defaults preserve the historical behaviour
      # (bind 5060, advertise the first local IPv4). The socket binds all
      # interfaces; :udp_local_addr only sets the IP advertised in Via/Contact.
      #
      # The family comes from the configured address when there is one, else from
      # :udp_family. Deriving it is what lets this transport start on a host that
      # carries no IPv4 at all; the socket itself stays IPv4 until step 3 of
      # docs/design/multi-interface.md.
      port = Application.get_env(:elixip2, :udp_local_port, @default_local_port)
      configured_ip = Application.get_env(:elixip2, :udp_local_addr)

      family =
        SIP.NetUtils.address_family(configured_ip) ||
          Application.get_env(:elixip2, :udp_family, :ipv4)

      ips = SIP.NetUtils.get_local_ips([family])

      case configured_ip || List.first(ips) do
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

          case Socket.UDP.open(port, mode: :active) do
            {:ok, socket} ->
              :ok = Socket.UDP.process(socket, self())
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

  # A bind failure aborts the boot, so the log line is the operator's whole
  # diagnosis: spell the posix reason out instead of leaving a bare atom, and for
  # the overwhelmingly common one say what to look for. The socket binds EVERY
  # interface (`:udp_local_addr` only sets the IP advertised in Via/Contact), so it
  # collides with another process even when that one bound a single address.
  defp bind_error(:eaddrinuse) do
    ":eaddrinuse (address already in use) — another process holds this UDP port. " <>
      "Note this socket binds every interface, so it also collides with a process " <>
      "bound to one specific address on that port (check `ss -ulnp`)."
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
