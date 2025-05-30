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
  def init({ _dest_ip, _dest_port}) do
    try do
      # TODO support for IPV6
      ips = SIP.NetUtils.get_local_ips( [ :ipv4 ] )
      if ips == [] do
        Logger.error([module: SIP.Test.Transport.UDP,
                      message: "Could not find any valid IP V4 address. Check your network connection"])
        { :stop, :networkdown }
      else
        initial_state = %{ t_isreliable: false, localip: hd(ips), localips: ips,
                        localport: @default_local_port, upperlayer: nil }
        case  Socket.UDP.open(@default_local_port, [mode: :active]) do
          {:ok, socket} ->
            :ok = Socket.UDP.process(socket, self())
            { :ok, Map.put(initial_state, :socket, socket) }

          { :error, err } ->
            Logger.error("Failed to create UDP socket on port #{@default_local_port}.")
            { :stop, err }
        end
      end
    rescue
      err in RuntimeError ->
        Logger.error("Failed to start UDP transport.")
        Logger.error(Exception.format(:error, err, __STACKTRACE__))
        { :stop, :failedtostart }
    end
  end

  @impl true
  @spec handle_call(  {:sendmsg, binary(), :inet.ip_address(), :inet.port_number }, any(), map() ) ::  { :reply, :ok, map() }
  def handle_call({ :sendmsg, msgstr, destip, dest_port }, _from, state) do
    destipstr = case SIP.NetUtils.ip2string(destip) do
      { :error, :einval } ->
        Logger.error([module: SIP.Test.Transport.UDP, message: "sendmsg: invalid destination address."])
        IO.inspect(destip)
        raise "UDP: invalid IP address"
      ipstr when is_binary(ipstr)-> ipstr
    end

    Logger.debug("UDP: Message sent to #{destipstr}:#{dest_port} ---->\r\n" <> msgstr <> "\r\n-----------------")
    case Socket.Datagram.send(state.socket, msgstr, { destip, dest_port }) do
      :ok -> { :reply, :ok, state }
      { :error, reason } ->
        Logger.debug("UDP: failed to send message. Error: #{reason}");
        { :reply, :transporterror, state }
    end
  end

  def handle_call(:getlocalipandport, _from, state) do
    { :reply, { :ok, state.localip, state.localport }, state}
  end

  # Set the upper layer handler for transactions to process
  def handle_call( {:setupperlayer, ul_pid }, _from, state) when is_pid(ul_pid) do
    { :reply, :ok, Map.put(state, :upperlayer, ul_pid) }
  end

  def handle_call( {:setupperlayer, ul_func }, _from, state) when is_function(ul_func, 2) do
    { :reply, :ok, Map.put(state, :upperlayer, ul_func) }
  end

  def handle_call( {:setupperlayer, nil }, _from, state) do
    { :reply, :ok, Map.put(state, :upperlayer, nil) }
  end

# Receving an UDP datagram
  @impl true
  def handle_info({:udp, socket, ip, port, message}, state) do
    SIP.Transport.ImplHelpers.process_incoming_message(state, message, @transport_str, __MODULE__, socket, ip, port)
  end

  @impl true
  def terminate(_reason, state) do
    if not is_nil(state.socket) do
      Socket.close(state.socket)
    end
  end
end
