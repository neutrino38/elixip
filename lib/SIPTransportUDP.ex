defmodule SIP.Transport.UDP do
  use GenServer
  require Logger
  require Socket

  @transport_str "udp"
  @default_local_port 5060
  def transport_str, do: @transport_str

  @spec is_reliable() :: boolean()
  def is_reliable, do: false


  @impl true
  def init({ _dest_ip, _dest_port}) do
    ips = SIP.NetUtils.get_local_ips( [ :ipv4 ] )

    initial_state = %{ t_isreliable: false, localip: hd(ips), localips: ips, localport: @default_local_port }
    {:ok, socket} = :gen_udp.open(@default_local_port, [:binary, active: true])
    initial_state = Map.put(initial_state, :socket, socket)
    { :ok, initial_state }
  end

  @impl true
  def handle_call({ :sendmsg, msgstr, destip, dest_port }, _from, state) do
    destipstr = case SIP.NetUtils.ip2string(destip) do
      { :error, :einval } ->
        Logger.error([module: SIP.Test.Transport.UDPMockup, message: "sendmsg: invalid destination address."])
        IO.inspect(destip)
        raise "UDP: invalid IP address"
        ipstr when is_binary(ipstr)-> ipstr
    end
    Logger.debug("UDP: Message sent to #{destipstr}:#{dest_port} ---->\r\n" <> msgstr <> "\r\n-----------------")
    :gen_udp.send(state.socket, msgstr, destip, dest_port)
  end

# Receving an UDP datagram
  @impl true
  def handle_info({:udp, _socket, ip, port, message}, state) do
    case SIP.Transac.process_sip_message(message) do
      :ok -> { :noreply, state }

      { :no_matching_transaction, parsed_msg } ->
        if is_atom(parsed_msg.method) do
          # We need to start a new transaction
          SIP.Transac.start_uas_transaction(parsed_msg, { state.localip, state.localport, "UDP", SIP.Transport.UDP, self() } , { ip, port })
        else
          Logger.error("Received a SIP #{parsed_msg.response} response from #{ip}:#{port} not linked to any transaction. Droping it")
          { :noreply, state }
        end

      _ ->
        Logger.error("Received an invalid SIP message from #{ip}:#{port}")
        { :noreply, state }
    end
  end

  @impl true
  def terminate(_reason, state) do
    if not is_nil(state.socket) do
      :gen_udp.close(state.socket)
    end
  end
end
