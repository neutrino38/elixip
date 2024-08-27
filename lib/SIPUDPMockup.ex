defmodule SIP.Test.Transport.UDPMockup do
  @moduledoc """
  Mockup for transport module
  """
  alias SIP.NetUtils
  use GenServer
  require Logger
  require SIP.Transac
  require SIPMsg
  import SIP.Msg.Ops

  # @destproxy "1.2.3.4"
  # @destport 5080
#  @ringing_time 2000

  @transport_str "udp"
  def transport_str, do: @transport_str

  @spec is_reliable() :: boolean()
  def is_reliable, do: false

  def select_instance(_ruri) do

  end

  # Simulated call scenarii

  def simulate_successful_answer(t_pid) do
    GenServer.cast(t_pid, {:simulate, :successfulcall})
  end

  def simulate_noanswer_answer(t_pid) do
    GenServer.cast(t_pid, {:simulate, :noanswer})
  end

  @spec simulate_busy_answer(pid()) :: :ok
  def simulate_busy_answer(t_pid) do
    GenServer.cast(t_pid, {:simulate, :busy})
  end


  defp handle_req(state, :INVITE, sipreq) do
    Map.put(state, :req, sipreq)
  end

  defp handle_req(state, :ACK, _sipreq) do
    if Map.has_key?(state, :req) and state.req.method == INVITE do
      Map.delete(state, :req)
    else
      state
    end
  end

  defp handle_req(state, :CANCEL, sipreq) do
    if Map.has_key?(state, :req) do
      if sipreq.transid == state.req.transid do
        # Simulate cancellig
        siprsp = reply_to_request(sipreq, 200, "OK")
        Process.send_after(self(), { :recv, siprsp }, 100)
        siprsp2 = reply_to_request(sipreq, 487, nil)
        Process.send_after(self(), { :recv, siprsp2 }, 200)
      end

      state
    else
      siprsp = reply_to_request(sipreq, 481, "No such transaction")
      Process.send_after(self(), { :recv, siprsp }, 100)
      state
    end

  end

  defp handle_req(state, _method, _sipreq) do
    state
  end

  defp handle_resp(state, _code, _sipresp) do
    state
  end

  # Callbacks


  @impl true
  def init({ _dest_ip, _dest_port}) do
    ips = SIP.NetUtils.get_local_ips( [ :ipv4 ] )
    initial_state = %{ t_isreliable: false, localip: hd(ips), localport: 5060 }
    { :ok, initial_state }
  end

  @impl true
  def handle_call({ :sendmsg, msgstr, destip, dest_port }, _from, state) do
    destipstr = case SIP.NetUtils.ip2string(destip) do
      { :error, :einval } ->
        Logger.error([module: SIP.Test.Transport.UDPMockup, message: "sendmsg: invalid destination address."])
        IO.inspect(destip)
        raise "UDPMockup: invalid IP address"
      ipstr when is_binary(ipstr)-> ipstr
    end
    Logger.debug("UDPMockup: Message sent to #{destipstr}:#{dest_port} ---->\r\n" <> msgstr <> "\r\n-----------------")
    case SIPMsg.parse(msgstr, fn code, errmsg, lineno, line ->
			IO.puts("\n" <> errmsg)
			IO.puts("Offending line #{lineno}: #{line}")
			IO.puts("Error code #{code}")
			end) do
        { :ok, sipmsg } ->
          case sipmsg.method do
            false ->
              { :reply, :ok, handle_resp(state, sipmsg.response, sipmsg) }

            method ->
              { :reply, :ok, handle_req(state, method, sipmsg) }

          end
        _ ->  { :reply, :invalidreq, state }
      end
  end

  # Obtain localip and port values
  def handle_call(:getlocalipandport, _from, state) do
    { :reply, { :ok, state.localip, state.localport }, state}
  end

  # Simulate call scenario
  @impl true
  @spec handle_cast({:simulate, 100, non_neg_integer()}, map()) :: { :noreply, map() }
  def handle_cast( { :simulate, 100, after_ms }, state) do
    siprsp = reply_to_request(state.req, 100, "Trying")
    Process.send_after(self(), { :recv, siprsp }, after_ms)
    { :noreply,  state }
  end

  def handle_cast({ :simulate, scenario }, state) when is_atom(scenario) do

    new_state = Map.put(state, :scenario, scenario)
    case scenario do
      :successfulcall -> handle_cast({:simulate, 100, 200}, new_state)
      :busy -> handle_cast({:simulate, 100, 200}, new_state)
      :notregistered -> handle_cast({:simulate, 100, 200}, new_state)
    end
  end

  @spec handle_cast({:simulate, 180, non_neg_integer()}, map()) :: { :noreply, map() }
  def handle_cast( { :simulate, 180, after_ms }, state) do
    siprsp = reply_to_request(state.req, 180, "Ringing", [], "as424e7930")
    Logger.debug([transid: state.req.transid, module: SIP.Test.Transport.UDPMockup,
                 message: "Simulating a 180 Ringing after #{after_ms} ms."])

    Process.send_after(self(), { :recv, siprsp }, after_ms)
    { :noreply,  state}
  end

  def handle_cast( { :simulate, 200, after_ms }, state) do
    sdp_body = %{ contenttype: "application/sdp", data: "blablabla\r\n" }
    siprsp = reply_to_request(state.req, 200, "OK", [body: [ sdp_body ], contact: "<sip:90901@212.83.152.250:5090>" ], "as424e7930")
    Logger.debug([transid: state.req.transid, module: SIP.Test.Transport.UDPMockup,
                 message: "Simulating a 200 Ringing after #{after_ms} ms."])

    Process.send_after(self(), { :recv, siprsp }, after_ms)
    { :noreply,  state}
  end

  def handle_cast( {:simulate, resp, after_ms }, state) when resp in 400..487 do
    siprsp = reply_to_request(state.req, resp, nil, [], "as424e7930")

    Logger.debug([transid: state.req.transid, module: SIP.Test.Transport.UDPMockup,
                 message: "Simulating a #{resp} Answer #{after_ms} ms."])

    Process.send_after(self(), { :recv, siprsp }, after_ms)
    { :noreply,  state}
  end

  @impl true

  # Handle 100 Trying
  def handle_info({ :recv, siprsp}, state) when siprsp.response == 100 do
    Logger.debug([transid: state.req.transid, module: SIP.Test.Transport.UDPMockup,
    message: "Received SIP resp #{siprsp.response} scenario #{state.scenario}"])
    SIP.Transac.process_sip_message(SIPMsg.serialize(siprsp))
    case state.scenario do
      :successfulcall ->
        # We received the 100 Trying -- simulate a 180 ringing after some time
        GenServer.cast(self(), { :simulate, 180, 200 })

      :notregistered ->
        # answer with 480 Temporary Unavailable
        GenServer.cast(self(), { :simulate, 480, 200 })

      :busy ->
        # We received the 100 Trying -- simulate a 180 ringing after some time
        # then simulate 486 Busy sent by the user
        GenServer.cast(self(), { :simulate, 180, 200 })

      :noanswer ->
          # We received the 100 Trying -- simulate a 180 ringing after some time
          # then simulate 486 Busy sent by the user
          GenServer.cast(self(), { :simulate, 180, 200 })

      _ ->
        Logger.warning( [ module: SIP.Test.Transport.UDPMockup, message: "Unidentified SIP scenario #{state.scenario}"])
        GenServer.cast(self(), { :simulate, 404, 200 })
    end
    { :noreply,  state }
  end

   # Handle 180 Ringing
  def handle_info({ :recv, siprsp}, state) when siprsp.response == 180 do
    Logger.debug([transid: state.req.transid, module: SIP.Test.Transport.UDPMockup,
    message: "Received SIP resp #{siprsp.response} scenario #{state.scenario}"])
    SIP.Transac.process_sip_message(SIPMsg.serialize(siprsp))
    case state.scenario do
      :successfulcall ->
        # We received the 180 Ringing -- simulate a 200 OK after some time
        GenServer.cast(self(), { :simulate, 200, 4000 })

      :noanswer ->
        GenServer.cast(self(), { :simulate, 408, 2000 })

      :busy ->
        GenServer.cast(self(), { :simulate, 486, 2000 })

    end
    { :noreply,  state }
  end

  # Include case with 486, 487
  def handle_info({ :recv, siprsp}, state) when is_integer(siprsp.response) do
    Logger.debug([transid: state.req.transid, module: SIP.Test.Transport.UDPMockup,
    message: "Received SIP resp #{siprsp.response} scenario #{state.scenario}"])
    SIP.Transac.process_sip_message(SIPMsg.serialize(siprsp))

    { :noreply,  state }
  end

  def handle_info({ :recv, sipreq}, state) when sipreq.method == :REGISTER do
    Logger.debug([transid: state.req.transid, module: SIP.Test.Transport.UDPMockup,
    message: "Received SIP REGISTER in scenario #{state.scenario}"])

    # Simulate remote IP
    { :ok, ip } = NetUtils.parse_address("82.184.8.2")
    port = 53936
    case SIP.Transac.process_sip_message(SIPMsg.serialize(sipreq)) do
      :ok -> { :noreply, state }

      { :no_matching_transaction, parsed_msg } ->
        # We need to start a new transaction
        SIP.Transac.start_uas_transaction(parsed_msg, { state.localip, state.localport, "UDP", SIP.Test.Transport.UDPMockup, self() } , { ip, port })

      _ ->
        Logger.error("Received an invalid SIP message from #{ip}:#{port}")
        { :noreply, state }
    end
    { :noreply,  state }
  end

end
