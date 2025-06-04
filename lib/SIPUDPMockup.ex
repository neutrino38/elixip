defmodule SIP.Test.Transport.UDPMockup do
  @moduledoc """
  Mockup for transport module for unit testing
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

  def simulate_challenge(t_pid) do
    GenServer.cast(t_pid, {:simulate, :challenge})
  end


  def simulate_successful_register(t_pid) do
    GenServer.cast(t_pid, {:simulate, :successfulregister})
  end
  defp handle_req(state, :INVITE, sipreq) do
    Map.put(state, :req, sipreq)
  end

  defp handle_req(state, :REGISTER, sipreq) do
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

  defp handle_req(state, :BYE, sipreq) do
    if state.scenario in [ :inboundinvite ] do
      # Handle the BYE request and answers it
      resp = SIP.Msg.Ops.reply_to_request(sipreq, 200, "OK")
      Process.send_after(self(), { :recv, resp }, 100)
      Logger.debug("UDPMockup: replied to BYE")

      # Forward event to the test process
      if state.testapppid != nil do
        send(state.testapppid, :BYE)
      end
    end
    state
  end

  defp handle_req(state, _method, _sipreq) do
    state
  end

  defp handle_resp(state, code, _sipresp) do
    if state.scenario == :inboundinvite and state.testapppid != nil do
      # Forward event to the test process
      case code do
        200 -> send(state.testapppid, code)
        486 -> send(state.testapppid, code)
        _ -> nil
      end
    end
    state
  end

  # Callbacks


  @impl true
  def init({ _dest_ip, _dest_port}) do
    ips = SIP.NetUtils.get_local_ips( [ :ipv4 ] )
    if ips == [] do
      Logger.error([module: SIP.Test.Transport.UDPMockup, message: "Could not find any valid IP V4 address. Check your network connection"])
      { :stop, :networkdown }
    else
      initial_state = %{ t_isreliable: false, localip: hd(ips), localport: 5060, upperlayer: nil, testapppid: nil }
      { :ok, initial_state }
    end
  end

  @impl true
  def handle_call({ :sendmsg, msgstr, destip, dest_port }, _from, state) do
    destipstr = case SIP.NetUtils.ip2string(destip) do
      { :error, :einval } ->
        Logger.error([module: SIP.Test.Transport.UDPMockup, message: "sendmsg: invalid destination address #{inspect(destip)}."])

        raise "UDPMockup: invalid IP address"
      ipstr when is_binary(ipstr)-> ipstr
    end

    Logger.debug("UDPMockup: Message sent to #{destipstr}:#{dest_port} ---->\r\n" <> msgstr <> "\r\n-----------------")
    case SIPMsg.parse(msgstr, fn code, errmsg, lineno, line ->
			Logger.error("UDPMockup: failed to parse sent msg:" <> errmsg)
			Logger.debug("UDPMockup: Offending line #{lineno}: #{line}")
			Logger.debug("UDPMockup: Error code #{code}")
			end) do
        { :ok, sipmsg } ->
          case sipmsg.method do
            false ->
              { :reply, :ok, handle_resp(state, sipmsg.response, sipmsg) }

            method ->
              { :reply, :ok, handle_req(state, method, sipmsg) }

          end

        err ->
          Logger.error("UDPMockup: failed to parse sent msg: #{inspect(err)}")
          { :reply, :transporterror, state }
      end
  end

  # Obtain localip and port values
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

  def handle_call( :settestapp, { pid, _ref }, state) do
    { :reply, :ok, Map.put(state, :testapppid, pid) }
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
      :successfulregister -> handle_cast({:simulate, 200, 200}, new_state)
      :busy -> handle_cast({:simulate, 100, 200}, new_state)
      :notregistered -> handle_cast({:simulate, 100, 200}, new_state)
      :challenge -> handle_cast({:simulate, 401, 200}, new_state)
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

  @spec handle_cast({:simulate, 200, non_neg_integer()}, map()) :: { :noreply, map() }
  def handle_cast( { :simulate, 200, after_ms }, state) do
    siprsp = if state.req.method == :INVITE do
      #invite case
      sdp_body = %{ contenttype: "application/sdp", data: "blablabla\r\n" }
      reply_to_request(state.req, 200, "OK", [body: [ sdp_body ], contact: "<sip:90901@212.83.152.250:5090>" ], "as424e7930")
    else
      # register case
      reply_to_request(state.req, 200, "OK", [ contact: state.req.contact ], "as424e7930")
    end
    Logger.debug([transid: state.req.transid, module: SIP.Test.Transport.UDPMockup,
                 message: "Simulating a 200 OK after #{after_ms} ms."])

    Process.send_after(self(), { :recv, siprsp }, after_ms)
    { :noreply,  state}
  end

  @spec handle_cast({:simulate, 401 | 407, non_neg_integer()}, map()) :: { :noreply, map() }
  def handle_cast( { :simulate, resp , after_ms }, state) when resp in [ 401, 407 ] do
    siprsp = SIP.Msg.Ops.challenge_request(state.req, resp, "Digest", "elioz.net", "SHA256", [], "as424e7930" )
    Logger.debug([transid: state.req.transid, module: SIP.Test.Transport.UDPMockup,
                 message: "Simulating a #{resp} Digest challenge after #{after_ms} ms."])

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


  defp set_inbound_scenario(state, sipreq) when sipreq.method == :REGISTER do
    Map.put(state, :req, sipreq) |> Map.put(:scenario, :inboundregister)
  end

  defp set_inbound_scenario(state, sipreq) when sipreq.method == :INVITE do
    Map.put(state, :req, sipreq) |> Map.put(:scenario, :inboundinvite)
  end

  defp set_inbound_scenario(state, sipreq) when is_atom(sipreq.method) do
    state
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

  def handle_info({ :recv, sipreq}, state) when is_atom(sipreq.method) do
    state = set_inbound_scenario(state, sipreq)
    Logger.debug([transid: sipreq.transid, module: SIP.Test.Transport.UDPMockup,
                 message: "Received SIP #{sipreq.method} in scenario #{state.scenario}"])

    # Simulate remote IP
    { :ok, ip } = NetUtils.parse_address("82.184.8.2")
    port = 53936
    SIP.Transport.ImplHelpers.process_incoming_message(
      state, SIPMsg.serialize(sipreq), "UDP", __MODULE__, { { 1,2,3,4 }, 5080}, ip, port)
  end

end
