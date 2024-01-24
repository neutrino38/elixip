defmodule SIP.Test.Transport.UDPMockup do
  @moduledoc """
  Mockup for transport module
  """
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

  def simulate_busy_answer(t_pid) do
    GenServer.cast(t_pid, {:simulate, :busy})
  end

  # Callbacks


  @impl true
  def init({ _dest_ip, _dest_port}) do
    ips = SIP.NetUtils.get_local_ips( [ :ipv4 ] )
    initial_state = %{ t_isreliable: false, localip: hd(ips), localport: 5060 }
    { :ok, initial_state }
  end

  @impl true
  def handle_call({ :sendmsg, msgstr }, _from, state) do
    Logger.debug("Transport mockeup: Message sent ---->\r\n" <> msgstr <> "\r\n-----------------")
    case SIPMsg.parse(msgstr, fn code, errmsg, lineno, line ->
			IO.puts("\n" <> errmsg)
			IO.puts("Offending line #{lineno}: #{line}")
			IO.puts("Error code #{code}")
			end) do
        { :ok, sipreq } ->
          if sipreq.method == :INVITE do
            { :reply, :ok, Map.put(state, :req, sipreq) }
          else
            { :reply, :ok, state }
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

  def handle_cast({ :simulate, scenario }, state) do

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
    siprsp = reply_to_request(state.req, 200, nil, [], "as424e7930")

    Logger.debug([transid: state.req.transid, module: SIP.Test.Transport.UDPMockup,
                 message: "Simulating a #{resp} Answer #{after_ms} ms."])

    Process.send_after(self(), { :recv, siprsp }, after_ms)
    { :noreply,  state}
  end

  @impl true
  def handle_info({ :recv, siprsp}, state) do
    Logger.debug([transid: state.req.transid, module: SIP.Test.Transport.UDPMockup,
    message: "Received SIP resp #{siprsp.response}."])

    SIP.Transac.process_sip_message(SIPMsg.serialize(siprsp))
    case siprsp.response do
      100 ->
          case state.scenario do
            :successfulcall ->
              # We received the 100 Trying -- simulate a 180 ringing after some time
              GenServer.cast(self(), { :simulate, 180, 200 })

            :notregistered ->
              # answer with 480 Temporary Unavailable
              GenServer.cast(self(), { :simulate, 480, 200 })

            :busy
              # We received the 100 Trying -- simulate a 180 ringing after some time
              # then simulate 486 Busy sent by the user
              GenServer.cast(self(), { :simulate, 180, 200 })

            _ ->
              GenServer.cast(self(), { :simulate, 404, 200 })
          end

      180 ->
        case state.scenario do
          :successfulcall ->
            # We received the 180 Ringing -- simulate a 200 OK after some time
            GenServer.cast(self(), { :simulate, 200, 4000 })

          :busy ->
            GenServer.cast(self(), { :simulate, 486, 2000 })

          end
      _ -> nil
    end
    { :noreply,  state }
  end
end
