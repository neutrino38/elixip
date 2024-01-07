defmodule SIP.Test.Transport.UDPMockup do
  @moduledoc """
  Mockup for transport module
  """
  use GenServer
  require Logger
  require SIP.Transac
  require SIPMsg
  import SIPMsgOps

  # @destproxy "1.2.3.4"
  # @destport 5080
#  @ringing_time 2000

  @transport_str "udp"
  def transport_str, do: @transport_str

  def is_reliable, do: false

  # Simulated call scenarii

  def simulate_successful_answer(t_pid) do
    GenServer.cast(t_pid, {:simulate, 100, 200})
  end


  # Callbacks


  @impl true
  def init(nil) do
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
        { :ok, sipreq } -> { :reply, :ok, Map.put(state, :req, sipreq) }
        _ ->  { :reply, :invalidreq, state }
      end
  end

  # Obtain localip and port values
  def handle_call(:getlocalipandport, _from, state) do
    { :reply, { :ok, state.localip, state.localport }, state}
  end

  # Simulate Answers
  @impl true
  @spec handle_cast({:simulate, 100, non_neg_integer()}, map()) :: { :noreply, map() }
  def handle_cast( { :simulate, 100, after_ms }, state) do
    siprsp = reply_to_request(state.req, 100, "Trying")
    Process.send_after(self(), { :recv, siprsp }, after_ms)
    { :noreply,  state}
  end

  @spec handle_cast({:simulate, 180, non_neg_integer()}, map()) :: { :noreply, map() }
  def handle_cast( { :simulate, 180, after_ms }, state) do
    siprsp = reply_to_request(state.req, 180, "Ringing")
    Logger.debug([transid: state.req.transid, module: SIP.Test.Transport.UDPMockup,
                 message: "Simulating a 180 Ringing after #{after_ms} ms."])

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
          # We received the 100 Trying -- simulate a 180 ringing after some time
          GenServer.cast(self(), { :simulate, 180, 200 })

      _ -> nil
    end
    { :noreply,  state }
  end
end
