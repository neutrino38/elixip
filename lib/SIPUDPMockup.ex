defmodule SIP.Test.Transport.UDPMockup do
  @moduledoc """
  Mockup for transport module
  """
  use GenServer
  require Logger
  require SIP.Transac
  import SIPMsgOps

  @destproxy "1.2.3.4"
  @destport 5080

  @transport_str "udp"
  def transport_str, do: @transport_str

  def is_reliable, do: false

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
    { :reply, :ok, state}
  end

  # Obtain localip and port values
  def handle_call(:getlocalipandport, _from, state) do
    { :reply, { :ok, state.localip, state.localport }, state}
  end

  @impl true
  @spec handle_cast({:simulate, 100, map(), non_neg_integer()}, map()) :: { :noreply, map() }
  def handle_cast( { :simulate, 100, sipreq, after_ms }, state) do
    siprsp = reply_to_request(sipreq, 100, "Trying")
    Process.send_after(self(), { :simu, siprsp }, after_ms)
    { :noreply,  state}
  end

  def handle_cast( { :simulate, 180, sipreq, after_ms }, state) do
    siprsp = reply_to_request(sipreq, 180, "Ringing")
    Process.send_after(self(), { :simu, siprsp }, after_ms)
    { :noreply,  state}
  end

  @impl true
  def handle_info({ :simu, siprsp}, state) do
    SIP.Transac.process_sip_message(SIPMsg.serialize(siprsp))
    state
  end
end
