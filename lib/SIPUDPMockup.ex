defmodule SIP.Test.Transport.UDPMockup do
  @moduledoc """
  Mockup for transport module
  """
  use GenServer
  require Logger
  require SIP.Transac
  import SIPMsgOps

   # Callbacks

  @remote_ip "200.1.2.3"
  @remote_port 5080

  @impl true
  def init(nil) do
    initial_state = %{ t_isreliable: false }
    { :ok, initial_state }
  end

  @impl true
  def handle_call({ :sendmsg, msgstr }, _from, state) do
    Logger.debug("Transport mockeup: Message sent ---->\r\n" <> msgstr <> "\r\n-----------------")
    { :reply, :ok, state}
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
