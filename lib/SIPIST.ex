defmodule SIP.IST do
  @moduledoc "SIP INVITE server transaction"
  use GenServer
  import SIP.Trans.Timer
  import SIP.Transac.Common
  require Logger

  # Callbacks

  @impl true
  def init({ t_mod, t_pid, remote_ip, remote_port, sipmsg, upperlayer }) do
    initial_state = %SIP.Transac{ msg: sipmsg, tmod: t_mod, tpid: t_pid, app: nil, timeout: 0,
                      t_isreliable: apply(t_mod, :is_reliable, []), destip: remote_ip,
                      destport: remote_port, state: :trying, upperlayer: upperlayer }

    # state = if not initial_state.t_isreliable, do: schedule_timer_A(initial_state), else: initial_state

    # Asynchornously process the request
    GenServer.cast(self(), :sipreq)
    { :ok, initial_state }
  end

  @impl true
  # Handle ACK sent by UAC
  def handle_cast( {:onsipmsg, req, _remoteip, _remoteport }, state) when is_map(req) and req.method == :ACK do
    # TODO, check the IP/port against the  IP/port of the original request
    if state.state == :confirmed do
      Logger.debug([ transid: state.msg.transid,  module: __MODULE__,
                      message: "ACK received. confirmed -> terminated"])
      { :noreply, schedule_timer_K(state, 5000) |> Map.put(:state, :terminated) }
    else
      { :noreply, state }
    end
  end

  # Handle CANCEL
  def handle_cast({:onsipmsg, req, _remoteip, _remoteport }, state) when is_map(req) and req.method == :CANCEL do
    if state.state in [ :trying, :proceeding ] do
      cancel_resp = SIP.Msg.Ops.reply_to_request(req, 200, "OK")
      sendout_msg(state, cancel_resp)

    else
      Logger.debug([ transid: state.msg.transid,  module: __MODULE__,
                      message: "CANCEL rejected in state #{state.state}"])
      # RFC 3261: 9.2 Processing CANCEL Requests
      cancel_resp = SIP.Msg.Ops.reply_to_request(req, 481, "Call/Transaction Does Not Exist")
      sendout_msg(state, cancel_resp)
      { :noreply, state }
    end
  end

  def handle_cast({:onsipmsg, req, _remoteip, _remoteport }, state) when is_map(req) when is_atom(req.method) do
    Logger.warning([ transid: state.msg.transid,  module: __MODULE__,
                    message: "Ignoring unsupported SIP request #{req.method}"])
    { :noreply, state }
  end

  def handle_cast({:onsipmsg, rsp, _remoteip, _remoteport }, state) when is_map(rsp) when rsp.method == false do
    Logger.warning([ transid: state.msg.transid,  module: __MODULE__,
                    message: "Ignoring unsupported SIP response #{rsp.response}"])
    { :noreply, state }
  end

  # This is invoked at NIST transaction creation to forward the request to upperlayer
  # asynchronously
  def handle_cast(:sipreq, state) do
    Logger.info([ transid: state.msg.transid,  module: __MODULE__,
                    message: "SIP Request #{state.msg.method} received"])
    case process_UAS_request(state) do
      # Schedule timer F (max NIST transaction)
      { :ok, state } -> { :noreply, SIP.Trans.Timer.schedule_timer_F(state) }

      # In case of failure, timerK is scheduled by internal_reply()
      { :upperlayerfailure, state } -> { :noreply, state }
    end
  end

  @impl true
  # Timer K - kill the transaction
  def handle_info({ :timeout, _tref, :timerK } , state)  do
    handle_timer(:timerK, state)
  end

  # Timer F - timeout
  def handle_info({ :timeout, _tref, :timerF } , state)  do
    case reply_to_UAC(state, state.sipmsg, 408, "Timeout", [], state.totag) do
      { :ok, new_state } -> { :noreply, new_state }
      { _err, new_state } -> { :noreply, new_state }
    end
  end

  # Handle SIP retransmission
  def handle_info({ :timerA, ms }, state) do
    # Resending last final response in case of an unreliable transport
    handle_UAS_timerA({ :timerA, ms }, state)
  end

  #Implementation of reply transaction interface
  @impl true
  def handle_call({ resp_code, reason, upd_fields, totag }, _from, state) when is_integer(resp_code) do
    { code, new_state } = reply_to_UAC(state, state.msg, resp_code, reason, upd_fields, totag);
    { :reply, code, new_state }
  end

  @impl true
  def handle_call(:ack, _from, state) do
    Logger.warning([ transid: state.msg.transid,  module: __MODULE__,
                    message: "Cannot ACK an Invite Server Transaction"])
      { :reply, :notsupported, state }
  end
end
