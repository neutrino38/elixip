defmodule SIP.ICT do
  @moduledoc "SIP INVITE client transaction"
  use GenServer
  import SIP.Trans.Timer
  require SIP.Msg.Ops
  require Logger

  # Callbacks

  @impl true
  def init({ sipmsg, app_pid, ring_timeout }) do
    t_mod = sipmsg.ruri.tp_module
    t_pid = sipmsg.ruri.tp_pid

    initial_state = %SIP.Transac{ msg: sipmsg, tmod: t_mod, tpid: t_pid, app: app_pid, timeout: ring_timeout,
                       t_isreliable: apply(t_mod, :is_reliable, []), destip: sipmsg.ruri.destip,
                       destport: sipmsg.ruri.destport, state: :sending }

    case SIP.Transac.Common.sendout_msg(initial_state, sipmsg) do
      {:ok, state} ->
        Logger.info([ transid: sipmsg.transid, module: __MODULE__,
                    message: "Sent INVITE to #{sipmsg.ruri}"])
        if not state.t_isreliable do
          schedule_timer_A(state)
        end
        { :ok, state }

      { :invalid_sip_msg, _state } ->
        Logger.error([ transid: sipmsg.transid, module: __MODULE__,
                        message: "Fail to serialize SIP message."])
        { :stop, "Fail to serialize message" }

      { code, _state } ->
          Logger.error([ transid: sipmsg.transid, module: __MODULE__,
          message: "Transport error. Fail to send SIP request  #{code}"])
          { :stop, "Fail to send SIP request" }
    end
  end

  @impl true
  # CANCEL  current transaction from dialog layer
  def handle_call(:cancel, _from, state) do
    SIP.Transac.Common.cancel(state)
  end

  def handle_call(:gettransport, _from, state ) do
    { :reply, { state.tmod, state.tpid }, state }
  end

  @doc "ACK the transaction (only needed in case of 200 OK received)"
  def handle_call(:ack, _from, state) do
    SIP.Transac.Common.send_ack(state)
  end

  @impl true
   # Process SIP response from transport layer
  def handle_cast({ :onsipmsg, siprsp, _remoteip, _remoteport }, state) do
    cond do
      siprsp.method != false ->
        Logger.warning([ transid: state.msg.transid, message: "Received an #{siprsp.method} SIP request. But this is a client transaction'"])
        {:noreply, state}

      # The response matches the INVITE req
      state.msg.cseq == siprsp.cseq ->
        new_state = SIP.Transac.Common.handle_UAS_sip_response(state, siprsp)
        {:noreply, new_state}


      # The response matches the CANCEL req
      siprsp.cseq == { hd(state.msg.cseq), :CANCEL } ->
        new_state = SIP.Transac.Common.handle_cancel_response(state, siprsp)
        {:noreply, new_state}

      true ->
        Logger.warning([ transid: state.msg.transid, message: "Response CSeq #{siprsp.cseq} does not match transaction requests'"])
        {:noreply, state}
    end
  end

  @impl true
  # Handle T1 time retransmission
  def handle_info({ :timerA, ms }, state) do
    case handle_timer({ :timerA, ms }, state) do
      { :noreply, newstate } -> { :noreply, newstate }
      { :stop, _reason, state} ->
        GenServer.stop(self())
        { :noreply, state }
    end
  end

  # Handle other timers
  def handle_info({ :timeout, _tref, timer } , state) when timer in [ :timerT2, :timerK] do
    case handle_timer(timer, state) do
      { :noreply, newstate } -> { :noreply, newstate }
      { :stop, _reason, state} ->
        GenServer.stop(self())
        # Notify the tranport that this transaction is terminated
        { :noreply, state }
    end
  end
end
