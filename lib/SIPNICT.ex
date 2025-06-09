defmodule SIP.NICT do
  @moduledoc "SIP non-INVITE client transaction"
  use GenServer
  import SIP.Trans.Timer
  import SIP.Transac.Common
  require SIP.Msg.Ops
  require Logger

  # Callbacks

  @impl true
  def init({ sipmsg, app_pid, ring_timeout }) do
    t_mod = sipmsg.ruri.tp_module
    t_pid = sipmsg.ruri.tp_pid

    # Add contact header
    sipmsg = SIP.Transport.add_contact_header(t_mod, t_pid, sipmsg)

    # Create GenServer state
    initial_state = %SIP.Transac{ msg: sipmsg, tmod: t_mod, tpid: t_pid, app: app_pid, timeout: ring_timeout,
                       t_isreliable: apply(t_mod, :is_reliable, []), destip: sipmsg.ruri.destip,
                       destport: sipmsg.ruri.destport, state: :sending }

    # Sendout the message using the transport
    case sendout_msg(initial_state, sipmsg) do
      {:ok, state} ->
        Logger.info([ transid: sipmsg.transid, module: __MODULE__,
                      message: "Sent #{sipmsg.method} #{sipmsg.ruri}"])
        state = if not state.t_isreliable do
          schedule_timer_A(state)
        else
          state
        end

        # Arm timer F
        state = schedule_timer_F(state)
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
    cancel(state)
  end

  def handle_call(:gettransport, _from, state ) do
    { :reply, { state.tmod, state.tpid }, state }
  end

  def handle_call(:ack, _from, state) do
    Logger.warning([ transid: state.msg.transid, module: __MODULE__,
                     message: "Sending ACK is not supported for a non invite client transaction"])
    { :reply, :unsupported, state }
  end

  @impl true
   # Process SIP response from transport layer
  def handle_cast({ :onsipmsg, siprsp, _remoteip, _remoteport }, state) do
    cond do
      siprsp.method != false ->
        Logger.warning([ transid: state.msg.transid, message: "Received an #{siprsp.method} SIP request. But this is a client transaction'"])
        {:noreply, state}

      # The response matches the inital req
      state.msg.cseq == siprsp.cseq ->
        new_state = handle_UAS_sip_response(state, siprsp)
        new_state = if siprsp.response >= 200 do
          schedule_timer_K(new_state, 5000) |> cancel_timer_F()
        else
          new_state
        end
        {:noreply, new_state}


      # The response matches the CANCEL req
      siprsp.cseq == { hd(state.msg.cseq), :CANCEL } ->
        new_state = handle_cancel_response(state, siprsp)
        {:noreply, new_state}

      true ->
        Logger.warning([ transid: state.msg.transid, module: __MODULE__,
                       message: "Response CSeq #{siprsp.cseq} does not match transaction requests'"])
        {:noreply, state}
    end
  end

  @impl true
  # Handle T1 time retransmission
  def handle_info({ :timerA, ms }, state) do
    case handle_timer({ :timerA, ms }, state) do
      { :noreply, newstate } -> { :noreply, newstate }
      { :stop, _reason, state} ->
        { :stop, :normal, state }
    end
  end

  # Handle other timers
  def handle_info({ :timeout, _tref, timer } , state) do
    handle_timer(timer, state)
  end
end
