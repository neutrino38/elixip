defmodule SIP.ICT do
  @moduledoc "SIP INVITE client transaction"
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

    # Fix the Contact header with the transport's local IP/port so the remote
    # peer and proxy can route in-dialog requests back to us (RFC 3261 §8.1.1.8).
    # Only do so when the Contact still carries the placeholder address
    # (0.0.0.0); a Contact already pointing somewhere is left untouched so that
    # SIP.ICT can also be used to forward messages verbatim.
    sipmsg =
      if contact_needs_fixup?(sipmsg) do
        SIP.Transport.add_contact_header(t_mod, t_pid, sipmsg)
      else
        sipmsg
      end

    initial_state = %SIP.Transac{ msg: sipmsg, tmod: t_mod, tpid: t_pid, app: app_pid, timeout: ring_timeout,
                       t_isreliable: apply(t_mod, :is_reliable, []), destip: sipmsg.ruri.destip,
                       destport: sipmsg.ruri.destport, state: :sending }

    case sendout_msg(initial_state, sipmsg) do
      {:ok, state} ->
        Logger.info([ transid: sipmsg.transid, module: __MODULE__,
                     message: "Sent INVITE to #{sipmsg.ruri}"])
        state = if not state.t_isreliable do
          schedule_timer_A(state) |> schedule_timer_B(ring_timeout * 1000)
        else
          schedule_timer_B(state, ring_timeout * 1000)
        end
        { :ok,  state }

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

  # True when the Contact is missing (nil) or carries the placeholder address
  # (0.0.0.0) that the session layer inserts and expects the transport to
  # overwrite with the real local IP/port. Any other Contact (e.g. when
  # forwarding) is preserved.
  defp contact_needs_fixup?(sipmsg) do
    case Map.get(sipmsg, :contact) do
      nil -> true
      %SIP.Uri{domain: "0.0.0.0"} -> true
      _ -> false
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

  @doc "ACK the transaction (only needed in case of 200 OK received)"
  def handle_call(:ack, _from, state) do
    send_ack(state)
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
        new_state =handle_UAS_sip_response(state, siprsp)
        {:noreply, new_state}


      # The response matches the CANCEL req
      siprsp.cseq == { hd(state.msg.cseq), :CANCEL } ->
        new_state = handle_cancel_response(state, siprsp)
        {:noreply, new_state}

      true ->
        Logger.warning([ transid: state.msg.transid, message: "Response CSeq #{siprsp.cseq} does not match transaction requests'"])
        {:noreply, state}
    end
  end

  @impl true
  # Handle T1 time retransmission
  def handle_info({ :timerA, ms }, state) do
    handle_timer({ :timerA, ms }, state)
  end

  # Handle other timers
  # - timer B - this is the ring time
  # - timer H - if ACK is not sent on time
  # - timer K - normal end of transaction
  def handle_info({ :timeout, _tref, timer } , state) do
    handle_timer(timer, state, __MODULE__)
  end
end
