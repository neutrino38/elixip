defmodule SIP.ICT do
  @moduledoc "SIP INVITE client transaction"
  use GenServer
  import SIP.Trans.Timer
  require SIPMsgOps
  require Logger

  defp safe_serialize(sipmsg, state) do
    try do
      msgstr = SIPMsg.serialize(sipmsg)
      { :ok, Map.put(state, :msgstr, msgstr) }
    rescue
      e in RuntimeError ->
        Logger.debug([ transid: sipmsg.transid, message: e.message])
        { :invalid_sip_msg, state }
    end
  end



  # Callbacks

  @impl true
  def init({ t_mod, t_pid, sipmsg, app_pid, ring_timeout }) do
    initial_state = %{ msg: sipmsg, tmod: t_mod, tpid: t_pid, app: app_pid, t2: ring_timeout,
                       t_isreliable: apply(t_mod, :is_reliable, []),  state: :sending }

    case safe_serialize(sipmsg, initial_state) do
      {:ok, initial_state} ->
        case GenServer.call(t_pid, { :sendmsg, initial_state.msgstr }  ) do
          :ok ->
            if not initial_state.t_isreliable do
              schedule_timer_A(initial_state)
            end
            { :ok, initial_state }

          code ->
            Logger.error([ transid: sipmsg.transid, message: "ICT: Fail to send SIP request  #{code}"])
            { :stop, "Fail to send SIP erequest" }
        end

      { code, _initial_state} ->
        Logger.error([ transid: sipmsg.transid, message: "ICT: Fail to serialize SIP message #{code}"])
        { :stop, "Fail to serialize message" }
    end

  end

  @impl true
  # CANCEL  current transaction from dialog layer
  def handle_call(:cancel, _from, state) do
    if state.state in [ :sending, :proceeding ] do
      cancel = state.msg |> SIPMsgOps.cancel_request() |> SIPMsg.serialize()
      Logger.info([ transid: state.msg.transid, message: "ICT: sending CANCEL"])
      case GenServer.call(state.tpid, { :sendmsg, cancel }  ) do
        :ok ->
          { :reply, :ok, %{ state | state: :cancelling }}

        code ->
          Logger.error([ transid: state.msg.transid, message: "ICT: Fail to send CANCEL message #{code}"])
          { :reply, :transport_error, state}
      end
    else
      Logger.debug([ transid: state.msg.transid, message: "Cannot CANCEL transaction in #{state.state} state"])
      { :reply, :bad_state, state}
    end
  end

  # ACK the transaction (only needed in case of 200 OK received)
  def handle_call(:ack, _from, state) do
    if state.state == :confirmed do
      routeset = case Map.fetch(state, :route) do
        {:ok, routeset} -> routeset
        :error -> nil
      end

      remote_contact = case Map.fetch(state, :remotecontact) do
        {:ok, rcontact} -> rcontact
        :error -> nil
      end
      ack_sent = state.msg |> SIPMsgOps.ack_request(remote_contact, routeset) |> SIPMsg.serialize()
      Logger.info([ transid: state.msg.transid, message: "Sending ACK"])
      case GenServer.call(state.tpid, {:sendmsg, ack_sent} ) do
        :ok ->
          new_state = if state.t_isreliable do
            Logger.debug([ transid: state.msg.transid, message: "ACK sent: #{state.state} -> terminated"])
            schedule_timer_K(state, 0) |> Map.put(:ack, ack_sent) |> Map.put(:state, :terminated)
          else
            # RFC 3261 clause 17.1.2.2 arm timer K for unreliable transport
            Logger.debug([ transid: state.msg.transid, message: "ACK sent. Arming timer_K"])
            schedule_timer_K(state, 5000) |> Map.put(:ack, ack_sent)
          end
          { :reply, :ok, new_state }

        code ->
          Logger.error([ transid: state.msg.transid, message: "ICT: Fail to send ACK message #{code}"])
          # Arm a timer to destroy the transaction
          { :reply, :transport_error, state}
      end
    end
  end

  # Handle privisional (1xx) responses
  defp handle_sip_response(state, sipmsg) when SIPMsgOps.is_1xx_resp(sipmsg) do
    Logger.debug([ transid: sipmsg.transid, message: "Received prov resp #{sipmsg.response}"])
    case state.state do
      :sending ->
        # Todo: support 100rel and send PRACK

        # Send provisional response to app layer
        send(state.app, { :response, sipmsg })
        Logger.debug([ transid: sipmsg.transid, message: "state: sending -> proceeding"])
        upd_msg = if sipmsg.response > 100 do
          #Store the to header to obtain the 'to' tag
          Map.put(state.msg, :to, sipmsg.to)
        else
          state.msg
        end
        %{ state | state: :proceeding, msg: upd_msg } |> schedule_timer_B(state.t2 * 1000)

      :proceeding ->
        send(state.app, { :response, sipmsg })
        state

      _ ->
        Logger.debug([ transid: sipmsg.transid, message: "state: #{state.state}. Ignoring resp."])
        state
    end
  end

  # Handle OK responses (2xx)
  defp handle_sip_response(state, sip_resp) when SIPMsgOps.is_2xx_resp(sip_resp) do
    Logger.debug([ transid: sip_resp.transid, message: "Received #{sip_resp.response} final resp"])
    cond do
      state.state in [ :sending, :proceeding ] ->
        send(state.app, { :response, sip_resp })
        Logger.debug([ transid: sip_resp.transid, message: "state: #{state.state} -> confirmed"])
        routeset = case Map.fetch(sip_resp, :route) do
          { :ok, routeset } -> routeset
          :error -> nil
        end
        # Update status, the to header of the request with the to of the response to get the to tag
        state = %{ state | msg: Map.put(state.msg, :to, sip_resp.to), state: :confirmed }

        Map.put(state, :remotecontact, sip_resp.contact) |> Map.put(:route, routeset)

      # Corner case when 200 OK retransmission is still not acked by app layer.
      state.state == :confirmed ->
        send(state.app, { :response, sip_resp })
        state

      # Handle 200 OK retransmission on unrelable transport (UDP)
      state.state == :terminated and is_bitstring(state.ack) ->
        GenServer.call(state.tpid, :sendmsg, state.ack )
        state

      true ->
        Logger.debug([ transid: sip_resp.transid, message: "state: #{state.state}. Ignoring resp."])
        state
    end
  end

  # Handle 4xx, 5xx, 6xx responses
  defp handle_sip_response(state, sipmsg) when SIPMsgOps.is_failure_resp(sipmsg) do
    Logger.debug([ transid: sipmsg.transid, message: "Received #{sipmsg.response} failure resp"])
    cond do
      state.state in [ :sending, :proceeding ] ->
        # Send the message to the application layer
        send(sipmsg.app, { :response, sipmsg })
        # Send ACK automatically
        { :reply, _reply, new_state } = handle_call(:ack, self(), state)
        new_state

        state.state == :confirmed  and is_bitstring(state.ack) ->
          #Resend the same ack message
          GenServer.call(state.tpid, :sendmsg, state.ack )
          state

        true ->
          Logger.debug([ transid: sipmsg.transid, message: "state: #{state.state}. Ignoring resp."])
          state
      end
  end

  defp handle_cancel_response(state, siprsp) do
    if siprsp.response == 200 do
      state
    else
      send(state.app, { :cancel_rejected, siprsp.response})
      state
    end
  end
  @impl true
   # Process SIP response from transport layer
  def handle_cast({ :onsipmsg, siprsp }, state) do
    cond do
      siprsp.method != false ->
        Logger.warning([ transid: state.msg.transid, message: "Received an #{siprsp.method} SIP request. But this is a client transaction'"])
        {:noreply, state}

      # The response matches the INVITE req
      state.msg.cseq == siprsp.cseq ->
        new_state = handle_sip_response(state, siprsp)
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
        { :noreply, state }
    end
  end
end
