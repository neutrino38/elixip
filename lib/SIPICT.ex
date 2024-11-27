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
    if state.state in [ :sending, :proceeding ] do
      Logger.info([ transid: state.msg.transid,  module: __MODULE__,
                  message: "Cancelling transaction"])

      # Build the CANCEL request from the initial request
      cancel = SIP.Msg.Ops.cancel_request(state.msg)

      # Send it aout
      case SIP.Transac.Common.sendout_msg(state, cancel) do
        { :ok, state } ->
          Logger.debug([ transid: state.msg.transid, message: "CANCEL sent: #{state.state} -> cancelling"])
          { :reply, :ok, %{ state | state: :cancelling }}

        { :invalid_sip_msg, state } ->
          Logger.error([ transid: state.msg.transid, module: __MODULE__,
                       message: "Fail to build CANCEL message."])
          { :reply, :invalid_sip_msg, state}


        { code, state } ->
          Logger.error([ transid: state.msg.transid, module: __MODULE__,
                       message: "Fail to send CANCEL message #{code}"])
          { :reply, :transport_error, state}
      end
    else
      Logger.warning([ transid: state.msg.transid, module: __MODULE__,
                     message: "Cannot CANCEL transaction in #{state.state} state"])
      { :reply, :bad_state, state}
    end
  end

  def handle_call(:gettransport, _from, state ) do
    { :reply, { state.tmod, state.tpid }, state }
  end

  @doc "ACK the transaction (only needed in case of 200 OK received)"
  def handle_call(:ack, _from, state) do
    if state.state in [:confirmed, :rejected] do
      routeset = case Map.fetch(state, :route) do
        {:ok, routeset} -> routeset
        :error -> nil
      end

      remote_contact = case Map.fetch(state, :remotecontact) do
        {:ok, rcontact} -> rcontact
        :error -> nil
      end
      ack_sent = state.msg |> SIP.Msg.Ops.ack_request(remote_contact, routeset) |> SIPMsg.serialize()
      Logger.debug([ transid: state.msg.transid,  module: __MODULE__,
                  message: "Sending ACK"])
      case SIP.Transac.Common.sendout_msg(state, ack_sent) do
        { :ok, state } ->
          new_state = if state.t_isreliable do
            Logger.debug([ transid: state.msg.transid, message: "ACK sent: #{state.state} -> terminated"])
            schedule_timer_K(state, 0) |> Map.put(:state, :terminated)
          else
            # RFC 3261 clause 17.1.2.2 arm timer K for unreliable transport
            Logger.debug([ transid: state.msg.transid, message: "ACK sent. Arming timer_K"])
            schedule_timer_K(state, 5000)
          end
          { :reply, :ok, new_state }

        { :invalid_sip_msg, state } ->
          Logger.error([ transid: state.msg.transid, module: __MODULE__,
                         message: "Fail to build ACK message."])
          { :reply, :invalid_sip_msg, state }

        { code, state } ->
          Logger.error([ transid: state.msg.transid, module: __MODULE__,
                       message: "Fail to send ACK message #{code}"])
          # Arm a timer to destroy the transaction
          { :reply, :transport_error, state}
      end
    end
  end

  # Handle privisional (1xx) responses
  defp handle_sip_response(state, sipmsg) when SIP.Msg.Ops.is_1xx_resp(sipmsg) do
    Logger.debug([ transid: sipmsg.transid, module: __MODULE__,
                 message: "Received prov resp #{sipmsg.response}"])
    case state.state do
      :sending ->
        # Todo: support 100rel and send PRACK

        # Send provisional response to app layer
        if sipmsg.response != 100 do
          # We do not forward 100 Trying to the dialog layer
          send(state.app, { :response, sipmsg, self() })
        end
        Logger.debug([ transid: sipmsg.transid,  module: __MODULE__,
                     message: "state: sending -> proceeding"])
        upd_msg = if sipmsg.response > 100 do
          #Store the to header to obtain the 'to' tag
          Map.put(state.msg, :to, sipmsg.to)
        else
          state.msg
        end
        %{ state | state: :proceeding, msg: upd_msg } |> schedule_timer_B(state.timeout * 1000)

      :proceeding ->
        if sipmsg.response != 100 do
          # We do not forward 100 Trying to the dialog layer
          send(state.app, { :response, sipmsg, self() })
        end
        state

      _ ->
        Logger.debug([ transid: sipmsg.transid,  module: __MODULE__,
                     message: "state: #{state.state}. Ignoring resp."])
        state
    end
  end

  # Handle OK responses (2xx)
  defp handle_sip_response(state, sip_resp) when SIP.Msg.Ops.is_2xx_resp(sip_resp) do
    Logger.debug([ transid: sip_resp.transid,  module: __MODULE__,
                 message: "Received #{sip_resp.response} final resp"])
    cond do
      state.state in [ :sending, :proceeding ] ->
        send(state.app, { :response, sip_resp, self() })
        Logger.debug([ transid: sip_resp.transid,
                     module: __MODULE__,message: "state: #{state.state} -> confirmed"])
        routeset = case Map.fetch(sip_resp, :route) do
          { :ok, routeset } -> routeset
          :error -> nil
        end

        Logger.info([ transid: sip_resp.transid,  module: __MODULE__,
                    message: "answered with #{sip_resp.response}"])
        # Update status, the to header of the request with the to of the response to get the to tag
        state = %{ state | msg: Map.put(state.msg, :to, sip_resp.to), state: :confirmed }
        Map.put(state, :remotecontact, sip_resp.contact) |> Map.put(:route, routeset)

      # Corner case when 200 OK retransmission is still not acked by app layer.
      state.state == :confirmed ->
        send(state.app, { :response, sip_resp, self() })
        state

      # Handle 200 OK retransmission on unrelable transport (UDP)
      state.state == :terminated and is_bitstring(state.ack) ->
        SIP.Transac.Common.sendout_msg(state, state.ack)
        state

      true ->
        Logger.debug([ transid: sip_resp.transid, module: __MODULE__,
                     message: "state: #{state.state}. Ignoring resp."])
        state
    end
  end

  # Handle 4xx, 5xx, 6xx responses
  defp handle_sip_response(state, sipmsg) when SIP.Msg.Ops.is_failure_resp(sipmsg) do
    cond do
      state.state in [ :sending, :proceeding ] ->
        # Send the message to the application layer
        send(state.app, { :response, sipmsg, self() })
        # Send ACK automatically on failure
        Logger.debug([ transid: sipmsg.transid, module: __MODULE__,
                      message: "Received #{sipmsg.response}. State: #{state.state} -> rejected"])
        Logger.info([ transid: sipmsg.transid, message: "Call rejected with response #{sipmsg.response}"])
        { :reply, _reply, new_state } = handle_call(:ack, self(), %SIP.Transac{state | state: :rejected })
        new_state

      state.state == :rejected  and is_bitstring(state.ack) ->
        #Resend the same ack message
        SIP.Transac.Common.sendout_msg(state, state.ack )
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
      send(state.app, { :cancel_rejected, siprsp.response, self() })
      state
    end
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
        # Notify the tranport that this transaction is terminated
        { :noreply, state }
    end
  end
end
