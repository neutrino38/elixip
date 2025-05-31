defmodule SIP.Transac.Common do
  @moduledoc """
  Module that gather all common an utility functions to implement SIP
  transactions
  """
  import SIP.Trans.Timer
  require Logger
  require SIP.Msg.Ops

  @doc "Send a SIP message to the transport layer"
  @spec sendout_msg(map(), binary()) :: {:ok | :invalid_sip_msg | :transporterror, map()}
  def sendout_msg(state, sipmsgstr) when is_map(state) and is_binary(sipmsgstr) do
    rez = GenServer.call(state.tpid,{ :sendmsg, sipmsgstr, state.destip, state.destport } )
    { rez, state }
  end

  @spec sendout_msg(map(), map()) :: {:ok | :invalid_sip_msg | :transporterror, map()}
  def sendout_msg(state, sipmsg) when is_map(state) and is_map(sipmsg) do
    try do
      msgstr = SIPMsg.serialize(sipmsg)
      state = case sipmsg.method do
        :ACK -> Map.put(state, :ack, msgstr)
        :CANCEL -> state
        false -> Map.put(state, :rspstr, msgstr)
        _ -> Map.put(state, :msgstr, msgstr)
      end

      sendout_msg(state, msgstr)

    rescue
      e ->
        Logger.error(Exception.format(:error, e, __STACKTRACE__))
        Logger.error("")
        { :invalid_sip_msg, state }
    end
  end

  def cancel(state) do
    if state.state in [ :sending, :proceeding ] do
      Logger.info([ transid: state.msg.transid,  module: __MODULE__,
                message: "Cancelling transaction"])

      # Build the CANCEL request from the initial request
      cancel = SIP.Msg.Ops.cancel_request(state.msg)

      # Send it aout
      case sendout_msg(state, cancel) do
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

      # Handle privisional (1xx) responses
  def handle_UAS_sip_response(state, sipmsg) when SIP.Msg.Ops.is_1xx_resp(sipmsg) do
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
  def handle_UAS_sip_response(state, sip_resp) when SIP.Msg.Ops.is_2xx_resp(sip_resp) do
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
        if state.msg.method == :INVITE do
          send(state.app, { :response, sip_resp, self() })
        end
        state


      # Handle 200 OK retransmission on unrelable transport (UDP)
      state.state == :terminated  ->
        if is_bitstring(state.ack) and state.msg.method == :INVITE do
          sendout_msg(state, state.ack)
        end
        state

      true ->
        Logger.debug([ transid: sip_resp.transid, module: __MODULE__,
                     message: "state: #{state.state}. Ignoring resp."])
        state
    end
  end

  # Handle 4xx, 5xx, 6xx responses
  def handle_UAS_sip_response(state, sipmsg) when SIP.Msg.Ops.is_failure_resp(sipmsg) do
    cond do
      state.state in [ :sending, :proceeding ] ->
        # Send the message to the application layer
        send(state.app, { :response, sipmsg, self() })
        # Send ACK automatically on failure
        Logger.debug([ transid: sipmsg.transid, module: __MODULE__,
                      message: "Received #{sipmsg.response}. State: #{state.state} -> rejected"])
        Logger.info([ transid: sipmsg.transid, message: "Call rejected with response #{sipmsg.response}"])

        if state.msg.method == :INVITE do
          { :reply, _reply, new_state } = send_ack(%SIP.Transac{state | state: :rejected })
          new_state
        else
          %SIP.Transac{state | state: :rejected }
        end

      state.state == :rejected  and is_bitstring(state.ack) ->
        #Resend the same ack message
        sendout_msg(state, state.ack )
        state

      true ->
        Logger.debug([ transid: sipmsg.transid, message: "state: #{state.state}. Ignoring resp."])
        state
      end
  end

  def send_ack(state) do
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
      case sendout_msg(state, ack_sent) do
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



  def handle_cancel_response(state, siprsp) do
    if siprsp.response == 200 do
      state
    else
      send(state.app, { :cancel_rejected, siprsp.response, self() })
      state
    end
  end
end
