defmodule SIP.Transac.Common do
  @moduledoc """
  Module that gather all common an utility functions to implement SIP
  transactions
  """
  import SIP.Trans.Timer
  require Logger
  import SIP.Msg.Ops

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

  # Handle OK responses (2xx) from UAS
  def handle_UAS_sip_response(state, sip_resp) when SIP.Msg.Ops.is_2xx_resp(sip_resp) do
    Logger.debug([ transid: sip_resp.transid,  module: __MODULE__,
                 message: "Received #{sip_resp.response} final resp"])
    cond do
      state.state in [ :sending, :proceeding ] ->
        send(state.app, { :response, sip_resp, self() })
        Logger.debug([ transid: sip_resp.transid,
                     module: __MODULE__,message: "state: #{state.state} -> confirmed"])
        Logger.info([ transid: sip_resp.transid,  module: __MODULE__,
                    message: "answered with #{sip_resp.response}"])
        # Update status, the to header of the request with the to of the response to get the to tag
        # and buidl the ACK in case of ICT transaction according to section 17.1.1.3 of RFC 3261
        state = %{ state | msg: Map.put(state.msg, :to, sip_resp.to), state: :confirmed }

        # Process specific fields
        case state.msg.method do
          :INVITE ->
            # INVITE Process Record-Route record and use the route set
            routeset = Map.get(sip_resp, :recordroute)
            Map.put(state, :remotecontact, sip_resp.contact) |> Map.put(:route, routeset)

          :REGISTER ->
            path = Map.get(sip_resp, "Path")
            Map.put(state, :path, path)

          # To do SUBSCRIBE and PUBLISH

          _ -> state
        end

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

  # UAC: Handle 4xx, 5xx, 6xx responses
  def handle_UAS_sip_response(state, sipmsg) when SIP.Msg.Ops.is_failure_resp(sipmsg) do
    cond do
      state.state in [ :sending, :proceeding ] ->
        # Send the message to the application layer
        send(state.app, { :response, sipmsg, self() })

        Logger.debug([ transid: sipmsg.transid, module: __MODULE__,
                      message: "Received #{sipmsg.response}. State: #{state.state} -> rejected"])

        if state.msg.method == :INVITE do
          if sipmsg.response in [ 401, 407 ] do
            Logger.info([ transid: sipmsg.transid, message: "INVITE challenged. Code #{sipmsg.response}"])
          else
            Logger.info([ transid: sipmsg.transid, message: "INVITE rejected Code #{sipmsg.response}"])
          end
          # Send ACK automatically on failure in case of Invite Client Transaction (ICT)
          # Update the to field of the original request to comply with section 17.1.1.3
          # of RFC 3261

          { :reply, _reply, new_state } = send_ack(
            %SIP.Transac{state | state: :rejected, msg: Map.put(state.msg, :to, sipmsg.to) })
          new_state
        else
          if sipmsg.response in [ 401, 407 ] do
            Logger.info([ transid: sipmsg.transid, message: "#{state.msg.method} challenged. Code #{sipmsg.response}"])
          else
            Logger.info([ transid: sipmsg.transid, message: "#{state.msg.method} rejected Code #{sipmsg.response}"])
          end
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

  # Internal Server Transaction Finite State Machine
  defp fsm_reply(state, resp_code, rsp) when state.state in [ :trying, :proceeding ] do

    case SIP.Transac.Common.sendout_msg(state, rsp) do
      {:ok, new_state} ->
        Logger.info([ transid: rsp.transid, module: __MODULE__,
                     message: "Sent response #{resp_code} to #{state.msg.method}"])

        case resp_code do
          # Transition to proceeding
          rc when rc in 100..199 ->
            { :ok, Map.put(new_state, :state, :proceeding) }

          rc when rc in 200..699 ->
            # Final answer
            # Cancel timer F, arm timer K (NIST) or time A (IST)
            # set transaction state to terminated
            new_state = if state.msg == :INVITE do
              st = schedule_generic_timer(new_state, :timerF, :timerf, nil)
                        |> Map.put(:state, :confirmed)
              if state.t_isreliable do
                st
              else
                # Arm T2 to retransmit last final response
                schedule_timer_A(st) |> Map.put(:state, rspstr: SIPMsg.serialize(rsp) )
              end
            else
              schedule_timer_K(new_state, 5000)
                        |> schedule_generic_timer(:timerF, :timerf, nil)
                        |> Map.put(:state, :terminated)
            end
            { :ok, new_state }
        end

      { :invalid_sip_msg, _state } ->
        Logger.error([ transid: rsp.transid, module: __MODULE__,
                        message: "Fail to serialize SIP message."])
        { :invalid_sip_msg, state }

      { code, _state } ->
          Logger.error([ transid: rsp.transid, module: __MODULE__,
          message: "Transport error. Fail to send SIP response #{resp_code}. Err #{code}"])
          { code, state }
    end

  end

  defp fsm_reply(state, _resp_code, rsp) when state.state == :terminated do
    Logger.info([ transid: rsp.transid, module: __MODULE__,
                  message: "Final response to #{state.msg.method} already sent"])
    { :ignore, state }
  end

  # reply to request from UAC - specific case when we need to challenge. upd_fields contains the auth parameters
  def reply_to_UAC(state, sipmsg, resp_code, _reason, upd_fields, totag) when is_map(upd_fields) and resp_code in [ 401, 407 ] do
    # Build the challenge response
    resp = challenge_request(sipmsg, resp_code,
      upd_fields.authproc, upd_fields.realm, upd_fields.algorithm,
      [], totag)

    # Send it to the transaction state machine
    case fsm_reply(state, resp_code, resp) do
      { :ok, new_state } when resp_code in 200..599 -> { :ok, new_state }
      { code, state }  -> { code, state }
    end
  end

  # Other regular cases
  def reply_to_UAC(state, sipmsg, resp_code, reason, upd_fields, totag) when is_list(upd_fields) do
    # Fix contact if needed
    upd_fields = case resp_code do
      rc when rc in 200..299 ->
        #fix_contact(state, upd_fields)
        upd_fields

      # Todo, handle redirect here.
      rc when rc in 300..399 -> upd_fields

      # Other cases
      _ -> upd_fields
    end

    # Build the SIP reponse
    resp = reply_to_request(sipmsg, resp_code, reason, upd_fields, totag)

    resp = if sipmsg.method == :INVITE and resp_code in 200..299 do
      # Correct contact field for INVITE transaction
      SIP.Transport.add_contact_header(state.tmod, state.tpid, resp)
    else
      resp
    end

    # Send it to the transaction state machine

    case fsm_reply(state, resp_code, resp) do
      { :ok, new_state } when resp_code in 200..599 -> { :ok, new_state }
      { :ok, new_state } when resp_code in 100..199 -> { :ok, new_state }
      { code, state }  -> { code, state }
    end
  end

  # Call upper layer request handling function and
  def process_UAS_request(state, ul_fun) when is_function(ul_fun) do
    # TODO add debug support
    case ul_fun.(state.msg, self(), false) do
      # upper layer has started processing the request. Save the PID and the totag
      { :ok, ul_pid, { _ftag, _cid, totag } } -> { :ok, Map.put(state, :app, ul_pid) |> Map.put(:totag, totag) }

      # upper layer could not process the request and indicated a response code
      # close the transaction with this response code
      { :error, { code, reason, { _ftag, _cid, totag } }} ->
        { _errcode, state } = reply_to_UAC(state, state.msg, code, reason, [], totag)
        { :upperlayerfailure, state }


      # General error
      anything ->
        Logger.error([ transid: state.msg.transid, module: __MODULE__,
                     message: "Dialog layer failed to process SIP request. Err #{inspect(anything)}"])
        { _errcode, state } =  reply_to_UAC(state, state.msg, 403, "Denied", [], generate_from_or_to_tag())
        { :upperlayerfailure, state }
    end
  end

  # When upperlayer is a callback that returns the upperlayer PID
  def process_UAS_request(state) when is_function(state.upperlayer) do
    process_UAS_request(state, state.upperlayer)
  end

  # when upperlayer is a PID -> send the message
  def process_UAS_request(state) when is_pid(state.upperlayer) do
    send(state.upperlayer, { state.sipmsg.method, state.sipmsg } )
    { :ok, Map.put(state, :app, state.upperlayer) }
  end

  # when upperlayer is not specified -> send to the dialog layer
  def process_UAS_request(state) when is_nil(state.upperlayer) do
    process_UAS_request(state, &SIP.Dialog.process_incoming_request/3)
  end
end
