defmodule SIP.Transac.Common do
  @moduledoc """
  Module that gather all common an utility functions to implement SIP
  transactions
  """
  import SIP.Trans.Timer
  require Logger
  import SIP.Msg.Ops

  @doc """
  Send a SIP message to the transport layer.

  Through `SIP.Transport.send_msg/4`, which answers `:transporterror` rather than
  exiting when the transport is gone: the pid held here is cached and a
  transaction is linked to its dialog, so an exit used to kill both — silently
  (design §14.4, R3). Every caller below already reads that code.
  """
  @spec sendout_msg(map(), binary()) :: {:ok | :invalid_sip_msg | :transporterror, map()}
  def sendout_msg(state, sipmsgstr) when is_map(state) and is_binary(sipmsgstr) do
    rez = SIP.Transport.send_msg(state.tpid, sipmsgstr, state.destip, state.destport)
    {rez, state}
  end

  @spec sendout_msg(map(), map()) :: {:ok | :invalid_sip_msg | :transporterror, map()}
  def sendout_msg(state, sipmsg) when is_map(state) and is_map(sipmsg) do
    try do
      msgstr = SIPMsg.serialize(sipmsg)

      state =
        case sipmsg.method do
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
        {:invalid_sip_msg, state}
    end
  end

  def cancel(state) do
    if state.state in [:sending, :proceeding] do
      Logger.info(
        transid: state.msg.transid,
        module: __MODULE__,
        message: "Cancelling transaction"
      )

      # Build the CANCEL request from the initial request
      cancel = SIP.Msg.Ops.cancel_request(state.msg)

      # Send it aout
      case sendout_msg(state, cancel) do
        {:ok, state} ->
          Logger.debug(
            transid: state.msg.transid,
            message: "CANCEL sent: #{state.state} -> cancelling"
          )

          {:reply, :ok, %{state | state: :cancelling}}

        {:invalid_sip_msg, state} ->
          Logger.error(
            transid: state.msg.transid,
            module: __MODULE__,
            message: "Fail to build CANCEL message."
          )

          {:reply, :invalid_sip_msg, state}

        {code, state} ->
          Logger.error(
            transid: state.msg.transid,
            module: __MODULE__,
            message: "Fail to send CANCEL message #{code}"
          )

          {:reply, :transport_error, state}
      end
    else
      if state.state != :cancelling do
        Logger.warning(
          transid: state.msg.transid,
          module: __MODULE__,
          message: "Cannot CANCEL transaction in #{state.state} state"
        )
      end

      {:reply, :bad_state, state}
    end
  end

  # Handle privisional (1xx) responses
  def handle_UAS_sip_response(state, sipmsg) when SIP.Msg.Ops.is_1xx_resp(sipmsg) do
    Logger.debug(
      transid: sipmsg.transid,
      module: __MODULE__,
      message: "Received prov resp #{sipmsg.response}"
    )

    case state.state do
      :sending ->
        # Todo: support 100rel and send PRACK

        # Send provisional response to app layer
        if sipmsg.response != 100 do
          # We do not forward 100 Trying to the dialog layer
          send(state.app, {:response, sipmsg, self()})
        end

        Logger.debug(
          transid: sipmsg.transid,
          module: __MODULE__,
          message: "state: sending -> proceeding"
        )

        upd_msg =
          if sipmsg.response > 100 do
            # Store the to header to obtain the 'to' tag
            Map.put(state.msg, :to, sipmsg.to)
          else
            state.msg
          end

        if state.msg == :INVITE do
          %{state | state: :proceeding, msg: upd_msg} |> schedule_timer_B(state.timeout * 1000)
        else
          %{state | state: :proceeding, msg: upd_msg}
        end

      :proceeding ->
        if sipmsg.response != 100 do
          # We do not forward 100 Trying to the dialog layer
          send(state.app, {:response, sipmsg, self()})
        end

        state

      _ ->
        Logger.debug(
          transid: sipmsg.transid,
          module: __MODULE__,
          message: "state: #{state.state}. Ignoring resp."
        )

        state
    end
  end

  @doc "Handle OK responses (2xx) from UAS. To be used in ICT and NICT"
  def handle_UAS_sip_response(state, sip_resp) when SIP.Msg.Ops.is_2xx_resp(sip_resp) do
    Logger.debug(
      transid: sip_resp.transid,
      module: __MODULE__,
      message: "Received #{sip_resp.response} final resp"
    )

    cond do
      # `:cancelling` belongs here as much as the other two, and leaving it out
      # dropped exactly the response RFC 3261 §16.7 is about: a 2xx crossing our
      # CANCEL. The callee picked up, we ignored their answer, and they were left
      # in a call nobody would ever ACK or BYE. Cancelling asks; it does not
      # decide, and the transaction is over only when a final says so.
      state.state in [:sending, :proceeding, :cancelling] ->
        send(state.app, {:response, sip_resp, self()})

        Logger.debug(
          transid: sip_resp.transid,
          module: __MODULE__,
          message: "state: #{state.state} -> confirmed"
        )

        Logger.info(
          transid: sip_resp.transid,
          module: __MODULE__,
          message: "answered with #{sip_resp.response}"
        )

        # Update status, the to header of the request with the to of the response to get the to tag
        # and buidl the ACK in case of ICT transaction according to section 17.1.1.3 of RFC 3261
        state = %{state | msg: Map.put(state.msg, :to, sip_resp.to), state: :confirmed}

        # Process specific fields and timers
        case state.msg.method do
          :INVITE ->
            # INVITE Process Record-Route record and use the route set
            routeset = Map.get(sip_resp, :recordroute)

            # Deviation from RFC 3261 - 17.1.1.2
            # Arm timer D in any case (transport unreliable or not).
            # That will limit the time
            # when the application layer can ACK the transaction.
            # remotecontact becomes the ACK RURI — a 2xx to INVITE must carry
            # exactly one Contact; guard against peers that send several.
            Map.put(state, :remotecontact, SIP.Uri.first_contact(sip_resp.contact))
            |> Map.put(:route, routeset)
            |> cancel_timer_B()
            |> schedule_timer_D()

          :REGISTER ->
            path = Map.get(sip_resp, "Path")
            Map.put(state, :path, path)

          # To do SUBSCRIBE and PUBLISH

          _ ->
            state
        end

      # The answer again, before the application has ACKed it — the far end
      # retransmits every T1 from the moment it answers, so this crosses every ACK
      # that takes longer than that to come back. Absorbed, like the retransmission
      # after the ACK below: it says nothing new, and there is nothing to resend
      # yet. The ACK the application is about to send is what the far end is asking
      # for.
      #
      # It used to go up to the application a second time. A B2BUA read it as an
      # answer to relay, found no forwarded request to match it with ("No forwarded
      # request correlates with the 200"), and logged a warning on every call whose
      # ACK took more than 500 ms — while a session that DID relay it sent the
      # caller a second 200 for an INVITE it had already answered.
      state.state == :confirmed ->
        Logger.debug(
          transid: sip_resp.transid,
          module: __MODULE__,
          message: "Absorbing #{sip_resp.response} retransmission (ACK not sent yet)"
        )

        state

      # Handle 200 OK retransmission on unrelable transport (UDP)
      state.state == :terminated ->
        if is_bitstring(state.ack) and state.msg.method == :INVITE do
          sendout_msg(state, state.ack)
        end

        state

      true ->
        Logger.debug(
          transid: sip_resp.transid,
          module: __MODULE__,
          message: "state: #{state.state}. Ignoring resp."
        )

        state
    end
  end

  # UAC: Handle 4xx, 5xx, 6xx responses
  def handle_UAS_sip_response(state, sipmsg) when SIP.Msg.Ops.is_failure_resp(sipmsg) do
    cond do
      # `:cancelling` included, for the response a CANCEL exists to obtain: the
      # 487 (RFC 3261 §9.1). Without it a cancelled INVITE was never ACKed —
      # against §17.1.1.2, which requires an ACK for every non-2xx final — and
      # the layer above was never told the branch had ended, so a forked dialog
      # waited on a branch that was already over and a leg leaked until timer B.
      state.state in [:sending, :proceeding, :cancelling] ->
        # Send the message to the application layer
        send(state.app, {:response, sipmsg, self()})

        Logger.debug(
          transid: sipmsg.transid,
          module: __MODULE__,
          message: "Received #{sipmsg.response}. State: #{state.state} -> rejected"
        )

        if state.msg.method == :INVITE do
          if sipmsg.response in [401, 407] do
            Logger.info(
              transid: sipmsg.transid,
              message: "INVITE challenged. Code #{sipmsg.response}"
            )
          else
            Logger.info(
              transid: sipmsg.transid,
              message: "INVITE rejected Code #{sipmsg.response}"
            )
          end

          # Send ACK automatically on failure in case of Invite Client Transaction (ICT)
          # Update the to field of the original request to comply with section 17.1.1.3
          # of RFC 3261

          {:reply, _reply, new_state} =
            send_ack(%SIP.Transac{
              state
              | state: :rejected,
                msg: Map.put(state.msg, :to, sipmsg.to)
            })

          new_state
        else
          if sipmsg.response in [401, 407] do
            Logger.info(
              transid: sipmsg.transid,
              message: "#{state.msg.method} challenged. Code #{sipmsg.response}"
            )
          else
            Logger.info(
              transid: sipmsg.transid,
              message: "#{state.msg.method} rejected Code #{sipmsg.response}"
            )
          end

          %SIP.Transac{state | state: :rejected}
        end

      state.state == :rejected and is_bitstring(state.ack) ->
        # Resend the same ack message
        sendout_msg(state, state.ack)
        state

      true ->
        Logger.debug(transid: sipmsg.transid, message: "state: #{state.state}. Ignoring resp.")
        state
    end
  end

  @doc """
  Send the ACK of a final response of an INVITE client transaction.

  Called again for every 2xx retransmission the far end sends: RFC 3261 §13.2.2.4
  owes one ACK per 2xx *received*, so being asked twice is the ordinary case and
  not a state error. The ACK that went out is kept serialized (`state.ack`, set by
  `sendout_msg/2`) and resent verbatim — §17.1.1.3 builds it from the ORIGINAL
  request, so rebuilding it could only produce the same bytes.

  And it always answers: the bare `if` this used to be returned `nil` in every
  other state, which is not a `handle_call/3` reply — the transaction crashed on
  it, taking with it the ACK of the retransmission that came next.
  """
  def send_ack(state) do
    cond do
      state.state in [:confirmed, :rejected] ->
        build_and_send_ack(state)

      is_binary(Map.get(state, :ack)) ->
        Logger.debug(transid: state.msg.transid, module: __MODULE__, message: "Resending ACK")

        {_code, state} = sendout_msg(state, state.ack)
        {:reply, :ok, state}

      true ->
        Logger.warning(
          transid: state.msg.transid,
          module: __MODULE__,
          message: "Cannot ACK a transaction in #{state.state} state"
        )

        {:reply, :bad_state, state}
    end
  end

  defp build_and_send_ack(state) do
    routeset =
      case Map.fetch(state, :route) do
        {:ok, routeset} -> routeset
        :error -> nil
      end

    remote_contact =
      case Map.fetch(state, :remotecontact) do
        {:ok, rcontact} -> rcontact
        :error -> nil
      end

    # The MAP goes to sendout_msg/2, not a string we serialized ourselves: that
    # clause is the one that keeps the bytes in `state.ack`, and the ACK is the
    # one request this stack has to be able to send twice (a 2xx retransmission
    # asks for it, §13.2.2.4). Serializing here left `state.ack` nil for ever, so
    # the two places that resend it — the retransmitted-2xx branch of
    # handle_UAS_sip_response/2 and send_ack/1 above — could never fire.
    # :confirmed = a 2xx was received, and ITS ack is a transaction of its own,
    # under a fresh branch (§13.2.2.4); :rejected keeps the INVITE's branch,
    # that ACK belongs to the INVITE transaction (§17.1.1.3).
    ack_sent =
      SIP.Msg.Ops.ack_request(state.msg, remote_contact, routeset, [], state.state == :confirmed)

    Logger.debug(transid: state.msg.transid, module: __MODULE__, message: "Sending ACK")

    case sendout_msg(state, ack_sent) do
      {:ok, state} ->
        new_state =
          cond do
            # The ACK of a 2xx: outlive it by 64*T1 so a callee that has not seen
            # it yet gets it again when it retransmits its answer (§13.2.2.4 —
            # see schedule_timer_K/2). On a reliable transport too: TCP delivers
            # the ACK, but a UAS retransmits its 2xx until it *processes* one, and
            # the retransmission crossing our ACK is exactly what the 500 ms
            # window around answering produces.
            state.state == :confirmed ->
              Logger.debug(
                transid: state.msg.transid,
                message: "ACK sent: #{state.state} -> terminated"
              )

              schedule_timer_K(state, :after_ack)
              |> Map.put(:state, :terminated)
              |> cancel_timer_D()

            # The ACK of a non-2xx final (§17.1.1.3), unchanged: `:rejected` is
            # what makes a retransmitted failure response resend this ACK.
            state.t_isreliable ->
              Logger.debug(
                transid: state.msg.transid,
                message: "ACK sent: #{state.state} -> terminated"
              )

              schedule_timer_K(state, 0) |> Map.put(:state, :terminated) |> cancel_timer_D()

            true ->
              # RFC 3261 clause 17.1.2.2 arm timer K for unreliable transport
              # We are not using timer D but timer K instead to handle responses retransmissions
              # After ACK is sent.
              Logger.debug(transid: state.msg.transid, message: "ACK sent. Arming timer_K")
              schedule_timer_K(state, :default) |> cancel_timer_D()
          end

        {:reply, :ok, new_state}

      {:invalid_sip_msg, state} ->
        Logger.error(
          transid: state.msg.transid,
          module: __MODULE__,
          message: "Fail to build ACK message."
        )

        {:reply, :invalid_sip_msg, state}

      {code, state} ->
        Logger.error(
          transid: state.msg.transid,
          module: __MODULE__,
          message: "Fail to send ACK message #{code}"
        )

        # Arm a timer to destroy the transaction
        {:reply, :transport_error, state}
    end
  end

  def handle_cancel_response(state, siprsp) do
    if siprsp.response == 200 do
      state
    else
      send(state.app, {:cancel_rejected, siprsp.response, self()})
      state
    end
  end

  # Keep the To tag a response went out with — but never *unset* a known one: a
  # response that carries no tag says nothing about the transaction's identity.
  defp remember_totag(state, nil), do: state
  defp remember_totag(state, totag), do: Map.put(state, :totag, totag)

  # Internal Server Transaction Finite State Machine
  defp fsm_reply(state, resp_code, rsp) when state.state in [:trying, :proceeding] do
    case SIP.Transac.Common.sendout_msg(state, rsp) do
      {:ok, new_state} ->
        Logger.info(
          transid: rsp.transid,
          module: __MODULE__,
          message: "Sent response #{resp_code} to #{state.msg.method}"
        )

        totag =
          case SIP.Uri.get_uri_param(rsp.to, "tag") do
            {:no_such_param, nil} -> nil
            {:ok, value} -> value
          end

        case resp_code do
          # Transition to proceeding.
          #
          # `remember_totag/2`, like every branch below: a 100 Trying may carry a To
          # tag (ours does — the dialog puts one on every response it composes) and
          # that tag is the transaction's from then on. Dropping it left an IST whose
          # `totag` was nil for as long as the callee said nothing, and the CANCEL
          # that a caller tired of waiting sends is answered with `state.totag` — so
          # the 200 to the CANCEL raised "Missing totag" and killed the transaction
          # instead. The caller then got no answer at all to its CANCEL.
          100 ->
            {:ok, Map.put(new_state, :state, :proceeding) |> remember_totag(totag)}

          rc when rc in 101..199 ->
            if totag == nil do
              raise "Invalid #{rc} response. Missing totag"
            end

            # TODO: totag is not protected here. It can be changed. Make sure that
            #       the intial value is not changed.
            {:ok, Map.put(new_state, :state, :proceeding) |> remember_totag(totag)}

          rc when rc in 200..699 ->
            # Final answer
            # Cancel timer F, arm timer K (NIST) or time A (IST)
            # set transaction state to terminated
            new_state =
              if state.msg.method == :INVITE do
                # new_state, not state: sendout_msg/2 stored the serialized response in
                # :rspstr, and that is what timer A and the request-retransmission
                # handlers resend. Dropping it here (the code branched off `state`)
                # left an IST on a reliable transport with the *previous* 1xx as its
                # last response.
                st =
                  cancel_timer_F(new_state)
                  |> Map.put(:state, :confirmed)
                  |> remember_totag(totag)

                if state.t_isreliable do
                  schedule_timer_H(st)
                else
                  # Arm timer A to retransmit last final response if ACK is not
                  # received on time for unreliable transports.
                  # TODO: That should be timer G here. Timer G should behave like time A
                  # but is specific to this case. We will change that later
                  Logger.debug(
                    transid: rsp.transid,
                    module: __MODULE__,
                    message: "final response sent. Arming timer A for IST transaction"
                  )

                  schedule_timer_A(st) |> schedule_timer_H()
                end
              else
                schedule_timer_K(new_state, :default)
                |> cancel_timer_F()
                |> Map.put(:state, :terminated)
              end

            {:ok, new_state}
        end

      {:invalid_sip_msg, _state} ->
        Logger.error(
          transid: rsp.transid,
          module: __MODULE__,
          message: "Fail to serialize SIP message."
        )

        {:invalid_sip_msg, state}

      {code, _state} ->
        Logger.error(
          transid: rsp.transid,
          module: __MODULE__,
          message: "Transport error. Fail to send SIP response #{resp_code}. Err #{code}"
        )

        {code, state}
    end
  end

  defp fsm_reply(state, _resp_code, rsp) when state.state == :terminated do
    Logger.info(
      transid: rsp.transid,
      module: __MODULE__,
      message: "Final response to #{state.msg.method} already sent"
    )

    {:ignore, state}
  end

  # reply to request from UAC - specific case when we need to challenge. upd_fields contains the auth parameters
  def reply_to_UAC(state, sipmsg, resp_code, _reason, upd_fields, totag)
      when is_map(upd_fields) and resp_code in [401, 407] do
    # Build the challenge response
    resp =
      challenge_request(
        sipmsg,
        resp_code,
        upd_fields.authproc,
        upd_fields.realm,
        upd_fields.algorithm,
        [],
        totag
      )

    # Send it to the transaction state machine
    case fsm_reply(state, resp_code, resp) do
      {:ok, new_state} ->
        # If application layer is a PID, send the nonce. challenge_request/7
        # stores the auth params under :wwwauthenticate / :proxyauthenticate as a
        # map keyed by string ("nonce"), so read them back the same way.
        nonce =
          case resp_code do
            401 -> resp.wwwauthenticate["nonce"]
            407 -> resp.proxyauthenticate["nonce"]
          end

        # Add nonce to reply
        {{:ok, nonce}, new_state}

      {code, state} ->
        {code, state}
    end
  end

  # `nil` is how part of this stack spells "no extra header fields" — the 503 a
  # dialog answers when it has too many transactions open, among others. It matched
  # no clause at all: the FunctionClauseError killed the server transaction, and the
  # dialog that had called it died of the raised exit it got back. So a dialog
  # refusing ONE request lost the whole call, both legs and the scenario with it,
  # and the caller got no answer to the request that was refused (production,
  # 2026-08-12: Alice's BYE).
  def reply_to_UAC(state, sipmsg, resp_code, reason, nil, totag),
    do: reply_to_UAC(state, sipmsg, resp_code, reason, [], totag)

  # Other regular cases
  def reply_to_UAC(state, sipmsg, resp_code, reason, upd_fields, totag)
      when is_list(upd_fields) do
    # Fix contact if needed
    upd_fields =
      case resp_code do
        rc when rc in 200..299 ->
          # fix_contact(state, upd_fields)
          upd_fields

        # Todo, handle redirect here.
        rc when rc in 300..399 ->
          upd_fields

        # Other cases
        _ ->
          upd_fields
      end

    # Build the SIP reponse
    resp = reply_to_request(sipmsg, resp_code, reason, upd_fields, totag)

    resp =
      if sipmsg.method == :INVITE and resp_code in 200..299 do
        # Correct contact field for INVITE transaction
        SIP.Transport.add_contact_header(state.tmod, state.tpid, resp)
      else
        resp
      end

    # Send it to the transaction state machine

    case fsm_reply(state, resp_code, resp) do
      {:ok, new_state} when resp_code in 200..599 -> {:ok, new_state}
      {:ok, new_state} when resp_code in 100..199 -> {:ok, new_state}
      {code, state} -> {code, state}
    end
  end

  # Call upper layer request handling function and
  def process_UAS_request(state, ul_fun) when is_function(ul_fun) do
    # TODO add debug support
    case ul_fun.(state.msg, self(), false) do
      # upper layer has started processing the request. Save the PID and the totag
      {:ok, ul_pid, {_ftag, _cid, totag}} ->
        {:ok, Map.put(state, :app, ul_pid) |> Map.put(:totag, totag)}

      # upper layer could not process the request and indicated a response code
      # close the transaction with this response code
      {:error, {code, reason, {_ftag, _cid, totag}}} ->
        {_errcode, state} = reply_to_UAC(state, state.msg, code, reason, [], totag)
        {:upperlayerfailure, state}

      # The dialog layer answered the request itself and there is nothing to bind to
      # an application process: an out-of-dialog OPTIONS (RFC 3261 §11.2). Not a
      # failure, hence its own shape rather than the :error channel above — a 200
      # reported as an "upper layer failure" would be a lie in the logs. A To tag is
      # generated here: any response above 100 needs one, and no dialog exists to
      # provide it.
      {:answered, code, reason, fields} ->
        {_rc, state} =
          reply_to_UAC(state, state.msg, code, reason, fields, generate_from_or_to_tag())

        {:answered, state}

      # General error
      anything ->
        Logger.error(
          transid: state.msg.transid,
          module: __MODULE__,
          message: "Dialog layer failed to process SIP request. Err #{inspect(anything)}"
        )

        {_errcode, state} =
          reply_to_UAC(state, state.msg, 403, "Denied", [], generate_from_or_to_tag())

        {:upperlayerfailure, state}
    end
  end

  # When upperlayer is a callback that returns the upperlayer PID
  def process_UAS_request(state) when is_function(state.upperlayer) do
    process_UAS_request(state, state.upperlayer)
  end

  # when upperlayer is a PID -> send the message
  def process_UAS_request(state) when is_pid(state.upperlayer) do
    send(state.upperlayer, {state.sipmsg.method, state.sipmsg})
    {:ok, Map.put(state, :app, state.upperlayer)}
  end

  # when upperlayer is not specified -> send to the dialog layer
  def process_UAS_request(state) when is_nil(state.upperlayer) do
    process_UAS_request(state, &SIP.Dialog.process_incoming_request/3)
  end
end
