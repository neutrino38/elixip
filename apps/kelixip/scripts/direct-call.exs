# Reference kelixip call script: Alice calls Bob, wherever Bob registered.
#
# kamailio's `lookup("location"); t_relay()` done as a B2BUA: the location
# service says where the AOR is, this script relays the call there over a second
# dialog it owns — and stays in the signalling path for the whole call.
#
# Commented use case in B2BUA.md, "Scenario direct-call.exs".
defmodule Kelix.DirectCall do
  use SIP.Scenario

  uas(:invite)

  # Refuse to load when the location service is absent, instead of failing on
  # the first INVITE.
  config(uses_modules: [:registrar])

  state initial_state do
    goto(wait_invite)
  end

  # The {:INVITE, …} that created this instance is already in our mailbox.
  state wait_invite do
    on_events do
      {:INVITE, req, _trans, _dlg} ->
        b2bua_reply(req, 100, "Trying")
        goto(place_call, "INVITE received")

      {:dialog_terminated, _dlg, _reason} ->
        scenario_aborted("caller vanished before the INVITE")
    after
      60_000 -> scenario_failure("no INVITE received")
    end
  end

  # Where is Bob? A state with no on_events: it decides and moves on.
  #
  # The MODULE says where the AOR is and hands back a peer; the SCRIPT decides
  # what SIP each outcome means. Nothing is rescued here — a module that faults
  # raises, and the scenario runner logs it and fails the scenario, which is more
  # readable than an error mapped twice.
  state place_call do
    req = last_uas_req()

    case Kelix.Mod.Registrar.targets(ctx_get(:domain), req) do
      {:ok, peer} ->
        b2bua_forward(req, peer, false)
        goto(proceeding, "call forwarded")

      :notfound ->
        b2bua_reply(req, 480, "Temporarily Unavailable")
        scenario_success("Bob is registered nowhere right now")

      :no_aor ->
        b2bua_reply(req, 400, "Bad Request")
        scenario_success("the INVITE names no AOR")

      :unavailable ->
        b2bua_reply(req, 500, "Location Service Unavailable")
        scenario_failure("the location service could not answer")
    end
  end

  state proceeding do
    on_events do
      # Everything the device says goes back to Alice, collapsed into our single
      # inbound dialog.
      {:outbound, {code, resp, _trans, _dlg}} when code in 101..199 ->
        b2bua_forward_reply(resp)
        stay("provisional #{code}")

      {:outbound, {200, resp, _trans, _dlg}} ->
        b2bua_forward_reply(resp)
        goto(wait_ack, "200 OK relayed")

      # A refusal. If Bob has another device, the hunt is already trying it.
      {:outbound, {code, resp, _trans, _dlg}} when code >= 300 ->
        b2bua_forward_reply(resp)

        if b2bua_hunting?() do
          stay("#{code}, trying Bob's next device")
        else
          scenario_success("Bob answered #{code}")
        end

      # Alice gave up. Two different things, and both are wanted: stop the
      # search, and tell the device that is ringing. Then wait: a CANCEL asks,
      # it does not decide (RFC 3261 §16.7).
      {:CANCEL, req, _trans, _dlg} ->
        b2bua_cancel_forward()
        b2bua_forward(req)
        goto(cancelling, "caller cancelled")

      {:BYE, req, _trans, _dlg} ->
        b2bua_cancel_forward()
        b2bua_reply(req, 200, "OK")
        scenario_success("caller hung up before answer")

      {:outbound, {:dialog_terminated, _dlg, reason}} ->
        b2bua_reply(last_uas_req(), 500, "Outbound leg lost")
        scenario_failure("outbound leg died: #{inspect(reason)}")
    after
      180_000 ->
        b2bua_reply(last_uas_req(), 408, "Request Timeout")
        scenario_failure("Bob never answered")
    end
  end

  # The CANCEL has gone to Bob; his transaction is not over until a final response
  # says so (RFC 3261 §16.7). Staying here to hear it is the whole point: end now
  # and a device that answers a fraction of a second later is left off-hook in a
  # call nobody is in.
  #
  # `SIP.DialogImpl` catches that case on its own — it is not a policy, so no
  # script may get it wrong — and this state does not make it correct, it makes it
  # VISIBLE: a call answered after its cancellation is a real event, and the
  # difference between "abandoned" and "answered then hung up" is one somebody
  # bills on.
  state cancelling do
    on_events do
      # What normally comes back, and fast.
      {:outbound, {487, _resp, _trans, _dlg}} ->
        scenario_aborted("caller cancelled, callee confirmed")

      # The race. Bob picked up before the CANCEL reached him; nobody is left to
      # talk to, so acknowledge his answer and hang up (§13.2.2.4 then §15).
      {:outbound, {200, _resp, _trans, _dlg}} ->
        b2bua_send_BYE()
        scenario_success("callee answered after the cancellation; hung up")

      # Still ringing somewhere: keep listening rather than take a 180 for an end.
      {:outbound, {code, _resp, _trans, _dlg}} when code in 100..199 ->
        stay("provisional #{code} after cancel")

      {:outbound, {code, _resp, _trans, _dlg}} when code >= 300 ->
        scenario_aborted("caller cancelled, callee answered #{code}")

      {:outbound, {:dialog_terminated, _dlg, _reason}} ->
        scenario_aborted("caller cancelled, outbound leg gone")

      {:dialog_terminated, _dlg, _reason} ->
        scenario_aborted("caller cancelled")
    after
      # Bounded on purpose: past timer B the outbound transaction is over whatever
      # we heard, and an instance held on a leg that says nothing is a slot lost.
      32_000 -> scenario_aborted("caller cancelled, callee never concluded")
    end
  end

  # Alice's ACK is relayed rather than answered here: what Bob's device gets is
  # what Alice sent.
  state wait_ack do
    on_events do
      {:ACK, req, _trans, _dlg} ->
        b2bua_forward(req)
        goto(connected, "ACK relayed")
    after
      # RFC 3261 timer H: no ACK is coming. Hang up the leg we did establish.
      32_000 ->
        b2bua_send_BYE()
        scenario_failure("no ACK from the caller")
    end
  end

  state connected do
    on_events do
      {:BYE, req, _trans, _dlg} ->
        b2bua_forward(req)
        b2bua_reply(req, 200, "OK")
        goto(wait_far_bye_ok, "caller hung up")

      {:outbound, {:BYE, req, _trans, _dlg}} ->
        b2bua_forward(req)
        b2bua_reply(req, 200, "OK")
        goto(wait_far_bye_ok, "callee hung up")

      {:dialog_terminated, _dlg, reason} ->
        scenario_success("inbound leg ended: #{inspect(reason)}")

      {:outbound, {:dialog_terminated, _dlg, reason}} ->
        scenario_success("outbound leg ended: #{inspect(reason)}")

      # The ACK of a re-INVITE's 200 is a transaction of its own (RFC 3261
      # §13.2.2.4), so every re-INVITE that crosses owes one back.
      {:ACK, req, _trans, _dlg} ->
        b2bua_forward(req)
        stay("ACK relayed (caller -> callee)")

      {:outbound, {:ACK, req, _trans, _dlg}} ->
        b2bua_forward(req)
        stay("ACK relayed (callee -> caller)")

      # Default relay, written out rather than assumed: everything else
      # in-dialog (re-INVITE, UPDATE, INFO, MESSAGE, REFER…), then the responses.
      {:outbound, {m, req, _trans, _dlg}} when is_atom(m) ->
        b2bua_forward(req)
        stay("relayed #{m} (callee -> caller)")

      {:outbound, {code, resp, _trans, _dlg}} when is_integer(code) ->
        b2bua_forward_reply(resp)
        stay("relayed #{code} (callee -> caller)")

      {m, req, _trans, _dlg} when is_atom(m) ->
        b2bua_forward(req)
        stay("relayed #{m} (caller -> callee)")

      {code, resp, _trans, _dlg} when is_integer(code) ->
        b2bua_forward_reply(resp)
        stay("relayed #{code} (caller -> callee)")
    after
      14_400_000 -> scenario_failure("maximum call duration reached")
    end
  end

  state wait_far_bye_ok do
    on_events do
      {:outbound, {200, _resp, _trans, _dlg}} -> scenario_success("call relayed and ended")
      {200, _resp, _trans, _dlg} -> scenario_success("call relayed and ended")
      {:dialog_terminated, _dlg, _reason} -> scenario_success("call ended")
      {:outbound, {:dialog_terminated, _dlg, _reason}} -> scenario_success("call ended")
    after
      5_000 -> scenario_success("BYE unanswered, closing anyway")
    end
  end

  on_shutdown do
    # Both legs are wound down by the automatic teardown; there is nothing left
    # to do here but say why we stopped.
    scenario_aborted("B2BUA stopped gracefully")
  end
end
