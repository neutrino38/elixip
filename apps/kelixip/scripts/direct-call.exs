# Reference kelixip call script: Alice calls Bob, wherever Bob registered.
#
# kamailio's `lookup("location"); t_relay()` done as a B2BUA: the location
# service says where the AOR is, this script relays the call there over a second
# dialog it owns — and stays in the signalling path for the whole call.
#
# Commented use case in B2BUA.md, "Scenario direct-call.exs".
defmodule Kelix.DirectCall do
  use SIP.Scenario
  require Logger

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
  state place_call do
    req = last_uas_req()

    case where_is(req, ctx_get(:domain)) do
      {:ok, peer} ->
        b2bua_forward(req, peer, false)
        goto(proceeding, "call forwarded")

      {:answer, code, reason} ->
        b2bua_reply(req, code, reason)
        scenario_success("answered #{code} locally")
    end
  end

  state proceeding do
    on_events do
      # Everything the device says goes back to Alice, collapsed into our single
      # inbound dialog.
      {:outbound, {code, resp, _trans, _dlg}} when code in 101..199 ->
        b2bua_forward_reply(resp)
        goto(loop, "provisional #{code}")

      {:outbound, {200, resp, _trans, _dlg}} ->
        b2bua_forward_reply(resp)
        goto(wait_ack, "200 OK relayed")

      # A refusal. If Bob has another device, the hunt is already trying it.
      {:outbound, {code, resp, _trans, _dlg}} when code >= 300 ->
        b2bua_forward_reply(resp)

        if b2bua_hunting?() do
          goto(loop, "#{code}, trying Bob's next device")
        else
          scenario_success("Bob answered #{code}")
        end

      # Alice gave up. Two different things, and both are wanted: stop the
      # search, and tell the device that is ringing.
      {:CANCEL, req, _trans, _dlg} ->
        b2bua_cancel_forward()
        b2bua_forward(req)
        scenario_aborted("caller cancelled")

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
        goto(loop, "ACK relayed (caller -> callee)")

      {:outbound, {:ACK, req, _trans, _dlg}} ->
        b2bua_forward(req)
        goto(loop, "ACK relayed (callee -> caller)")

      # Default relay, written out rather than assumed: everything else
      # in-dialog (re-INVITE, UPDATE, INFO, MESSAGE, REFER…), then the responses.
      {:outbound, {m, req, _trans, _dlg}} when is_atom(m) ->
        b2bua_forward(req)
        goto(loop, "relayed #{m} (callee -> caller)")

      {:outbound, {code, resp, _trans, _dlg}} when is_integer(code) ->
        b2bua_forward_reply(resp)
        goto(loop, "relayed #{code} (callee -> caller)")

      {m, req, _trans, _dlg} when is_atom(m) ->
        b2bua_forward(req)
        goto(loop, "relayed #{m} (caller -> callee)")

      {code, resp, _trans, _dlg} when is_integer(code) ->
        b2bua_forward_reply(resp)
        goto(loop, "relayed #{code} (caller -> callee)")
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

  # ── application logic ───────────────────────────────────────────────────────

  # The module decides WHERE Bob is; the scenario decides what SIP that means.
  defp where_is(req, domain) do
    aor = to_string(req.ruri.userpart)

    case Kelix.Mod.Registrar.targets(domain, aor) do
      # ready-to-dial URIs, already carrying the flow they registered over, in
      # descending q — hence use_srv: false and ruri: :peer
      {:ok, uris} ->
        {:ok, %SIP.B2bua.Peer{uris: uris, use_srv: false, ruri: :peer, fork: :serial}}

      :notfound ->
        {:answer, 480, "Temporarily Unavailable"}

      {:error, reason} ->
        Logger.error("lookup for #{aor}@#{domain} failed: #{inspect(reason)}")
        {:answer, 500, "Location Service Unavailable"}
    end
  rescue
    # A module unloaded mid-call must not kill the instance and leave Alice with
    # nothing.
    err ->
      Logger.error("lookup raised: #{Exception.message(err)}")
      {:answer, 500, "Location Service Unavailable"}
  end
end
