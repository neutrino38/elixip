# Reference B2BUA scenario — a pure signaling back-to-back user agent. Run it with:
#     elixipp --listen udp:5060 apps/elixip2/scenarios/b2bua_basic.exs
#
# One instance is spawned per inbound INVITE. It creates a SECOND dialog toward
# the configured peer and then relays, in both directions, until one side hangs
# up. Media is not touched: the SDP bodies cross verbatim and the endpoints talk
# to each other directly (`media` argument `false` — see docs/design/b2bua_module.md §7).
#
# What makes this readable is that the two legs are told apart *syntactically*:
# an event of the outbound leg arrives wrapped as `{:outbound, {…}}`, an event of
# the inbound leg arrives bare. And `b2bua_forward/1` / `b2bua_forward_reply/1`
# are direction-free — they relay to the *other* leg, whichever that is — so the
# symmetric states below say each rule once.
#
# Unlike kamailio's t_relay() or Asterisk's Dial(), nothing is relayed unless
# this script says so. The catch-all clauses of `connected` are what a
# "relay everything" policy looks like when it is written down rather than
# assumed.
defmodule B2BUA.Basic do
  use SIP.Scenario

  # Server scenario: elixipp starts the listeners and spawns one instance per
  # inbound INVITE dialog.
  uas(:invite)

  # `peer` is where calls go. A bare URI is shorthand for a one-target peer;
  # `%SIP.B2bua.Peer{}` is the full form (target list, SRV, fork, R-URI policy).
  # Override it per run with `-c FILE` or an elixipp config block.
  config(domains: :any, peer: "sip:callee@127.0.0.1:5070")

  # The {:INVITE, …} that created this instance is already in our mailbox.
  state initial_state do
    goto(wait_invite)
  end

  state wait_invite do
    on_events do
      {:INVITE, req, _trans, _dlg} ->
        # Tell the caller we are working on it, then open the outbound leg.
        b2bua_reply(req, 100, "Trying")
        b2bua_forward(req, ctx_get(:peer), false)
        goto(proceeding, "INVITE relayed")
    after
      60_000 -> scenario_failure("no INVITE received")
    end
  end

  # The callee is being alerted. Everything it says goes back to the caller —
  # collapsed into our single inbound dialog, so the caller sees one early
  # dialog however many the callee's side produced.
  state proceeding do
    on_events do
      {:outbound, {code, resp, _trans, _dlg}} when code in 101..199 ->
        b2bua_forward_reply(resp)
        goto(loop, "provisional #{code}")

      {:outbound, {200, resp, _trans, _dlg}} ->
        b2bua_forward_reply(resp)
        goto(wait_ack, "200 OK relayed")

      {:outbound, {code, resp, _trans, _dlg}} when code >= 300 ->
        b2bua_forward_reply(resp)
        scenario_success("callee answered #{code}")

      # The caller gave up. The inbound dialog has already answered the CANCEL
      # and 487'd its INVITE by itself; what we owe the callee is the CANCEL of
      # the INVITE we sent it.
      {:CANCEL, req, _trans, _dlg} ->
        b2bua_forward(req)
        scenario_aborted("caller cancelled")

      {:outbound, {:dialog_terminated, _dlg, reason}} ->
        b2bua_reply(last_uas_req(), 500, "Outbound leg lost")
        scenario_failure("outbound leg died: #{inspect(reason)}")
    after
      # No answer. Give up on both sides: the 408 goes to the caller, and the
      # automatic teardown CANCELs the attempt still ringing at the callee.
      180_000 ->
        b2bua_reply(last_uas_req(), 408, "Request Timeout")
        scenario_failure("callee never answered")
    end
  end

  # The 200 OK is relayed; the caller's ACK confirms it end to end. Relaying the
  # ACK rather than sending our own the moment the callee answered is the
  # deferred-ACK discipline of §6: what the callee gets is what the caller sent.
  state wait_ack do
    on_events do
      {:ACK, req, _trans, _dlg} ->
        b2bua_forward(req)
        goto(connected, "ACK relayed")
    after
      # RFC 3261 timer H: the 2xx stopped being retransmitted, so no ACK is
      # coming. Hang up the leg we did establish.
      32_000 ->
        b2bua_send_BYE()
        scenario_failure("no ACK from the caller")
    end
  end

  # The call is up. Everything in-dialog crosses, in either direction, and the
  # first BYE ends it.
  state connected do
    on_events do
      # Hangup, from whichever side: relay it, answer it locally so the sender
      # is not left retransmitting, and wait for the far end's 200.
      {:BYE, req, _trans, _dlg} ->
        b2bua_forward(req)
        b2bua_reply(req, 200, "OK")
        goto(wait_far_bye_ok, "caller hung up")

      {:outbound, {:BYE, req, _trans, _dlg}} ->
        b2bua_forward(req)
        b2bua_reply(req, 200, "OK")
        goto(wait_far_bye_ok, "callee hung up")

      # One side gave up on its own: tell the other and stop.
      {:dialog_terminated, _dlg, reason} ->
        scenario_success("inbound leg ended: #{inspect(reason)}")

      {:outbound, {:dialog_terminated, _dlg, reason}} ->
        scenario_success("outbound leg ended: #{inspect(reason)}")

      # The default relay, written out rather than assumed. Requests first
      # (re-INVITE, UPDATE, INFO, MESSAGE, NOTIFY, REFER…), then responses.
      # ACK is excluded: it was already relayed in wait_ack, and a stray one
      # here would be re-sent against a transaction that is done.
      {:outbound, {m, req, _trans, _dlg}} when is_atom(m) and m != :ACK ->
        b2bua_forward(req)
        goto(loop, "relayed #{m} (callee -> caller)")

      {:outbound, {code, resp, _trans, _dlg}} when is_integer(code) ->
        b2bua_forward_reply(resp)
        goto(loop, "relayed #{code} (callee -> caller)")

      {m, req, _trans, _dlg} when is_atom(m) and m != :ACK ->
        b2bua_forward(req)
        goto(loop, "relayed #{m} (caller -> callee)")

      {code, resp, _trans, _dlg} when is_integer(code) ->
        b2bua_forward_reply(resp)
        goto(loop, "relayed #{code} (caller -> callee)")
    after
      # A call nobody ever ends. The teardown BYEs both legs on the way out.
      14_400_000 -> scenario_failure("maximum call duration reached")
    end
  end

  # The BYE was relayed; its 200 may come back on either leg (we answered the
  # near side ourselves, so this is the far one). Either way the call is over —
  # an unanswered BYE is not a failure, the teardown finishes the job.
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

  # A controller asked us to stop mid-call (kelictl, or a parent FSM). Both legs
  # are wound down by the automatic teardown — CANCEL what is ringing, BYE what
  # is up — so there is nothing to do here but say why we stopped.
  on_shutdown do
    scenario_aborted("controller asked to stop")
  end
end
