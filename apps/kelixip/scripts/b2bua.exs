# Reference kelixip B2BUA call script: place a call to a *registered* subscriber.
# One instance is spawned per inbound INVITE by Kelix.Router → Kelix.InstancePool.
# The served domain is injected into the context by the router (config override
# `domain:`).
#
# This is the kamailio `lookup("location"); t_relay()` pattern done as a B2BUA
# (design docs/design/b2bua_module.md §3.2): the location service says where the
# AOR is, and this script relays the call there over a second dialog it owns.
# Unlike a proxy it stays in the signalling path for the whole call, so it can be
# told to hang up, can meter, and later can put media in the middle.
#
# Separation of concerns (§11.1): the MODULE decides where the subscriber is
# (Kelix.Mod.Registrar.targets/2 → a ready-to-dial %SIP.B2bua.Peer{}); the SCRIPT
# decides what SIP that means — whom to call, what to answer when nobody is
# registered, and what crosses between the two legs.
defmodule Kelix.B2bua do
  use SIP.Scenario

  uas(:invite)

  # Load-time contract (§5.3): refuse this script when the location service is
  # not installed, instead of letting the first INVITE die on an undefined function.
  config(uses_modules: [:registrar])

  # The {:INVITE, …} is already queued by the dialog layer; wait for it.
  state initial_state do
    goto(wait_invite)
  end

  state wait_invite do
    on_events do
      {:INVITE, req, _trans_pid, _dialog_pid} ->
        b2bua_reply(req, 100, "Trying")
        goto(place_call, "INVITE")

      {:dialog_terminated, _dialog_pid, _reason} ->
        scenario_aborted("caller vanished before the INVITE")
    after
      60_000 -> scenario_failure("no INVITE received")
    end
  end

  # Where is the callee? In the domain the router gave us — not the R-URI domain,
  # which may be an alias the store folds.
  #
  # The MODULE says where the AOR is and hands back a peer; the SCRIPT decides
  # what SIP each outcome means. Nothing is rescued here — a module that faults
  # raises, and the scenario runner logs it and fails the scenario.
  state place_call do
    req = last_uas_req()

    case Kelix.Mod.Registrar.targets(ctx_get(:domain), req) do
      {:ok, peer} ->
        # The highest-q contact is dialled first; if it refuses, the hunt walks
        # down the rest — as branches of this same leg, so nothing above the
        # dialog notices how many devices were tried. Ringing them all at once
        # is P4.
        b2bua_forward(req, peer, false)
        goto(proceeding, "call forwarded")

      # Registered nowhere right now — the subscriber exists, the device does
      # not answer. 480 says "try later", which is what a voicemail or a
      # follow-me rule would branch on.
      :notfound ->
        b2bua_reply(req, 480, "Temporarily Unavailable")
        scenario_success("callee is not registered")

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
      {:outbound, {code, resp, _trans, _dlg}} when code in 101..199 ->
        b2bua_forward_reply(resp)
        stay("provisional #{code}")

      {:outbound, {200, resp, _trans, _dlg}} ->
        b2bua_forward_reply(resp)
        goto(wait_ack, "200 OK relayed")

      # A final from the callee. With a serial hunt this may be one device
      # refusing rather than the call failing, so ask before concluding.
      {:outbound, {code, resp, _trans, _dlg}} when code >= 300 ->
        b2bua_forward_reply(resp)

        if b2bua_hunting?() do
          stay("#{code}, trying the next target")
        else
          scenario_success("callee answered #{code}")
        end

      # The caller gave up. The inbound dialog has already answered the CANCEL
      # and 487'd its INVITE; what we owe the callee is the CANCEL of its INVITE.
      # Then we wait: a CANCEL asks, it does not decide (RFC 3261 §16.7).
      {:CANCEL, req, _trans, _dlg} ->
        b2bua_cancel_forward()
        b2bua_forward(req)
        goto(cancelling, "caller cancelled")

      # A caller who hangs up while the callee is still being rung. Not what the
      # RFC asks for (that is a CANCEL), but real user agents send it, and
      # without this clause it matched nothing and sat in the mailbox until the
      # state timed out. Nothing is relayed: the outbound INVITE has no dialog to
      # BYE, it has an attempt to CANCEL, which b2bua_cancel_forward/0 does.
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
        scenario_failure("callee never answered")
    end
  end

  # The CANCEL has gone to the callee; its transaction is not over until a final
  # response says so (RFC 3261 §16.7). Staying here to hear it is the whole point:
  # end now and a device that answers a fraction of a second later is left
  # off-hook in a call nobody is in.
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

      # The race. The callee picked up before the CANCEL reached it; nobody is
      # left to talk to, so acknowledge the answer and hang up (§13.2.2.4, §15).
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

  state wait_ack do
    on_events do
      {:ACK, req, _trans, _dlg} ->
        b2bua_forward(req)
        goto(connected, "ACK relayed")
    after
      # RFC 3261 timer H: the 2xx is no longer retransmitted, so no ACK is
      # coming. Hang up the leg we did establish.
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

      # A re-INVITE or an UPDATE. Four different things arrive under this shape —
      # hold/retrieve, a media added or withdrawn, a changed address, a session
      # timer refresh — and with no media server all four cross: the SDP belongs
      # to the endpoints, so each of these is a conversation between them that we
      # only carry. scenarios/b2bua_media.exs is where the third case stops
      # crossing, because there the peer moves and our endpoint does not.
      {m, req, _trans, _dlg} when m in [:INVITE, :UPDATE] ->
        b2bua_forward(req)
        stay("relayed #{m} (caller -> callee)")

      {:outbound, {m, req, _trans, _dlg}} when m in [:INVITE, :UPDATE] ->
        b2bua_forward(req)
        stay("relayed #{m} (callee -> caller)")

      # The ACK of a re-INVITE's 200: a transaction of its own (RFC 3261
      # §13.2.2.4), so every re-INVITE that crosses owes one back. Without this
      # the far end retransmits its 200 until timer H and drops a live call.
      {:ACK, req, _trans, _dlg} ->
        b2bua_forward(req)
        stay("ACK relayed (caller -> callee)")

      {:outbound, {:ACK, req, _trans, _dlg}} ->
        b2bua_forward(req)
        stay("ACK relayed (callee -> caller)")

      # Default relay, written out rather than assumed: everything else in-dialog
      # (INFO, MESSAGE, NOTIFY, REFER…), then the responses.
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

  # Cooperative shutdown (§5.3): both legs are wound down by the automatic
  # teardown — CANCEL what is ringing, BYE what is up — so there is nothing left
  # to do here but say why we stopped.
  on_shutdown do
    scenario_aborted("B2BUA stopped gracefully")
  end
end
