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
# (Kelix.Mod.Registrar.targets/2 → ready-to-dial URIs, ordered by q); the SCRIPT
# decides what SIP that means — whom to call, what to answer when nobody is
# registered, and what crosses between the two legs.
defmodule Kelix.B2bua do
  use SIP.Scenario
  require Logger

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

  # Where is the callee? The AOR is the R-URI user part, in the domain the router
  # gave us — not the R-URI domain, which may be an alias the store folds.
  state place_call do
    req = last_uas_req()

    case lookup_targets(req, ctx_get(:domain)) do
      {:ok, peer} ->
        # The highest-q contact is dialled first; if it refuses, the hunt walks
        # down the rest — as branches of this same leg, so nothing above the
        # dialog notices how many devices were tried. Ringing them all at once
        # is P4.
        b2bua_forward(req, peer, false)
        goto(proceeding, "call forwarded")

      {:answer, code, reason, desc} ->
        b2bua_reply(req, code, reason)
        scenario_success(desc)
    end
  end

  state proceeding do
    on_events do
      {:outbound, {code, resp, _trans, _dlg}} when code in 101..199 ->
        b2bua_forward_reply(resp)
        goto(loop, "provisional #{code}")

      {:outbound, {200, resp, _trans, _dlg}} ->
        b2bua_forward_reply(resp)
        goto(wait_ack, "200 OK relayed")

      # A final from the callee. With a serial hunt this may be one device
      # refusing rather than the call failing, so ask before concluding.
      {:outbound, {code, resp, _trans, _dlg}} when code >= 300 ->
        b2bua_forward_reply(resp)

        if b2bua_hunting?() do
          goto(loop, "#{code}, trying the next target")
        else
          scenario_success("callee answered #{code}")
        end

      # The caller gave up. The inbound dialog has already answered the CANCEL
      # and 487'd its INVITE; what we owe the callee is the CANCEL of its INVITE.
      {:CANCEL, req, _trans, _dlg} ->
        b2bua_cancel_forward()
        b2bua_forward(req)
        scenario_aborted("caller cancelled")

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
        goto(loop, "relayed #{m} (caller -> callee)")

      {:outbound, {m, req, _trans, _dlg}} when m in [:INVITE, :UPDATE] ->
        b2bua_forward(req)
        goto(loop, "relayed #{m} (callee -> caller)")

      # The ACK of a re-INVITE's 200: a transaction of its own (RFC 3261
      # §13.2.2.4), so every re-INVITE that crosses owes one back. Without this
      # the far end retransmits its 200 until timer H and drops a live call.
      {:ACK, req, _trans, _dlg} ->
        b2bua_forward(req)
        goto(loop, "ACK relayed (caller -> callee)")

      {:outbound, {:ACK, req, _trans, _dlg}} ->
        b2bua_forward(req)
        goto(loop, "ACK relayed (callee -> caller)")

      # Default relay, written out rather than assumed: everything else in-dialog
      # (INFO, MESSAGE, NOTIFY, REFER…), then the responses.
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

  # Cooperative shutdown (§5.3): both legs are wound down by the automatic
  # teardown — CANCEL what is ringing, BYE what is up — so there is nothing left
  # to do here but say why we stopped.
  on_shutdown do
    scenario_aborted("B2BUA stopped gracefully")
  end

  # ── application logic ───────────────────────────────────────────────────────

  # Ask the location service where the AOR is and turn that into a peer, or into
  # the SIP answer the caller gets instead.
  #
  # The rescue is the load-bearing part, as in the registrar script: a module
  # that is not installed (UndefinedFunctionError) or that faults mid-lookup
  # would otherwise kill this instance and leave the caller with nothing. The
  # load-time `uses_modules` contract makes that unlikely, not impossible — a
  # module can be unloaded while calls are running.
  defp lookup_targets(req, domain) do
    aor = aor_of(req)

    case Kelix.Mod.Registrar.targets(domain, aor) do
      {:ok, uris} ->
        # Serial: a subscriber's devices are alternatives, not a group to ring
        # together — the store already ordered them by q, i.e. by which one the
        # subscriber wants tried first.
        {:ok, %SIP.B2bua.Peer{uris: uris, use_srv: false, ruri: :peer, fork: :serial}}

      :notfound ->
        # Registered nowhere right now — the subscriber exists, the device does
        # not answer. 480 says "try later", which is what a voicemail or a
        # follow-me rule would branch on.
        {:answer, 480, "Temporarily Unavailable", "#{aor} is not registered"}

      {:error, reason} ->
        Logger.error("b2bua: location lookup for #{aor}@#{domain} failed: #{inspect(reason)}")
        {:answer, 500, "Location Service Unavailable", "lookup failed"}
    end
  rescue
    err ->
      Logger.error("b2bua: location lookup raised: #{Exception.message(err)}")
      {:answer, 500, "Location Service Unavailable", "lookup raised"}
  end

  # The AOR is the R-URI user part (RFC 3261 §10.3): whom the call is *for*.
  defp aor_of(req) do
    case Map.get(req, :ruri) do
      %SIP.Uri{userpart: user} when is_binary(user) -> user
      _ -> ""
    end
  end
end
