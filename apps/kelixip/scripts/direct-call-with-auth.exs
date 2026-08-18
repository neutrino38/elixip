# Reference kelixip call script: Alice calls Bob — after proving she is Alice.
#
# `direct-call.exs` plus digest authentication of the INVITE (design
# docs/design/evolution-auth-db.md §2): kamailio's
# `proxy_authenticate(); lookup("location"); t_relay()`, done as a B2BUA.
#
# Separation of concerns (§11.1): `Kelix.Mod.AuthDb` DECIDES — challenge, accept or
# refuse, and who the digest proved the sender to be — and this SCRIPT composes the
# SIP that each verdict means. The module never builds a response, and the script
# never reads an Authorization header.
#
# Everything from `place_call` on is `direct-call.exs` unchanged: authentication is
# three states in front of the call, not a complication of the call.
defmodule Kelix.DirectCallWithAuth do
  use SIP.Scenario
  use SBB.Call

  uas(:invite)

  # Refuse to load when either module is absent, instead of failing on the first
  # INVITE: the location service, and the authentication backend that now gates it.
  config(uses_modules: [:registrar, :auth_db])

  state initial_state do
    goto(wait_invite)
  end

  # The {:INVITE, …} that created this instance is already in our mailbox.
  state wait_invite do
    on_events do
      {:INVITE, req, _trans, _dlg} ->
        b2bua_reply(req, 100, "Trying")
        goto(authenticate_caller, "INVITE received")

      {:dialog_terminated, _dlg, _reason} ->
        scenario_aborted("caller vanished before the INVITE")
    after
      60_000 -> scenario_failure("no INVITE received")
    end
  end

  # Who is calling? A state with no on_events: it decides and moves on.
  #
  # The INVITE needs no carrying around — `on_events` stored it and
  # `last_uas_req()` reads it back, here and in every later state, which matters
  # doubly now: the request authenticated is the *last* one received, i.e. the one
  # carrying the credentials, never the challenged one.
  #
  # `sip_ctx.domain` is the realm to require. For an INVITE that is the *caller's*
  # domain and not the R-URI's — calling out of the domain is the point of a call —
  # and for a node serving one domain the two coincide (see
  # `Kelix.Mod.AuthDb.authenticate/3`).
  state authenticate_caller do
    req = last_uas_req()

    case Kelix.Mod.AuthDb.authenticate(req, sip_ctx.domain) do
      # The digest proved `identity.user`, and the identity check has already had
      # its say about the From asserting someone else (auth_db `identity_check`).
      # Noting it is what makes the caller of a metered call knowable.
      {:ok, identity} ->
        SIP.Scenario.Monitor.note_account(identity.user)
        goto(place_call, "INVITE authenticated as #{identity.user}")

      # 407 rather than 401: we are formally a UAS, but a UA expects the server
      # that routes its calls to challenge as a proxy, and many will not retry a
      # 401 on an INVITE. `stale` tells the client its nonce merely aged, so it
      # replays without asking the user for a password again.
      {:requireauth, stale} ->
        params =
          Kelix.Auth.challenge_params(sip_ctx.domain,
            stale: stale,
            algorithm: Kelix.Mod.AuthDb.challenge_algorithm()
          )

        b2bua_challenge(req, params, 407)
        goto(wait_credentials, if(stale, do: "407 stale", else: "407 challenge"))

      # Answer and keep waiting — never end the instance on a refused INVITE. The
      # dialog does NOT die with us: nothing monitors the app pid, so a dialog
      # whose instance ended still matches the next INVITE of that Call-ID and
      # casts it to a dead process. The client would then get NO answer at all
      # until the dialog expires. A 403 is one request's verdict, not the end of
      # the conversation — a client that fixes its credentials must be able to say
      # so, and it is the same reasoning as the registrar's.
      {:reject, code, reason} ->
        b2bua_reply(req, code, reason)
        goto(wait_credentials, "#{code} #{reason}")
    end
  end

  # The challenged INVITE comes back with credentials, on the same dialog: same
  # Call-ID, a new CSeq, no To tag. Its ACK never reaches us — the server
  # transaction absorbs the ACK of a non-2xx (RFC 3261 §17.2.1).
  state wait_credentials do
    on_events do
      {:INVITE, req, _trans, _dlg} ->
        b2bua_reply(req, 100, "Trying")
        goto(authenticate_caller, "INVITE re-submitted")

      # A caller that cancels the challenged attempt: nothing was forwarded, so
      # there is nothing to cancel but ourselves.
      {:CANCEL, _req, _trans, _dlg} ->
        scenario_aborted("caller cancelled the challenged call")

      {:dialog_terminated, _dlg, _reason} ->
        scenario_success("caller gave up on the challenge")
    after
      # A UA replays a challenge within a second. This is the scanner, and the
      # phone whose password is wrong: end the instance rather than hold a slot
      # for it.
      32_000 -> scenario_success("no credentials came back")
    end
  end

  # Where is Bob? The MODULE says where the AOR is and hands back a peer; the
  # SCRIPT decides what SIP each outcome means. Nothing is rescued here — a module
  # that faults raises, and the scenario runner logs it and fails the scenario,
  # which is more readable than an error mapped twice.
  #
  # From here on this script IS direct-call.exs: the same `call/1`, the same arms.
  # Authentication was three states in front of the call, not a complication of
  # it, and that reads better now that the call itself is one line.
  state place_call do
    req = last_uas_req()

    case Kelix.Mod.Registrar.targets(ctx_get(:domain), req) do
      {:ok, peer} ->
        call(args: %{peer: peer, request: req})

        on_events do
          {:call, :connected, _} ->
            goto(connected, "call established")

          {:call, :rejected, %{code: code}} ->
            scenario_success("Bob answered #{code}")

          {:call, :cancelled, _} ->
            scenario_aborted("caller cancelled, callee confirmed")

          {:call, :answered_after_cancel, _} ->
            scenario_success("callee answered after the cancellation; hung up")

          {:call, :caller_hung_up, _} ->
            scenario_success("caller hung up before answer")

          {:call, :caller_gone, %{reason: reason}} ->
            scenario_aborted("caller vanished while it rang: #{inspect(reason)}")

          {:call, :timeout, _} ->
            scenario_failure("Bob never answered")

          {:call, :failed, %{reason: reason}} ->
            scenario_failure("call setup failed: #{reason}")
        end

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
      # None of it is re-authenticated: the dialog was authenticated when it was
      # created, and challenging mid-call breaks UAs and proves nothing new
      # (`Kelix.Mod.AuthDb.challengeable?/1`).
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
