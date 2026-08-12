# Reference kelixip call script: Alice calls Bob — authenticated, media in the middle.
#
# `direct-call-with-auth.exs` with the media plane of `scenarios/b2bua_media.exs`:
# kamailio's `proxy_authenticate(); lookup("location"); t_relay()`, done as a
# media-terminated B2BUA. Read it next to `direct-call-with-auth.exs` — the
# difference between the two files is precisely what a media server costs
# (design docs/design/b2bua_module.md §7, §12).
#
# What changes, and nothing else does:
#
#   * `media_connect()` before the call is forwarded;
#   * the media argument of `b2bua_forward/3` is `@media` instead of `false`. From
#     there the SDP bodies that cross are OURS in both directions: the caller is
#     answered by the media server, the callee is offered by the media server, and
#     the two endpoints are attached when the callee answers. This script never
#     touches an SDP body and never calls a bridge primitive —
#     `b2bua_forward_reply/1` does it, at the one moment both sides are known;
#   * the clauses that only exist because there is a media plane to lose
#     (`:media_lost`, `:media_timeout`, `:server_disconnected`), and a `releasing`
#     state every exit path *after* the call was placed goes through;
#   * a re-offer is read before it is relayed (`b2bua_reoffer_kind/1`). A peer that
#     only moved is answered here, because our endpoint did not move — the one
#     decision the signalling scenario has no way to make.
#
# Authentication is untouched: three states in front of the call, exactly as in
# `direct-call-with-auth.exs`, and none of them allocates media — nothing is
# reserved on the media server for a caller that has not proven who it is.
#
# Separation of concerns (§11.1): `Kelix.Mod.AuthDb` DECIDES who is calling,
# `Kelix.Mod.Registrar` DECIDES where the callee is, and this SCRIPT composes the
# SIP that each verdict means. The module never builds a response, and the script
# never reads an Authorization header nor an SDP body.
#
# The media server is NOT named here: `Kelix.Router` hands each instance the MCU
# `Kelix.MediaPool` selected for that call (`:mediaserver_instance`, design §9), so
# `media_connect/0` reaches a pool-chosen server. With no `[mediaserver.pool.*]`
# configured there is nothing to connect to and this script cannot run — use
# `direct-call-with-auth.exs` for a signalling-only deployment.
defmodule Kelix.DirectCallWithAuthAndMedia do
  use SIP.Scenario

  uas(:invite)

  # Refuse to load when either module is absent, instead of failing on the first
  # INVITE: the location service, and the authentication backend that gates it.
  config(uses_modules: [:registrar, :auth_db])

  # How each leg terminates its media. `inbound: [webrtc: :if_offered]` takes a
  # secure leg when the caller asks for one (SDES from a SIP phone, DTLS+ICE from a
  # WebRTC client) and plain RTP otherwise; `outbound: [webrtc: :no]` offers plain
  # RTP to the registered device — which is what makes this a WebRTC gateway when
  # the two differ.
  #
  # Transcoding is a policy, not a fact. The codec is picked ONCE for both legs:
  # the first codec of the caller's list that the callee also answered (§5).
  # `:avoid` transcodes only when that intersection is empty, `:forbid` refuses the
  # media instead, `:force` keeps each leg on the head of its own list.
  #
  # Video is `:forbid`: transcoding video is the expensive one — a decode, a
  # scale and a re-encode per call — and a video leg that cannot be relayed is
  # better refused than served at that price. Audio keeps `:avoid`, where the
  # fallback costs little and losing the call would cost the caller everything.
  #
  # To reach a callee that is itself a WebRTC client, do not flip `outbound:` here
  # — put `profile: :webrtc_if_supported` on the peer below and let the framework
  # walk the webrtc → avpf → avp ladder on a 488 (§7.5).
  @media {:mediaserver,
          inbound: [webrtc: :if_offered, media: :audio_video],
          outbound: [webrtc: :no, media: :audio_video],
          transcode: [audio: :avoid, video: :forbid]}

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
  # transaction absorbs the ACK of a non-2xx (RFC 3261 §17.2.1). No media has been
  # allocated yet, so every way out of here ends the instance directly.
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
  state place_call do
    req = last_uas_req()

    case Kelix.Mod.Registrar.targets(ctx_get(:domain), req) do
      {:ok, peer} ->
        # The media server first: without one there is nothing to answer the
        # caller with, and the outbound INVITE has no body to carry.
        media_connect()
        b2bua_forward(req, peer, @media)

        if ctx_get(:lasterr) == :ok do
          goto(proceeding, "call forwarded")
        else
          # The offer could not be terminated (no common codec, a WebRTC offer we
          # were told not to take). That is a statement about what the caller
          # asked for, so it is a 488 — not a 500, which would blame us.
          b2bua_reply(req, 488, "Not Acceptable Here")
          goto(releasing, "media setup failed: #{inspect(ctx_get(:lasterr))}")
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

  state proceeding do
    on_events do
      # A provisional. Its SDP, if it has one, is dropped by the framework: with a
      # media server the callee's early media is a media event, not an answer to
      # relay — the caller's answer was decided when their INVITE arrived. That is
      # what leaves the hunt free to walk Bob's other devices (§7.4).
      {:outbound, {code, resp, _trans, _dlg}} when code in 101..199 ->
        b2bua_forward_reply(resp)
        goto(loop, "provisional #{code}")

      # Bob answered: the framework feeds his answer to the outbound endpoint,
      # attaches the two, and puts OUR answer in the 200 Alice receives. One line,
      # and it is the same line as in direct-call-with-auth.exs.
      {:outbound, {200, resp, _trans, _dlg}} ->
        b2bua_forward_reply(resp)
        goto(wait_ack, "200 OK relayed")

      # A refusal — or a 2xx whose media could not be bridged, which the framework
      # hands over as a 488 so it reads as one device refusing rather than as the
      # call failing. If Bob has another device, the hunt is already trying it.
      {:outbound, {code, resp, _trans, _dlg}} when code >= 300 ->
        b2bua_forward_reply(resp)

        if b2bua_hunting?() do
          goto(loop, "#{code}, trying Bob's next device")
        else
          case b2bua_media_error() do
            nil -> goto(releasing, "Bob answered #{code}")
            reason -> goto(releasing, "no device could be bridged: #{inspect(reason)}")
          end
        end

      # Alice gave up. Two different things, and both are wanted: stop the search,
      # and tell the device that is ringing. Then wait: a CANCEL asks, it does not
      # decide (RFC 3261 §16.7).
      {:CANCEL, req, _trans, _dlg} ->
        b2bua_cancel_forward()
        b2bua_forward(req)
        goto(cancelling, "caller cancelled")

      {:BYE, req, _trans, _dlg} ->
        b2bua_cancel_forward()
        b2bua_reply(req, 200, "OK")
        goto(releasing, "caller hung up before answer")

      # The media plane went away while Bob was still ringing. There is no call to
      # hang up yet — Alice gets a 500 and the teardown CANCELs the attempt still
      # ringing at Bob.
      {:ms_event, _ref, :server_disconnected} ->
        b2bua_reply(last_uas_req(), 500, "Media Server Unavailable")
        goto(releasing, "media server gone before answer")

      {:outbound, {:dialog_terminated, _dlg, reason}} ->
        b2bua_reply(last_uas_req(), 500, "Outbound leg lost")
        goto(releasing, "outbound leg died: #{inspect(reason)}")
    after
      180_000 ->
        b2bua_reply(last_uas_req(), 408, "Request Timeout")
        goto(releasing, "Bob never answered")
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
  # bills on. Every branch leaves through `releasing`, which frees the media Alice
  # reserved before she changed her mind.
  state cancelling do
    on_events do
      # What normally comes back, and fast.
      {:outbound, {487, _resp, _trans, _dlg}} ->
        goto(releasing, "caller cancelled, callee confirmed")

      # The race. Bob picked up before the CANCEL reached him; nobody is left to
      # talk to, so acknowledge his answer and hang up (§13.2.2.4 then §15).
      {:outbound, {200, _resp, _trans, _dlg}} ->
        b2bua_send_BYE()
        goto(releasing, "callee answered after the cancellation; hung up")

      # Still ringing somewhere: keep listening rather than take a 180 for an end.
      {:outbound, {code, _resp, _trans, _dlg}} when code in 100..199 ->
        goto(loop, "provisional #{code} after cancel")

      {:outbound, {code, _resp, _trans, _dlg}} when code >= 300 ->
        goto(releasing, "caller cancelled, callee answered #{code}")

      {:outbound, {:dialog_terminated, _dlg, _reason}} ->
        goto(releasing, "caller cancelled, outbound leg gone")

      {:ms_event, _ref, :server_disconnected} ->
        goto(releasing, "media server gone while cancelling")

      {:dialog_terminated, _dlg, _reason} ->
        goto(releasing, "caller cancelled")
    after
      # Bounded on purpose: past timer B the outbound transaction is over whatever
      # we heard, and an instance held on a leg that says nothing is a slot lost.
      32_000 -> goto(releasing, "caller cancelled, callee never concluded")
    end
  end

  # Alice's ACK is relayed rather than answered here: Bob's device gets the ACK of
  # the offer/answer it took part in, which in media mode is ours, not Alice's.
  state wait_ack do
    on_events do
      {:ACK, req, _trans, _dlg} ->
        b2bua_forward(req)
        goto(connected, "ACK relayed")
    after
      # RFC 3261 timer H: no ACK is coming. Hang up the leg we did establish.
      32_000 ->
        b2bua_send_BYE()
        goto(releasing, "no ACK from the caller")
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
        goto(releasing, "inbound leg ended: #{inspect(reason)}")

      {:outbound, {:dialog_terminated, _dlg, reason}} ->
        goto(releasing, "outbound leg ended: #{inspect(reason)}")

      # A leg has stopped sending on EVERY media it negotiated — not one media,
      # which is a peer turning its camera off and no reason to end anything.
      # There is no media left to carry, so both sides are told (§14.6, R2b).
      {:ms_event, _ref, :media_lost} ->
        b2bua_send_BYE()
        b2bua_reply(last_uas_req(), 200, "OK")
        goto(releasing, "media stopped flowing")

      # One media went quiet. Worth saying, not worth hanging up for.
      {:ms_event, _ref, {:media_timeout, media}} ->
        goto(loop, "#{media} went silent")

      # The media server itself is gone. With one media session per call this takes
      # the CALL down, not one leg — so both legs are wound down rather than one of
      # them re-pointed somewhere.
      {:ms_event, _ref, :server_disconnected} ->
        b2bua_send_BYE()
        b2bua_reply(last_uas_req(), 200, "OK")
        goto(releasing, "media server disconnected")

      # A re-INVITE or an UPDATE. Four things arrive under this shape, and the
      # media mode is where they stop being one rule (direct-call-with-auth.exs
      # relays all four): with a media server a peer that merely MOVED — a new
      # c=, a new port, an ICE restart — has not changed anything the far end can
      # see, because our endpoint did not move. Same for a session-timer refresh,
      # which carries no offer at all: each leg has its own timer, and we are a UA
      # on both.
      #
      # Everything else crosses, and the two lists are written in that order on
      # purpose: what is absorbed is named explicitly, and anything the framework
      # cannot classify (`:unknown`) falls through to the relay. Propagating a
      # change nobody needed costs a transaction; swallowing a hold or an added
      # media breaks the call.
      #
      # None of it is re-authenticated: the dialog was authenticated when it was
      # created, and challenging mid-call breaks UAs and proves nothing new
      # (`Kelix.Mod.AuthDb.challengeable?/1`).
      {m, req, _trans, _dlg} when m in [:INVITE, :UPDATE] ->
        case b2bua_reoffer_kind(req) do
          kind when kind in [:address_change, :no_sdp, :no_change] ->
            b2bua_reply_reoffer(req)
            goto(loop, "#{m} answered locally (#{kind}, caller)")

          kind ->
            b2bua_forward(req)
            goto(loop, "relayed #{m} (#{kind}, caller -> callee)")
        end

      {:outbound, {m, req, _trans, _dlg}} when m in [:INVITE, :UPDATE] ->
        case b2bua_reoffer_kind(req) do
          kind when kind in [:address_change, :no_sdp, :no_change] ->
            b2bua_reply_reoffer(req)
            goto(loop, "#{m} answered locally (#{kind}, callee)")

          kind ->
            b2bua_forward(req)
            goto(loop, "relayed #{m} (#{kind}, callee -> caller)")
        end

      # The ACK of a re-INVITE's 200 is a transaction of its own (RFC 3261
      # §13.2.2.4), so every re-INVITE that crosses owes one back.
      {:ACK, req, _trans, _dlg} ->
        b2bua_forward(req)
        goto(loop, "ACK relayed (caller -> callee)")

      {:outbound, {:ACK, req, _trans, _dlg}} ->
        b2bua_forward(req)
        goto(loop, "ACK relayed (callee -> caller)")

      # Default relay, written out rather than assumed: everything else in-dialog
      # (INFO, MESSAGE, REFER…), then the responses.
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
      14_400_000 -> goto(releasing, "maximum call duration reached")
    end
  end

  state wait_far_bye_ok do
    on_events do
      {:outbound, {200, _resp, _trans, _dlg}} -> goto(releasing, "call relayed and ended")
      {200, _resp, _trans, _dlg} -> goto(releasing, "call relayed and ended")
      {:dialog_terminated, _dlg, _reason} -> goto(releasing, "call ended")
      {:outbound, {:dialog_terminated, _dlg, _reason}} -> goto(releasing, "call ended")
    after
      5_000 -> goto(releasing, "BYE unanswered, closing anyway")
    end
  end

  # Every exit path taken once media was allocated comes through here.
  # `media_cleanup_ressources/0` and not `media_stop/0`: this state is reached with
  # the server sometimes already gone, and only the former skips dead handles,
  # releases BOTH legs' peer connections and lets go of the server handle besides
  # (§14.6). Both SIP legs are wound down by the automatic teardown.
  state releasing do
    media_cleanup_ressources()
    scenario_success("call released")
  end

  on_shutdown do
    media_cleanup_ressources()
    scenario_aborted("B2BUA stopped gracefully")
  end
end
