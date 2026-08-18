# Reference kelixip call script: Alice calls Bob — authenticated, media in the middle.
#
# `direct-call-with-auth.exs` with the media plane of `scenarios/b2bua_media.exs`:
# kamailio's `proxy_authenticate(); lookup("location"); t_relay()`, done as a
# media-terminated B2BUA. Read it next to `direct-call-with-auth.exs` — the
# difference between the two files is precisely what a media server costs
# (design docs/design/DESIGN-FRAMEWORK.md#57-media-modes).
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
  use SBB.Call

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
  #
  # `:avoid` on both. It does put a transcoder on the path — `:forbid` is the only
  # policy that wires a bare Endpoint ↔ Endpoint — but a JSR-309 transcoder decides
  # per incoming packet: while both legs carry the same codec it forwards untouched,
  # and the answer floats that shared set to the front so they keep doing so. What
  # it buys over a bare relay is the day a peer switches codec mid-stream: the path
  # follows instead of breaking, with no renegotiation.
  #
  # Video could not afford this until the media server learnt to bridge video the
  # way it bridges audio (mediaserver 8f80fed) — before that, a transcoder on the
  # path meant a decode, a scale and a re-encode on every single call.
  #
  # To reach a callee that is itself a WebRTC client, do not flip `outbound:` here
  # — put `profile: :webrtc_if_supported` on the peer below and let the framework
  # walk the webrtc → avpf → avp ladder on a 488 (§7.5).
  @media {:mediaserver,
          inbound: [webrtc: :if_offered, media: :audio_video],
          outbound: [webrtc: :no, media: :audio_video],
          transcode: [audio: :avoid, video: :avoid]}

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
  #
  # `media_connect()` stays HERE, before the block: whether this call has a media
  # plane at all is this script's decision, and a server that cannot be reached
  # means no call is placed. What `call/1` takes over starts at the forward.
  #
  # Every outcome leaves through `releasing` rather than through a terminal —
  # what the media server holds for this call has to be given back, whichever way
  # the call ended. That is the whole of what a media B2BUA adds here, and it is
  # exactly the part the block does not decide.
  state place_call do
    req = last_uas_req()

    case Kelix.Mod.Registrar.targets(ctx_get(:domain), req) do
      {:ok, peer} ->
        # The media server first: without one there is nothing to answer the
        # caller with, and the outbound INVITE has no body to carry.
        media_connect()

        case ctx_get(:lasterr) do
          {:error, :no_media_server} ->
            # There is no media server to be had — the pool looked and found none.
            # That is OUR unavailability, not a problem with what the caller
            # offered, so it is a 503 and it may carry a Retry-After: an upstream
            # proxy can try another route, which a 488 would never let it do.
            #
            # This branch exists because the alternative was worse than a refusal:
            # a missing pooled MCU used to fall back to the global `:mediaserver`
            # config, whose default is the TEST MOCKUP. The call then signalled
            # perfectly and carried no media at all (2026-08-13).
            b2bua_reply(req, 503, "Service Unavailable")
            goto(releasing, "no media server available")

          :ok ->
            call(args: %{peer: peer, request: req, media: @media})

            on_events do
              {:call, :connected, _} ->
                goto(connected, "call established")

              # A refusal — or a 2xx whose media could not be bridged, which the
              # framework hands over as a 488 so it reads as one device refusing
              # rather than as the call failing.
              {:call, :rejected, %{code: code}} ->
                case b2bua_media_error() do
                  nil -> goto(releasing, "Bob answered #{code}")
                  reason -> goto(releasing, "no device could be bridged: #{inspect(reason)}")
                end

              {:call, :cancelled, _} ->
                goto(releasing, "caller cancelled, callee confirmed")

              {:call, :answered_after_cancel, _} ->
                goto(releasing, "callee answered after the cancellation; hung up")

              {:call, :caller_hung_up, _} ->
                goto(releasing, "caller hung up before answer")

              {:call, :caller_gone, %{reason: reason}} ->
                goto(releasing, "caller vanished while it rang: #{inspect(reason)}")

              # The media plane went away before the call was up. The block has
              # already answered the caller when their INVITE was still pending.
              {:call, :media_lost, _} ->
                goto(releasing, "media server gone before answer")

              {:call, :timeout, _} ->
                goto(releasing, "Bob never answered")

              {:call, :failed, %{reason: reason}} ->
                goto(releasing, "call setup failed: #{inspect(reason)}")
            end

          other ->
            # media_connect() failed for a reason of its own. Ours either way.
            b2bua_reply(req, 503, "Service Unavailable")
            goto(releasing, "media connect failed: #{inspect(other)}")
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

  # The call is up. `bridge/1` is the relay — every arm of the state this replaces
  # was a forward and a stay — and `media: @media` is what tells it that a peer
  # merely MOVING has nothing to say to the far end, because our endpoint did not
  # move. What is left here is what the media plane makes into a decision.
  state connected do
    bridge(args: %{media: @media})

    on_events do
      {:bridge, :ended, _} ->
        goto(releasing, "call relayed and ended")

      {:bridge, :max_duration, _} ->
        goto(releasing, "maximum call duration reached")

      # No media left to carry — either a leg stopped sending on every media it
      # negotiated (§14.6, R2b), or the server itself is gone, which with one
      # media session per call takes the CALL down rather than one leg. Both
      # sides are told, and that is a decision, which is why the block reports it
      # instead of taking it.
      {:bridge, :media_lost, %{reason: reason}} ->
        b2bua_send_BYE()
        b2bua_reply(last_uas_req(), 200, "OK")
        goto(releasing, "media plane gone: #{reason}")

      # Nothing in this script asks for the call back yet. Left explicit so the
      # day something does, the arm is where it is expected rather than missing.
      {:bridge, :interrupted, %{message: message}} ->
        goto(releasing, "bridge interrupted with nothing to do: #{inspect(message)}")
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
