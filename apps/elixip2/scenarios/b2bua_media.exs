# Reference B2BUA scenario — media-terminated. Run it with:
#     elixipp --listen udp:5060 apps/elixip2/scenarios/b2bua_media.exs
#
# Read it next to scenarios/b2bua_basic.exs: same call, same states, and the
# difference between the two files is precisely what a media server costs. That
# pairing is the documentation (design docs/design/DESIGN-FRAMEWORK.md#5-b2bua), which is
# why this arrived as a NEW file rather than as a flag on the other one — the
# basic scenario exists to show a complete B2BUA in ~60 lines of FSM, and it only
# keeps that property while it is the simplest thing that relays a call.
#
# What changes, and nothing else does:
#
#   * `b2bua_resolve()` then `media_connect()` before the call is forwarded — in
#     that order, so the media server is chosen knowing where the call goes;
#   * the media argument of `b2bua_forward/3` is `{:mediaserver, …}` instead of
#     `false`. From there the SDP bodies that cross are OURS in both directions:
#     the caller is answered by the media server, the callee is offered by the
#     media server, and the two endpoints are attached when the callee answers.
#     The scenario never touches an SDP body and never calls a bridge primitive —
#     `b2bua_forward_reply/1` does it, at the one moment both sides are known;
#   * three clauses that only exist because there is a media plane to lose:
#     `:media_lost`, `:server_disconnected`, and the cleanup on the way out;
#   * a re-offer is read before it is relayed (`b2bua_reoffer_kind/1`). A peer
#     that only moved is answered here, because our endpoint did not move —
#     the one decision the signalling scenario has no way to make.
#
# What that buys, beyond transcoding: the caller's answer comes from the media
# server, so it is decided once and never changes as targets change. Early media
# and forking stop being mutually exclusive (§7.4) — with no media server,
# relaying a 183 with SDP pins the leg to that target and ends the hunt.
defmodule B2BUA.Media do
  use SIP.Scenario

  uas(:invite)

  # `peer` is where calls go; `mediaserver` selects the adapter (`:mockup` by
  # default, `:mendooze` for a real one). Override either per run with `-c FILE`.
  config(
    domains: :any,
    peer: "sip:callee@127.0.0.1:5070",
    mediaserver: %{module: :mockup, url: "http://127.0.0.1:8080"}
  )

  # How each leg terminates its media. This is where a WebRTC gateway is
  # expressed — `inbound: [webrtc: :yes]`, `outbound: [webrtc: :no]` — and where
  # transcoding is a policy rather than a fact: `:avoid` connects the two
  # endpoints directly when they share a codec and transcodes only when they do
  # not, `:forbid` fails the call instead, `:force` always transcodes.
  @media {:mediaserver,
          inbound: [webrtc: :if_offered, media: :audio_video],
          outbound: [webrtc: :no, media: :audio_video],
          transcode: [audio: :avoid, video: :avoid]}

  state initial_state do
    goto(wait_invite)
  end

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

  # Open the outbound leg. A state with no on_events: it decides and moves on.
  # The INVITE needs no carrying around — `on_events` stored it and
  # `last_uas_req()` reads it back, here and in every later state.
  state place_call do
    req = last_uas_req()

    # Where the call goes, before which media server carries it: the outbound
    # leg's media has to leave by an interface the callee can reach, and only the
    # resolved target says which that is.
    b2bua_resolve(ctx_get(:peer))

    # Then the media server: without one there is nothing to answer the caller
    # with, and the outbound INVITE has no body to carry. And its verdict is read
    # BEFORE the forward: forwarding on a failed connect used to place a call
    # that signalled perfectly and carried no media at all (2026-08-13).
    media_connect()

    case ctx_get(:lasterr) do
      :ok ->
        b2bua_forward(req, b2bua_resolved_peer(), @media)

        cond do
          ctx_get(:lasterr) == :ok ->
            goto(proceeding, "INVITE relayed")

          # The media server was there a moment ago and is not any more —
          # stopped, or killed under the call. OUR unavailability, so a 503 —
          # which also lets an upstream proxy try another route, where a 488
          # would end the call.
          b2bua_media_unavailable?() ->
            b2bua_reply(req, 503, "Service Unavailable")
            goto(releasing, "media plane gone: #{inspect(ctx_get(:lasterr))}")

          true ->
            # The offer could not be terminated (no common codec, a WebRTC offer
            # we were told not to take). That is a statement about what the
            # caller asked for, so it is a 488 — not a 500, which would blame us.
            b2bua_reply(req, 488, "Not Acceptable Here")
            goto(releasing, "media setup failed: #{inspect(ctx_get(:lasterr))}")
        end

      err ->
        # No media plane: media_connect() found no server, or could not reach
        # the one configured. Same verdict as above, for the same reason.
        b2bua_reply(req, 503, "Service Unavailable")
        goto(releasing, "no media server: #{inspect(err)}")
    end
  end

  state proceeding do
    on_events do
      # A provisional. Its SDP, if it has one, is dropped by the framework: with
      # a media server the callee's early media is a media event, not an answer
      # to relay — the caller's answer was decided when their INVITE arrived.
      # That is what leaves the hunt free to move on.
      {:outbound, {code, resp, _trans, _dlg}} when code in 101..199 ->
        b2bua_forward_reply(resp)
        stay("provisional #{code}")

      # The callee answered: the framework feeds its answer to the outbound
      # endpoint, attaches the two, and puts OUR answer in the 200 the caller
      # receives. One line, and it is the same line as in b2bua_basic.exs.
      {:outbound, {200, resp, _trans, _dlg}} ->
        b2bua_forward_reply(resp)
        goto(wait_ack, "200 OK relayed")

      # A final from the callee — or a 2xx whose media could not be bridged,
      # which the framework hands over as a 488 so it reads as one device
      # refusing rather than as the call failing.
      {:outbound, {code, resp, _trans, _dlg}} when code >= 300 ->
        b2bua_forward_reply(resp)

        if b2bua_hunting?() do
          stay("#{code}, trying the next target")
        else
          case b2bua_media_error() do
            nil -> goto(releasing, "callee answered #{code}")
            reason -> goto(releasing, "no target could be bridged: #{inspect(reason)}")
          end
        end

      # A CANCEL asks, it does not decide (RFC 3261 §16.7): wait for the callee's
      # final before releasing anything.
      {:CANCEL, req, _trans, _dlg} ->
        b2bua_cancel_forward()
        b2bua_forward(req)
        goto(cancelling, "caller cancelled")

      {:BYE, req, _trans, _dlg} ->
        b2bua_cancel_forward()
        b2bua_reply(req, 200, "OK")
        goto(releasing, "caller hung up before answer")

      # The media plane went away while we were still ringing. There is no call
      # to hang up yet — the caller gets a 500 and the teardown CANCELs the
      # attempt still ringing at the callee.
      {:ms_event, _ref, :server_disconnected} ->
        b2bua_reply(last_uas_req(), 500, "Media Server Unavailable")
        goto(releasing, "media server gone before answer")

      {:outbound, {:dialog_terminated, _dlg, reason}} ->
        b2bua_reply(last_uas_req(), 500, "Outbound leg lost")
        goto(releasing, "outbound leg died: #{inspect(reason)}")
    after
      180_000 ->
        b2bua_reply(last_uas_req(), 408, "Request Timeout")
        goto(releasing, "callee never answered")
    end
  end

  # The CANCEL has gone to the callee; its transaction is not over until a final
  # response says so (RFC 3261 §16.7). Ending here instead would leave a device
  # that answers a fraction of a second later off-hook in a call nobody is in.
  #
  # `SIP.DialogImpl` catches that on its own — it is not a policy, so no script
  # may get it wrong — and this state does not make it correct, it makes it
  # VISIBLE. Every branch leaves through `releasing`, which is what frees the
  # media resources this scenario allocated before the caller changed its mind.
  state cancelling do
    on_events do
      {:outbound, {487, _resp, _trans, _dlg}} ->
        goto(releasing, "caller cancelled, callee confirmed")

      # The race. Acknowledge the answer nobody is left to take, then end it
      # (§13.2.2.4 then §15) — and release the media on the way out.
      {:outbound, {200, _resp, _trans, _dlg}} ->
        b2bua_send_BYE()
        goto(releasing, "callee answered after the cancellation; hung up")

      {:outbound, {code, _resp, _trans, _dlg}} when code in 100..199 ->
        stay("provisional #{code} after cancel")

      {:outbound, {code, _resp, _trans, _dlg}} when code >= 300 ->
        goto(releasing, "caller cancelled, callee answered #{code}")

      {:outbound, {:dialog_terminated, _dlg, _reason}} ->
        goto(releasing, "caller cancelled, outbound leg gone")

      {:ms_event, _ref, :server_disconnected} ->
        goto(releasing, "media server gone while cancelling")

      {:dialog_terminated, _dlg, _reason} ->
        goto(releasing, "caller cancelled")
    after
      32_000 -> goto(releasing, "caller cancelled, callee never concluded")
    end
  end

  state wait_ack do
    on_events do
      {:ACK, req, _trans, _dlg} ->
        b2bua_forward(req)
        goto(connected, "ACK relayed")
    after
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
        stay("#{media} went silent")

      # The media server itself is gone. With one media session per call this
      # takes the CALL down, not one leg — so both legs are wound down rather
      # than one of them re-pointed somewhere.
      {:ms_event, _ref, :server_disconnected} ->
        b2bua_send_BYE()
        b2bua_reply(last_uas_req(), 200, "OK")
        goto(releasing, "media server disconnected")

      # A re-INVITE or an UPDATE. Four things arrive under this shape, and the
      # media mode is where they stop being one rule (see b2bua_basic.exs, which
      # relays all four): with a media server a peer that merely MOVED — a new
      # c=, a new port, an ICE restart — has not changed anything the far end can
      # see, because our endpoint did not move. Same for a session-timer refresh,
      # which carries no offer at all: each leg has its own timer, and we are a
      # UA on both.
      #
      # Everything else crosses, and the two lists are written in that order on
      # purpose: what is absorbed is named explicitly, and anything the framework
      # cannot classify (`:unknown`) falls through to the relay. Propagating a
      # change nobody needed costs a transaction; swallowing a hold or an added
      # media breaks the call.
      {m, req, _trans, _dlg} when m in [:INVITE, :UPDATE] ->
        case b2bua_reoffer_kind(req) do
          kind when kind in [:address_change, :no_sdp, :no_change] ->
            b2bua_reply_reoffer(req)
            stay("#{m} answered locally (#{kind}, caller)")

          kind ->
            b2bua_forward(req)
            stay("relayed #{m} (#{kind}, caller -> callee)")
        end

      {:outbound, {m, req, _trans, _dlg}} when m in [:INVITE, :UPDATE] ->
        case b2bua_reoffer_kind(req) do
          kind when kind in [:address_change, :no_sdp, :no_change] ->
            b2bua_reply_reoffer(req)
            stay("#{m} answered locally (#{kind}, callee)")

          kind ->
            b2bua_forward(req)
            stay("relayed #{m} (#{kind}, callee -> caller)")
        end

      # The ACK of a re-INVITE's 200: its own transaction (RFC 3261 §13.2.2.4).
      {:ACK, req, _trans, _dlg} ->
        b2bua_forward(req)
        stay("ACK relayed (caller -> callee)")

      {:outbound, {:ACK, req, _trans, _dlg}} ->
        b2bua_forward(req)
        stay("ACK relayed (callee -> caller)")

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

  # Every exit path comes through here. `media_cleanup_ressources/0` and not
  # `media_stop/0`: this state is reached with the server sometimes already gone,
  # and only the former skips dead handles, releases BOTH legs' peer connections
  # and lets go of the server handle besides (§14.6).
  state releasing do
    media_cleanup_ressources()
    scenario_success("call released")
  end

  on_shutdown do
    media_cleanup_ressources()
    scenario_aborted("controller asked to stop")
  end
end
