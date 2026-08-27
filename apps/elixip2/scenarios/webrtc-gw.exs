# Reference B2BUA scenario: a WebRTC-to-SIP gateway.
#
# A browser calls in through the proxy over WebRTC (DTLS-SRTP, ICE, RTP/SAVPF);
# the callee is an ordinary SIP phone behind the same proxy and understands none
# of it. Both legs terminate their media on the server, which translates. Run it
# with:
#     elixipp --listen wss:5061 apps/elixip2/scenarios/webrtc-gw.exs
#
# Commented use case in B2BUA.md, "Scenario webrtc-gw.exs".
defmodule B2BUA.WebrtcGw do
  use SIP.Scenario

  uas(:invite)

  config(
    domains: :any,
    proxy: "sip:proxy.example.com:5060",
    # What the callee is offered, and what to offer it next if it refuses
    # (design §7.5): the ladder is `webrtc → avpf → avp`. `:avp` for a gateway
    # facing phones that are known never to do WebRTC — one offer, no ladder;
    # `:webrtc_required` for one that refuses to place the call in the clear.
    profile: :webrtc_if_supported,
    mediaserver: %{module: :mendooze, url: "http://10.0.0.12:9090"}
  )

  # The browser leg takes WebRTC. The phone leg says nothing about transport
  # here — the profile does, one rung at a time, and writing `webrtc:` in
  # `outbound:` as well would fix the very thing the ladder exists to discover.
  # Audio transcodes only if the two do not share a codec; video is forced
  # because a browser's VP8 and a phone's H.264 never meet.
  @media {:mediaserver,
          inbound: [webrtc: :yes, media: :audio_video],
          outbound: [media: :audio_video],
          transcode: [audio: :avoid, video: :force]}

  state initial_state do
    goto(wait_invite)
  end

  state wait_invite do
    on_events do
      {:INVITE, req, _trans, _dlg} ->
        b2bua_reply(req, 100, "Trying")

        peer = %SIP.B2bua.Peer{
          uris: [req.ruri],
          # keep what the proxy asked for; only route it back to the proxy
          ruri: :keep,
          outbound_proxy: ctx_get(:proxy),
          # A phone that answers "Not Acceptable Here" is refusing the BODY, not
          # the call: the framework offers it the next profile down, on a new
          # INVITE to the same target, before anything else is tried.
          profile: ctx_get(:profile)
        }

        # Where the call goes, before which media server carries it: the outbound
        # leg's media has to leave by an interface the callee can reach, and only
        # the resolved target says which that is.
        b2bua_resolve(peer)

        # Then the media server: without one there is nothing to answer the
        # browser with, and the outbound INVITE has no body to carry.
        media_connect()

        b2bua_forward(req, b2bua_resolved_peer(), @media)

        cond do
          ctx_get(:lasterr) == :ok ->
            goto(proceeding, "INVITE relayed")

          # No media plane: media_connect() found no server, or the one it found
          # is gone. Ours, not the browser's — a 503, which also leaves the proxy
          # in front free to try another gateway.
          b2bua_media_unavailable?() ->
            b2bua_reply(req, 503, "Service Unavailable")
            scenario_failure("no media server: #{inspect(ctx_get(:lasterr))}")

          true ->
            # The offer could not be terminated (no common codec, a WebRTC offer
            # we were told not to take). That is a statement about what the caller
            # asked for, so it is a 488 — not a 500, which would blame us.
            b2bua_reply(req, 488, "Not Acceptable Here")
            scenario_failure("media setup failed: #{inspect(ctx_get(:lasterr))}")
        end
    after
      60_000 -> scenario_failure("no INVITE received")
    end
  end

  state proceeding do
    on_events do
      # A provisional. Its SDP, if it has one, is dropped by the framework: with
      # a media server the phone's early media is a media event, not an answer
      # to relay — the browser's answer was decided when its INVITE arrived.
      {:outbound, {code, resp, _trans, _dlg}} when code in 101..199 ->
        b2bua_forward_reply(resp)
        stay("provisional #{code}")

      # The phone answered: the framework feeds its answer to the outbound
      # endpoint, attaches the two, and puts OUR answer in the 200 the browser
      # receives. One line, and it is the same line as in direct-call.exs.
      {:outbound, {200, resp, _trans, _dlg}} ->
        b2bua_forward_reply(resp)
        goto(wait_ack, "200 OK relayed")

      # A final from the phone — or a 2xx whose media could not be bridged,
      # which the framework hands over as a 488.
      #
      # `b2bua_hunting?/0` is what makes the offer ladder work from here: a 488
      # relayed while a profile is left is not the end of the call, it is the
      # framework having just re-offered the same phone something it may accept.
      # The same question covers a hunt over several targets, which is why it is
      # asked before anything is concluded.
      {:outbound, {code, resp, _trans, _dlg}} when code >= 300 ->
        b2bua_forward_reply(resp)

        if b2bua_hunting?() do
          stay("#{code}, still placing the call")
        else
          case b2bua_media_error() do
            nil -> scenario_success("callee answered #{code}")
            reason -> scenario_failure("call cannot be bridged: #{inspect(reason)}")
          end
        end

      # A CANCEL asks, it does not decide (RFC 3261 §16.7): wait for the phone's
      # final before releasing anything.
      {:CANCEL, req, _trans, _dlg} ->
        b2bua_cancel_forward()
        b2bua_forward(req)
        goto(cancelling, "caller cancelled")

      # The media plane went away while we were still ringing. There is no call
      # to hang up yet — the browser gets a 500 and the teardown CANCELs the
      # INVITE still ringing at the phone.
      {:ms_event, _ref, :server_disconnected} ->
        b2bua_reply(last_uas_req(), 500, "Media Server Unavailable")
        goto(releasing, "media server gone before answer")
    after
      180_000 ->
        b2bua_reply(last_uas_req(), 408, "Request Timeout")
        goto(releasing, "callee never answered")
    end
  end

  # The CANCEL has gone to the phone; its transaction is not over until a final
  # response says so (RFC 3261 §16.7). Ending here instead would leave a handset
  # that answers a fraction of a second later off-hook in a call nobody is in.
  #
  # `SIP.DialogImpl` catches that on its own — it is not a policy, so no script
  # may get it wrong — and this state does not make it correct, it makes it
  # VISIBLE. Every branch leaves through `releasing`, which frees the peer
  # connection the browser leg allocated.
  state cancelling do
    on_events do
      {:outbound, {487, _resp, _trans, _dlg}} ->
        goto(releasing, "caller cancelled, phone confirmed")

      # The race. Acknowledge the answer nobody is left to take, then end it
      # (§13.2.2.4 then §15) — and release the media on the way out.
      {:outbound, {200, _resp, _trans, _dlg}} ->
        b2bua_send_BYE()
        goto(releasing, "phone answered after the cancellation; hung up")

      {:outbound, {code, _resp, _trans, _dlg}} when code in 100..199 ->
        stay("provisional #{code} after cancel")

      {:outbound, {code, _resp, _trans, _dlg}} when code >= 300 ->
        goto(releasing, "caller cancelled, phone answered #{code}")

      {:outbound, {:dialog_terminated, _dlg, _reason}} ->
        goto(releasing, "caller cancelled, outbound leg gone")

      {:ms_event, _ref, :server_disconnected} ->
        goto(releasing, "media server gone while cancelling")

      {:dialog_terminated, _dlg, _reason} ->
        goto(releasing, "caller cancelled")
    after
      32_000 -> goto(releasing, "caller cancelled, phone never concluded")
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

      # A re-offer. On a WebRTC leg this is most often an ICE restart or a new
      # candidate address — the browser moved, our endpoint did not, and telling
      # the phone would be noise at best.
      {m, req, _trans, _dlg} when m in [:INVITE, :UPDATE] ->
        case b2bua_reoffer_kind(req) do
          kind when kind in [:address_change, :no_sdp, :no_change] ->
            b2bua_reply_reoffer(req)
            stay("#{m} answered locally (#{kind})")

          kind ->
            b2bua_forward(req)
            stay("relayed #{m} (#{kind})")
        end

      {:outbound, {m, req, _trans, _dlg}} when m in [:INVITE, :UPDATE] ->
        case b2bua_reoffer_kind(req) do
          kind when kind in [:address_change, :no_sdp, :no_change] ->
            b2bua_reply_reoffer(req)
            stay("#{m} answered locally (#{kind})")

          kind ->
            b2bua_forward(req)
            stay("relayed #{m} (#{kind})")
        end

      # One media went quiet. Worth saying, not worth hanging up for — a browser
      # that turned its camera off is still on the call.
      {:ms_event, _ref, {:media_timeout, media}} ->
        stay("#{media} went silent")

      # Every negotiated media is silent: there is nothing left to carry.
      {:ms_event, _ref, :media_lost} ->
        b2bua_send_BYE()
        b2bua_reply(last_uas_req(), 200, "OK")
        goto(releasing, "media stopped flowing")

      # The media server itself is gone. With one media session per call this
      # takes the CALL down, not one leg.
      {:ms_event, _ref, :server_disconnected} ->
        b2bua_send_BYE()
        b2bua_reply(last_uas_req(), 200, "OK")
        goto(releasing, "media server disconnected")

      {:dialog_terminated, _dlg, reason} ->
        goto(releasing, "inbound leg ended: #{inspect(reason)}")

      {:outbound, {:dialog_terminated, _dlg, reason}} ->
        goto(releasing, "outbound leg ended: #{inspect(reason)}")

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

  # Every exit path comes through here.
  state releasing do
    media_cleanup_ressources()
    scenario_success("call released")
  end

  on_shutdown do
    media_cleanup_ressources()
    scenario_aborted("controller asked to stop")
  end
end
