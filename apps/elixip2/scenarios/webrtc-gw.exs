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
    mediaserver: %{module: :mendooze, url: "http://10.0.0.12:9090"}
  )

  # The browser leg takes WebRTC, the phone leg must not. Audio transcodes only
  # if the two do not share a codec; video is forced because a browser's VP8 and
  # a phone's H.264 never meet.
  @media {:mediaserver,
          inbound: [webrtc: :yes, media: :audio_video],
          outbound: [webrtc: :no, media: :audio_video],
          transcode: [audio: :avoid, video: :force]}

  state initial_state do
    goto(wait_invite)
  end

  state wait_invite do
    on_events do
      {:INVITE, req, _trans, _dlg} ->
        b2bua_reply(req, 100, "Trying")

        # The media server first: without one there is nothing to answer the
        # browser with, and the outbound INVITE has no body to carry.
        media_connect()

        peer = %SIP.B2bua.Peer{
          uris: [req.ruri],
          # keep what the proxy asked for; only route it back to the proxy
          ruri: :keep,
          outbound_proxy: ctx_get(:proxy)
        }

        b2bua_forward(req, peer, @media)

        if ctx_get(:lasterr) == :ok do
          goto(proceeding, "INVITE relayed")
        else
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
        goto(loop, "provisional #{code}")

      # The phone answered: the framework feeds its answer to the outbound
      # endpoint, attaches the two, and puts OUR answer in the 200 the browser
      # receives. One line, and it is the same line as in direct-call.exs.
      {:outbound, {200, resp, _trans, _dlg}} ->
        b2bua_forward_reply(resp)
        goto(wait_ack, "200 OK relayed")

      # A final from the phone — or a 2xx whose media could not be bridged,
      # which the framework hands over as a 488.
      {:outbound, {code, resp, _trans, _dlg}} when code >= 300 ->
        b2bua_forward_reply(resp)

        case b2bua_media_error() do
          nil -> scenario_success("callee answered #{code}")
          reason -> scenario_failure("call cannot be bridged: #{inspect(reason)}")
        end

      {:CANCEL, req, _trans, _dlg} ->
        b2bua_cancel_forward()
        b2bua_forward(req)
        scenario_aborted("caller cancelled")

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
            goto(loop, "#{m} answered locally (#{kind})")

          kind ->
            b2bua_forward(req)
            goto(loop, "relayed #{m} (#{kind})")
        end

      {:outbound, {m, req, _trans, _dlg}} when m in [:INVITE, :UPDATE] ->
        case b2bua_reoffer_kind(req) do
          kind when kind in [:address_change, :no_sdp, :no_change] ->
            b2bua_reply_reoffer(req)
            goto(loop, "#{m} answered locally (#{kind})")

          kind ->
            b2bua_forward(req)
            goto(loop, "relayed #{m} (#{kind})")
        end

      # One media went quiet. Worth saying, not worth hanging up for — a browser
      # that turned its camera off is still on the call.
      {:ms_event, _ref, {:media_timeout, media}} ->
        goto(loop, "#{media} went silent")

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
        goto(loop, "ACK relayed (caller -> callee)")

      {:outbound, {:ACK, req, _trans, _dlg}} ->
        b2bua_forward(req)
        goto(loop, "ACK relayed (callee -> caller)")

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
