# WebRTC UAC scenario: place a call as a browser-shaped WebRTC client — SIP over
# WSS, a WebRTC offer (DTLS/ICE, rtcp-mux, mid, candidates), T.140 text on an
# outgoing WebSocket, mendooze media — then play a media file and record what
# comes back, so the returned file can be compared to the source.
#
# Emulates the captured IVeS web client (docs/design/DESIGN-FRAMEWORK.md#65-webrtc-sdp/§2.5)
# against the IVeS WebRTC gateway. Run it against the dev platform with:
#     elixipp -c ives.json scenarios/uac_invite_webrtc.exs
#
# The `-c FILE` JSON overrides the placeholder identity below and selects the
# media adapter through its `"mediaserver"` header key (e.g. mendooze). Without
# a real gateway, keep the Mockup media adapter (config.exs default) for a
# call-flow smoke run.
defmodule UAC.InviteWebRTC do
  use SIP.Scenario

  # Placeholder identity — override at run time with `elixipp -c FILE`.
  @username "1000"
  @authusername "1000"
  @displayname "WebRTC Test User"
  @domain "example.com"
  # WebRTC signaling proxy reached over WSS (the transport layer routes
  # transport=wss). Overridable by the external JSON header.
  @proxy "sip.example.com"
  @passwd "changeme"
  @callee_num "90901"

  config(
    username: @username,
    authusername: @authusername,
    displayname: @displayname,
    domain: @domain,
    passwd: @passwd,
    # WSS signaling: the transport parameter selects the WebSocket-Secure
    # transport (SIP.Transport.WSS). Port 443 is the usual WSS front.
    proxyuri: "sip:#{@proxy}:443;transport=wss",
    proxyusesrv: false
  )

  # -------------------------------------------------------------------------------
  state initial_state do
    # Media adapter (Mockup / Mendooze) + URL come from config :elixip2,
    # :mediaserver — override per run with the `-c FILE` JSON "mediaserver" key.
    media_connect()
    goto(next)
  end

  # -------------------------------------------------------------------------------
  state calling do
    # webrtc: :yes makes the media layer build a browser-shaped WebRTC offer
    # (UDP/TLS/RTP/SAVPF, setup:actpass, ice, rtcp-mux, mid, candidates).
    #
    # text_transport: :ws is the browser's own text arrangement: audio and video
    # in RTP, and T.140 on a WebSocket the media server OPENS towards the URL the
    # answer publishes. Drop the option and the text goes on a WebRTC data
    # channel instead, which is the default on a WebRTC leg.
    send_INVITE("sip:#{@callee_num}@#{sip_ctx.domain}", :mediaserver,
      timeout: 90,
      webrtc: :yes,
      media: [:audio, :video, :text],
      text_transport: :ws
    )

    on_events do
      {100, _rsp, _trans_pid, _dialog_pid} ->
        stay("100 Trying")

      # The captured flow authenticates twice: kamailio answers 407 (proxy) and
      # the gateway answers 401 (with qop="auth"). send_auth_INVITE handles both
      # via the dialog layer; keep the WebRTC offer on the resubmit.
      {code, rsp, _trans_pid, _dialog_pid} when code in [401, 407] ->
        send_auth_INVITE(rsp, "sip:#{@callee_num}@#{sip_ctx.domain}", :mediaserver,
          timeout: 90,
          webrtc: :yes,
          media: [:audio, :video, :text],
          text_transport: :ws
        )

        stay("#{code} Authentication Required")

      {180, _rsp, _trans_pid, _dialog_pid} ->
        stay("180 Ringing")

      {183, rsp_183, trans_pid, _dialog_pid} ->
        process_invite_reply(rsp_183, trans_pid)
        stay("183 Session Progress")

      {200, rsp_200, trans_pid, _dialog_pid} ->
        process_invite_reply(rsp_200, trans_pid)
        goto(call_answered, "200 OK")

      {code, _rsp, _trans_pid, _dialog_pid} when code in 400..699 ->
        scenario_failure("Call failure with code #{code}")
    after
      30_000 -> scenario_failure("Call not answered after 30s")
    end
  end

  # -------------------------------------------------------------------------------
  state call_answered do
    on_events do
      # ICE/DTLS came up (real EndpointConnectedEvent on mendooze, simulated on
      # the Mockup): the media path is ready.
      {:ms_event, _conn, :ice_connected} ->
        goto(call_established, "media connected")

      # Media negotiation/setup failed (bad remote SDP, no common codec, a
      # control RPC error…). Trace the cause and hang up instead of waiting for
      # the timeout.
      {:ms_event, _conn, {:media_error, reason}} ->
        goto(no_media_hangup, "media negotiation failed: #{inspect(reason)}")

      # Not a negotiation failure: the server itself is gone, so there is nothing
      # to renegotiate with. Same destination, and for a stronger reason.
      {:ms_event, _server, :server_disconnected} ->
        goto(no_media_hangup, "media server disconnected")
    after
      30_000 -> goto(no_media_hangup, "no media connectivity after 30s")
    end
  end

  # -------------------------------------------------------------------------------
  state call_established do
    # The recorder FIRST: what the far end returns starts arriving as soon as the
    # player sends, and a recorder started afterwards misses the head of it. Its
    # duration is unbounded (0) — the playback is what decides how long this
    # runs. Both handles live at once on this leg: a player feeds what the
    # endpoint sends, a recorder takes what it receives.
    #
    # `.mkv`, not `.mp4`: the Matroska container takes PCMU, Opus, H.264, VP8 and
    # the text track as they come. In MP4 a PCMU return is transcoded to AAC and
    # a VP8 one is lost, so the comparison with the source would no longer say
    # anything about the network (the media server's
    # `docs/maintenance/recette-ws-client.md`).
    media_record("/home/buu/record-return.mkv", 0)
    media_play("/home/buu/record.mp4")

    on_events do
      {:ms_event, _player, :player_started} ->
        stay("media: start")

      {:ms_event, _recorder, :recorder_started} ->
        stay("record: start")

      {:ms_event, _player, :player_ended} ->
        goto(draining_record, "media: EOF")

      # The media server closed the file on its own (an error, or a stop
      # condition in its options): there is nothing left to record.
      {:ms_event, _recorder, {:recorder_stopped, reason}} ->
        goto(hangup_call, "record stopped: #{inspect(reason)}")

      {:BYE, req, _trans_pid, _dialog_pid} ->
        reply_request(req, 200, "OK")
        scenario_success("BYE")

      # The media plane died under an established call: hang up rather than hold
      # a silent call open. `:server_disconnected` is delivered to us but the
      # framework acts on none of it (design docs/design/DESIGN-FRAMEWORK.md#67-the-media-server-as-a-failure-domain),
      # so every media scenario owes this clause.
      {:ms_event, _server, :server_disconnected} ->
        goto(hangup_call, "media server disconnected")
    end
  end

  # -------------------------------------------------------------------------------
  # The far end returns what it was sent, so the tail of the file is still coming
  # back when the player reaches EOF. The recording keeps running for that tail —
  # without it the returned file stops short of its end and the comparison with
  # the source fails on material nothing lost. `media_cleanup_ressources/0` in
  # `hangup_call` is what closes the file, and closing it is what writes the MP4
  # index.
  state draining_record do
    on_events do
      {:ms_event, _recorder, {:recorder_stopped, reason}} ->
        goto(hangup_call, "record stopped: #{inspect(reason)}")

      {:BYE, req, _trans_pid, _dialog_pid} ->
        reply_request(req, 200, "OK")
        scenario_success("BYE")

      {:ms_event, _server, :server_disconnected} ->
        goto(hangup_call, "media server disconnected")
    after
      3_000 -> goto(hangup_call, "record tail elapsed")
    end
  end

  # -------------------------------------------------------------------------------
  state hangup_call do
    # Before the BYE, and with the defensive helper rather than media_stop/0: it
    # skips dead handles and swallows their errors, where media_stop/0 would call
    # a server that may be the very thing that died.
    media_cleanup_ressources()
    send_BYE()

    on_events do
      {200, _bye_rsp, _trans_pid, _dialog_pid} -> scenario_success("200 OK")
    after
      4_000 -> scenario_failure("No 200 OK received for BYE")
    end
  end

  # -------------------------------------------------------------------------------
  state no_media_hangup do
    media_cleanup_ressources()
    send_BYE()

    on_events do
      {200, _bye_rsp, _trans_pid, _dialog_pid} -> scenario_failure("rcv_media timed out")
    after
      4_000 -> scenario_failure("No 200 OK received for BYE")
    end
  end
end
