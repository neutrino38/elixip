# WebRTC UAC scenario: place a call as a browser-shaped WebRTC client — SIP over
# WSS, a WebRTC offer (DTLS/ICE, rtcp-mux, mid, candidates), mendooze media — and
# play a media file once the media path is up.
#
# Emulates the captured IVeS web client (docs/webrtc_sdp_design.md §1.8/§2.5)
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
    send_INVITE("sip:#{@callee_num}@#{sip_ctx.domain}", :mediaserver, timeout: 90, webrtc: :yes)
    goto(call_progress)
  end

  # -------------------------------------------------------------------------------
  state call_progress do
    on_events do
      {100, _rsp, _trans_pid, _dialog_pid} ->
        goto(loop, "100 Trying")

      # The captured flow authenticates twice: kamailio answers 407 (proxy) and
      # the gateway answers 401 (with qop="auth"). send_auth_INVITE handles both
      # via the dialog layer; keep the WebRTC offer on the resubmit.
      {code, rsp, _trans_pid, _dialog_pid} when code in [401, 407] ->
        send_auth_INVITE(rsp, "sip:#{@callee_num}@#{sip_ctx.domain}", :mediaserver,
          timeout: 90,
          webrtc: :yes
        )

        goto(loop, "#{code} Authentication Required")

      {180, _rsp, _trans_pid, _dialog_pid} ->
        goto(loop, "180 Ringing")

      {183, rsp_183, trans_pid, _dialog_pid} ->
        process_invite_reply(rsp_183, trans_pid)
        goto(loop, "183 Session Progress")

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
      {:ms_event, _conn, :ice_connected} -> goto(start_play, "media connected")
    after
      10_000 -> scenario_failure("No media connectivity after 10s")
    end
  end

  # -------------------------------------------------------------------------------
  state start_play do
    media_play("titi.mp4")
    goto(next)
  end

  # -------------------------------------------------------------------------------
  state call_established do
    on_events do
      {:ms_event, _player, :player_started} ->
        goto(loop, "media: start")

      {:ms_event, _player, :player_ended} ->
        goto(hangup_call, "media: EOF")

      {:BYE, req, _trans_pid, _dialog_pid} ->
        reply_request(req, 200, "OK")
        scenario_success("BYE")
    end
  end

  # -------------------------------------------------------------------------------
  state hangup_call do
    send_BYE()

    on_events do
      {200, _bye_rsp, _trans_pid, _dialog_pid} -> scenario_success("200 OK")
    after
      4_000 -> scenario_failure("No 200 OK received for BYE")
    end
  end
end
