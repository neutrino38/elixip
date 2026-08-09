# Reference UAS (server-side) INVITE scenario — answers a video call and plays a
# media file to the caller. Run it with:
#     elixipp --listen udp:5060 apps/elixip2/scenarios/play.exs
#
# elixipp loads this file, sees it is a `:uas_invite` scenario (set by the
# `uas :invite` annotation), starts the configured listeners and registers
# Elixip.ScenarioUAS as the call processing module. One instance of this scenario
# is spawned per inbound INVITE dialog and receives
# `{:INVITE, req, transaction_id, dialog_pid}` in its mailbox.
#
# The offer request (INVITE / re-INVITE / UPDATE) is stored automatically in the
# context, so the reply_invite* macros serve it without re-passing it. The
# scenario never sends the 487 on a CANCEL (it is automatic) — it is only notified
# of it. A 100 Trying is not automatic: send `reply_invite(100, "Trying")` if needed.
defmodule UAS.Example.Call.Play do
  use SIP.Scenario
  # Adds the server-only redirect_invite / challenge_invite macros. The generic
  # reply_invite* / reply_request come in through SIP.Scenario (-> CallUAC).
  use SIP.Session.CallUAS

  # Marks the scenario type as :uas_invite so elixipp runs it in call-server mode.
  uas(:invite)

  # Served domains (virtual-server style): the INVITE R-URI domain must match,
  # otherwise Elixip.ScenarioUAS rejects the call with 604. `:any` is the
  # catch-all. The media adapter comes from `config :elixip2, :mediaserver`
  # (Mockup by default; override with a `-c FILE` JSON header or config.exs).
  config(domains: :any)

  # The {:INVITE, …} is already queued in our mailbox by the dialog layer.
  state initial_state do
    goto(wait_invite)
  end

  state wait_invite do
    on_events do
      {:INVITE, _req, _trans, _dlg} ->
        # auto_store stashed the request; reply_invite reads it back.
        media_connect()
        reply_invite(180, "Ringing")
        goto(answering, "INVITE")

      {:scenario_ctl, :shutdown, _reason} ->
        scenario_aborted("UAS Invite stopped gracefully")
    after
      60_000 -> scenario_failure("no INVITE received")
    end
  end

  # Negotiate the SDP answer with the media server and send 200 OK. On a media
  # failure this replies 500 and sets lasterr, so the goto below aborts.
  #
  # Sending the 200 and waiting for the events are two DISTINCT states on
  # purpose: the wait state loops on ACK (goto loop re-runs the whole state
  # body, not just its on_events), and re-entering a state that starts with
  # reply_invite_with_sdp would renegotiate the SDP with the media server and
  # re-reply on the already-ACKed transaction.
  state answering do
    reply_invite_with_sdp(200, [media: :tc, webrtc: :if_offered])
    goto(wait_media)
  end

  # Wait for media connectivity before starting playback: :ice_connected fires
  # on the server's first validated RTP packet (plain RTP included), i.e. once
  # the NAT latch is done — starting the player earlier sends the opening
  # keyframe to the (possibly unreachable) SDP address. ACK and :ice_connected
  # arrive in either order; ACK just loops here (safe: no entry action).
  state wait_media do
    on_events do
      {:CANCEL, _req, _trans, _dlg} ->
        scenario_success("caller cancelled")

      # ACK of our 2xx (nothing to reply); confirms the call is established.
      {:ACK, _req, _trans, _dlg} ->
        goto(loop, "ACK")

      # We have media connectivity
      {:ms_event, _conn, :ice_connected} ->
        goto(next, "call established")

      {:BYE, req, _trans, _dlg} ->
        reply_request(req, 200, "OK")
        media_stop()
        scenario_success("BYE before media")

      # The server we answered with is gone: the SDP we sent names a dead media
      # path, so hang up instead of waiting out the timeout. `:server_disconnected`
      # is delivered to us but acted upon by nothing in the framework (design
      # docs/design/b2bua_module.md §14.6) — every media scenario owes this clause.
      {:ms_event, _server, :server_disconnected} ->
        goto(hanging_up, "media server disconnected")
    after
      # a caller that never sends RTP (broken NAT path) must not pin the call
      15_000 -> scenario_failure("no media from caller")
    end
  end

  state start_playing do
    media_play("/var/lib/kelixip/rec/record.mp4")

    on_events do
      {:ms_event, _res, :player_started} ->
        goto(next, "playfile started")

      {:ms_event, _res, {:player_error, reason}} ->
        scenario_failure("player error: #{inspect(reason)}")

      {:ms_event, _server, :server_disconnected} ->
        goto(hanging_up, "media server disconnected")

      {:BYE, req, _trans, _dlg} ->
        reply_request(req, 200, "OK")
        media_stop()
        scenario_success("BYE while starting playback")
    after
      10_000 -> scenario_failure("player did not start")
    end
  end

  state in_call do
    on_events do
      # Re-INVITE: renegotiate media on the same peer connection.
      {:INVITE, _req, _trans, _dlg} ->
        reply_invite_with_sdp(200)
        goto(loop, "re-INVITE")

      {:INFO, req, _trans, _dlg} ->
        reply_request(req, 200, "OK")
        goto(loop, "INFO")

      # In-dialog UPDATE.
      {:UPDATE, _req, _trans, _dlg} ->
        reply_invite_with_sdp(200, [media: :tc])
        goto(loop, "UPDATE")

      {:BYE, req, _trans, _dlg} ->
        reply_request(req, 200, "OK")
        media_stop()
        scenario_success("BYE")

      # End of the played file (the adapter's event is :player_ended, per the
      # MediaServer.Behaviour contract — there is no :player_stopped).
      {:ms_event, _res, :player_ended} ->
        goto(hanging_up, "playfile end")

      {:ms_event, _res, {:player_error, reason}} ->
        goto(hanging_up, "player error: #{inspect(reason)}")

      # Not one resource failing but the whole media plane going away.
      {:ms_event, _server, :server_disconnected} ->
        goto(hanging_up, "media server disconnected")

      {:scenario_ctl, :shutdown, _reason} ->
        goto(hanging_up, "shutdown")

      {:dialog_terminated, _dlg, _reason} ->
        scenario_success("call ended")
    after
      600_000 -> scenario_success("idle timeout")
    end
  end

  state hanging_up do
    # media_cleanup_ressources/0, not media_stop/0: this state is now also reached
    # WITH the media server gone, and only the former skips dead handles and
    # swallows their errors. On the ordinary paths it does everything media_stop/0
    # did and releases the peer connection too.
    media_cleanup_ressources()
    send_BYE()

    on_events do
      {200, _bye_rsp, _trans_pid, _dialog_pid} -> scenario_success("Clean shutdown")
    after
      10_000 -> scenario_failure("BYE not answered")
    end
  end

  # Cooperative shutdown catch-all. The states that know what a wind-down means
  # for them handle it themselves above; this covers every other state and any
  # state added later, which would otherwise leave the media resources
  # allocated on the server.
  on_shutdown do
    media_cleanup_ressources()
    scenario_aborted("UAS Invite stopped gracefully")
  end
end
