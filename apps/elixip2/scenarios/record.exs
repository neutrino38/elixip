#
#  Example of recording audio / video / text in an MP4 file
#
defmodule UAS.Example.Call.Record do
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

        # Do not ring a caller we cannot serve. This scenario exists to record
        # what the caller sends, so with no media server there is nothing to
        # answer with and nothing to record — see no_media_server for the code.
        case ctx_get(:lasterr) do
          {:error, :no_media_server} -> goto(no_media_server, "no media server")
          _ -> goto(ringing, "INVITE")
        end

      {:scenario_ctl, :shutdown, _reason } -> scenario_aborted("UAS Invite stopped gracefully")
    after
      60_000 -> scenario_failure("no INVITE received")
    end
  end

  # A state of its own rather than two more lines above: the 180 is what commits
  # us to the call, and it must come after the media server is known to exist.
  state ringing do
    reply_invite(180, "Ringing")
    goto(answering)
  end

  # No media server to be had — the pool looked and found none. `503`, not a `488`:
  # the caller's offer is fine, we are the ones missing a resource, and a 503 is
  # what lets an upstream proxy try somewhere else.
  #
  # This state exists because the alternative was worse than a refusal: a missing
  # media server used to fall back to the global `:mediaserver` config, whose
  # default is the TEST MOCKUP. The call then answered, recorded nothing, and
  # reported success (2026-08-13).
  state no_media_server do
    reply_invite(503, "Service Unavailable")
    scenario_failure("no media server available")
  end

  state answering do
    # Negotiate the SDP answer with the media server and send 200 OK. On a media
    # failure this replies 500 and sets lasterr, so the goto below aborts.
    reply_invite_with_sdp(200, [media: :tc, webrtc: :if_offered])
    # media_start_echo()
    # wait_video: start all tracks on the first video I-frame; echo: loop the
    # received video back to the caller while recording.
    media_record("/var/lib/kelixip/rec/record.mp4", 60000, wait_video: true, echo: true)
    goto(in_call)
  end

  state in_call do
    on_events do
      # ACK of our 2xx (nothing to reply); confirms the call is established.
      {:ACK, _req, _trans, _dlg} ->
        goto(loop, "ACK")

      # Re-INVITE: renegotiate media on the same peer connection.
      {:INVITE, _req, _trans, _dlg} ->
        reply_invite_with_sdp(200)
        goto(loop, "re-INVITE")

      {:ms_event, _recorder, :recorder_started} ->
        goto loop, "recorder started"

      # In-dialog UPDATE.
      {:UPDATE, _req, _trans, _dlg} ->
        reply_invite_with_sdp(200, [media: :tc])
        goto(loop, "UPDATE")

      {:BYE, req, _trans, _dlg} ->
        reply_request(req, 200, "OK")
        media_stop();
        scenario_success("BYE")

      # Caller cancelled before / around answer: the IST already sent 200 (CANCEL)
      # and 487 (INVITE); nothing to reply here.
      {:CANCEL, _req, _trans, _dlg} ->
        scenario_success("caller cancelled")

      {:scenario_ctl, :shutdown, _reason } ->
        send_BYE()
        goto hanging_up, "shutdown"

      {:dialog_terminated, _dlg, _reason} ->
        scenario_success("call ended")
    after
      600_000 -> scenario_success("idle timeout")
    end
  end

  state hanging_up do
    media_stop();
    on_events do
      {200, _bye_rsp, _trans_pid, _dialog_pid} -> scenario_success("Clean shutdown")
    after
      10_000 -> scenario_failure("BYE not answered")
    end
   end

  # Cooperative shutdown catch-all. The two states that know what a wind-down
  # means for them handle it themselves above (wait_invite aborts, in_call sends
  # a BYE and waits for its 200); this covers every other state — today
  # hanging_up, where a second shutdown means "stop waiting for that 200" — and
  # any state added later, which would otherwise leave the media resources
  # allocated on the server.
  #
  # It also makes the script servable by kelixip: Kelix.ScriptRegistry refuses a
  # script with no `on_shutdown` block, precisely so no served scenario relies on
  # elixip's default (abrupt) abort.
  #
  # media_cleanup_ressources, not media_stop: it releases the action, the peer
  # connection and the server handle, and is nil-safe — reached before
  # media_connect() (or after a media_stop) it is a no-op, where media_stop
  # raises on a context with no media server.
  on_shutdown do
    media_cleanup_ressources()
    scenario_aborted("UAS Invite stopped gracefully")
  end
end
