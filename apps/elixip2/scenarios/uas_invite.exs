# Reference UAS (server-side) INVITE scenario — a minimal call server. Run it with:
#     elixipp --listen udp:5060 apps/elixip2/scenarios/uas_invite.exs
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
defmodule UAS.InviteExample do
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
        media_connect();
        reply_invite(180, "Ringing")
        goto(answering, "INVITE")

      {:scenario_ctl, :shutdown, _reason } -> scenario_aborted("UAS Invite stopped gracefully")
    after
      60_000 -> scenario_failure("no INVITE received")
    end
  end

  state answering do
    # Negotiate the SDP answer with the media server and send 200 OK. On a media
    # failure this replies 500 and sets lasterr, so the goto below aborts.
    reply_invite_with_sdp(200, [media: :tc])
    # media_start_echo()
    # wait_video: start all tracks on the first video I-frame; echo: loop the
    # received video back to the caller while recording.
    media_record("record.mp4", 60000, wait_video: true, echo: true)
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

      # The media plane went away under an established call: the recording is
      # over and there is nothing left to carry the call, so hang up rather than
      # hold a silent one open. `:server_disconnected` is delivered to us but
      # acted upon by nothing in the framework (design
      # docs/design/DESIGN-FRAMEWORK.md#67-the-media-server-as-a-failure-domain) — every media scenario owes this
      # clause, and a UAS more than most: it is the side left holding the call.
      {:ms_event, _server, :server_disconnected} ->
        send_BYE()
        goto hanging_up, "media server disconnected"

      # In-dialog UPDATE.
      {:UPDATE, _req, _trans, _dlg} ->
        reply_invite_with_sdp(200, [media: :tc])
        goto(loop, "UPDATE")

      # In-dialog INFO — in practice a media_control picture_fast_update, which
      # Linphone repeats every 15 s. We have nothing to do with it yet (relaying
      # the FPU to the media server is the job of the mcu module), but it must
      # still be answered: on_events is a plain receive, so an unmatched INFO
      # stays in the mailbox, its server transaction sits in :trying and timer F
      # fires 32 s later.
      {:INFO, req, _trans, _dlg} ->
        reply_request(req, 200, "OK")
        goto(loop, "INFO")

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
    # media_cleanup_ressources/0, not media_stop/0: this state is now also reached
    # WITH the media server gone, and only the former skips dead handles and
    # swallows their errors. It also releases the peer connection and the server
    # handle, which media_stop/0 leaves behind.
    media_cleanup_ressources();
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
