# Reference UAS (server-side) INVITE scenario — a minimal call server. Run it with:
#     elixipp --listen udp:5060 scenarios/uas_invite.exs
#
# elixipp loads this file, sees it is a `:uas_invite` scenario (set by the
# `uas :invite` annotation), starts the configured listeners and registers
# Elixip.ScenarioUAS as the call processing module. One instance of this scenario
# is spawned per inbound INVITE dialog and receives
# `{:INVITE, req, transaction_id, dialog_pid}` in its mailbox.
#
# The offer request (INVITE / re-INVITE / UPDATE) is stored automatically in the
# context, so the reply_invite* macros serve it without re-passing it. The
# scenario never sends 100 Trying (the INVITE server transaction does) nor the
# 487 on a CANCEL (also automatic) — it is only notified of them.
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
      32_000 -> scenario_failure("no INVITE received")
    end
  end

  state answering do
    # Negotiate the SDP answer with the media server and send 200 OK. On a media
    # failure this replies 500 and sets lasterr, so the goto below aborts.
    reply_invite_with_sdp(200)
    goto(in_call)
  end

  state in_call do
    # media_start_echo()
    media_record("record.mp4", 60000)
    media_play("titi.mp4")

    on_events do
      # ACK of our 2xx (nothing to reply); confirms the call is established.
      {:ACK, _req, _trans, _dlg} ->
        goto(loop, "ACK")

      # Re-INVITE: renegotiate media on the same peer connection.
      {:INVITE, _req, _trans, _dlg} ->
        reply_invite_with_sdp(200)
        goto(loop, "re-INVITE")

      # In-dialog UPDATE.
      {:UPDATE, _req, _trans, _dlg} ->
        reply_invite_with_sdp(200)
        goto(loop, "UPDATE")

      {:BYE, req, _trans, _dlg} ->
        reply_request(req, 200, "OK")
        media_stop();
        scenario_success("BYE")

      # Caller cancelled before / around answer: the IST already sent 200 (CANCEL)
      # and 487 (INVITE); nothing to reply here.
      {:CANCEL, _req, _trans, _dlg} ->
        scenario_success("caller cancelled")

      {:dialog_terminated, _dlg, _reason} ->
        scenario_success("call ended")
    after
      600_000 -> scenario_success("idle timeout")
    end
  end
end
