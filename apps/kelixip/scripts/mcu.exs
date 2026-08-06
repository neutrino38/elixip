# Reference kelixip conference (MCU) script — design docs/design/mcu_module.md §7.
# One instance is spawned per inbound INVITE by Kelix.Router → Kelix.InstancePool;
# the served domain is injected into the context by the router (`domain:` override).
#
# Separation of concerns, as in registrar.exs (§11.1): the MODULE decides, the
# SCRIPT composes the SIP response. The `admit` DSL macro (Kelix.Mod.Mcu.Script,
# backed by the context-aware Kelix.Mod.Mcu.admit/4 through do_admit/4 below)
# resolves the DID, reserves the slot and stores the participant handle in the
# appdata (:mcu_conf / :mcu_part); its verdict comes back in sip_ctx.lasterr,
# mapped here onto SIP codes:
#
#   :ok                             -> 180, then 200 with the SDP answer
#   {:error, :no_such_conference}   -> 404 Not Found
#   {:error, :full}                 -> 486 Busy Here
#   {:error, :mcu_down}             -> 503 Service Unavailable
#   :jsr309_media_already_in_use    -> 500 (a JSR309 media session already runs on
#                                      this session: MCU and JSR309 calls are
#                                      mutually exclusive)
#
# It is shipped as a REFERENCE, not as a fixed part of the module: it lives in
# script_dir, a domain points a dial rule at it, and a deployment is expected to copy
# and adapt it. Joining is deliberately NOT authenticated (§6.1.1, limitation L8):
# whoever reaches the DID enters the conference. A deployment that needs a PIN or a
# digest challenge inserts it before the admit call below and points its dial rule at
# the copy — no module change, no core change.
#
# It answers **total conversation** — audio, video and T.140 text (with RFC 4103
# redundancy when the caller offers it) — over plain RTP, SDES-SRTP or DTLS-SRTP +
# ICE-lite, so a SIP phone, a text terminal and a WebRTC gateway join the same
# conference. A media the offer does not carry is simply not answered; one with no
# codec in common is answered with port 0 and the call proceeds without it.
#
# NOTE — self-references must go through `__MODULE__`, never through the name
# written below: the script registry appends `.V<version>` to every module of a
# loaded script (hot reload, §5.3), so this compiles as `Kelix.Mcu.Call.V1` and a
# hardcoded `Kelix.Mcu.Call.f()` would be a call into a module that does not exist.
defmodule Kelix.Mcu.Call do
  use SIP.Scenario
  use SIP.Session.CallUAS
  # the admit/attach/leave DSL macros — rebind sip_ctx in place, verdict in sip_ctx.lasterr
  use Kelix.Mod.Mcu.Script
  require Logger
  import SIP.Session, only: [reply: 5, reply: 6]

  uas(:invite)

  # Declared so the load-time contract (§5.3) refuses this script when the module is
  # not installed, instead of letting the first INVITE die inside the instance.
  config(uses_modules: [:mcu])

  # The {:INVITE, …} is already queued in our mailbox by the dialog layer.
  state initial_state do
    goto(wait_invite)
  end

  state wait_invite do
    on_events do
      {:INVITE, req, _trans, dialog_pid} ->
        reply_invite(100, "Trying")

        admit(req, dialog_pid)

        case sip_ctx.lasterr do
          :ok ->
            # admit/4 stored the conference and the participant handle in the appdata
            conf = SIP.Context.appdata_get(sip_ctx, :mcu_conf)
            part = SIP.Context.appdata_get(sip_ctx, :mcu_part)

            # The local identity of this leg is the conference itself: it is what an
            # in-dialog request we originate (the BYE below) puts in From/To, and
            # without it `send_BYE()` has no URI to build.
            ctx_set(:username, conf.did)
            # FW-1: tells the adapter which conference this leg joins. The media
            # macros forward it to create_peer_connection/3 without having to know
            # what it means. `nat_latch` rides along: a conference leg always answers
            # the caller's offer, so the address we are told to send to is the one the
            # caller wrote down — its private one, for every handset behind a NAT.
            appdata_set(:media_conn_opts, mcu_participant: part, nat_latch: true)
            # A conference is pinned to its MCU (§1.3): the leg must reach the server
            # holding the mixer, not whatever the media pool would hand out.
            appdata_set(:mediaserver_instance, Kelix.Mod.Mcu.media_config(conf))

            media_connect()
            reply_invite(180, "Ringing")
            goto(answering, "INVITE #{conf.did}")

          # MCU and JSR309 calls are mutually exclusive; the 500 is already out
          :jsr309_media_already_in_use ->
            scenario_failure("JSR309 media session already in progress")

          # module verdict; the SIP error response is already out
          {:error, reason} ->
            scenario_success("rejected: #{inspect(reason)}")
        end

      {:CANCEL, _req, _trans, _dlg} ->
        scenario_success("cancelled before answer")

      {:scenario_ctl, :shutdown, _reason} ->
        scenario_aborted("MCU script stopped gracefully")
    after
      30_000 -> scenario_failure("no INVITE received")
    end
  end

  state answering do
    # → adapter set_remote_offer: negotiate, StartReceiving, build the answer. The
    # per-cause mapping matters (§6.5): an unusable offer is a 488 (retrying it is
    # pointless), a media-server failure a 500 (ours, and a retry may work).
    reply_invite_with_sdp(200,
      # total conversation: audio, video and T.140 text. This is what we *accept*,
      # not what we demand — only the medias the offer actually carries are answered,
      # so an audio-only phone is unaffected. A conference whose `medias` omits "text"
      # declines the text section with port 0 the same way.
      media: :tc,
      # accept a secure leg when the offer asks for one (SDES from a SIP phone,
      # DTLS+ICE from a WebRTC gateway); `:no` would refuse it with a 488
      webrtc: :if_offered,
      on_media_error: &__MODULE__.media_error/1
    )

    case sip_ctx.lasterr do
      {:media_error, reason} ->
        # The error response is already out; release the slot and end cleanly. The
        # code we answered with travels with the reason so the module's call funnel
        # (§11) can tell a 488 from a 500 — only the script knows which it chose.
        {code, _text} = media_error(reason)
        media_cleanup_ressources()
        leave({:no_media, code})
        scenario_success("media refused: #{code} (#{inspect(reason)})")

      _ ->
        goto(in_call)
    end
  end

  state in_call do
    on_events do
      # The ACK is what puts the participant in the mix: a caller that never ACKs
      # never enters it, and no RTP leaves the MCU before that (§2, point 2). Once
      # in, move to in_conference: the caller re-sends this ACK for every 200 the
      # transaction layer retransmits (RFC 3261 §13.2.2.4), and those copies must
      # not re-run the ACK-time sequence.
      {:ACK, _req, _trans, _dlg} ->
        attach()
        goto(in_conference, "ACK: in the mix")

      # Re-INVITE / UPDATE: renegotiate on the same participant.
      {:INVITE, _req, _trans, _dlg} ->
        reply_invite_with_sdp(200,
          media: :tc,
          webrtc: :if_offered,
          on_media_error: &__MODULE__.media_error/1
        )

        goto(loop, "re-INVITE")

      {:UPDATE, _req, _trans, _dlg} ->
        reply_invite_with_sdp(200,
          media: :tc,
          webrtc: :if_offered,
          on_media_error: &__MODULE__.media_error/1
        )

        goto(loop, "UPDATE")

      # An INFO carrying media_control+xml is the peer asking for an intra-frame from
      # what the mixer sends it (a decoder that lost sync). §6.4: answer 200 either
      # way — an INFO we do not understand is still a request we must not leave
      # unanswered — and ask the MCU for the frame when it is that.
      {:INFO, req, _trans, dialog_pid} ->
        reply(dialog_pid, req, 200, "OK", [])
        goto(loop, request_fpu(sip_ctx, req))

      {:BYE, req, _trans, dialog_pid} ->
        reply(dialog_pid, req, 200, "OK", [])
        media_cleanup_ressources()
        leave(:bye)
        scenario_success("BYE")

      # The caller cancelled around the answer: the IST already sent 487, only the
      # teardown is ours.
      {:CANCEL, _req, _trans, _dlg} ->
        media_cleanup_ressources()
        leave(:cancel)
        scenario_success("cancelled")

      # The media server went away (§9.2): the mix is gone, so the call is too.
      {:mcu_event, :server_disconnected} ->
        media_cleanup_ressources()
        leave(:mcu_lost)
        send_BYE()
        goto(hanging_up, "mcu lost")

      # The mixer needs a fresh intra-frame from this leg (a new tile started, or a
      # decoder lost sync): ask for one the way RFC 5168 has it (§6.4).
      {:mcu_event, :fpu_requested} ->
        send_INFO(__MODULE__.picture_fast_update(),
          contenttype: "application/media_control+xml"
        )

        goto(loop, "FPU requested")

      # P7/S1 (§16.1): every media of this leg has gone silent — the module only sends
      # this once the AND is satisfied, so one dead media does not get us here. Same
      # teardown as losing the media server: the call is over, it just has not been
      # hung up yet.
      {:mcu_event, :media_timeout, media} ->
        media_cleanup_ressources()
        leave(:media_timeout)
        send_BYE()
        goto(hanging_up, "media timeout on #{media}")

      # P7/S2: real media is flowing. An observation for the operator view, already
      # emitted by the module — nothing for the call to do.
      {:mcu_event, :media_connected, _media} ->
        goto(loop, "media connected")

      {:mcu_event, _event} ->
        goto(loop, "mcu event")

      {:mcu_event, _event, _arg} ->
        goto(loop, "mcu event")

      {:dialog_terminated, _dlg, _reason} ->
        media_cleanup_ressources()
        leave(:bye)
        scenario_success("dialog ended")

      {:scenario_ctl, :shutdown, _reason} ->
        send_BYE()
        goto(hanging_up, "shutdown")
    after
      # G3: with no RTP watchdog on the MCU API, this is the only protection against
      # a leg that stops sending. P7 makes it the last resort behind the watchdog.
      7_200_000 ->
        send_BYE()
        goto(hanging_up, "idle timeout")
    end
  end

  # The steady state, split from in_call so only the FIRST ACK runs the ACK-time
  # sequence. Retransmitted ACKs are a normal fact of UDP life — each one used to
  # re-run attach/1 and re-emit participant.joined per retransmission.
  state in_conference do
    on_events do
      # the retransmission itself: this leg is already in the mix
      {:ACK, _req, _trans, _dlg} ->
        goto(loop, "ACK retransmitted; already in the mix")

      # Re-INVITE: renegotiate on the same participant. Answering rewinds the
      # adapter to answered, and the re-INVITE's own ACK must re-run the ACK-time
      # sequence on the changed medias — wait for it back in in_call.
      {:INVITE, _req, _trans, _dlg} ->
        reply_invite_with_sdp(200,
          media: :tc,
          webrtc: :if_offered,
          on_media_error: &__MODULE__.media_error/1
        )

        goto(in_call, "re-INVITE")

      # UPDATE renegotiates too but carries no ACK (RFC 3311): its 200 concludes
      # the offer/answer, so the ACK-time sequence runs right away.
      {:UPDATE, _req, _trans, _dlg} ->
        reply_invite_with_sdp(200,
          media: :tc,
          webrtc: :if_offered,
          on_media_error: &__MODULE__.media_error/1
        )

        attach()
        goto(loop, "UPDATE: renegotiated")

      # From here on, exactly what in_call handles.
      {:INFO, req, _trans, dialog_pid} ->
        reply(dialog_pid, req, 200, "OK", [])
        goto(loop, request_fpu(sip_ctx, req))

      {:BYE, req, _trans, dialog_pid} ->
        reply(dialog_pid, req, 200, "OK", [])
        media_cleanup_ressources()
        leave(:bye)
        scenario_success("BYE")

      {:CANCEL, _req, _trans, _dlg} ->
        media_cleanup_ressources()
        leave(:cancel)
        scenario_success("cancelled")

      {:mcu_event, :server_disconnected} ->
        media_cleanup_ressources()
        leave(:mcu_lost)
        send_BYE()
        goto(hanging_up, "mcu lost")

      {:mcu_event, :fpu_requested} ->
        send_INFO(__MODULE__.picture_fast_update(),
          contenttype: "application/media_control+xml"
        )

        goto(loop, "FPU requested")

      # P7/S1 (§16.1): every media of this leg has gone silent — the module only sends
      # this once the AND is satisfied, so one dead media does not get us here. Same
      # teardown as losing the media server: the call is over, it just has not been
      # hung up yet.
      {:mcu_event, :media_timeout, media} ->
        media_cleanup_ressources()
        leave(:media_timeout)
        send_BYE()
        goto(hanging_up, "media timeout on #{media}")

      # P7/S2: real media is flowing. An observation for the operator view, already
      # emitted by the module — nothing for the call to do.
      {:mcu_event, :media_connected, _media} ->
        goto(loop, "media connected")

      {:mcu_event, _event} ->
        goto(loop, "mcu event")

      {:mcu_event, _event, _arg} ->
        goto(loop, "mcu event")

      {:dialog_terminated, _dlg, _reason} ->
        media_cleanup_ressources()
        leave(:bye)
        scenario_success("dialog ended")

      {:scenario_ctl, :shutdown, _reason} ->
        send_BYE()
        goto(hanging_up, "shutdown")
    after
      # G3 again: the idle backstop must keep running once in the mix.
      7_200_000 ->
        send_BYE()
        goto(hanging_up, "idle timeout")
    end
  end

  state hanging_up do
    on_events do
      {200, _rsp, _trans, _dlg} ->
        media_cleanup_ressources()
        leave(:bye)
        scenario_success("clean shutdown")
    after
      10_000 ->
        media_cleanup_ressources()
        leave(:bye)
        scenario_failure("BYE not answered")
    end
  end

  on_shutdown do
    send_BYE()
    media_cleanup_ressources()
    leave(:bye)
    scenario_aborted("MCU call stopped gracefully")
  end

  # ── application logic ───────────────────────────────────────────────────────
  # The module decides; these compose the SIP reply. Every one of them is rescued:
  # as in registrar.exs, a module that is not installed or that faults mid-verdict
  # must become a SIP response, never a dead instance — the caller would otherwise
  # retransmit into the void.

  # Backs the `admit` macro (Kelix.Mod.Mcu.Script). The module decides — its
  # verdict comes back in `sip_ctx.lasterr`, including the JSR309 mutual exclusion
  # refusal — this composes the SIP reply for the error verdicts and returns the
  # updated context; the state code tests `sip_ctx.lasterr`.
  defp do_admit(sip_ctx, req, dialog_pid, domain) do
    # `displayname: :auto` overlays the caller's name on its tile — the From
    # header's display name, else the From URI's user part. Replace with a string
    # (or drop the option) in a copy that wants its own naming policy.
    sip_ctx = Kelix.Mod.Mcu.admit(sip_ctx, domain, req, displayname: :auto)

    case sip_ctx.lasterr do
      :ok ->
        # name the conference this instance serves, so `kelictl monitor` says WHICH
        SIP.Scenario.Monitor.note_account(SIP.Context.appdata_get(sip_ctx, :mcu_conf).did)

      :jsr309_media_already_in_use ->
        {code, text} = sip_response(:jsr309_media_already_in_use)
        reply(dialog_pid, req, code, text, [], "reply #{code}")

      {:error, reason} ->
        {code, text} = sip_response(reason)
        reply(dialog_pid, req, code, text, [], "reply #{code}")
    end

    sip_ctx
  rescue
    e ->
      Logger.error(module: __MODULE__, message: "mcu script failed: #{Exception.message(e)}")
      reply(dialog_pid, req, 500, "Server Internal Error", [], "script_failed")
      SIP.Context.set(sip_ctx, :lasterr, {:error, :script_failed})
  end

  # §6.5. A wedged or absent module (`:down` / `:timeout` from
  # `Kelix.Module.safe_call/3`) is a 500: nothing is known about the DID.
  defp sip_response(:no_such_conference), do: {404, "Not Found"}
  defp sip_response(:full), do: {486, "Busy Here"}
  defp sip_response(:mcu_down), do: {503, "Service Unavailable"}
  # a JSR309 media session already owns this session's medias (mutual exclusion)
  defp sip_response(:jsr309_media_already_in_use), do: {500, "Server Internal Error"}
  defp sip_response(_reason), do: {500, "Server Internal Error"}

  @doc false
  # Per-cause media-error mapping, passed to reply_invite_with_sdp as a function so
  # the causes keep their own SIP semantics (§6.5).
  def media_error(:no_common_codec), do: {488, "Not Acceptable Here"}
  def media_error(:secure_not_supported), do: {488, "Not Acceptable Here"}
  def media_error({:bad_offer, _reason}), do: {400, "Bad Request"}
  def media_error(_reason), do: {500, "Server Internal Error"}

  # Backs the `attach` macro (Kelix.Mod.Mcu.Script). ACK time: codecs,
  # StartSending, mixer join. A transient failure here leaves an established call
  # whose leg is not in the mix; it is logged and the call kept (lasterr reset to
  # :ok), because the caller can hear the problem and hang up, and tearing a
  # confirmed dialog down on a transient RPC error is worse.
  defp do_attach(sip_ctx) do
    sip_ctx = Kelix.Mod.Mcu.attach(sip_ctx)

    case sip_ctx.lasterr do
      :ok ->
        sip_ctx

      # MCU and JSR309 are mutually exclusive: the module refused the leg (and
      # logged why); the refusal stays in lasterr, so the goto that follows
      # aborts the scenario
      :jsr309_media_already_in_use ->
        sip_ctx

      {:error, reason} ->
        Logger.error(module: __MODULE__, message: "attach failed: #{inspect(reason)}")
        SIP.Context.set(sip_ctx, :lasterr, :ok)
    end
  rescue
    e ->
      Logger.error(module: __MODULE__, message: "attach raised: #{Exception.message(e)}")
      SIP.Context.set(sip_ctx, :lasterr, :ok)
  end

  @doc false
  # RFC 5168: the one-primitive body every video UA understands as "send me a new
  # intra-frame now". Kept whole rather than assembled, because this exact wording is
  # what interoperates.
  def picture_fast_update() do
    """
    <?xml version="1.0" encoding="utf-8" ?>\
    <media_control><vc_primitive><to_encoder><picture_fast_update/>\
    </to_encoder></vc_primitive></media_control>
    """
  end

  # The other direction: the peer asks, the MCU obliges (`SendFPU`). A non-video
  # conference or an unknown INFO is not an error — it is simply not a request for a
  # frame.
  defp request_fpu(sip_ctx, req) do
    if media_control?(req) do
      case Kelix.Mod.Mcu.send_fpu(SIP.Context.appdata_get(sip_ctx, :mcu_part)) do
        :ok ->
          "INFO: FPU"

        {:error, reason} ->
          Logger.warning(module: __MODULE__, message: "SendFPU failed: #{inspect(reason)}")
          "INFO: FPU failed"
      end
    else
      "INFO"
    end
  rescue
    e ->
      Logger.warning(module: __MODULE__, message: "SendFPU raised: #{Exception.message(e)}")
      "INFO"
  end

  # Content-Type is what identifies it; the body is only checked for the primitive so
  # a media_control message asking for something else is not taken for an FPU.
  defp media_control?(req) do
    String.contains?(to_string(Map.get(req, :contenttype)), "media_control") and
      String.contains?(body_of(req), "picture_fast_update")
  end

  defp body_of(req) do
    case Map.get(req, :body) do
      body when is_binary(body) -> body
      [%{data: body} | _] when is_binary(body) -> body
      _ -> ""
    end
  end

  # Backs the `leave` macro (Kelix.Mod.Mcu.Script). Idempotent teardown, called
  # from seven places: `leave/2` tolerates an already-removed participant by
  # contract (§7, property 1), and the media resources are released first — the
  # adapter connection owns the MCU-side participant. The context-aware facade
  # reads the `:mcu_part` handle back from the appdata (a nil one is a no-op) and
  # applies the JSR309 mutual exclusion.
  defp do_leave(sip_ctx, reason) do
    Kelix.Mod.Mcu.leave(sip_ctx, reason)
  rescue
    e ->
      Logger.warning(module: __MODULE__, message: "leave raised: #{Exception.message(e)}")
      sip_ctx
  end
end
