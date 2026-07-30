# Reference kelixip AD-HOC conference script — design docs/design/mcu_module.md §17.5.
#
# This is `mcu.exs` with ONE clause changed: instead of requiring the DID to already
# designate a conference, the first caller on it CREATES one (`ensure_conference/3`),
# and later callers join that same one. Everything after that — 180, the SDP answer,
# the ACK putting the leg in the mix, the teardown — is identical.
#
# The distinction §17.4 insists on: the MODULE still creates nothing by itself. There
# is no template and no implicit rule; this SCRIPT decides to, on a DID pattern its
# own dial rule matched. `mcu.exs` remains the booked-conference reference and keeps
# answering 404 on an unknown DID — point a dial rule at one or the other, per domain.
#
# Consequence, and it is limitation L10: whoever reaches an ad-hoc DID can now CREATE
# a room, not merely join one. L8's advice — protect the perimeter upstream (trusted
# proxy, ACL) or add a challenge to a copy of this script — stops being merely prudent
# here.
#
# Two options make an ad-hoc room behave the way a caller expects:
#   owner: :caller        the room dies with the call that made it, IF nobody joined
#   destroy_when_empty:   the room dies with its last participant
#
# It is shipped as a REFERENCE: it lives in script_dir and a deployment is expected to
# copy and adapt it.
defmodule Kelix.Mcu.AdhocCall do
  use SIP.Scenario
  use SIP.Session.CallUAS
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
        case admit(req, dialog_pid, sip_ctx.domain) do
          {:ok, conf, part} ->
            # The local identity of this leg is the conference itself: it is what an
            # in-dialog request we originate (the BYE below) puts in From/To, and
            # without it `send_BYE()` has no URI to build.
            ctx_set(:username, conf.did)
            appdata_set(:mcu_part, part)
            # FW-1: tells the adapter which conference this leg joins. The media
            # macros forward it to create_peer_connection/3 without having to know
            # what it means.
            appdata_set(:media_conn_opts, mcu_participant: part)
            # A conference is pinned to its MCU (§1.3): the leg must reach the server
            # holding the mixer, not whatever the media pool would hand out.
            appdata_set(:mediaserver_instance, Kelix.Mod.Mcu.media_config(conf))

            media_connect()
            reply_invite(180, "Ringing")
            goto(answering, "INVITE #{conf.did}")

          {:rejected, description} ->
            scenario_success(description)
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
      media: :audio_video,
      # accept a secure leg when the offer asks for one (SDES from a SIP phone,
      # DTLS+ICE from a WebRTC gateway); `:no` would refuse it with a 488
      webrtc: :if_offered,
      on_media_error: &Kelix.Mcu.AdhocCall.media_error/1
    )

    case sip_ctx.lasterr do
      {:media_error, reason} ->
        # The error response is already out; release the slot and end cleanly. The
        # code we answered with travels with the reason so the module's call funnel
        # (§11) can tell a 488 from a 500 — only the script knows which it chose.
        {code, _text} = media_error(reason)
        media_cleanup_ressources()
        leave(sip_ctx, {:no_media, code})
        scenario_success("media refused: #{code} (#{inspect(reason)})")

      _ ->
        goto(in_call)
    end
  end

  state in_call do
    on_events do
      # The ACK is what puts the participant in the mix: a caller that never ACKs
      # never enters it, and no RTP leaves the MCU before that (§2, point 2).
      {:ACK, _req, _trans, _dlg} ->
        goto(loop, attach(sip_ctx))

      # Re-INVITE / UPDATE: renegotiate on the same participant.
      {:INVITE, _req, _trans, _dlg} ->
        reply_invite_with_sdp(200,
          media: :audio_video,
          webrtc: :if_offered,
          on_media_error: &Kelix.Mcu.AdhocCall.media_error/1
        )

        goto(loop, "re-INVITE")

      {:UPDATE, _req, _trans, _dlg} ->
        reply_invite_with_sdp(200,
          media: :audio_video,
          webrtc: :if_offered,
          on_media_error: &Kelix.Mcu.AdhocCall.media_error/1
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
        leave(sip_ctx, :bye)
        scenario_success("BYE")

      # The caller cancelled around the answer: the IST already sent 487, only the
      # teardown is ours.
      {:CANCEL, _req, _trans, _dlg} ->
        media_cleanup_ressources()
        leave(sip_ctx, :cancel)
        scenario_success("cancelled")

      # The media server went away (§9.2): the mix is gone, so the call is too.
      {:mcu_event, :server_disconnected} ->
        media_cleanup_ressources()
        leave(sip_ctx, :mcu_lost)
        send_BYE()
        goto(hanging_up, "mcu lost")

      # The mixer needs a fresh intra-frame from this leg (a new tile started, or a
      # decoder lost sync): ask for one the way RFC 5168 has it (§6.4).
      {:mcu_event, :fpu_requested} ->
        send_INFO(Kelix.Mcu.AdhocCall.picture_fast_update(),
          contenttype: "application/media_control+xml"
        )

        goto(loop, "FPU requested")

      {:mcu_event, _event} ->
        goto(loop, "mcu event")

      {:dialog_terminated, _dlg, _reason} ->
        media_cleanup_ressources()
        leave(sip_ctx, :bye)
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

  state hanging_up do
    on_events do
      {200, _rsp, _trans, _dlg} ->
        media_cleanup_ressources()
        leave(sip_ctx, :bye)
        scenario_success("clean shutdown")
    after
      10_000 ->
        media_cleanup_ressources()
        leave(sip_ctx, :bye)
        scenario_failure("BYE not answered")
    end
  end

  on_shutdown do
    send_BYE()
    media_cleanup_ressources()
    leave(sip_ctx, :bye)
    scenario_aborted("MCU call stopped gracefully")
  end

  # ── application logic ───────────────────────────────────────────────────────
  # The module decides; these compose the SIP reply. Every one of them is rescued:
  # as in registrar.exs, a module that is not installed or that faults mid-verdict
  # must become a SIP response, never a dead instance — the caller would otherwise
  # retransmit into the void.

  defp admit(req, dialog_pid, domain) do
    with {:ok, _conf, origin} <- ensure_room(domain, req),
         {:ok, conf, part} <- Kelix.Mod.Mcu.admit(domain, req) do
      # name the conference this instance serves, so `kelictl monitor` says WHICH
      SIP.Scenario.Monitor.note_account(conf.did)
      Logger.info(module: __MODULE__, message: "#{conf.did}: room #{origin} (#{conf.uid})")
      {:ok, conf, part}
    else
      {:error, reason} ->
        {code, text} = sip_response(reason)
        reply(dialog_pid, req, code, text, [], "reply #{code}")
        {:rejected, "#{code} #{text}"}
    end
  rescue
    e ->
      Logger.error(module: __MODULE__, message: "mcu script failed: #{Exception.message(e)}")
      reply(dialog_pid, req, 500, "Server Internal Error", [], "script_failed")
      {:rejected, "500 Server Internal Error"}
  end

  # Resolve the room the R-URI names, creating it on first arrival — atomically, so
  # two INVITEs landing together on the same unknown DID produce one room and not a
  # `:did_in_use` for the second caller (§17.4).
  #
  # `owner: :caller` makes an abandoned room disappear with this call: if this
  # instance dies before anyone joins — a caller who never ACKs, a crash, a media
  # failure — the module destroys the empty conference. A room somebody joined
  # survives, and then goes with its last participant (`destroy_when_empty`).
  defp ensure_room(domain, req) do
    case did_of(req) do
      nil ->
        {:error, :no_such_conference}

      did ->
        Kelix.Mod.Mcu.ensure_conference(domain, did,
          name: "Ad-hoc #{did}",
          owner: :caller,
          destroy_when_empty: true
        )
    end
  end

  defp did_of(req) do
    case Map.get(req, :ruri) do
      %SIP.Uri{userpart: user} when is_binary(user) and user != "" -> user
      _ -> nil
    end
  end

  # §6.5. A wedged or absent module (`:down` / `:timeout` from
  # `Kelix.Module.safe_call/3`) is a 500: nothing is known about the DID.
  defp sip_response(:no_such_conference), do: {404, "Not Found"}
  # creation-specific verdicts (§8.3 errors), mapped like their REST counterparts
  defp sip_response(:no_did_available), do: {486, "Busy Here"}
  defp sip_response(:did_in_use), do: {486, "Busy Here"}
  defp sip_response(:did_required), do: {404, "Not Found"}
  defp sip_response(:no_mediaserver), do: {503, "Service Unavailable"}
  defp sip_response(:unknown_mcu), do: {503, "Service Unavailable"}
  defp sip_response(:rpc_error), do: {500, "Server Internal Error"}
  defp sip_response(:full), do: {486, "Busy Here"}
  defp sip_response(:mcu_down), do: {503, "Service Unavailable"}
  defp sip_response(_reason), do: {500, "Server Internal Error"}

  @doc false
  # Per-cause media-error mapping, passed to reply_invite_with_sdp as a function so
  # the causes keep their own SIP semantics (§6.5).
  def media_error(:no_common_codec), do: {488, "Not Acceptable Here"}
  def media_error(:secure_not_supported), do: {488, "Not Acceptable Here"}
  def media_error({:bad_offer, _reason}), do: {400, "Bad Request"}
  def media_error(_reason), do: {500, "Server Internal Error"}

  # ACK time: codecs, StartSending, mixer join. A failure here leaves an established
  # call whose leg is not in the mix; it is logged and the call kept, because the
  # caller can hear the problem and hang up, and tearing a confirmed dialog down on a
  # transient RPC error is worse.
  defp attach(sip_ctx) do
    case Kelix.Mod.Mcu.attach(SIP.Context.appdata_get(sip_ctx, :mcu_part)) do
      :ok ->
        "ACK: in the mix"

      {:error, reason} ->
        Logger.error(module: __MODULE__, message: "attach failed: #{inspect(reason)}")
        "ACK: attach failed"
    end
  rescue
    e ->
      Logger.error(module: __MODULE__, message: "attach raised: #{Exception.message(e)}")
      "ACK: attach failed"
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

  # Idempotent teardown, called from seven places: `leave/2` tolerates an
  # already-removed participant by contract (§7, property 1), and the media resources
  # are released first — the adapter connection owns the MCU-side participant.
  defp leave(sip_ctx, reason) do
    case SIP.Context.appdata_get(sip_ctx, :mcu_part) do
      nil -> :ok
      part -> Kelix.Mod.Mcu.leave(part, reason)
    end
  rescue
    e ->
      Logger.warning(module: __MODULE__, message: "leave raised: #{Exception.message(e)}")
      :ok
  end
end
