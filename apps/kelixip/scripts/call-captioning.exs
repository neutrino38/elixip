# Kelixip call script: a captioned call out through the operator trunk.
#
# A deaf or hard-of-hearing caller, on a client that types and reads (T.140),
# calls a hearing party behind the `sip-trunk-prod` trunk (Kelix.Mod.SipServers).
# A SpeechProcessor sits between the legs (B2BUA.md, `speech:`):
#
#   * what the callee says is written to the caller as T.140 — the captions;
#   * what the caller types is spoken to the callee;
#   * audio passes both ways, mixed with the synthesis towards the callee.
#
# The caller must offer text, else there is nothing to caption onto: 488. The
# callee need not: a trunk that declines the text still has its voice captioned,
# and the caller keeps its text section.
#
# Without speech processing — speech-server not configured on the media server,
# not running, or Mistral not answering — the call has no purpose: 503 Speech
# Processing Unavailable, before anything reaches the trunk. Speech lost during
# a call does not end it: the voices still cross, and the log says so.
#
# Audio and text only, video is declined on both legs. Towards the trunk, the
# offer is AMR-WB then PCMA and nothing else. Towards the caller, the same two
# come first when it offered them; its other codecs stay, the SpeechProcessor
# decodes whatever each leg carries.
defmodule Kelix.CallCaptioning do
  use SIP.Scenario
  use SBB.Call
  use Kelix.Mod.AuthDb

  uas(:invite)

  config(uses_modules: [:auth_db, :sip_servers])

  @trunk "sip-trunk-prod"
  @realm "visioassistance.net"

  @media {:mediaserver,
          inbound: [
            webrtc: :if_offered,
            media: [:audio, :text],
            prefer_codecs: [audio: ["AMR-WB", "PCMA"]]
          ],
          outbound: [webrtc: :no, media: [:audio, :text], audio_codec: ["AMR-WB", "PCMA"]],
          speech: [inbound: [speak: true], outbound: [transcribe: true]]}

  state initial_state do
    goto(wait_invite)
  end

  state wait_invite do
    on_events do
      {:INVITE, req, _trans, _dlg} ->
        b2bua_reply(req, 100, "Trying")
        goto(authenticate_caller, "INVITE received")

      {:dialog_terminated, _dlg, _reason} ->
        scenario_aborted("caller vanished before the INVITE")
    after
      60_000 -> scenario_failure("no INVITE received")
    end
  end

  state authenticate_caller do
    AuthDb.SBB.authenticate(realm: @realm)

    on_events do
      {:auth, :authenticated, %{user: user}} ->
        goto(check_caller_text, "INVITE authenticated as #{user}")

      {:auth, :cancelled, _} ->
        scenario_success("caller cancelled the challenged call")

      {:auth, :caller_gone, %{reason: reason}} ->
        scenario_success("caller gave up on the challenge: #{inspect(reason)}")

      {:auth, :timeout, _} ->
        scenario_success("no credentials came back")

      {:auth, :refused, %{attempts: attempts}} ->
        scenario_success("gave up on this sender after #{attempts} refused attempts")
    end
  end

  state check_caller_text do
    req = last_uas_req()

    if :text in SIP.Msg.Ops.media_kinds(SIP.Msg.Ops.sdp_body(req)) do
      goto(place_call, "the caller offers text")
    else
      b2bua_reply(req, 488, "Not Acceptable Here")
      scenario_success("the caller offers no text to caption onto")
    end
  end

  # The media server before the trunk: the trunk counts every call forwarded to
  # it, and a call we cannot carry must not be one of them.
  state place_call do
    req = last_uas_req()
    media_connect()

    case {ctx_get(:lasterr), media_speech_available()} do
      {:ok, {:error, {:speech_unavailable, reason}}} ->
        b2bua_reply(req, 503, "Speech Processing Unavailable")
        media_cleanup_ressources()
        scenario_failure("speech processing unavailable: #{reason}")

      {:ok, :ok} ->
        case Kelix.Mod.SipServers.forward(sip_ctx, req, @trunk) do
          {:error, :not_found} ->
            b2bua_reply(req, 503, "Service Unavailable")
            media_cleanup_ressources()
            scenario_failure("no SIP server named #{@trunk} in this domain")

          {:error, reason} ->
            b2bua_reply(req, 503, "Service Unavailable")
            goto(releasing, "#{@trunk} cannot take the call now: #{inspect(reason)}")

          {newreq, peer} ->
            call(args: %{peer: peer, request: newreq, media: @media})

            on_events do
              {:call, :connected, _} ->
                goto(connected, "captioned call established")

              {:call, :rejected, %{code: code}} ->
                case b2bua_media_error() do
                  nil -> goto(releasing, "the trunk answered #{code}")
                  reason -> goto(releasing, "the call could not be bridged: #{inspect(reason)}")
                end

              {:call, :cancelled, _} ->
                goto(releasing, "caller cancelled, callee confirmed")

              {:call, :answered_after_cancel, _} ->
                goto(releasing, "callee answered after the cancellation; hung up")

              {:call, :caller_hung_up, _} ->
                goto(releasing, "caller hung up before answer")

              {:call, :caller_gone, %{reason: reason}} ->
                goto(releasing, "caller vanished while it rang: #{inspect(reason)}")

              {:call, :media_lost, _} ->
                goto(releasing, "media server gone before answer")

              {:call, :timeout, _} ->
                goto(releasing, "the callee never answered")

              {:call, :failed, %{reason: :speech_unavailable, cause: cause}} ->
                media_cleanup_ressources()
                scenario_failure("speech processing unavailable: #{cause}")

              {:call, :failed, %{reason: reason}} ->
                goto(releasing, "call setup failed: #{inspect(reason)}")
            end
        end

      {{:error, :no_media_server}, _} ->
        b2bua_reply(req, 503, "Service Unavailable")
        goto(releasing, "no media server available")

      {other, _} ->
        b2bua_reply(req, 503, "Service Unavailable")
        goto(releasing, "media connect failed: #{inspect(other)}")
    end
  end

  state connected do
    bridge(args: %{media: @media})

    on_events do
      {:bridge, :caller_hung_up, _} ->
        goto(releasing, "call ended: caller hung up")

      {:bridge, :callee_hung_up, _} ->
        goto(releasing, "call ended: callee hung up")

      {:bridge, :session_expired, %{leg: leg}} ->
        goto(releasing, "session timer expired on the #{leg}'s leg")

      {:bridge, :max_duration, _} ->
        goto(releasing, "maximum call duration reached")

      {:bridge, :media_lost, %{reason: reason}} ->
        b2bua_send_BYE()
        b2bua_reply(last_uas_req(), 200, "OK")
        goto(releasing, "media plane gone: #{reason}")

      {:bridge, :interrupted, %{message: message}} ->
        goto(releasing, "bridge interrupted with nothing to do: #{inspect(message)}")
    end
  end

  state releasing do
    media_cleanup_ressources()
    scenario_success("call released")
  end

  on_shutdown do
    media_cleanup_ressources()
    scenario_aborted("B2BUA stopped gracefully")
  end
end
