# Voice dialogue with the caller, on a real media server and speech-server —
# the acceptance call of the SpeechProcessor chatbot (mediaserver
# docs/conception/SPEECH-PROCESSOR/SPEC.md §12). Run it with:
#     elixipp --listen udp:5060 apps/elixip2/scenarios/speech_bot.exs
#
# The bot greets the caller, then repeats every sentence it recognized
# ("Vous avez dit : …"). It always finishes its phrase: speaking while it
# talks does not cut it off (no barge-in). Each speech event is a transition, so the run log is the record of the call: what
# was recognized, when each phrase started and ended, and any service outage.
#
# Needs a media server started with --speech-url and --speech-streaming-url;
# `media_voices()` tells, at the start, whether it is.
defmodule UAS.SpeechBot do
  use SIP.Scenario
  use SIP.Session.CallUAS

  uas(:invite)

  # `voice` is a speech-server alias ("" = the first voice of the language).
  # `show_text` also writes what the caller said to their own T.140 text, when
  # their phone carries text.
  config(
    domains: :any,
    mediaserver: %{module: :mendooze, url: "http://127.0.0.1:9090"},
    voice: "",
    show_text: true
  )

  @greeting "Bonjour, je suis le robot de test. Parlez, je vous répète ce que j'ai compris."

  state initial_state do
    goto(wait_invite)
  end

  state wait_invite do
    on_events do
      {:INVITE, _req, _trans, _dlg} ->
        media_connect()

        case ctx_get(:lasterr) do
          :ok -> goto(ringing, "INVITE")
          _ -> goto(no_media_server, "no media server")
        end

      {:scenario_ctl, :shutdown, _reason} ->
        scenario_aborted("speech bot stopped gracefully")
    after
      60_000 -> scenario_failure("no INVITE received")
    end
  end

  state ringing do
    reply_invite(180, "Ringing")
    goto(answering)
  end

  state no_media_server do
    reply_invite(503, "Service Unavailable")
    scenario_failure("no media server available")
  end

  # Speech starts on the first media packet, not on the 200: the recognition
  # has nothing to hear before, and the greeting would be lost to a NAT path
  # not yet latched.
  state answering do
    reply_invite_with_sdp(200, media: :tc, webrtc: :if_offered)

    on_events do
      {:CANCEL, _req, _trans, _dlg} ->
        scenario_success("caller cancelled")

      {:ACK, _req, _trans, _dlg} ->
        stay("ACK")

      {:ms_event, _conn, :ice_connected} ->
        goto(greeting, "media connected")

      {:BYE, req, _trans, _dlg} ->
        reply_request(req, 200, "OK")
        media_cleanup_ressources()
        scenario_success("BYE before media")

      {:ms_event, _server, :server_disconnected} ->
        goto(hanging_up, "media server disconnected")
    after
      15_000 -> scenario_failure("no media from caller")
    end
  end

  state greeting do
    voices = media_voices()

    case media_start_speech(voice: ctx_get(:voice), show_text: ctx_get(:show_text)) do
      :ok ->
        media_say(@greeting)
        goto(in_dialogue, "speech started, voices #{inspect(voices)}")

      {:error, reason} ->
        goto(hanging_up, "speech not available: #{inspect(reason)}, voices #{inspect(voices)}")
    end
  end

  state in_dialogue do
    on_events do
      {:ms_event, _conn, {:speech_recognized, text, true}} ->
        media_say("Vous avez dit : " <> text)
        stay("recognized: #{text}")

      {:ms_event, _conn, {:speech_recognized, text, false}} ->
        stay("partial: #{text}")

      # No barge-in: the phrase being said goes to its end. The media server
      # never cuts one on its own; media_stop_speaking() here would.
      {:ms_event, _conn, {:speech_activity, true}} ->
        stay("caller speaks")

      {:ms_event, _conn, {:speech_activity, false}} ->
        stay("caller silent")

      {:ms_event, _conn, {:speech_started, say_id}} ->
        stay("say #{say_id} started")

      {:ms_event, _conn, {:speech_done, say_id, interrupted}} ->
        stay("say #{say_id} done#{if interrupted, do: " (interrupted)", else: ""}")

      {:ms_event, _conn, {:speech_service, function, st, reason}} ->
        stay("speech-server #{function} #{st}: #{reason}")

      {:INVITE, _req, _trans, _dlg} ->
        reply_invite_with_sdp(200)
        stay("re-INVITE")

      {:BYE, req, _trans, _dlg} ->
        reply_request(req, 200, "OK")
        media_cleanup_ressources()
        scenario_success("BYE")

      {:ms_event, _conn, :media_lost} ->
        goto(hanging_up, "media lost")

      {:ms_event, _server, :server_disconnected} ->
        goto(hanging_up, "media server disconnected")

      {:scenario_ctl, :shutdown, _reason} ->
        goto(hanging_up, "shutdown")

      {:dialog_terminated, _dlg, _reason} ->
        media_cleanup_ressources()
        scenario_success("call ended")
    after
      600_000 -> goto(hanging_up, "idle timeout")
    end
  end

  state hanging_up do
    media_cleanup_ressources()
    send_BYE()

    on_events do
      {200, _bye_rsp, _trans_pid, _dialog_pid} -> scenario_success("Clean shutdown")
    after
      10_000 -> scenario_failure("BYE not answered")
    end
  end

  on_shutdown do
    media_cleanup_ressources()
    scenario_aborted("speech bot stopped gracefully")
  end
end
