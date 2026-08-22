# Reference kelixip conference (MCU) script — design docs/design/DESIGN-MCU.md#5-an-inbound-call.
# One instance is spawned per inbound INVITE by Kelix.Router → Kelix.InstancePool;
# the served domain is injected into the context by the router (`domain:` override).
#
# Separation of concerns, as in registrar.exs (§11.1): the MODULE decides, the
# SCRIPT composes the SIP response. The `admit` FSL macro (Kelix.Mod.Mcu.Script,
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
  # the module's verbs: the admit/leave FSL macros (they rebind sip_ctx in place and
  # leave their verdict in sip_ctx.lasterr) and the Mcu.SBB blocks
  use Kelix.Mod.Mcu
  require Logger
  import SIP.Session, only: [reply: 6]

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
            # admit/4 stored the conference and wired the leg: local identity, the
            # connection options the media macros forward, and the MCU this
            # conference is pinned to
            conf = SIP.Context.appdata_get(sip_ctx, :mcu_conf)

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
      # gets the text section removed from the answer entirely (never port 0 — the
      # deployed WebRTC client chokes on a port-0 text echo).
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
        goto(in_conference)
    end
  end

  # The leg's whole life in the mix, as one block (Kelix.Mod.Mcu.SBB.Conference):
  # the ACK that puts the participant in the mix, the retransmissions that must not
  # re-run it, the RFC 5168 frame requests both ways, the teardowns, and the idle
  # backstop. What is left here is what a deployment actually decides — how to
  # answer a renegotiation, what to do with a peer's message, and what each ending
  # is worth.
  state in_conference do
    Mcu.SBB.conference()

    on_events do
      # The block hands the request back UNANSWERED, because answering it is a
      # policy: a deployment may refuse an added media, cap a resolution, or answer
      # with a different media set than it accepted at the start. Answer it the way
      # this one wants — the request is in the context, so this reads like the 200
      # in `answering` — then go back into the mix. `goto(loop, …)` re-runs this
      # body, which calls the block again: that is the whole re-entry mechanism.
      {:conference, :renegotiation, %{method: method}} ->
        reply_invite_with_sdp(200,
          media: :tc,
          webrtc: :if_offered,
          on_media_error: &__MODULE__.media_error/1
        )

        goto(loop, "#{method} renegotiated")

      # A peer's script said something (§20.5). Only a leg that called
      # `mcu_accept_messages()` ever gets one; this reference script logs it and
      # goes back into the mix. Answer it, forward it as a SIP MESSAGE, raise a
      # hand — that is what a copy changes.
      {:conference, :message, %{envelope: envelope}} ->
        Logger.info(module: __MODULE__, message: "#{envelope.kind} from #{envelope.from.part_id}")

        goto(loop, "collaboration message")

      # From here on the leg is out: the media connection is released and the
      # participant removed, with the reason the outcome names. Nothing to free —
      # only the verdict to name, which is the script's business.
      {:conference, :caller_hung_up, %{reason: reason}} ->
        scenario_success("BYE (#{inspect(reason)})")

      {:conference, :cancelled, _} ->
        scenario_success("cancelled")

      {:conference, :mcu_lost, _} ->
        scenario_success("mcu lost")

      {:conference, :media_timeout, %{media: media}} ->
        scenario_success("media timeout on #{media}")

      # The mix refused this leg at ACK time: an established call that never got
      # into the conference is a failure, not a call that ended.
      {:conference, :attach_refused, %{reason: reason}} ->
        scenario_failure("not mixed: #{inspect(reason)}")

      {:conference, :idle_timeout, _} ->
        scenario_failure("idle timeout")
    end
  end

  # A kick (`kelictl mcu participant kick`), a drain and a node shutdown are three
  # ways to stop a leg from outside, and they all arrive here — including the one
  # that reaches the block, which unwinds it and re-applies the shutdown as the
  # transition this state would have written. One path, one verdict.
  on_shutdown do
    send_BYE()

    on_events do
      {200, _rsp, _trans, _dlg} ->
        media_cleanup_ressources()
        leave(:bye)
        scenario_aborted("MCU call stopped gracefully")

      # We are already leaving; a media plane that dies now changes nothing, and
      # consuming it is what stops it being read as a second shutdown.
      {:ms_event, _server, _event} ->
        stay("media event while stopping")
    after
      10_000 ->
        media_cleanup_ressources()
        leave(:bye)
        scenario_aborted("stopped, BYE unanswered")
    end
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
