# Reference kelixip script: a conference entered from Microsoft Teams Direct Routing.
#
# This is `mcu_adhoc.exs` with ONE gate in front of it: the INVITE must come from the
# SIP server declared under the slug `microsoft-pstnhub` (Kelix.Mod.SipServers — its
# URIs and its `source_networks`, see docs/kelixip/modules/sip_servers.md). A request
# from anywhere else is refused with 403 before anything is created. One that passes
# is joined to the conference whose DID is the user part of the Request-URI, created
# on first arrival exactly as `mcu_adhoc.exs` does.
#
#   kelictl sip_servers server.create domain=example.com slug=microsoft-pstnhub \
#     type=sip-appsrv \
#     'primary_uri=sip:sip.pstnhub.microsoft.com:5061;transport=tls' \
#     'backup_uri=sip:sip2.pstnhub.microsoft.com:5061;transport=tls' \
#     'tertiary_uri=sip:sip3.pstnhub.microsoft.com:5061;transport=tls' \
#     source_networks=52.112.0.0/14,52.120.0.0/14 use_fqdn_contact=true
#
# Recognising is the module's business (`matches_server/2` reads the source flow of
# the request); trusting it is this script's: here, only that one server may create
# or join a room. Limitation L10 of `mcu_adhoc.exs` is thus closed by the perimeter
# check rather than by a challenge.
#
# It is shipped as a REFERENCE: it lives in script_dir and a deployment is expected to
# copy and adapt it — another slug, or several trusted servers, is a change to
# `@trusted_server` and to the one `case` that reads it.
#
# NOTE — self-references must go through `__MODULE__`, never through the name
# written below: the script registry appends `.V<version>` to every module of a
# loaded script (hot reload, §5.3), so this compiles as `Kelix.Mcu.FromSfuCall.V1`
# and a hardcoded `Kelix.Mcu.FromSfuCall.f()` would call a module that does not exist.
defmodule Kelix.Mcu.FromSfuCall do
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
  config(uses_modules: [:mcu, :sip_servers])

  # The slug of the only SIP server allowed in (Kelix.Mod.SipServers).
  @trusted_server "microsoft-pstnhub"

  # The {:INVITE, …} is already queued in our mailbox by the dialog layer.
  state initial_state do
    goto(wait_invite)
  end

  state wait_invite do
    on_events do
      {:INVITE, req, _trans, dialog_pid} ->
        case Kelix.Mod.SipServers.matches_server(sip_ctx, req) do
          {@trusted_server, peer} ->
            # Teams finds the SBC by the FQDN of our Contact and drops a call whose
            # 200 names an address: the server's domain when it has
            # `use_fqdn_contact = true`, nil (the address) otherwise
            publish_contact_host(peer.contact_host)
            admit(req, dialog_pid)

            case sip_ctx.lasterr do
              :ok ->
                # admit/4 stored the conference and wired the leg: local identity,
                # the connection options the media macros forward, and the MCU this
                # conference is pinned to
                conf = SIP.Context.appdata_get(sip_ctx, :mcu_conf)

                media_connect()
                reply_invite(180, "Ringing")
                goto(answering, "INVITE #{conf.did} from #{@trusted_server}")

              # MCU and JSR309 calls are mutually exclusive; the 500 is already out
              :jsr309_media_already_in_use ->
                scenario_failure("JSR309 media session already in progress")

              # module verdict; the SIP error response is already out
              {:error, reason} ->
                scenario_success("rejected: #{inspect(reason)}")
            end

          # another declared server, or none: nothing is created for it
          _ ->
            reply_invite(403, "Forbidden")
            scenario_success("rejected: not from #{@trusted_server}")
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
    did = did_of(req)

    case ensure_room(domain, did) do
      {:ok, _conf, origin} ->
        # `displayname: :auto` overlays the caller's name on its tile — the From
        # header's display name, else the From URI's user part. Replace with a string
        # (or drop the option) in a copy that wants its own naming policy.
        sip_ctx = Kelix.Mod.Mcu.admit(sip_ctx, domain, req, did: did, displayname: :auto)

        case sip_ctx.lasterr do
          :ok ->
            # name the conference this instance serves, so `kelictl monitor` says WHICH
            conf = SIP.Context.appdata_get(sip_ctx, :mcu_conf)
            SIP.Scenario.Monitor.note_account(conf.did)
            Logger.info(module: __MODULE__, message: "#{conf.did}: room #{origin} (#{conf.uid})")

          :jsr309_media_already_in_use ->
            {code, text} = sip_response(:jsr309_media_already_in_use)
            reply(dialog_pid, req, code, text, [], "reply #{code}")

          {:error, reason} ->
            {code, text} = sip_response(reason)
            reply(dialog_pid, req, code, text, [], "reply #{code}")
        end

        sip_ctx

      {:error, reason} ->
        {code, text} = sip_response(reason)
        reply(dialog_pid, req, code, text, [], "reply #{code}")
        SIP.Context.set(sip_ctx, :lasterr, {:error, reason})
    end
  rescue
    e ->
      Logger.error(module: __MODULE__, message: "mcu script failed: #{Exception.message(e)}")
      reply(dialog_pid, req, 500, "Server Internal Error", [], "script_failed")
      SIP.Context.set(sip_ctx, :lasterr, {:error, :script_failed})
  end

  # Resolve the room the R-URI names, creating it on first arrival — atomically, so
  # two INVITEs landing together on the same unknown DID produce one room and not a
  # `:did_in_use` for the second caller (§17.4).
  #
  # `owner: :caller` makes an abandoned room disappear with this call: if this
  # instance dies before anyone joins — a caller who never ACKs, a crash, a media
  # failure — the module destroys the empty conference. A room somebody joined
  # survives, and then goes with its last participant (`destroy_when_empty`).
  defp ensure_room(_domain, nil), do: {:error, :no_such_conference}

  defp ensure_room(domain, did) do
    Kelix.Mod.Mcu.ensure_conference(domain, did,
      name: "Teams #{did}",
      owner: :caller,
      destroy_when_empty: true
    )
  end

  # The conference number, computed once: the room is created and joined under it.
  # A copy that derives it otherwise (the last digits of the number, a lookup)
  # changes this function alone.
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
