defmodule Kelix.Mod.Mcu.SBB.Conference do
  @moduledoc """
  The FSM behind `Kelix.Mod.Mcu.SBB.conference/1`: a conference leg's life in the
  mix, once.

  What it replaces is three states of the reference scripts — `in_call`,
  `in_conference` and `hanging_up` — which carried **no conference policy at
  all**. They carried SIP: which ACK is the first one, that an INFO is answered
  whether or not it is an RFC 5168 request, that a BYE is answered before the
  slot is released, that our own BYE is followed by a wait for its 200, that a leg
  gone silent is a leg to hang up.

  They were already two copies and had already drifted. `mcu_adhoc.exs` held the
  same three states minus three clauses, and the consequence was not a missing
  feature: `on_events` compiles to a `receive` and the runner injects no
  catch-all, so a `{:mcu_event, :media_connected, :audio}` sent to an ad-hoc leg
  matched no clause and stayed in the mailbox for the whole call — a leg whose
  media died held its slot until the 2 h backstop, and nothing reported it.

  ## The seam

  This block is to a conference leg what `bridge/1` is to a B2BUA call: it takes
  over **once the call is answered** and runs until something happens the script
  has a policy for. The answer stays with the script — its media set, its
  `webrtc:` mode, its `on_media_error` mapping, whatever else a deployment wants
  in that 200 — which is why the block takes no `media:` and no `webrtc:`. It is
  entered where the scripts wrote `goto(in_call)`.

  ## Handing a request back, and coming back in

  A renegotiation is a **policy** decision — a deployment may refuse an added
  media, cap a resolution, answer with a different media set than it accepted at
  the start — so the block does not answer it. The request travels **inside the
  outcome** rather than being re-posted: `sbb_return/1` posts one event and ends
  the block, and a `send(self(), {:INVITE, …})` on top of it would leave two
  events in the mailbox — the host would match its own `{:INVITE, …}` clause
  first, re-enter on `goto(loop, …)`, and the block would then find
  `{:conference, :renegotiation, …}` in its own mailbox with no clause for it.
  That is the drift above, rebuilt on purpose.

  Most arms will not read `req`: the block matched the request in an `on_events`
  of its own, which is what stores it in the **shared** context, so the script's
  `reply_invite_with_sdp/2` and `last_uas_req/0` find it without being given it.

  The block remembers where it is in the shared `appdata`, under
  `:mcu_leg_phase`, **not** in its sandbox — the sandbox is cleared on every
  entry, so a block keyed on it would re-run the ACK-time sequence each time the
  host came back:

  | Value | Meaning on entry | Set when |
  |---|---|---|
  | absent / `:awaiting_ack` | the next ACK is the first one: attach | the script answered a 200 and entered; a re-INVITE was handed back |
  | `:attach_pending` | attach now, before waiting for anything | an UPDATE was handed back (RFC 3311: its 200 concludes the offer/answer, no ACK follows) |
  | `:in_mix` | an ACK is a retransmission: ignore it | the leg attached |

  Two consequences to accept rather than engineer around. A script that
  **refuses** a re-INVITE (488) leaves the phase at `:awaiting_ack`; no ACK ever
  comes — the server transaction absorbs the ACK of a non-2xx (RFC 3261
  §17.2.1) — so nothing re-attaches and the leg stays in the mix with the media it
  had, which is right. A script that refuses an **UPDATE** costs one redundant
  `attach`, since the block cannot see which code the script chose; `attach`
  re-applies the codecs the leg already has, and the scripts already called it on
  every ACK and every UPDATE.

  ## The window

  Between two entries the call is up and nothing answers it. For a message that
  is a log line; for a renegotiation the script owes a response inside timer B,
  so that arm answers first and does its bookkeeping after.

  ## Shutdown

  The block declares no `{:scenario_ctl, :shutdown, _}` clause, and needs none:
  the clause `on_events` injects jumps to `:__shutdown__`, the block has no
  `on_shutdown`, so `sbb_loop/5` throws and the root re-applies it as the
  transition the host state would have written. The script's `on_shutdown` runs
  with the block unwound.
  """

  use SIP.SBB

  require Logger

  # `:conference` is the leaf's own default, so there is no `@sbb_namespace` line:
  # the namespace follows the verb a scenario writes (`Mcu.SBB.conference()`).
  @sbb_returns [
    renegotiation:
      "a re-INVITE or an UPDATE arrived and is **unanswered** — " <>
        "%{method: :INVITE | :UPDATE, req, transaction, dialog}. The call is whole: " <>
        "answer it (or refuse it) and re-enter with goto(loop, …)",
    message:
      "a peer's script said something — %{envelope}. The call is whole; only a leg " <>
        "that called mcu_accept_messages() ever gets one",
    caller_hung_up:
      "the leg is out: a BYE, answered, or the dialog went away on its own — %{reason}",
    cancelled:
      "the leg is out: a CANCEL around the answer — %{}. The IST sent the 487, the " <>
        "teardown was ours",
    mcu_lost:
      "the leg is out: the media server went away and our BYE is out — " <>
        "%{via: :mcu_event | :ms_event, bye_answered}",
    media_timeout:
      "the leg is out: every media of this leg went silent (P7/S1) and our BYE is " <>
        "out — %{media, bye_answered}",
    idle_timeout: "the leg is out: the G3 backstop fired and our BYE is out — %{bye_answered}",
    attach_refused:
      "the leg is out: the mix refused it at ACK time — %{reason}, " <>
        "`:jsr309_media_already_in_use`"
  ]

  # A conference leg lasts as long as its dialog, and `:idle_timeout` is the
  # bound. Nothing here is worth a completion deadline.
  @sbb_timeout :infinity

  # G3: with no RTP watchdog on the MCU API this is the last protection against a
  # leg that stops sending. **Idle**, not a budget — every event the loop consumes
  # re-arms it — which is why the name differs from `bridge`'s `:max_duration`.
  @default_idle_timeout 7_200_000

  # How long our own BYE is worth waiting for. Not an argument: one caller, one
  # right value.
  @bye_timeout 10_000

  # No `on_events`: this reads where the leg is and moves. The only phase that
  # needs acting on here is the UPDATE that was handed back and answered — RFC
  # 3311 §5.1 makes its 200 the end of the offer/answer, so no ACK follows and
  # the mix has to be told now.
  state initial_state do
    if appdata_get(:mcu_leg_phase) == :attach_pending do
      case attach_leg(sip_ctx) do
        {sip_ctx, :ok} ->
          appdata_set(:mcu_leg_phase, :in_mix)
          goto(in_conference, "UPDATE renegotiated: back in the mix")

        {sip_ctx, {:refused, reason}} ->
          sip_ctx = release_leg(sip_ctx, reason)
          sbb_return({:conference, :attach_refused, %{reason: reason}})
      end
    else
      goto(in_conference)
    end
  end

  # The loop. Everything it consumes ends on `goto(loop, …)` rather than `stay`,
  # because the idle deadline is absolute and only re-running the body re-arms it.
  state in_conference do
    on_events do
      # The ACK is what puts the participant in the mix: a caller that never ACKs
      # never enters it, and no RTP leaves the MCU before that. The caller re-sends
      # this ACK for every 200 the transaction layer retransmits (RFC 3261
      # §13.2.2.4), and those copies must not re-run the ACK-time sequence — the
      # guard is the phase, where the scripts used two whole states.
      {:ACK, _req, _trans, _dlg} ->
        if appdata_get(:mcu_leg_phase) == :in_mix do
          goto(loop, "ACK retransmitted; already in the mix")
        else
          case attach_leg(sip_ctx) do
            {sip_ctx, :ok} ->
              appdata_set(:mcu_leg_phase, :in_mix)
              goto(loop, "ACK: in the mix")

            {sip_ctx, {:refused, reason}} ->
              sip_ctx = release_leg(sip_ctx, reason)
              sbb_return({:conference, :attach_refused, %{reason: reason}})
          end
        end

      # A renegotiation on the same participant, handed back UNANSWERED. The phase
      # says what its answer will owe: a re-INVITE's own ACK re-attaches, an
      # UPDATE has no ACK so the attach happens on re-entry.
      {m, req, trans, dlg} when m in [:INVITE, :UPDATE] ->
        appdata_set(:mcu_leg_phase, if(m == :INVITE, do: :awaiting_ack, else: :attach_pending))

        sbb_return(
          {:conference, :renegotiation, %{method: m, req: req, transaction: trans, dialog: dlg}}
        )

      # An INFO carrying an RFC 5168 request is the peer asking for an intra-frame
      # from what the mixer sends it (a decoder that lost sync). Answer 200 either
      # way — an INFO we do not understand is still a request we must not leave
      # unanswered — and ask the MCU for the frame when it is that.
      {:INFO, req, _trans, _dlg} ->
        reply_request(req, 200, "OK")
        goto(loop, request_fpu(sip_ctx, req))

      {:BYE, req, _trans, _dlg} ->
        reply_request(req, 200, "OK")
        sip_ctx = release_leg(sip_ctx, :bye)
        sbb_return({:conference, :caller_hung_up, %{reason: :bye}})

      # The caller cancelled around the answer: the IST already sent the 487, only
      # the teardown is ours.
      {:CANCEL, _req, _trans, _dlg} ->
        sip_ctx = release_leg(sip_ctx, :cancel)
        sbb_return({:conference, :cancelled, %{}})

      # The mixer needs a fresh intra-frame from this leg (a new tile started, or a
      # decoder lost sync): ask for one the way RFC 5168 has it.
      {:mcu_event, :fpu_requested} ->
        {body, contenttype} = SIP.Msg.Ops.picture_fast_update()
        send_INFO(body, contenttype: contenttype)
        goto(loop, "FPU requested")

      # The media server went away: the mix is gone, so the call is too.
      {:mcu_event, :server_disconnected} ->
        sip_ctx = end_call(sip_ctx, :mcu_lost, {:mcu_lost, :mcu_event})
        goto(hanging_up, "mcu lost")

      # The same fact by the other route. The module relays `:server_disconnected`
      # because it watches the server on behalf of every leg; this one is what our
      # OWN media connection reports — `media_connect/0` makes this process the
      # event sink — so both reach us and neither is guaranteed to be first.
      # Whichever arrives ends the call; the other lands in a state that ignores it.
      {:ms_event, _server, :server_disconnected} ->
        sip_ctx = end_call(sip_ctx, :mcu_lost, {:mcu_lost, :ms_event})
        goto(hanging_up, "media server disconnected")

      # P7/S1: every media of this leg has gone silent — the module only sends this
      # once the AND is satisfied, so one dead media does not get us here. Same
      # teardown as losing the media server: the call is over, it just has not been
      # hung up yet.
      {:mcu_event, :media_timeout, media} ->
        sip_ctx = end_call(sip_ctx, :media_timeout, {:media_timeout, media})
        goto(hanging_up, "media timeout on #{media}")

      # P7/S2: real media is flowing. An observation for the operator view, already
      # emitted by the module — nothing for the call to do.
      {:mcu_event, :media_connected, _media} ->
        goto(loop, "media connected")

      # A peer's script said something. Handed back whole, which is what keeps the
      # documented feature possible: the module doc has a script handling it in
      # the very state this block absorbs.
      {:mcu_message, envelope} ->
        sbb_return({:conference, :message, %{envelope: envelope}})

      {:dialog_terminated, _dlg, reason} ->
        sip_ctx = release_leg(sip_ctx, :bye)
        sbb_return({:conference, :caller_hung_up, %{reason: reason}})

      # The catch-alls, and they are the point of having one copy of this loop.
      # An event no clause matches is not ignored, it **stays in the mailbox for
      # the whole call**, and nothing reports it: that is how a media event the
      # ad-hoc script had never been taught about left a dead leg holding its slot
      # for two hours. Both event families get a floor, below the clauses that
      # carry a policy.
      {:mcu_event, _event} ->
        goto(loop, "mcu event")

      {:mcu_event, _event, _arg} ->
        goto(loop, "mcu event")

      {:ms_event, _server, _event} ->
        goto(loop, "media event")
    after
      sbb_data_get(:idle_timeout) || @default_idle_timeout ->
        sip_ctx = end_call(sip_ctx, :idle_timeout, :idle_timeout)
        goto(hanging_up, "idle timeout")
    end
  end

  # Our BYE is out and the leg is already released. All that is left to learn is
  # whether the far end acknowledged it, which is a key of the outcome rather than
  # an outcome of its own.
  state hanging_up do
    on_events do
      {200, _rsp, _trans, _dlg} ->
        goto(concluded, "BYE answered")

      # A dead media server is reported by both routes and neither is guaranteed
      # to be first, so the second one lands here, where the call is already
      # ending. Consuming it is what keeps it out of the mailbox — and consuming
      # it *here* is what stops the clause `on_events` would otherwise inject from
      # turning it into a shutdown, which would lose the outcome this teardown
      # exists to report. `stay` rather than `goto(loop)`: a flapping server must
      # not keep extending the wait for our own BYE.
      {:ms_event, _server, _event} ->
        stay("media event, already hanging up")

      {:mcu_event, _event} ->
        stay("mcu event, already hanging up")

      {:mcu_event, _event, _arg} ->
        stay("mcu event, already hanging up")
    after
      @bye_timeout ->
        sbb_data_set(:bye_answered, false)
        goto(concluded, "BYE unanswered, closing anyway")
    end
  end

  # Which end the call came to is the outcome's NAME, so the three that pass
  # through `hanging_up` are resolved in one place — and written out literally,
  # because `sbb_return/1` can only check an outcome it can read. A mistyped one
  # is not a crash, it is a host waiting on its `after` for an event nobody will
  # send.
  state concluded do
    answered = sbb_data_get(:bye_answered) != false

    case sbb_data_get(:ending) do
      {:mcu_lost, via} ->
        sbb_return({:conference, :mcu_lost, %{via: via, bye_answered: answered}})

      {:media_timeout, media} ->
        sbb_return({:conference, :media_timeout, %{media: media, bye_answered: answered}})

      :idle_timeout ->
        sbb_return({:conference, :idle_timeout, %{bye_answered: answered}})
    end
  end

  # ── what the block owns ─────────────────────────────────────────────────────

  # The call is over and we are the ones ending it: release the leg, name why to
  # the module, then hang up. The pending outcome goes to the sandbox because
  # three clauses lead to `hanging_up` and only one of them will be resolved.
  defp end_call(sip_ctx, reason, ending) do
    sip_ctx = release_leg(sip_ctx, reason)
    SIP.Scenario.Monitor.note_command(:sip, "send_BYE")

    sip_ctx
    |> SIP.Scenario.Runner.sbb_data_set(__MODULE__, :ending, ending)
    |> SIP.Session.CallInDialog.do_send_bye(nil)
  end

  # The leg is out. Media first, then the participant: the adapter connection owns
  # the MCU-side participant, so releasing it in the other order leaves the mixer
  # holding a connection nobody drives.
  #
  # `lasterr` is reset deliberately. `leave/2` never errors by contract, but the
  # JSR309 mutual exclusion can leave its refusal there, and every caller below
  # continues on a `goto` — which aborts the scenario as a failure on anything
  # other than `:ok`.
  defp release_leg(sip_ctx, reason) do
    SIP.Scenario.Monitor.note_command(:media, "media_cleanup_ressources")
    sip_ctx = SIP.Session.Media.media_cleanup_ressources(sip_ctx)
    SIP.Scenario.Monitor.note_command(:media, "mcu_leave")

    sip_ctx
    |> Kelix.Mod.Mcu.leave(reason)
    |> SIP.Context.set(:lasterr, :ok)
  rescue
    e ->
      Logger.warning(module: __MODULE__, message: "leave raised: #{Exception.message(e)}")
      SIP.Context.set(sip_ctx, :lasterr, :ok)
  end

  # ACK time: codecs, StartSending, mixer join. Returns the context and the verdict
  # separately, with `lasterr` always back to `:ok` — the trap this block inherited
  # from the script helper it replaces is that `attach/1` leaves its verdict there,
  # and a `goto` on the next line would kill a call the reference policy says to
  # keep.
  #
  # That policy: a transient failure is logged and the call **kept**, because the
  # caller can hear the problem and hang up, and tearing down a confirmed dialog on
  # an RPC hiccup is worse. Only the JSR309 mutual exclusion ends the leg.
  defp attach_leg(sip_ctx) do
    SIP.Scenario.Monitor.note_command(:media, "mcu_attach")
    attached = Kelix.Mod.Mcu.attach(sip_ctx)

    verdict =
      case attached.lasterr do
        :ok ->
          :ok

        :jsr309_media_already_in_use ->
          {:refused, :jsr309_media_already_in_use}

        {:error, reason} ->
          Logger.error(module: __MODULE__, message: "attach failed: #{inspect(reason)}")
          :ok
      end

    {SIP.Context.set(attached, :lasterr, :ok), verdict}
  rescue
    e ->
      Logger.error(module: __MODULE__, message: "attach raised: #{Exception.message(e)}")
      {SIP.Context.set(sip_ctx, :lasterr, :ok), :ok}
  end

  # The other direction of RFC 5168: the peer asks, the MCU obliges (`SendFPU`).
  # A non-video conference, or an INFO that is not a request for a frame, is not
  # an error. Returns the transition description, so the log says which it was.
  defp request_fpu(sip_ctx, req) do
    if SIP.Msg.Ops.picture_fast_update?(req) do
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
end
