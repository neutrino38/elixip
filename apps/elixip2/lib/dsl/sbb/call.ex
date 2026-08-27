defmodule SBB.Call do
  @moduledoc """
  The establishment half of a call, as a service building block.

  A B2BUA script says *which* call to place and *what each outcome means*; the
  sequence in between — forward the INVITE, relay the provisionals, hunt the
  peer's next target, handle the caller giving up, wait for the ACK — is the same
  in every one of them, down to the comments. `call/1` is that sequence.

      state place_call do
        case Kelix.Mod.Registrar.targets(ctx_get(:domain), last_uas_req()) do
          {:ok, peer} ->
            call(args: %{peer: peer})

            on_events do
              {:call, :connected, _} -> goto(connected, "call established")
              {:call, :rejected, %{code: code}} -> scenario_success("callee said \#{code}")
              {:call, :cancelled, _} -> scenario_aborted("caller cancelled")
              ...
            end

          :notfound ->
            b2bua_reply(last_uas_req(), 480, "Temporarily Unavailable")
            scenario_success("registered nowhere")
        end
      end

  ## What it takes

  Through `args`, all optional but `:peer`:

    * `:peer` — where to send the INVITE, as `Kelix.Mod.Registrar.targets/2` and
      the other providers return it: one target or a list to hunt serially. **With
      a media server**, resolve it before connecting the media and pass what
      `b2bua_resolved_peer/0` gives back:

          b2bua_resolve(peer)
          media_connect()
          sbb_call(peer: b2bua_resolved_peer(), media: @media)

      The block resolves an unresolved peer itself, so nothing breaks without
      that; what is lost is the choice of a media server carrying an interface
      the callee can reach, which only the resolved target names (step 5 of
      `docs/design/multi-interface.md`). The order matters, not the verb: the
      media server is chosen inside `media_connect/0`;
    * `:request` — the INVITE to forward, defaulting to `last_uas_req()`, which
      is what a UAS instance always has;
    * `:media` — passed through to `b2bua_forward/4` (`false` by default);
    * `:ring_timeout` — how long to wait for a final before giving up on the
      callee, in ms (180 s by default). A provider's own per-target value is
      honoured by the hunt underneath, independently of this bound.

  ## What it answers

  See `SBB.Call.Establish`. The block completes the SIP transactions it owns —
  a caller whose INVITE is never answered is left hanging, so the 408 and the
  500 below are sent here rather than left to a script to remember — and then
  hands the *verdict* back: whether a rejected call is a success, whether a
  cancellation is an abort, and what to bill, are the script's to name (S3).
  """

  @doc false
  defmacro __using__(_opts) do
    # Teach the scenario that `:call` is a block's namespace, so `on_events`
    # classifies its returns as scenario events even in a state written before
    # the call site — see the return contract in
    # docs/design/DESIGN-SBB.md#21-the-shape-of-a-return.
    SIP.Scenario.register_namespace(__CALLER__.module, :call)
    SIP.Scenario.register_namespace(__CALLER__.module, :bridge)

    quote do
      import SBB.Call
    end
  end

  @doc """
  Establish the outbound leg and relay it to the caller until the call is up or
  over. Options are `sbb_fsm/2`'s, plus the block's own `args` named plainly at
  the call site — `call(peer: peer)`; see the module doc for what it reads.
  """
  defmacro call(opts \\ []) do
    quote do
      sbb_fsm(SBB.Call.Establish, unquote(opts))
    end
  end

  @doc """
  Relay the established call until it ends, or until something interrupts it.
  Options are `sbb_fsm/2`'s, plus the block's own `args` named plainly at the
  call site; see `SBB.Call.Bridge` for what it reads.

  A host that took the call back on `{:bridge, :interrupted, _}` re-enters with
  `bridge(resume: true)`: the call was never torn down, only the relay paused.
  """
  defmacro bridge(opts \\ []) do
    quote do
      sbb_fsm(SBB.Call.Bridge, unquote(opts))
    end
  end

  defmodule Establish do
    @moduledoc """
    The FSM behind `SBB.Call.call/1`: `place_call`, `proceeding`, `cancelling`
    and `wait_ack` of every B2BUA script, once.
    """

    use SIP.SBB

    @sbb_namespace :call

    @sbb_args [:peer, :request, :media, :ring_timeout]

    @sbb_returns [
      connected: "the callee answered and the caller ACKed — %{}",
      rejected:
        "the callee refused with a final ≥ 300, and no target is left to try — " <>
          "%{code, reason}; the response has been relayed to the caller",
      cancelled:
        "the caller gave up and the attempt is over — %{code}, the final the " <>
          "callee ended on (487 in the ordinary case, nil if its leg just died)",
      answered_after_cancel:
        "the callee picked up before the CANCEL reached it — %{}; the answer has " <>
          "been acknowledged and hung up, so the call is over, not up",
      caller_hung_up: "the caller sent BYE instead of CANCEL while it rang — %{}",
      caller_gone: "the caller's dialog ended while it rang — %{reason}",
      media_lost:
        "the media plane went away before the call was up — %{answered}, true if " <>
          "the caller's INVITE has been answered (500) and false if it is still " <>
          "pending, which it is once the caller has cancelled",
      failed:
        "the establishment could not complete — %{reason}: `:outbound_leg_lost` " <>
          "or `:no_ack`. The caller has been answered or hung up as the case needs"
    ]

    # A backstop, not the protocol timer: the ring timeout below and timer H in
    # `wait_ack` are what actually bound this block. This one only catches a
    # sequence that somehow reaches neither.
    @sbb_timeout 300_000

    @default_ring_timeout 180_000

    state initial_state do
      req = sbb_data_get(:request) || last_uas_req()
      media = sbb_data_get(:media) || false

      # Idempotent: a peer the scenario already resolved is returned unchanged, so
      # this costs nothing after the recommended order and covers the scenario
      # that skipped it. It cannot recover the media server's choice, which was
      # made in `media_connect/0` before this block ran — only the caller can put
      # those two in the right order.
      b2bua_resolve(sbb_data_get(:peer))

      b2bua_forward(req, b2bua_resolved_peer(), media)

      cond do
        ctx_get(:lasterr) == :ok ->
          goto(proceeding, "call forwarded")

        # The media server was there a moment ago and is not any more — stopped,
        # or killed under the call. Ours, not a problem with what the caller
        # offered, so it is a 503 and it may carry a Retry-After: an upstream
        # proxy can try another route, which a 488 would never let it do.
        b2bua_media_unavailable?() ->
          b2bua_reply(req, 503, "Service Unavailable")
          sbb_return({:call, :failed, %{reason: :media_unavailable}})

        # The offer could not be terminated (no common codec, a WebRTC offer we
        # were told not to take). That is a statement about what the caller asked
        # for, so it is a 488 — not a 500, which would blame us.
        media != false ->
          b2bua_reply(req, 488, "Not Acceptable Here")
          sbb_return({:call, :failed, %{reason: :media_setup, cause: ctx_get(:lasterr)}})

        # No media in this call: whatever went wrong is ours.
        true ->
          b2bua_reply(req, 500, "Server Internal Error")
          sbb_return({:call, :failed, %{reason: :forward_failed, cause: ctx_get(:lasterr)}})
      end
    end

    state proceeding do
      on_events do
        # Everything the callee says goes back to the caller, collapsed into the
        # single inbound dialog.
        {:outbound, {code, resp, _trans, _dlg}} when code in 101..199 ->
          b2bua_forward_reply(resp)
          stay("provisional #{code}")

        {:outbound, {200, resp, _trans, _dlg}} ->
          b2bua_forward_reply(resp)
          goto(wait_ack, "200 OK relayed")

        # A refusal. If the peer has another target, the hunt is already trying
        # it, and this was one device saying no rather than the call being over.
        {:outbound, {code, resp, _trans, _dlg}} when code >= 300 ->
          b2bua_forward_reply(resp)

          if b2bua_hunting?() do
            stay("#{code}, trying the next target")
          else
            sbb_return({:call, :rejected, %{code: code, reason: resp.reason}})
          end

        # The caller gave up. Two different things, and both are wanted: stop the
        # search, and tell the device that is ringing. Then wait — a CANCEL asks,
        # it does not decide (RFC 3261 §16.7).
        {:CANCEL, req, _trans, _dlg} ->
          b2bua_cancel_forward()
          b2bua_forward(req)
          goto(cancelling, "caller cancelled")

        # Real user agents send a BYE where the RFC asks for a CANCEL.
        {:BYE, req, _trans, _dlg} ->
          b2bua_cancel_forward()
          b2bua_reply(req, 200, "OK")
          sbb_return({:call, :caller_hung_up, %{}})

        # Nobody is left to ring for. Without this the callee's phone keeps
        # ringing until the timeout below — the very failure §2 of the spec uses
        # to decide what belongs in the framework rather than in a script.
        {:dialog_terminated, _dlg, reason} ->
          b2bua_cancel_forward()
          sbb_return({:call, :caller_gone, %{reason: reason}})

        # The media plane went away while the callee was still ringing. There is
        # no call to hang up yet, so the caller is answered and the teardown
        # CANCELs the attempt still ringing.
        #
        # Written out rather than left to the clause `on_events` injects into
        # every wait: that clause treats a dead media server as a shutdown, which
        # from inside a block would end the scenario over a decision the host may
        # well have a policy for. Reporting it is what leaves the policy there.
        {:ms_event, _ref, :server_disconnected} ->
          b2bua_reply(last_uas_req(), 500, "Media Server Unavailable")
          sbb_return({:call, :media_lost, %{answered: true}})

        {:outbound, {:dialog_terminated, _dlg, reason}} ->
          b2bua_reply(last_uas_req(), 500, "Outbound Leg Lost")
          sbb_return({:call, :failed, %{reason: :outbound_leg_lost, cause: reason}})
      after
        # The caller's INVITE is answered here rather than left to the script:
        # an INVITE with no final response leaves a caller hanging, which is not
        # a policy anybody should be free to forget.
        sbb_data_get(:ring_timeout) || @default_ring_timeout ->
          b2bua_cancel_forward()
          b2bua_reply(last_uas_req(), 408, "Request Timeout")
          sbb_return({:call, :timeout, %{}})
      end
    end

    # The CANCEL has gone to the callee; its transaction is not over until a
    # final response says so (RFC 3261 §16.7). Staying here to hear it is the
    # whole point: end now and a device that answers a fraction of a second later
    # is left off-hook in a call nobody is in.
    #
    # `SIP.DialogImpl` catches that case on its own — it is not a policy, so no
    # script may get it wrong — and this state does not make it correct, it makes
    # it VISIBLE: a call answered after its cancellation is a real event, and the
    # difference between "abandoned" and "answered then hung up" is one somebody
    # bills on.
    state cancelling do
      on_events do
        # What normally comes back, and fast.
        {:outbound, {487, _resp, _trans, _dlg}} ->
          sbb_return({:call, :cancelled, %{code: 487}})

        # The race. The callee picked up before the CANCEL reached it; nobody is
        # left to talk to, so acknowledge the answer and hang up (§13.2.2.4, §15).
        {:outbound, {200, _resp, _trans, _dlg}} ->
          b2bua_send_BYE()
          sbb_return({:call, :answered_after_cancel, %{}})

        # Still ringing somewhere: keep listening rather than take a 180 for an
        # end.
        {:outbound, {code, _resp, _trans, _dlg}} when code in 100..199 ->
          stay("provisional #{code} after cancel")

        {:outbound, {code, _resp, _trans, _dlg}} when code >= 300 ->
          sbb_return({:call, :cancelled, %{code: code}})

        {:outbound, {:dialog_terminated, _dlg, _reason}} ->
          sbb_return({:call, :cancelled, %{code: nil}})

        # Nothing is answered here: the caller has cancelled, and their INVITE is
        # ended by the 487 the dialog layer owes them, not by us.
        {:ms_event, _ref, :server_disconnected} ->
          sbb_return({:call, :media_lost, %{answered: false}})

        {:dialog_terminated, _dlg, _reason} ->
          sbb_return({:call, :cancelled, %{code: nil}})
      after
        # Bounded on purpose: past timer B the outbound transaction is over
        # whatever we heard, and an instance held on a leg that says nothing is a
        # slot lost.
        32_000 -> sbb_return({:call, :cancelled, %{code: nil}})
      end
    end

    # The caller's ACK is relayed rather than answered here: what the callee's
    # device gets is what the caller sent.
    state wait_ack do
      on_events do
        {:ACK, req, _trans, _dlg} ->
          b2bua_forward(req)
          sbb_return({:call, :connected, %{}})
      after
        # RFC 3261 timer H: no ACK is coming. Hang up the leg we did establish —
        # again, completing what this block started rather than leaving a
        # half-open call for a script to notice.
        32_000 ->
          b2bua_send_BYE()
          sbb_return({:call, :failed, %{reason: :no_ack}})
      end
    end
  end

  defmodule Bridge do
    @moduledoc """
    The FSM behind `SBB.Call.bridge/1`: the `connected` and `wait_far_bye_ok`
    states of every B2BUA script, once.

    These states carry **no policy at all** — every arm is a forward and a stay,
    down to the ones written out in full for the ACK of a re-INVITE and for the
    default relay of INFO / MESSAGE / NOTIFY / REFER. What policy there is sits
    at the edges, and comes back as an outcome for the script to name.

    ## What it takes

    Through `args`, all optional:

      * `:on_callee_hangup` — `:hang_up` (default) ends the call when the callee
        goes away, which is what a relay does. `:keep_caller` answers the callee
        and hands the call back with the CALLER'S LEG STILL UP, so the script can
        do something with it: play a prompt, offer a redirect, place another call
        and bridge again. The BYE is then never relayed — relaying it is what
        tears the caller's dialog down — and the outcome is `:callee_left`
        instead of `:callee_hung_up`, so a script cannot opt in and go on
        treating it as the end of the call by accident;
      * `:media` — truthy when the call goes through a media server. It changes
        one thing, and only one: a re-INVITE that merely MOVES a peer (a new
        `c=`, a new port, an ICE restart) or refreshes a session timer is
        answered locally instead of being relayed, because our endpoint did not
        move and the far end has nothing to learn. Without a media server the two
        legs are the same offer/answer and everything crosses;
      * `:max_duration` — the call's own bound, in ms (4 h by default).

    ## Interruption

    `{:bridge_break, message}` — sent by `kelictl`, by a module, by a timer —
    ends the block with `{:bridge, :interrupted, %{message: message}}` without
    touching the call. The host does its business and calls `bridge(resume: true)`
    again. In between, in-dialog traffic keeps arriving and nothing answers it:
    an unanswered re-INVITE runs at timer B and an unanswered BYE is
    retransmitted, so that interval is the scale of a prompt, not of a decision.
    """

    use SIP.SBB

    @sbb_namespace :bridge

    @sbb_args [:media, :on_callee_hangup, :max_duration]

    @sbb_returns [
      caller_hung_up:
        "the call is over and the caller ended it — %{reason}: `:bye`, " <>
          "`:bye_unanswered` when the far end never answered it, or whatever ended " <>
          "the dialog when it went away on its own",
      callee_hung_up: "the call is over and the callee ended it — %{reason}, as above",
      callee_left:
        "the callee went away and `on_callee_hangup: :keep_caller` kept the " <>
          "caller — %{reason}. The call is NOT over: the caller's leg is up, " <>
          "answered, and waiting for whatever the script does next. Only ever " <>
          "returned to a script that asked for it",
      interrupted: "a {:bridge_break, message} arrived; the call is untouched — %{message}",
      max_duration: "the call's own bound expired — %{}",
      media_lost:
        "the media plane is gone — %{reason: :media_lost | :server_disconnected}. Both " <>
          "legs are still up: hanging them up is a policy, so it is the host's"
    ]

    # A call lasts as long as it lasts. S7's bound is the dialog here, not a
    # timer: the block is listening for the end it is bounded by, and
    # `:max_duration` below is the script's bound, not the mechanism's.
    @sbb_timeout :infinity

    @default_max_duration 14_400_000

    state initial_state do
      on_events do
        # Either side hangs up. Both legs are told, and the leg that asked is
        # answered, before waiting for the far end's 200.
        {:BYE, req, _trans, _dlg} ->
          b2bua_forward(req)
          b2bua_reply(req, 200, "OK")
          sbb_data_set(:ended_by, :caller)
          goto(wait_far_bye_ok, "caller hung up")

        # The callee hangs up. Its BYE is answered either way — a BYE nobody
        # answers is retransmitted — but relaying it is what ends the caller's
        # dialog, so that is the one thing the option withholds.
        {:outbound, {:BYE, req, _trans, _dlg}} ->
          if sbb_data_get(:on_callee_hangup) == :keep_caller do
            b2bua_reply(req, 200, "OK")
            sbb_return({:bridge, :callee_left, %{reason: :bye}})
          else
            b2bua_forward(req)
            b2bua_reply(req, 200, "OK")
            sbb_data_set(:ended_by, :callee)
            goto(wait_far_bye_ok, "callee hung up")
          end

        {:dialog_terminated, _dlg, reason} ->
          sbb_return({:bridge, :caller_hung_up, %{reason: reason}})

        # The callee's leg went away without a BYE. Nothing to answer, and the
        # same question about the caller's.
        {:outbound, {:dialog_terminated, _dlg, reason}} ->
          if sbb_data_get(:on_callee_hangup) == :keep_caller do
            sbb_return({:bridge, :callee_left, %{reason: reason}})
          else
            sbb_return({:bridge, :callee_hung_up, %{reason: reason}})
          end

        # The host takes the call back for a moment — a prompt, a lookup, an
        # operator. Nothing is torn down: `bridge(resume: true)` picks it up.
        {:bridge_break, message} ->
          sbb_return({:bridge, :interrupted, %{message: message}})

        # A leg has stopped sending on EVERY media it negotiated — not one media,
        # which is a peer turning its camera off and no reason to end anything.
        # And the media server itself going away takes the CALL down rather than
        # one leg, with one media session per call. Both are reported rather than
        # acted on: hanging up both legs is a decision, and a script may have
        # another one.
        {:ms_event, _ref, :media_lost} ->
          sbb_return({:bridge, :media_lost, %{reason: :media_lost}})

        {:ms_event, _ref, :server_disconnected} ->
          sbb_return({:bridge, :media_lost, %{reason: :server_disconnected}})

        # One media went quiet. Worth saying, not worth hanging up for.
        {:ms_event, _ref, {:media_timeout, media}} ->
          stay("#{media} went silent")

        # A re-INVITE or an UPDATE. Four things arrive under this shape. A
        # session-timer refresh is answered here whatever the media mode — each
        # leg has a timer of its own and we are a UA on both. A peer that merely
        # MOVED is answered here only with a media server, since only then has
        # our endpoint stayed put; without one the far end has to hear about it.
        #
        # What is absorbed is named explicitly, and anything the framework cannot
        # classify (`:unknown`) falls through to the relay. Propagating a change
        # nobody needed costs a transaction; swallowing a hold or an added media
        # breaks the call.
        {m, req, _trans, _dlg} when m in [:INVITE, :UPDATE] ->
          case absorbable_reoffer(sbb_data_get(:media), req, b2bua_reoffer_kind(req)) do
            {true, kind} ->
              b2bua_reply_reoffer(req)
              stay("#{m} answered locally (#{kind}, caller)")

            {false, kind} ->
              b2bua_forward(req)
              stay("relayed #{m} (#{kind}, caller -> callee)")
          end

        {:outbound, {m, req, _trans, _dlg}} when m in [:INVITE, :UPDATE] ->
          case absorbable_reoffer(sbb_data_get(:media), req, b2bua_reoffer_kind(req)) do
            {true, kind} ->
              b2bua_reply_reoffer(req)
              stay("#{m} answered locally (#{kind}, callee)")

            {false, kind} ->
              b2bua_forward(req)
              stay("relayed #{m} (#{kind}, callee -> caller)")
          end

        # The ACK of a re-INVITE's 200 is a transaction of its own (RFC 3261
        # §13.2.2.4), so every re-INVITE that crosses owes one back.
        {:ACK, req, _trans, _dlg} ->
          b2bua_forward(req)
          stay("ACK relayed (caller -> callee)")

        {:outbound, {:ACK, req, _trans, _dlg}} ->
          b2bua_forward(req)
          stay("ACK relayed (callee -> caller)")

        # Default relay, written out rather than assumed: everything else
        # in-dialog (INFO, MESSAGE, REFER…), then the responses.
        {:outbound, {m, req, _trans, _dlg}} when is_atom(m) ->
          b2bua_forward(req)
          stay("relayed #{m} (callee -> caller)")

        {:outbound, {code, resp, _trans, _dlg}} when is_integer(code) ->
          b2bua_forward_reply(resp)
          stay("relayed #{code} (callee -> caller)")

        {m, req, _trans, _dlg} when is_atom(m) ->
          b2bua_forward(req)
          stay("relayed #{m} (caller -> callee)")

        {code, resp, _trans, _dlg} when is_integer(code) ->
          b2bua_forward_reply(resp)
          stay("relayed #{code} (caller -> callee)")
      after
        sbb_data_get(:max_duration) || @default_max_duration ->
          sbb_return({:bridge, :max_duration, %{}})
      end
    end

    state wait_far_bye_ok do
      on_events do
        {:outbound, {200, _resp, _trans, _dlg}} ->
          goto(concluded, "far end answered the BYE")

        {200, _resp, _trans, _dlg} ->
          goto(concluded, "far end answered the BYE")

        {:dialog_terminated, _dlg, _reason} ->
          goto(concluded, "leg gone after the BYE")

        {:outbound, {:dialog_terminated, _dlg, _reason}} ->
          goto(concluded, "leg gone after the BYE")
      after
        # The far end never answered the BYE. The call is over either way.
        5_000 ->
          sbb_data_set(:end_reason, :bye_unanswered)
          goto(concluded, "BYE unanswered, closing anyway")
      end
    end

    # Which side hung up is the outcome's NAME, not a field in it — a host reads
    # `{:bridge, :caller_hung_up, _}` and knows, where `%{by: by}` made it look up
    # a value. One state rather than a `case` in each of the five arms above, and
    # both spellings written literally so `sbb_return` can check them.
    state concluded do
      reason = sbb_data_get(:end_reason) || :bye

      case sbb_data_get(:ended_by) do
        :callee -> sbb_return({:bridge, :callee_hung_up, %{reason: reason}})
        _caller -> sbb_return({:bridge, :caller_hung_up, %{reason: reason}})
      end
    end

    # Whether a re-offer can be answered locally instead of crossing. Returns the
    # kind too, so the caller can say which it was.
    #
    # The RFC 4028 session-timer refresh — an offerless UPDATE — is absorbed
    # whatever the media mode: that timer runs between us and ONE peer, on a leg
    # where we are its UA, and RFC 3311 §5.1 answers it with a bare 200 that needs
    # no media of ours to say. Relaying it instead puts a request on the far leg,
    # which has a timer of its own, and a signalling B2BUA then answers a refresh
    # with the far end's silence.
    #
    # The other two need a media server: without one the SDP belongs to the
    # endpoints, so a peer that merely moved has moved for the far end too.
    # Anything the framework cannot classify (`:unknown`) crosses.
    defp absorbable_reoffer(media, req, kind) do
      cond do
        SIP.Msg.Ops.offerless_update?(req) -> {true, kind}
        media in [nil, false] -> {false, kind}
        true -> {kind in [:address_change, :no_sdp, :no_change], kind}
      end
    end
  end
end
