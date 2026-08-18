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
      the other providers return it: one target or a list to hunt serially;
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
    # docs/design/service-building-block.md#s2--the-shape-of-a-return.
    SIP.Scenario.register_namespace(__CALLER__.module, :call)

    quote do
      import SBB.Call
    end
  end

  @doc """
  Establish the outbound leg and relay it to the caller until the call is up or
  over. Options are `sbb_fsm/2`'s; see the module doc for the `args` it reads.
  """
  defmacro call(opts \\ []) do
    quote do
      sbb_fsm(SBB.Call.Establish, unquote(opts))
    end
  end

  defmodule Establish do
    @moduledoc """
    The FSM behind `SBB.Call.call/1`: `place_call`, `proceeding`, `cancelling`
    and `wait_ack` of every B2BUA script, once.
    """

    use SIP.SBB

    @sbb_namespace :call

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

      b2bua_forward(req, sbb_data_get(:peer), media)

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
end
