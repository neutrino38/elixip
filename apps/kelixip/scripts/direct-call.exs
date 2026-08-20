# Reference kelixip call script: Alice calls Bob, wherever Bob registered.
#
# kamailio's `lookup("location"); t_relay()` done as a B2BUA: the location
# service says where the AOR is, this script relays the call there over a second
# dialog it owns — and stays in the signalling path for the whole call.
#
# Commented use case in B2BUA.md, "Scenario direct-call.exs".
defmodule Kelix.DirectCall do
  use SIP.Scenario
  use SBB.Call

  uas(:invite)

  # Refuse to load when the location service is absent, instead of failing on
  # the first INVITE.
  config(uses_modules: [:registrar])

  state initial_state do
    goto(wait_invite)
  end

  # The {:INVITE, …} that created this instance is already in our mailbox.
  state wait_invite do
    on_events do
      {:INVITE, req, _trans, _dlg} ->
        b2bua_reply(req, 100, "Trying")
        goto(place_call, "INVITE received")

      {:dialog_terminated, _dlg, _reason} ->
        scenario_aborted("caller vanished before the INVITE")
    after
      60_000 -> scenario_failure("no INVITE received")
    end
  end

  # Where is Bob? The MODULE says where the AOR is and hands back a peer; the
  # SCRIPT decides what SIP each outcome means. Nothing is rescued here — a
  # module that faults raises, and the scenario runner logs it and fails the
  # scenario, which is more readable than an error mapped twice.
  #
  # `call/1` is everything between "forward this INVITE" and "the call is up or
  # over": the provisionals, the serial hunt over Bob's devices, the caller
  # giving up, the cancel race, the ACK. What stays here is what only this script
  # can answer — whether an outcome is a success, a failure or an abort.
  state place_call do
    req = last_uas_req()

    case Kelix.Mod.Registrar.targets(ctx_get(:domain), req) do
      {:ok, peer} ->
        call(args: %{peer: peer, request: req})

        on_events do
          {:call, :connected, _} ->
            goto(connected, "call established")

          {:call, :rejected, %{code: code}} ->
            scenario_success("Bob answered #{code}")

          # A call answered a fraction of a second after its cancellation is a
          # real event, and the difference between "abandoned" and "answered then
          # hung up" is one somebody bills on.
          {:call, :cancelled, _} ->
            scenario_success("caller cancelled, callee confirmed")

          {:call, :answered_after_cancel, _} ->
            scenario_success("callee answered after the cancellation; hung up")

          {:call, :caller_hung_up, _} ->
            scenario_success("caller hung up before answer")

          {:call, :caller_gone, %{reason: reason}} ->
            scenario_aborted("caller vanished while it rang: #{inspect(reason)}")

          {:call, :timeout, _} ->
            scenario_success("Bob never answered")

          {:call, :failed, %{reason: reason}} ->
            scenario_failure("call setup failed: #{reason}")
        end

      :notfound ->
        b2bua_reply(req, 480, "Temporarily Unavailable")
        scenario_success("Bob is registered nowhere right now")

      :no_aor ->
        b2bua_reply(req, 400, "Bad Request")
        scenario_success("the INVITE names no AOR")

      :unavailable ->
        b2bua_reply(req, 500, "Location Service Unavailable")
        scenario_failure("the location service could not answer")
    end
  end

  # The call is up. `bridge/1` is the relay: every arm of the state this replaces
  # was a forward and a stay, in-dialog traffic in both directions, down to the
  # ACK a re-INVITE's 200 owes back. What is left here is the end of the call.
  state connected do
    bridge()

    on_events do
      {:bridge, :caller_hung_up, _} ->
        scenario_success("call relayed and ended: caller hung up")

      {:bridge, :callee_hung_up, _} ->
        scenario_success("call relayed and ended: callee hung up")

      {:bridge, :max_duration, _} ->
        scenario_success("maximum call duration reached")

      # Neither can happen in this script — there is no media plane, and nothing
      # asks for the call back — but an outcome nobody matches leaves the machine
      # waiting on an `after` that is not there. Saying so beats hanging.
      {:bridge, :media_lost, %{reason: reason}} ->
        scenario_failure("media plane gone from a call that has none: #{reason}")

      {:bridge, :interrupted, %{message: message}} ->
        scenario_failure("bridge interrupted with nothing to do: #{inspect(message)}")
    end
  end

  on_shutdown do
    # Both legs are wound down by the automatic teardown; there is nothing left
    # to do here but say why we stopped.
    scenario_aborted("B2BUA stopped gracefully")
  end
end
