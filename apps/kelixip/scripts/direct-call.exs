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
            scenario_aborted("caller cancelled, callee confirmed")

          {:call, :answered_after_cancel, _} ->
            scenario_success("callee answered after the cancellation; hung up")

          {:call, :caller_hung_up, _} ->
            scenario_success("caller hung up before answer")

          {:call, :caller_gone, %{reason: reason}} ->
            scenario_aborted("caller vanished while it rang: #{inspect(reason)}")

          {:call, :timeout, _} ->
            scenario_failure("Bob never answered")

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

  state connected do
    on_events do
      {:BYE, req, _trans, _dlg} ->
        b2bua_forward(req)
        b2bua_reply(req, 200, "OK")
        goto(wait_far_bye_ok, "caller hung up")

      {:outbound, {:BYE, req, _trans, _dlg}} ->
        b2bua_forward(req)
        b2bua_reply(req, 200, "OK")
        goto(wait_far_bye_ok, "callee hung up")

      {:dialog_terminated, _dlg, reason} ->
        scenario_success("inbound leg ended: #{inspect(reason)}")

      {:outbound, {:dialog_terminated, _dlg, reason}} ->
        scenario_success("outbound leg ended: #{inspect(reason)}")

      # The ACK of a re-INVITE's 200 is a transaction of its own (RFC 3261
      # §13.2.2.4), so every re-INVITE that crosses owes one back.
      {:ACK, req, _trans, _dlg} ->
        b2bua_forward(req)
        stay("ACK relayed (caller -> callee)")

      {:outbound, {:ACK, req, _trans, _dlg}} ->
        b2bua_forward(req)
        stay("ACK relayed (callee -> caller)")

      # Default relay, written out rather than assumed: everything else
      # in-dialog (re-INVITE, UPDATE, INFO, MESSAGE, REFER…), then the responses.
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
      14_400_000 -> scenario_failure("maximum call duration reached")
    end
  end

  state wait_far_bye_ok do
    on_events do
      {:outbound, {200, _resp, _trans, _dlg}} -> scenario_success("call relayed and ended")
      {200, _resp, _trans, _dlg} -> scenario_success("call relayed and ended")
      {:dialog_terminated, _dlg, _reason} -> scenario_success("call ended")
      {:outbound, {:dialog_terminated, _dlg, _reason}} -> scenario_success("call ended")
    after
      5_000 -> scenario_success("BYE unanswered, closing anyway")
    end
  end

  on_shutdown do
    # Both legs are wound down by the automatic teardown; there is nothing left
    # to do here but say why we stopped.
    scenario_aborted("B2BUA stopped gracefully")
  end
end
