# Reference kelixip call script: Alice calls Bob — after proving she is Alice.
#
# `direct-call.exs` plus digest authentication of the INVITE (design
# docs/design/evolution-auth-db.md §2): kamailio's
# `proxy_authenticate(); lookup("location"); t_relay()`, done as a B2BUA.
#
# Separation of concerns (§11.1): `Kelix.Mod.AuthDb` DECIDES — challenge, accept or
# refuse, and who the digest proved the sender to be — and the block it publishes
# (`AuthDb.SBB.authenticate/1`) composes the SIP that each verdict means. The
# module never builds a response, and this script never reads an Authorization
# header nor writes a 407: it names what each OUTCOME means for this call flow.
#
# Everything from `place_call` on is `direct-call.exs` unchanged: authentication is
# one state in front of the call, not a complication of the call.
defmodule Kelix.DirectCallWithAuth do
  use SIP.Scenario
  use SBB.Call
  use Kelix.Mod.AuthDb

  uas(:invite)

  # Refuse to load when either module is absent, instead of failing on the first
  # INVITE: the location service, and the authentication backend that now gates it.
  config(uses_modules: [:registrar, :auth_db])

  state initial_state do
    goto(wait_invite)
  end

  # The {:INVITE, …} that created this instance is already in our mailbox.
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

  # Who is calling? One verb: the block challenges, waits for the credentials,
  # verifies them and challenges again, and this script says what each outcome
  # means. What used to be here — 407 rather than 401, `stale`, "answer a refusal
  # and keep waiting", the 32 s a challenge is worth — was never about this call
  # flow, and was already copied verbatim into the media variant.
  #
  # The identity the digest proves is recorded in the context, so the leg placed
  # next asserts it (`P-Asserted-Identity`); nothing here has to carry it.
  state authenticate_caller do
    AuthDb.SBB.authenticate()

    on_events do
      {:auth, :authenticated, %{user: user}} ->
        goto(place_call, "INVITE authenticated as #{user}")

      # A caller that cancels the challenged attempt: nothing was forwarded, so
      # there was nothing to cancel but ourselves.
      {:auth, :cancelled, _} ->
        scenario_success("caller cancelled the challenged call")

      {:auth, :caller_gone, %{reason: reason}} ->
        scenario_success("caller gave up on the challenge: #{inspect(reason)}")

      # A UA replays a challenge within a second. This is the scanner, and the
      # phone whose password is wrong: end the instance rather than hold a slot.
      {:auth, :timeout, _} ->
        scenario_success("no credentials came back")

      {:auth, :refused, %{attempts: attempts}} ->
        scenario_success("gave up on this sender after #{attempts} refused attempts")
    end
  end

  # Where is Bob? The MODULE says where the AOR is and hands back a peer; the
  # SCRIPT decides what SIP each outcome means. Nothing is rescued here — a module
  # that faults raises, and the scenario runner logs it and fails the scenario,
  # which is more readable than an error mapped twice.
  #
  # From here on this script IS direct-call.exs: the same `call/1`, the same arms.
  # Authentication is one state in front of the call, not a complication of it,
  # and the two read alike now that each is one verb and its outcomes.
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
