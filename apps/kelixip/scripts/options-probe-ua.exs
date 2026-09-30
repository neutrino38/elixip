# Reference kelixip OPTIONS script: a capability probe of a registered UA.
#
# Bound by a `pattern` or the `default = true` rule of [[domain.options]], it
# serves an OPTIONS naming a user (`sip:bob@example.com`) the way
# `direct-call-with-auth.exs` serves an INVITE: the sender proves who it is, the
# registrar says where Bob is, and the probe is relayed to him. Bob's answer — his
# `Allow`, `Accept`, `Supported` — is what goes back.
#
# The challenge relies on the OPTIONS dialog: the re-submission with credentials
# keeps its Call-ID and From-tag, so it reaches this instance, and the dialog lives
# 32 s after the last OPTIONS on it.
defmodule Kelix.OptionsProbeUA do
  use SIP.Scenario
  use Kelix.Mod.AuthDb

  uas(:options)

  # Refuse to load when either module is absent, instead of failing on the first
  # probe: the location service, and the authentication backend that gates it.
  config(uses_modules: [:registrar, :auth_db])

  state initial_state do
    goto(wait_options)
  end

  # The {:OPTIONS, …} that created this instance is already in our mailbox.
  state wait_options do
    on_events do
      {:OPTIONS, _req, _trans, _dlg} ->
        goto(authenticate_sender, "OPTIONS received")

      {:dialog_terminated, _dlg, _reason} ->
        scenario_aborted("sender vanished before the OPTIONS")
    after
      5_000 -> scenario_failure("no OPTIONS received")
    end
  end

  state authenticate_sender do
    AuthDb.SBB.authenticate()

    on_events do
      {:auth, :authenticated, %{user: user}} ->
        goto(probe_ua, "OPTIONS authenticated as #{user}")

      {:auth, :caller_gone, %{reason: reason}} ->
        scenario_success("sender gave up on the challenge: #{inspect(reason)}")

      {:auth, :timeout, _} ->
        scenario_success("no credentials came back")

      {:auth, :refused, %{attempts: attempts}} ->
        scenario_success("gave up on this sender after #{attempts} refused attempts")

      # An OPTIONS has no CANCEL of its own; the block names the outcome anyway.
      {:auth, :cancelled, _} ->
        scenario_success("sender cancelled the challenged OPTIONS")
    end
  end

  # Where is Bob? The module says where the AOR is, the script says what each
  # outcome means.
  state probe_ua do
    req = last_uas_req()

    case Kelix.Mod.Registrar.targets(ctx_get(:domain), req) do
      {:ok, peer} ->
        b2bua_forward(req, peer, false)
        goto(wait_answer, "OPTIONS relayed")

      :notfound ->
        b2bua_reply(req, 480, "Temporarily Unavailable")
        scenario_success("the UA is registered nowhere right now")

      :no_aor ->
        b2bua_reply(req, 400, "Bad Request")
        scenario_success("the OPTIONS names no AOR")

      :unavailable ->
        b2bua_reply(req, 500, "Location Service Unavailable")
        scenario_failure("the location service could not answer")
    end
  end

  state wait_answer do
    on_events do
      {:outbound, {code, _resp, _trans, _dlg}} when code in 100..199 ->
        stay("provisional #{code}")

      # A refusal from one binding of a serial hunt is the answer of one device,
      # not of the UA: ask before concluding.
      {:outbound, {code, resp, _trans, _dlg}} when code >= 300 ->
        b2bua_forward_reply(resp)

        if b2bua_hunting?() do
          stay("#{code}, trying the next binding")
        else
          scenario_success("the UA answered #{code}")
        end

      {:outbound, {code, resp, _trans, _dlg}} ->
        b2bua_forward_reply(resp)
        scenario_success("the UA answered #{code}")

      {:outbound, {:dialog_terminated, _dlg, reason}} ->
        b2bua_reply(last_uas_req(), 408, "Request Timeout")
        scenario_success("the UA never answered: #{inspect(reason)}")
    after
      32_000 ->
        b2bua_reply(last_uas_req(), 408, "Request Timeout")
        scenario_success("the UA never answered")
    end
  end

  on_shutdown do
    scenario_aborted("stopped")
  end
end
