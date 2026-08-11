# Reference kelixip registrar script. One instance is spawned
# per inbound REGISTER dialog by Kelix.Router → Kelix.InstancePool. The served
# domain is injected into the context (sip_ctx.domain) by the router.
# This version sends no OPTIONS keepalive of its own: probing liveness is left to
# the registered client (UAC). Answering the client's OPTIONS is not this script's
# business either — an in-dialog OPTIONS is answered 200 OK by the dialog layer,
# and an out-of-dialog one by Kelix.Options, neither of which reaches a scenario.

defmodule Kelix.Registrar do
  use SIP.Scenario
  require Logger

  uas(:register)

  # Declared so the load-time contract (§5.3) refuses this script when either module
  # is missing, instead of letting the first REGISTER die on an undefined function.
  config(uses_modules: [:registrar, :auth_db])

  # The {:REGISTER, …} is already queued by the dialog layer; wait for it.
  state initial_state do
    goto(wait_register)
  end

  # The REGISTER itself needs no carrying around: on_events stores the inbound
  # request in the context, and last_uas_req() reads it back in any later state.
  state wait_register do
    on_events do
      {:REGISTER, _req, _trans_pid, _dialog_pid} ->
        goto(process_register, "registering")

      # The connection this UA registered over is gone. Over a connected transport
      # that IS the end of the registration: the binding names a flow nothing can
      # reach any more. Over UDP nothing dies, and the net is the dialog's own
      # `:registerexpire` timer, which stops it `:normal` — the clause below.
      {:dialog_terminated, _dialog_pid, :transport_down} ->
        scenario_aborted("client connection lost")

      {:dialog_terminated, _dialog_pid, _reason} ->
        scenario_success("registration ended")
    after
      600_000 ->
        scenario_success("registration idle timeout")
    end
  end

  state process_register do
    req = last_uas_req()

    case Kelix.Mod.AuthDb.do_registration_auth(req, sip_ctx.domain) do
      {:requireauth, stale} ->
        params =
          Kelix.Auth.challenge_params(sip_ctx.domain,
            stale: stale,
            algorithm: Kelix.Mod.AuthDb.challenge_algorithm()
          )

        SIP.Session.Registrar.challenge_registration(sip_ctx, req, params)
        goto(wait_register, if(stale, do: "401 stale", else: "401 challenge"))

      :ok ->
        goto(save_registration, "REGISTER auth OK")

      # Answer and keep waiting — never end the instance on a refused REGISTER.
      # The dialog does NOT die with us: nothing monitors the app pid, so a dialog
      # whose instance ended still matches the next REGISTER of that Call-ID and
      # casts it to a dead process. The client would then get NO answer at all
      # until the dialog's own expiration timer fires, up to an hour later. A 403
      # is one request's verdict, not the end of the conversation — a client that
      # fixes its credentials must be able to say so.
      {:reject, code, reason} ->
        SIP.Session.Registrar.reject_registration(sip_ctx, req, code, reason)
        goto(wait_register, "#{code} #{reason}")
    end
  end

  state save_registration do
    req = last_uas_req()

    case Kelix.Mod.Registrar.save(sip_ctx, req) do
      {:registered, granted} ->
        SIP.Session.Registrar.accept_registration(sip_ctx, req, granted)
        goto(wait_refresh, "200 OK")

      {:unregistered, granted} ->
        SIP.Session.Registrar.accept_registration(sip_ctx, req, granted)
        scenario_success("unregistered")

      # RFC 3261 §10.3 step 7: the 423 MUST carry Min-Expires, otherwise the client
      # has no way to know what to ask for. Passing the bound as an integer is what
      # tells reject_registration to put it there.
      {:error, {423, reason}} ->
        min = Kelix.Mod.Registrar.min_expires(sip_ctx.domain)
        SIP.Session.Registrar.reject_registration(sip_ctx, req, 423, min)
        goto(wait_register, "423 #{reason} (min #{min})")

      # The store is down or wedged — Kelix.Module.safe_call/3 degrades to this
      # instead of blocking us (§8.2). 503, not 500: nothing is broken, the service
      # is momentarily unavailable and the client should retry — and we must still
      # be here when it does (see the 403 above).
      {:error, reason} when reason in [:down, :timeout] ->
        Logger.error(module: __MODULE__, message: "Failed to save registration: #{reason}")
        SIP.Session.Registrar.reject_registration(sip_ctx, req, 503, "Service Unavailable")
        goto(wait_register, "503 store down")

      # 400 (no Contact, bad wildcard) / 403 (too many contacts): one request is
      # refused, the AOR's existing bindings are untouched, and so is this session.
      {:error, {code, reason}} ->
        SIP.Session.Registrar.reject_registration(sip_ctx, req, code, reason)
        goto(wait_register, "#{code} #{reason}")
    end
  end

  state wait_refresh do
    on_events do
      {:REGISTER, _req, _trans_pid, _dialog_pid} ->
        goto(process_register, "registering")

      {:dialog_terminated, _dialog_pid, :transport_down} ->
        scenario_aborted("client connection lost")

      {:dialog_terminated, _dialog_pid, _reason} ->
        scenario_success("registration ended")
    end
  end

  # Cooperative shutdown (§5.3): a registrar has no BYE/media to release.
  on_shutdown do
    scenario_aborted("Registrar stopped gracefully")
  end
end
