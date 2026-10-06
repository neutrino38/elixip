# Reference kelixip registrar script for a domain that chats: registrar-presence.exs,
# plus the delivery of the messages stored while the user had no device
# reachable (chat-basic-plan, C8).
#
# After each 200 OK that leaves the AOR registered — a first registration, a
# refresh, a device coming back from a new network — the Silo is asked to flush
# (`Kelix.Mod.Silo.flush/2`): the messages kept for this AOR go to the devices
# this REGISTER binds, over the connection it came on, in the order they
# arrived. After the 200, never before: a MESSAGE pushed while the client is
# still completing its registration is lost. The flush runs in the module, not
# here; this script only says when.
#
# A device already served a message is not served it again: the Silo knows it
# by its `+sip.instance`. A refresh flushes too — it costs one indexed query
# when nothing is pending, and it is what catches a message stored between two
# refreshes of a device whose connection never dropped.
#
# Everything else is registrar-presence.exs, whose notes follow.
#
# Reference kelixip registrar script that also drives presence: registrar.exs,
# plus a report to the presence collection each time a registration changes. A
# subscriber who publishes nothing is then open while one of its devices is
# registered and closed otherwise, and its watchers are NOTIFYed on each change.
#
# One instance is spawned per inbound REGISTER dialog — per device — by
# Kelix.Router → Kelix.InstancePool. The served domain is injected into the
# context (sip_ctx.domain) by the router.
#
# Three reports, one per way a registration moves:
#   * a REGISTER saved, whatever its outcome (registered, refreshed, removed);
#   * the connection the device registered over dropped;
#   * the registration was not refreshed in time (the dialog's :registerexpire).
# None of them says open or closed: the collection reads the registrar, all the
# AOR's devices included, so one handset leaving does not close a subscriber
# another handset keeps registered.
#
# Two things differ from registrar.exs beyond the reports, both so that a
# registration always has an instance alive to report its end:
#   * a refused REGISTER (403, 423, 400, 503) leaves the bindings it
#     would have changed as they were, so a refused REFRESH goes back to waiting
#     for the next one instead of ending the session;
#   * the wait for a refresh ends when this dialog's registration lapses in the
#     registrar, not when the dialog's own timer fires: that timer is re-armed by
#     every REGISTER received, refused ones included, on the lifetime asked
#     rather than the one granted.
#
# This version sends no OPTIONS keepalive of its own: probing liveness is left to
# the registered client (UAC). Answering the client's OPTIONS is not this script's
# business either — an in-dialog OPTIONS is answered 200 OK by the dialog layer,
# and an out-of-dialog one by Kelix.Options, neither of which reaches a scenario.

defmodule Kelix.RegistrarChat do
  use SIP.Scenario
  require Logger

  uas(:register)

  # Declared so the load-time contract (§5.3) refuses this script when either module
  # is missing, instead of letting the first REGISTER die on an undefined function.
  config(uses_modules: [:registrar, :auth_db, :presence, :silo])

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
        Kelix.Mod.Presence.registration_ended(sip_ctx)
        scenario_aborted("client connection lost")

      {:dialog_terminated, _dialog_pid, _reason} ->
        Kelix.Mod.Presence.registration_ended(sip_ctx)
        scenario_success("registration ended")
    after
      5_000 ->
        scenario_failure("registration idle timeout")
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
        # `back`, not a named state: this detour serves both the first REGISTER and
        # a refresh, and each caller resumes its own wait — with its own idle
        # timeout, which for a session already registered is the dialog's
        # :registerexpire rather than a fresh 5 s.
        goto(back, if(stale, do: "401 stale", else: "401 challenge"))

      :ok -> goto(save_registration, "REGISTER auth OK")

      # Answer and keep waiting — give a small grace window for the UA to send
      # a correct REGISTER
      {:reject, code, reason} ->
        SIP.Session.Registrar.reject_registration(sip_ctx, req, code, reason)
        goto(refused, "#{code} #{reason}")
    end
  end

  state save_registration do
    req = last_uas_req()

    case Kelix.Mod.Registrar.save(sip_ctx, req) do
      {:registered, granted} ->
        SIP.Session.Registrar.accept_registration(sip_ctx, req, granted)
        Kelix.Mod.Presence.registration_changed(sip_ctx)
        # After the 200: what was kept for this AOR, to the devices just bound.
        Kelix.Mod.Silo.flush(sip_ctx, req)
        goto(wait_refresh, "200 OK")

      {:unregistered, granted} ->
        SIP.Session.Registrar.accept_registration(sip_ctx, req, granted)
        Kelix.Mod.Presence.registration_changed(sip_ctx)
        scenario_success("unregistered")

      # RFC 3261 §10.3 step 7: the 423 MUST carry Min-Expires, otherwise the client
      # has no way to know what to ask for. Passing the bound as an integer is what
      # tells reject_registration to put it there.
      {:error, {423, reason}} ->
        min = Kelix.Mod.Registrar.min_expires(sip_ctx.domain)
        SIP.Session.Registrar.reject_registration(sip_ctx, req, 423, min)
        goto(refused, "423 #{reason} (min #{min})")

      # The store is down or wedged — Kelix.Module.safe_call/3 degrades to this
      # instead of blocking us (§8.2). 503, not 500: nothing is broken, the service
      # is momentarily unavailable and the client should retry — and we must still
      # be here when it does (see the 403 above).
      {:error, reason} when reason in [:down, :timeout] ->
        Logger.error(module: __MODULE__, message: "Failed to save registration: #{reason}")
        SIP.Session.Registrar.reject_registration(sip_ctx, req, 503, "Service Unavailable")
        goto(refused, "503 store down")

      # 400 (no Contact, bad wildcard) / 403 (too many contacts): one request is
      # refused, the AOR's existing bindings are untouched, and so is this session.
      {:error, {code, reason}} ->
        SIP.Session.Registrar.reject_registration(sip_ctx, req, code, reason)
        goto(refused, "#{code} #{reason}")
    end
  end

  # A refused REGISTER changed nothing: the session is registered exactly when it
  # was before, and waits accordingly — for a first REGISTER that works, or for
  # the refresh of the registration it still holds.
  state refused do
    case Kelix.Mod.Registrar.remaining_ms(sip_ctx) do
      0 -> goto(wait_register, "not registered")
      _still_running -> goto(wait_refresh, "registration still running")
    end
  end

  state wait_refresh do
    on_events do
      {:REGISTER, _req, _trans_pid, _dialog_pid} ->
        goto(process_register, "registering")

      {:dialog_terminated, _dialog_pid, :transport_down} ->
        Kelix.Mod.Presence.registration_ended(sip_ctx)
        scenario_aborted("client connection lost")

      {:dialog_terminated, _dialog_pid, _reason} ->
        Kelix.Mod.Presence.registration_ended(sip_ctx)
        scenario_success("registration ended")
    after
      # No refresh came before the registration lapsed in the registrar.
      Kelix.Mod.Registrar.remaining_ms(sip_ctx) ->
        Kelix.Mod.Presence.registration_ended(sip_ctx)
        scenario_success("registration not refreshed")
    end
  end

  # Cooperative shutdown (§5.3): a registrar has no BYE/media to release.
  on_shutdown do
    scenario_aborted("Registrar stopped gracefully")
  end
end
