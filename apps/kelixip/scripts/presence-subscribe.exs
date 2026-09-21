# Reference kelixip presence script, SUBSCRIBE half — the notifier of RFC 6665.
# One instance is spawned per inbound SUBSCRIBE dialog by Kelix.Router →
# Kelix.InstancePool. The served domain and the event package of the
# [[domain.presence]] block that routed us here are injected into the context.
#
# The negotiation is NOT here. The router has already answered 489 for any
# package this domain does not serve, and `accept_subscription/1` answers 406 and
# 423 itself. What is left is what a script is for: who may watch, what state to
# send, and when to stop.
#
# Admission is ONE question in this reference: is the presentity a subscriber of
# this deployment? A deployment with a policy of its own writes it in
# `authorize`, next to that question — a `reject_subscription(403, "Forbidden")`
# in the same place.
defmodule Kelix.PresenceSubscribe do
  use SIP.Scenario
  require Logger

  uas(:presence)

  # Declared so the load-time contract (§5.3) refuses this script when either
  # module is missing, instead of letting the first SUBSCRIBE die on an undefined
  # function.
  config(uses_modules: [:presence, :auth_db])

  # The {:SUBSCRIBE, …} is already queued by the dialog layer; wait for it.
  state initial_state do
    goto(wait_subscribe)
  end

  state wait_subscribe do
    on_events do
      {:SUBSCRIBE, _req, _trans_pid, _dialog_pid} ->
        goto(authorize, "SUBSCRIBE received")

      {:dialog_terminated, _dialog_pid, :transport_down} ->
        scenario_aborted("watcher connection lost")

      {:dialog_terminated, _dialog_pid, _reason} ->
        scenario_success("subscription ended")
    after
      32_000 ->
        scenario_failure("no SUBSCRIBE received")
    end
  end

  # May this watcher watch? The only check this reference makes is that the
  # presentity exists in the subscriber base: subscribing to a user nobody
  # provisioned is 404, not an empty state a watcher would wait on for an hour.
  #
  # The SUBSCRIBE itself needs no carrying around: on_events stores the inbound
  # request and last_uas_req() reads it back in any later state.
  state authorize do
    req = last_uas_req()

    if Kelix.Mod.AuthDb.subscriber?(SIP.Msg.Ops.target_aor(req), sip_ctx.domain) do
      goto(subscribe, "presentity exists")
    else
      reject_subscription(404, "Not Found")
      goto(wait_subscribe, "404 no such presentity")
    end
  end

  state subscribe do
    case accept_subscription(
           package: ctx_get(:event_package),
           allow_events: Kelix.Domains.event_packages(sip_ctx.domain)
         ) do
      {:ok, sub} ->
        # The framework holds THIS subscription; the module holds who watches
        # what. Registering hands back the state as it stands — nil when nothing
        # has been published about the resource yet, which a watcher is told as
        # an explicitly closed state rather than by silence.
        case Kelix.Mod.Presence.watch(sip_ctx, sub) do
          {:ok, doc} ->
            notify(doc || SIP.Presence.Doc.new(sub.presentity_uri, :closed))
            goto(subscribed, "200 + NOTIFY")

          {:error, reason} ->
            Logger.error(module: __MODULE__, message: "presence store unavailable: #{reason}")
            terminate_subscription(:noresource)
            scenario_failure("presence store #{reason}")
        end

      # 406 / 423 have already gone out; the watcher may ask again with what the
      # refusal told it. (The 489 never reaches here — the router raised it.)
      {:error, code} ->
        goto(wait_subscribe, "#{code}")
    end
  end

  # Subscribed. Three things happen here, and the state machine says which:
  # the state changes, the watcher refreshes, or the subscription ends.
  state subscribed do
    on_events do
      # The fan-out: one PUBLISH became one push per watcher, and each watcher
      # sends its own NOTIFY from its own state (DESIGN-PRESENCE.md, decision 1).
      # `nil` means nothing is published about the resource any more.
      {:presence, :state, _resource, doc} ->
        sub = last_subscription()
        notify(doc || SIP.Presence.Doc.new(sub.presentity_uri, :closed))
        stay("state pushed")

      # A refresh is another SUBSCRIBE on the same dialog: negotiated again,
      # granted again, and answered with the state as it stands.
      {:SUBSCRIBE, _req, _trans_pid, _dialog_pid} ->
        goto(authorize, "refresh")

      # The end of the subscription is the dialog's: it arms the granted
      # lifetime, sends the final NOTIFY and hands us exactly one of these. An
      # un-SUBSCRIBE (Expires: 0) takes the same path.
      {:subscription_terminated, _ref, reason} ->
        Kelix.Mod.Presence.unwatch(sip_ctx)
        scenario_success("subscription ended: #{reason}")

      {:dialog_terminated, _dialog_pid, :transport_down} ->
        scenario_aborted("watcher connection lost")

      {:dialog_terminated, _dialog_pid, _reason} ->
        scenario_success("dialog ended")
    end
  end

  # Cooperative shutdown (§5.3). The collection drops us on its own — it monitors
  # the instances that watch — and the dialog sends the final NOTIFY as it goes.
  on_shutdown do
    scenario_aborted("Notifier stopped gracefully")
  end
end
