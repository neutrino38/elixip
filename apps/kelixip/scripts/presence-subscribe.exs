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
# Two questions, in this order. WHO is watching — the digest, and nothing else,
# answers that — then MAY they watch, which in this reference is one question: is
# the presentity a subscriber of this deployment? A deployment with a policy of
# its own writes it in `authorize`, next to that question — a
# `reject_subscription(403, "Forbidden")` in the same place, with the
# authenticated identity already in the context.
#
# A presentity with no state — a room destroyed under its watcher, a user on a
# domain with no registrar — ends the subscription with `noresource` rather than
# with an explicitly closed state a watcher would wait on for nothing.
defmodule Kelix.PresenceSubscribe do
  use SIP.Scenario
  use Kelix.Mod.AuthDb
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
        goto(authenticate_watcher, "SUBSCRIBE received")

      {:dialog_terminated, _dialog_pid, :transport_down} ->
        scenario_aborted("watcher connection lost")

      {:dialog_terminated, _dialog_pid, _reason} ->
        scenario_success("subscription ended")
    after
      32_000 ->
        scenario_failure("no SUBSCRIBE received")
    end
  end

  # WHO is watching? The digest proves it, and nothing else does: a SUBSCRIBE names
  # its watcher in a `From` anyone can write. Without this state the state of every
  # provisioned user is readable by whoever asks for it — presence is exactly the
  # data a hostile watcher wants, since it says when someone is at their desk.
  #
  # 401, not 407: the presence server is the notifier of the resource, not a proxy
  # on the way to it (RFC 3261 §22.1). The realm defaults to the served domain.
  #
  # A refresh comes back here too. A UA that was challenged once replays its
  # credentials on every SUBSCRIBE of the dialog, so this costs nothing, and the
  # alternative is a subscription that authenticated once and is then extended for
  # hours by anyone who can guess a Call-ID.
  state authenticate_watcher do
    AuthDb.SBB.authenticate(code: 401)

    on_events do
      {:auth, :authenticated, %{user: user}} ->
        goto(authorize, "SUBSCRIBE authenticated as #{user}")

      {:auth, :caller_gone, %{reason: reason}} ->
        scenario_aborted("watcher vanished while challenged: #{inspect(reason)}")

      # A UA replays a challenge within a second. What does not is a scanner, or a
      # phone with a wrong password: end the instance rather than hold a slot.
      {:auth, :timeout, _} ->
        scenario_success("no credentials came back")

      {:auth, :refused, %{attempts: attempts}} ->
        scenario_success("gave up on this watcher after #{attempts} refused attempts")

      # A CANCEL on a SUBSCRIBE: legal, never seen. Named so the block's every
      # outcome is answered — one nobody matches leaves the machine waiting.
      {:auth, :cancelled, _} ->
        scenario_success("watcher cancelled the challenged SUBSCRIBE")
    end
  end

  # May this watcher watch? The only check this reference makes is that the
  # presentity exists — a subscriber of this deployment, or a resource another
  # module reports a state for, a conference room: subscribing to one nobody
  # provisioned is 404, not an empty state a watcher would wait on for an hour.
  #
  # The SUBSCRIBE itself needs no carrying around: on_events stores the inbound
  # request and last_uas_req() reads it back in any later state.
  state authorize do
    req = last_uas_req()

    if Kelix.Mod.Presence.exists?(sip_ctx, SIP.Msg.Ops.target_aor(req)) do
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
        # what. Registering hands back the state as it stands — nil when the
        # resource has none at all, which ends the subscription: the dialog sends
        # the final NOTIFY, `terminated;reason=noresource`.
        case Kelix.Mod.Presence.watch(sip_ctx, sub) do
          {:ok, nil} ->
            trace_notify(sub, nil)
            terminate_subscription(:noresource)
            goto(ending, "200 + NOTIFY noresource")

          {:ok, doc} ->
            trace_notify(sub, doc)
            notify(doc)
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
      # `nil` means the resource has no state any more — a room destroyed, the
      # module that reported it gone — and ends the subscription.
      {:presence, :state, _resource, nil} ->
        trace_notify(last_subscription(), nil)
        terminate_subscription(:noresource)
        goto(ending, "state gone: noresource")

      {:presence, :state, _resource, doc} ->
        trace_notify(last_subscription(), doc)
        notify(doc)
        stay("state pushed")

      # A refresh is another SUBSCRIBE on the same dialog: negotiated again,
      # granted again, and answered with the state as it stands.
      {:SUBSCRIBE, _req, _trans_pid, _dialog_pid} ->
        goto(authenticate_watcher, "refresh")

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

  # We ended the subscription: the dialog sends the final NOTIFY and hands back
  # the one `:subscription_terminated` every end produces.
  state ending do
    on_events do
      {:subscription_terminated, _ref, reason} ->
        Kelix.Mod.Presence.unwatch(sip_ctx)
        scenario_success("subscription ended: #{reason}")

      {:presence, :state, _resource, _doc} ->
        stay("subscription ending")

      {:dialog_terminated, _dialog_pid, :transport_down} ->
        scenario_aborted("watcher connection lost")

      {:dialog_terminated, _dialog_pid, _reason} ->
        scenario_success("dialog ended")
    after
      32_000 ->
        Kelix.Mod.Presence.unwatch(sip_ctx)
        scenario_failure("subscription did not end")
    end
  end

  # One line per NOTIFY: to whom, about whom, on which package, saying what.
  defp trace_notify(sub, doc) do
    Logger.info(
      module: __MODULE__,
      message:
        "NOTIFY #{sub.event} to #{SIP.Subscription.watcher_uri(sub)} " <>
          "about #{sub.presentity_uri}: " <>
          if(doc, do: SIP.EventPackage.summary(doc), else: "no state, ending (noresource)")
    )
  end

  # Cooperative shutdown (§5.3). The collection drops us on its own — it monitors
  # the instances that watch — and the dialog sends the final NOTIFY as it goes.
  on_shutdown do
    scenario_aborted("Notifier stopped gracefully")
  end
end
