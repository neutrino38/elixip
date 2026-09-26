# Reference kelixip presence script, LIST subscription half — the resource list
# server of RFC 4662, with the list carried in the SUBSCRIBE itself (RFC 5367).
#
# One instance is spawned per inbound SUBSCRIBE dialog, exactly like
# presence-subscribe.exs. What differs is what the watcher asked for: one
# subscription covering N buddies, answered by one NOTIFY carrying an RLMI
# manifest and one PIDF part per buddy.
#
# Two things about a list subscription that an ordinary one does not have to
# think about, and which is why this is a script of its own rather than a branch:
#
#   * the Request-URI names a LIST, not a presentity. A Linphone client sends
#     `sip:rls@sip.linphone.org` whatever its own domain is, so the realm to
#     challenge on is the watcher's — its `From` — and never the routed domain;
#   * the buddies sit on their own domains, none of which has to be the routed
#     one. `watch_many/3` files each on its own and answers its state — what was
#     published, else open/closed from the registrar for a known subscriber of a
#     domain that has one; any other entry is answered `noresource` rather than
#     left silent.
defmodule Kelix.PresenceRls do
  use SIP.Scenario
  use Kelix.Mod.AuthDb
  require Logger

  uas(:presence)

  config(uses_modules: [:presence, :auth_db])

  # How long a state change waits for the ones that follow it before a NOTIFY
  # goes out. A roster coming online produces one push per buddy within a few
  # hundred milliseconds; without this the watcher gets one NOTIFY per buddy, each
  # carrying the whole envelope.
  @batch_ms 500

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

  # WHO is watching, on ITS OWN realm. `sip:rls@…` is a URI no subscriber belongs
  # to: challenging on the routed domain would ask for credentials that exist
  # nowhere, and the watcher would answer the challenge for ever.
  state authenticate_watcher do
    AuthDb.SBB.authenticate(code: 401, realm: :from_domain)

    on_events do
      {:auth, :authenticated, %{user: user}} ->
        goto(subscribe, "SUBSCRIBE authenticated as #{user}")

      {:auth, :caller_gone, %{reason: reason}} ->
        scenario_aborted("watcher vanished while challenged: #{inspect(reason)}")

      {:auth, :timeout, _} ->
        scenario_success("no credentials came back")

      {:auth, :refused, %{attempts: attempts}} ->
        scenario_success("gave up on this watcher after #{attempts} refused attempts")

      {:auth, :cancelled, _} ->
        scenario_success("watcher cancelled the challenged SUBSCRIBE")
    end
  end

  # No `authorize` state, and that is a decision: the presentity of a list
  # subscription is the list, and a list is whatever the watcher put in its own
  # SUBSCRIBE. There is nothing to look up and refuse — an entry with no state
  # is reported `noresource` in the manifest, one buddy at a time.
  state subscribe do
    case accept_subscription(
           package: ctx_get(:event_package),
           allow_events: Kelix.Domains.event_packages(sip_ctx.domain)
         ) do
      {:ok, sub} ->
        case Kelix.Mod.Presence.watch_many(sip_ctx, sub, sub.list_entries) do
          {:ok, states} ->
            notify_list(states)
            goto(subscribed, "200 + full-state NOTIFY (#{map_size(states)} resources)")

          {:error, reason} ->
            Logger.error(module: __MODULE__, message: "presence store unavailable: #{reason}")
            terminate_subscription(:noresource)
            scenario_failure("presence store #{reason}")
        end

      # 406 / 420 / 423 have already gone out. A watcher whose Accept cannot
      # carry a list asks again, one subscription per buddy.
      {:error, code} ->
        goto(wait_subscribe, "#{code}")
    end
  end

  state subscribed do
    on_events do
      # The first state change of a burst: hold it and collect what follows.
      {:presence, :state, resource, doc} ->
        appdata_set(:pending, %{uri_of(resource) => doc})
        goto(batching, "state changed")

      {:SUBSCRIBE, _req, _trans_pid, _dialog_pid} ->
        goto(authenticate_watcher, "refresh")

      {:subscription_terminated, _ref, reason} ->
        Kelix.Mod.Presence.unwatch(sip_ctx)
        scenario_success("subscription ended: #{reason}")

      {:dialog_terminated, _dialog_pid, :transport_down} ->
        scenario_aborted("watcher connection lost")

      {:dialog_terminated, _dialog_pid, _reason} ->
        scenario_success("dialog ended")
    end
  end

  # Collecting. Everything that ends the subscription ends it here too — a state
  # held back is not worth a subscription that outlives its dialog.
  state batching do
    on_events do
      {:presence, :state, resource, doc} ->
        appdata_set(:pending, Map.put(appdata_get(:pending), uri_of(resource), doc))
        stay("collected")

      {:SUBSCRIBE, _req, _trans_pid, _dialog_pid} ->
        goto(authenticate_watcher, "refresh")

      {:subscription_terminated, _ref, reason} ->
        Kelix.Mod.Presence.unwatch(sip_ctx)
        scenario_success("subscription ended: #{reason}")

      {:dialog_terminated, _dialog_pid, :transport_down} ->
        scenario_aborted("watcher connection lost")

      {:dialog_terminated, _dialog_pid, _reason} ->
        scenario_success("dialog ended")
    after
      @batch_ms ->
        notify_list(appdata_get(:pending))
        appdata_set(:pending, %{})
        goto(subscribed, "partial NOTIFY")
    end
  end

  on_shutdown do
    scenario_aborted("Notifier stopped gracefully")
  end

  # A label with no SIP meaning: the collection pushes `{user, domain, event}`,
  # the manifest names URIs.
  defp uri_of({user, domain, _event}), do: "sip:#{user}@#{domain}"
end
