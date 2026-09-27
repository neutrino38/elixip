# Reference UAS (server-side) presence scenario — the notifier half of RFC 6665.
# Run it with:
#     elixipp --listen udp:5060 apps/elixip2/scenarios/uas_presence.exs
#
# elixipp loads this file, sees it is a `:uas_presence` scenario (set by the
# `uas :presence` annotation), starts the configured listeners and registers
# Elixip.ScenarioUAS as the presence processing module. One instance of this
# scenario is spawned per inbound SUBSCRIBE dialog — and one per PUBLISH, whose
# dialog lives no longer than its transaction — and receives
# `{:SUBSCRIBE, req, transaction_id, dialog_pid}` in its mailbox.
#
# The negotiation is NOT here: `accept_subscription/1` reads Event, Accept and
# Expires, answers 489 / 406 / 423 itself, and the factory has already refused
# any package other than the one declared below. What is left for the script is
# what a script is for: whether this watcher may watch, what state to send, and
# when to stop.
#
# It keeps no collection. A published state is acknowledged and forgotten, and
# one watcher gets one document: who watches what, and one PUBLISH becoming N
# NOTIFYs, is the kelixip `presence` module's (DESIGN-PRESENCE.md).
defmodule UAS.PresenceExample do
  use SIP.Scenario

  # Marks the scenario type as :uas_presence so elixipp runs it in server mode.
  uas(:presence)

  @domain "example.com"
  @package "presence"
  # Ceiling on the subscription lifetime we grant (seconds). What goes back in
  # the 200 OK is min(what the watcher asked, this, the package's max).
  @granted_expires 300

  # `event_package` is what Elixip.ScenarioUAS answers 489 on, before any of the
  # states below run. No outbound account: a server scenario is seeded from the
  # inbound request, not from a local identity.
  config(domain: @domain, event_package: @package)

  # The {:SUBSCRIBE, …} message is already queued in our mailbox by the dialog
  # layer; jump straight to the waiting state.
  state initial_state do
    goto(next)
  end

  # ---------------------------------------------------------------------------
  # A watcher asks. Admission is the only decision left to the script — this one
  # admits everybody, which is what a test tool is for; a real policy is a
  # `reject_subscription(403, "Forbidden")` in the same place.
  state wait_subscribe do
    on_events do
      {:SUBSCRIBE, _req, _trans_pid, _dialog_pid} ->
        case accept_subscription(
               package: @package,
               expires: @granted_expires,
               allow_events: [@package]
             ) do
          {:ok, sub} ->
            notify(
              SIP.Presence.Doc.new(sub.presentity_uri, :open,
                contact: sub.presentity_uri,
                note: "Available"
              )
            )

            goto(subscribed, "200 + NOTIFY")

          # 489 / 406 / 423 have already gone out; the watcher may ask again
          # with what the refusal told it.
          {:error, code} ->
            stay("#{code}")
        end

      # A PUBLISH arrives on a dialog of its own, so this instance serves one and
      # ends. The entity-tag is minted here because nothing here stores one: with
      # no collection there is no state to refresh, and a publisher presenting
      # this tag again is answered 412 — correctly, since we kept nothing.
      {:PUBLISH, _req, _trans_pid, _dialog_pid} ->
        case check_publish(package: @package) do
          {:ok, pub} ->
            reply_publish(200,
              etag: SIP.Publication.new_etag(),
              expires: SIP.Publication.remaining(pub)
            )

            scenario_success("PUBLISH accepted (not stored)")

          # 400 / 415 / 423 / 489 have already gone out.
          {:error, code} ->
            scenario_success("PUBLISH refused with #{code}")
        end

      {:scenario_ctl, :shutdown, _reason} ->
        scenario_aborted("Notifier stopped gracefully")
    after
      32_000 ->
        scenario_failure("no SUBSCRIBE received")
    end
  end

  # ---------------------------------------------------------------------------
  # Subscribed. A refresh is another SUBSCRIBE on the same dialog: negotiated
  # again, granted again, and answered with the state as it stands.
  #
  # The end of the subscription is NOT handled here: the dialog arms the granted
  # lifetime, sends the final NOTIFY (`Subscription-State: terminated`) and hands
  # us exactly one {:subscription_terminated, …}. An un-SUBSCRIBE (Expires: 0)
  # takes the same path.
  state subscribed do
    on_events do
      {:SUBSCRIBE, _req, _trans_pid, _dialog_pid} ->
        case accept_subscription(
               package: @package,
               expires: @granted_expires,
               allow_events: [@package]
             ) do
          {:ok, sub} ->
            notify(
              SIP.Presence.Doc.new(sub.presentity_uri, :open,
                contact: sub.presentity_uri,
                note: "Available"
              )
            )

            stay("SUBSCRIBE refreshed")

          {:error, code} ->
            stay("#{code}")
        end

      {:subscription_terminated, _ref, reason} ->
        scenario_success("subscription ended: #{reason}")

      {:scenario_ctl, :shutdown, _reason} ->
        scenario_aborted("Notifier stopped gracefully")

      # The connection this watcher subscribed over is gone. Over UDP nothing
      # dies and the subscription lapses instead — the clause above.
      {:dialog_terminated, _dialog_pid, :transport_down} ->
        scenario_aborted("Watcher connection lost")

      {:dialog_terminated, _dialog_pid, _reason} ->
        scenario_success("dialog ended")
    after
      600_000 ->
        scenario_success("subscription idle timeout")
    end
  end

  # Cooperative shutdown — required by kelixip's load-time contract (§5.3). A
  # notifier has no BYE to send nor media to release; the dialog sends the final
  # NOTIFY when it goes, so aborting cleanly is enough.
  on_shutdown do
    scenario_aborted("Notifier stopped gracefully")
  end
end
