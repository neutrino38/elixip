# Reference UAC (client-side) presence scenario — the watcher half of RFC 6665.
# Run it against the notifier of scenarios/uas_presence.exs with:
#     elixipp --listen udp:5060 apps/elixip2/scenarios/uas_presence.exs
#     elixipp apps/elixip2/scenarios/uac_subscribe.exs
#
# The presentity it watches is the `watch` key of the config block below: edit it,
# the way uac_invite.exs's callee number is edited. `-c accounts.json` carries the
# credentials and the domain of the run, not this target — the external JSON
# validates a fixed set of keys (see ELIXIPP.md, "JSON parameterisation").
#
# Three things this scenario deliberately does NOT do, because the framework
# does them: answer each NOTIFY 200 (the dialog does, before the request is even
# surfaced), re-SUBSCRIBE before expiry (the dialog does, with the package, the
# id and the lifetime that were negotiated), and decide when the subscription is
# over (exactly one {:subscription_terminated, …} says so, whichever way it
# ended). What is left is what a watcher is for: asking, displaying, stopping.
defmodule UAC.SubscribeExample do
  use SIP.Scenario

  @username "alice"
  @authusername "alice"
  @domain "example.com"
  @passwd "changeme"
  @watch "sip:bob@example.com"
  @expires 120
  # Stop after this many states received, so the reference run terminates.
  @max_notifies 2

  config(
    username: @username,
    authusername: @authusername,
    domain: @domain,
    passwd: @passwd,
    watch: @watch,
    proxyusesrv: false
  )

  state initial_state do
    appdata_set(:notifies, 0)
    goto(next)
  end

  # ---------------------------------------------------------------------------
  # Ask. The Accept advertised and the lifetime asked for both come from the
  # event package (RFC 6665 §4.4.1) — send_SUBSCRIBE reads them there, so this
  # scenario names neither.
  state subscribing do
    send_SUBSCRIBE(appdata_get(:watch), "presence", expires: @expires)

    on_events do
      {100, _rsp, _trans_pid, _dialog_pid} ->
        stay("100 Trying")

      {401, rsp, _trans_pid, _dialog_pid} ->
        send_auth_SUBSCRIBE(rsp, appdata_get(:watch), "presence", expires: @expires)
        stay("401 Unauthorized")

      # The first NOTIFY may arrive BEFORE the 200 that belongs to it (RFC 6665
      # §4.2.1.2 has the notifier send the 2xx first, and UDP reorders anyway).
      # The dialog has already answered it and adopted the tag it carries.
      {:NOTIFY, req, _trans_pid, _dialog_pid} ->
        goto(watching, label("early NOTIFY", notified_document(req)))

      {200, rsp, trans_pid, _dialog_pid} ->
        # Records what the notifier GRANTED — which may be less than what was
        # asked — and lets the dialog arm the refresh on it.
        process_sip_reply(rsp, trans_pid)
        goto(watching, "200 OK")

      # 423 carries the Min-Expires the notifier will accept and 489 says it does
      # not serve this package: both are actionable, and both are the scenario's
      # to act on, since only it knows whether asking again is worth it.
      {errcode, _rsp, _trans_pid, _dialog_pid} when errcode in 400..699 ->
        scenario_failure("SUBSCRIBE refused with #{errcode}")
    after
      5_000 ->
        scenario_failure("no answer to the SUBSCRIBE")
    end
  end

  # ---------------------------------------------------------------------------
  # Watching. Each NOTIFY is one state of the presentity; the transition label is
  # where it is displayed, so it shows up in `--monitor` and in the sequence
  # diagram rather than on a terminal the monitor owns.
  state watching do
    on_events do
      {:NOTIFY, req, _trans_pid, _dialog_pid} ->
        appdata_set(:notifies, appdata_get(:notifies) + 1)
        state_label = label("NOTIFY", notified_document(req))

        if appdata_get(:notifies) >= @max_notifies do
          goto(unsubscribing, state_label)
        else
          stay(state_label)
        end

      # The answer to the refresh the dialog sent on our behalf. Re-arms the next
      # one on the lifetime this 200 granted.
      {200, rsp, trans_pid, _dialog_pid} ->
        process_sip_reply(rsp, trans_pid)
        stay("refresh accepted")

      # A refresh answered 481 is a notifier that has restarted and no longer
      # knows this subscription. It is correct, and re-subscribing is a fresh
      # send_SUBSCRIBE — a new dialog, since the old one is gone.
      {481, _rsp, _trans_pid, _dialog_pid} ->
        goto(subscribing, "481: subscription lost, subscribing again")

      {:subscription_terminated, _ref, reason} ->
        scenario_success("subscription ended: #{reason}")
    after
      (@expires + 30) * 1000 ->
        scenario_failure("nothing happened while watching")
    end
  end

  # ---------------------------------------------------------------------------
  # Stop watching: the same SUBSCRIBE with Expires: 0. The 200 is not the end —
  # the notifier still owes us one last NOTIFY saying the subscription is
  # terminated, and that is what ends the run.
  state unsubscribing do
    send_unSUBSCRIBE()

    on_events do
      {100, _rsp, _trans_pid, _dialog_pid} ->
        stay("100 Trying")

      {:NOTIFY, req, _trans_pid, _dialog_pid} ->
        stay(label("final NOTIFY", notified_document(req)))

      {200, _rsp, _trans_pid, _dialog_pid} ->
        stay("un-SUBSCRIBE accepted")

      {:subscription_terminated, _ref, reason} ->
        scenario_success("un-subscribed: #{reason}")

      {errcode, _rsp, _trans_pid, _dialog_pid} when errcode in 400..699 ->
        scenario_failure("un-SUBSCRIBE refused with #{errcode}")
    after
      5_000 ->
        scenario_failure("the subscription never ended")
    end
  end

  # The transition label for one received state — formatting, and nothing else.
  # The reading is the framework's: `notified_document/1` parses the body with
  # the very event package the notifier wrote it with, so no scenario re-derives
  # a content type or an XML parser (CLAUDE.md, *Writing a scenario*).
  defp label(prefix, {:ok, %SIP.Presence.Doc{} = doc}) do
    "#{prefix}: " <>
      Enum.join([SIP.Presence.Doc.status(doc) | SIP.Presence.Doc.contacts(doc)], " ")
  end

  # The final NOTIFY states a termination in its Subscription-State and carries
  # no document at all.
  defp label(prefix, {:error, :no_body}), do: "#{prefix}: no state"
  defp label(prefix, {:error, reason}), do: "#{prefix}: unreadable (#{inspect(reason)})"
end
