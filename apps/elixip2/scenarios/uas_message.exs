# Reference UAS (server-side) page-mode scenario — answering MESSAGE (RFC 3428).
# Run it with:
#     elixipp --listen udp:5060 apps/elixip2/scenarios/uas_message.exs
#
# elixipp loads this file, sees it is a `:uas_message` scenario (set by the
# `uas :message` annotation), starts the configured listeners and registers
# Elixip.ScenarioUAS as the chat processing module. One instance of this
# scenario is spawned per inbound out-of-dialog MESSAGE and receives
# `{:MESSAGE, req, transaction_id, dialog_pid}` in its mailbox.
#
# It answers and forgets. What a MESSAGE says is never logged (GDPR,
# docs/design/chat-basic-plan.md, C1b): the instance reports the KIND of message
# it answered — text, typing indicator, delivery notification — not its text.
#
# To carry a message on instead of answering it only, a state sends a page of
# its own: `send_page(target, last_uas_req())` rebuilds the one received and
# addresses it to `target`, and the answer comes back as `{:page, …}`.
defmodule UAS.MessageExample do
  use SIP.Scenario

  # Marks the scenario type as :uas_message so elixipp runs it in server mode.
  uas(:message)

  # The {:MESSAGE, …} message is already queued in our mailbox by the dialog
  # layer; jump straight to the waiting state.
  state initial_state do
    goto(next)
  end

  state wait_message do
    on_events do
      {:MESSAGE, req, _trans_pid, _dialog_pid} ->
        reply_message(200)
        scenario_success("answered #{SIP.Msg.Ops.message_kind(req)}")
    after
      5_000 -> scenario_failure("no MESSAGE received")
    end
  end
end
