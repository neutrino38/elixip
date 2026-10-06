# Reference kelixip chat script: Alice writes to Bob — page mode (RFC 3428),
# after proving she is Alice.
#
# One instance per CONVERSATION, not per MESSAGE (chat-basic-plan, C3b/C3c):
# the router keys it on the sender, the recipient and the flow the first MESSAGE
# came over, and routes every later MESSAGE of that key here. So the first
# MESSAGE is challenged, and the ones that follow on the same flow are not —
# the router's decision is the trust. A MESSAGE sent inside a dialog is not
# challenged either (`Kelix.Mod.AuthDb.challengeable?/1`): the dialog was
# authenticated when it was created. The conversation ends when it falls
# silent (`idle_timeout` of its [[domain.chat]] rule) or when its connection
# drops.
#
# Each MESSAGE is relayed to every registered device of the recipient at once
# (`SBB.Page`), and the sender gets one answer:
#   * a device took it              → its code (200, or 202 when every device
#                                     that answered said 202 itself);
#   * a device refused it           → the refusal (603 blocked, 415 type…),
#                                     never stored;
#   * nobody took it                → stored in the Silo and 202, or 480 for a
#                                     typing indicator, which is worth nothing
#                                     later; 503 when the Silo does not answer;
#   * the recipient does not exist  → 404, and nothing is stored: filling a
#                                     node's storage must cost an attacker
#                                     something.
#
# What a MESSAGE says never appears in the journal nor in the logs
# (chat-basic-plan, C1b): the script handles requests, not their text.
defmodule Kelix.P2PChat do
  use SIP.Scenario
  use SBB.Page
  use Kelix.Mod.AuthDb

  uas(:message)

  # Refuse to load when a module is missing, instead of failing on the first
  # MESSAGE: the location service, the authentication backend, the store.
  config(uses_modules: [:registrar, :auth_db, :silo])

  # The {:MESSAGE, …} that created this instance is already in our mailbox.
  state initial_state do
    on_events do
      {:MESSAGE, _req, _trans, _dlg} -> goto(gate, "MESSAGE received")
    after
      5_000 -> scenario_failure("no MESSAGE received")
    end
  end

  # The first MESSAGE of the conversation is challenged — unless it was sent
  # inside a dialog, which was authenticated when it was created.
  state gate do
    if Kelix.Mod.AuthDb.challengeable?(last_uas_req()),
      do: goto(authenticate_sender, "challengeable"),
      else: goto(check_recipient, "in-dialog, not challenged")
  end

  state authenticate_sender do
    AuthDb.SBB.authenticate()

    on_events do
      {:auth, :authenticated, %{user: user}} ->
        goto(check_recipient, "MESSAGE authenticated as #{user}")

      {:auth, :caller_gone, %{reason: reason}} ->
        scenario_success("sender gave up on the challenge: #{inspect(reason)}")

      {:auth, :timeout, _} ->
        scenario_success("no credentials came back")

      {:auth, :refused, %{attempts: attempts}} ->
        scenario_success("gave up on this sender after #{attempts} refused attempts")

      {:auth, :cancelled, _} ->
        scenario_success("sender cancelled")
    end
  end

  # A recipient nobody provisioned is a 404, before anything is relayed or kept.
  state check_recipient do
    req = last_uas_req()

    if Kelix.Mod.AuthDb.subscriber?(SIP.Msg.Ops.target_aor(req), ctx_get(:domain)) do
      goto(relay, "recipient exists")
    else
      reply_message(404)
      goto(conversing, "404, no such user")
    end
  end

  # Every device at once. With none registered, the fan-out has no device to
  # page and answers :unreachable at once — the Silo's case.
  state relay do
    req = last_uas_req()

    case Kelix.Mod.Registrar.targets(ctx_get(:domain), req) do
      {:ok, peer} ->
        page(args: %{peer: peer})

        on_events do
          {:page, :delivered, %{code: code}} ->
            reply_message(code)
            goto(conversing, "#{code} from a device")

          {:page, :refused, %{code: code}} ->
            reply_message(code)
            goto(conversing, "#{code}, refused by a device")

          {:page, :unreachable, %{served: served}} ->
            appdata_set(:served, served)
            goto(store, "no device took it")
        end

      :notfound ->
        appdata_set(:served, [])
        goto(store, "nobody registered")

      :no_aor ->
        reply_message(400)
        goto(conversing, "400, no recipient")

      :unavailable ->
        reply_message(500)
        goto(conversing, "500, location service down")
    end
  end

  # Nobody took it: keep it for the recipient's next REGISTER. Not a typing
  # indicator: "Bob is typing" is worth nothing once Bob has stopped.
  state store do
    req = last_uas_req()

    if SIP.Msg.Ops.message_kind(req) == :is_composing do
      reply_message(480)
      goto(conversing, "480, typing indicator not stored")
    else
      case Kelix.Mod.Silo.store(sip_ctx, req, served: appdata_get(:served)) do
        {:stored, %{id: id}} ->
          reply_message(202)
          goto(conversing, "202, stored as #{id}")

        {:error, :quota} ->
          reply_message(486)
          goto(conversing, "486, the recipient's storage is full")

        {:error, :expired} ->
          reply_message(480)
          goto(conversing, "480, the sender gave it no lifetime")

        {:error, :no_aor} ->
          reply_message(400)
          goto(conversing, "400, no recipient")

        {:error, :down} ->
          reply_message(503)
          goto(conversing, "503, storage down")
      end
    end
  end

  # The next MESSAGE of this conversation: same sender, same recipient, same
  # flow — the router's word for "already authenticated". It ends when it falls
  # silent or its connection drops (the clauses the router's events inject).
  state conversing do
    on_events do
      {:MESSAGE, _req, _trans, _dlg} -> goto(check_recipient, "next MESSAGE")
    end
  end

  on_shutdown do
    scenario_aborted("chat stopped gracefully")
  end
end
