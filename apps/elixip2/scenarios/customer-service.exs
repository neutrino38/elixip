# Reference B2BUA scenario: a customer service hunting a list of numbers.
#
# Alice calls a short number; behind it there is no registered device but an
# ordered list of numbers, tried serially until one picks up. Run it with:
#     elixipp --listen udp:5060 apps/elixip2/scenarios/customer-service.exs
#
# Commented use case in B2BUA.md, "Scenario customer-service.exs". The states
# from `wait_ack` on are the ones every B2BUA scenario shares — read
# b2bua_basic.exs for those; what is specific to a hunt is `wait_invite` and
# `proceeding`.
defmodule B2BUA.CustomerService do
  use SIP.Scenario

  uas(:invite)

  config(
    domains: :any,
    # tried in this order; the first one that answers takes the call
    agents: [
      "sip:+33140000001@trunk.example.com",
      "sip:+33140000002@trunk.example.com",
      "sip:+33612345678@trunk.example.com"
    ],
    trunk: "sip:trunk.example.com:5060"
  )

  state initial_state do
    goto(wait_invite)
  end

  state wait_invite do
    on_events do
      {:INVITE, req, _trans, _dlg} ->
        b2bua_reply(req, 100, "Trying")
        # A caller on a queue-like service expects to hear something.
        b2bua_reply(req, 180, "Ringing")

        peer = %SIP.B2bua.Peer{
          uris: ctx_get(:agents),
          fork: :serial,
          # 486 Busy and 480 Unavailable mean "try the next one"; 603 Decline is
          # this service refusing the call, and stops the hunt.
          retry_on: [408, 480, 486, 500..599],
          # the trunk is the next hop for every one of them
          outbound_proxy: ctx_get(:trunk),
          notify_progress: true
        }

        b2bua_forward(req, peer, false)

        if ctx_get(:lasterr) == :ok do
          goto(proceeding, "hunting the agents")
        else
          b2bua_reply(req, 500, "Server Internal Error")
          scenario_failure("cannot place the call: #{inspect(ctx_get(:lasterr))}")
        end
    after
      60_000 -> scenario_failure("no INVITE received")
    end
  end

  state proceeding do
    on_events do
      # notify_progress: true — the hunt says which number it is on. Useful to
      # log, to meter, or to feed a supervision screen.
      {:outbound, {:serial_attempting, uri, _at}} ->
        stay("calling #{uri}")

      {:outbound, {:serial_not_reachable, uri, code, _at}} ->
        stay("#{uri} did not take it (#{inspect(code)})")

      {:outbound, {:serial_exhausted, _at}} ->
        stay("no agent left to try")

      # 18x from an agent: relayed, but Alice already heard our 180. Relaying a
      # 183 with SDP would pin the call to that agent, which the hunt has not
      # decided yet.
      {:outbound, {code, resp, _trans, _dlg}} when code in 101..199 ->
        b2bua_forward_reply(resp)
        stay("provisional #{code}")

      {:outbound, {200, resp, _trans, _dlg}} ->
        b2bua_forward_reply(resp)
        goto(wait_ack, "an agent took the call")

      {:outbound, {code, resp, _trans, _dlg}} when code >= 300 ->
        b2bua_forward_reply(resp)

        if b2bua_hunting?() do
          stay("#{code}, next agent")
        else
          # The list is exhausted: this final IS the answer of the call.
          scenario_success("no agent available (#{code})")
        end

      # A CANCEL asks, it does not decide (RFC 3261 §16.7): the agent being rung
      # may still pick up, and an abandoned call is not the same event as one an
      # agent answered a moment too late.
      {:CANCEL, req, _trans, _dlg} ->
        b2bua_cancel_forward()
        b2bua_forward(req)
        goto(cancelling, "caller cancelled")

      {:BYE, req, _trans, _dlg} ->
        b2bua_cancel_forward()
        b2bua_reply(req, 200, "OK")
        scenario_success("caller hung up while we were hunting")
    after
      # The whole hunt, not one agent: with a static list there is no per-target
      # ring timeout — the hunt moves on when a target REFUSES, not when it
      # merely keeps ringing. Ringing each agent for 15 s needs a provider peer.
      120_000 ->
        b2bua_cancel_forward()
        b2bua_reply(last_uas_req(), 408, "Request Timeout")
        scenario_failure("nobody answered")
    end
  end

  # From here on, nothing is specific to a hunt: these are the states every
  # B2BUA scenario shares, and they are the ones b2bua_basic.exs comments.

  # The CANCEL has gone to the agent being rung; its transaction is not over
  # until a final response says so (RFC 3261 §16.7). `SIP.DialogImpl` handles the
  # race on its own — no script may get it wrong — and this state makes it
  # VISIBLE, which for a queue is the point: an agent who answered an abandoned
  # call is not an abandoned call.
  state cancelling do
    on_events do
      {:outbound, {487, _resp, _trans, _dlg}} ->
        scenario_aborted("caller abandoned, agent confirmed")

      {:outbound, {200, _resp, _trans, _dlg}} ->
        b2bua_send_BYE()
        scenario_success("agent answered after the caller abandoned; hung up")

      {:outbound, {code, _resp, _trans, _dlg}} when code in 100..199 ->
        stay("provisional #{code} after cancel")

      {:outbound, {code, _resp, _trans, _dlg}} when code >= 300 ->
        scenario_aborted("caller abandoned, agent answered #{code}")

      {:outbound, {:dialog_terminated, _dlg, _reason}} ->
        scenario_aborted("caller abandoned, agent leg gone")

      {:dialog_terminated, _dlg, _reason} ->
        scenario_aborted("caller abandoned")
    after
      32_000 -> scenario_aborted("caller abandoned, agent never concluded")
    end
  end

  state wait_ack do
    on_events do
      {:ACK, req, _trans, _dlg} ->
        b2bua_forward(req)
        goto(connected, "ACK relayed")
    after
      32_000 ->
        b2bua_send_BYE()
        scenario_failure("no ACK from the caller")
    end
  end

  state connected do
    on_events do
      {:BYE, req, _trans, _dlg} ->
        b2bua_forward(req)
        b2bua_reply(req, 200, "OK")
        goto(wait_far_bye_ok, "caller hung up")

      {:outbound, {:BYE, req, _trans, _dlg}} ->
        b2bua_forward(req)
        b2bua_reply(req, 200, "OK")
        goto(wait_far_bye_ok, "agent hung up")

      {:dialog_terminated, _dlg, reason} ->
        scenario_success("inbound leg ended: #{inspect(reason)}")

      {:outbound, {:dialog_terminated, _dlg, reason}} ->
        scenario_success("outbound leg ended: #{inspect(reason)}")

      {:ACK, req, _trans, _dlg} ->
        b2bua_forward(req)
        stay("ACK relayed (caller -> agent)")

      {:outbound, {:ACK, req, _trans, _dlg}} ->
        b2bua_forward(req)
        stay("ACK relayed (agent -> caller)")

      {:outbound, {m, req, _trans, _dlg}} when is_atom(m) ->
        b2bua_forward(req)
        stay("relayed #{m} (agent -> caller)")

      {:outbound, {code, resp, _trans, _dlg}} when is_integer(code) ->
        b2bua_forward_reply(resp)
        stay("relayed #{code} (agent -> caller)")

      {m, req, _trans, _dlg} when is_atom(m) ->
        b2bua_forward(req)
        stay("relayed #{m} (caller -> agent)")

      {code, resp, _trans, _dlg} when is_integer(code) ->
        b2bua_forward_reply(resp)
        stay("relayed #{code} (caller -> agent)")
    after
      14_400_000 -> scenario_failure("maximum call duration reached")
    end
  end

  state wait_far_bye_ok do
    on_events do
      {:outbound, {200, _resp, _trans, _dlg}} -> scenario_success("call relayed and ended")
      {200, _resp, _trans, _dlg} -> scenario_success("call relayed and ended")
      {:dialog_terminated, _dlg, _reason} -> scenario_success("call ended")
      {:outbound, {:dialog_terminated, _dlg, _reason}} -> scenario_success("call ended")
    after
      5_000 -> scenario_success("BYE unanswered, closing anyway")
    end
  end

  on_shutdown do
    scenario_aborted("controller asked to stop")
  end
end
