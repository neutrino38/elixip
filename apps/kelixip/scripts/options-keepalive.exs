# Reference kelixip OPTIONS script: the liveness ping of an upstream proxy or load
# balancer, served by a script.
#
# Bound by the `keepalive = true` rule of [[domain.options]], it answers an OPTIONS
# whose Request-URI names no user (`sip:example.com`). The drain is not its
# business: a draining node answers 503 before any script is asked (Kelix.Options),
# so leaving the upstream rotation never depends on this script loading.
#
# The answer is the core's own `Allow`, so the node says one thing whoever answers.
# One ping, one instance: it ends once it has answered, because an instance holds
# a `max_calls` slot for as long as it lives.
defmodule Kelix.OptionsKeepalive do
  use SIP.Scenario

  uas(:options)

  state initial_state do
    goto(wait_options)
  end

  # The {:OPTIONS, …} that created this instance is already in our mailbox.
  state wait_options do
    on_events do
      {:OPTIONS, req, _trans, _dlg} ->
        b2bua_reply(req, 200, "OK", [{"Allow", Kelix.Options.allow()}])
        scenario_success("keepalive answered")

      {:dialog_terminated, _dlg, _reason} ->
        scenario_aborted("sender vanished before the OPTIONS")
    after
      5_000 -> scenario_failure("no OPTIONS received")
    end
  end

  on_shutdown do
    scenario_aborted("stopped")
  end
end
