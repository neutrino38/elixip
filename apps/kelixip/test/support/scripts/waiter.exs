# A valid registrar script that stays alive (waits for shutdown) so tests can
# observe quota / active instances. Touches no dialog, so a fake dialog pid is ok.
defmodule KelixTest.Waiter do
  use SIP.Scenario
  uas :register

  state initial_state do
    on_events do
      {:scenario_ctl, :shutdown, _reason} -> scenario_aborted("shutdown")
    after
      30_000 -> scenario_success("timeout")
    end
  end

  on_shutdown do
    scenario_aborted("shutdown")
  end
end
