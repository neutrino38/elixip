# The waiter, under a module of its own: domains_write_test serves it by NAME from
# script_dir, and the registry refuses a second script defining KelixTest.Waiter.
defmodule KelixTest.DomainWaiter do
  use SIP.Scenario
  uas(:register)

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
