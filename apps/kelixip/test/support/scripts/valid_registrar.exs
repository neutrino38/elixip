# Minimal VALID kelixip registrar script: it is a scenario (uas :register) AND
# handles cooperative shutdown explicitly (on_shutdown block) — passes §5.3.
defmodule KelixTest.ValidRegistrar do
  use SIP.Scenario
  uas :register

  state initial_state do
    scenario_success("ok")
  end

  on_shutdown do
    scenario_aborted("shutdown")
  end
end
