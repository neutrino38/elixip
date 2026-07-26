# A valid scenario but WITHOUT an on_shutdown block — must be refused by the
# load-time contract (§5.3): kelixip forbids the abrupt default shutdown.
defmodule KelixTest.NoShutdown do
  use SIP.Scenario
  uas :register

  state initial_state do
    scenario_success("ok")
  end
end
