# Fixture: the sub-scenario that sibling_parent.exs pulls in with `sub_fsm`. It sits
# next to its parent and NOT in the directory the test suite runs from, which is what
# makes the resolution rule (relative to the declaring file, include-style) observable.
defmodule SubFsmFixture.SiblingChild do
  use SIP.Scenario

  config(username: "child", domain: "example.com")

  state initial_state do
    notify_parent(:child_ran)
    scenario_success("done")
  end
end
