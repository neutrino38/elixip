# Fixture: a scenario that pulls in a sub-scenario by bare file name. The file lives
# next to this one, and nowhere near the directory the suite runs from — so this only
# loads if `sub_fsm` resolves the path against the declaring file (include semantics).
defmodule SubFsmFixture.SiblingParent do
  use SIP.Scenario

  config(username: "parent", domain: "example.com")

  state initial_state do
    sub_fsm("sibling_child.exs", as: :child)
    goto(waiting)
  end

  state waiting do
    on_events do
      {:scenario_msg, :child, :child_ran} -> scenario_success("child ran")
    after
      2_000 -> scenario_failure("child never reported")
    end
  end
end
