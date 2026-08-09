defmodule SIP.Test.ScenarioResilience do
  @moduledoc """
  The scenario engine's safety net — design docs/design/b2bua_module.md §14,
  decision R2.

  Every SIP primitive a state can call is a `GenServer.call` toward a dialog. A
  dialog that dies between the liveness check and the call makes that an EXIT in
  the scenario process, and the `state` macro rescued exceptions only — so the
  scenario process died where it stood. `Runner.finalize/4` never ran: no B2BUA
  leg torn down, no media released, and, for a relayed INVITE, a caller left
  waiting for a final response nobody would ever send.

  What is asserted here is not that the exit is *survived* — a state that cannot
  talk to its dialog has nothing left to do — but that the scenario **ends**,
  because ending is what runs the teardown.
  """
  use ExUnit.Case

  setup_all do
    :ok = SIP.Scenario.Runner.bootstrap_stack()
    :ok
  end

  defmodule Exiting do
    use SIP.Scenario

    config(username: "resilience", domain: "example.com")

    state initial_state do
      # A dialog that is already gone: what a leg whose transport just died looks
      # like from inside a state. Nothing here is contrived — `SIP.Dialog.reply/5`
      # and `new_request/2` are GenServer.calls on exactly such a pid.
      dead = spawn(fn -> :ok end)
      ref = Process.monitor(dead)
      receive do: ({:DOWN, ^ref, :process, _, _} -> :ok)

      GenServer.call(dead, :getdialogid)

      scenario_success("unreachable")
    end

    # Runner.finalize/4 calls this last. Since run_instance/2 runs the FSM in the
    # CALLING process, `self()` here is the test process.
    def cleanup(_ctx), do: send(self(), :teardown_ran)
  end

  test "an exit inside a state ends the scenario as a failure instead of killing it" do
    assert SIP.Scenario.Runner.run_instance(Exiting) == {:error, "exit!"}
  end

  test "…and the teardown runs, which is the whole reason to catch it" do
    SIP.Scenario.Runner.run_instance(Exiting)
    assert_received :teardown_ran
  end

  defmodule Raising do
    use SIP.Scenario

    config(username: "resilience", domain: "example.com")

    state initial_state do
      raise "boom"
      scenario_success("unreachable")
    end
  end

  # The pre-existing exception path, pinned here next to its new sibling so the
  # two stay told apart: a scenario that raises still reports "exception!", not
  # "exit!".
  test "an exception is still reported as one" do
    assert SIP.Scenario.Runner.run_instance(Raising) == {:error, "exception!"}
  end
end
