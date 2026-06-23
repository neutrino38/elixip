defmodule SIP.Test.SubFsm do
  use ExUnit.Case

  # ── Scenario fixtures ───────────────────────────────────────────────────────

  # A child that announces itself to its parent, then waits for a go-ahead.
  defmodule Child do
    use SIP.Scenario

    config(username: "bob", domain: "example.com")

    state initial_state do
      notify_parent(:ready)
      goto(waiting)
    end

    state waiting do
      on_events do
        {:scenario_msg, :parent, :go} -> scenario_success("went")
      after
        2_000 -> scenario_failure("no go received")
      end
    end
  end

  # A parent that spawns the child, waits for its :ready, sends :go, and waits for
  # the child's successful exit.
  defmodule Parent do
    use SIP.Scenario

    config(username: "alice", domain: "example.com")

    state initial_state do
      sub_fsm(Child, as: :callee)
      goto(waiting)
    end

    state waiting do
      on_events do
        {:scenario_msg, :callee, :ready} ->
          notify(:callee, :go)
          goto(finishing)
      after
        2_000 -> scenario_failure("child never became ready")
      end
    end

    state finishing do
      on_events do
        {:scenario_exit, :callee, :success, _reason} -> scenario_success("child done")
      after
        2_000 -> scenario_failure("child never exited")
      end
    end
  end

  # Calls notify_parent with no parent set: must be a silent no-op so the same
  # scenario also runs standalone.
  defmodule Orphan do
    use SIP.Scenario

    config(username: "solo", domain: "example.com")

    state initial_state do
      notify_parent(:nobody_listening)
      scenario_success("standalone ok")
    end
  end

  # Sits in an on_events forever (until a shutdown request). No on_shutdown block,
  # so the default cooperative termination (:aborted) applies.
  defmodule WaitsForever do
    use SIP.Scenario

    config(username: "w", domain: "example.com")

    state initial_state do
      on_events do
        {:never, _x} -> scenario_success("unreachable")
      after
        60_000 -> scenario_failure("timeout")
      end
    end
  end

  # Same, but with a custom on_shutdown handler.
  defmodule CustomShutdown do
    use SIP.Scenario

    config(username: "c", domain: "example.com")

    state initial_state do
      on_events do
        {:never, _x} -> scenario_success("unreachable")
      after
        60_000 -> scenario_failure("timeout")
      end
    end

    on_shutdown do
      scenario_aborted("custom wind-down")
    end
  end

  # ── Tests ───────────────────────────────────────────────────────────────────

  test "parent and child exchange messages and the child's exit propagates" do
    assert Parent.run(false) == :ok
  end

  test "notify_parent is a no-op when the scenario has no parent" do
    assert Orphan.run(false) == :ok
  end

  test "a cooperative shutdown request aborts a waiting child by default" do
    parent = self()

    {pid, ref} =
      spawn_monitor(fn ->
        result =
          SIP.Scenario.Runner.run_instance(WaitsForever, parent_pid: parent, self_name: :child)

        send(parent, {:result, result})
      end)

    # Let it reach the on_events before asking it to stop.
    Process.sleep(50)
    send(pid, {:scenario_ctl, :shutdown, :test})

    assert_receive {:scenario_exit, :child, :aborted, "shutdown"}, 1_000
    assert_receive {:result, {:aborted, "shutdown"}}, 1_000
    assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 1_000
  end

  test "on_shutdown runs a custom wind-down instead of the default" do
    parent = self()

    pid =
      spawn(fn ->
        result =
          SIP.Scenario.Runner.run_instance(CustomShutdown, parent_pid: parent, self_name: :child)

        send(parent, {:result, result})
      end)

    Process.sleep(50)
    send(pid, {:scenario_ctl, :shutdown, :test})

    assert_receive {:scenario_exit, :child, :aborted, "custom wind-down"}, 1_000
    assert_receive {:result, {:aborted, "custom wind-down"}}, 1_000
  end

  test "sub_fsm requires an :as name" do
    assert_raise KeyError, fn ->
      SIP.Scenario.Runner.spawn_child(%SIP.Context{}, Child, [], self())
    end
  end
end
