defmodule SIP.Test.SpawnFsm do
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
        {:parent_msg, :go} -> scenario_success("went")
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
      spawn_fsm(Child, as: :callee)
      goto(waiting)
    end

    state waiting do
      on_events do
        {:child_msg, :callee, :ready} ->
          notify(:callee, :go)
          goto(finishing)
      after
        2_000 -> scenario_failure("child never became ready")
      end
    end

    state finishing do
      on_events do
        {:child_exit, :callee, :success, _reason} -> scenario_success("child done")
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

  # A UAS call scenario child: waits for the inbound INVITE routed to it by the
  # call dispatcher installed by spawn_fsm.
  defmodule UasChild do
    use SIP.Scenario

    uas(:invite)
    config(domain: "example.com")

    state initial_state do
      on_events do
        {:INVITE, _req, _t, _dlg} -> scenario_success("got INVITE")
      after
        5_000 -> scenario_failure("no INVITE")
      end
    end
  end

  # ── Tests ───────────────────────────────────────────────────────────────────

  test "parent and child exchange messages and the child's exit propagates" do
    assert Parent.run(false) == :ok
  end

  # `spawn_fsm "child.exs"` names a file next to the scenario that declares it —
  # include semantics, so a scenario is self-contained wherever it is run from.
  # Resolving against the current directory instead is what made
  # scenarios/uac_register_and_uas_invite.exs die with a bare "exception!" for anyone
  # who did not happen to be standing in apps/elixip2. The fixture pair lives in
  # test/support/scenarios/, which is NOT the suite's working directory: a
  # cwd-relative resolution cannot find the child.
  test "a spawn_fsm path is resolved next to the file that declares it" do
    parent = SIP.Scenario.Loader.load_file!("test/support/scenarios/sibling_parent.exs")
    assert SIP.Scenario.Runner.run_instance(parent) == :ok
  end

  test "a sub-scenario that exists nowhere is reported with both paths tried" do
    defmodule Missing do
      use SIP.Scenario

      config(username: "m", domain: "example.com")

      state initial_state do
        spawn_fsm("no_such_child.exs", as: :ghost)
        goto(loop)
      end
    end

    # The state body rescues the raise and fails the scenario; the message itself is
    # in the log (Exception.format), which is why the reason is spelled out there.
    assert {:error, _} = SIP.Scenario.Runner.run_instance(Missing)
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

    assert_receive {:child_exit, :child, :aborted, "shutdown"}, 1_000
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

    assert_receive {:child_exit, :child, :aborted, "custom wind-down"}, 1_000
    assert_receive {:result, {:aborted, "custom wind-down"}}, 1_000
  end

  # The 1.4 inter-FSM event shapes cannot be aliased the way `sub_fsm` was: a
  # scenario still matching one would never be woken, and would wait on its
  # `after` without a word. The compile-time warning is that safety net, so it
  # gets a test of its own.
  describe "deprecated inter-FSM event shapes" do
    defp compile_warnings(source) do
      ExUnit.CaptureIO.capture_io(:stderr, fn -> Code.compile_string(source) end)
    end

    defp scenario_matching(pattern) do
      """
      defmodule :"#{:erlang.unique_integer([:positive])}" do
        use SIP.Scenario
        state initial_state do
          on_events do
            #{pattern} -> scenario_success("ok")
          end
        end
      end
      """
    end

    test "matching {:scenario_msg, …} warns and names both replacements" do
      warnings = compile_warnings(scenario_matching("{:scenario_msg, :parent, :go}"))

      assert warnings =~ "{:scenario_msg, …} is no longer sent"
      assert warnings =~ "{:parent_msg, payload}"
      assert warnings =~ "{:child_msg, name, payload}"
    end

    test "matching {:scenario_exit, …} warns, guard or no guard" do
      assert compile_warnings(scenario_matching("{:scenario_exit, :callee, o, _r}")) =~
               "{:child_exit, name, outcome, reason}"

      assert compile_warnings(
               scenario_matching("{:scenario_exit, :callee, o, _r} when o == :success")
             ) =~ "{:child_exit, name, outcome, reason}"
    end

    test "the current shapes warn about nothing" do
      for pattern <- [
            "{:parent_msg, :go}",
            "{:child_msg, :callee, :ready}",
            "{:child_exit, n, o, r}"
          ] do
        refute compile_warnings(scenario_matching(pattern)) =~ "no longer sent"
      end
    end
  end

  test "spawn_fsm requires an :as name" do
    assert_raise KeyError, fn ->
      SIP.Scenario.Runner.spawn_child(%SIP.Context{}, Child, [], self())
    end
  end

  describe "spawn_fsm of a :uas_invite scenario" do
    # The ConfigRegistry is a global Agent shared across test modules: save and
    # restore the call processing module so these tests neither depend on nor
    # disturb the others.
    setup do
      {:ok, _} = SIP.Session.ConfigRegistry.start()
      prev = SIP.Session.ConfigRegistry.get_call_processing_module()
      :ok = SIP.Session.ConfigRegistry.set_call_processing_module(nil)
      on_exit(fn -> SIP.Session.ConfigRegistry.set_call_processing_module(prev) end)
      :ok
    end

    test "installs the call dispatcher and routes one INVITE to the waiting child" do
      ctx = SIP.Scenario.Runner.spawn_child(%SIP.Context{}, UasChild, [as: :callee], self())
      %SIP.Scenario.Child{pid: child_pid} = ctx.appdata[:__children__][:callee]

      assert SIP.Session.ConfigRegistry.get_call_processing_module() ==
               SIP.Scenario.CallDispatcher

      # The first INVITE is bound to the waiting child…
      assert SIP.Scenario.CallDispatcher.on_new_call(self(), %{method: :INVITE}, self()) ==
               {:accept, child_pid}

      # …and with no child left the next one is rejected 486.
      assert SIP.Scenario.CallDispatcher.on_new_call(self(), %{method: :INVITE}, self()) ==
               {:reject, 486, "Busy Here"}

      # Deliver the INVITE (as the dialog layer would after :accept) so the
      # child runs to completion.
      send(child_pid, {:INVITE, %{method: :INVITE, body: []}, self(), self()})
      assert_receive {:child_exit, :callee, :success, _}, 1_000
    end

    test "does not override an already configured call processing module" do
      :ok = SIP.Session.ConfigRegistry.set_call_processing_module(SomeOtherCallServer)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          ctx = SIP.Scenario.Runner.spawn_child(%SIP.Context{}, UasChild, [as: :callee], self())
          %SIP.Scenario.Child{pid: child_pid} = ctx.appdata[:__children__][:callee]

          # Wind the child down so it does not sit in its 5s INVITE wait.
          send(child_pid, {:scenario_ctl, :shutdown, :test})
          assert_receive {:child_exit, :callee, :aborted, _}, 1_000
        end)

      assert log =~ "already configured"
      assert SIP.Session.ConfigRegistry.get_call_processing_module() == SomeOtherCallServer
    end

    test "a dead waiting child is purged from the dispatcher queue" do
      ctx = SIP.Scenario.Runner.spawn_child(%SIP.Context{}, UasChild, [as: :callee], self())
      %SIP.Scenario.Child{pid: child_pid, ref: ref} = ctx.appdata[:__children__][:callee]

      Process.exit(child_pid, :kill)
      assert_receive {:DOWN, ^ref, :process, ^child_pid, :killed}, 1_000
      # The dispatcher's own :DOWN is processed before our next call (same mailbox).
      _ = :sys.get_state(SIP.Scenario.CallDispatcher)

      assert SIP.Scenario.CallDispatcher.on_new_call(self(), %{method: :INVITE}, self()) ==
               {:reject, 486, "Busy Here"}
    end
  end
end
