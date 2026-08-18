defmodule SIP.Test.SbbFsm do
  use ExUnit.Case

  # Phase 1 of docs/design/service-building-block-design.md: the mechanism alone,
  # on toy blocks. No SIP here — a block is an FSM run by the calling process on
  # the caller's context, and that is what these assert.

  # ── Toy blocks ──────────────────────────────────────────────────────────────

  # Returns straight away with what it was given at the call site.
  defmodule Echo do
    use SIP.SBB

    state initial_state do
      sbb_return({:echo, sbb_data_get(:payload)})
    end
  end

  # Walks two states of its own before returning, so `goto` inside a block is
  # exercised — including `goto next`, which needs the block's own state list.
  defmodule TwoSteps do
    use SIP.SBB

    state initial_state do
      sbb_data_set(:steps, 1)
      goto(second)
    end

    state second do
      sbb_data_set(:steps, sbb_data_get(:steps) + 1)
      sbb_return({:walked, sbb_data_get(:steps)})
    end
  end

  # Consumes events until it has seen enough, using `stay` to re-enter its wait.
  defmodule CountTo do
    use SIP.SBB

    state initial_state do
      sbb_data_set(:seen, 0)
      goto(counting)
    end

    state counting do
      on_events do
        {:tick, _n} ->
          seen = sbb_data_get(:seen) + 1
          sbb_data_set(:seen, seen)

          if seen >= sbb_data_get(:target),
            do: sbb_return({:counted, seen}),
            else: stay("tick #{seen}")
      end
    end
  end

  # Ends the whole scenario from inside a block (S8).
  defmodule Fatal do
    use SIP.SBB

    state initial_state do
      scenario_failure("block decided to stop everything")
    end
  end

  # Calls another block, to check that composition is a plain call stack and that
  # a terminal thrown two levels down still reaches the root.
  defmodule Nesting do
    use SIP.SBB

    state initial_state do
      sbb_fsm(Fatal)
      sbb_return({:nesting, :unreachable})
    end
  end

  defmodule NestingEcho do
    use SIP.SBB

    state initial_state do
      sbb_fsm(Echo, args: %{payload: :from_inner})

      on_events do
        {:echo, payload} -> sbb_return({:outer, payload})
      end
    end
  end

  # Never returns on its own: only its deadline can end it.
  defmodule Hangs do
    use SIP.SBB

    @sbb_timeout 60
    @sbb_timeout_event {:hangs, :timed_out}

    state initial_state do
      on_events do
        {:never, _} -> sbb_return({:hangs, :impossible})
      end
    end
  end

  # ── Hosts ───────────────────────────────────────────────────────────────────

  defmodule HostEcho do
    use SIP.Scenario

    state initial_state do
      sbb_fsm(Echo, args: %{payload: :hello})

      on_events do
        {:echo, payload} -> scenario_success("echoed #{inspect(payload)}")
      after
        1_000 -> scenario_failure("block never returned")
      end
    end
  end

  defmodule HostTwoSteps do
    use SIP.Scenario

    state initial_state do
      sbb_fsm(TwoSteps)

      on_events do
        {:walked, n} -> scenario_success("walked #{n}")
      after
        1_000 -> scenario_failure("block never returned")
      end
    end
  end

  defmodule HostCount do
    use SIP.Scenario

    state initial_state do
      # Queued before entering: the block reads the caller's own mailbox, which
      # is the whole point of S6.
      for n <- 1..3, do: send(self(), {:tick, n})
      sbb_fsm(CountTo, args: %{target: 3})

      on_events do
        {:counted, n} -> scenario_success("counted #{n}")
      after
        1_000 -> scenario_failure("block never returned")
      end
    end
  end

  defmodule HostFatal do
    use SIP.Scenario

    state initial_state do
      sbb_fsm(Fatal)
      scenario_success("the block should never have let us get here")
    end
  end

  defmodule HostNesting do
    use SIP.Scenario

    state initial_state do
      sbb_fsm(Nesting)
      scenario_success("the nested block should never have let us get here")
    end
  end

  defmodule HostNestingEcho do
    use SIP.Scenario

    state initial_state do
      sbb_fsm(NestingEcho)

      on_events do
        {:outer, payload} -> scenario_success("outer got #{inspect(payload)}")
      after
        1_000 -> scenario_failure("nested block never returned")
      end
    end
  end

  defmodule HostDeadline do
    use SIP.Scenario

    state initial_state do
      sbb_fsm(Hangs)

      on_events do
        {:hangs, :timed_out} -> scenario_success("block bounded by its deadline")
      after
        1_000 -> scenario_failure("deadline never fired")
      end
    end
  end

  # A block that ignores an event must leave it in the mailbox for the host —
  # the deferred fall-through of S5.
  defmodule HostFallThrough do
    use SIP.Scenario

    state initial_state do
      send(self(), {:for_the_host, :kept})
      sbb_fsm(Echo, args: %{payload: :done})

      on_events do
        # Arrival order: what the block ignored comes back before its own return.
        {:for_the_host, :kept} -> goto(then_the_return, "host event survived the block")
        {:echo, _} -> scenario_failure("the block's event overtook the pending one")
      after
        1_000 -> scenario_failure("nothing came back")
      end
    end

    state then_the_return do
      on_events do
        {:echo, :done} -> scenario_success("both events, in order")
      after
        1_000 -> scenario_failure("the block's own event never arrived")
      end
    end
  end

  # The sandbox is per-call: a second entry starts from nothing unless resumed.
  defmodule Accumulate do
    use SIP.SBB

    state initial_state do
      sbb_data_set(:runs, (sbb_data_get(:runs) || 0) + 1)
      sbb_return({:runs, sbb_data_get(:runs)})
    end
  end

  defmodule HostSandbox do
    use SIP.Scenario

    state initial_state do
      sbb_fsm(Accumulate)
      sbb_fsm(Accumulate)
      goto(collect)
    end

    state collect do
      on_events do
        {:runs, first} ->
          send(self(), {:first, first})
          goto(second_run)
      after
        1_000 -> scenario_failure("no first result")
      end
    end

    state second_run do
      on_events do
        {:runs, second} ->
          receive do
            # Both runs must have counted 1: the second call started from an
            # empty sandbox rather than inheriting the first.
            {:first, 1} when second == 1 -> scenario_success("both runs started clean")
            {:first, first} -> scenario_failure("sandbox leaked: #{first} then #{second}")
          after
            0 -> scenario_failure("lost the first result")
          end
      after
        1_000 -> scenario_failure("no second result")
      end
    end
  end

  defmodule HostSandboxResumed do
    use SIP.Scenario

    state initial_state do
      sbb_fsm(Accumulate)
      goto(again)
    end

    state again do
      on_events do
        {:runs, _first} -> goto(resume)
      after
        1_000 -> scenario_failure("no first result")
      end
    end

    state resume do
      sbb_fsm(Accumulate, resume: true)

      on_events do
        {:runs, 2} -> scenario_success("the resumed run found the first one's count")
        {:runs, n} -> scenario_failure("resume lost the sandbox: counted #{n}, expected 2")
      after
        1_000 -> scenario_failure("no second result")
      end
    end
  end

  # ── Harness ─────────────────────────────────────────────────────────────────

  defp run(module) do
    watcher = self()

    {pid, ref} =
      spawn_monitor(fn ->
        send(watcher, {:outcome, SIP.Scenario.Runner.run_instance(module)})
      end)

    receive do
      {:outcome, outcome} ->
        receive do
          {:DOWN, ^ref, :process, ^pid, _} -> :ok
        after
          1_000 -> :ok
        end

        outcome
    after
      5_000 -> flunk("scenario #{inspect(module)} did not finish")
    end
  end

  # ── The mechanism ───────────────────────────────────────────────────────────

  test "a block returns an event the host matches, and args seed its sandbox" do
    assert :ok = run(HostEcho)
  end

  test "a block walks states of its own before returning" do
    assert :ok = run(HostTwoSteps)
  end

  test "a block consumes events and `stay`s inside its own wait" do
    assert :ok = run(HostCount)
  end

  test "blocks nest, and the inner one's event reaches the outer one" do
    assert :ok = run(HostNestingEcho)
  end

  # ── Terminals propagate (S8) ────────────────────────────────────────────────

  test "a terminal inside a block ends the host" do
    assert {:error, "block decided to stop everything"} = run(HostFatal)
  end

  test "a terminal two blocks deep still ends the host" do
    assert {:error, "block decided to stop everything"} = run(HostNesting)
  end

  # ── The bound (S7) ──────────────────────────────────────────────────────────

  test "a block that never returns is ended by its own deadline" do
    assert :ok = run(HostDeadline)
  end

  test "the deadline is overridable at the call site" do
    defmodule HostShortDeadline do
      use SIP.Scenario

      state initial_state do
        sbb_fsm(Hangs, timeout: 30)

        on_events do
          {:hangs, :timed_out} -> scenario_success("bounded")
        after
          1_000 -> scenario_failure("deadline never fired")
        end
      end
    end

    assert :ok = run(HostShortDeadline)
  end

  # ── Events the block ignores (S5) ───────────────────────────────────────────

  test "an event the block does not consume is still there for the host" do
    assert :ok = run(HostFallThrough)
  end

  # ── The sandbox (§3.2) ──────────────────────────────────────────────────────

  test "the sandbox is cleared between two calls of the same block" do
    assert :ok = run(HostSandbox)
  end

  test "resume: true keeps the sandbox across calls" do
    assert :ok = run(HostSandboxResumed)
  end

  # ── Misuse ──────────────────────────────────────────────────────────────────

  test "sbb_fsm in an on_events clause is a compile error" do
    source = """
    defmodule SIP.Test.SbbFsm.InClause do
      use SIP.Scenario
      state initial_state do
        on_events do
          {:go, _} -> sbb_fsm(SIP.Test.SbbFsm.Echo)
        end
      end
    end
    """

    assert_raise CompileError, ~r/only allowed in a state body/, fn ->
      Code.compile_string(source)
    end
  end

  test "entering something that is not a block is rejected" do
    assert_raise ArgumentError, ~r/is not a service building block/, fn ->
      SIP.Scenario.Runner.run_sbb(%SIP.Context{}, HostEcho)
    end
  end

  test "sbb_return outside a block fails the scenario rather than transitioning" do
    defmodule HostStrayReturn do
      use SIP.Scenario

      state initial_state do
        sbb_return({:stray, :event})
      end
    end

    assert {:error, {:sbb_return_outside_sbb, :initial_state}} = run(HostStrayReturn)
  end

  # ── The property the whole mechanism rests on ───────────────────────────────

  test "the per-state try/catch stays transparent to a throw" do
    # A terminal crosses N state frames as a throw, and the wrapper every state
    # body carries must keep catching :exit and exceptions ONLY. If someone adds
    # a bare `catch value ->` there, blocks stop propagating and this fails.
    defmodule Thrower do
      use SIP.Scenario

      state initial_state do
        throw(:crossed_the_state_frame)
      end
    end

    assert catch_throw(SIP.Scenario.Runner.run_instance(Thrower)) == :crossed_the_state_frame
  end
end
