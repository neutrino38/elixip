defmodule SIP.Test.SbbFsm do
  use ExUnit.Case

  # Phase 1 of docs/design/service-building-block-design.md: the mechanism alone,
  # on toy blocks. No SIP here — a block is an FSM run by the calling process on
  # the caller's context, and that is what these assert.

  # ── Toy blocks ──────────────────────────────────────────────────────────────

  # Returns straight away with what it was given at the call site.
  defmodule Echo do
    use SIP.SBB

    @sbb_returns [heard: "gives back what the call site put in its sandbox — %{payload}"]

    state initial_state do
      sbb_return({:echo, :heard, %{payload: sbb_data_get(:payload)}})
    end
  end

  # Walks two states of its own before returning, so `goto` inside a block is
  # exercised — including `goto next`, which needs the block's own state list.
  defmodule TwoSteps do
    use SIP.SBB

    @sbb_returns [walked: "how many states it went through — %{steps}"]

    state initial_state do
      sbb_data_set(:steps, 1)
      goto(second)
    end

    state second do
      sbb_data_set(:steps, sbb_data_get(:steps) + 1)
      sbb_return({:two_steps, :walked, %{steps: sbb_data_get(:steps)}})
    end
  end

  # Consumes events until it has seen enough, using `stay` to re-enter its wait.
  defmodule CountTo do
    use SIP.SBB

    @sbb_returns [counted: "the target was reached — %{seen}"]

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
            do: sbb_return({:count_to, :counted, %{seen: seen}}),
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

    @sbb_returns [unreachable: "never sent: the block it calls ends the scenario first"]

    state initial_state do
      sbb_fsm(Fatal)
      sbb_return({:nesting, :unreachable, %{}})
    end
  end

  defmodule NestingEcho do
    use SIP.SBB

    @sbb_returns [relayed: "what the block it called returned — %{payload}"]

    state initial_state do
      sbb_fsm(Echo, args: %{payload: :from_inner})

      on_events do
        {:echo, :heard, %{payload: payload}} ->
          sbb_return({:nesting_echo, :relayed, %{payload: payload}})
      end
    end
  end

  # Never returns on its own: only its deadline can end it.
  defmodule Hangs do
    use SIP.SBB

    @sbb_timeout 60
    @sbb_returns [impossible: "the event it waits for is never sent"]

    state initial_state do
      on_events do
        {:never, _} -> sbb_return({:hangs, :impossible, %{}})
      end
    end
  end

  # Waits for an event the test never sends, so a shutdown is what ends it.
  defmodule Waiting do
    use SIP.SBB

    @sbb_returns [released: "the event it waits for arrived — %{}"]

    state initial_state do
      on_events do
        {:release, _} -> sbb_return({:waiting, :released, %{}})
      end
    end
  end

  # ── Hosts ───────────────────────────────────────────────────────────────────

  defmodule HostEcho do
    use SIP.Scenario

    state initial_state do
      sbb_fsm(Echo, args: %{payload: :hello})

      on_events do
        {:echo, :heard, %{payload: payload}} -> scenario_success("echoed #{inspect(payload)}")
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
        {:two_steps, :walked, %{steps: n}} -> scenario_success("walked #{n}")
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
        {:count_to, :counted, %{seen: n}} -> scenario_success("counted #{n}")
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
        {:nesting_echo, :relayed, %{payload: p}} -> scenario_success("outer got #{inspect(p)}")
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
        {:hangs, :timeout, %{block: Hangs}} -> scenario_success("block bounded by its deadline")
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
        {:echo, _, _} -> scenario_failure("the block's event overtook the pending one")
      after
        1_000 -> scenario_failure("nothing came back")
      end
    end

    state then_the_return do
      on_events do
        {:echo, :heard, %{payload: :done}} -> scenario_success("both events, in order")
      after
        1_000 -> scenario_failure("the block's own event never arrived")
      end
    end
  end

  # The sandbox is per-call: a second entry starts from nothing unless resumed.
  defmodule Accumulate do
    use SIP.SBB

    @sbb_returns [counted: "how many times this block has run — %{runs}"]

    state initial_state do
      sbb_data_set(:runs, (sbb_data_get(:runs) || 0) + 1)
      sbb_return({:accumulate, :counted, %{runs: sbb_data_get(:runs)}})
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
        {:accumulate, :counted, %{runs: first}} ->
          send(self(), {:first, first})
          goto(second_run)
      after
        1_000 -> scenario_failure("no first result")
      end
    end

    state second_run do
      on_events do
        {:accumulate, :counted, %{runs: second}} ->
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
        {:accumulate, :counted, _} -> goto(resume)
      after
        1_000 -> scenario_failure("no first result")
      end
    end

    state resume do
      sbb_fsm(Accumulate, resume: true)

      on_events do
        {:accumulate, :counted, %{runs: 2}} ->
          scenario_success("the resumed run found the first one's count")

        {:accumulate, :counted, %{runs: n}} ->
          scenario_failure("resume lost the sandbox: counted #{n}, expected 2")
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
          {:hangs, :timeout, _} -> scenario_success("bounded")
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
        sbb_return({:host_stray_return, :event, %{}})
      end
    end

    assert {:error, {:sbb_return_outside_sbb, :initial_state}} = run(HostStrayReturn)
  end

  # ── Cooperative shutdown through a block ────────────────────────────────────

  # A shutdown is addressed to the SCENARIO. Reaching it while a block holds the
  # machine must still run the host's on_shutdown: that block is where a script
  # frees what the call reserved — for a B2BUA, the media endpoints. Ending the
  # scenario from inside the block instead leaks them, silently, on every
  # graceful stop that lands mid-call.
  test "a shutdown reaching a block runs the host's on_shutdown" do
    defmodule HostWithShutdown do
      use SIP.Scenario

      state initial_state do
        sbb_fsm(Waiting)

        on_events do
          {:waiting, _, _} -> scenario_success("returned")
        after
          2_000 -> scenario_failure("block never returned")
        end
      end

      on_shutdown do
        # What a real script does here is release resources; asserting that it
        # ran at all is the same thing one level up.
        scenario_aborted("wound down by the host")
      end
    end

    test_pid = self()

    {pid, ref} =
      spawn_monitor(fn ->
        send(test_pid, {:outcome, SIP.Scenario.Runner.run_instance(HostWithShutdown)})
      end)

    # Give the block time to be the one waiting.
    Process.sleep(50)
    send(pid, {:scenario_ctl, :shutdown, :test})

    assert_receive {:outcome, {:aborted, "wound down by the host"}}, 5_000
    assert_receive {:DOWN, ^ref, :process, ^pid, _}, 2_000
  end

  # A host with no on_shutdown keeps the old verdict: a controller-driven stop is
  # an abort, not a failure.
  test "a shutdown reaching a block still aborts a host that declares none" do
    defmodule HostNoShutdown do
      use SIP.Scenario

      state initial_state do
        sbb_fsm(Waiting)

        on_events do
          {:waiting, _, _} -> scenario_success("returned")
        after
          2_000 -> scenario_failure("block never returned")
        end
      end
    end

    test_pid = self()

    {pid, _ref} =
      spawn_monitor(fn ->
        send(test_pid, {:outcome, SIP.Scenario.Runner.run_instance(HostNoShutdown)})
      end)

    Process.sleep(50)
    send(pid, {:scenario_ctl, :shutdown, :test})

    assert_receive {:outcome, {:aborted, "shutdown"}}, 5_000
  end

  # ── The return contract (spec §4.2) ─────────────────────────────────────────

  defp compile!(source), do: Code.compile_string(source)

  test "a return that is not {namespace, outcome, data} is a compile error" do
    assert_raise CompileError, ~r/three elements, the last a map/, fn ->
      compile!("""
      defmodule SIP.Test.SbbFsm.TwoElements do
        use SIP.SBB
        state initial_state do
          sbb_return({:two_elements, :done})
        end
      end
      """)
    end
  end

  test "a return under another block's namespace is a compile error" do
    assert_raise CompileError, ~r/namespace is :wrong_ns, not :call/, fn ->
      compile!("""
      defmodule SIP.Test.SbbFsm.WrongNs do
        use SIP.SBB
        @sbb_namespace :wrong_ns
        @sbb_returns [done: "…"]
        state initial_state do
          sbb_return({:call, :done, %{}})
        end
      end
      """)
    end
  end

  # The one that pays for itself: an undeclared outcome is not a crash at run
  # time, it is a host waiting on its `after` for an event nobody sends.
  test "an outcome the block does not declare is a compile error" do
    assert_raise CompileError, ~r/:conected is not one of this block's declared outcomes/, fn ->
      compile!("""
      defmodule SIP.Test.SbbFsm.Typo do
        use SIP.SBB
        @sbb_namespace :typo
        @sbb_returns [connected: "…"]
        state initial_state do
          sbb_return({:typo, :conected, %{}})
        end
      end
      """)
    end
  end

  # A block that declares no vocabulary is not checked on outcomes: declaring is
  # opt-in, enforcement follows the declaration.
  test "a block with no declared vocabulary keeps its outcomes unchecked" do
    assert [{_mod, _bin} | _] =
             compile!("""
             defmodule SIP.Test.SbbFsm.Undeclared do
               use SIP.SBB
               state initial_state do
                 sbb_return({:undeclared, :whatever, %{}})
               end
             end
             """)
  end

  # The face module a scenario writes `use SBB.Call` for teaches the namespaces
  # for the whole module, so a host that handles a return in a state written
  # BEFORE the call site is classified too. This is the hook it uses.
  test "a face module can register its blocks' namespaces for the whole scenario" do
    defmodule Face do
      defmacro __using__(_opts) do
        SIP.Scenario.register_namespace(__CALLER__.module, :faced)
        quote(do: :ok)
      end
    end

    defmodule HostFaced do
      use SIP.Scenario
      use Face

      # No sbb_fsm anywhere: only the face taught this module that `:faced` is a
      # block's namespace and not a SIP method.
      state initial_state do
        send(self(), {:faced, :done, %{}})

        on_events do
          {:faced, :done, _} ->
            case Process.get(:scenario_event_type) do
              :scenario -> scenario_success("classified from the face")
              other -> scenario_failure("classified as #{inspect(other)}")
            end
        after
          500 -> scenario_failure("no event")
        end
      end
    end

    assert :ok = run(HostFaced)
  end

  test "the namespace defaults to the block's own name, underscored" do
    assert Echo.__sbb_namespace__() == :echo
  end

  # A bounded block can always return :timeout, whether or not its author listed
  # it — so the vocabulary says so, and the event follows the contract.
  test "timeout is part of a bounded block's vocabulary, and follows the contract" do
    assert Keyword.has_key?(Hangs.__sbb_returns__(), :timeout)
    assert Hangs.__sbb_timeout_event__() == {:hangs, :timeout, %{block: Hangs}}
  end

  test "an unbounded block has no timeout outcome" do
    defmodule Endless do
      use SIP.SBB
      @sbb_timeout :infinity
      @sbb_returns [ended: "…"]

      state initial_state do
        sbb_return({:endless, :ended, %{}})
      end
    end

    refute Keyword.has_key?(Endless.__sbb_returns__(), :timeout)
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
