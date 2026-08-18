defmodule SIP.Test.ScenarioStayBack do
  use ExUnit.Case

  # ── Scenario fixtures (compiled once) ───────────────────────────────────────

  # `stay` consumes an event and comes back to the same `on_events` without
  # re-running the state body: :entries counts state entries, :events counts
  # consumed events, and the terminal state asserts on both.
  defmodule Stays do
    use SIP.Scenario

    state initial_state do
      appdata_set(:entries, (appdata_get(:entries) || 0) + 1)
      appdata_set(:events, 0)

      on_events do
        {:tick, _n} ->
          appdata_set(:events, appdata_get(:events) + 1)
          stay("tick")

        {:done, _} ->
          goto(finished, "done")
      end
    end

    state finished do
      case {appdata_get(:entries), appdata_get(:events)} do
        {1, 3} -> scenario_success("stayed")
        other -> scenario_failure("unexpected #{inspect(other)}")
      end
    end
  end

  # A cooperative shutdown must still be honoured from inside a stay loop.
  defmodule StaysThenShutdown do
    use SIP.Scenario

    state initial_state do
      on_events do
        {:tick, _n} -> stay("tick")
      end
    end
  end

  # The `after` deadline belongs to the wait, not to each event: a stream of
  # consumed events must not keep the state alive past it.
  defmodule StayKeepsDeadline do
    use SIP.Scenario

    state initial_state do
      on_events do
        {:tick, _n} -> stay("tick")
      after
        250 -> scenario_success("deadline")
      end
    end
  end

  # A B2BUA `connected` state stays for every relayed message, for hours. If the
  # closure re-entry were not a tail call, that state would grow a stack until the
  # call ended.
  defmodule StaysForever do
    use SIP.Scenario

    state initial_state do
      on_events do
        {:tick, _n} ->
          stay("tick")

        {:done, from} ->
          :erlang.garbage_collect()
          send(from, :erlang.process_info(self(), [:stack_size, :memory]))
          scenario_success("ok")
      end
    end
  end

  # The `after` body is the one place the compile-time check cannot see, since it
  # belongs to the on_events it prunes. The runner is the net under it.
  defmodule StaysAfterDeadline do
    use SIP.Scenario

    state initial_state do
      on_events do
        {:tick, _n} -> goto(loop)
      after
        0 -> stay("nothing left to wait for")
      end
    end
  end

  # goto back: a detour state returns to whoever called it. The detour also does
  # a `goto loop` and a `stay`, neither of which may change what `back` points to.
  defmodule GoesBack do
    use SIP.Scenario

    state initial_state do
      appdata_set(:visits, 0)
      goto(a)
    end

    state a do
      appdata_set(:visits, appdata_get(:visits) + 1)

      if appdata_get(:visits) == 1 do
        goto(detour, "first pass")
      else
        scenario_success("back after #{appdata_get(:visits)} visits")
      end
    end

    state detour do
      n = appdata_get(:detours) || 0
      appdata_set(:detours, n + 1)

      if n < 1 do
        goto(loop, "loop in detour")
      else
        send(self(), {:ping, 1})
        send(self(), {:ping, 2})

        on_events do
          {:ping, 1} -> stay("first ping")
          {:ping, 2} -> goto(back, "return")
        end
      end
    end
  end

  defmodule BackFromInitialState do
    use SIP.Scenario

    state initial_state do
      goto(back)
    end
  end

  # ── stay ────────────────────────────────────────────────────────────────────

  test "stay consumes an event without re-running the state body" do
    pid = run_async(Stays)

    for n <- 1..3, do: send(pid, {:tick, n})
    send(pid, {:done, :now})

    assert_receive {:done, :ok}, 2_000
  end

  test "a shutdown request is honoured from inside a stay loop" do
    pid = run_async(StaysThenShutdown)

    send(pid, {:tick, 1})
    send(pid, {:tick, 2})
    send(pid, {:scenario_ctl, :shutdown, :test})

    assert_receive {:done, {:aborted, "shutdown"}}, 2_000
  end

  test "stay does not re-arm the after deadline of the on_events" do
    pid = run_async(StayKeepsDeadline)

    # One tick every 100 ms, well under the 250 ms deadline. Re-arming would push
    # the timeout past the last tick (500 + 250 ms); keeping the deadline fires
    # it around 250 ms, i.e. before the ticks are even over.
    ticker =
      spawn(fn ->
        Enum.each(1..5, fn n ->
          Process.sleep(100)
          send(pid, {:tick, n})
        end)
      end)

    started = System.monotonic_time(:millisecond)
    assert_receive {:done, :ok}, 2_000
    elapsed = System.monotonic_time(:millisecond) - started
    Process.exit(ticker, :kill)

    assert elapsed < 600, "on_events waited #{elapsed} ms, the 250 ms deadline was re-armed"
  end

  test "stay is reported to the monitor, so the call does not look frozen" do
    {:ok, _} = SIP.Scenario.Monitor.start()

    pid = run_async(Stays)
    send(pid, {:tick, 1})

    assert wait_for_event("tick", 100)

    for n <- 2..3, do: send(pid, {:tick, n})
    send(pid, {:done, :now})
    assert_receive {:done, :ok}, 2_000
  end

  test "stay outside an on_events clause is a compile-time error" do
    assert_raise CompileError, ~r/stay is only allowed in an on_events clause/, fn ->
      Code.compile_string("""
      defmodule SIP.Test.StayOutside do
        use SIP.Scenario

        state initial_state do
          stay("nowhere to go back to")
        end
      end
      """)
    end
  end

  test "a stay in an after body stops the scenario instead of spinning" do
    assert StaysAfterDeadline.run(false) ==
             {:error, {:stay_outside_on_events, :initial_state}}
  end

  test "an on_events deadline is absolute and its remainder never goes negative" do
    assert SIP.Scenario.deadline(:infinity) == :infinity
    assert SIP.Scenario.remaining_timeout(:infinity) == :infinity

    deadline = SIP.Scenario.deadline(1_000)
    assert SIP.Scenario.remaining_timeout(deadline) in 990..1_000
    assert SIP.Scenario.remaining_timeout(SIP.Scenario.deadline(-5)) == 0
  end

  test "a long stay loop grows neither stack nor heap" do
    footprint = fn count ->
      pid = run_async(StaysForever)
      Enum.each(1..count, &send(pid, {:tick, &1}))
      send(pid, {:done, self()})
      assert_receive info when is_list(info), 30_000
      assert_receive {:done, :ok}, 5_000
      info
    end

    few = footprint.(100)
    many = footprint.(20_000)

    assert many[:stack_size] == few[:stack_size]
    assert many[:memory] == few[:memory]
  end

  # ── goto back ───────────────────────────────────────────────────────────────

  test "goto back returns to the calling state, which loop and stay leave alone" do
    assert GoesBack.run(false) == :ok
  end

  test "goto back with no previous state fails the scenario cleanly" do
    assert BackFromInitialState.run(false) == {:error, "goto back with no previous state"}
  end

  test "the runner records the state it came from" do
    ctx = SIP.Scenario.Runner.build_context(username: "alice", domain: "example.com")
    assert ctx.laststate == nil
    assert SIP.Context.get(SIP.Context.set(ctx, :laststate, :calling), :laststate) == :calling
  end

  # ── helpers ─────────────────────────────────────────────────────────────────

  defp run_async(module) do
    parent = self()
    spawn(fn -> send(parent, {:done, module.run(false)}) end)
  end

  defp wait_for_event(_event, 0), do: false

  defp wait_for_event(event, attempts) do
    if Enum.any?(SIP.Scenario.Monitor.calls(), &(&1.event == event)) do
      true
    else
      Process.sleep(10)
      wait_for_event(event, attempts - 1)
    end
  end
end
