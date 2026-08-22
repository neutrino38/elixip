defmodule SIP.Test.SbbMonitor do
  use ExUnit.Case, async: false

  @moduledoc """
  What the live monitor shows while a service building block holds the FSM
  (phase 2 of docs/design/DESIGN-SBB.md, §4).

  One call, one row: a block's states show on the host's row, qualified with the
  block they belong to, so the operator reads `SBB.Call/waiting_answer` instead of
  a call frozen for thirty seconds in the last state its scenario declares — and
  instead of a state name that scenario does not declare at all.
  """

  # ── Blocks ──────────────────────────────────────────────────────────────────

  # Waits in a state of its own until the test releases it, so the row can be
  # read while the block holds the machine.
  defmodule Waiting do
    use SIP.SBB

    @sbb_returns [released: "the test let it go — %{}", gave_up: "nobody did — %{}"]

    state initial_state do
      goto(holding)
    end

    state holding do
      on_events do
        {:release, _} -> sbb_return({:waiting, :released, %{}})
      after
        3_000 -> sbb_return({:waiting, :gave_up, %{}})
      end
    end
  end

  # Holds in a state of its own, then returns — so the row can be read while the
  # block is there AND after it has handed control back.
  defmodule Quiet do
    use SIP.SBB

    @sbb_returns [done: "walked one state of its own and returned — %{}", gave_up: "— %{}"]

    state initial_state do
      goto(finishing)
    end

    state finishing do
      on_events do
        {:let_go, _} -> sbb_return({:quiet, :done, %{}})
      after
        3_000 -> sbb_return({:quiet, :gave_up, %{}})
      end
    end
  end

  # Waits where it starts: nothing but the report on the way in can put its
  # initial_state on the row.
  defmodule Immediate do
    use SIP.SBB

    @sbb_returns [released: "— %{}", gave_up: "— %{}"]

    state initial_state do
      on_events do
        {:release, _} -> sbb_return({:immediate, :released, %{}})
      after
        3_000 -> sbb_return({:immediate, :gave_up, %{}})
      end
    end
  end

  defmodule Outer do
    use SIP.SBB

    @sbb_returns [done: "the block it called returned — %{}", timeout_of_inner: "— %{}"]

    state initial_state do
      sbb_fsm(Waiting)

      on_events do
        {:waiting, _, _} -> sbb_return({:outer, :done, %{}})
      after
        3_000 -> sbb_return({:outer, :timeout_of_inner, %{}})
      end
    end
  end

  defmodule Fatal do
    use SIP.SBB

    state initial_state do
      scenario_failure("the block stopped everything")
    end
  end

  # ── Hosts ───────────────────────────────────────────────────────────────────

  defmodule HostWaiting do
    use SIP.Scenario

    state initial_state do
      sbb_fsm(Waiting)

      on_events do
        {:waiting, _, _} -> scenario_success("done")
      after
        3_000 -> scenario_failure("block never returned")
      end
    end
  end

  defmodule HostImmediate do
    use SIP.Scenario

    state initial_state do
      sbb_fsm(Immediate)

      on_events do
        {:immediate, _, _} -> scenario_success("done")
      after
        3_000 -> scenario_failure("block never returned")
      end
    end
  end

  defmodule HostNested do
    use SIP.Scenario

    state initial_state do
      sbb_fsm(Outer)

      on_events do
        {:outer, _, _} -> scenario_success("done")
      after
        3_000 -> scenario_failure("block never returned")
      end
    end
  end

  # The block returns on its own; the host then waits on something else, leaving
  # the returned event unmatched in the mailbox. The row must show the host's
  # state — the block is over.
  defmodule HostAfterReturn do
    use SIP.Scenario

    state initial_state do
      sbb_fsm(Quiet)

      on_events do
        {:release, _} -> scenario_success("released")
      after
        3_000 -> scenario_failure("never released")
      end
    end
  end

  defmodule HostFatal do
    use SIP.Scenario

    state initial_state do
      sbb_fsm(Fatal)
      scenario_success("unreachable")
    end
  end

  # ── Harness ─────────────────────────────────────────────────────────────────

  setup do
    {:ok, _pid} = SIP.Scenario.Monitor.start()
    slot = System.unique_integer([:positive])
    on_exit(fn -> SIP.Scenario.Monitor.clear(slot) end)
    {:ok, slot: slot}
  end

  defp row(slot) do
    Enum.find(SIP.Scenario.Monitor.calls(), &(&1.slot == slot))
  end

  # The reports are casts from another process: wait for the row to reach `state`
  # rather than sampling it once. Returns the row, or flunks with what it last saw
  # — a wrong value fails on the assertion, a missing one on the timeout.
  defp await_state(slot, state, timeout \\ 2_000) do
    deadline = System.monotonic_time(:millisecond) + timeout
    await_state(slot, state, deadline, nil)
  end

  defp await_state(slot, state, deadline, last) do
    case row(slot) do
      %{state: ^state} = row ->
        row

      other ->
        if System.monotonic_time(:millisecond) < deadline do
          Process.sleep(5)
          await_state(slot, state, deadline, other)
        else
          flunk("row never reached #{inspect(state)}; last seen: #{inspect(last || other)}")
        end
    end
  end

  defp start_scenario(module, slot) do
    test = self()

    spawn(fn ->
      send(test, {:outcome, SIP.Scenario.Runner.run_instance(module, slot_id: slot)})
    end)
  end

  defp await_outcome do
    receive do
      {:outcome, outcome} -> outcome
    after
      5_000 -> flunk("scenario did not finish")
    end
  end

  defp label(module), do: module |> Module.split() |> Enum.join(".")

  # ── The row while a block holds the machine ─────────────────────────────────

  test "a block's state shows on the host's row, qualified with the block", %{slot: slot} do
    pid = start_scenario(HostWaiting, slot)

    row = await_state(slot, "#{label(Waiting)}/holding")

    # Same row, still the host's scenario: the block is where the call is, not
    # what the call is.
    assert row.scenario == label(HostWaiting)
    assert row.slot == slot

    send(pid, {:release, :now})
    assert :ok = await_outcome()
  end

  # Both machines call their first state `initial_state`: only the qualification
  # tells the row where the call is, and only the report on the way in puts it
  # there.
  test "entering a block is reported before its first state runs", %{slot: slot} do
    pid = start_scenario(HostImmediate, slot)

    row = await_state(slot, "#{label(Immediate)}/initial_state")
    assert row.scenario == label(HostImmediate)

    send(pid, {:release, :now})
    assert :ok = await_outcome()
  end

  test "a nested block shows the innermost one, where the call actually is",
       %{slot: slot} do
    pid = start_scenario(HostNested, slot)

    row = await_state(slot, "#{label(Waiting)}/holding")
    assert row.scenario == label(HostNested)

    send(pid, {:release, :now})
    assert :ok = await_outcome()
  end

  test "on return the row goes back to the host's own state", %{slot: slot} do
    pid = start_scenario(HostAfterReturn, slot)

    # The block holds the machine in a state of its own...
    await_state(slot, "#{label(Quiet)}/finishing")
    send(pid, {:let_go, :now})

    # ...and once it returns, the host's state replaces it, unqualified, while the
    # host waits on something the block's event is not. Without the report on the
    # way out, the row would still read `Quiet/finishing` here.
    row = await_state(slot, "initial_state")
    assert row.scenario == label(HostAfterReturn)

    send(pid, {:release, :now})
    assert :ok = await_outcome()
  end

  # A block's return is `{namespace, outcome, data}` — two leading atoms — and the
  # namespace is the block author's word, so no table can list it. `on_events`
  # recognises the SHAPE and types it :scenario. Without that rule an unknown
  # leading atom falls through to :sip, and the sequence diagram draws the
  # block's return as an arrow from the peer: an event that came from nobody,
  # attributed to the far end.
  test "a block's return is typed as a scenario event, not as a SIP message",
       %{slot: slot} do
    pid = start_scenario(HostWaiting, slot)

    await_state(slot, "#{label(Waiting)}/holding")
    send(pid, {:release, :now})
    assert :ok = await_outcome()

    row = await_state(slot, "succeeded")
    assert row.event_type == :scenario
  end

  # A terminal thrown from a block unwinds every run_sbb frame: the outcome is the
  # host's, so it must be reported unqualified, on the host's row.
  test "a terminal from inside a block is reported as the host's outcome", %{slot: slot} do
    start_scenario(HostFatal, slot)

    assert {:error, "the block stopped everything"} = await_outcome()

    row = await_state(slot, "failed")
    assert row.scenario == label(HostFatal)
    assert row.event == "the block stopped everything"
  end
end
