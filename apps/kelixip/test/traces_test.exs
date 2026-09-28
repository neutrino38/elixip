defmodule Kelix.TracesTest do
  # Kelix.Traces on its own (an unregistered store per test), then the whole path
  # an operator takes: `debug <id> on` on a live scenario, `off`, `list`, `show`.
  use ExUnit.Case, async: false

  alias Kelix.Control
  alias Kelix.Traces

  @waiter Path.join(__DIR__, "support/scripts/waiter.exs")

  defp store(limits) do
    start_supervised!({Traces, name: nil, limits: limits})
  end

  defp keep(server, slot, doc \\ "@startuml\n@enduml\n") do
    {:ok, _} = Traces.store(doc, %{slot: slot, scenario: "X"}, FSL.Diagram.PlantUML, server)
  end

  describe "the store" do
    test "keeps a diagram under its instance id, oldest first, several per instance" do
      server = store(%{trace_retention: 60, max_traces: 10})
      keep(server, 7, "one")
      keep(server, 8, "other")
      keep(server, 7, "two")

      assert {:ok, [first, second]} = Traces.get(7, server)
      assert {first.document, second.document} == {"one", "two"}
      assert first.format == "plantuml"
      assert first.running == Process.alive?(self())
      assert Traces.get(9, server) == {:error, :not_found}

      assert [%{id: 7}, %{id: 8}, %{id: 7}] = rows = Traces.list(server)
      refute Enum.any?(rows, &Map.has_key?(&1, :document))
    end

    test "drops the oldest past max_traces" do
      server = store(%{trace_retention: 60, max_traces: 2})
      for id <- 1..3, do: keep(server, id)

      assert Enum.map(Traces.list(server), & &1.id) == [2, 3]
    end

    test "forgets a diagram trace_retention seconds after it was written" do
      server = store(%{trace_retention: 1, max_traces: 10})
      keep(server, 1)
      assert [%{id: 1, expires_in_s: left}] = Traces.list(server)
      assert left <= 1

      Process.sleep(1_100)
      assert Traces.list(server) == []
      assert Traces.get(1, server) == {:error, :not_found}
    end

    test "answers an error rather than raising when it is not running" do
      assert {:error, {:trace_store_unavailable, _}} =
               Traces.store("x", %{slot: 1}, FSL.Diagram.PlantUML, :no_such_store)
    end
  end

  describe "a live scenario" do
    defp spawn_waiter(domain) do
      route = %{domain: domain, function: :registrar, script: @waiter, max_calls: nil}
      assert {:accept, pid} = Kelix.InstancePool.accept(route, nil, %{method: :REGISTER})
      on_exit(fn -> send(pid, {:scenario_ctl, :shutdown, :test}) end)
      %{id: id} = Enum.find(Kelix.InstancePool.list(), &(&1.pid == pid))
      {id, pid}
    end

    defp await_trace(id) do
      Enum.reduce_while(1..50, {:error, :not_found}, fn _i, acc ->
        case Control.trace(id) do
          {:ok, _} = found -> {:halt, found}
          _ -> Process.sleep(20) && {:cont, acc}
        end
      end)
    end

    test "debug on, then off, keeps the diagram of the call in progress" do
      {id, pid} = spawn_waiter("debug.test")

      assert Control.debug_scenario(id, :on) == :ok
      assert Control.debug_scenario(id, :off) == :ok

      assert {:ok, [trace]} = await_trace(id)
      assert trace.domain == "debug.test"
      assert trace.script == @waiter
      assert trace.running
      assert trace.document =~ "@startuml"
      assert trace.document =~ ~r/journal on \(initial_state\)/
      assert trace.document =~ ~r/journal off \(initial_state\)/

      # The scenario never noticed: still waiting, still stoppable.
      assert Process.alive?(pid)
      assert Control.shutdown_scenario(id) == :ok
    end

    test "debug on keeps the diagram when the scenario ends" do
      {id, _pid} = spawn_waiter("debug-end.test")

      assert Control.debug_scenario(id, :on) == :ok
      assert Control.shutdown_scenario(id) == :ok

      assert {:ok, [trace]} = await_trace(id)
      assert trace.document =~ "aborted"

      assert Enum.any?(Control.traces(), &(&1.id == id))
    end

    test "an unknown instance" do
      assert Control.debug_scenario(999_999, :on) == {:error, :not_found}
      assert Control.trace(999_999) == {:error, :not_found}
    end

    test "kelictl debug on / off / list / show" do
      {id, _pid} = spawn_waiter("debug-cli.test")
      run = &Kelix.Control.CLI.run(&1, node())

      assert {0, out} = run.(["debug", "#{id}", "on"])
      assert out =~ "journal on for scenario #{id}"
      assert {0, _} = run.(["debug", "#{id}", "off"])
      assert {:ok, _} = await_trace(id)

      assert {0, list} = run.(["debug", "list"])
      assert list =~ "debug-cli.test"
      assert list =~ "running"

      assert {0, doc} = run.(["debug", "show", "#{id}"])
      assert doc =~ ~r/^' Scenario/
      assert doc =~ "@enduml"

      assert {3, _} = run.(["debug", "999999", "on"])
      assert {3, _} = run.(["debug", "show", "999999"])
      assert {2, _} = run.(["debug", "x", "on"])
      assert {2, usage} = run.(["debug", "sideways"])
      assert usage =~ "debug <id> on|off"
      assert {0, help} = run.(["debug", "help"])
      assert help =~ "trace_retention"
    end
  end
end
