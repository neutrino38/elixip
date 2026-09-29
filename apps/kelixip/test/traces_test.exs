defmodule Kelix.TracesTest do
  # Kelix.Traces on its own (an unregistered store per test), then the whole path
  # an operator takes: `debug <id> on` on a live scenario, `off`, `list`, `show`,
  # and what kelescope subscribes to.
  use ExUnit.Case, async: false

  alias Kelix.Control
  alias Kelix.Traces

  @waiter Path.join(__DIR__, "support/scripts/waiter.exs")

  @limits %{trace_retention: 60, max_traces: 10, max_trace_bytes: 1_048_576}

  defp store(limits \\ %{}) do
    start_supervised!({Traces, name: nil, limits: Map.merge(@limits, limits)},
      id: make_ref()
    )
  end

  defp meta(id), do: %{slot: id, scenario: "X", pid: "p", t0: 0, config: [passwd: "s3cret"]}

  defp journal(n \\ 1) do
    [%{kind: :transition, at: 1_000, to: :initial_state, event: "start", type: nil}] ++
      for i <- 1..n do
        %{
          kind: :message,
          at: 2_000 + i,
          dir: :out,
          lane: "call-1",
          label: "INVITE ##{i}",
          body: "INVITE sip:x SIP/2.0\r\n",
          reply: false,
          repeat: false
        }
      end
  end

  defp keep(server, id, events \\ journal()),
    do: {:ok, _} = Traces.store(events, meta(id), server)

  describe "the store" do
    test "keeps the journal itself, unrendered, under its instance id" do
      server = store()
      keep(server, 7)

      assert {:ok, trace} = Traces.get(7, server)
      assert trace.events == journal()
      assert trace.meta.slot == 7
      assert trace.sip_count == 1
      assert trace.running
      assert %DateTime{} = trace.expires_at
      assert Traces.get(8, server) == {:error, :not_found}

      assert [%{id: 7} = summary] = Traces.list(server)
      refute Map.has_key?(summary, :events)
      assert Traces.has?(7, server)
    end

    test "one journal per instance: a second one replaces the first" do
      server = store()
      keep(server, 7, journal(1))
      keep(server, 7, journal(3))

      assert [%{id: 7, sip_count: 3}] = Traces.list(server)
    end

    test "a run the pool did not start is not kept" do
      server = store()

      assert Traces.store(journal(), %{meta(1) | slot: {1, :child}}, server) ==
               {:error, :no_instance_id}
    end

    test "drops the oldest past max_traces" do
      server = store(%{max_traces: 2})
      for id <- 1..3, do: keep(server, id)
      assert Enum.map(Traces.list(server), & &1.id) == [2, 3]
    end

    test "cuts a journal past max_trace_bytes, and says so with a :cut" do
      server = store(%{max_trace_bytes: 300})
      keep(server, 1, journal(20))

      {:ok, trace} = Traces.get(1, server)
      assert %{kind: :cut} = List.last(trace.events)
      assert trace.sip_count < 20
      assert trace.bytes <= 300
    end

    test "forgets a journal trace_retention seconds after it was written, and tells" do
      server = store(%{trace_retention: 1})
      %{traces: []} = Traces.subscribe(self(), server)
      keep(server, 1)

      assert_receive {:kelix_traces, {:upsert, %{id: 1}}}
      assert_receive {:kelix_traces, {:remove, 1}}, 2_000
      assert Traces.list(server) == []
    end

    test "tells when the instance of a kept journal ends" do
      server = store()
      %{limits: %{max_traces: 10}} = Traces.subscribe(self(), server)
      parent = self()

      instance =
        spawn(fn ->
          send(parent, {:stored, Traces.store(journal(), meta(4), server)})
          receive do: (:stop -> :ok)
        end)

      assert_receive {:stored, {:ok, _}}
      assert_receive {:kelix_traces, {:upsert, %{id: 4, running: true}}}

      send(instance, :stop)
      assert_receive {:kelix_traces, {:upsert, %{id: 4, running: false}}}, 1_000
    end

    test "an unsubscribed or dead subscriber is told nothing more" do
      server = store()
      Traces.subscribe(self(), server)
      :ok = Traces.unsubscribe(self(), server)
      keep(server, 1)
      refute_receive {:kelix_traces, _}, 100
    end

    test "answers an error rather than raising when it is not running" do
      assert {:error, {:trace_store_unavailable, _}} =
               Traces.store(journal(), meta(1), :no_such_store)
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

    defp await(fun) do
      Enum.reduce_while(1..100, nil, fn _i, _acc ->
        case fun.() do
          nil -> Process.sleep(20) && {:cont, nil}
          false -> Process.sleep(20) && {:cont, nil}
          found -> {:halt, found}
        end
      end)
    end

    defp await_trace(id) do
      await(fn ->
        case Control.trace(id) do
          {:ok, trace} -> trace
          _ -> nil
        end
      end)
    end

    defp traced?(id),
      do: Enum.find_value(Control.monitor(), fn row -> row.id == id and row.traced end)

    test "on, then off: the monitor row says so, and the journal is kept" do
      {id, pid} = spawn_waiter("debug.test")
      on_exit(fn -> Control.unsubscribe_traces(self()) end)
      %{traces: _} = Control.subscribe_traces(self())

      assert Control.debug_scenario(id, :on) == :ok
      assert await(fn -> traced?(id) end)

      assert Control.debug_scenario(id, :off) == :ok
      assert_receive {:kelix_traces, {:upsert, %{id: ^id, running: true}}}, 2_000
      refute traced?(id)

      assert trace = await_trace(id)
      assert trace.domain == "debug.test"
      assert trace.script == @waiter
      assert Enum.any?(trace.events, &match?(%{kind: :command, name: "journal on" <> _}, &1))

      # The scenario never noticed: still waiting, still stoppable.
      assert Process.alive?(pid)
      assert Control.shutdown_scenario(id) == :ok
      assert_receive {:kelix_traces, {:upsert, %{id: ^id, running: false}}}, 2_000
    end

    test "a scenario has one journal: `on` after `off` is refused" do
      {id, _pid} = spawn_waiter("debug-once.test")
      assert Control.debug_scenario(id, :on) == :ok
      assert Control.debug_scenario(id, :off) == :ok
      assert await_trace(id)

      assert Control.debug_scenario(id, :on) == {:error, :journal_written}
    end

    test "an unknown instance" do
      assert Control.debug_scenario(999_999, :on) == {:error, :not_found}
      assert Control.trace(999_999) == {:error, :not_found}
    end

    test "kelictl debug on / off / list / show, as a ladder or PlantUML" do
      {id, _pid} = spawn_waiter("debug-cli.test")
      run = &Kelix.Control.CLI.run(&1, node())

      assert {0, out} = run.(["debug", "#{id}", "on"])
      assert out =~ "journal on for scenario #{id}"
      assert {0, monitor} = run.(["monitor"])
      assert monitor =~ "#{id} ●" or await(fn -> traced?(id) end)

      assert {0, _} = run.(["debug", "#{id}", "off"])
      assert await_trace(id)

      assert {0, list} = run.(["debug", "list"])
      assert list =~ "debug-cli.test"
      assert list =~ "running"

      assert {0, ladder} = run.(["debug", "show", "#{id}"])
      assert ladder =~ "Scenario : KelixTest.Waiter"
      assert ladder =~ "journal on (initial_state)"
      refute ladder =~ "@startuml"

      assert {0, puml} = run.(["debug", "show", "--format-puml", "#{id}"])
      assert puml =~ ~r/^' Scenario/
      assert puml =~ "@enduml"

      assert {4, again} = run.(["debug", "#{id}", "on"])
      assert again =~ "already written"
      assert {3, _} = run.(["debug", "999999", "on"])
      assert {3, _} = run.(["debug", "show", "999999"])
      assert {2, _} = run.(["debug", "x", "on"])
      assert {2, usage} = run.(["debug", "sideways"])
      assert usage =~ "debug <id> on|off"
      assert {0, help} = run.(["debug", "help"])
      assert help =~ "max_trace_bytes"
    end
  end
end
