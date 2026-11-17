defmodule Kelix.DebugTriggersPoolTest do
  # The node's own store, claimed by the pool (debug-triggers-plan.md, T3): a
  # matching run starts with its journal on and is filed under `origin: :rule`,
  # a run the pool refuses consumes nothing, a domain that stops serving the
  # script takes the rule with it.
  use ExUnit.Case, async: false

  import Kelix.Test.Fixtures

  alias Kelix.{Control, DebugTriggers, InstancePool}

  @waiter Path.join(__DIR__, "support/scripts/waiter.exs")

  setup do
    dom = "trig-#{System.unique_integer([:positive])}.test"
    serve_domains(~s([[domain]]\nname = "#{dom}"\n[domain.registrar]\nscript = "#{@waiter}"))
    on_exit(fn -> DebugTriggers.remove(dom, @waiter) end)
    %{dom: dom}
  end

  defp route(dom, max_calls \\ nil),
    do: %{domain: dom, function: :registrar, script: @waiter, max_calls: max_calls}

  defp register(user, dom) do
    %{
      method: :REGISTER,
      from: "<sip:#{user}@#{dom}>;tag=1",
      to: "<sip:#{user}@#{dom}>",
      ruri: %SIP.Uri{domain: dom}
    }
  end

  defp spawn_run(dom, req) do
    assert {:accept, pid} = InstancePool.accept(route(dom), nil, req)
    on_exit(fn -> send(pid, {:scenario_ctl, :shutdown, :test}) end)
    %{id: id} = Enum.find(InstancePool.list(), &(&1.pid == pid))
    {id, pid}
  end

  defp await(fun) do
    Enum.reduce_while(1..100, nil, fn _i, _acc ->
      case fun.() do
        falsy when falsy in [nil, false] -> Process.sleep(20) && {:cont, nil}
        found -> {:halt, found}
      end
    end)
  end

  defp traced?(id),
    do: Enum.find_value(Control.monitor(), fn row -> row.id == id and row.traced end)

  defp kept(id) do
    await(fn ->
      case Control.trace(id) do
        {:ok, trace} -> trace
        _ -> nil
      end
    end)
  end

  test "a matching run is journaled from its first state, filed under the rule", %{dom: dom} do
    spec = %{count: 2, duration: "1h", filter: %{caller: "alice"}}
    {:ok, _} = DebugTriggers.set(dom, @waiter, spec, "test")

    {id, _pid} = spawn_run(dom, register("alice", dom))
    assert await(fn -> traced?(id) end)
    assert {:ok, %{remaining: 1}} = DebugTriggers.get(dom, @waiter)

    assert Control.shutdown_scenario(id) == :ok
    assert trace = kept(id)
    assert trace.origin == :rule
    assert trace.domain == dom
    assert Enum.any?(trace.events, &match?(%{kind: :transition, to: :initial_state}, &1))
  end

  test "kelictl debug list shows the journal under origin rule", %{dom: dom} do
    {:ok, _} = DebugTriggers.set(dom, @waiter, %{count: 1, duration: "1h"}, "test")
    {id, _pid} = spawn_run(dom, register("alice", dom))
    assert await(fn -> traced?(id) end)
    assert Control.shutdown_scenario(id) == :ok
    assert kept(id)

    assert {0, out} = Kelix.Control.CLI.run(["debug", "list"], node())
    assert out =~ "origin"
    assert out =~ ~r/^#{id}\s.*#{Regex.escape(dom)}\s.*waiter\.exs\s+rule\s/m
  end

  test "a run the filter does not match is not journaled and consumes nothing", %{dom: dom} do
    spec = %{count: 2, duration: "1h", filter: %{caller: "alice"}}
    {:ok, _} = DebugTriggers.set(dom, @waiter, spec, "test")

    {id, _pid} = spawn_run(dom, register("bob", dom))
    Process.sleep(100)
    refute traced?(id)
    assert {:ok, %{remaining: 2}} = DebugTriggers.get(dom, @waiter)
  end

  test "a request the pool refuses consumes nothing", %{dom: dom} do
    {:ok, _} = DebugTriggers.set(dom, @waiter, %{count: 1, duration: "1h"}, "test")

    assert {:reject, 503, _} = InstancePool.accept(route(dom, 0), nil, register("alice", dom))
    assert {:ok, %{remaining: 1}} = DebugTriggers.get(dom, @waiter)
  end

  test "the last run ends the rule", %{dom: dom} do
    {:ok, _} = DebugTriggers.set(dom, @waiter, %{count: 1, duration: "1h"}, "test")

    {id, _pid} = spawn_run(dom, register("alice", dom))
    assert await(fn -> traced?(id) end)
    assert DebugTriggers.get(dom, @waiter) == {:error, :not_found}

    {id2, _pid} = spawn_run(dom, register("alice", dom))
    Process.sleep(100)
    refute traced?(id2)
  end

  test "an operator's journal is filed under :operator", %{dom: dom} do
    {id, _pid} = spawn_run(dom, register("alice", dom))
    assert Control.debug_scenario(id, :on) == :ok
    assert Control.debug_scenario(id, :off) == :ok
    assert %{origin: :operator} = kept(id)
  end

  test "a domain that stops serving the script takes the rule with it", %{dom: dom} do
    {:ok, _} = DebugTriggers.set(dom, @waiter, %{count: 1, duration: "1h"}, "test")

    serve_domains(~s([[domain]]\nname = "#{dom}"\n[domain.registrar]\nscript = "other.exs"))
    assert DebugTriggers.get(dom, @waiter) == {:error, :not_found}
  end
end
