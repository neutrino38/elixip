# Phase 5: tests for the Elixip.ScenarioUAS factory (call server side) — domain
# check (604), concurrency quota (503), :any catch-all, and the backward-compat
# Elixip.RegistrarUAS alias. The domain/quota rejects need no live SIP stack
# (no instance is spawned); an accepted call spawns a blocking scenario instance.

defmodule UASFactoryFixture.Block do
  use SIP.Scenario
  uas(:invite)
  config(domains: ["example.com", "sip.example.com"])

  # Stay alive until shut down (the auto-injected {:scenario_ctl, :shutdown, _}
  # clause aborts us cooperatively).
  state initial_state do
    on_events do
      {:never, _ignored} -> scenario_failure("unexpected")
    after
      60_000 -> scenario_success("timeout")
    end
  end
end

defmodule UASFactoryFixture.CatchAll do
  use SIP.Scenario
  uas(:invite)
  config(domains: :any)

  state initial_state do
    on_events do
      {:never, _ignored} -> scenario_failure("unexpected")
    after
      60_000 -> scenario_success("timeout")
    end
  end
end

defmodule SIP.Test.ScenarioUASFactory do
  use ExUnit.Case

  defp start_factory(opts) do
    case Process.whereis(Elixip.ScenarioUAS) do
      nil -> :ok
      pid -> GenServer.stop(pid)
    end

    {:ok, _} = Elixip.ScenarioUAS.start_link(opts)
    :ok
  end

  defp invite(domain), do: %{method: :INVITE, ruri: %SIP.Uri{domain: domain}}

  test "on_new_call rejects a non-served domain with 604" do
    start_factory(scenario_module: UASFactoryFixture.Block, max_instances: 5)

    assert {:reject, 604, "Does Not Exist Anywhere"} =
             Elixip.ScenarioUAS.on_new_call(self(), invite("evil.com"), self())

    stats = Elixip.ScenarioUAS.stats()
    assert stats.total_rejected_domain == 1
    assert stats.active == 0
  end

  test "on_new_call accepts a served domain (case-insensitive match)" do
    start_factory(scenario_module: UASFactoryFixture.Block, max_instances: 5)

    assert {:accept, pid} =
             Elixip.ScenarioUAS.on_new_call(self(), invite("Example.COM"), self())

    assert is_pid(pid)
    assert Elixip.ScenarioUAS.stats().active == 1
    send(pid, {:scenario_ctl, :shutdown, :test})
  end

  test ":any is a catch-all domain" do
    start_factory(scenario_module: UASFactoryFixture.CatchAll, max_instances: 5)

    assert {:accept, pid} =
             Elixip.ScenarioUAS.on_new_call(self(), invite("anything.test"), self())

    send(pid, {:scenario_ctl, :shutdown, :test})
  end

  test "on_new_call enforces the max_instances quota with 503" do
    start_factory(scenario_module: UASFactoryFixture.Block, max_instances: 1)

    assert {:accept, pid1} =
             Elixip.ScenarioUAS.on_new_call(self(), invite("example.com"), self())

    assert {:reject, 503, "Service Unavailable"} =
             Elixip.ScenarioUAS.on_new_call(self(), invite("example.com"), self())

    stats = Elixip.ScenarioUAS.stats()
    assert stats.active == 1
    assert stats.total_started == 1
    assert stats.total_rejected_quota == 1

    send(pid1, {:scenario_ctl, :shutdown, :test})
  end

  test "max_run caps the total number of calls with 503" do
    start_factory(scenario_module: UASFactoryFixture.CatchAll, max_instances: 5, max_run: 1)

    assert {:accept, pid} =
             Elixip.ScenarioUAS.on_new_call(self(), invite("a.test"), self())

    assert {:reject, 503, _} =
             Elixip.ScenarioUAS.on_new_call(self(), invite("a.test"), self())

    send(pid, {:scenario_ctl, :shutdown, :test})
  end

  test "explicit :domains option overrides the scenario config" do
    start_factory(
      scenario_module: UASFactoryFixture.CatchAll,
      max_instances: 5,
      domains: "only.example"
    )

    assert {:reject, 604, _} =
             Elixip.ScenarioUAS.on_new_call(self(), invite("a.test"), self())

    assert {:accept, pid} =
             Elixip.ScenarioUAS.on_new_call(self(), invite("only.example"), self())

    send(pid, {:scenario_ctl, :shutdown, :test})
  end

  test "ConfigRegistry dispatches an inbound INVITE to ScenarioUAS.on_new_call" do
    {:ok, _} = SIP.Session.ConfigRegistry.start()
    start_factory(scenario_module: UASFactoryFixture.CatchAll, max_instances: 5)
    :ok = SIP.Session.ConfigRegistry.set_call_processing_module(Elixip.ScenarioUAS)

    # The dialog layer calls dispatch/3 for an inbound INVITE; it must reach
    # on_new_call/3 on the registered call processing module.
    assert {:accept, pid} =
             SIP.Session.ConfigRegistry.dispatch(self(), invite("x.test"), self())

    assert Elixip.ScenarioUAS.stats().active == 1
    send(pid, {:scenario_ctl, :shutdown, :test})
  end

  test "Elixip.RegistrarUAS alias delegates to the ScenarioUAS server" do
    start_factory(scenario_module: UASFactoryFixture.Block, max_instances: 5)

    assert is_map(Elixip.RegistrarUAS.stats())

    assert {:accept, pid} =
             Elixip.RegistrarUAS.on_new_registration(self(), %{method: :REGISTER}, self())

    # Same server: the accept is visible through both names.
    assert Elixip.ScenarioUAS.stats().active == 1
    send(pid, {:scenario_ctl, :shutdown, :test})
  end
end
