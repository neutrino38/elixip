defmodule Kelix.ControlTest do
  # Kelix.Control verbs (design §10.1). The :kelixip app is running, so the
  # surfaces (InstancePool, MediaPool, Domains, ScriptRegistry, ModuleRegistry)
  # are live singletons — empty at boot.
  use ExUnit.Case, async: false

  alias Kelix.Control

  # a valid registrar script that stays alive until told to shut down
  @waiter Path.join(__DIR__, "support/scripts/waiter.exs")

  # a module exposing a control command, and one without a control surface
  defmodule FakeCtl do
    def handle_control("ping", _args), do: {:ok, :pong}
    def handle_control(_cmd, _args), do: {:error, :unknown_cmd}
  end

  defmodule BareMod do
  end

  describe "module-contributed commands" do
    test "module_command/3 routes to the module's handle_control/2" do
      Kelix.ModuleRegistry.register("fake", FakeCtl, %{})
      on_exit(fn -> Kelix.ModuleRegistry.unregister("fake") end)

      assert Control.module_command("fake", "ping", %{}) == {:ok, :pong}
      assert Control.module_command("fake", "nope", %{}) == {:error, :unknown_cmd}
    end

    test "module_command/3 on a module without a control surface" do
      Kelix.ModuleRegistry.register("bare", BareMod, %{})
      on_exit(fn -> Kelix.ModuleRegistry.unregister("bare") end)

      assert Control.module_command("bare", "x", %{}) == {:error, :no_command_surface}
    end

    test "module_reload/1 on an unconfigured module" do
      assert Control.module_reload("registrar") == {:error, :not_configured}
    end
  end

  describe "read + simple verbs" do
    test "status/0 aggregates node + surfaces" do
      s = Control.status()
      assert s.node == node()
      assert is_integer(s.uptime_ms)
      assert is_map(s.instances)
      assert is_list(s.media_pool)
      assert is_list(s.modules)
    end

    # It used to read SIP.Scenario.Monitor — elixipp's --monitor store, which the
    # server never starts — so it was always empty and `kelictl stop <id>` had no
    # way to learn an id.
    # Instances of neighbouring tests may still be draining (the pool frees a slot
    # on an async :DOWN), so every assertion here is scoped to its own domain.
    defp spawn_watched(domain) do
      route = %{domain: domain, function: :registrar, script: @waiter, max_calls: nil}
      assert {:accept, pid} = Kelix.InstancePool.accept(route, nil, %{method: :REGISTER})
      on_exit(fn -> send(pid, {:scenario_ctl, :shutdown, :test}) end)
      pid
    end

    defp row_for(domain), do: Enum.find(Control.monitor(), &(&1.domain == domain))

    # The FSM store is fed by casts, so let the first transition land.
    defp await_state(domain) do
      Enum.reduce_while(1..50, nil, fn _i, _acc ->
        case row_for(domain) do
          %{state: s} = row when s != "" -> {:halt, row}
          _ -> Process.sleep(20) && {:cont, nil}
        end
      end)
    end

    test "monitor/0 lists the running instances, with the id `stop` takes" do
      pid = spawn_watched("mon.test")

      assert row = await_state("mon.test")
      assert row.function == :registrar
      assert is_integer(row.id)
      assert row.pid == pid

      # …joined with the FSM view: which state the scenario sits in, and on what
      # event. Reading that is the point of a DSL-driven server.
      assert row.state == "initial_state"
      assert row.scenario != ""

      # the id is usable as advertised
      assert Control.shutdown_scenario(row.id) == :ok
    end

    test "monitor/0 degrades to empty FSM columns rather than failing" do
      spawn_watched("nofsm.test")
      assert row = await_state("nofsm.test")

      # drop the FSM row: the pool still knows the instance, the join must not care
      SIP.Scenario.Monitor.clear(row.id)

      assert row = row_for("nofsm.test")
      assert row.state == ""
      assert row.command == ""
    end

    test "set_log_level/1 applies a valid level and rejects a bad one" do
      prev = Logger.level()
      on_exit(fn -> Logger.configure(level: prev) end)

      assert Control.set_log_level("debug") == :ok
      assert Logger.level() == :debug
      assert Control.set_log_level("nope") == {:error, :invalid_level}
    end

    test "reload_domains/0 needs a configured path" do
      prev = Application.get_env(:kelixip, :domains_path)
      Application.delete_env(:kelixip, :domains_path)
      on_exit(fn -> if prev, do: Application.put_env(:kelixip, :domains_path, prev) end)

      assert Control.reload_domains() == {:error, :no_domains_path}
    end

    test "reload_script/2 reports a per-name result" do
      res = Control.reload_script(["does-not-exist"])
      assert match?({:error, _}, res["does-not-exist"])
    end

    test "shutdown_scenario/1 on an unknown id" do
      assert Control.shutdown_scenario(999_999) == {:error, :not_found}
    end

    test "mediaserver_toggle/2 on an unknown MCU" do
      assert Control.mediaserver_toggle("ghost", false) == {:error, :unknown}
    end

    test "graceful_shutdown/0 drains without stopping the VM when suppressed" do
      Application.put_env(:kelixip, :graceful_stop, false)
      on_exit(fn -> Application.delete_env(:kelixip, :graceful_stop) end)

      assert Control.graceful_shutdown() == :ok
    end

    test "module_command/3 on an unknown module" do
      assert Control.module_command("ghost", "do", %{}) == {:error, :unknown_module}
    end
  end
end
