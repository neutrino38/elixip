defmodule SIP.Test.FSL.Standalone do
  @moduledoc """
  A state machine with **no protocol at all**: `use FSL.Machine`, no host, no
  binding, nothing started.

  This is what the extraction is for, and the one thing no other test in this
  repository can check — every scenario here is a SIP scenario, so a coupling
  that survives would survive unnoticed. Run against `FSL.Host.Default`, so
  every callback answers the least the machine needs: the context is a plain
  `%FSL.Context{}`, the `config` block goes to appdata, nothing is bootstrapped,
  no event hook fires, no clause is injected, and the teardown releases nothing.

  It is also the smoke test P3 needs: what compiles and runs here is what will
  compile and run once these modules are a package that does not depend on
  `:elixip2` (extraction plan §7, P3).
  """
  use ExUnit.Case, async: true

  # The language, whole: states, `goto next` / `loop` / `back`, `on_events` with
  # its selective receive, `stay`, appdata, `cleanup/1`, the terminals.
  defmodule Counter do
    use FSL.Machine

    config(target: 3, label: "counting")

    state initial_state do
      appdata_set(:seen, [])
      goto(next)
    end

    state counting do
      seen = appdata_get(:seen)

      if length(seen) >= appdata_get(:target) do
        goto(reporting)
      else
        on_events do
          {:tick, n} ->
            appdata_set(:seen, seen ++ [n])
            goto(loop)

          {:noise, _} ->
            stay("ignored")
        after
          5_000 -> scenario_failure("no tick")
        end
      end
    end

    state reporting do
      send(appdata_get(:probe), {:counted, appdata_get(:seen), fsl_ctx.currentstate})
      goto(next)
    end

    state done do
      scenario_success("counted to #{length(appdata_get(:seen))}")
    end

    def cleanup(fsl_ctx) do
      send(FSL.Context.appdata_get(fsl_ctx, :probe), :cleaned_up)
      :ok
    end
  end

  test "runs on FSL.Host.Default, with no protocol and nothing started" do
    test_pid = self()

    pid =
      spawn(fn ->
        send(
          test_pid,
          {:done, FSL.Runner.run_instance(Counter, appdata: %{probe: test_pid})}
        )
      end)

    # `stay` consumes an event and re-enters the same wait: the noise is dropped
    # and the ticks still all land.
    send(pid, {:noise, :ignore_me})
    for n <- 1..3, do: send(pid, {:tick, n})

    assert_receive {:counted, [1, 2, 3], :reporting}, 5_000
    assert_receive :cleaned_up, 5_000
    assert_receive {:done, :ok}, 5_000
  end

  test "the config block lands in appdata, because that is what the default host does" do
    ctx = FSL.Host.Default.build_context(target: 3, label: "counting")

    assert %FSL.Context{} = ctx
    assert FSL.Context.appdata_get(ctx, :target) == 3
    assert FSL.Context.appdata_get(ctx, :label) == "counting"
  end

  test "it names no host, so it gets the default one" do
    assert FSL.Host.of(Counter) == FSL.Host.Default
  end

  # The control protocol is the language's, so it works with no host: a machine
  # that never considered being stopped is still stoppable, which is what a
  # server draining needs.
  defmodule Waits do
    use FSL.Machine

    state initial_state do
      on_events do
        {:never, _} -> scenario_success("unreachable")
      after
        30_000 -> scenario_failure("timeout")
      end
    end
  end

  test "cooperative shutdown needs no host" do
    test_pid = self()
    pid = spawn(fn -> send(test_pid, {:done, FSL.Runner.run_instance(Waits)}) end)

    send(pid, {:scenario_ctl, :shutdown, :operator})
    assert_receive {:done, {:aborted, "shutdown"}}, 5_000
  end

  # …and no clause is injected for a failure domain that does not exist: a
  # machine with no media plane is not silently wound down by a media event.
  test "no host means no injected clause of a host's" do
    test_pid = self()
    pid = spawn(fn -> send(test_pid, {:done, FSL.Runner.run_instance(Waits)}) end)

    send(pid, {:ms_event, self(), :server_disconnected})
    refute_receive {:done, _}, 300

    send(pid, {:scenario_ctl, :shutdown, :operator})
    assert_receive {:done, {:aborted, _}}, 5_000
  end

  # The slot FSL keeps for the binding's own vocabulary is empty here, and the
  # language never looks inside it.
  test "__scenario_type__/0 is nil when no binding wrote in it" do
    assert Counter.__scenario_type__() == nil
    assert FSL.Loader.scenario_type(Counter) == nil
    # SIP's reading of "declared nothing" is `:uac`, and it lives on SIP's side.
    assert SIP.Scenario.Loader.scenario_type(Counter) == :uac
  end
end
