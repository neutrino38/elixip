defmodule SIP.Test.ScenarioEngine do
  use ExUnit.Case

  # ── Scenario fixtures (compiled once) ───────────────────────────────────────

  # Exercises goto next / goto <named> / goto loop, appdata accumulation across
  # loop iterations, and scenario_success. No SIP / media involved, so it runs
  # entirely in the calling process and finishes synchronously.
  defmodule Basic do
    use SIP.Scenario

    config username: "alice", domain: "example.com"

    state initial_state do
      appdata_set(:count, 0)
      goto next
    end

    state second do
      n = appdata_get(:count)
      appdata_set(:count, n + 1)

      if n < 2 do
        goto loop, "iteration #{n}"
      else
        goto third
      end
    end

    state third do
      scenario_success("looped #{appdata_get(:count)} times")
    end
  end

  defmodule Fails do
    use SIP.Scenario

    state initial_state do
      scenario_failure("boom")
    end
  end

  # A non-:ok lasterr makes the next `goto` abort the scenario as a failure.
  defmodule LastErrAborts do
    use SIP.Scenario

    state initial_state do
      ctx_set(:lasterr, {:error, :simulated})
      goto unreached
    end

    state unreached do
      scenario_success("should not happen")
    end
  end

  defmodule WithCleanup do
    use SIP.Scenario

    state initial_state do
      scenario_success("ok")
    end

    def cleanup(_sip_ctx) do
      # run_instance/1 runs in the calling (test) process, so this lands in the
      # test mailbox and can be asserted.
      send(self(), :cleanup_called)
      :ok
    end
  end

  # Uses on_events so the event type is inferred from the matched pattern.
  defmodule InferEvents do
    use SIP.Scenario

    config username: "alice", domain: "example.com"

    state initial_state do
      on_events do
        {:ms_event, _conn, _evt} -> goto holding, "media event"
        {code, _r, _t, _d} when is_integer(code) -> goto holding, "sip response"
      end
    end

    state holding do
      # Plain receive: stay until the test releases us, so the monitor can be
      # inspected before the terminal report overwrites the event type.
      receive do
        :stop -> scenario_success("ok")
      end
    end
  end

  # ── Tests ───────────────────────────────────────────────────────────────────

  test "runs the FSM through next / named / loop transitions to success" do
    assert Basic.run(false) == :ok
  end

  test "exposes the declared states in order" do
    assert Basic.__scenario_states__() == [:initial_state, :second, :third]
  end

  test "scenario_failure returns {:error, reason}" do
    assert Fails.run(false) == {:error, "boom"}
  end

  test "goto aborts as failure when lasterr is not :ok" do
    assert LastErrAborts.run(false) == {:error, {:error, :simulated}}
  end

  test "calls the optional cleanup/1 callback on termination" do
    assert WithCleanup.run(false) == :ok
    assert_received :cleanup_called
  end

  test "build_context applies config, computes ha1 and keeps unknown keys in appdata" do
    ctx =
      SIP.Scenario.Runner.build_context(
        username: "bob",
        authusername: "bob",
        domain: "ex.com",
        passwd: "secret",
        proxy: "p.ex.com"
      )

    assert ctx.username == "bob"
    assert ctx.domain == "ex.com"
    # :ha1 is derived from :passwd (which must be applied after authusername/domain).
    assert is_binary(ctx.ha1)
    # Non-native config keys are preserved in appdata.
    assert ctx.appdata[:proxy] == "p.ex.com"
    # Setting the username also generates the From tag.
    assert is_binary(ctx.ftag)
  end

  test "run(false) is reentrant: several instances reuse an already-started stack" do
    # Start the stack once, then run several independent instances. This is the
    # basis of the future SIPP-like parallel mode.
    assert SIP.Scenario.start_stack() == :ok
    assert Basic.run(false) == :ok
    assert Basic.run(false) == :ok
  end

  test "on_events infers the event type and feeds it to the monitor" do
    {:ok, _} = SIP.Scenario.Monitor.start()

    parent = self()
    pid = spawn(fn -> send(parent, {:done, InferEvents.run(false)}) end)
    # An :ms_event must be inferred as :media. Check before sending :stop, since
    # the terminal report would overwrite the event type.
    send(pid, {:ms_event, make_ref(), :ice_connected})
    assert wait_for_event_type(:media, 100) == :media

    send(pid, :stop)
    assert_receive {:done, :ok}, 2_000
  end

  defp wait_for_event_type(_type, 0), do: :timeout

  defp wait_for_event_type(type, attempts) do
    if Enum.any?(SIP.Scenario.Monitor.calls(), &(&1.event_type == type)) do
      type
    else
      Process.sleep(10)
      wait_for_event_type(type, attempts - 1)
    end
  end
end
