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
end
