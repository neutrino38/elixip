defmodule SIP.Test.FSL.CtxVar do
  @moduledoc """
  The language no longer spells the context variable in its own source.

  A scenario reads `sip_ctx` because it is holding a SIP session; an XMPP one
  would read `xmpp_ctx`, a chatbot `bot_ctx`. What had to go is not the name —
  deployed kelixip scripts write `sip_ctx` twelve times in `registrar.exs` and
  seventeen in `mcu.exs`, and the name is right for what they hold — but the
  assumption that there is only one (extraction plan §4.2).

  The SIP scenarios of this suite are the proof that the *default path* is
  unchanged; this file is the proof that it is a path and not the only one. The
  machine below binds `bot_ctx`, drives the same runner, and uses only the
  language's own verbs — which is exactly what a second binding would do before
  it has verbs of its own.
  """
  use ExUnit.Case

  # `use FSL.Context, ctx_var: :bot_ctx` first, so the name is recorded before
  # the SIP context (which would name `sip_ctx`) is pulled in by SIP.Scenario.
  # After P2 this is `use FSL.Machine, ctx_var: :bot_ctx` and the SIP half is
  # not in the picture at all.
  defmodule Bot do
    use FSL.Context, ctx_var: :bot_ctx
    use SIP.Scenario

    config(username: "bot", domain: "example.com")

    state initial_state do
      appdata_set(:steps, [:initial_state])
      goto(next)
    end

    state thinking do
      appdata_set(:steps, appdata_get(:steps) ++ [:thinking])
      ctx_set(:lasterr, :ok)
      goto(waiting)
    end

    state waiting do
      on_events do
        {:parent_msg, :go} ->
          appdata_set(:steps, appdata_get(:steps) ++ [:waiting])
          goto(done)

        {:parent_msg, :again} ->
          stay("asked again")
      after
        5_000 -> scenario_failure("nobody said go")
      end
    end

    state done do
      # The context is reachable by its own name, in a state body, exactly as
      # `sip_ctx` is in a SIP scenario.
      send(appdata_get(:probe), {:steps, bot_ctx.appdata.steps, bot_ctx.currentstate})
      scenario_success("walked #{length(appdata_get(:steps))} states")
    end
  end

  test "a machine that calls its context bot_ctx runs on the same engine" do
    test_pid = self()

    pid =
      spawn(fn ->
        send(
          test_pid,
          {:done, SIP.Scenario.Runner.run_instance(Bot, appdata: %{probe: test_pid})}
        )
      end)

    # `stay` re-enters the wait, on the context the clause produced — the one
    # piece of the language that has to name the variable twice.
    send(pid, {:parent_msg, :again})
    send(pid, {:parent_msg, :go})

    assert_receive {:steps, [:initial_state, :thinking, :waiting], :done}, 5_000
    assert_receive {:done, :ok}, 5_000
  end

  test "the SIP scenarios of this repository still bind sip_ctx" do
    # The default path, stated rather than assumed: every scenario in the suite
    # depends on it, and a change to SIP.Context's `ctx_var:` would break them
    # all at once with no test naming the cause.
    defmodule PlainSip do
      use SIP.Scenario

      state initial_state do
        scenario_success(inspect(sip_ctx.currentstate))
      end
    end

    assert SIP.Scenario.Runner.run_instance(PlainSip) == :ok
  end
end
