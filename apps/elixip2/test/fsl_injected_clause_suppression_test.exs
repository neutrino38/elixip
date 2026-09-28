defmodule SIP.Test.FSL.InjectedClauseSuppression do
  @moduledoc """
  The **suppression rule** for the clauses `on_events` injects into every wait.

  Two families are injected today: the cooperative-shutdown clause
  (`{:scenario_ctl, :shutdown, _}`, the FSM control protocol) and the
  media-death clause (`{:ms_event, _, :server_disconnected}`). Each is
  suppressed when the scenario's own clauses already catch what it is for — but
  **not by the same test**, and the difference is the point.

  The media clause is a policy default, so its suppression is deliberately
  generous: a clause matching every media event, or a catch-all, is enough.
  Erring that way leaves the scenario in charge, which is the safe direction —
  the default exists for scenarios that never considered the case, not to
  overrule those that did.

  The shutdown clause is the FSM control protocol, so only an explicit
  `:scenario_ctl` clause opts out of it: it is prepended ahead of a possible
  catch-all, and a scenario that merely writes `event -> ...` has not thereby
  declined to be stoppable. That asymmetry is what the split has to preserve —
  the shutdown clause stays FSL's, the media clause becomes the host's.

  `media_server_down_test` proves the media clause *fires*, and that an explicit
  or a generic media clause keeps control. What is pinned here is the rule
  itself, both families, including the three cases nothing covered: a catch-all
  over the media clause, a guarded generic media clause, and a catch-all facing
  the shutdown clause — which it does not suppress. The extraction turns this into
  `c:injected_clauses/0` + `c:clause_covers?/2`
  (finite-state-language/elixir/docs/extraction-plan.md §4.5), reimplementing
  exactly this generosity — so it is worth having it written down as clauses
  rather than as a comment.
  """
  use ExUnit.Case

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    :ok
  end

  # ── media death ─────────────────────────────────────────────────────────────

  # A catch-all catches this too. Nothing covered this case, and it is the one a
  # scenario writer reaches for when the event list grows.
  defmodule CatchAll do
    use SIP.Scenario

    state initial_state do
      on_events do
        event -> scenario_success("caught #{inspect(event)} myself")
      after
        30_000 -> scenario_failure("clause never ran")
      end
    end
  end

  # A generic media clause behind a guard. Still generic — the pattern is what
  # is read, and it matches every media event — so the scenario keeps control
  # and its own guard decides. The guard failing means the event falls through
  # to the `after`, which is the scenario's business, not the framework's.
  defmodule GuardedGeneric do
    use SIP.Scenario

    state initial_state do
      on_events do
        {:ms_event, _ref, event} when event == :server_disconnected ->
          scenario_success("handled it under a guard")
      after
        30_000 -> scenario_failure("clause never ran")
      end
    end
  end

  # A media clause for ANOTHER event. Nothing here catches a server going away,
  # so the default must still be injected.
  defmodule OtherMediaEvent do
    use SIP.Scenario

    state initial_state do
      on_events do
        {:ms_event, _ref, :ice_connected} -> scenario_success("wrong event")
      after
        30_000 -> scenario_failure("waited for media that never came")
      end
    end
  end

  # ── cooperative shutdown ────────────────────────────────────────────────────

  # Handles the control message itself: the injected clause must not be
  # prepended ahead of it, or the scenario's own reaction would never run.
  defmodule OwnShutdown do
    use SIP.Scenario

    state initial_state do
      on_events do
        {:scenario_ctl, :shutdown, reason} -> scenario_success("mine: #{inspect(reason)}")
      after
        30_000 -> scenario_failure("clause never ran")
      end
    end
  end

  # Considers neither: both injected clauses are present, and each leaves the
  # state by construction.
  defmodule Oblivious do
    use SIP.Scenario

    state initial_state do
      on_events do
        {:parent_msg, _p} -> scenario_success("unrelated")
      after
        30_000 -> scenario_failure("nothing woke this wait")
      end
    end
  end

  defp run(module) do
    test_pid = self()
    spawn(fn -> send(test_pid, {:done, SIP.Scenario.Runner.run_instance(module, [])}) end)
  end

  describe "the media-death clause" do
    test "a catch-all suppresses it" do
      pid = run(CatchAll)
      send(pid, {:ms_event, self(), :server_disconnected})
      assert_receive {:done, :ok}, 5_000
    end

    test "a generic media clause behind a guard suppresses it" do
      pid = run(GuardedGeneric)
      send(pid, {:ms_event, self(), :server_disconnected})
      assert_receive {:done, :ok}, 5_000
    end

    test "a clause for another media event does not" do
      pid = run(OtherMediaEvent)
      send(pid, {:ms_event, self(), :server_disconnected})

      # The injected clause took it: :aborted, not :ok and not a timeout.
      assert_receive {:done, {:aborted, _reason}}, 5_000
    end

    test "no media clause at all: the default fires" do
      pid = run(Oblivious)
      send(pid, {:ms_event, self(), :server_disconnected})
      assert_receive {:done, {:aborted, _reason}}, 5_000
    end
  end

  describe "the cooperative-shutdown clause" do
    test "a scenario handling :scenario_ctl itself keeps control" do
      pid = run(OwnShutdown)
      send(pid, {:scenario_ctl, :shutdown, :operator})
      assert_receive {:done, :ok}, 5_000
    end

    test "one that does not is wound down as :aborted" do
      pid = run(Oblivious)
      send(pid, {:scenario_ctl, :shutdown, :operator})
      assert_receive {:done, {:aborted, _reason}}, 5_000
    end

    # The asymmetry with the media clause, and it is deliberate: the shutdown
    # clause is PREPENDED, ahead of a possible catch-all, and only an explicit
    # `:scenario_ctl` clause opts out of it. A controller asking a scenario to
    # stop is the FSM control protocol, not a policy default — a scenario that
    # happens to write `event -> ...` has not thereby declined to be stoppable,
    # and one that could not be stopped would be a node that cannot drain.
    #
    # This is the half of the rule that stays FSL's after the split, so the
    # asymmetry is what has to be carried across, not tidied away.
    test "a catch-all does NOT suppress it: the control protocol is not a default" do
      pid = run(CatchAll)
      send(pid, {:scenario_ctl, :shutdown, :operator})
      assert_receive {:done, {:aborted, "shutdown"}}, 5_000
    end
  end

  # Both injected families leave the state by construction, which is why they
  # are instrumented without the `stay` rewrite and produce no dead-branch
  # warning. `stay` in an injected clause would be a wait with nothing to
  # re-enter; that neither of them can is a property of the injection, and a
  # scenario compiling without warnings is how it is visible.
  test "injecting both clauses into a scenario compiles clean" do
    # Oblivious carries both injections in its single on_events. Compiling it
    # (done at module definition above) emitting no warning is the assertion;
    # this test states the intent and keeps the module referenced.
    assert :initial_state in Oblivious.__scenario_states__()
  end
end
