defmodule SIP.Test.FSL.CompileErrorLocation do
  @moduledoc """
  **Where a compile error points.**

  Four of FSL's checks run at macro-expansion time and refuse a scenario before
  it ever runs: `stay` outside an `on_events`, `sbb_fsm` inside a clause, an
  `sbb_return` naming an outcome its block does not declare, and the 1.4 event
  shapes nothing sends any more. Each of them exists for one reason — the
  failure it prevents is silent. A mistyped `sbb_return` outcome is not a crash,
  it is a host sitting on its `after` waiting for an event nobody will ever
  send: thirty seconds of nothing, with nothing in the log.

  A check like that is only worth having if its message names **the scenario's
  own file and line**. Crossing a package boundary is exactly how that gets
  lost: a `CompileError` pointing into `FSL.Machine` rather than into the `.exs`
  the operator is editing would undo the reason these checks exist
  (finite-state-language/elixir/docs/extraction-plan.md §4.13, §5.2). So the
  location is asserted here, before the move, and must still hold after it.

  The scenarios are compiled from strings under a made-up path, which is what
  makes "the error names the caller's file" checkable at all: the string's path
  is one no test file could otherwise produce.
  """
  use ExUnit.Case

  @file_under_test "/scenarios/operators_own_script.exs"

  # Compile `source` as if it lived at @file_under_test, and return the error it
  # raised. `Code.compile_string/2` is the only way to choose the file a macro's
  # `__CALLER__` reports.
  defp compile_error!(source) do
    assert_raise CompileError, fn -> Code.compile_string(source, @file_under_test) end
  end

  # Each source is written with the offending construct on a known line, counted
  # from the leading newline of the heredoc — hence the explicit line numbers
  # below rather than a search.

  test "`stay` outside an on_events names the state's file and the stay's line" do
    err =
      compile_error!("""
      defmodule Bad.StayInState do
        use SIP.Scenario

        state initial_state do
          stay
        end
      end
      """)

    assert err.file == @file_under_test
    assert err.line == 5
    assert Exception.message(err) =~ "stay is only allowed in an on_events clause"
    # …and it says which state, so a scenario with twenty of them is actionable.
    assert Exception.message(err) =~ "state initial_state"
  end

  test "`stay` in an on_shutdown block does too" do
    err =
      compile_error!("""
      defmodule Bad.StayInShutdown do
        use SIP.Scenario

        state initial_state do
          scenario_success("x")
        end

        on_shutdown do
          stay
        end
      end
      """)

    assert err.file == @file_under_test
    assert err.line == 9
    assert Exception.message(err) =~ "on_shutdown block"
  end

  test "`sbb_fsm` inside an on_events clause names the clause's line" do
    err =
      compile_error!("""
      defmodule Bad.SbbInClause do
        use SIP.Scenario

        state initial_state do
          on_events do
            {:parent_msg, _p} ->
              sbb_fsm SomeBlock
              goto initial_state
          after
            100 -> scenario_failure("t")
          end
        end
      end
      """)

    assert err.file == @file_under_test
    assert err.line == 6
    assert Exception.message(err) =~ "sbb_fsm is only allowed in a state body"
  end

  test "an sbb_return outcome the block does not declare names its line" do
    err =
      compile_error!("""
      defmodule Bad.UndeclaredOutcome do
        use SIP.SBB

        @sbb_namespace :probe
        @sbb_returns [ok: "the only outcome this block declares"]

        state initial_state do
          sbb_return({:probe, :not_declared, %{}})
        end
      end
      """)

    assert err.file == @file_under_test
    assert err.line == 8
    assert Exception.message(err) =~ "not_declared"
  end

  test "an sbb_return of a bare atom is refused, with a location" do
    err =
      compile_error!("""
      defmodule Bad.BareReturn do
        use SIP.SBB

        @sbb_namespace :probe
        @sbb_returns [ok: "fine"]

        state initial_state do
          sbb_return(:ok)
        end
      end
      """)

    assert err.file == @file_under_test
    assert Exception.message(err) =~ "{namespace, outcome, data}"
  end

  # The deprecated shapes are a *warning*, not an error: a scenario matching one
  # compiles and simply never wakes. The location matters for the same reason,
  # and `IO.warn` carries it the same way.
  test "a deprecated event shape warns at the clause's file and line" do
    warning =
      ExUnit.CaptureIO.capture_io(:stderr, fn ->
        Code.compile_string(
          """
          defmodule Bad.DeprecatedShapes do
            use SIP.Scenario

            state initial_state do
              on_events do
                {:scenario_msg, _name, _p} -> goto initial_state
                {:scenario_exit, _name, _o, _r} -> goto initial_state
              after
                100 -> scenario_failure("t")
              end
            end
          end
          """,
          @file_under_test
        )
      end)

    assert warning =~ "{:scenario_msg, …} is no longer sent"
    assert warning =~ "{:scenario_exit, …} is no longer sent"
    # Both point at the clause that is wrong, in the operator's file.
    assert warning =~ "#{@file_under_test}:6"
    assert warning =~ "#{@file_under_test}:7"
  end
end
