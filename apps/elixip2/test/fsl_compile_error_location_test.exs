defmodule SIP.Test.FSL.CompileErrorLocation do
  @moduledoc """
  A compile error still names the **scenario's own file and line** when the
  scenario was written against the facade rather than against the language.

  `use SIP.Scenario` is `use FSL.Machine` plus three session mixins, and every
  one of those is another layer of macro expansion between the author's file and
  the check that refuses their code. That is exactly how a location gets lost:
  each layer is an opportunity for an error to be reported against the module
  that expanded it instead of the module that wrote it. The checks themselves,
  and their behaviour under a bare `use FSL.Machine`, are the package's
  (`test/compile_error_location_test.exs`); what is asserted here is that
  crossing the facade costs nothing.

  Worth its own file rather than a line in the package's, because the failure it
  guards is a *deployment* failure: `.exs` scenarios and kelixip scripts are
  compiled at run time, from `/etc/kelixip/scripts` and from customer
  directories, and an operator staring at a `CompileError` that points into
  `FSL.Machine` has nothing to go on.
  """
  use ExUnit.Case

  @file_under_test "/etc/kelixip/scripts/operators_own_script.exs"

  defp compile_error!(source) do
    assert_raise CompileError, fn -> Code.compile_string(source, @file_under_test) end
  end

  test "`stay` outside an on_events, through use SIP.Scenario" do
    err =
      compile_error!("""
      defmodule Bad.StayInState do
        use SIP.Scenario

        config username: "alice", domain: "example.com"

        state initial_state do
          stay
        end
      end
      """)

    assert err.file == @file_under_test
    assert err.line == 7
    assert Exception.message(err) =~ "stay is only allowed in an on_events clause"
  end

  test "`sbb_fsm` inside an on_events clause, through use SIP.Scenario" do
    err =
      compile_error!("""
      defmodule Bad.SbbInClause do
        use SIP.Scenario

        state initial_state do
          on_events do
            {:INVITE, _r, _t, _d} ->
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

  test "an undeclared sbb_return outcome, through use SIP.SBB" do
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

  # A warning rather than an error, and the location matters for the same
  # reason: a scenario matching an old shape compiles and simply never wakes.
  test "a deprecated event shape warns at the script's own file and line" do
    warning =
      ExUnit.CaptureIO.capture_io(:stderr, fn ->
        Code.compile_string(
          """
          defmodule Bad.DeprecatedShapes do
            use SIP.Scenario

            state initial_state do
              on_events do
                {:scenario_msg, _name, _p} -> goto initial_state
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
    assert warning =~ "#{@file_under_test}:6"
  end
end
