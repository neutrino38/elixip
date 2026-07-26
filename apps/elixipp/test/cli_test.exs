defmodule Elixipp.CLITest do
  use ExUnit.Case

  # CLI-level validation of the --log-sequence single-call constraint.
  # (Moved here from the framework's sequence_diagram_test when elixipp became
  # its own umbrella app — Elixipp.CLI lives in :elixipp, not :elixip2.)

  test "validate_log_sequence rejects --log-sequence with several simultaneous calls" do
    assert {:error, _} = Elixipp.CLI.validate_log_sequence([log_sequence: true], 2)
  end

  test "validate_log_sequence allows a single call (any --max-run)" do
    assert Elixipp.CLI.validate_log_sequence([log_sequence: true], 1) == :ok
    # Flag absent → always allowed.
    assert Elixipp.CLI.validate_log_sequence([], 5) == :ok
  end
end
