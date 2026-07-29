defmodule Elixipp.CLITest do
  use ExUnit.Case

  # CLI-level validation and option normalisation.
  # (Moved here from the framework's sequence_diagram_test when elixipp became
  # its own umbrella app — Elixipp.CLI lives in :elixipp, not :elixip2.)

  alias Elixipp.CLI

  describe "--log-sequence" do
    test "rejects --log-sequence with several simultaneous calls" do
      assert {:error, _} = CLI.validate_log_sequence([log_sequence: true], 2)
    end

    test "allows a single call (any --max-run)" do
      assert CLI.validate_log_sequence([log_sequence: true], 1) == :ok
      # Flag absent → always allowed.
      assert CLI.validate_log_sequence([], 5) == :ok
    end
  end

  describe "--max-run" do
    # Regression: 0 is documented as "no limit" (the only way to recycle slots
    # indefinitely with an explicit flag, e.g. to walk through every --config
    # account). It used to reach the run loops as 0, where `total_started < 0` is
    # never true, so a run started nothing at all and reported "Total : 0".
    test "0 means unlimited" do
      assert CLI.resolve_max_run(0) == nil
    end

    test "any other value is passed through" do
      assert CLI.resolve_max_run(1) == 1
      assert CLI.resolve_max_run(100) == 100
      assert CLI.resolve_max_run(nil) == nil
    end
  end

  describe "listener_report/1" do
    test "no failure: nothing to report" do
      assert CLI.listener_report([{{:udp, :all, 5060}, :ok}]) == {:ok, []}
    end

    test "a partial failure is reported but not fatal" do
      started = [{{:udp, :all, 5060}, :ok}, {{:tcp, :all, 80}, {:error, :eacces}}]
      assert {:ok, [msg]} = CLI.listener_report(started)
      assert msg =~ "tcp sur *:80"
      assert msg =~ "permission refusée"
    end

    test "all listeners down is fatal, and says why for each" do
      started = [
        {{:tcp, {127, 0, 0, 1}, 5060}, {:error, :eaddrinuse}},
        {{:tls, :all, 5061}, {:error, :enoent}}
      ]

      assert {:fatal, [busy, cert]} = CLI.listener_report(started)
      assert busy =~ "tcp sur 127.0.0.1:5060"
      assert busy =~ "déjà utilisé"
      assert cert =~ "certificat"
    end

    test "an unexpected error shape still yields a message" do
      assert {:fatal, [msg]} = CLI.listener_report([{{:wss, :all, 5065}, {:error, {:tls, :bad}}}])
      assert msg =~ "wss sur *:5065"
    end
  end

  describe "server_scenario_overrides/1" do
    # A UAS shares one set of credentials across every instance (there is no run
    # counter to cycle accounts on), and this is the documented way to give the
    # reference registrar scenario the password it must verify. It used to be
    # dropped in server mode, which made a real digest check unreachable.
    test "no --config: no override" do
      assert CLI.server_scenario_overrides(nil) == []
    end

    test "the header and the first account reach the instances" do
      path =
        Path.join(System.tmp_dir!(), "elixipp_uas_cfg_#{System.unique_integer([:positive])}.json")

      File.write!(path, """
      {
        "domain": "example.com",
        "accounts": [
          { "username": "alice", "password": "s3cret" },
          { "username": "bob", "password": "other" }
        ]
      }
      """)

      on_exit(fn -> File.rm(path) end)

      overrides = CLI.server_scenario_overrides(SIP.Scenario.ExternalConfig.load!(path))

      # :passwd (a client's own credential, turned into the ha1 of *our* identity
      # by the context) is re-keyed to :password — the shared secret a registrar
      # verifies an incoming digest against, read from appdata by the scenario.
      assert Keyword.get(overrides, :password) == "s3cret"
      refute Keyword.has_key?(overrides, :passwd)
      assert Keyword.get(overrides, :username) == "alice"
      assert Keyword.get(overrides, :domain) == "example.com"
    end
  end
end
