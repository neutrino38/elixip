defmodule SIP.Test.SequenceDiagram do
  use ExUnit.Case

  alias SIP.Scenario.SequenceDiagram
  alias SIP.Scenario.SequenceJournal

  # ── Pure formatter (SequenceDiagram) ────────────────────────────────────────

  @meta %{
    scenario: "UAC.Invite",
    pid: "#PID<0.123.0>",
    config: [username: "alice", domain: "example.com", passwd: "s3cret"]
  }

  @events [
    %{kind: :transition, to: :initial_state, event: "start", type: nil},
    %{kind: :transition, to: :calling, event: "", type: nil},
    %{kind: :command, type: :sip, name: "send_INVITE"},
    %{kind: :transition, to: :answered, event: "200 OK", type: :sip},
    %{kind: :command, type: :media, name: "media_play"},
    %{kind: :terminal, outcome: :succeeded, reason: "answered", type: :sip}
  ]

  test "renders a well-formed PlantUML document" do
    out = SequenceDiagram.to_plantuml(@events, @meta)

    assert out =~ "@startuml"
    assert out =~ "@enduml"
    # Both participants are declared (the README example forgot `elixip`).
    assert out =~ ~s(participant "alice" as elixip)
    assert out =~ ~s(participant "example.com" as peer)
  end

  test "renders commands, transitions and the terminal outcome" do
    out = SequenceDiagram.to_plantuml(@events, @meta)

    # Outbound SIP command → request arrow with the bare method name.
    assert out =~ "elixip -> peer : INVITE"
    # A :sip transition carrying a description → inbound arrow.
    assert out =~ "elixip <-- peer : 200 OK"
    # First transition is the initial-state note; later ones are from -> to.
    assert out =~ "note over elixip : initial_state"
    assert out =~ "note over elixip : calling -> answered"
    # Media command rendered as a self-note (no SIP peer).
    assert out =~ "note over elixip : media_play"
    # Terminal outcome.
    assert out =~ "succeeded: answered"
  end

  test "masks secrets in the configuration header and never leaks them" do
    out = SequenceDiagram.to_plantuml(@events, @meta)

    assert out =~ "passwd: ****"
    refute out =~ "s3cret"
    # Non-secret config is shown.
    assert out =~ "username:"
  end

  test "auth command names keep an (auth) suffix" do
    out = SequenceDiagram.to_plantuml([%{kind: :command, type: :sip, name: "send_auth_REGISTER"}], @meta)
    assert out =~ "elixip -> peer : REGISTER (auth)"
  end

  test "builds a filename with a sanitized pid" do
    assert SequenceDiagram.filename(@meta) == "UAC.Invite_0.123.0.puml"
    assert SequenceDiagram.safe_pid("#PID<0.987.2>") == "0.987.2"
  end

  # ── Journal collection (SequenceJournal) ────────────────────────────────────

  test "collects events in chronological order while enabled" do
    refute SequenceJournal.enabled?()

    :ok = SequenceJournal.start(@meta)
    assert SequenceJournal.enabled?()

    SequenceJournal.record_transition(:initial_state, "start", nil)
    SequenceJournal.record_command(:sip, "send_INVITE")
    SequenceJournal.record_transition(:answered, "200 OK", :sip)
    SequenceJournal.record_transition(:succeeded, "done", :sip)

    assert SequenceJournal.events() == [
             %{kind: :transition, to: :initial_state, event: "start", type: nil},
             %{kind: :command, type: :sip, name: "send_INVITE"},
             %{kind: :transition, to: :answered, event: "200 OK", type: :sip},
             %{kind: :terminal, outcome: :succeeded, reason: "done", type: :sip}
           ]

    :ok = SequenceJournal.clear()
    refute SequenceJournal.enabled?()
    assert SequenceJournal.events() == []
  end

  test "recording is a no-op when no journal is started" do
    SequenceJournal.clear()
    assert SequenceJournal.record_command(:sip, "send_INVITE") == :ok
    assert SequenceJournal.record_transition(:calling, "", nil) == :ok
    assert SequenceJournal.events() == []
  end

  # ── CLI validation (single-call constraint) ─────────────────────────────────

  test "validate_log_sequence rejects --log-sequence with several simultaneous calls" do
    assert {:error, _} = Elixipp.CLI.validate_log_sequence([log_sequence: true], 2)
  end

  test "validate_log_sequence allows a single call (any --max-run)" do
    assert Elixipp.CLI.validate_log_sequence([log_sequence: true], 1) == :ok
    # Flag absent → always allowed.
    assert Elixipp.CLI.validate_log_sequence([], 5) == :ok
  end

  # ── End-to-end: a scenario run writes the .puml file ────────────────────────

  defmodule SeqScenario do
    use SIP.Scenario

    config username: "alice", authusername: "alice", domain: "example.com", passwd: "s3cret"

    state initial_state do
      goto next
    end

    state calling do
      # Call the raw monitor hook directly so the journal records a command
      # without needing the SIP stack / network.
      SIP.Scenario.Monitor.note_command(:sip, "send_INVITE")
      goto wait, "INVITE sent"
    end

    state wait do
      scenario_success("answered")
    end
  end

  test "a scenario run with --log-sequence enabled writes the PlantUML file" do
    path = SequenceDiagram.filename(%{scenario: "SIP.Test.SequenceDiagram.SeqScenario", pid: inspect(self())})
    File.rm(path)

    Application.put_env(:elixip2, :log_sequence, true)

    try do
      # Runs synchronously in this (test) process, so the file pid is self().
      assert SeqScenario.run(false) == :ok
    after
      Application.delete_env(:elixip2, :log_sequence)
    end

    assert File.exists?(path)
    content = File.read!(path)
    assert content =~ "@startuml"
    assert content =~ "@enduml"
    assert content =~ "elixip -> peer : INVITE"
    assert content =~ "note over elixip : initial_state -> calling"
    assert content =~ "passwd: ****"
    refute content =~ "s3cret"

    File.rm(path)
  end
end
