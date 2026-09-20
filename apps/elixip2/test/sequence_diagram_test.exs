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
    %{kind: :command, type: :media, name: "media_connect"},
    %{kind: :transition, to: :calling, event: "", type: nil},
    %{kind: :command, type: :sip, name: "send_INVITE"},
    %{kind: :transition, to: :answered, event: "200 OK", type: :sip},
    %{kind: :command, type: :media, name: "media_play"},
    %{kind: :transition, to: :playing, event: "media connected", type: :media},
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
    # Terminal outcome.
    assert out =~ "succeeded: answered"
  end

  test "renders media commands and events against a media-server lane" do
    out = SequenceDiagram.to_plantuml(@events, @meta)

    # The media lane is declared as a `control`, only because media was touched.
    assert out =~ ~s(control "media server" as ms)
    # Media command → outbound colored arrow (the media_ prefix is stripped).
    assert out =~ "elixip -[#DarkOrange]> ms : connect"
    assert out =~ "elixip -[#DarkOrange]> ms : play"
    # Media event → colored arrow from the media server.
    assert out =~ "ms -[#DarkOrange]> elixip : media connected"
  end

  test "omits the media lane when no media is involved" do
    sip_only = [
      %{kind: :transition, to: :initial_state, event: "start", type: nil},
      %{kind: :command, type: :sip, name: "send_INVITE"},
      %{kind: :terminal, outcome: :succeeded, reason: "ok", type: :sip}
    ]

    refute SequenceDiagram.to_plantuml(sip_only, @meta) =~ "as ms"
  end

  test "masks secrets in the configuration header and never leaks them" do
    out = SequenceDiagram.to_plantuml(@events, @meta)

    assert out =~ "passwd: ****"
    refute out =~ "s3cret"
    # Non-secret config is shown.
    assert out =~ "username:"
  end

  test "auth command names keep an (auth) suffix" do
    out =
      SequenceDiagram.to_plantuml(
        [%{kind: :command, type: :sip, name: "send_auth_REGISTER"}],
        @meta
      )

    assert out =~ "elixip -> peer : REGISTER (auth)"
  end

  test "builds a filename with a sanitized pid" do
    assert SequenceDiagram.filename(@meta) == "UAC.Invite_0.123.0.puml"
    assert SequenceDiagram.safe_pid("#PID<0.987.2>") == "0.987.2"
  end

  # ── Real SIP messages (recorded by SIP.Scenario.SipTrace) ───────────────────

  @t0 1_000_000

  defp sip(at_ms, dir, fields) do
    Map.merge(
      %{
        kind: :sip,
        at: @t0 + at_ms * 1_000,
        dir: dir,
        method: nil,
        code: nil,
        reason: nil,
        cseq: nil,
        callid: "c1",
        peer: "10.0.0.1:5060/udp",
        tag: nil,
        retransmit: false,
        sdp: false
      },
      fields
    )
  end

  @traced_meta Map.put(@meta, :t0, @t0)

  defp traced_events do
    [
      %{kind: :transition, at: @t0, to: :initial_state, event: "start", type: nil},
      %{kind: :command, at: @t0 + 1_000, type: :sip, name: "send_INVITE"},
      sip(2, :out, %{method: :INVITE, cseq: "1 INVITE", sdp: true}),
      sip(502, :out, %{method: :INVITE, cseq: "1 INVITE", sdp: true, retransmit: true}),
      sip(600, :in, %{code: 180, reason: "Ringing", cseq: "1 INVITE"}),
      sip(900, :in, %{code: 200, reason: "OK", cseq: "1 INVITE", sdp: true}),
      %{kind: :transition, at: @t0 + 901_000, to: :answered, event: "200 OK", type: :sip},
      sip(902, :out, %{method: :ACK, cseq: "1 ACK"}),
      sip(950, :out, %{
        method: :INVITE,
        cseq: "1 INVITE",
        callid: "c2",
        tag: :outbound,
        peer: "10.0.0.9:5060/tcp"
      }),
      %{kind: :terminal, at: @t0 + 2_000_000, outcome: :succeeded, reason: "ok", type: :sip}
    ]
  end

  test "one participant per Call-ID, labelled with the leg tag and the peer" do
    out = SequenceDiagram.to_plantuml(traced_events(), @traced_meta)

    assert out =~ ~s(participant "10.0.0.1:5060/udp" as peer1)
    assert out =~ ~s(participant "outbound 10.0.0.9:5060/tcp" as peer2)
    refute out =~ "as peer\n"
    # The header names the Call-ID behind each lane.
    assert out =~ "'   peer1: 10.0.0.1:5060/udp — Call-ID c1"
    assert out =~ "'   peer2: outbound 10.0.0.9:5060/tcp — Call-ID c2"
  end

  test "real messages are arrows: solid requests, dashed responses, grey retransmissions" do
    out = SequenceDiagram.to_plantuml(traced_events(), @traced_meta)

    assert out =~ "elixip -> peer1 : +2ms INVITE #1 +SDP"
    assert out =~ "elixip -[#Gray]> peer1 : +502ms INVITE #1 +SDP (retransmission)"
    assert out =~ "peer1 --> elixip : +600ms 180 Ringing / 1 INVITE"
    assert out =~ "peer1 --> elixip : +900ms 200 OK / 1 INVITE +SDP"
    assert out =~ "elixip -> peer1 : +902ms ACK #1"
    assert out =~ "elixip -> peer2 : +950ms INVITE #1"
  end

  test "with real messages, commands become notes and transitions stop drawing arrows" do
    out = SequenceDiagram.to_plantuml(traced_events(), @traced_meta)

    assert out =~ "hnote over elixip : +1ms send_INVITE"
    refute out =~ "elixip -> peer :"
    refute out =~ "elixip <-- peer"
    assert out =~ "note over elixip : +901ms initial_state -> answered"
    assert out =~ "note over elixip #LightGreen : +2000ms succeeded: ok"
  end

  test "events without a clock carry no time prefix" do
    out = SequenceDiagram.to_plantuml(@events, @meta)
    refute out =~ "+0ms"
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

    assert Enum.map(SequenceJournal.events(), &Map.delete(&1, :at)) == [
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

  # ── End-to-end: a scenario run writes the .puml file ────────────────────────

  defmodule SeqScenario do
    use SIP.Scenario

    config(username: "alice", authusername: "alice", domain: "example.com", passwd: "s3cret")

    state initial_state do
      # Call the raw monitor hooks directly so the journal records commands
      # without needing the SIP stack / media server / network.
      SIP.Scenario.Monitor.note_command(:media, "media_connect")
      goto(next)
    end

    state calling do
      SIP.Scenario.Monitor.note_command(:sip, "send_INVITE")
      goto(wait, "INVITE sent")
    end

    state wait do
      scenario_success("answered")
    end
  end

  test "a scenario run with --log-sequence enabled writes the PlantUML file" do
    path =
      SequenceDiagram.filename(%{
        scenario: "SIP.Test.SequenceDiagram.SeqScenario",
        pid: inspect(self())
      })

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
    # Every label opens with the time since the journal started.
    assert content =~ ~r/elixip -> peer : \+\d+ms INVITE/
    assert content =~ ~r/elixip -\[#DarkOrange\]> ms : \+\d+ms connect/
    assert content =~ ~r/note over elixip : \+\d+ms initial_state -> calling/
    assert content =~ "passwd: ****"
    refute content =~ "s3cret"

    File.rm(path)
  end
end
