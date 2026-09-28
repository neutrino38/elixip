defmodule Kelix.Control.LadderTest do
  # kelictl's text ladder of a kept journal, drawn from FSL.Journal events.
  use ExUnit.Case, async: true

  alias Kelix.Control.Ladder

  @meta %{scenario: "UAC.Invite", pid: "#PID<0.1.0>", t0: 0, config: [username: "1000"]}

  defp msg(at_ms, dir, lane, label, opts \\ []) do
    Map.merge(
      %{
        kind: :message,
        at: at_ms * 1000,
        dir: dir,
        lane: lane,
        party: nil,
        peer: "10.0.0.1:5060/udp",
        label: label,
        reply: dir == :in,
        repeat: false,
        body: "INVITE sip:bob@x SIP/2.0\r\nCall-ID: #{lane}\r\n",
        clipped: false,
        decoded_from: nil
      },
      Map.new(opts)
    )
  end

  @call [
    %{kind: :transition, at: 1_000, to: :initial_state, event: "start", type: nil},
    %{kind: :command, at: 2_000, type: :sip, name: "send_INVITE"}
  ]

  defp lines(events, opts \\ []), do: Ladder.render(events, @meta, opts) |> String.split("\n")

  test "a header naming each conversation, then one column per lane" do
    out = Ladder.render(@call ++ [msg(641, :out, "c1", "INVITE #1 +SDP")], @meta)

    assert out =~ "Scenario : UAC.Invite"
    assert out =~ "peer1: 10.0.0.1:5060/udp — Call-ID c1"
    assert out =~ ~r/^ +1000 +10\.0\.0\.1:5060\/udp$/m
  end

  test "requests and responses are arrows, pointing the way they went, timed" do
    out =
      lines(
        @call ++ [msg(641, :out, "c1", "INVITE #1"), msg(756, :in, "c1", "200 OK / 1 INVITE")]
      )

    assert Enum.find(out, &(&1 =~ "INVITE #1")) =~ ~r/^ +\+0\.641s +\|-+ INVITE #1 -+>\|$/
    assert Enum.find(out, &(&1 =~ "200 OK")) =~ ~r/^ +\+0\.756s +\|<-+ 200 OK \/ 1 INVITE -+\|$/
  end

  test "states and commands are notes under the scenario's column" do
    out = lines(@call ++ [%{kind: :transition, at: 3_000, to: :calling, event: "", type: nil}])

    assert Enum.any?(out, &(&1 =~ ~r/\+0\.001s +\| initial_state/))
    assert Enum.any?(out, &(&1 =~ ~r/\| send_INVITE/))
    assert Enum.any?(out, &(&1 =~ ~r/\| initial_state -> calling/))
  end

  test "a journal joined mid-run draws its first transition from the state it joined" do
    out =
      Ladder.render(
        [%{kind: :transition, at: 1_000, to: :talking, event: "", type: nil}],
        Map.put(@meta, :joined_in, :ringing)
      )

    assert out =~ "ringing -> talking"
  end

  test "two conversations get two columns; media gets its own" do
    out =
      Ladder.render(
        @call ++
          [
            %{kind: :command, at: 2_500, type: :media, name: "media_connect"},
            msg(641, :out, "c1", "INVITE #1"),
            msg(700, :out, "reg", "REGISTER #1", peer: "10.0.0.9:5060/udp"),
            %{
              kind: :transition,
              at: 800_000,
              to: :talking,
              event: "media connected",
              type: :media
            }
          ],
        @meta
      )

    assert out =~ "peer2: 10.0.0.9:5060/udp — Call-ID reg"
    assert out =~ "media server"
    assert out =~ ~r/\|-+ connect -+>\|/
    assert out =~ ~r/\|<-+ media connected -+\|/
  end

  test "a long label is truncated, never wrapped" do
    out = lines([msg(1, :in, "c1", String.duplicate("Very long reason ", 10))])
    arrow = Enum.find(out, &(&1 =~ "Very long"))
    assert arrow =~ "…"
    assert String.length(arrow) < 60
  end

  test "--full prints each message's text after its arrow" do
    out =
      Ladder.render([msg(641, :out, "c1", "INVITE #1", decoded_from: "deflate")], @meta,
        full: true
      )

    assert out =~ ~r/INVITE #1 -+>\|\n +INVITE sip:bob@x SIP\/2\.0\n +Call-ID: c1/
    assert out =~ "(body shown decoded: deflate)"
    refute Ladder.render([msg(641, :out, "c1", "INVITE #1")], @meta) =~ "sip:bob@x"
  end

  test "the outcome, a cut, and a kind it does not know" do
    out =
      Ladder.render(
        [
          %{kind: :cut, at: 2_000},
          %{kind: :telemetry, at: 2_500},
          %{kind: :terminal, at: 3_000, outcome: :failed, reason: "486 Busy", type: :sip}
        ],
        @meta
      )

    assert out =~ "-- journal truncated --"
    assert out =~ "== failed: 486 Busy =="
    refute out =~ "telemetry"
  end
end
