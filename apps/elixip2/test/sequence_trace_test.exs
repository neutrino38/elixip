defmodule SIP.Test.SequenceTrace do
  @moduledoc """
  `SIP.Scenario.SipTrace`: the messages a transaction sends or receives reach the
  scenario that traces them, and nobody else — then a whole call against the
  mockup transport, drawn from what actually went on the wire.
  """
  use ExUnit.Case

  alias SIP.Scenario.SipTrace
  alias SIP.Scenario.SequenceDiagram
  alias SIP.Test.Transport.Mockup

  @invite %{
    method: :INVITE,
    response: nil,
    reason: nil,
    cseq: [1, :INVITE],
    callid: "call-1",
    contenttype: "application/sdp"
  }

  @ok %{method: false, response: 200, reason: "OK", cseq: [1, :INVITE], callid: "call-1"}

  @ok_wire "SIP/2.0 200 OK\r\n" <>
             "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-1\r\n" <>
             "From: <sip:alice@example.com>;tag=1\r\n" <>
             "To: <sip:bob@example.com>;tag=2\r\n" <>
             "Call-ID: call-1\r\n" <>
             "CSeq: 1 INVITE\r\n" <>
             "Content-Length: 0\r\n\r\n"

  defp transaction(app) do
    %{app: app, destip: {10, 0, 0, 1}, destport: 5060, tmod: Mockup}
  end

  setup do
    SipTrace.take()

    # Run from the umbrella root, `:kelixip` has started and Kelix.Config has
    # routed every diagram to Kelix.Traces. These tests read the file elixipp
    # writes, so they run as the standalone tool does.
    SIP.Test.AppEnv.preserve([:sequence_output])
    Application.delete_env(:elixip2, :sequence_output)
    :ok
  end

  # ── Unit: the sink ──────────────────────────────────────────────────────────

  test "a transaction whose application is not traced records nothing" do
    SipTrace.sent(transaction(self()), @invite)
    assert SipTrace.take() == []
  end

  test "sent and received messages reach the traced scenario in order, then are gone" do
    :ok = SipTrace.watch()
    SipTrace.sent(transaction(self()), @invite)
    SipTrace.received(transaction(self()), @ok, {10, 0, 0, 2}, 5062)

    assert [invite, ok] = SipTrace.take()

    assert %{
             kind: :message,
             dir: :out,
             lane: "call-1",
             party: nil,
             peer: "10.0.0.1:5060/udp",
             label: "INVITE #1 +SDP",
             reply: false,
             repeat: false,
             method: :INVITE,
             code: nil,
             cseq: "1 INVITE",
             sdp: true
           } = invite

    assert %{
             dir: :in,
             lane: "call-1",
             peer: "10.0.0.2:5062/udp",
             label: "200 OK / 1 INVITE",
             reply: true,
             method: nil,
             code: 200,
             reason: "OK",
             sdp: false
           } =
             ok

    assert invite.at <= ok.at
    assert SipTrace.take() == []
  end

  test "each message carries its text, decoded and clipped" do
    :ok = SipTrace.watch()
    SipTrace.sent(transaction(self()), @ok_wire, retransmit: true)
    assert [%{body: body, clipped: false, decoded_from: nil}] = SipTrace.take()
    assert body =~ "SIP/2.0 200 OK"
    assert body =~ "Call-ID: call-1"

    long =
      String.replace(@ok_wire, "Content-Length: 0\r\n\r\n", "") <>
        "Content-Type: text/plain\r\nContent-Length: 20000\r\n\r\n" <>
        String.duplicate("é", 10_000)

    # take/0 forgot the watch with the events
    :ok = SipTrace.watch()
    SipTrace.sent(transaction(self()), long, retransmit: true)
    assert [%{body: cut, clipped: true}] = SipTrace.take()
    assert byte_size(cut) <= 8_192
    assert String.valid?(cut)
  end

  test "a received message with no source address falls back to the transaction's peer" do
    :ok = SipTrace.watch()
    SipTrace.received(transaction(self()), @ok, nil, nil)
    assert [%{peer: "10.0.0.1:5060/udp"}] = SipTrace.take()
  end

  test "a dialog bound to the scenario tags its messages with its leg" do
    :ok = SipTrace.watch()
    dialog = spawn(fn -> Process.sleep(:infinity) end)
    :ok = SipTrace.bind(dialog, self(), :outbound)

    SipTrace.sent(transaction(dialog), @invite)
    assert [%{party: "outbound"}] = SipTrace.take()

    # The binding went with the events.
    SipTrace.sent(transaction(dialog), @invite)
    assert SipTrace.take() == []
    Process.exit(dialog, :kill)
  end

  test "binding to an untraced application is a no-op" do
    dialog = spawn(fn -> Process.sleep(:infinity) end)
    :ok = SipTrace.bind(dialog, self(), :outbound)
    SipTrace.sent(transaction(dialog), @invite)
    assert SipTrace.take() == []
    Process.exit(dialog, :kill)
  end

  test "adopting a dialog keeps the tag the dialog bound itself with" do
    :ok = SipTrace.watch()
    dialog = spawn(fn -> Process.sleep(:infinity) end)
    :ok = SipTrace.bind(dialog, self(), :inbound)
    :ok = SipTrace.adopt(dialog)

    SipTrace.sent(transaction(dialog), @invite)
    assert [%{party: "inbound"}] = SipTrace.take()
    Process.exit(dialog, :kill)
  end

  test "a retransmission is read back from its wire form" do
    :ok = SipTrace.watch()
    SipTrace.sent(transaction(self()), @ok_wire, retransmit: true)

    assert [
             %{
               dir: :out,
               lane: "call-1",
               label: "200 OK / 1 INVITE (retransmission)",
               reply: true,
               repeat: true,
               code: 200,
               cseq: "1 INVITE"
             }
           ] =
             SipTrace.take()
  end

  test "an unparsable wire form records nothing" do
    :ok = SipTrace.watch()
    SipTrace.sent(transaction(self()), "not sip at all\r\n\r\n")
    assert SipTrace.take() == []
  end

  test "a traced scenario that dies leaves no rows behind" do
    parent = self()

    pid =
      spawn(fn ->
        :ok = SipTrace.watch()
        SipTrace.sent(transaction(self()), @invite)
        send(parent, :recorded)
      end)

    assert_receive :recorded, 1_000
    assert wait_until(fn -> :ets.lookup(:sip_scenario_trace, {:watch, pid}) == [] end)
    assert :ets.select(:sip_scenario_trace, [{{{:event, pid, :_}, :_}, [], [true]}]) == []
  end

  defp wait_until(fun, tries \\ 50) do
    cond do
      fun.() -> true
      tries == 0 -> false
      true -> Process.sleep(10) && wait_until(fun, tries - 1)
    end
  end

  # ── The host: what predates the journal, and where the diagram goes ─────────

  describe "SIP.FSL.Host" do
    test "a B2BUA's outbound legs are adopted with their tag when the journal starts" do
      :ok = SipTrace.watch()
      leg = spawn(fn -> Process.sleep(:infinity) end)
      on_exit(fn -> Process.exit(leg, :kill) end)

      ctx =
        SIP.Context.appdata_set(%SIP.Context{}, :__b2bua__, %SIP.B2bua.State{
          legs: %{outbound: %SIP.B2bua.Leg{tag: :outbound, dialogpid: leg}}
        })

      assert SIP.Session.B2bua.leg_dialogs(ctx) == [{:outbound, leg}]
      assert SIP.Session.B2bua.leg_dialogs(%SIP.Context{}) == []

      :ok = SIP.FSL.Host.journal_started(ctx)
      SipTrace.sent(transaction(leg), @invite)
      assert [%{party: "outbound"}] = SipTrace.take()
    end

    test "journal_events/2 hands the journal, unrendered, to :sequence_output, else :default" do
      events = [%{kind: :command, at: 1, type: :sip, name: "send_INVITE"}]
      assert SIP.FSL.Host.journal_events(events, %{}) == :default

      defmodule Sink do
        def keep(events, meta), do: {:ok, {events, meta}}
      end

      Application.put_env(:elixip2, :sequence_output, {Sink, :keep})

      assert SIP.FSL.Host.journal_events(events, %{slot: 3}) ==
               {:ok, {events, %{slot: 3}}}
    end
  end

  # ── End to end: a call drawn from the wire ───────────────────────────────────

  defmodule TracedCall do
    use SIP.Scenario

    @callee "sip:testcall@mydomain.com;unittest=trace"

    config(
      username: "toto",
      authusername: "toto",
      displayname: "Toto",
      domain: "mydomain.com",
      debug: true
    )

    state initial_state do
      media_connect(MediaServer.Mockup, "sip:localhost:8080")
      goto(next)
    end

    state calling do
      send_INVITE(@callee, :mediaserver, timeout: 30, webrtc: :no)
      goto(call_progress)
    end

    state call_progress do
      on_events do
        {100, _rsp, _trans_pid, _dialog_pid} ->
          stay("100 Trying")

        {180, _rsp, _trans_pid, _dialog_pid} ->
          stay("180 Ringing")

        {200, rsp, trans_pid, _dialog_pid} ->
          process_invite_reply(rsp, trans_pid)
          goto(hangup_call, "200 OK")

        {code, _rsp, _trans_pid, _dialog_pid} when code in 400..699 ->
          scenario_failure("Call failure with code #{code}")
      after
        10_000 -> scenario_failure("Call not answered")
      end
    end

    state hangup_call do
      send_BYE()

      on_events do
        {200, _bye_rsp, _trans_pid, _dialog_pid} -> scenario_success("200 OK for BYE")
      after
        4_000 -> scenario_failure("No 200 OK for BYE")
      end
    end
  end

  defmodule TracedUAS do
    use SIP.Scenario

    config(username: "bob", domain: "mydomain.com", debug: true)

    state initial_state do
      scenario_success("seen")
    end
  end

  describe "a UAS instance with debug: true" do
    test "draws the request it was spawned for as its first arrow" do
      dialog = spawn(fn -> Process.sleep(:infinity) end)
      parent = self()

      spawn(fn ->
        result =
          SIP.Scenario.Runner.run_instance(TracedUAS,
            dialog_pid: dialog,
            inbound_request: @invite
          )

        send(parent, {:scenario_result, result, inspect(self())})
      end)

      assert_receive {:scenario_result, :ok, pid}, 5_000
      Process.exit(dialog, :kill)

      path = SequenceDiagram.filename(%{scenario: "SIP.Test.SequenceTrace.TracedUAS", pid: pid})
      content = File.read!(path)
      File.rm(path)

      assert content =~ ~s(participant "peer 1" as peer1)
      assert content =~ "'   peer1: peer 1 — call-1"

      [_header, body] = String.split(content, "@startuml\n")
      first = body |> String.split("\n") |> Enum.find(&(&1 =~ ~r/ : /))
      assert first =~ ~r/^peer1 -> local : \+\d+ms INVITE #1 \+SDP$/
    end
  end

  describe "a scenario with debug: true" do
    setup do
      SIP.Test.AppEnv.preserve_proxy()
      :ok = SIP.Scenario.start_stack()

      Application.put_env(:elixip2, :proxyuri, %SIP.Uri{
        domain: "mydomain.com",
        scheme: "sip:",
        port: 5060
      })

      Application.put_env(:elixip2, :proxyusesrv, false)

      t_pid = Mockup.instance!("sip:mockup@unit.test;unittest=trace")
      :ok = Mockup.set_peer(t_pid, SIP.Test.Peers.AnsweringUAS)
      :ok
    end

    @tag timeout: 20_000
    test "writes a sequence diagram of the messages that went on the wire" do
      parent = self()

      spawn(fn ->
        send(parent, {:scenario_result, TracedCall.run(false), inspect(self())})
      end)

      assert_receive {:scenario_result, result, pid}, 15_000
      assert result == :ok

      path = SequenceDiagram.filename(%{scenario: "SIP.Test.SequenceTrace.TracedCall", pid: pid})
      assert File.exists?(path)
      content = File.read!(path)
      File.rm(path)

      # One lane, the callee, named by its address on the mockup transport.
      assert content =~ ~r/participant "[^"]+\/udp" as peer1/
      refute content =~ ~s(as peer\n)

      # The whole call, as sent and received — not as the script described it.
      assert content =~ ~r/local -> peer1 : \+\d+ms INVITE #\d+ \+SDP/
      assert content =~ ~r/peer1 --> local : \+\d+ms 100 Trying \/ \d+ INVITE/
      assert content =~ ~r/peer1 --> local : \+\d+ms 180 Ringing \/ \d+ INVITE/
      assert content =~ ~r/peer1 --> local : \+\d+ms 200 OK \/ \d+ INVITE \+SDP/
      assert content =~ ~r/local -> peer1 : \+\d+ms ACK #\d+/
      assert content =~ ~r/local -> peer1 : \+\d+ms BYE #\d+/
      assert content =~ ~r/peer1 --> local : \+\d+ms 200 OK \/ \d+ BYE/

      # The script's commands and states are still there, beside the arrows.
      assert content =~ ~r/hnote over local : \+\d+ms send_INVITE/
      assert content =~ ~r/hnote over local : \+\d+ms send_BYE/
      assert content =~ ~r/note over local : \+\d+ms call_progress -> hangup_call/
      assert content =~ "succeeded: 200 OK for BYE"
      refute content =~ "local <-- peer"
    end
  end
end
