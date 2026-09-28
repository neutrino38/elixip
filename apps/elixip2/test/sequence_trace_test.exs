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
             kind: :sip,
             dir: :out,
             method: :INVITE,
             code: nil,
             cseq: "1 INVITE",
             callid: "call-1",
             peer: "10.0.0.1:5060/udp",
             sdp: true,
             retransmit: false
           } = invite

    assert %{
             dir: :in,
             method: nil,
             code: 200,
             reason: "OK",
             peer: "10.0.0.2:5062/udp",
             sdp: false
           } =
             ok

    assert invite.at <= ok.at
    assert SipTrace.take() == []
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
    assert [%{tag: :outbound}] = SipTrace.take()

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
    assert [%{tag: :inbound}] = SipTrace.take()
    Process.exit(dialog, :kill)
  end

  test "a retransmission is read back from its wire form" do
    :ok = SipTrace.watch()
    SipTrace.sent(transaction(self()), @ok_wire, retransmit: true)

    assert [
             %{
               dir: :out,
               code: 200,
               reason: "OK",
               cseq: "1 INVITE",
               callid: "call-1",
               retransmit: true
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

  describe "a scenario with debug: true" do
    # FSL.Journal does not collect the trace yet: docs/design/debug-fsl-port-plan.md.
    @describetag :skip

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
      assert content =~ ~r/elixip -> peer1 : \+\d+ms INVITE #\d+ \+SDP/
      assert content =~ ~r/peer1 --> elixip : \+\d+ms 100 Trying \/ \d+ INVITE/
      assert content =~ ~r/peer1 --> elixip : \+\d+ms 180 Ringing \/ \d+ INVITE/
      assert content =~ ~r/peer1 --> elixip : \+\d+ms 200 OK \/ \d+ INVITE \+SDP/
      assert content =~ ~r/elixip -> peer1 : \+\d+ms ACK #\d+/
      assert content =~ ~r/elixip -> peer1 : \+\d+ms BYE #\d+/
      assert content =~ ~r/peer1 --> elixip : \+\d+ms 200 OK \/ \d+ BYE/

      # The script's commands and states are still there, beside the arrows.
      assert content =~ ~r/hnote over elixip : \+\d+ms send_INVITE/
      assert content =~ ~r/hnote over elixip : \+\d+ms send_BYE/
      assert content =~ ~r/note over elixip : \+\d+ms call_progress -> hangup_call/
      assert content =~ "succeeded: 200 OK for BYE"
      refute content =~ "elixip <-- peer"
    end
  end
end
