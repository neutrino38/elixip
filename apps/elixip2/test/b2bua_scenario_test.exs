defmodule SIP.Test.B2bua.Scenario do
  @moduledoc """
  The reference B2BUA scenario (`scenarios/b2bua_basic.exs`) driven end to end:
  a call is relayed from INVITE to BYE across two legs.

  This is what exercises the **macro** layer — `b2bua_forward`,
  `b2bua_forward_reply`, `b2bua_reply`, `b2bua_send_BYE` and the `{:outbound,
  {…}}` patterns — which the session-level suite (`b2bua_session_test.exs`)
  bypasses by calling the backing functions directly.

  The outbound leg is real (a dialog, a transaction, the UDP mockup on the
  wire); the inbound leg is a stub dialog recording what the B2BUA replies on
  it, which keeps this suite on the macros rather than on the crossing.
  `b2bua_three_party_test.exs` is the one with two real transports.
  """
  use ExUnit.Case

  @scenario Path.expand("../scenarios/b2bua_basic.exs", __DIR__)

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _config_pid} = SIP.Session.ConfigRegistry.start()
    :ok = SIP.Auth.Secret.start()
    module = SIP.Scenario.Loader.load_file!(@scenario)
    %{scenario: module}
  end

  setup do
    {:ok, stub} = SIP.Test.B2bua.InboundDialogStub.start_link(self())
    on_exit(fn -> if Process.alive?(stub), do: GenServer.stop(stub) end)
    %{stub: stub}
  end

  # A mockup peer of this suite's OWN — not the shared `unittest=1` instance every
  # other suite drives. Sharing it meant another suite's retransmitted INVITEs
  # landed in this test's mailbox as {:invite_sent, …}, ahead of the answer it was
  # waiting for.
  #
  # A test that counts what reaches the callee takes the argument and gets an
  # instance of its own: the mockup reports a request going out as a bare atom
  # (`:ACK`, `:BYE`), so one left behind by the test before it is
  # indistinguishable from the one being asserted on.
  defp peer_uri(tag \\ "b2bua_scenario") do
    %SIP.Uri{scheme: "sip:", userpart: "callee", domain: "example.com", port: 5060}
    |> SIP.Uri.set_uri_param("unittest", tag)
  end

  defp inbound_invite do
    {:ok, raw} = File.read(Path.join(__DIR__, "SIP-INVITE-LVP.txt"))
    {:ok, req} = SIPMsg.parse(raw, fn _c, _m, _l, _line -> nil end)
    Map.put(req, :callid, SIP.Msg.Ops.generate_branch_value())
  end

  # A bare in-dialog request as the dialog layer would hand one to the scenario.
  defp in_dialog(method, invite) do
    %{invite | method: method, body: [], contentlength: 0, cseq: [2, method]}
  end

  # Run one instance of the scenario in its own process (an FSM blocks on
  # receive, so it cannot share the test process), with the stub as its inbound
  # dialog and the mockup as its peer. Returns {pid, monitor_ref}.
  defp start_instance(module, stub, invite, peer \\ peer_uri()) do
    test_pid = self()

    spawn_monitor(fn ->
      # Surface the instance's outcome to the test.
      outcome =
        SIP.Scenario.Runner.run_instance(module,
          dialog_pid: stub,
          inbound_request: invite,
          config_overrides: [peer: peer]
        )

      send(test_pid, {:instance_done, outcome})
    end)
  end

  defp transport_pid(peer \\ peer_uri()) do
    SIP.Transport.Selector.select_transport(peer).tp_pid
  end

  test "the scenario declares the shape elixipp needs to run it as a call server",
       %{scenario: module} do
    assert module.__scenario_type__() == :uas_invite
    assert :initial_state in module.__scenario_states__()

    for state <- [:wait_invite, :proceeding, :wait_ack, :connected, :wait_far_bye_ok] do
      assert state in module.__scenario_states__()
    end

    # A cooperative shutdown is handled explicitly rather than defaulting.
    assert function_exported?(module, :__state___shutdown__, 1)
  end

  @tag timeout: 60_000
  test "a call is relayed end to end: 100, 180, 200, ACK, BYE", %{scenario: module, stub: stub} do
    invite = inbound_invite()

    # Watch the callee side from the start: the mockup tells us when the
    # forwarded INVITE reaches it, which is what says the outbound leg is up.
    tp_pid = transport_pid()
    :ok = GenServer.call(tp_pid, :settestapp)
    # the far end answers the relayed BYE, which is what really ends the scenario
    SIP.Test.Transport.UDPMockup.answer_bye(tp_pid)

    {instance, ref} = start_instance(module, stub, invite)

    # The dialog layer would deliver the INVITE that created the instance.
    send(instance, {:INVITE, invite, self(), stub})

    # 1. The caller is told we are working on it — a local answer, not a relay.
    assert_receive {:replied, 100, "Trying", _req, _fields}, 5_000

    # 2. The INVITE reached the callee, carrying a dialog identity of its own
    #    and none of the inbound leg's hop-scoped headers (the §4 rules, here on
    #    a request that really crossed the stack).
    assert_receive {:invite_sent, fwd}, 5_000
    assert fwd.callid != invite.callid
    refute Map.has_key?(fwd, :recordroute)
    refute Map.has_key?(fwd, :proxyauthorization)
    assert Map.get(fwd, "Max-Forwards") in [15, "15"]
    assert fwd.body == invite.body

    # 3. The callee rings, and that reaches the caller in OUR inbound dialog.
    GenServer.cast(tp_pid, {:simulate, 180, 100})
    assert_receive {:replied, 180, _reason, relayed_req, _fields}, 5_000
    assert relayed_req.callid == invite.callid

    # 4. The callee answers. The relayed 200 carries the callee's SDP and our
    #    own Contact (the callee's stayed behind — RFC 3261 §12.1.1).
    GenServer.cast(tp_pid, {:simulate, 200, 100})
    assert_receive {:replied, 200, _reason, _req, fields}, 5_000
    assert [%{data: sdp}] = Keyword.fetch!(fields, :body)
    assert sdp =~ "v=0"
    assert Keyword.fetch!(fields, :contact).domain == "0.0.0.0"

    # 5. The caller's ACK is relayed (deferred-ACK discipline, §6): what the
    #    callee gets is the confirmation the caller actually sent.
    send(instance, {:ACK, in_dialog(:ACK, invite), nil, stub})

    # 6. The caller hangs up: the BYE crosses and is answered locally, so the
    #    caller is not left retransmitting.
    send(instance, {:BYE, in_dialog(:BYE, invite), self(), stub})
    assert_receive {:replied, 200, "OK", bye_req, _}, 5_000
    assert bye_req.method == :BYE
    assert_receive :BYE, 5_000

    # 7. The far end's 200 to the relayed BYE ends the scenario successfully.
    assert_receive {:instance_done, :ok}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end

  # A callee that has not seen the ACK sends its 200 again (RFC 3261 §13.3.1.4),
  # and it is owed another ACK — from the client transaction, which outlives the
  # first ACK by 64*T1 for exactly this and answers alone: no dialog, no scenario,
  # no `{:outbound, {200, …}}` event for a call that is simply up.
  #
  # Nothing answered it before: the transaction was destroyed the moment it ACKed
  # (timer D = 0 on a reliable transport), so the retransmission matched nothing,
  # the callee went on asking, and a Linphone over TCP tore the call down. What
  # reached the scenario instead was a spurious 200 to relay.
  @tag timeout: 60_000
  test "a callee still retransmitting its 200 is ACKed again by the transaction alone", %{
    scenario: module,
    stub: stub
  } do
    invite = inbound_invite()
    # Its own callee, so the `:ACK` counted below is this test's (see peer_uri/1).
    peer = peer_uri("b2bua_2xx_retrans")
    tp_pid = transport_pid(peer)
    :ok = GenServer.call(tp_pid, :settestapp)
    SIP.Test.Transport.UDPMockup.answer_bye(tp_pid)

    {instance, _ref} = start_instance(module, stub, invite, peer)
    send(instance, {:INVITE, invite, self(), stub})

    assert_receive {:replied, 100, "Trying", _req, _fields}, 5_000
    assert_receive {:invite_sent, _fwd}, 5_000
    GenServer.cast(tp_pid, {:simulate, 200, 100})
    assert_receive {:replied, 200, _reason, _req, _fields}, 5_000

    # It answers again while our ACK is still on its way — the T1 retransmission
    # every callee starts the moment it answers. Nothing can be resent yet, so it
    # is absorbed where it lands.
    GenServer.cast(tp_pid, {:simulate, 200, 0})

    # The caller ACKs, and the callee gets it.
    send(instance, {:ACK, in_dialog(:ACK, invite), nil, stub})
    assert_receive :ACK, 5_000

    # It answers again after the ACK too — that one had not reached it either —
    # and this time there is something to resend.
    SIP.Test.Transport.UDPMockup.retransmit_2xx(tp_pid)
    assert_receive :ACK, 5_000

    # …while the caller heard nothing of any of it: a retransmission is not a new
    # answer, so no 200 was relayed a second time on the inbound leg.
    refute_receive {:replied, 200, _reason, _req, _fields}, 500

    # And the call is up: the BYE crosses, is answered on the near side, and the
    # scenario ends on the far end's 200.
    send(instance, {:BYE, in_dialog(:BYE, invite), self(), stub})
    assert_receive {:replied, 200, "OK", bye_req, _}, 5_000
    assert bye_req.method == :BYE
    assert_receive :BYE, 5_000
    assert_receive {:instance_done, :ok}, 10_000
  end

  # The other half of the same production failure (2026-08-12: Bob answered, the
  # call was torn down one second later). A caller owes an ACK per 2xx it receives
  # too, and our own INVITE server transaction retransmits its 200 every T1 until
  # the first ACK gets back — so a second ACK to relay is ordinary traffic.
  #
  # There is nothing left to relay it onto: the transaction it confirms was
  # acknowledged and released, and whoever still wants an ACK asks by retransmitting
  # its 2xx (the test above). What matters is that it does not read as a relay
  # failure — that is what BYEd both legs of a call that was up.
  @tag timeout: 60_000
  test "a caller that ACKs twice does not lose its call", %{scenario: module, stub: stub} do
    invite = inbound_invite()
    tp_pid = transport_pid()
    :ok = GenServer.call(tp_pid, :settestapp)
    SIP.Test.Transport.UDPMockup.answer_bye(tp_pid)

    {instance, _ref} = start_instance(module, stub, invite)
    send(instance, {:INVITE, invite, self(), stub})

    assert_receive {:replied, 100, "Trying", _req, _fields}, 5_000
    assert_receive {:invite_sent, _fwd}, 5_000
    GenServer.cast(tp_pid, {:simulate, 200, 100})
    assert_receive {:replied, 200, _reason, _req, _fields}, 5_000

    ack = in_dialog(:ACK, invite)
    send(instance, {:ACK, ack, nil, stub})
    send(instance, {:ACK, ack, nil, stub})

    send(instance, {:BYE, in_dialog(:BYE, invite), self(), stub})
    assert_receive {:replied, 200, "OK", bye_req, _}, 5_000
    assert bye_req.method == :BYE
    assert_receive {:instance_done, :ok}, 10_000
  end

  # The four things a re-INVITE can mean (hold, a media added or withdrawn, a
  # changed address, a session-timer refresh) all cross in signaling mode, so
  # what this pins is the mechanism they share — and the ACK, which is where it
  # used to break: the ACK of a re-INVITE's 200 is a transaction of ITS OWN (RFC
  # 3261 §13.2.2.4), and posting it on the initial INVITE's transaction leaves
  # the callee retransmitting a 200 nobody confirmed.
  @tag timeout: 60_000
  test "a re-INVITE crosses, and its ACK reaches the transaction it confirms", %{
    scenario: module,
    stub: stub
  } do
    invite = inbound_invite()
    tp_pid = transport_pid()
    :ok = GenServer.call(tp_pid, :settestapp)
    # the far end answers the relayed BYE, which is what really ends the scenario
    SIP.Test.Transport.UDPMockup.answer_bye(tp_pid)

    {instance, _ref} = start_instance(module, stub, invite)
    send(instance, {:INVITE, invite, self(), stub})

    assert_receive {:replied, 100, "Trying", _req, _fields}, 5_000
    assert_receive {:invite_sent, _fwd}, 5_000
    GenServer.cast(tp_pid, {:simulate, 200, 100})
    assert_receive {:replied, 200, _reason, _req, _fields}, 5_000

    # The call is up: the initial ACK crosses (wait_ack) and lands on the initial
    # INVITE's transaction.
    send(instance, {:ACK, in_dialog(:ACK, invite), nil, stub})

    # The caller now re-INVITEs — a hold, a codec change, a new address; in
    # signaling mode the scenario does not read the body, it carries it.
    reinvite = %{in_dialog(:INVITE, invite) | cseq: [3, :INVITE], body: invite.body}
    send(instance, {:INVITE, reinvite, self(), stub})

    assert_receive {:invite_sent, fwd_reinvite}, 5_000
    assert fwd_reinvite.method == :INVITE
    # Same dialog on the callee's side, a later CSeq: a re-INVITE, not a new call.
    assert fwd_reinvite.callid != invite.callid
    assert [cseq_num, :INVITE] = fwd_reinvite.cseq
    assert cseq_num > 1

    # The callee accepts, and that 200 goes back to the caller on the re-INVITE.
    GenServer.cast(tp_pid, {:simulate, 200, 100})
    assert_receive {:replied, 200, _reason, answered_req, _fields}, 5_000
    assert answered_req.cseq == [3, :INVITE]

    # …and the caller's ACK confirms it. It must land on the RE-INVITE's client
    # transaction, and this is what says it did: posted on the initial INVITE's
    # transaction instead — which is what the leg-level `initial_trans` gave —
    # the relay comes back `{:error, :nosuchtransaction}` and takes the whole
    # scenario down with it. The call surviving to its BYE IS the assertion.
    send(instance, {:ACK, %{in_dialog(:ACK, invite) | cseq: [3, :ACK]}, nil, stub})

    send(instance, {:BYE, in_dialog(:BYE, invite), self(), stub})
    assert_receive {:replied, 200, "OK", bye_req, _}, 5_000
    assert bye_req.method == :BYE
    assert_receive {:instance_done, :ok}, 10_000
  end

  # The one in-dialog request that does NOT cross, on a B2BUA with no media at all:
  # an offerless UPDATE, i.e. an RFC 4028 session-timer refresh. A session timer runs
  # between us and ONE peer — we are its UA on that leg — so the far end has nothing
  # to answer, and RFC 3311 §5.1 lets us say 200 with no SDP, which a signalling
  # B2BUA can do without a media server.
  #
  # Relayed instead, the refresh reaches a callee that answers on its own timer and
  # the caller waits on a transaction we opened for nothing. Raised instead (what
  # reply_invite_with_sdp did until 2026-08-17), it takes the call down.
  @tag timeout: 60_000
  test "an offerless UPDATE from the caller is answered here and does not cross", %{
    scenario: module,
    stub: stub
  } do
    invite = inbound_invite()
    peer = peer_uri("b2bua_caller_refresh")
    tp_pid = transport_pid(peer)
    :ok = GenServer.call(tp_pid, :settestapp)
    SIP.Test.Transport.UDPMockup.answer_bye(tp_pid)

    {instance, _ref} = start_instance(module, stub, invite, peer)
    send(instance, {:INVITE, invite, self(), stub})

    assert_receive {:replied, 100, "Trying", _req, _fields}, 5_000
    assert_receive {:invite_sent, _fwd}, 5_000
    GenServer.cast(tp_pid, {:simulate, 200, 100})
    assert_receive {:replied, 200, _reason, _req, _fields}, 5_000
    send(instance, {:ACK, in_dialog(:ACK, invite), nil, stub})

    update = %{in_dialog(:UPDATE, invite) | cseq: [3, :UPDATE]}
    send(instance, {:UPDATE, update, self(), stub})

    # Answered here, with no SDP either way.
    assert_receive {:replied, 200, "OK", answered, fields}, 5_000
    assert answered.method == :UPDATE
    assert answered.cseq == [3, :UPDATE]
    assert Keyword.get(fields, :body) == nil
    assert Keyword.fetch!(fields, :contact).domain == "0.0.0.0"

    # And nothing went to the callee. Its transport reports every INVITE it is
    # sent, so a refresh relayed as one would show up here.
    refute_receive {:invite_sent, _fwd}, 1_000

    # The call is still up: it hangs up normally afterwards.
    send(instance, {:BYE, in_dialog(:BYE, invite), self(), stub})
    assert_receive {:replied, 200, "OK", bye_req, _}, 5_000
    assert bye_req.method == :BYE
    assert_receive {:instance_done, :ok}, 10_000
  end

  # The same rule seen from the other side — the half a caller-side test cannot
  # show. The callee refreshes on ITS timer, over the wire, and what must not
  # happen is a request appearing on the inbound leg.
  @tag timeout: 60_000
  test "an offerless UPDATE from the callee is answered on its own leg and does not cross", %{
    scenario: module,
    stub: stub
  } do
    invite = inbound_invite()
    peer = peer_uri("b2bua_callee_refresh")
    tp_pid = transport_pid(peer)
    :ok = GenServer.call(tp_pid, :settestapp)

    {instance, _ref} = start_instance(module, stub, invite, peer)
    send(instance, {:INVITE, invite, self(), stub})

    assert_receive {:replied, 100, "Trying", _req, _fields}, 5_000
    assert_receive {:invite_sent, _fwd}, 5_000
    GenServer.cast(tp_pid, {:simulate, 200, 100})
    assert_receive {:replied, 200, _reason, _req, _fields}, 5_000
    send(instance, {:ACK, in_dialog(:ACK, invite), nil, stub})

    SIP.Test.Transport.UDPMockup.refresh_session(tp_pid)

    # Nothing reaches the caller: not the UPDATE, and not a re-INVITE built from it.
    refute_receive {:sent_on_inbound, _req}, 2_000

    # The call is still up — the scenario answered the refresh and stayed in `loop`
    # rather than failing on it, and the callee's hangup still ends the call at the
    # caller.
    SIP.Test.Transport.UDPMockup.hangup(tp_pid)
    assert_receive {:sent_on_inbound, %{method: :BYE}}, 5_000
  end

  # The OTHER hangup, and the one nothing covered: the CALLEE puts the phone down.
  # Its BYE arrives on the outbound leg — `{:outbound, {:BYE, …}}` — and what it
  # owes is a BYE on the INBOUND one, so the caller stops talking to itself.
  #
  # Traffic of 2026-08-14, Bob calling Alice: Alice hung up, two BYEs went out
  # towards Alice — one relayed, one from the teardown, the second answered 481 —
  # and Bob's phone stayed off-hook. Every existing test hangs up from the caller's
  # side, where relaying to "the other leg" happens to mean the outbound one.
  @tag timeout: 60_000
  test "a callee that hangs up ends the call at the CALLER, not back at itself", %{
    scenario: module,
    stub: stub
  } do
    invite = inbound_invite()
    # Its own callee: this test counts what does NOT reach it.
    peer = peer_uri("b2bua_callee_bye")
    tp_pid = transport_pid(peer)
    :ok = GenServer.call(tp_pid, :settestapp)

    {instance, _ref} = start_instance(module, stub, invite, peer)
    send(instance, {:INVITE, invite, self(), stub})

    assert_receive {:replied, 100, "Trying", _req, _fields}, 5_000
    assert_receive {:invite_sent, _fwd}, 5_000
    GenServer.cast(tp_pid, {:simulate, 200, 100})
    assert_receive {:replied, 200, _reason, _req, _fields}, 5_000
    send(instance, {:ACK, in_dialog(:ACK, invite), nil, stub})

    # The callee hangs up — on the wire, so the BYE crosses the transport, its own
    # server transaction and the outbound dialog, and reaches the scenario exactly
    # as production delivers it. `hangup/1` was written for this and nothing had
    # ever called it.
    SIP.Test.Transport.UDPMockup.hangup(tp_pid)

    # The BYE must cross to the CALLER, on the inbound leg…
    assert_receive {:sent_on_inbound, %{method: :BYE}}, 5_000

    # …and NOT go back out to the callee, who is the one that just hung up. A BYE
    # returning to it lands on a dialog it has already closed: 481, and the caller
    # — never told anything — is left holding a dead call.
    refute_receive :BYE, 1_000
  end

  @tag timeout: 60_000
  test "a callee that refuses is relayed verbatim and ends the call", %{
    scenario: module,
    stub: stub
  } do
    invite = inbound_invite()
    tp_pid = transport_pid()
    :ok = GenServer.call(tp_pid, :settestapp)
    # the far end answers the relayed BYE, which is what really ends the scenario
    SIP.Test.Transport.UDPMockup.answer_bye(tp_pid)

    {instance, _ref} = start_instance(module, stub, invite)
    send(instance, {:INVITE, invite, self(), stub})

    assert_receive {:replied, 100, "Trying", _req, _fields}, 5_000
    assert_receive {:invite_sent, _fwd}, 5_000
    GenServer.cast(tp_pid, {:simulate, 486, 100})

    # The refusal reaches the caller with its own code, not a code of our own
    # invention, and the scenario stops.
    assert_receive {:replied, 486, _reason, _req, _fields}, 5_000
    assert_receive {:instance_done, :ok}, 10_000
  end

  # Real user agents send a BYE where the RFC asks for a CANCEL. Without a clause
  # for it in `proceeding` it matched nothing, sat in the mailbox, and the callee
  # kept ringing until the state timed out three minutes later.
  @tag timeout: 60_000
  test "a caller who hangs up while the callee is being rung is answered and stops it",
       %{scenario: module, stub: stub} do
    invite = inbound_invite()
    tp_pid = transport_pid()
    :ok = GenServer.call(tp_pid, :settestapp)
    # the far end answers the relayed BYE, which is what really ends the scenario
    SIP.Test.Transport.UDPMockup.answer_bye(tp_pid)

    {instance, ref} = start_instance(module, stub, invite)
    send(instance, {:INVITE, invite, self(), stub})

    assert_receive {:replied, 100, "Trying", _req, _fields}, 5_000
    assert_receive {:invite_sent, _fwd}, 5_000
    GenServer.cast(tp_pid, {:simulate, 180, 100})
    assert_receive {:replied, 180, _reason, _req, _fields}, 5_000

    # The caller hangs up mid-ring.
    send(instance, {:BYE, in_dialog(:BYE, invite), self(), stub})

    # It is answered rather than ignored…
    assert_receive {:replied, 200, "OK", bye_req, _}, 5_000
    assert bye_req.method == :BYE

    # …and the scenario ends now, so the teardown CANCELs the attempt still
    # ringing instead of leaving the callee's phone going.
    assert_receive {:instance_done, :ok}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end

  # ── The cancel race (RFC 3261 §16.7) ────────────────────────────────────────

  # Cancelling ASKS; it does not decide. The scenario used to end on the CANCEL,
  # which is right until the callee's answer crosses it on the wire.
  test "a CANCEL waits for the callee's final before ending the call", %{
    scenario: module,
    stub: stub
  } do
    invite = inbound_invite()
    tp_pid = transport_pid()
    :ok = GenServer.call(tp_pid, :settestapp)

    {instance, ref} = start_instance(module, stub, invite)
    send(instance, {:INVITE, invite, self(), stub})
    assert_receive {:replied, 100, "Trying", _req, _fields}, 5_000
    assert_receive {:invite_sent, _fwd}, 5_000
    GenServer.cast(tp_pid, {:simulate, 180, 100})
    assert_receive {:replied, 180, _reason, _req, _fields}, 5_000

    # The caller gives up. The mockup answers the relayed CANCEL the way a UA
    # does: 200 to the CANCEL, then 487 to the INVITE it cancels.
    send(instance, {:CANCEL, in_dialog(:CANCEL, invite), self(), stub})

    # The scenario ends on the 487, not on the CANCEL — and it does end, rather
    # than sitting in `cancelling` until its 32 s deadline.
    assert_receive {:instance_done, {:aborted, _}}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end

  # The race itself, and the reason the state exists: the callee picked up before
  # the CANCEL reached it. Nobody is left to talk to, so the 2xx must be ACKed —
  # §13.2.2.4 puts that ACK in the UAC core, and a 2xx nobody acknowledges leaves
  # the callee off-hook retransmitting it — and then ended with a BYE (§15).
  #
  # Observed in production 2026-08-11: the callee answered ~20 s after the caller
  # had hung up, and stayed in a call that never existed.
  test "a callee answering after the CANCEL is acknowledged and hung up", %{
    scenario: module,
    stub: stub
  } do
    invite = inbound_invite()
    tp_pid = transport_pid()
    :ok = GenServer.call(tp_pid, :settestapp)
    SIP.Test.Transport.UDPMockup.answer_bye(tp_pid)

    {instance, ref} = start_instance(module, stub, invite)
    send(instance, {:INVITE, invite, self(), stub})
    assert_receive {:replied, 100, "Trying", _req, _fields}, 5_000
    assert_receive {:invite_sent, _fwd}, 5_000

    # The caller gives up…
    send(instance, {:CANCEL, in_dialog(:CANCEL, invite), self(), stub})

    # …and the callee answers anyway, ahead of the 487 the mockup schedules for
    # the CANCEL: the answer crossed the cancellation.
    GenServer.cast(tp_pid, {:simulate, 200, 0})

    # Both, in this order, and neither is optional.
    assert_receive :ACK, 5_000
    assert_receive :BYE, 5_000

    assert_receive {:instance_done, :ok}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end

  @tag timeout: 60_000
  test "when the scenario dies mid-attempt the outbound leg is not left ringing", %{
    scenario: module,
    stub: stub
  } do
    invite = inbound_invite()
    tp_pid = transport_pid()
    :ok = GenServer.call(tp_pid, :settestapp)
    # the far end answers the relayed BYE, which is what really ends the scenario
    SIP.Test.Transport.UDPMockup.answer_bye(tp_pid)

    {instance, ref} = start_instance(module, stub, invite)
    send(instance, {:INVITE, invite, self(), stub})
    assert_receive {:replied, 100, "Trying", _req, _fields}, 5_000
    assert_receive {:invite_sent, _fwd}, 5_000
    GenServer.cast(tp_pid, {:simulate, 180, 100})
    assert_receive {:replied, 180, _reason, _req, _fields}, 5_000

    # A controller stops the scenario while the callee is still ringing. The
    # teardown owes the callee a CANCEL and the caller a final response.
    send(instance, {:scenario_ctl, :shutdown, :test})

    assert_receive {:instance_done, {:aborted, _}}, 10_000
    assert_receive {:replied, 487, "Request Terminated", _req, _}, 5_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end
end
