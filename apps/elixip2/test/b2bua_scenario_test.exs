defmodule SIP.Test.B2bua.Scenario do
  @moduledoc """
  The reference B2BUA scenario (`scenarios/b2bua_basic.exs`) driven end to end:
  a call is relayed from INVITE to BYE across two legs.

  This is what exercises the **macro** layer — `b2bua_forward`,
  `b2bua_forward_reply`, `b2bua_reply`, `b2bua_send_BYE` and the `{:outbound,
  {…}}` patterns — which the session-level suite (`b2bua_session_test.exs`)
  bypasses by calling the backing functions directly.

  The outbound leg is real (a dialog, a transaction, the UDP mockup on the
  wire). The inbound leg is a stub dialog recording what the B2BUA replies on
  it, because both legs would otherwise land on the *same* shared mockup
  instance — every `unittest` URI resolves to one destination. A three-party
  test on real sockets is the next step (see the P1e note in the design doc).
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

  defp peer_uri do
    %SIP.Uri{scheme: "sip:", userpart: "callee", domain: "example.com", port: 5060}
    |> SIP.Uri.set_uri_param("unittest", "1")
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
  defp start_instance(module, stub, invite) do
    test_pid = self()

    spawn_monitor(fn ->
      # Surface the instance's outcome to the test.
      outcome =
        SIP.Scenario.Runner.run_instance(module,
          dialog_pid: stub,
          inbound_request: invite,
          config_overrides: [peer: peer_uri()]
        )

      send(test_pid, {:instance_done, outcome})
    end)
  end

  defp transport_pid do
    SIP.Transport.Selector.select_transport(peer_uri()).tp_pid
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

  @tag timeout: 60_000
  test "a callee that refuses is relayed verbatim and ends the call", %{
    scenario: module,
    stub: stub
  } do
    invite = inbound_invite()
    tp_pid = transport_pid()
    :ok = GenServer.call(tp_pid, :settestapp)

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

  @tag timeout: 60_000
  test "when the scenario dies mid-attempt the outbound leg is not left ringing", %{
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

    # A controller stops the scenario while the callee is still ringing. The
    # teardown owes the callee a CANCEL and the caller a final response.
    send(instance, {:scenario_ctl, :shutdown, :test})

    assert_receive {:instance_done, {:aborted, _}}, 10_000
    assert_receive {:replied, 487, "Request Terminated", _req, _}, 5_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end
end
