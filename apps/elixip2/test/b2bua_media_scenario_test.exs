defmodule SIP.Test.B2bua.MediaScenario do
  @moduledoc """
  The media B2BUA reference scenario (`scenarios/b2bua_media.exs`) driven end to
  end — the sibling of `b2bua_scenario_test.exs`, and deliberately a separate
  file for the same reason the scenario is (design §12): the two read as a pair,
  and what the pair shows is what a media server costs.

  Same harness as the signalling suite: a stub inbound dialog recording what the
  B2BUA replies, a real outbound leg on its own UDP mockup instance, and
  `MediaServer.Mockup` as the media plane.
  """
  use ExUnit.Case

  @scenario Path.expand("../scenarios/b2bua_media.exs", __DIR__)

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

  # One mockup instance PER TEST. The mockup announces a hangup as the bare atom
  # `:BYE`, which carries no identity, so a teardown BYE still in flight from
  # another test of this module lands in whichever test is running — and
  # `refute_receive :BYE` then fails on someone else's call. Draining cannot fix
  # that (the arrival is not ordered against the drain); a peer of one's own can.
  defp peer_uri(name) do
    %SIP.Uri{scheme: "sip:", userpart: "callee", domain: "example.com", port: 5060}
    |> SIP.Uri.set_uri_param("unittest", "b2bua_media_#{name}")
  end

  defp inbound_invite do
    {:ok, raw} = File.read(Path.join(__DIR__, "SIP-INVITE-LVP.txt"))
    {:ok, req} = SIPMsg.parse(raw, fn _c, _m, _l, _line -> nil end)
    Map.put(req, :callid, SIP.Msg.Ops.generate_branch_value())
  end

  defp in_dialog(method, invite) do
    %{invite | method: method, body: [], contentlength: 0, cseq: [2, method]}
  end

  # A re-offer from the caller: same dialog, a later CSeq, an SDP of its own.
  defp reoffer(invite, sdp, cseq) do
    %{
      invite
      | method: :INVITE,
        cseq: [cseq, :INVITE],
        body: [%{contenttype: "application/sdp", data: sdp}]
    }
  end

  # The caller's own offer, moved to another address and put on hold — the two
  # re-offers §R4.1b sorts in opposite directions.
  defp moved(sdp), do: String.replace(sdp, "c=IN IP4 192.168.24.71", "c=IN IP4 192.168.24.99")
  defp on_hold(sdp), do: String.replace(sdp, "a=sendrecv", "a=sendonly")

  # Drive the call to `connected`: INVITE relayed, callee answers, ACK crosses.
  defp establish(module, stub, invite, name) do
    tp_pid = transport_pid(name)
    :ok = GenServer.call(tp_pid, :settestapp)
    SIP.Test.Transport.UDPMockup.answer_bye(tp_pid)

    {instance, ref} = start_instance(module, stub, invite, name)
    send(instance, {:INVITE, invite, self(), stub})

    assert_receive {:replied, 100, "Trying", _req, _fields}, 5_000
    assert_receive {:invite_sent, _fwd}, 5_000
    GenServer.cast(tp_pid, {:simulate, 200, 100})
    assert_receive {:replied, 200, _reason, _req, _fields}, 5_000
    send(instance, {:ACK, in_dialog(:ACK, invite), nil, stub})

    {instance, ref, tp_pid}
  end

  defp start_instance(module, stub, invite, name) do
    test_pid = self()

    spawn_monitor(fn ->
      outcome =
        SIP.Scenario.Runner.run_instance(module,
          dialog_pid: stub,
          inbound_request: invite,
          config_overrides: [
            peer: peer_uri(name),
            mediaserver: %{module: :mockup, url: "http://127.0.0.1:8080"}
          ]
        )

      send(test_pid, {:instance_done, outcome})
    end)
  end

  defp transport_pid(name),
    do: SIP.Transport.Selector.select_transport(peer_uri(name)).tp_pid

  test "it is the same shape as the signalling scenario, plus a media plane", %{scenario: module} do
    assert module.__scenario_type__() == :uas_invite

    for state <- [:wait_invite, :proceeding, :wait_ack, :connected, :wait_far_bye_ok, :releasing] do
      assert state in module.__scenario_states__()
    end

    assert function_exported?(module, :__state___shutdown__, 1)
  end

  @tag timeout: 60_000
  test "a call is relayed with the media server in the middle: neither side sees the other's SDP",
       %{scenario: module, stub: stub} do
    invite = inbound_invite()
    caller_sdp = SIP.Session.extract_sdp(invite)
    assert is_binary(caller_sdp)

    tp_pid = transport_pid(:relayed)
    :ok = GenServer.call(tp_pid, :settestapp)
    SIP.Test.Transport.UDPMockup.answer_bye(tp_pid)

    {instance, ref} = start_instance(module, stub, invite, :relayed)
    send(instance, {:INVITE, invite, self(), stub})

    assert_receive {:replied, 100, "Trying", _req, _fields}, 5_000

    # 1. The callee is offered OUR media, not the caller's. This is the whole
    #    difference from b2bua_basic.exs, where the body crossed verbatim.
    assert_receive {:invite_sent, fwd}, 5_000
    fwd_sdp = SIP.Session.extract_sdp(fwd)
    assert is_binary(fwd_sdp)
    assert fwd_sdp != caller_sdp

    # 2. The callee rings. Nothing of its SDP reaches the caller — and the
    #    scenario is still free to hunt, which relaying a 183 would have ended.
    GenServer.cast(tp_pid, {:simulate, 180, 100})
    assert_receive {:replied, 180, _reason, _req, prov_fields}, 5_000
    assert Keyword.get(prov_fields, :body) in [nil, []]

    # 3. The callee answers, and the caller gets the MEDIA SERVER's answer.
    GenServer.cast(tp_pid, {:simulate, 200, 100})
    assert_receive {:replied, 200, _reason, _req, fields}, 5_000
    assert [%{data: answer}] = Keyword.fetch!(fields, :body)
    assert answer =~ "v=0"
    # The callee's canned answer says 212.83.152.250; ours cannot.
    refute answer =~ "212.83.152.250"
    assert Keyword.fetch!(fields, :contact).domain == "0.0.0.0"

    # 4. The call is up and ends the ordinary way.
    send(instance, {:ACK, in_dialog(:ACK, invite), nil, stub})
    send(instance, {:BYE, in_dialog(:BYE, invite), self(), stub})
    assert_receive {:replied, 200, "OK", bye_req, _}, 5_000
    assert bye_req.method == :BYE

    assert_receive {:instance_done, :ok}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end

  # §14.6: the media server is a failure domain of its own, and with one media
  # session per call it takes the CALL down rather than one leg. Six reference
  # scenarios already carry this clause by hand; this is the one that cannot do
  # without it.
  @tag timeout: 60_000
  test "the media server going away hangs up both legs", %{scenario: module, stub: stub} do
    invite = inbound_invite()
    tp_pid = transport_pid(:server_gone)
    :ok = GenServer.call(tp_pid, :settestapp)
    SIP.Test.Transport.UDPMockup.answer_bye(tp_pid)

    {instance, _ref} = start_instance(module, stub, invite, :server_gone)
    send(instance, {:INVITE, invite, self(), stub})

    assert_receive {:replied, 100, "Trying", _req, _fields}, 5_000
    assert_receive {:invite_sent, _fwd}, 5_000
    GenServer.cast(tp_pid, {:simulate, 200, 100})
    assert_receive {:replied, 200, _reason, _req, _fields}, 5_000
    send(instance, {:ACK, in_dialog(:ACK, invite), nil, stub})

    # The media plane announces it is gone, the way an adapter does.
    send(instance, {:ms_event, self(), :server_disconnected})

    # The callee is BYEd…
    assert_receive :BYE, 5_000
    # …and the scenario ends rather than holding a call with no media.
    assert_receive {:instance_done, :ok}, 10_000
  end

  # The hangup that comes from the OTHER side, in media mode. Traffic of
  # 2026-08-14 (Bob calling Alice, Alice hangs up): two BYEs went out towards
  # Alice — one relayed, one from the teardown, the second answered 481 — and
  # Bob's phone stayed off-hook. The signalling suite covers the same crossing;
  # this one adds the media plane, which is what production runs.
  @tag timeout: 60_000
  test "a callee that hangs up ends the call at the CALLER, not back at itself", %{
    scenario: module,
    stub: stub
  } do
    invite = inbound_invite()
    {_instance, _ref, tp_pid} = establish(module, stub, invite, :callee_bye)

    # On the wire, so the BYE crosses its own server transaction and the outbound
    # dialog exactly as production delivers it.
    SIP.Test.Transport.UDPMockup.hangup(tp_pid)

    # It must cross to the CALLER, on the inbound leg…
    assert_receive {:sent_on_inbound, %{method: :BYE}}, 5_000

    # …and not go back out to the callee, who is the one that just hung up.
    refute_receive :BYE, 1_000
  end

  # §R4.1b. The signalling scenario relays all four kinds of re-offer because it
  # cannot tell them apart; this one reads the offer first, and the two rows of
  # the table that stay on this side of the B2BUA are the point of the whole
  # exercise: our endpoint did not move, so the far end has nothing to learn.
  @tag timeout: 60_000
  test "a caller that only moved is answered here, and the callee never hears of it", %{
    scenario: module,
    stub: stub
  } do
    invite = inbound_invite()
    caller_sdp = SIP.Session.extract_sdp(invite)
    {instance, _ref, _tp_pid} = establish(module, stub, invite, :moved)

    send(instance, {:INVITE, reoffer(invite, moved(caller_sdp), 3), self(), stub})

    # Answered here, with the media server's answer…
    assert_receive {:replied, 200, "OK", req, fields}, 5_000
    assert req.cseq == [3, :INVITE]
    assert [%{data: answer}] = Keyword.fetch!(fields, :body)
    assert answer =~ "v=0"
    assert Keyword.fetch!(fields, :contact).domain == "0.0.0.0"

    # …and nothing crossed. This is the assertion the whole feature exists for.
    refute_receive {:invite_sent, _fwd}, 1_000

    # Its ACK confirms a 200 the callee never sent, so it must not be relayed
    # onto the callee's INVITE transaction either — the call surviving to its
    # BYE is what says it was not.
    send(instance, {:ACK, %{in_dialog(:ACK, invite) | cseq: [3, :ACK]}, nil, stub})
    send(instance, {:BYE, in_dialog(:BYE, invite), self(), stub})
    assert_receive {:replied, 200, "OK", bye_req, _}, 5_000
    assert bye_req.method == :BYE
    assert_receive {:instance_done, :ok}, 10_000
  end

  # The fourth row of the table: a refresh with no offer at all. Answering it
  # locally means putting OUR offer in the 200 (RFC 3261 §14.2) and reading the
  # answer from the ACK — which is why a signalling B2BUA cannot do this and a
  # media-terminating one can.
  @tag timeout: 60_000
  test "an offerless refresh is answered with our own offer, and its ACK stays here", %{
    scenario: module,
    stub: stub
  } do
    invite = inbound_invite()
    caller_sdp = SIP.Session.extract_sdp(invite)
    {instance, _ref, _tp_pid} = establish(module, stub, invite, :refresh)

    send(instance, {:INVITE, %{in_dialog(:INVITE, invite) | cseq: [3, :INVITE]}, self(), stub})

    assert_receive {:replied, 200, "OK", req, fields}, 5_000
    assert req.cseq == [3, :INVITE]
    assert [%{data: our_offer}] = Keyword.fetch!(fields, :body)
    assert our_offer =~ "v=0"
    refute_receive {:invite_sent, _fwd}, 1_000

    # The answer comes back in the ACK, and goes to the media server rather than
    # onto the callee's INVITE transaction.
    ack = %{
      in_dialog(:ACK, invite)
      | cseq: [3, :ACK],
        body: [%{contenttype: "application/sdp", data: caller_sdp}]
    }

    send(instance, {:ACK, ack, nil, stub})

    send(instance, {:BYE, in_dialog(:BYE, invite), self(), stub})
    assert_receive {:replied, 200, "OK", bye_req, _}, 5_000
    assert bye_req.method == :BYE
    assert_receive {:instance_done, :ok}, 10_000
  end

  # The other direction of the same rule — and the half that P3 did not have:
  # a re-offer that crosses crosses as OURS, exactly like the initial INVITE.
  @tag timeout: 60_000
  test "a hold crosses, and both sides still see only our SDP", %{scenario: module, stub: stub} do
    invite = inbound_invite()
    caller_sdp = SIP.Session.extract_sdp(invite)
    {instance, _ref, tp_pid} = establish(module, stub, invite, :hold)

    held = on_hold(caller_sdp)
    send(instance, {:INVITE, reoffer(invite, held, 3), self(), stub})

    # The callee is told — it must stop sending, or play its own hold tone.
    assert_receive {:invite_sent, fwd}, 5_000
    fwd_sdp = SIP.Session.extract_sdp(fwd)
    assert is_binary(fwd_sdp)
    # …but with our offer, not the caller's.
    assert fwd_sdp != held
    refute fwd_sdp =~ "192.168.24.71"

    # The callee accepts, and the caller is answered by the media server: the
    # answer it has been owed since it re-offered, not the callee's.
    GenServer.cast(tp_pid, {:simulate, 200, 100})
    assert_receive {:replied, 200, _reason, req, fields}, 5_000
    assert req.cseq == [3, :INVITE]
    assert [%{data: answer}] = Keyword.fetch!(fields, :body)
    refute answer =~ "212.83.152.250"

    send(instance, {:ACK, %{in_dialog(:ACK, invite) | cseq: [3, :ACK]}, nil, stub})
    send(instance, {:BYE, in_dialog(:BYE, invite), self(), stub})
    assert_receive {:replied, 200, "OK", bye_req, _}, 5_000
    assert bye_req.method == :BYE
    assert_receive {:instance_done, :ok}, 10_000
  end

  @tag timeout: 60_000
  test "one media going silent is not a hangup, every media is", %{scenario: module, stub: stub} do
    invite = inbound_invite()
    tp_pid = transport_pid(:media_lost)
    :ok = GenServer.call(tp_pid, :settestapp)
    SIP.Test.Transport.UDPMockup.answer_bye(tp_pid)

    {instance, _ref} = start_instance(module, stub, invite, :media_lost)
    send(instance, {:INVITE, invite, self(), stub})

    assert_receive {:replied, 100, "Trying", _req, _fields}, 5_000
    assert_receive {:invite_sent, _fwd}, 5_000
    GenServer.cast(tp_pid, {:simulate, 200, 100})
    assert_receive {:replied, 200, _reason, _req, _fields}, 5_000
    send(instance, {:ACK, in_dialog(:ACK, invite), nil, stub})

    # A peer that turned its camera off is still on the call.
    send(instance, {:ms_event, self(), {:media_timeout, :video}})
    refute_receive :BYE, 1_000

    # Every media of R gone is a call with nothing left to carry.
    send(instance, {:ms_event, self(), :media_lost})
    assert_receive :BYE, 5_000
    assert_receive {:instance_done, :ok}, 10_000
  end
end
