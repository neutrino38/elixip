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
