defmodule SIP.Test.B2bua.EarlyMedia do
  @moduledoc """
  What a B2BUA does with a `183 Session Progress` that carries the callee's SDP,
  under both media policies — because there are two, and the difference is a
  service decision rather than a protocol one.

  By default the body is dropped and the provisional relayed without it (§7.4):
  the caller's answer comes from the media server, is decided when its INVITE
  arrives, and committing it on a 1xx would pin the call to the target that sent
  it. `early_media: true` says the opposite — for the services placed in front of
  a gateway, where the announcement or the network ringback IS what the caller
  called for.

  The same harness as the other B2BUA suites: a stub inbound dialog recording
  what we reply, a real outbound leg on a UDP mockup, `MediaServer.Mockup` as the
  media plane.
  """
  use ExUnit.Case, async: false

  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

  # Not tagged `:flaky`, unlike the other media suites: this one asks for no
  # media server of a given profile — the peer is resolved by the block, after
  # `media_connect()` — so the host's pool selector is never consulted and no
  # singleton another file leaves behind can answer for it.

  # One scenario, and the policy read from the configuration: the two tests must
  # differ by the `early_media:` option and by nothing else, which two scenario
  # modules could not promise.
  defmodule Gateway do
    use SIP.Scenario
    use SBB.Call

    uas(:invite)

    config(
      peer: "sip:callee@example.com:5060;unittest=b2bua_early_media",
      mediaserver: %{module: :mockup, url: "http://127.0.0.1:8080"},
      early_media: false
    )

    state initial_state do
      on_events do
        {:INVITE, req, _trans, _dlg} ->
          b2bua_reply(req, 100, "Trying")
          goto(place_call, "INVITE received")
      after
        5_000 -> scenario_failure("no INVITE")
      end
    end

    # `media_connect()` alone, and the peer resolved by the block: resolving here
    # would ask the host's media-server selector for a server carrying this
    # target's profiles, and this suite has no pool to answer with.
    state place_call do
      media_connect()

      call(args: %{peer: ctx_get(:peer), media: media_mode(ctx_get(:early_media))})

      on_events do
        {:call, :connected, _} -> goto(bridging, "call established")
        {:call, outcome, _} -> scenario_failure("not established: #{outcome}")
      end
    end

    state bridging do
      bridge(args: %{media: media_mode(ctx_get(:early_media))})

      on_events do
        {:bridge, :caller_hung_up, _} -> goto(releasing, "caller hung up")
        {:bridge, :callee_hung_up, _} -> goto(releasing, "callee hung up")
        {:bridge, outcome, _} -> scenario_failure("unexpected: #{outcome}")
      end
    end

    state releasing do
      media_cleanup_ressources()
      scenario_success("call released")
    end

    defp media_mode(early_media) do
      {:mediaserver,
       inbound: [webrtc: :no, media: :audio_video],
       outbound: [webrtc: :no, media: :audio_video],
       transcode: [audio: :avoid, video: :avoid],
       early_media: early_media}
    end
  end

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _config_pid} = SIP.Session.ConfigRegistry.start()
    :ok = SIP.Auth.Secret.start()
    :ok
  end

  setup do
    {:ok, stub} = SIP.Test.B2bua.InboundDialogStub.start_link(self())
    on_exit(fn -> if Process.alive?(stub), do: GenServer.stop(stub) end)
    %{stub: stub}
  end

  defp peer_uri(tag) do
    %SIP.Uri{scheme: "sip:", userpart: "callee", domain: "example.com", port: 5060}
    |> SIP.Uri.set_uri_param("unittest", tag)
  end

  defp inbound_invite do
    {:ok, raw} = File.read(Path.join(__DIR__, "SIP-INVITE-LVP.txt"))
    {:ok, req} = SIPMsg.parse(raw, fn _c, _m, _l, _line -> nil end)
    Map.put(req, :callid, SIP.Msg.Ops.generate_branch_value())
  end

  defp in_dialog(method, invite) do
    %{invite | method: method, body: [], contentlength: 0, cseq: [2, method]}
  end

  # Ring the callee and have it answer 183 with the SDP of a gateway that has
  # something to play. Returns what the caller was told about it.
  defp ring_with_early_media(stub, tag, early_media?) do
    invite = inbound_invite()
    tp = SIP.Transport.Selector.select_transport(peer_uri(tag)).tp_pid
    :ok = Mockup.set_peer(tp, Manual)
    :ok = Mockup.attach_probe(tp)

    test_pid = self()

    {instance, ref} =
      spawn_monitor(fn ->
        outcome =
          SIP.Scenario.Runner.run_instance(Gateway,
            dialog_pid: stub,
            inbound_request: invite,
            config_overrides: [peer: peer_uri(tag), early_media: early_media?]
          )

        send(test_pid, {:instance_done, outcome})
      end)

    send(instance, {:INVITE, invite, self(), stub})
    assert_receive {:replied, 100, "Trying", _req, _fields}, 5_000
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000

    Manual.simulate(tp, 183, 50)
    assert_receive {:replied, 183, _reason, _req, fields}, 5_000

    %{instance: instance, ref: ref, invite: invite, tp: tp, fields: fields}
  end

  # The callee's own SDP says 212.83.152.250 (SIP.Test.Peer): whatever the caller
  # receives, it cannot be that address — the media is terminated on the server.
  defp sdp_of(fields) do
    case Keyword.get(fields, :body) do
      [%{data: sdp}] -> sdp
      other -> other
    end
  end

  @tag timeout: 60_000
  test "early_media: true relays the 183 with OUR answer, and the call goes on",
       %{stub: stub} do
    %{instance: instance, ref: ref, invite: invite, tp: tp, fields: fields} =
      ring_with_early_media(stub, "b2bua_early_media", true)

    # 1. The caller can now receive what the gateway plays: it has an answer.
    early = sdp_of(fields)
    assert is_binary(early)
    assert early =~ "v=0"
    refute early =~ "212.83.152.250"

    # 2. An early dialog is only usable if the caller knows where to write.
    assert Keyword.fetch!(fields, :contact).domain == "0.0.0.0"

    # 3. The 183 committed nothing it then contradicts: the 2xx carries the same
    #    session, which is the caller's whole reason to keep the media it opened.
    Manual.simulate(tp, 200, 50)
    assert_receive {:replied, 200, _reason, _req, ok_fields}, 5_000
    assert sdp_of(ok_fields) == early

    send(instance, {:ACK, in_dialog(:ACK, invite), self(), stub})
    assert_receive {:sip_mockup, {:request_sent, :ACK, _}}, 5_000

    send(instance, {:BYE, in_dialog(:BYE, invite), self(), stub})
    assert_receive {:sip_mockup, {:request_sent, :BYE, _}}, 5_000

    assert_receive {:instance_done, :ok}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end

  @tag timeout: 60_000
  test "without the option the 183 still crosses stripped of its SDP (§7.4)", %{stub: stub} do
    %{instance: instance, ref: ref, invite: invite, tp: tp, fields: fields} =
      ring_with_early_media(stub, "b2bua_no_early_media", false)

    assert sdp_of(fields) in [nil, []]

    # And the default path is unharmed: the 2xx is where the answer appears.
    Manual.simulate(tp, 200, 50)
    assert_receive {:replied, 200, _reason, _req, ok_fields}, 5_000
    assert sdp_of(ok_fields) =~ "v=0"

    send(instance, {:ACK, in_dialog(:ACK, invite), self(), stub})
    send(instance, {:BYE, in_dialog(:BYE, invite), self(), stub})

    assert_receive {:instance_done, :ok}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end
end
