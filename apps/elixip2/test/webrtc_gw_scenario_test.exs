defmodule SIP.Test.B2bua.WebrtcGwScenario do
  @moduledoc """
  The WebRTC-gateway reference scenario (`scenarios/webrtc-gw.exs`, commented in
  B2BUA.md) driven end to end, for the one thing that scenario alone exercises:
  the offer-profile ladder of design §7.5.

  A browser calls in over WebRTC and the phone on the other side refuses the
  offer. The gateway does not give up and does not tell the browser: it offers
  the phone the profile below, then the one below that, and the call completes on
  plain RTP. The scenario contains not one line about profiles — the `%Peer{}`
  carries one, and the `code >= 300` clause it already had asks
  `b2bua_hunting?/0` before concluding anything.

  Same harness as the other scenario suites: a stub inbound dialog recording what
  the B2BUA replies, a real outbound leg on its own UDP mockup instance, and
  `MediaServer.Mockup` as the media plane. The session-layer properties of the
  ladder (CSeq, correlation, `fallback_on`, the `_required` profiles) are pinned
  down in `b2bua_offer_profile_test.exs`; this one is about the scenario.
  """
  use ExUnit.Case

  @scenario Path.expand("../scenarios/webrtc-gw.exs", __DIR__)

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

  # One mockup peer per test — see b2bua_media_scenario_test.exs for why. The
  # scenario keeps the R-URI it was called on (`ruri: :keep`, the proxy decided
  # whom the call is for), so the peer is named by the INVITE's own R-URI and
  # the proxy is taken out of the way.
  defp callee_uri(name) do
    %SIP.Uri{scheme: "sip:", userpart: "phone", domain: "example.com", port: 5060}
    |> SIP.Uri.set_uri_param("unittest", "webrtc_gw_#{name}")
  end

  defp transport_pid(name),
    do: SIP.Transport.Selector.select_transport(callee_uri(name)).tp_pid

  defp inbound_invite(name) do
    {:ok, raw} = File.read(Path.join(__DIR__, "SIP-INVITE-LVP.txt"))
    {:ok, req} = SIPMsg.parse(raw, fn _c, _m, _l, _line -> nil end)

    req
    |> Map.put(:callid, SIP.Msg.Ops.generate_branch_value())
    |> Map.put(:ruri, callee_uri(name))
  end

  defp in_dialog(method, invite) do
    %{invite | method: method, body: [], contentlength: 0, cseq: [2, method]}
  end

  defp start_instance(module, stub, invite, overrides) do
    test_pid = self()

    spawn_monitor(fn ->
      outcome =
        SIP.Scenario.Runner.run_instance(module,
          dialog_pid: stub,
          inbound_request: invite,
          config_overrides:
            [
              proxy: nil,
              mediaserver: %{module: :mockup, url: "http://127.0.0.1:8080"}
            ] ++ overrides
        )

      send(test_pid, {:instance_done, outcome})
    end)
  end

  defp offered_protocols(invite) do
    invite
    |> SIP.Session.extract_sdp()
    |> String.split(["\r\n", "\n"])
    |> Enum.filter(&String.starts_with?(&1, "m="))
    |> Enum.map(fn line -> line |> String.split(" ") |> Enum.at(2) end)
  end

  @tag timeout: 60_000
  test "the phone refuses WebRTC twice and the call completes on plain RTP",
       %{scenario: module, stub: stub} do
    invite = inbound_invite(:ladder)
    browser_sdp = SIP.Session.extract_sdp(invite)

    tp_pid = transport_pid(:ladder)
    :ok = GenServer.call(tp_pid, :settestapp)
    SIP.Test.Transport.UDPMockup.answer_bye(tp_pid)

    {instance, _ref} = start_instance(module, stub, invite, [])
    send(instance, {:INVITE, invite, self(), stub})

    assert_receive {:replied, 100, "Trying", _req, _fields}, 5_000

    # Rung 1: a browser-shaped offer, built by the media server — not the
    # browser's own, which the phone never sees.
    assert_receive {:invite_sent, webrtc}, 5_000
    assert offered_protocols(webrtc) == ["UDP/TLS/RTP/SAVPF", "UDP/TLS/RTP/SAVPF"]
    assert SIP.Session.extract_sdp(webrtc) != browser_sdp

    GenServer.cast(tp_pid, {:simulate, 488, 100})

    # Rung 2: the feedback profile, on a NEW CSeq. The phone's server
    # transaction for the INVITE it just refused is still alive, and two bodies
    # under one CSeq are a merged request (RFC 3261 §8.2.2.2) — answered 482.
    assert_receive {:invite_sent, avpf}, 5_000
    assert offered_protocols(avpf) == ["RTP/AVPF", "RTP/AVPF"]
    assert hd(avpf.cseq) > hd(webrtc.cseq)
    assert avpf.callid == webrtc.callid
    assert avpf.ruri.domain == webrtc.ruri.domain

    GenServer.cast(tp_pid, {:simulate, 488, 100})

    # Rung 3, the bottom of the ladder.
    assert_receive {:invite_sent, avp}, 5_000
    assert offered_protocols(avp) == ["RTP/AVP", "RTP/AVP"]
    assert hd(avp.cseq) > hd(avpf.cseq)

    # Through all of it the browser has been told nothing: the refusals are
    # between the gateway and the phone.
    refute_receive {:replied, 488, _reason, _req, _fields}, 200

    GenServer.cast(tp_pid, {:simulate, 200, 100})

    assert_receive {:replied, 200, _reason, _req, fields}, 5_000
    assert [%{data: relayed}] = Keyword.fetch!(fields, :body)
    assert relayed != browser_sdp
    assert relayed =~ "m=audio"

    send(instance, {:ACK, in_dialog(:ACK, invite), nil, stub})
    send(instance, {:BYE, in_dialog(:BYE, invite), nil, stub})

    assert_receive {:instance_done, _outcome}, 10_000
  end

  @tag timeout: 60_000
  test "profile: :webrtc_required does not fall back — the refusal is the call's answer",
       %{scenario: module, stub: stub} do
    invite = inbound_invite(:required)

    tp_pid = transport_pid(:required)
    :ok = GenServer.call(tp_pid, :settestapp)

    {instance, _ref} = start_instance(module, stub, invite, profile: :webrtc_required)
    send(instance, {:INVITE, invite, self(), stub})

    assert_receive {:replied, 100, "Trying", _req, _fields}, 5_000
    assert_receive {:invite_sent, webrtc}, 5_000
    assert offered_protocols(webrtc) == ["UDP/TLS/RTP/SAVPF", "UDP/TLS/RTP/SAVPF"]

    GenServer.cast(tp_pid, {:simulate, 488, 100})

    # The browser learns of it, which is what `_required` means.
    assert_receive {:replied, 488, _reason, _req, _fields}, 5_000
    assert_receive {:instance_done, _outcome}, 10_000
  end
end
