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

  # Same leaked singleton as b2bua_media_scenario_test.exs: red in a full run,
  # green on its own.
  @moduletag :flaky

  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

  # A host media-server selector that looked and found nothing — the shape
  # `Kelix.Router.media_for_profiles/1` answers with when no pooled MCU carries
  # the profiles a resolved call needs. `:unavailable` is a verdict, not a server.
  defmodule EmptyPool do
    def media_for_profiles(_profiles), do: [module: :unavailable]
  end

  @scenario Path.expand("../scenarios/webrtc-gw.exs", __DIR__)

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _config_pid} = SIP.Session.ConfigRegistry.start()
    :ok = SIP.Auth.Secret.start()

    # This scenario is the only reference one that calls `b2bua_resolve/1`, so it
    # is the only one whose `media_connect()` consults the host's media-server
    # selector (`SIP.Session.Media.use_mediaserver/1`, constrained path). Run from
    # the umbrella ROOT, `:kelixip` has started and `Kelix.Config.apply_app_env/1`
    # has written that key into the `:elixip2` env — so the pool of a kelixip
    # nobody configured answered `:unavailable`, and both tests died on a 503 they
    # never asked for. Green from `apps/elixip2`, red from the root, same code.
    #
    # These tests drive the scenario as the standalone tool does: no selector, the
    # `config_overrides` below decide. The third test installs one deliberately.
    SIP.Test.AppEnv.preserve([:mediaserver_selector])
    Application.delete_env(:elixip2, :mediaserver_selector)

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
    :ok = Mockup.set_peer(tp_pid, Manual)
    :ok = Mockup.attach_probe(tp_pid)

    {instance, _ref} = start_instance(module, stub, invite, [])
    send(instance, {:INVITE, invite, self(), stub})

    assert_receive {:replied, 100, "Trying", _req, _fields}, 5_000

    # Rung 1: a browser-shaped offer, built by the media server — not the
    # browser's own, which the phone never sees.
    assert_receive {:sip_mockup, {:request_sent, :INVITE, webrtc}}, 5_000
    assert offered_protocols(webrtc) == ["UDP/TLS/RTP/SAVPF", "UDP/TLS/RTP/SAVPF"]
    assert SIP.Session.extract_sdp(webrtc) != browser_sdp

    Manual.simulate(tp_pid, 488, 100)

    # Rung 2: the feedback profile, on a NEW CSeq. The phone's server
    # transaction for the INVITE it just refused is still alive, and two bodies
    # under one CSeq are a merged request (RFC 3261 §8.2.2.2) — answered 482.
    assert_receive {:sip_mockup, {:request_sent, :INVITE, avpf}}, 5_000
    assert offered_protocols(avpf) == ["RTP/AVPF", "RTP/AVPF"]
    assert hd(avpf.cseq) > hd(webrtc.cseq)
    assert avpf.callid == webrtc.callid
    assert avpf.ruri.domain == webrtc.ruri.domain

    Manual.simulate(tp_pid, 488, 100)

    # Rung 3, the bottom of the ladder.
    assert_receive {:sip_mockup, {:request_sent, :INVITE, avp}}, 5_000
    assert offered_protocols(avp) == ["RTP/AVP", "RTP/AVP"]
    assert hd(avp.cseq) > hd(avpf.cseq)

    # Through all of it the browser has been told nothing: the refusals are
    # between the gateway and the phone.
    refute_receive {:replied, 488, _reason, _req, _fields}, 200

    Manual.simulate(tp_pid, 200, 100)

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
    :ok = Mockup.set_peer(tp_pid, Manual)
    :ok = Mockup.attach_probe(tp_pid)

    {instance, _ref} = start_instance(module, stub, invite, profile: :webrtc_required)
    send(instance, {:INVITE, invite, self(), stub})

    assert_receive {:replied, 100, "Trying", _req, _fields}, 5_000
    assert_receive {:sip_mockup, {:request_sent, :INVITE, webrtc}}, 5_000
    assert offered_protocols(webrtc) == ["UDP/TLS/RTP/SAVPF", "UDP/TLS/RTP/SAVPF"]

    Manual.simulate(tp_pid, 488, 100)

    # The browser learns of it, which is what `_required` means.
    assert_receive {:replied, 488, _reason, _req, _fields}, 5_000
    assert_receive {:instance_done, _outcome}, 10_000
  end

  # The gateway terminates BOTH legs' media on the server, so no media server
  # means no call: nothing to answer the browser with, and no body for the
  # outbound INVITE. The scenario reads that verdict where record.exs reads it —
  # straight after `media_connect()` — and refuses before the phone is rung.
  #
  # The 503 is the point: the browser's offer was fine, we are the ones missing a
  # resource, and a 503 is what lets the proxy in front try another gateway. A 488
  # would send it back to the caller as its own fault.
  @tag timeout: 60_000
  test "no media server: the browser gets a 503 and the phone is never rung",
       %{scenario: module, stub: stub} do
    invite = inbound_invite(:nomedia)

    tp_pid = transport_pid(:nomedia)
    :ok = Mockup.set_peer(tp_pid, Manual)
    :ok = Mockup.attach_probe(tp_pid)

    Application.put_env(:elixip2, :mediaserver_selector, {EmptyPool, :media_for_profiles})
    on_exit(fn -> Application.delete_env(:elixip2, :mediaserver_selector) end)

    {instance, _ref} = start_instance(module, stub, invite, [])
    send(instance, {:INVITE, invite, self(), stub})

    assert_receive {:replied, 100, "Trying", _req, _fields}, 5_000
    assert_receive {:replied, 503, "Service Unavailable", _req, _fields}, 5_000

    # Nothing went out: the refusal happens before the call is placed, so no
    # handset rings for a call that cannot carry a word.
    refute_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 500

    assert_receive {:instance_done, {:error, "no media server available"}}, 10_000
  end
end
