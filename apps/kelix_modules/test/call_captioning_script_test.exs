defmodule Kelix.CallCaptioningScriptTest do
  @moduledoc """
  `apps/kelixip/scripts/call-captioning.exs`: the call flow, on the mockup media
  server. What the SpeechProcessor does with the text of each leg is
  `Mendooze.ConnTest`'s ("speech: …").
  """
  use ExUnit.Case, async: false

  alias Kelix.Mod.SipServers
  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

  @domain "example.com"
  @realm "visioassistance.net"
  @caller "alice"
  @password "secret"
  @dialled "0612345678"
  @ruri "sip:#{@dialled}@example.com"
  @trunk_peer "cc-trunk"

  @ha1 SIP.Auth.compute_ha1("MD5", @caller, @realm, @password)

  @audio """
  v=0\r
  o=- 1 1 IN IP4 192.168.1.50\r
  s=-\r
  c=IN IP4 192.168.1.50\r
  t=0 0\r
  m=audio 40000 RTP/AVP 0 8 101\r
  a=rtpmap:0 PCMU/8000\r
  a=rtpmap:8 PCMA/8000\r
  a=rtpmap:101 telephone-event/8000\r
  a=sendrecv\r
  """

  @audio_text @audio <>
                """
                m=text 40002 RTP/AVP 98 99\r
                a=rtpmap:98 t140/1000\r
                a=rtpmap:99 red/1000\r
                a=fmtp:99 98/98/98\r
                a=sendrecv\r
                """

  defmodule MockDialog do
    use GenServer
    def start_link(test), do: GenServer.start_link(__MODULE__, test)
    def init(test), do: {:ok, test}

    def handle_call({:replyreq, req, code, reason, fields}, _from, test) do
      send(test, {:replied, code, reason, fields, req})
      {:reply, :ok, test}
    end

    def handle_call({:newreq, req}, _from, test) do
      send(test, {:sent_on_inbound, req})
      {:reply, {:ok, self()}, test}
    end

    def handle_call(_msg, _from, test), do: {:reply, :ok, test}
    def handle_info(_msg, test), do: {:noreply, test}
  end

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()

    toml = Path.join(System.tmp_dir!(), "call_captioning_domains.toml")
    File.write!(toml, "[[domain]]\nname = \"#{@domain}\"\n")
    :ok = Kelix.Domains.reload(toml)

    on_exit(fn ->
      empty = Path.join(System.tmp_dir!(), "call_captioning_empty.toml")
      File.write!(empty, "")
      _ = Kelix.Domains.reload(empty)
      File.rm(toml)
    end)

    %{
      scenario:
        SIP.Scenario.Loader.load_file!(
          Path.expand("../../kelixip/scripts/call-captioning.exs", __DIR__)
        )
    }
  end

  setup do
    start_supervised!(SipServers.child_spec(:sip_servers, %{}))

    Application.put_env(:kelixip, :authdb_ha1_lookup, fn
      @caller, @realm -> {:ok, @ha1}
      _user, _realm -> :notfound
    end)

    on_exit(fn -> Application.delete_env(:kelixip, :authdb_ha1_lookup) end)
    :ok
  end

  defp create_trunk do
    {:ok, _} =
      SipServers.handle_control("server.create", %{
        "domain" => @domain,
        "slug" => "sip-trunk-prod",
        "type" => "sip-trunk",
        "primary_uri" => "sip:0123456789@10.0.0.9:5060;unittest=#{@trunk_peer}",
        "register" => false,
        "send_keepalive" => false
      })

    :ok
  end

  defp trunk_mockup do
    uri =
      %SIP.Uri{domain: "10.0.0.9", port: 5060} |> SIP.Uri.set_uri_param("unittest", @trunk_peer)

    tp = SIP.Transport.Selector.select_transport(uri).tp_pid
    :ok = Mockup.set_peer(tp, Manual)
    :ok = Mockup.attach_probe(tp)
    tp
  end

  defp invite(callid, sdp, auth \\ nil) do
    req = %{
      "Max-Forwards" => 70,
      method: :INVITE,
      ruri: %SIP.Uri{userpart: @dialled, domain: @domain},
      from: %SIP.Uri{userpart: @caller, domain: @domain, params: %{"tag" => "alice-tag"}},
      to: %SIP.Uri{userpart: @dialled, domain: @domain},
      contact: %SIP.Uri{userpart: @caller, domain: "10.0.0.1", port: 5060},
      callid: callid,
      cseq: [1, :INVITE],
      contenttype: "application/sdp",
      body: [%{contenttype: "application/sdp", data: sdp}],
      contentlength: byte_size(sdp)
    }

    if auth, do: Map.put(req, :proxyauthorization, auth), else: req
  end

  defp in_dialog(method, invite) do
    %{invite | method: method, body: [], contentlength: 0, cseq: [2, method]}
  end

  defp credentials(challenge) do
    response =
      SIP.Auth.compute_auth_response_from_ha1(
        "MD5",
        challenge["nonce"],
        @ha1,
        "INVITE",
        @ruri,
        %{"nc" => "00000001", "cnonce" => "0a4f113b", "qop" => "auth"}
      )

    %{
      "username" => @caller,
      "realm" => challenge["realm"],
      "nonce" => challenge["nonce"],
      "uri" => @ruri,
      "response" => response,
      "algorithm" => "MD5",
      "qop" => "auth",
      "nc" => "00000001",
      "cnonce" => "0a4f113b"
    }
  end

  defp start_instance(module, dialog, req) do
    test = self()

    {pid, ref} =
      spawn_monitor(fn ->
        outcome =
          SIP.Scenario.Runner.run_instance(module,
            dialog_pid: dialog,
            inbound_request: req,
            config_overrides: [
              domain: @domain,
              mediaserver: %{module: :mockup, url: "http://127.0.0.1:8080"}
            ]
          )

        send(test, {:instance_done, outcome})
      end)

    on_exit(fn -> if Process.alive?(pid), do: send(pid, {:scenario_ctl, :shutdown, :test}) end)
    {pid, ref}
  end

  defp authenticated_call(module, dialog, callid, sdp) do
    req = invite(callid, sdp)
    {instance, ref} = start_instance(module, dialog, req)
    send(instance, {:INVITE, req, self(), dialog})

    assert_receive {:replied, 100, "Trying", _f, _r}, 5_000
    assert_receive {:replied, 407, _reason, fields, _req}, 5_000
    challenge = Keyword.fetch!(fields, :proxyauthenticate)

    auth_req = invite(callid, sdp, credentials(challenge))
    send(instance, {:INVITE, auth_req, self(), dialog})
    {instance, ref, auth_req}
  end

  test "a caller that offers no text is refused with 488, once authenticated",
       %{scenario: module} do
    :ok = create_trunk()
    _tp = trunk_mockup()
    {:ok, dialog} = MockDialog.start_link(self())

    {instance, ref, _req} = authenticated_call(module, dialog, "cc-no-text", @audio)

    assert_receive {:replied, 488, _reason, _f, _r}, 5_000
    assert_receive {:instance_done, :ok}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
    refute_received {:sip_mockup, {:request_sent, :INVITE, _}}
  end

  defp put_mockup_env(env) do
    Application.put_env(:elixip2, MediaServer.Mockup, env)
    on_exit(fn -> Application.delete_env(:elixip2, MediaServer.Mockup) end)
  end

  test "without speech processing the caller gets 503 and the trunk never sees the call",
       %{scenario: module} do
    reason = "speech-server unreachable at http://127.0.0.1:9200: Couldn't connect to server"
    put_mockup_env(speech_available: {:error, {:speech_unavailable, reason}})
    :ok = create_trunk()
    _tp = trunk_mockup()
    {:ok, dialog} = MockDialog.start_link(self())

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        {instance, ref, _req} = authenticated_call(module, dialog, "cc-no-speech", @audio_text)

        assert_receive {:replied, 503, "Speech Processing Unavailable", _f, _r}, 5_000

        assert_receive {:instance_done, {:error, "speech processing unavailable: " <> ^reason}},
                       10_000

        assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
      end)

    refute_received {:sip_mockup, {:request_sent, :INVITE, _}}
    assert log =~ "failed (state place_call): \"speech processing unavailable: #{reason}\""
  end

  test "a SpeechProcessor that cannot be set up on the answer refuses the call at once",
       %{scenario: module} do
    put_mockup_env(
      speech_bridge_failure:
        {:speech_failed, :audio, {:jsr309_error, "Could not create speech processor\n"}}
    )

    :ok = create_trunk()
    tp = trunk_mockup()
    {:ok, dialog} = MockDialog.start_link(self())

    ExUnit.CaptureLog.capture_log(fn ->
      {instance, ref, _req} = authenticated_call(module, dialog, "cc-sp-fails", @audio_text)
      assert_receive {:sip_mockup, {:request_sent, :INVITE, _}}, 5_000

      Manual.simulate(tp, 200, 50)
      assert_receive {:replied, 503, "Speech Processing Unavailable", _f, _r}, 5_000
      assert_receive {:sip_mockup, {:request_sent, :BYE, _}}, 5_000

      # At once, not after timer H waiting for an ACK no 503 ever gets.
      assert_receive {:instance_done,
                      {:error, "speech processing unavailable: the media server could not" <> _}},
                     5_000

      assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
    end)
  end

  test "speech lost during the call keeps the call and says so in the log",
       %{scenario: module} do
    :ok = create_trunk()
    tp = trunk_mockup()
    {:ok, dialog} = MockDialog.start_link(self())

    {instance, ref, req} = authenticated_call(module, dialog, "cc-speech-lost", @audio_text)
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _}}, 5_000
    Manual.simulate(tp, 200, 50)
    assert_receive {:replied, 200, _reason, _f, _r}, 5_000
    send(instance, {:ACK, in_dialog(:ACK, req), self(), dialog})
    assert_receive {:sip_mockup, {:request_sent, :ACK, _}}, 5_000

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        send(
          instance,
          {:ms_event, make_ref(), {:speech_service, :asr, :down, "backend unavailable"}}
        )

        send(instance, {:ms_event, make_ref(), {:speech_service, :asr, :up, ""}})
        Process.sleep(300)
      end)

    assert log =~ "speech processing unavailable on the"
    assert log =~ "asr down (backend unavailable); the call goes on without it"
    assert log =~ "speech processing available on the"
    refute_received {:sip_mockup, {:request_sent, :BYE, _}}
    assert Process.alive?(instance)

    send(instance, {:BYE, in_dialog(:BYE, req), self(), dialog})
    assert_receive {:instance_done, :ok}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end

  test "the call goes to the trunk with audio and text, AMR-WB, PCMA then PCMU",
       %{scenario: module} do
    :ok = create_trunk()
    tp = trunk_mockup()
    {:ok, dialog} = MockDialog.start_link(self())

    {instance, ref, req} = authenticated_call(module, dialog, "cc-ok", @audio_text)

    assert_receive {:sip_mockup, {:request_sent, :INVITE, fwd}}, 5_000
    offer = SIP.Msg.Ops.sdp_body(fwd)
    assert SIP.Msg.Ops.media_kinds(offer) == [:audio, :text]
    [audio_line] = Regex.run(~r/^m=audio .*$/m, offer)
    assert offer =~ ~r/a=rtpmap:\d+ AMR-WB\/16000/
    assert audio_line =~ ~r/RTP\/AVP \d+ 8 0( |\r|$)/
    refute offer =~ "opus"

    Manual.simulate(tp, 200, 50)
    assert_receive {:replied, 200, _reason, _f, _r}, 5_000

    send(instance, {:ACK, in_dialog(:ACK, req), self(), dialog})
    assert_receive {:sip_mockup, {:request_sent, :ACK, _}}, 5_000

    send(instance, {:BYE, in_dialog(:BYE, req), self(), dialog})
    assert_receive {:instance_done, :ok}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end
end
