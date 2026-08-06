defmodule Kelix.Mod.McuCallTest do
  @moduledoc """
  The call path end to end: the reference `mcu.exs` driven by a spawned scenario
  instance, the real adapter, and a recording MCU transport (design
  `docs/design/mcu_module.md` §13, "Integration" + "Unit, mocked MCU").

  What it pins down is the part §2 says must be transcribed faithfully: the **RPC
  order** of an inbound call and the **answer-time / ACK-time split** — a caller that
  never ACKs must never enter the mix.
  """
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Kelix.Mcu.TestStub
  alias Kelix.Mod.Mcu
  alias Kelix.Mod.Mcu.{Client, Config, Conference}
  alias Kelix.Mod.Mcu.Adapter.Conn

  # The media servers the module drives now come from [mediaserver.pool.*], decoded
  # by Kelix.Config; the registry takes the resulting list directly so a test needs
  # no config file.
  @mediaservers [%{name: "mcu1", url: "http://127.0.0.1:18080"}]

  @domain "example.com"
  @rec_port 52_014
  # the address the media server itself reports on StartReceiving (§16.5) —
  # what the answer must advertise, and no longer a config value
  @media_ip "203.0.113.12"

  # A plain-RTP audio offer from a SIP phone.
  @offer """
  v=0\r
  o=- 1 1 IN IP4 192.168.1.50\r
  s=-\r
  c=IN IP4 192.168.1.50\r
  t=0 0\r
  m=audio 40000 RTP/AVP 8 0 101\r
  a=rtpmap:8 PCMA/8000\r
  a=rtpmap:0 PCMU/8000\r
  a=rtpmap:101 telephone-event/8000\r
  a=sendrecv\r
  """

  # A video phone: audio + H.264, with the profile every handset states.
  @offer_video """
  v=0\r
  o=- 1 1 IN IP4 192.168.1.50\r
  s=-\r
  c=IN IP4 192.168.1.50\r
  t=0 0\r
  m=audio 40000 RTP/AVP 8\r
  a=rtpmap:8 PCMA/8000\r
  a=sendrecv\r
  m=video 40002 RTP/AVPF 99\r
  b=AS:512\r
  a=rtpmap:99 H264/90000\r
  a=fmtp:99 profile-level-id=42e01f;packetization-mode=1\r
  a=rtcp-fb:99 nack\r
  a=sendrecv\r
  """

  # Hold, the flavour that starves our reception: the peer says it will not send.
  @offer_hold_inactive String.replace(@offer_video, "a=sendrecv", "a=inactive")

  # Hold, the flavour that does NOT: a caller holding with sendonly keeps sending
  # music-on-hold, so its RTP never stops and the watchdog must stay armed.
  @offer_hold_sendonly String.replace(@offer_video, "a=sendrecv", "a=sendonly")

  # RFC 5939, taken from a real capture (LiveVideoPlugin 4.4.10): AVP on the m= line,
  # AVPF declared as a potential configuration, and the feedback types it wants.
  @offer_capneg """
  v=0\r
  o=- 1 1 IN IP4 192.168.1.50\r
  s=-\r
  c=IN IP4 192.168.1.50\r
  t=0 0\r
  a=tcap:1 RTP/AVPF\r
  m=audio 40000 RTP/AVP 8\r
  a=rtpmap:8 PCMA/8000\r
  a=pcfg:1 t=1\r
  a=sendrecv\r
  m=video 40002 RTP/AVP 99\r
  a=rtpmap:99 H264/90000\r
  a=fmtp:99 profile-level-id=42e01f;packetization-mode=1\r
  a=pcfg:1 t=1\r
  a=rtcp-fb:* nack\r
  a=rtcp-fb:* nack pli\r
  a=rtcp-fb:* ccm fir\r
  a=rtcp-fb:* ccm tmmbr\r
  a=rtcp-fb:* goog-remb\r
  a=sendrecv\r
  """

  # A total-conversation terminal: audio, video and T.140 with RFC 4103 redundancy.
  # The text payload types are deliberately NOT the ones we would pick locally
  # (105/106), so the answer proves it reuses the offerer's numbering everywhere,
  # including inside the red fmtp.
  @offer_tc """
  v=0\r
  o=- 1 1 IN IP4 192.168.1.50\r
  s=-\r
  c=IN IP4 192.168.1.50\r
  t=0 0\r
  m=audio 40000 RTP/AVP 8\r
  a=rtpmap:8 PCMA/8000\r
  a=sendrecv\r
  m=video 40002 RTP/AVP 99\r
  a=rtpmap:99 H264/90000\r
  a=sendrecv\r
  m=text 40004 RTP/AVP 98 97\r
  a=rtpmap:98 red/1000\r
  a=rtpmap:97 t140/1000\r
  a=fmtp:98 97/97/97\r
  a=sendrecv\r
  """

  # A text terminal that does not do redundancy: plain T.140 only.
  @offer_text_plain """
  v=0\r
  o=- 1 1 IN IP4 192.168.1.50\r
  s=-\r
  c=IN IP4 192.168.1.50\r
  t=0 0\r
  m=audio 40000 RTP/AVP 8\r
  a=rtpmap:8 PCMA/8000\r
  a=sendrecv\r
  m=text 40004 RTP/AVP 97\r
  a=rtpmap:97 t140/1000\r
  a=sendrecv\r
  """

  # A video offer that states H.264 and no profile at all — a gateway, or a phone
  # that leaves the fmtp out. RFC 6184 makes silence mean Baseline level 1.0, which
  # is not what an HD720p mixer sends.
  @offer_video_no_fmtp """
  v=0\r
  o=- 1 1 IN IP4 192.168.1.50\r
  s=-\r
  c=IN IP4 192.168.1.50\r
  t=0 0\r
  m=audio 40000 RTP/AVP 8\r
  a=rtpmap:8 PCMA/8000\r
  a=sendrecv\r
  m=video 40002 RTP/AVP 99\r
  a=rtpmap:99 H264/90000\r
  a=sendrecv\r
  """

  # An offer with no codec the conference accepts (G.729 only).
  @offer_no_codec """
  v=0\r
  o=- 1 1 IN IP4 192.168.1.50\r
  s=-\r
  c=IN IP4 192.168.1.50\r
  t=0 0\r
  m=audio 40000 RTP/AVP 18\r
  a=rtpmap:18 G729/8000\r
  a=sendrecv\r
  """

  # A WebRTC-gateway-shaped offer: DTLS-SRTP + ICE, rtcp-mux, opus.
  @offer_secure """
  v=0\r
  o=- 1 1 IN IP4 192.168.1.50\r
  s=-\r
  c=IN IP4 192.168.1.50\r
  t=0 0\r
  m=audio 40000 UDP/TLS/RTP/SAVPF 111\r
  a=rtpmap:111 opus/48000/2\r
  a=fingerprint:sha-256 AA:BB:CC\r
  a=setup:actpass\r
  a=ice-ufrag:abcd\r
  a=ice-pwd:0123456789abcdef\r
  a=rtcp-mux\r
  a=sendrecv\r
  """

  defmodule MockDialog do
    @moduledoc "Captures the SIP replies the script composes, like the registrar test."
    use GenServer

    def start_link(test), do: GenServer.start_link(__MODULE__, test)
    def init(test), do: {:ok, test}

    def handle_call({:replyreq, req, code, reason, fields}, _from, test) do
      send(test, {:replied, code, reason, fields, req})
      {:reply, :ok, test}
    end

    # An in-dialog request we originate (INFO, BYE) reaches the dialog as :newreq.
    # Reported so a test can read what the script actually put on the wire.
    def handle_call({:newreq, req}, _from, test) do
      send(test, {:sent_request, Map.get(req, :method), req})
      {:reply, {:ok, self()}, test}
    end

    def handle_call(msg, _from, test) do
      send(test, {:dialog_call, msg})
      {:reply, :ok, test}
    end

    def handle_cast(_msg, test), do: {:noreply, test}
    def handle_info(_msg, test), do: {:noreply, test}
  end

  setup_all do
    %{
      scenario:
        SIP.Scenario.Loader.load_file!(Path.expand("../../kelixip/scripts/mcu.exs", __DIR__))
    }
  end

  setup context do
    {:ok, config} =
      Config.parse(%{
        "did_range" => "8000-8009",
        # no codec list: the media server arbitrates (P8a). `dtmf` is what says
        # telephone-event is proposed, and it is on by default.
        "dtmf" => true
      })

    start_supervised!({Mcu, config: config, module_name: "mcu", mediaservers: @mediaservers})

    # `@tag start_receiving:` lets one test pretend the server is an older build
    returns = %{
      "StartReceiving" => Map.get(context, :start_receiving, {:ok, [@rec_port, @media_ip]})
    }

    start_supervised!(
      {Client,
       name: "mcu1",
       base_url: "http://127.0.0.1:18080",
       transport: TestStub.transport(self(), returns),
       register: {Mcu, "mcu1"},
       reconnect_ms: 0},
      id: :client_mcu1
    )

    wait_for_client()

    {:ok, %{uid: uid, did: did}} =
      Mcu.handle_control("conference.create", %{"domain" => @domain, "name" => "Weekly"})

    # drain the setup RPCs (queue creation + conference creation) so each test reads
    # the call's own sequence off its mailbox
    _setup_rpcs = TestStub.rpc_order()

    %{uid: uid, did: did}
  end

  defp wait_for_client(attempts \\ 100) do
    case Mcu.mediaserver("mcu1") do
      {:ok, %{status: :up, client: pid}} when is_pid(pid) ->
        :ok

      _ when attempts > 0 ->
        Process.sleep(10)
        wait_for_client(attempts - 1)

      _ ->
        flunk("the mcu1 client never came up")
    end
  end

  # ── SIP fixtures ─────────────────────────────────────────────────────────────

  defp invite(did, opts \\ []) do
    %{
      method: :INVITE,
      ruri: %SIP.Uri{userpart: did, domain: @domain},
      from: %SIP.Uri{userpart: "alice", domain: "phone.example.com"},
      to: %SIP.Uri{userpart: did, domain: @domain},
      callid: "call-#{System.unique_integer([:positive])}",
      cseq: [1, :INVITE],
      body: Keyword.get(opts, :sdp, @offer),
      contenttype: "application/sdp"
    }
  end

  # RFC 5168: what a video phone sends when its decoder needs a fresh intra-frame.
  defp media_control_info() do
    %{
      method: :INFO,
      contenttype: "application/media_control+xml",
      body:
        ~s(<?xml version="1.0" encoding="utf-8" ?><media_control><vc_primitive>) <>
          ~s(<to_encoder><picture_fast_update/></to_encoder></vc_primitive></media_control>)
    }
  end

  defp spawn_call(scenario, dialog, req) do
    {pid, _ref} =
      SIP.Scenario.Runner.spawn_uas_instance(scenario,
        dialog_pid: dialog,
        inbound_request: req,
        config_overrides: [domain: @domain]
      )

    on_exit(fn -> if Process.alive?(pid), do: send(pid, {:scenario_ctl, :shutdown, :test}) end)
    pid
  end

  defp start_call(scenario, req) do
    {:ok, dialog} = MockDialog.start_link(self())
    pid = spawn_call(scenario, dialog, req)
    send(pid, {:INVITE, req, nil, dialog})
    {pid, dialog}
  end

  defp participants(uid) do
    {:ok, conf} = Mcu.conference(uid)
    Conference.participants(conf)
  end

  # The AND needs the row's media set, which `joined/2` fills after attach returns.
  # Waiting for it is not incidental: with an empty set the documented fallback reaps
  # the leg on its first timeout, which is right in production (a leg that never
  # joined) and wrong in a test that means to check the AND.
  defp joined_participant(uid) do
    wait_for(fn ->
      case participants(uid) do
        [%{medias: medias} = part] when map_size(medias) > 0 -> part
        _ -> nil
      end
    end)
  end

  defp wait_for(fun, attempts \\ 200) do
    case fun.() do
      nil when attempts > 0 ->
        Process.sleep(10)
        wait_for(fun, attempts - 1)

      false when attempts > 0 ->
        Process.sleep(10)
        wait_for(fun, attempts - 1)

      value ->
        value
    end
  end

  # ── the script as kelixip loads it ───────────────────────────────────────────

  describe "the reference script's contract" do
    test "it is a :uas_invite scenario, handles shutdown, and declares the mcu module", ctx do
      assert ctx.scenario.__scenario_type__() == :uas_invite
      # a script that cannot be told to wind down is refused at load (§5.3)
      assert function_exported?(ctx.scenario, :__state___shutdown__, 1)

      Kelix.ModuleRegistry.register("mcu", Mcu, %{})
      on_exit(fn -> Kelix.ModuleRegistry.unregister("mcu") end)

      # `config(uses_modules: [:mcu])` is what turns "the module is not installed"
      # from a dead instance on the first INVITE into a load-time error
      assert :ok = Kelix.ScriptRegistry.check_declared_modules(ctx.scenario, "mcu.exs")
    end
  end

  # ── the happy path ───────────────────────────────────────────────────────────

  describe "a SIP phone joins the conference" do
    test "180, then a 200 whose SDP answers the offered audio", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did))

      assert_receive {:replied, 180, "Ringing", _fields, _req}, 2000
      assert_receive {:replied, 200, _reason, fields, _req}, 2000

      answer = fields[:body]
      # §6.3 rule 3: the c= line is the address the media server reported on
      # StartReceiving (§16.5) — kelixip holds no media address of its own
      assert answer =~ "c=IN IP4 #{@media_ip}"
      # the receive port StartReceiving returned
      assert answer =~ "m=audio #{@rec_port} RTP/AVP"
      # rule 1: the offer's payload-type numbering is reused verbatim
      assert answer =~ "a=rtpmap:8 PCMA/8000"
      assert answer =~ "a=rtpmap:101 telephone-event/8000"
      assert answer =~ "a=fmtp:101 0-16"
      # the mixed participant is sendrecv (rule 7)
      assert answer =~ "a=sendrecv"
    end

    # No fallback on purpose: a guessed address produces a 200 whose media silently
    # goes nowhere, which is worse than a refused call (§16.5).
    @tag start_receiving: {:ok, [52_014]}
    test "a media server too old to report its media address gets no answer", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did))

      assert_receive {:replied, 180, "Ringing", _fields, _req}, 2000
      assert_receive {:replied, 500, _reason, _fields, _req}, 2000
      refute_received {:replied, 200, _reason, _fields, _req}
    end

    test "the RPC order follows §6.2 and splits at the ACK", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      # answer time: the participant exists and receives, but sends nothing yet.
      # SetRTPProperties carries natLatch, which the script asks for on every leg.
      answer_time = TestStub.rpc_order()
      assert answer_time == ["CreateParticipant", "StartReceiving", "SetRTPProperties"]

      # ACK time: codec, sending, and only then the mixer. The banner comes last:
      # `mcu.exs` asks for `displayname: :auto`, sent once the leg is in the mix.
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      ack_time = wait_for(fn -> non_empty(TestStub.rpc_order()) end)

      # P7/S1: the RTP watchdog is armed once the leg is really in the mix — one
      # StartRTPTimeout per receiving media, and NEVER on text (§16.1).
      assert ack_time == [
               "SetAudioCodec",
               "StartSending",
               "AddSidebarParticipant",
               "StartRTPTimeout",
               "SetParticipantDisplayName"
             ]
    end

    test "a retransmitted ACK does not re-run the ACK-time sequence", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      first = wait_for(fn -> non_empty(TestStub.rpc_order()) end)
      assert "StartSending" in first

      connected =
        wait_for(fn -> Enum.find(participants(ctx.uid), &(&1.state == :connected)) end)

      # Over UDP the caller re-sends the ACK for every retransmitted 200
      # (RFC 3261 §13.2.2.4); the leg must not rejoin the mixer. The INFO
      # serialises: once it is answered, both ACK copies have been processed,
      # and the only RPC they left behind is the INFO's own SendFPU.
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      send(pid, {:INFO, media_control_info(), nil, dialog})
      assert_receive {:replied, 200, "OK", _fields, _req}, 2000

      assert wait_for(fn -> non_empty(TestStub.rpc_order()) end) == ["SendFPU"]

      # still one participant, joined once: the join timestamp did not move
      [row] = participants(ctx.uid)
      assert row.state == :connected
      assert row.joined_at == connected.joined_at
    end

    test "attach/1 is idempotent: a second attach does not re-emit participant.joined", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      joined_log =
        capture_log(fn ->
          send(pid, {:ACK, %{method: :ACK}, nil, dialog})
          assert wait_for(fn -> Enum.find(participants(ctx.uid), &(&1.state == :connected)) end)
        end)

      # the channel works: the first join is an event…
      assert joined_log =~ "participant.joined"
      [connected] = participants(ctx.uid)

      # …and a script copy that kept re-attaching per ACK is absorbed by the
      # registry (§11.1, invariant 3): no second event, the join timestamp holds
      second_log = capture_log(fn -> assert :ok = Mcu.attach(connected) end)
      refute second_log =~ "participant.joined"

      [row] = participants(ctx.uid)
      assert row.joined_at == connected.joined_at
    end

    test "the leg asks the MCU to latch onto a symmetric NAT", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      # `mcu.exs` opts in for every leg: a conference leg only ever answers, so the
      # address we are told to send to is the caller's own — a private one for any
      # handset behind a NAT. Plain RTP/AVP offer, so nothing else is set.
      assert_received {:rpc, "SetRTPProperties", [42, 7, 0, props, 0]}
      assert props == %{"natLatch" => "1"}
    end

    test "CreateParticipant and StartSending carry the right arguments", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      # name from the From header, RTP participant, default mosaic and sidebar (§3.3)
      assert_received {:rpc, "CreateParticipant", [42, "alice@phone_example_com", 0, 0, 0]}
      # audio (0), the offered PT numbering, main role, RTP protocol, and the offer's
      # codec attributes (P8a): the media server negotiates against them and answers
      # with what it accepted.
      assert_received {:rpc, "StartReceiving", [42, 7, 0, rtp_map, 0, 0, offer]}
      assert rtp_map == %{"8" => 8, "0" => 0, "101" => 100}
      # this offer carries no a=fmtp, so the struct is present but its fmtp map empty —
      # the member always travels, so the server never has to distinguish "absent" from
      # "no fmtp offered"
      assert offer == %{"fmtp" => %{}}

      send(pid, {:ACK, %{method: :ACK}, nil, dialog})

      # the mixer sends PCMA (the first codec common to offer and conference) to the
      # address and port the offer advertised
      assert_receive {:rpc, "SetAudioCodec", [42, 7, 8]}, 2000
      assert_receive {:rpc, "StartSending", [42, 7, 0, "192.168.1.50", 40_000, _map, 0]}, 2000
      assert_receive {:rpc, "AddSidebarParticipant", [42, 0, 7]}, 2000
    end

    # The offer's fmtp is what the media server negotiates against, so it has to reach
    # it unchanged — the reason parse/1 keeps a raw form alongside the parsed structs.
    # The central property of P8a: the offer IS the menu. Before step 3b, kelixip
    # intersected the offer with the conference's codec list before the server saw it,
    # so a codec absent from that list was dropped silently and the server never got to
    # say whether it supported it.
    test "every offered codec is proposed to the server, not just the configured ones", ctx do
      # G.722 (9) and PCMU (0) are in this offer; the old default conference list would
      # have decided on them locally
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      assert_received {:rpc, "StartReceiving", [42, 7, 0, rtp_map, 0, 0, _offer]}
      # the whole offered set, telephone-event included, is what the server arbitrates
      assert rtp_map == %{"8" => 8, "0" => 0, "101" => 100}
    end

    # DTMF is a policy switch, not a codec list: it is the one thing a caller cannot
    # overrule, so it is filtered before the server is asked.
    test "dtmf = false drops the telephone-event payload type from the proposal", ctx do
      {:ok, conf} = Mcu.create_conference(@domain, name: "no dtmf", dtmf: false)
      {_pid, _dialog} = start_call(ctx.scenario, invite(conf.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      assert_received {:rpc, "StartReceiving", [_conf, _part, 0, rtp_map, 0, 0, _offer]}
      refute Map.has_key?(rtp_map, "101")
      assert Map.has_key?(rtp_map, "8")
    end

    test "the offer's fmtp is forwarded verbatim", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_video))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      assert_received {:rpc, "StartReceiving", [42, 7, 1, _map, 0, 0, offer]}

      assert offer == %{
               "fmtp" => %{"99" => "profile-level-id=42e01f;packetization-mode=1"}
             }
    end

    # The verdict also picks the PRIMARY codec, not just the send map: telling the mixer
    # to encode a codec the server filtered on receive would negotiate successfully and
    # decode nothing.
    @tag start_receiving: {:ok, [@rec_port, @media_ip, %{"0" => "", "101" => ""}]}
    test "the primary codec comes from the accepted set", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})

      # the offer proposed PCMA first, but the server accepted only PCMU (0) and
      # telephone-event — so PCMU is what the mixer is told to encode, never the DTMF
      assert_receive {:rpc, "SetAudioCodec", [42, 7, 0]}, 2000
    end

    # The verdict restricts what we SEND: never a codec the server just filtered on
    # receive. A stub that returns only [port, ip] is a pre-P8a server, which is what
    # every other test here exercises — this one is the delegated path.
    @tag start_receiving: {:ok, [@rec_port, @media_ip, %{"8" => ""}]}
    test "the send map is restricted to what the server accepted", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})

      # the offer proposed PCMA, PCMU and telephone-event; the server accepted PCMA
      # alone, so that is all we send
      assert_receive {:rpc, "StartSending", [42, 7, 0, _ip, _port, send_map, 0]}, 2000
      assert send_map == %{"8" => 8}
    end

    # The two boundary cases of the contract, in one answer: a PT accepted with a
    # NON-EMPTY fmtp is advertised with that exact string; a PT accepted with an EMPTY
    # one gets an a=rtpmap and no a=fmtp; a PT the server did not name is not
    # advertised at all.
    @tag start_receiving:
           {:ok,
            [
              @rec_port,
              @media_ip,
              %{"8" => "", "101" => "0-15"}
            ]}
    test "the answer is built from the server's verdict, verbatim", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, fields, _req}, 2000

      answer = fields[:body]

      # accepted with no fmtp: rtpmap only
      assert answer =~ "a=rtpmap:8 PCMA/8000"
      refute answer =~ "a=fmtp:8"

      # accepted with an fmtp: the server's string, NOT the 0-16 kelixip used to
      # synthesise — proving the value is relayed and not rebuilt
      assert answer =~ "a=rtpmap:101 telephone-event/8000"
      assert answer =~ "a=fmtp:101 0-15"

      # PCMU was offered and proposed, but the server did not accept it
      refute answer =~ "a=rtpmap:0 PCMU/8000"
    end

    test "the participant row tracks ringing → connected", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      # the slot is taken from admit/2 onwards — a ringing leg holds one
      [part] = participants(ctx.uid)
      assert part.state == :ringing
      assert part.name == "alice@phone_example_com"
      # bound by the adapter once CreateParticipant answered
      assert part.part_id == 7
      assert is_pid(part.conn)

      send(pid, {:ACK, %{method: :ACK}, nil, dialog})

      connected = wait_for(fn -> Enum.find(participants(ctx.uid), &(&1.state == :connected)) end)
      assert connected.medias.audio.codec == "PCMA"
      assert connected.medias.audio.rec_port == @rec_port
      assert connected.joined_at
    end

    test "BYE tears the leg down: the MCU side is released and the slot freed", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      assert_receive {:rpc, "AddSidebarParticipant", _params}, 2000
      _drain = TestStub.rpc_order()

      send(pid, {:BYE, %{method: :BYE}, nil, dialog})
      assert_receive {:replied, 200, "OK", _fields, _req}, 2000

      teardown = wait_for(fn -> non_empty(TestStub.rpc_order()) end)
      assert "StopSending" in teardown
      assert "StopReceiving" in teardown
      assert "DeleteParticipant" in teardown

      assert wait_for(fn -> participants(ctx.uid) == [] end)
    end
  end

  # ── video (P3) ───────────────────────────────────────────────────────────────

  describe "a video phone joins" do
    test "the answer carries the video plane: port, bandwidth, fmtp and feedback", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_video))
      assert_receive {:replied, 200, _reason, fields, _req}, 2000

      answer = fields[:body]
      assert answer =~ "m=video #{@rec_port} RTP/AVPF 99"
      assert answer =~ "a=rtpmap:99 H264/90000"
      # §6.3 rule 8: min(offered 512, the conference profile's 1024)
      assert answer =~ "b=AS:512"
      # H.264 interop: the offered profile is reflected, the offerer's own
      # sprop-parameter-sets never would be
      assert answer =~ "a=fmtp:99 profile-level-id=42e01f;packetization-mode=1"
      # an AVPF offer gets the feedback types advertised back, so its PLI/FIR are legitimate
      assert answer =~ "a=rtcp-fb:99 nack"
      refute answer =~ "m=video 0 "
    end

    test "the video RPCs are the ones §6.2 specifies, in order", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_video))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      # answer time: one participant, a receive plane per media, no sending yet
      assert TestStub.rpc_order() == [
               "CreateParticipant",
               "StartReceiving",
               "SetRTPProperties",
               "StartReceiving",
               "SetRTPProperties"
             ]

      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      ack_time = wait_for(fn -> non_empty(TestStub.rpc_order()) end)

      assert ack_time == [
               "SetAudioCodec",
               "StartSending",
               "SetVideoCodec",
               "StartSending",
               "AddSidebarParticipant",
               "AddMosaicParticipant",
               # P7/S1: one watchdog per receiving media (§16.1), armed once the leg
               # is really in the mix
               "StartRTPTimeout",
               "StartRTPTimeout",
               # the script's `displayname: :auto` banner, from the scenario process,
               # before the registry's layout follow-up on `{:joined}`
               "SetParticipantDisplayName",
               "SetCompositionType"
             ]
    end

    test "the video RPCs carry the offered profile and the conference's own", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_video))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      # answer time carries the transport properties only
      assert_receive {:rpc, "SetRTPProperties", [42, 7, 1, props, 0]}, 2000
      assert props["useNACK"] == "1"
      assert props["natLatch"] == "1"
      refute Map.has_key?(props, "codec.h264.profile-level-id")

      send(pid, {:ACK, %{method: :ACK}, nil, dialog})

      # SetVideoCodec carries the conference's inline profile (§5.1) — size, fps,
      # bitrate, intra period — because every leg is encoded from the same mosaic,
      # plus the H.264 profile the peer asked for: this map IS the encoder's
      # properties (`videoProperties`), and it replaces whatever SetRTPProperties set
      assert_receive {:rpc, "SetVideoCodec", [42, 7, 99, 6, 15, 1024, 300, encoder, 0]}, 2000
      assert encoder == %{"h264.profile-level-id" => "42e01f"}
      assert_receive {:rpc, "AddMosaicParticipant", [42, 0, 7]}, 2000
    end

    # Decision 11: the media server owns its decode capability, so the conference
    # declares no profile of its own. On the legacy path (no verdict) an offer that
    # states nothing is therefore answered with nothing — kelixip has nothing truthful
    # to say about what the mixer accepts.
    test "with no verdict and no offered profile, no fmtp is invented", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_video_no_fmtp))
      assert_receive {:replied, 200, _reason, fields, _req}, 2000

      assert fields[:body] =~ "a=rtpmap:99 H264/90000"
      refute fields[:body] =~ "a=fmtp:99"
    end

    # …and on the delegated path the server supplies it. This pins rule 9's invariant:
    # what the answer ANNOUNCES and what SetVideoCodec asks the encoder for are the
    # same string, because the second is a relay of the first and not a second decision.
    @tag start_receiving:
           {:ok,
            [
              @rec_port,
              @media_ip,
              # the stub answers every media with the same verdict, so the audio PT has
              # to be in it or the audio plane is declined and the leg never attaches
              %{"8" => "", "99" => "profile-level-id=640028;packetization-mode=1"}
            ]}
    test "the profile the server negotiated is announced AND given to the encoder", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_video_no_fmtp))
      assert_receive {:replied, 200, _reason, fields, _req}, 2000

      assert fields[:body] =~ "a=fmtp:99 profile-level-id=640028;packetization-mode=1"

      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      assert_receive {:rpc, "SetVideoCodec", [42, 7, 99, 6, 15, 1024, 300, encoder, 0]}, 2000

      # the packetization mode travels with the profile, by the same channel and for the
      # same reason: it is what bounds the slices the encoder produces, and server-side it
      # decides between VAAPI and libx264
      assert encoder == %{
               "h264.profile-level-id" => "640028",
               "h264.packetization-mode" => "1"
             }
    end

    test "a profile the offer does state still wins over ours", ctx do
      # Main 4.0, deliberately different from the conference's 42e01f: reflection
      # must win, because profile-level-id has to match for the ends to decode
      offer =
        String.replace(
          @offer_video,
          "a=fmtp:99 profile-level-id=42e01f;packetization-mode=1",
          "a=fmtp:99 profile-level-id=4d0028;packetization-mode=1"
        )

      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: offer))
      assert_receive {:replied, 200, _reason, fields, _req}, 2000

      assert fields[:body] =~ "a=fmtp:99 profile-level-id=4d0028;packetization-mode=1"
      refute fields[:body] =~ "42e01f"

      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      assert_receive {:rpc, "SetVideoCodec", [42, 7, 99, 6, 15, 1024, 300, encoder, 0]}, 2000
      assert encoder == %{"h264.profile-level-id" => "4d0028"}
    end

    # Turning a media off used to be expressed as an incompatible codec list; since
    # the media server arbitrates codecs (P8a), it is `medias` that says it.
    test "a video-less conference declines the video and keeps the audio", ctx do
      {:ok, %{did: did}} =
        Mcu.handle_control("conference.create", %{
          "domain" => @domain,
          "did" => "8300",
          "medias" => ["audio"]
        })

      {_pid, _dialog} = start_call(ctx.scenario, invite(did, sdp: @offer_video))
      assert_receive {:replied, 200, _reason, fields, _req}, 2000

      answer = fields[:body]
      # no common video codec ⇒ port 0, and the call proceeds audio-only (§6.3 rule 2)
      assert answer =~ "m=video 0 RTP/AVPF 99"
      assert answer =~ "m=audio #{@rec_port} RTP/AVP"
    end
  end

  describe "a WebRTC gateway leg joins (P4)" do
    test "the DTLS+ICE offer is answered and the leg reaches the mix", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_secure))
      assert_receive {:replied, 200, _reason, fields, _req}, 2000

      answer = fields[:body]
      # ICE-lite is session level and answers only (§6.3 rule 5)
      assert answer =~ "a=ice-lite"
      assert answer =~ "a=setup:passive"
      assert answer =~ "a=fingerprint:sha-256 "
      assert answer =~ "a=ice-ufrag:"
      assert answer =~ "a=candidate:"
      # the transport of the offer is mirrored (rule 4)
      assert answer =~ "m=audio #{@rec_port} UDP/TLS/RTP/SAVPF"

      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      assert_receive {:rpc, "AddSidebarParticipant", [42, 0, 7]}, 2000
      assert wait_for(fn -> Enum.find(participants(ctx.uid), &(&1.state == :connected)) end)
    end
  end

  describe "total conversation — a T.140 leg joins" do
    test "the text section is answered with red + t140 in the offerer's numbering", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_tc))
      assert_receive {:replied, 200, _reason, fields, _req}, 2000

      answer = fields[:body]
      assert answer =~ "m=audio #{@rec_port} RTP/AVP"
      assert answer =~ "m=video #{@rec_port} RTP/AVP"
      # the text m= line carries both formats, on the caller's payload types
      assert answer =~ "m=text #{@rec_port} RTP/AVP"
      assert answer =~ "a=rtpmap:98 red/1000"
      assert answer =~ "a=rtpmap:97 t140/1000"
      # RFC 4103 §5: red names the T.140 payload type, primary + 2 redundant — and
      # it names the CALLER's 97, not our local 106
      assert answer =~ "a=fmtp:98 97/97/97"
      refute answer =~ "a=fmtp:98 106"
      # nothing was declined
      refute answer =~ "m=text 0 "
    end

    test "the RPC sequence gains SetTextCodec, and no text join RPC", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_tc))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      # answer time: one StartReceiving per media, in the offer's order, each
      # followed by the properties call. This offer is plain RTP/AVP, so natLatch is
      # the only thing that call carries — the H.264 profile travels with
      # SetVideoCodec at ACK time instead.
      assert TestStub.rpc_order() == [
               "CreateParticipant",
               "StartReceiving",
               "SetRTPProperties",
               "StartReceiving",
               "SetRTPProperties",
               "StartReceiving",
               "SetRTPProperties"
             ]

      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      ack_time = wait_for(fn -> non_empty(TestStub.rpc_order()) end)

      # T140RED is preferred when the caller offers red (105 = TextCodec::T140RED),
      # and the text mixer needs no join: the MCU wires it at CreateParticipant
      assert ack_time == [
               "SetAudioCodec",
               "StartSending",
               "SetVideoCodec",
               "StartSending",
               "SetTextCodec",
               "StartSending",
               "AddSidebarParticipant",
               "AddMosaicParticipant",
               # P7/S1: still only TWO watchdogs on a three-media leg — text is never
               # armed, T.140 being legitimately silent between keystrokes (§16.1)
               "StartRTPTimeout",
               "StartRTPTimeout",
               # the script's `displayname: :auto` banner, then the automatic layout,
               # which still follows the *video* legs only: a text leg is not a tile
               "SetParticipantDisplayName",
               "SetCompositionType"
             ]
    end

    test "T140RED is what the mixer is told to send when the caller offers it", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_tc))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})

      # 105 = TextCodec::T140RED. Preference order is the CALLER's, honoured by the
      # media server — redundancy first here, and a lost packet is a lost character.
      assert_receive {:rpc, "SetTextCodec", [42, 7, 105]}, 2000
    end

    test "a terminal without redundancy gets plain t140 and no red fmtp", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_text_plain))
      assert_receive {:replied, 200, _reason, fields, _req}, 2000

      answer = fields[:body]
      assert answer =~ "a=rtpmap:97 t140/1000"
      refute answer =~ "red/1000"
      # red is what carries the redundancy: no red answered, no fmtp naming it
      refute answer =~ "a=fmtp:97"

      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      # 106 = TextCodec::T140
      assert_receive {:rpc, "SetTextCodec", [42, 7, 106]}, 2000
    end

    test "a conference with text off declines the section with port 0", ctx do
      {:ok, conf} =
        Kelix.Mod.Mcu.create_conference(@domain,
          name: "audio only",
          medias: ["audio", "video"]
        )

      {_pid, _dialog} = start_call(ctx.scenario, invite(conf.did, sdp: @offer_tc))
      assert_receive {:replied, 200, _reason, fields, _req}, 2000

      answer = fields[:body]
      # RFC 3264 §6: the section keeps its place, with port 0 and the offered formats
      assert answer =~ "m=text 0 RTP/AVP 98 97"
      assert answer =~ "m=audio #{@rec_port} RTP/AVP"
    end
  end

  describe "the automatic layout (§1.1 point 3)" do
    test "follows the number of video legs, and only moves when it changes", ctx do
      {pid1, dialog1} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_video))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid1, {:ACK, %{method: :ACK}, nil, dialog1})
      # 1 video leg ⇒ 1x1 (comp 0), moving off the configured 2x2
      assert_receive {:rpc, "SetCompositionType", [42, 0, 0, 6]}, 2000

      {:ok, dialog2} = MockDialog.start_link(self())
      req2 = invite(ctx.did, sdp: @offer_video)
      pid2 = spawn_call(ctx.scenario, dialog2, req2)
      send(pid2, {:INVITE, req2, nil, dialog2})
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid2, {:ACK, %{method: :ACK}, nil, dialog2})
      # 2 video legs ⇒ 1+1 (comp 6): side by side, not a 2x2 with two black tiles
      assert_receive {:rpc, "SetCompositionType", [42, 0, 6, 6]}, 2000

      # the registry records what it pushed, so `conference.show` tells the truth
      assert wait_for(fn -> match?({:ok, %{layout: %{comp: 6}}}, Mcu.conference(ctx.uid)) end)

      # one leaves ⇒ back to 1x1
      send(pid2, {:BYE, %{method: :BYE}, nil, dialog2})
      assert_receive {:rpc, "SetCompositionType", [42, 0, 0, 6]}, 2000
    end

    test "an audio-only conference issues no mosaic RPC at all", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      assert_receive {:rpc, "AddSidebarParticipant", _params}, 2000

      order = wait_for(fn -> non_empty(TestStub.rpc_order()) end) || []
      refute "SetCompositionType" in order
      refute "AddMosaicParticipant" in order
    end

    test "`auto: false` leaves the layout to the operator", ctx do
      {:ok, %{uid: uid, did: did}} =
        Mcu.handle_control("conference.create", %{
          "domain" => @domain,
          "did" => "8400",
          "layout" => %{"auto" => false, "comp" => 9}
        })

      # the creation's own SetCompositionType must not be mistaken for a layout move
      _create_rpcs = TestStub.rpc_order()

      {pid, dialog} = start_call(ctx.scenario, invite(did, sdp: @offer_video))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      assert_receive {:rpc, "AddMosaicParticipant", _params}, 2000

      order = wait_for(fn -> non_empty(TestStub.rpc_order()) end) || []
      refute "SetCompositionType" in order
      assert {:ok, %{layout: %{comp: 9}}} = Mcu.conference(uid)
    end

    test "the ladder is the smallest layout holding n tiles" do
      # 1x1, 1+1, 2x2, 1+4, 1+5, 1+7, 3x3, 4x4, 2+8 (§3.6 comp values)
      assert Enum.map(0..10, &Mcu.auto_comp/1) == [0, 0, 6, 1, 1, 10, 5, 4, 4, 2, 9]
      assert Mcu.auto_comp(16) == 9
      assert Mcu.auto_comp(17) == 11
    end
  end

  describe "RTP inactivity watchdog (§16.1, P7)" do
    # The AND lives in the controller (decided 2026-08-05): the server reports one
    # media at a time, and only "every watched media is silent" is a dead leg.
    test "one silent media is reported but does not hang up the call", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_video))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      assert_receive {:rpc, "AddMosaicParticipant", _params}, 2000

      part = joined_participant(ctx.uid)
      send(Mcu, {:mcu_event, "mcu1", {:media_timeout, 42, ctx.uid, part.part_id, :video}})

      # the leg keeps its slot and its tile: audio is still flowing
      refute_receive {:sent_request, :BYE, _req}, 500
      assert Process.alive?(pid)

      # and the silence is recorded, so the operator view can show which media died
      [part] = participants(ctx.uid)
      assert Map.has_key?(part.silent, :video)
    end

    test "the last silent media hangs up the call", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_video))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      assert_receive {:rpc, "AddMosaicParticipant", _params}, 2000

      part = joined_participant(ctx.uid)
      send(Mcu, {:mcu_event, "mcu1", {:media_timeout, 42, ctx.uid, part.part_id, :video}})
      refute_receive {:sent_request, :BYE, _req}, 300
      send(Mcu, {:mcu_event, "mcu1", {:media_timeout, 42, ctx.uid, part.part_id, :audio}})

      assert_receive {:sent_request, :BYE, _req}, 2000
    end

    # Without this, a leg that flapped once would be reaped the next time any OTHER
    # media hiccups — the AND would never forget.
    test "a media coming back clears its silence", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_video))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      assert_receive {:rpc, "AddMosaicParticipant", _params}, 2000

      part = joined_participant(ctx.uid)
      send(Mcu, {:mcu_event, "mcu1", {:media_timeout, 42, ctx.uid, part.part_id, :video}})
      send(Mcu, {:mcu_event, "mcu1", {:media_connected, 42, ctx.uid, part.part_id, :video}})

      # video is alive again, so audio going quiet is NOT the whole leg
      send(Mcu, {:mcu_event, "mcu1", {:media_timeout, 42, ctx.uid, part.part_id, :audio}})
      refute_receive {:sent_request, :BYE, _req}, 500
      assert Process.alive?(pid)
    end

    # An audio-only leg has a watched set of exactly one, so its single timeout IS
    # every media — the AND must not need two events to fire.
    test "an audio-only leg hangs up on its single timeout", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      assert_receive {:rpc, "AddSidebarParticipant", _params}, 2000

      part = joined_participant(ctx.uid)
      send(Mcu, {:mcu_event, "mcu1", {:media_timeout, 42, ctx.uid, part.part_id, :audio}})

      assert_receive {:sent_request, :BYE, _req}, 2000
    end
  end

  describe "hold and resume (§6.4, P7)" do
    # Without the disarming half of the watchdog, a hold longer than rtp_timeout_ms
    # reads as a dead leg and hangs up a working call — ten seconds being an ordinary
    # consultation transfer. The criterion is "will the peer send", not "is this hold".
    test "a hold the peer stops sending on disarms the watchdog", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_video))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      part = joined_participant(ctx.uid)

      TestStub.rpc_order()
      assert {:ok, _answer} = Conn.set_remote_offer(part.conn, @offer_hold_inactive)

      # both medias disarmed (timeoutMs = 0), and text was never armed to begin with
      assert_received {:rpc, "StartRTPTimeout", [_conf, _part, 0, 0, _role]}
      assert_received {:rpc, "StartRTPTimeout", [_conf, _part, 1, 0, _role]}
    end

    test "a hold the peer keeps sending on leaves it armed", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_video))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      part = joined_participant(ctx.uid)

      TestStub.rpc_order()
      assert {:ok, _answer} = Conn.set_remote_offer(part.conn, @offer_hold_sendonly)

      assert_received {:rpc, "StartRTPTimeout", [_conf, _part, 0, ms, _role]} when ms > 0
      refute_received {:rpc, "StartRTPTimeout", [_conf, _part, _media, 0, _role]}
    end

    test "resuming re-arms it", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_video))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      part = joined_participant(ctx.uid)

      assert {:ok, _} = Conn.set_remote_offer(part.conn, @offer_hold_inactive)
      TestStub.rpc_order()
      assert {:ok, _} = Conn.set_remote_offer(part.conn, @offer_video)

      # the ACK path returns early on an attached leg, so if the answer did not
      # re-arm, a resumed media would stay unwatched for good
      assert_received {:rpc, "StartRTPTimeout", [_conf, _part, 0, ms, _role]} when ms > 0
    end
  end

  describe "RFC 5939 capability negotiation (§6.3.1)" do
    test "an AVPF potential configuration is accepted on video, and stated", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_capneg))
      assert_receive {:replied, 200, _reason, fields, _req}, 2000

      answer = fields[:body]

      # the video m= line carries the upgraded profile, and a=acfg says WHICH
      # configuration was taken — without it the peer cannot tell an accepted capneg
      # from an answerer that changed the transport on its own
      assert answer =~ ~r/m=video \d+ RTP\/AVPF/
      assert answer =~ "a=acfg:1 t=1"

      # audio keeps AVP: the caller offers the upgrade there too, but there is no audio
      # feedback to switch on, so taking it would announce a profile we do nothing with
      assert answer =~ ~r/m=audio \d+ RTP\/AVP /
      refute answer =~ "RTP/AVPF 8"
    end

    test "the answered feedback is the intersection, per explicit payload type", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_capneg))
      assert_receive {:replied, 200, _reason, fields, _req}, 2000

      answer = fields[:body]

      # what we can honour, named per PT rather than with the offer's `*` wildcard
      assert answer =~ "a=rtcp-fb:99 nack"
      assert answer =~ "a=rtcp-fb:99 ccm fir"
      assert answer =~ "a=rtcp-fb:99 ccm tmmbr"
      refute answer =~ "rtcp-fb:*"

      # and NOT what has no server-side switch: announcing these would promise a
      # capability nothing implements
      refute answer =~ "goog-remb"
      refute answer =~ "nack pli"
    end

    test "what is announced is what is switched on server-side", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_capneg))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      # video (1) carries the three switches behind the three answered types
      assert_received {:rpc, "SetRTPProperties", [42, 7, 1, props, 0]}
      assert props["useNACK"] == "1"
      assert props["useRtcpFIR"] == "1"
      assert props["tmmbr"] == "1"

      # audio stayed AVP, so it gets none of them
      assert_received {:rpc, "SetRTPProperties", [42, 7, 0, audio_props, 0]}
      refute Map.has_key?(audio_props, "useNACK")
    end

    test "a caller that asks for no feedback gets none, and no upgrade", ctx do
      # same offer without the rtcp-fb lines: the upgrade would buy nothing
      offer = String.replace(@offer_capneg, ~r/a=rtcp-fb:[^\r]*\r\n/, "")
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: offer))
      assert_receive {:replied, 200, _reason, fields, _req}, 2000

      answer = fields[:body]
      refute answer =~ "RTP/AVPF"
      refute answer =~ "a=acfg"
      refute answer =~ "a=rtcp-fb"
    end
  end

  describe "FPU both ways (§6.4)" do
    test "the MCU asking becomes an INFO carrying picture_fast_update", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_video))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      assert_receive {:rpc, "AddMosaicParticipant", _params}, 2000

      [part] = participants(ctx.uid)
      send(Mcu, {:mcu_event, "mcu1", {:fpu_requested, 42, ctx.uid, part.part_id}})

      assert_receive {:sent_request, :INFO, req}, 2000
      assert to_string(req.contenttype) =~ "media_control"
      assert to_string(req.body) =~ "picture_fast_update"
      assert Process.alive?(pid)
    end

    test "the peer asking becomes a SendFPU, and any INFO is still answered 200", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_video))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      assert_receive {:rpc, "AddMosaicParticipant", _params}, 2000
      _drain = TestStub.rpc_order()

      send(pid, {:INFO, media_control_info(), nil, dialog})
      assert_receive {:replied, 200, "OK", _fields, _req}, 2000
      assert_receive {:rpc, "SendFPU", [42, 7]}, 2000

      # an INFO that is not a frame request is answered, and asks the MCU for nothing
      send(
        pid,
        {:INFO, %{method: :INFO, contenttype: "application/dtmf-relay", body: "1"}, nil, dialog}
      )

      assert_receive {:replied, 200, "OK", _fields, _req}, 2000
      refute_receive {:rpc, "SendFPU", _params}, 200
    end
  end

  # ── the caller that never ACKs, and the rejections ───────────────────────────

  describe "the answer-time / ACK-time split (§2, point 2)" do
    test "a caller that never ACKs never enters the mix", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      order = TestStub.rpc_order()
      refute "StartSending" in order
      refute "AddSidebarParticipant" in order
      # …and it still holds its slot, which is what the quota is for
      assert [%{state: :ringing}] = participants(ctx.uid)
    end
  end

  describe "rejections (§6.5)" do
    test "an unknown DID is a 404 and creates no participant", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite("9999"))

      assert_receive {:replied, 404, "Not Found", _fields, _req}, 2000
      assert participants(ctx.uid) == []
      assert TestStub.rpc_order() == []
    end

    test "a full conference is a 486", ctx do
      {:ok, %{uid: uid, did: did}} =
        Mcu.handle_control("conference.create", %{
          "domain" => @domain,
          "did" => "8100",
          "max_participants" => 1
        })

      {_pid, _dialog} = start_call(ctx.scenario, invite(did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      assert length(participants(uid)) == 1

      {:ok, dialog2} = MockDialog.start_link(self())
      req2 = invite(did)
      pid2 = spawn_call(ctx.scenario, dialog2, req2)
      send(pid2, {:INVITE, req2, nil, dialog2})

      assert_receive {:replied, 486, "Busy Here", _fields, _req}, 2000
      # the second caller took no slot
      assert length(participants(uid)) == 1
    end

    test "no codec in common is a 488, and the slot is released", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did, sdp: @offer_no_codec))

      assert_receive {:replied, 180, "Ringing", _fields, _req}, 2000
      assert_receive {:replied, 488, "Not Acceptable Here", _fields, _req}, 2000

      # the participant was created MCU-side (the offer is only read afterwards) and
      # must be deleted again — nothing may leak on a refused call (§9.1)
      order = wait_for(fn -> if "DeleteParticipant" in TestStub.rpc_order(), do: true end)
      assert order
      assert wait_for(fn -> participants(ctx.uid) == [] end)
    end

    test "a conference whose MCU is down is a 503", ctx do
      send(Mcu, {:mcu_event_stream_down, "mcu1"})
      assert wait_for(fn -> match?({:ok, %{status: :down}}, Mcu.mediaserver("mcu1")) end)

      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 503, "Service Unavailable", _fields, _req}, 2000
    end
  end

  # ── the safety nets ──────────────────────────────────────────────────────────

  describe "teardown paths" do
    test "a crashed instance is reaped: slot freed and MCU side released (§9.3)", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      assert_receive {:rpc, "AddSidebarParticipant", _params}, 2000
      _drain = TestStub.rpc_order()

      Process.exit(pid, :kill)

      assert wait_for(fn -> participants(ctx.uid) == [] end)
      teardown = wait_for(fn -> non_empty(TestStub.rpc_order()) end)
      assert "DeleteParticipant" in teardown
    end

    test "CANCEL before the answer releases the slot", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      send(pid, {:CANCEL, %{method: :CANCEL}, nil, dialog})
      assert wait_for(fn -> participants(ctx.uid) == [] end)
    end

    test "an auto-destroying conference goes away with its last participant", ctx do
      {:ok, %{uid: uid, did: did}} =
        Mcu.handle_control("conference.create", %{
          "domain" => @domain,
          "did" => "8200",
          "destroy_when_empty" => true
        })

      {pid, dialog} = start_call(ctx.scenario, invite(did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      send(pid, {:BYE, %{method: :BYE}, nil, dialog})
      assert wait_for(fn -> Mcu.conference(uid) == :error end)
      # …and its DID is free again
      assert Mcu.lookup_did(@domain, did) == :error
    end

    test "losing the media server ends the call: the script BYEs and the slot frees", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      assert_receive {:rpc, "AddSidebarParticipant", _params}, 2000

      # the mixer is gone (§9.2): a leg with no media must not hold its slot for the
      # hours the SIP-only idle timeout would take (G3)
      send(Mcu, {:mcu_event_stream_down, "mcu1"})

      # the slot is freed and the MCU-side participant released; the instance then
      # waits in `hanging_up` for the 200 to its BYE (the mock never sends one)
      assert wait_for(fn -> participants(ctx.uid) == [] end)
      assert wait_for(fn -> if "DeleteParticipant" in TestStub.rpc_order(), do: true end)
    end

    test "an FPU request reaches the owning scenario, keeping the call up", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      assert_receive {:rpc, "AddSidebarParticipant", _params}, 2000

      [part] = participants(ctx.uid)
      send(Mcu, {:mcu_event, "mcu1", {:fpu_requested, 42, ctx.uid, part.part_id}})

      # P3 turns it into an INFO; for now the instance must simply survive it rather
      # than leave it to rot in its mailbox
      Process.sleep(50)
      assert Process.alive?(pid)
      assert [%{state: :connected}] = participants(ctx.uid)
    end

    test "leave/2 is idempotent: a second call is a no-op, not an error", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      [part] = participants(ctx.uid)
      assert :ok = Mcu.leave(part, :bye)
      assert :ok = Mcu.leave(part, :bye)
      assert participants(ctx.uid) == []
    end
  end

  defp non_empty([]), do: nil
  defp non_empty(list), do: list
end
