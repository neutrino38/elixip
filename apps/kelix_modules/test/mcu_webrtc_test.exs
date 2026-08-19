defmodule Kelix.Mod.McuWebrtcTest do
  @moduledoc """
  The answer a **browser** gets from a conference leg (design `docs/design/mcu_module.md`
  §6.3 rules 3-6 and 11, `docs/design/webrtc_sdp_design.md` §1.2).

  `mcu_secure_test.exs` covers the security plane attribute by attribute on offers this
  suite writes itself. This one starts from the real thing instead — the captured Chrome
  142 offer (`apps/elixip2/test/SDP-chrome-142-offer.txt`, the fixture the JSR-309
  adapter is tested against, deliberately shared rather than copied) — and asserts what
  a JSEP peer *requires* of the answer, which a hand-written offer does not exercise:

    * every answered section names itself with the offer's `a=mid`, rejected sections
      included — the browser pairs the answer with its transceivers by that name;
    * a payload type is re-announced with the clock rate the offer gave **that PT**.
      Chrome offers one telephone-event per clock (110@48000, 126@8000), the media
      server picks one, and announcing the primary codec's clock for whichever came
      back is a codec the peer cannot match;
    * ICE credentials stay inside the `ice-char` grammar (RFC 8839 §5.4).

  The media server is the recording stub, and it answers a *delegated* verdict (the
  P8a third return value), because that is the path a browser leg takes on any current
  node — the accepted set is the server's, and the answer is assembled from it.
  """
  use ExUnit.Case, async: false

  alias Kelix.Mcu.TestStub
  alias Kelix.Mod.Mcu
  alias Kelix.Mod.Mcu.{Adapter, Client, Config}

  @mediaservers [%{name: "mcu1", url: "http://127.0.0.1:18080"}]
  @domain "example.com"
  @media_ip "203.0.113.12"
  # one receive port per media, so the m= lines and their candidates cannot be
  # confused with each other
  @audio_port 52_014
  @video_port 52_016
  @text_port 52_018

  @chrome_offer Path.expand("../../elixip2/test/SDP-chrome-142-offer.txt", __DIR__)
                |> File.read!()

  # The offer of the call that failed on 2026-08-06 10:55 (`webrtc.pcap`): the IVeS
  # Electron client, Chrome 138, **seven** H.264 payload types — four profiles times
  # two packetization modes. Kept verbatim because it is the offer that showed the
  # verdict guard was needed.
  @electron_offer File.read!(Path.expand("fixtures/SDP-webrtc-electron-offer.txt", __DIR__))

  # What Chrome adds to that offer when the page also opens a data channel: a media
  # type this MCU has nothing to answer with, carrying a mid of its own.
  @datachannel_section "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" <>
                         "c=IN IP4 0.0.0.0\r\n" <>
                         "a=mid:2\r\n" <>
                         "a=sctp-port:5000\r\n"

  # The fmtp a media server that arbitrated the offer returns for the payload types it
  # keeps (§16.3, `StartReceiving`'s third return value). Nothing unproposed is ever
  # accepted — which is what a real negotiator does, and what makes the audio case the
  # interesting one: OPUS plus the **8 kHz** telephone-event, out of the two clocks
  # Chrome offers.
  @accepts %{
    "111" => "minptime=10;useinbandfec=1",
    "126" => "",
    "8" => "",
    "101" => "",
    "109" => "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"
  }

  defp verdict(params) do
    accepted = Map.take(@accepts, Map.keys(Enum.at(params, 3)))
    {:ok, [port_for(params), @media_ip, accepted]}
  end

  # What the **real** media server answers today (`webrtc.pcap`, and
  # `RTPParticipant::StartReceiving` collapsing the offer's per-PT fmtp into one
  # `h264.fmtp`): every accepted H.264 payload type gets the server's own capability,
  # High profile 3.1 in packetization mode 1, whatever that payload type was offered as.
  @server_capability "profile-level-id=64001f;packetization-mode=1;level-asymmetry-allowed=1"

  # Everything proposed accepted, which is what the live server does: on video with its
  # own capability for every payload type, on audio with the fmtp of each codec.
  defp capability_verdict(params) do
    proposed = Enum.at(params, 3)

    accepted =
      case Enum.at(params, 2) do
        1 -> Map.new(proposed, fn {pt, _code} -> {pt, @server_capability} end)
        _ -> Map.new(proposed, fn {pt, code} -> {pt, audio_fmtp(code)} end)
      end

    {:ok, [port_for(params), @media_ip, accepted]}
  end

  # 98 = AudioCodec::OPUS, 100 = TELEPHONE_EVENT (§3.6); the rest carry no fmtp.
  defp audio_fmtp(98), do: "useinbandfec=0;usedtx=0"
  defp audio_fmtp(100), do: "0-16"
  defp audio_fmtp(_code), do: ""

  # A verdict where nothing survives the check: a profile the offer never named at all.
  defp unanswerable_verdict(params) do
    proposed = Enum.at(params, 3)

    accepted =
      case Enum.at(params, 2) do
        1 ->
          Map.new(proposed, fn {pt, _} -> {pt, "profile-level-id=58001f;packetization-mode=1"} end)

        _ ->
          Map.new(proposed, fn {pt, code} -> {pt, audio_fmtp(code)} end)
      end

    {:ok, [port_for(params), @media_ip, accepted]}
  end

  # What the **fixed** media server returns (per-payload-type resolution): each PT keeps
  # its own profile and its own mode, at our level since the peer allows asymmetry. This
  # is the conformant verdict — the one the guard drops nothing from, and the one where
  # kelixip still has to pick a single payload type to send on.
  @per_pt_verdict %{
    "39" => "profile-level-id=4d001f;packetization-mode=0;level-asymmetry-allowed=1",
    "103" => "profile-level-id=42001f;packetization-mode=1;level-asymmetry-allowed=1",
    "107" => "profile-level-id=42001f;packetization-mode=0;level-asymmetry-allowed=1",
    "109" => "profile-level-id=42e01f;packetization-mode=1;level-asymmetry-allowed=1",
    "115" => "profile-level-id=42e01f;packetization-mode=0;level-asymmetry-allowed=1",
    "117" => "profile-level-id=4d001f;packetization-mode=1;level-asymmetry-allowed=1",
    "119" => "profile-level-id=64001f;packetization-mode=1;level-asymmetry-allowed=1"
  }

  defp per_pt_verdict(params) do
    proposed = Enum.at(params, 3)

    accepted =
      case Enum.at(params, 2) do
        1 -> Map.take(@per_pt_verdict, Map.keys(proposed))
        _ -> Map.new(proposed, fn {pt, code} -> {pt, audio_fmtp(code)} end)
      end

    {:ok, [port_for(params), @media_ip, accepted]}
  end

  # A verdict shaped like the Linphone 6.2 case: the offered profile echoed back with
  # packetization-mode **1**, against an offer that stated no mode at all.
  @linphone_fmtp "profile-level-id=42801f;packetization-mode=1;level-asymmetry-allowed=1"

  defp linphone_verdict(params) do
    proposed = Enum.at(params, 3)

    accepted =
      case Enum.at(params, 2) do
        1 -> Map.new(proposed, fn {pt, _code} -> {pt, @linphone_fmtp} end)
        _ -> Map.new(proposed, fn {pt, code} -> {pt, audio_fmtp(code)} end)
      end

    {:ok, [port_for(params), @media_ip, accepted]}
  end

  defp port_for(params) do
    case Enum.at(params, 2) do
      0 -> @audio_port
      1 -> @video_port
      _ -> @text_port
    end
  end

  setup context do
    verdict =
      case context[:verdict] do
        :server_capability -> &capability_verdict/1
        :per_pt -> &per_pt_verdict/1
        :linphone -> &linphone_verdict/1
        :unanswerable -> &unanswerable_verdict/1
        _ -> &verdict/1
      end

    # S5: the WS text door, in its two failure shades. The default (stub) answers
    # a ws:// URL echoing the token.
    ws_override =
      case context[:ws] do
        :wss ->
          %{
            "ConfigureParticipantMediaConnection" => fn [c, _p, _m, _proto, t] ->
              {:ok, ["wss://203.0.113.12:9090/mcu/#{c}/#{t}"]}
            end
          }

        :fail ->
          %{"ConfigureParticipantMediaConnection" => {:error, :rpc_error}}

        _ ->
          %{}
      end

    {:ok, config} = Config.parse(%{"did_range" => "8000-8009"})
    start_supervised!({Mcu, config: config, module_name: "mcu", mediaservers: @mediaservers})

    start_supervised!(
      {Client,
       name: "mcu1",
       base_url: "http://127.0.0.1:18080",
       transport:
         TestStub.transport(self(), Map.merge(%{"StartReceiving" => verdict}, ws_override)),
       register: {Mcu, "mcu1"},
       reconnect_ms: 0},
      id: :client_mcu1
    )

    wait_for_client()

    # The file-wide conference deliberately has NO text: the browser fixtures all
    # carry the Elioz-injected `m=text … TCP/WSS` section, and these tests are
    # about audio/video rules — a text-less conference keeps their section maths
    # stable AND permanently rehearses the S5 §D7 rule (an admit without text
    # omits every m=text from the answer). The S5 describe below creates its own
    # conference, with text.
    {:ok, %{did: did}} =
      Mcu.handle_control("conference.create", %{
        "domain" => @domain,
        "medias" => ["audio", "video"]
      })

    _setup_rpcs = TestStub.rpc_order()

    %{did: did}
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

  # A leg answering audio, video and text, as a browser offer needs.
  defp leg(did, opts \\ []) do
    req = %{
      method: :INVITE,
      ruri: %SIP.Uri{userpart: did, domain: @domain},
      from: %SIP.Uri{userpart: "web", domain: "browser.example.com"},
      to: %SIP.Uri{userpart: did, domain: @domain}
    }

    {:ok, conf, part} = Mcu.admit(@domain, req)
    {:ok, client} = Adapter.connect("mcu://" <> conf.mcu)

    {:ok, conn} =
      Adapter.create_peer_connection(
        client,
        self(),
        [mcu_participant: part, media: :tc] ++ opts
      )

    on_exit(fn -> Adapter.close(conn) end)
    conn
  end

  defp answer_for(did, sdp) do
    conn = leg(did)
    assert {:ok, answer} = Adapter.set_remote_offer(conn, sdp)
    answer
  end

  # The m= sections of an SDP, in order, each as its own list of lines (m= line
  # first). Session-level lines are dropped: an assertion about a section must not
  # be satisfiable by an attribute that sits above the first m=.
  defp sections(sdp) do
    sdp
    |> String.split(~r/\r?\n/, trim: true)
    |> Enum.reduce([], fn
      "m=" <> _ = line, acc -> [[line] | acc]
      _line, [] -> []
      line, [current | rest] -> [current ++ [line] | rest]
    end)
    |> Enum.reverse()
  end

  describe "a=mid (§6.3 rule 11 — JSEP RFC 8829 §5.3.1)" do
    test "every answered section carries the offer's mid, verbatim", ctx do
      answer = answer_for(ctx.did, @chrome_offer)

      [audio, video] = sections(answer)

      assert "a=mid:0" in audio
      assert "a=mid:1" in video

      # never rebuilt from the media name: the peer has no section called "audio"
      refute answer =~ "a=mid:audio"
      refute answer =~ "a=mid:video"
    end

    test "a declined section names itself too", ctx do
      answer = answer_for(ctx.did, @chrome_offer <> @datachannel_section)

      [_audio, _video, data] = sections(answer)

      # port 0 with the offered transport and format echoed (RFC 3264 §6), plus the
      # mid: the browser has to know *which* of its sections we turned down
      assert hd(data) == "m=application 0 UDP/DTLS/SCTP webrtc-datachannel"
      assert "a=mid:2" in data
    end

    test "on a text-less conference the WebSocket text section is omitted, not declined", ctx do
      answer = answer_for(ctx.did, @chrome_offer <> @datachannel_section)

      # Deliberate RFC 3264 §6 deviation (S5 plan §D7): the Elioz client injects
      # `m=text … TCP/WSS` into the wire SDP after setLocalDescription and fails
      # to strip our port-0 echo on the way back, so libwebrtc counted three
      # answer sections against its two-section local offer and rejected the
      # whole answer. This conference has no text, so the section vanishes
      # entirely. The data-channel section, which IS in the browser's real
      # offer, keeps the standard port-0 echo — omitting THAT would break the
      # same check.
      refute answer =~ "m=text"
      assert [_audio, _video, data] = sections(answer)
      assert hd(data) == "m=application 0 UDP/DTLS/SCTP webrtc-datachannel"
    end

    test "an offer without mids is answered without any: nothing is invented", ctx do
      sip_offer =
        Enum.join(
          [
            "v=0",
            "o=- 1 1 IN IP4 192.168.1.50",
            "s=-",
            "c=IN IP4 192.168.1.50",
            "t=0 0",
            "m=audio 40000 RTP/AVP 8 101",
            "a=rtpmap:8 PCMA/8000",
            "a=rtpmap:101 telephone-event/8000",
            "a=sendrecv",
            ""
          ],
          "\r\n"
        )

      refute answer_for(ctx.did, sip_offer) =~ "a=mid:"
    end
  end

  describe "payload-type clock rates" do
    test "the accepted telephone-event keeps the clock the offer gave that PT", ctx do
      answer = answer_for(ctx.did, @chrome_offer)

      # the server kept PT 126, which the offer declared at 8000 Hz — even though the
      # primary audio codec is OPUS at 48000
      assert answer =~ "a=rtpmap:126 telephone-event/8000"
      refute answer =~ "telephone-event/48000"
      # and the 48 kHz PT the server did not accept is not announced at all
      refute answer =~ "a=rtpmap:110 "
    end

    test "the other accepted codecs are announced as offered", ctx do
      answer = answer_for(ctx.did, @chrome_offer)

      assert answer =~ "a=rtpmap:111 opus/48000/2"
      assert answer =~ "a=rtpmap:109 H264/90000"
      # the fmtp is the server's, verbatim (P8a)
      assert answer =~
               "a=fmtp:109 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"
    end
  end

  # The failure of webrtc.pcap: the answer described, for six of the seven offered H.264
  # payload types, a codec the offer never declared for them. libwebrtc refuses the whole
  # answer and the app hangs up right after the ACK.
  describe "the verdict is checked against the offer, per payload type (§6.3 rule 12)" do
    @tag verdict: :server_capability
    test "an H.264 PT answered with another PT's profile is dropped", ctx do
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          send(self(), {:answer, answer_for(ctx.did, @electron_offer)})
        end)

      assert_received {:answer, answer}

      [_audio, video] = sections(answer)

      # 119 is the only payload type the caller offered as 64001f/pm=1, which is what
      # the server answered for all of them
      assert hd(video) == "m=video #{@video_port} UDP/TLS/RTP/SAVPF 119"
      assert "a=fmtp:119 #{@server_capability}" in video

      # the six others named a profile or a packetization mode of their own
      for pt <- [39, 103, 107, 109, 115, 117] do
        refute answer =~ "a=rtpmap:#{pt} "
        assert log =~ "dropped pt #{pt} from the verdict"
      end

      # and the log sends the reader to the server's own resolution, not to a code path
      assert log =~ "check what it resolved for THIS payload type in its log"
    end

    @tag verdict: :server_capability
    test "the mixer sends on exactly the payload types the answer announced", ctx do
      conn = leg(ctx.did)

      ExUnit.CaptureLog.capture_log(fn ->
        assert {:ok, _answer} = Adapter.set_remote_offer(conn, @electron_offer)
        assert {:ok, _summary} = Adapter.attach(conn)
      end)

      calls = TestStub.rpc_calls()

      # StartSending's rtpMap is the answered set, not every PT that mapped to H.264 —
      # a stream on a payload type the answer left out is one the peer discards
      assert Enum.any?(calls, fn
               {"StartSending", [_conf, _part, 1, _ip, _port, %{"119" => 99}, 0]} -> true
               _ -> false
             end)

      # and the encoder is configured with the profile that answer states
      assert Enum.any?(calls, fn
               {"SetVideoCodec", [_c, _p, 99, _s, _f, _b, _i, props, 0]} ->
                 props == %{
                   "h264.profile-level-id" => "64001f",
                   "h264.packetization-mode" => "1"
                 }

               _ ->
                 false
             end)
    end

    @tag verdict: :server_capability
    test "an offer that states no H.264 fmtp has nothing to contradict", ctx do
      offer =
        Enum.join(
          [
            "v=0",
            "o=- 1 1 IN IP4 192.168.1.50",
            "s=-",
            "c=IN IP4 192.168.1.50",
            "t=0 0",
            "m=video 40000 RTP/AVP 96",
            "a=rtpmap:96 H264/90000",
            "a=sendrecv",
            ""
          ],
          "\r\n"
        )

      # the server accepts PT 96 with a profile of its own; a gateway that wrote no fmtp
      # gets it rather than losing its video over a parameter it never stated
      answer = answer_for(ctx.did, offer)
      assert answer =~ "a=rtpmap:96 H264/90000"
      assert answer =~ "a=fmtp:96 #{@server_capability}"
    end

    @tag verdict: :unanswerable
    test "a media where nothing survives is declined with port 0, and its receive plane closed",
         ctx do
      conn = leg(ctx.did)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          assert {:ok, answer} = Adapter.set_remote_offer(conn, @electron_offer)
          send(self(), {:answer, answer})
        end)

      assert_received {:answer, answer}
      [audio, video] = sections(answer)

      # audio still negotiates, so the call is answered (§6.3 rule 2): only a leg where
      # EVERY media came back empty is a 488
      assert hd(audio) =~ "m=audio #{@audio_port} "
      # the offered format list, echoed verbatim in its own order (RFC 3264 §6)
      assert hd(video) == "m=video 0 UDP/TLS/RTP/SAVPF 103 107 109 115 39 117 119"
      # the WS text section is omitted, not declined (text-less conference, §D7)
      refute answer =~ "m=text"
      assert log =~ "dropped pt 119 from the verdict"

      # and the port the server opened for a media we just declined is given back
      calls = TestStub.rpc_calls()
      assert Enum.any?(calls, &match?({"StopReceiving", [_c, _p, 1, 0]}, &1))
    end

    # An offer that states no packetization-mode at all — Linphone 6.2 with OpenH264 —
    # is NOT read as mode 0 (RFC 6184 §8.1 says it is; decided 2026-08-06 to differ).
    # Reading it that way cost H.264 entirely: the server answers its own mode 1, the
    # modes "differed", and the payload type was dropped.
    @tag verdict: :linphone
    test "an offer stating no packetization-mode keeps its H.264 payload type", ctx do
      offer =
        Enum.join(
          [
            "v=0",
            "o=- 1 1 IN IP4 192.168.1.50",
            "s=-",
            "c=IN IP4 192.168.1.50",
            "t=0 0",
            "m=video 40000 RTP/AVP 97",
            "a=rtpmap:97 H264/90000",
            "a=fmtp:97 profile-level-id=42801F",
            "a=sendrecv",
            ""
          ],
          "\r\n"
        )

      conn = leg(ctx.did)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          assert {:ok, answer} = Adapter.set_remote_offer(conn, offer)
          assert {:ok, _summary} = Adapter.attach(conn)
          send(self(), {:answer, answer})
        end)

      assert_received {:answer, answer}
      refute log =~ "dropped pt"
      assert answer =~ "a=rtpmap:97 H264/90000"
      assert answer =~ "a=fmtp:97 #{@linphone_fmtp}"

      # and the negotiated mode reaches the encoder by the same channel as the profile —
      # it decides the slice size, hence mode-0 conformance, and the software fallback
      assert Enum.any?(TestStub.rpc_calls(), fn
               {"SetVideoCodec", [_c, _p, 99, _s, _f, _b, _i, props, 0]} ->
                 props == %{
                   "h264.profile-level-id" => "42801f",
                   "h264.packetization-mode" => "1"
                 }

               _ ->
                 false
             end)
    end

    # The fixed server (per-PT resolution): nothing is dropped any more, and it is then
    # kelixip's job to keep what it sends consistent with what it announced.
    @tag verdict: :per_pt
    test "a per-payload-type verdict passes whole, and one PT carries the stream", ctx do
      conn = leg(ctx.did)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          assert {:ok, answer} = Adapter.set_remote_offer(conn, @electron_offer)
          assert {:ok, _summary} = Adapter.attach(conn)
          send(self(), {:answer, answer})
        end)

      assert_received {:answer, answer}
      [_audio, video] = sections(answer)

      # all seven payload types are announced, each with ITS OWN profile/mode pair
      assert hd(video) == "m=video #{@video_port} UDP/TLS/RTP/SAVPF 103 107 109 115 39 117 119"

      assert "a=fmtp:103 profile-level-id=42001f;packetization-mode=1;level-asymmetry-allowed=1" in video

      assert "a=fmtp:39 profile-level-id=4d001f;packetization-mode=0;level-asymmetry-allowed=1" in video

      refute log =~ "dropped pt"

      calls = TestStub.rpc_calls()

      # but the stream goes out on ONE payload type — the caller's first choice (103) —
      # and the encoder is configured with THAT payload type's profile, not another's
      assert Enum.any?(calls, fn
               {"StartSending", [_c, _p, 1, _ip, _port, %{"103" => 99}, 0]} -> true
               _ -> false
             end)

      assert Enum.any?(calls, fn
               {"SetVideoCodec", [_c, _p, 99, _s, _f, _b, _i, props, 0]} ->
                 props == %{
                   "h264.profile-level-id" => "42001f",
                   "h264.packetization-mode" => "1"
                 }

               _ ->
                 false
             end)
    end
  end

  describe "the answer honours the caller's preference order (§6.3 rule 1)" do
    @tag verdict: :server_capability
    test "the audio format list keeps the offer's order, and so does the primary codec",
         ctx do
      conn = leg(ctx.did)
      assert {:ok, answer} = Adapter.set_remote_offer(conn, @electron_offer)
      assert {:ok, summary} = Adapter.attach(conn)

      [audio, _video] = sections(answer)

      # the offer lists 111 9 0 110 126 — OPUS first. Answering 0 9 110 111 126 (ascending
      # payload type) would tell the browser we prefer G.711 and it would send G.711.
      assert hd(audio) == "m=audio #{@audio_port} UDP/TLS/RTP/SAVPF 111 9 0 110 126"

      # and the mixer encodes towards this leg with the caller's first choice
      assert summary.audio.codec == "OPUS"
      assert_received {:rpc, "SetAudioCodec", [_conf, _part, 98]}
    end
  end

  describe "the transport plane a browser reads" do
    test "ICE credentials stay inside the ice-char grammar (RFC 8839 §5.4)", ctx do
      answer = answer_for(ctx.did, @chrome_offer)

      assert [ufrag] = Regex.run(~r/a=ice-ufrag:(\S+)/, answer, capture: :all_but_first)
      assert [pwd] = Regex.run(~r/a=ice-pwd:(\S+)/, answer, capture: :all_but_first)

      # ice-char = ALPHA / DIGIT / "+" / "/" — no "-" and no "_", which is what
      # base64url produced and what a strict SDP parser rejects
      assert Regex.match?(~r|^[A-Za-z0-9+/]+$|, ufrag)
      assert Regex.match?(~r|^[A-Za-z0-9+/]+$|, pwd)
      # RFC 8839 §5.4 lengths: ufrag ≥ 4, pwd ≥ 22
      assert String.length(ufrag) >= 4
      assert String.length(pwd) >= 22

      # what the answer states is what the server was told
      assert_received {:rpc, "SetLocalSTUNCredentials", [42, 7, 0, ^ufrag, ^pwd, 0]}
    end

    test "one section per offered section, in order, each with its own port and candidate",
         ctx do
      answer = answer_for(ctx.did, @chrome_offer)

      assert [audio, video] = sections(answer)

      assert hd(audio) == "m=audio #{@audio_port} UDP/TLS/RTP/SAVPF 111 126"
      assert hd(video) =~ "m=video #{@video_port} UDP/TLS/RTP/SAVPF 109"

      assert "a=candidate:1 1 udp 2130706431 #{@media_ip} #{@audio_port} typ host" in audio
      assert "a=candidate:1 1 udp 2130706431 #{@media_ip} #{@video_port} typ host" in video

      # ice-lite is session level, the DTLS role is ours to state, and rtcp-mux is
      # mirrored from the offer
      assert answer =~ "a=ice-lite"
      assert "a=setup:passive" in audio
      assert "a=rtcp-mux" in audio
      assert "a=rtcp-mux" in video
    end

    test "the feedback answered on video is the intersection, per accepted PT", ctx do
      answer = answer_for(ctx.did, @chrome_offer)

      [audio, video] = sections(answer)

      assert "a=rtcp-fb:109 nack" in video
      assert "a=rtcp-fb:109 ccm fir" in video
      # Chrome never offers `ccm tmmbr`: `goog-remb` is the only congestion feedback
      # it understands, and answering it is what makes the mixer emit any at all
      # (rate-control lot 2)
      assert "a=rtcp-fb:109 goog-remb" in video
      # `transport-cc` needs `[mediaserver] transport_cc`, off by default — see the
      # "transport-wide congestion control" describe block below
      refute answer =~ "transport-cc"
      # no feedback on audio, whatever the offer asked for there — there is no audio
      # feedback this mixer acts on
      refute Enum.any?(audio, &String.starts_with?(&1, "a=rtcp-fb"))
    end
  end

  # ── transport-wide congestion control ─────────────────────────────────────────
  #
  # The half of the mediaserver's sender-side bandwidth estimator that lives here
  # (design `docs/design/kelixip-transport-wide-cc.md`). The captured Chrome offer
  # carries `a=extmap:3 <URI>` on its video section and `transport-cc` on every video
  # PT, so this is the real negotiation and not a hand-written one.
  #
  # This mixer only ever ANSWERS: there is no offer side to cover here.
  describe "transport-wide congestion control" do
    @transport_cc_uri "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"

    defp with_transport_cc(value) do
      block = Application.get_env(:elixip2, MediaServer.Mendooze, [])

      Application.put_env(
        :elixip2,
        MediaServer.Mendooze,
        Keyword.put(block, :transport_cc, value)
      )

      on_exit(fn -> Application.put_env(:elixip2, MediaServer.Mendooze, block) end)
    end

    # Two SetRTPProperties land per media: our local codec capability first (§16.3.4
    # (a)), the transport switches second. Drained and merged — the keys of the two
    # never collide, and asserting on a fixed position would only be asserting the
    # order of the pair.
    defp rtp_props(media) do
      receive do
        {:rpc, "SetRTPProperties", [42, 7, ^media, props, 0]} ->
          Map.merge(props, rtp_props(media))
      after
        0 -> %{}
      end
    end

    test "the switch on: same extmap id in the answer, feedback confirmed, leg armed",
         ctx do
      with_transport_cc(true)
      answer = answer_for(ctx.did, @chrome_offer)
      [audio, video] = sections(answer)

      # RFC 8285 §5: the browser's own id, never renumbered
      assert "a=extmap:3 #{@transport_cc_uri}" in video
      assert "a=rtcp-fb:109 transport-cc" in video

      # video only — there is no sender-side estimator behind an audio stream
      refute Enum.any?(audio, &String.starts_with?(&1, "a=extmap"))
      refute Enum.any?(audio, &(&1 =~ "transport-cc"))

      # the switch is the extmap property: keyed by URI, valued with the negotiated id
      props = rtp_props(1)
      assert props[@transport_cc_uri] == "3"
      # and the rtcp-fb switches next to it are untouched
      assert props["useNACK"] == "1"
      assert props["remb"] == "1"

      refute Map.has_key?(rtp_props(0), @transport_cc_uri)
    end

    test "the switch off: nothing answered, nothing armed", ctx do
      with_transport_cc(false)
      answer = answer_for(ctx.did, @chrome_offer)
      [_audio, video] = sections(answer)

      refute answer =~ "a=extmap"
      refute answer =~ "transport-cc"

      # the rest of the answered feedback is untouched
      assert "a=rtcp-fb:109 nack" in video
      assert "a=rtcp-fb:109 goog-remb" in video

      refute Map.has_key?(rtp_props(1), @transport_cc_uri)
    end

    test "an offer without the extension gets nothing back, switch on", ctx do
      with_transport_cc(true)
      # the feedback message stays offered: without the extension it would report on a
      # sequence number nothing writes
      offer = String.replace(@chrome_offer, ~r/a=extmap:3 [^\r\n]*\r?\n/, "")
      answer = answer_for(ctx.did, offer)

      refute answer =~ "a=extmap"
      refute answer =~ "transport-cc"

      refute Map.has_key?(rtp_props(1), @transport_cc_uri)
    end

    test "an asymmetric extmap direction is left alone (v1 perimeter)", ctx do
      with_transport_cc(true)

      offer =
        String.replace(
          @chrome_offer,
          "a=extmap:3 #{@transport_cc_uri}",
          "a=extmap:7/sendonly #{@transport_cc_uri}"
        )

      answer = answer_for(ctx.did, offer)

      refute answer =~ "a=extmap"
      refute answer =~ "transport-cc"

      refute Map.has_key?(rtp_props(1), @transport_cc_uri)
    end
  end

  describe "text over WebSocket for a conference participant (S5)" do
    # Mirrors the four JSR-309 adapter tests (mendooze_conn_test.exs, "Text over
    # WebSocket"), transposed to the conference API: ONE RPC returns the full
    # URL, and nothing else ever runs on that leg.
    setup do
      # a conference of its own, WITH text — the file-wide one deliberately
      # has none (see the top-level setup)
      {:ok, %{did: did}} =
        Mcu.handle_control("conference.create", %{
          "domain" => @domain,
          "name" => "with text",
          "medias" => ["audio", "video", "text"]
        })

      _setup_rpcs = TestStub.rpc_order()
      %{ws_did: did}
    end

    test "the offered WS text section is configured and answered with its URL", ctx do
      answer = answer_for(ctx.ws_did, @chrome_offer)

      [_audio, _video, text] = sections(answer)

      # proto mirrored from the offer, the literal `t140`, and the WS server's
      # port on the m= line (a nonzero port is the deployed client's liveness lock)
      assert hd(text) == "m=text 9090 TCP/WSS t140"
      assert "a=setup:passive" in text
      assert "a=connection:new" in text

      # the URL in the gateway's historical form: the scheme carried by the
      # attribute NAME, the value protocol-relative — the line only reads as a
      # URL because SDP's `:` separator falls before the `//`
      assert [url_line] = Enum.filter(text, &String.starts_with?(&1, "a=ws:"))
      assert url_line =~ ~r"^a=ws://203\.0\.113\.12:9090/mcu/42/[0-9a-f-]+$"

      # signalling only: no payload types, no redundancy, no crypto on this leg
      refute Enum.any?(text, &(&1 =~ "rtpmap" or &1 =~ "fmtp" or &1 =~ "crypto"))

      # ONE rpc drove it, carrying the very token the URL publishes — and text
      # never went near the RTP machinery (no StartReceiving, media 2)
      calls = TestStub.rpc_calls()

      assert {_, [42, 7, 2, 2, token]} =
               Enum.find(calls, &match?({"ConfigureParticipantMediaConnection", _}, &1))

      assert url_line =~ token
      refute Enum.any?(calls, &match?({"StartReceiving", [_, _, 2 | _]}, &1))
    end

    @tag ws: :wss
    test "a TLS media server yields a=wss — the scheme is the server's, never guessed", ctx do
      answer = answer_for(ctx.ws_did, @chrome_offer)

      assert answer =~ "a=wss://203.0.113.12:9090/mcu/42/"
      refute answer =~ "a=ws://"
    end

    test "a peer declaring itself passive gets no text section: nobody would connect", ctx do
      # RFC 4145: both sides passive means the WebSocket would never be dialed
      offer = String.replace(@chrome_offer, "a=setup:active", "a=setup:passive")

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          send(self(), {:answer, answer_for(ctx.ws_did, offer)})
        end)

      assert_received {:answer, answer}
      refute answer =~ "m=text"
      assert [_audio, _video] = sections(answer)
      assert log =~ "setup:passive"
      # the media server was never even asked
      refute Enum.any?(
               TestStub.rpc_calls(),
               &match?({"ConfigureParticipantMediaConnection", _}, &1)
             )
    end

    @tag ws: :fail
    test "a media server that cannot host the WebSocket loses the text, not the call", ctx do
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          send(self(), {:answer, answer_for(ctx.ws_did, @chrome_offer)})
        end)

      assert_received {:answer, answer}
      # the section is omitted — never a port-0 echo — and the call stands
      refute answer =~ "m=text"
      assert [audio, _video] = sections(answer)
      assert hd(audio) =~ "m=audio #{@audio_port} "
      assert log =~ "the WS text section is omitted, the call stands"
    end
  end
end
