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

    port =
      case Enum.at(params, 2) do
        0 -> @audio_port
        1 -> @video_port
        _ -> @text_port
      end

    {:ok, [port, @media_ip, accepted]}
  end

  setup do
    {:ok, config} = Config.parse(%{"did_range" => "8000-8009"})
    start_supervised!({Mcu, config: config, module_name: "mcu", mediaservers: @mediaservers})

    start_supervised!(
      {Client,
       name: "mcu1",
       base_url: "http://127.0.0.1:18080",
       transport: TestStub.transport(self(), %{"StartReceiving" => &verdict/1}),
       register: {Mcu, "mcu1"},
       reconnect_ms: 0},
      id: :client_mcu1
    )

    wait_for_client()
    {:ok, %{did: did}} = Mcu.handle_control("conference.create", %{"domain" => @domain})
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

      [audio, video, _text] = sections(answer)

      assert "a=mid:0" in audio
      assert "a=mid:1" in video

      # never rebuilt from the media name: the peer has no section called "audio"
      refute answer =~ "a=mid:audio"
      refute answer =~ "a=mid:video"
    end

    test "a declined section names itself too", ctx do
      answer = answer_for(ctx.did, @chrome_offer <> @datachannel_section)

      [_audio, _video, _text, data] = sections(answer)

      # port 0 with the offered transport and format echoed (RFC 3264 §6), plus the
      # mid: the browser has to know *which* of its sections we turned down
      assert hd(data) == "m=application 0 UDP/DTLS/SCTP webrtc-datachannel"
      assert "a=mid:2" in data
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

      assert [audio, video, text] = sections(answer)

      assert hd(audio) == "m=audio #{@audio_port} UDP/TLS/RTP/SAVPF 111 126"
      assert hd(video) =~ "m=video #{@video_port} UDP/TLS/RTP/SAVPF 109"
      # the m=text section of that offer is TCP/WSS: not RTP, so declined (G9)
      assert hd(text) == "m=text 0 TCP/WSS t140"

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

      [audio, video, _text] = sections(answer)

      assert "a=rtcp-fb:109 nack" in video
      assert "a=rtcp-fb:109 ccm fir" in video
      # offered but not implemented here (§6.3.1 rule 5), and never announced
      refute answer =~ "goog-remb"
      refute answer =~ "transport-cc"
      # no feedback on audio, whatever the offer asked for there — there is no audio
      # feedback this mixer acts on
      refute Enum.any?(audio, &String.starts_with?(&1, "a=rtcp-fb"))
    end
  end
end
