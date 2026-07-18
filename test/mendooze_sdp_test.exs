defmodule Mendooze.SdpTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias MediaServer.Mendooze.Sdp

  @moduledoc """
  Pure unit tests for the JSR309 SDP helpers: codec tables, offer/answer
  construction round trips (RTP clear / SDES / DTLS+ICE) and negotiation.
  """

  # ── local_rtp_map/3 ─────────────────────────────────────────────────────────

  describe "local_rtp_map/3" do
    test "audio codecs with dtmf" do
      assert Sdp.local_rtp_map(:audio, ["PCMU", "PCMA"], true) ==
               %{"0" => 0, "8" => 8, "101" => 100}
    end

    test "codec names are case-insensitive, OPUS uses code 98" do
      assert Sdp.local_rtp_map(:audio, ["opus"]) == %{"98" => 98}
    end

    test "video codecs, no dtmf entry even when requested" do
      assert Sdp.local_rtp_map(:video, ["H264", "VP8"], true) ==
               %{"99" => 99, "107" => 107}
    end

    test "unknown codec raises" do
      assert_raise ArgumentError, ~r/unknown audio codec/, fn ->
        Sdp.local_rtp_map(:audio, ["G729"])
      end
    end
  end

  # ── build/1 + parse/1 round trips ───────────────────────────────────────────

  describe "build/1 and parse/1" do
    test "audio-only RTP clear offer round-trips" do
      sdp_str =
        Sdp.build(%{
          ip: "192.168.1.10",
          medias: [%{type: :audio, port: 22_000, codecs: ["PCMU", "PCMA"], dtmf: true}]
        })

      assert sdp_str =~ "m=audio 22000 RTP/AVP 0 8 101"
      assert sdp_str =~ "c=IN IP4 192.168.1.10"
      assert sdp_str =~ "a=rtpmap:101 telephone-event/8000"
      assert sdp_str =~ "a=fmtp:101 0-16"

      assert {:ok, [audio]} = Sdp.parse(sdp_str)
      assert audio.type == :audio
      assert audio.ip == "192.168.1.10"
      assert audio.port == 22_000
      assert audio.rtp_map == %{"0" => 0, "8" => 8, "101" => 100}
      assert audio.codecs == ["PCMU", "PCMA"]
      assert audio.dtmf_pts == %{8000 => 101}
      assert audio.crypto == :none
      assert audio.ice == nil
      assert audio.rtcp_mux == false
      assert audio.direction == :sendrecv
    end

    test "audio+video DTLS + ICE offer round-trips" do
      fp = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01"
      ice = %{ufrag: "ufrag1", pwd: "pwd1234567890123456789012"}

      sdp_str =
        Sdp.build(%{
          ip: "10.0.0.1",
          medias: [
            %{
              type: :audio,
              port: 30_000,
              codecs: ["OPUS"],
              dtmf: true,
              crypto: {:dtls, :actpass, "sha-256", fp},
              ice: ice,
              rtcp_mux: true
            },
            %{
              type: :video,
              port: 30_002,
              codecs: ["VP8"],
              crypto: {:dtls, :actpass, "sha-256", fp},
              ice: ice,
              rtcp_mux: true
            }
          ]
        })

      assert sdp_str =~ "m=audio 30000 UDP/TLS/RTP/SAVPF 98 101"
      assert sdp_str =~ "m=video 30002 UDP/TLS/RTP/SAVPF 107"
      assert sdp_str =~ "a=rtpmap:98 opus/48000/2"
      assert sdp_str =~ "a=fingerprint:sha-256 #{fp}"
      assert sdp_str =~ "a=setup:actpass"

      assert {:ok, [audio, video]} = Sdp.parse(sdp_str)
      assert audio.crypto == {:dtls, :actpass, "sha-256", fp}
      assert audio.ice == ice
      assert audio.rtcp_mux == true
      assert audio.rtp_map == %{"98" => 98, "101" => 100}
      assert video.type == :video
      assert video.crypto == {:dtls, :actpass, "sha-256", fp}
      assert video.rtp_map == %{"107" => 107}
      assert video.dtmf_pts == %{}
    end

    test "SDES answer round-trips" do
      key = "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj"

      sdp_str =
        Sdp.build(%{
          ip: "10.0.0.2",
          medias: [
            %{
              type: :audio,
              port: 40_000,
              codecs: ["G722"],
              crypto: {:sdes, "AES_CM_128_HMAC_SHA1_80", key}
            }
          ]
        })

      assert sdp_str =~ "m=audio 40000 RTP/SAVP 9"
      assert sdp_str =~ "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:#{key}"

      assert {:ok, [audio]} = Sdp.parse(sdp_str)
      assert audio.crypto == {:sdes, "AES_CM_128_HMAC_SHA1_80", key}
      assert audio.codecs == ["G722"]
    end

    test "explicit protocol override for answers" do
      sdp_str =
        Sdp.build(%{
          ip: "10.0.0.3",
          medias: [%{type: :audio, port: 4000, codecs: ["PCMU"], protocol: "RTP/AVPF"}]
        })

      assert sdp_str =~ "m=audio 4000 RTP/AVPF 0"
    end
  end

  # ── parse/1 on foreign SDP ──────────────────────────────────────────────────

  describe "parse/1" do
    test "parses the sample SDP file (static PTs, session-level c=)" do
      sdp_str = File.read!(Path.join(__DIR__, "SDP-SIMPLE.txt"))

      assert {:ok, [audio]} = Sdp.parse(sdp_str)
      assert audio.type == :audio
      assert audio.ip == "10.10.1.99"
      assert audio.port == 11_424
      assert audio.rtp_map == %{"0" => 0, "8" => 8, "101" => 100}
      assert audio.dtmf_pts == %{8000 => 101}
      assert audio.direction == :sendrecv
      assert audio.crypto == :none
    end

    test "static payload types are recognized without a=rtpmap lines" do
      sdp_str = """
      v=0
      o=- 1 1 IN IP4 172.16.0.1
      s=call
      c=IN IP4 172.16.0.1
      t=0 0
      m=audio 5004 RTP/AVP 0 8
      """

      assert {:ok, [audio]} = Sdp.parse(sdp_str)
      assert audio.rtp_map == %{"0" => 0, "8" => 8}
      assert audio.codecs == ["PCMU", "PCMA"]
    end

    test "remote dynamic PT numbering is preserved (opus on 111)" do
      sdp_str = """
      v=0
      o=- 1 1 IN IP4 172.16.0.1
      s=call
      c=IN IP4 172.16.0.1
      t=0 0
      m=audio 5004 RTP/SAVPF 111 110
      a=rtpmap:111 opus/48000/2
      a=rtpmap:110 telephone-event/48000
      a=sendonly
      """

      assert {:ok, [audio]} = Sdp.parse(sdp_str)
      assert audio.rtp_map == %{"111" => 98, "110" => 100}
      assert audio.codecs == ["OPUS"]
      assert audio.dtmf_pts == %{48_000 => 110}
      assert audio.direction == :sendonly
    end

    test "unknown codecs are skipped, media-level c= wins over session c=" do
      sdp_str = """
      v=0
      o=- 1 1 IN IP4 172.16.0.1
      s=call
      c=IN IP4 172.16.0.1
      t=0 0
      m=audio 5004 RTP/AVP 0 18
      c=IN IP4 172.16.0.99
      a=rtpmap:18 G729/8000
      """

      assert {:ok, [audio]} = Sdp.parse(sdp_str)
      assert audio.ip == "172.16.0.99"
      assert audio.rtp_map == %{"0" => 0}
      assert audio.codecs == ["PCMU"]
    end

    test "session-level fingerprint and ICE are inherited by medias" do
      fp = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"

      sdp_str = """
      v=0
      o=- 1 1 IN IP4 172.16.0.1
      s=call
      c=IN IP4 172.16.0.1
      t=0 0
      a=fingerprint:sha-256 #{fp}
      a=ice-ufrag:sess-ufrag
      a=ice-pwd:sess-pwd-123456789012345
      m=audio 5004 RTP/SAVPF 0
      a=setup:active
      """

      assert {:ok, [audio]} = Sdp.parse(sdp_str)
      assert audio.crypto == {:dtls, :active, "sha-256", fp}
      assert audio.ice == %{ufrag: "sess-ufrag", pwd: "sess-pwd-123456789012345"}
    end

    test "text media with RED redundancy round-trips" do
      sdp_str =
        Sdp.build(%{
          ip: "172.16.0.1",
          medias: [%{type: :text, port: 24_000, codecs: ["T140", "T140RED"]}]
        })

      assert sdp_str =~ "m=text 24000 RTP/AVP 106 105"
      assert sdp_str =~ "a=rtpmap:106 t140/1000"
      assert sdp_str =~ "a=rtpmap:105 red/1000"
      assert sdp_str =~ "a=fmtp:105 106/106/106"

      assert {:ok, [text]} = Sdp.parse(sdp_str)
      assert text.type == :text
      assert text.port == 24_000
      assert text.codecs == ["T140", "T140RED"]
      assert text.rtp_map == %{"106" => 106, "105" => 105}
    end

    test "RED alone is advertised without an fmtp" do
      sdp_str =
        Sdp.build(%{
          ip: "172.16.0.1",
          medias: [%{type: :text, port: 24_000, codecs: ["T140RED"]}]
        })

      assert sdp_str =~ "a=rtpmap:105 red/1000"
      refute sdp_str =~ "a=fmtp:105"
    end

    test "non audio/video/text medias are returned as unsupported stubs (G9)" do
      sdp_str = """
      v=0
      o=- 1 1 IN IP4 172.16.0.1
      s=call
      c=IN IP4 172.16.0.1
      t=0 0
      m=audio 5004 RTP/AVP 0
      m=application 5006 UDP/BFCP *
      """

      # G9: every m= section is kept in offer order so the answerer can echo a
      # port-0 rejection for the ones it cannot answer.
      assert {:ok, [audio, app]} = Sdp.parse(sdp_str)
      assert audio.supported? and audio.type == :audio
      refute app.supported?
      assert app.type == :application
      assert app.protocol == "UDP/BFCP"
      assert app.port == 5006
    end

    test "a supported media type on a non-RTP transport is an unsupported stub (G9)" do
      sdp_str = """
      v=0
      o=- 1 1 IN IP4 172.16.0.1
      s=call
      c=IN IP4 172.16.0.1
      t=0 0
      m=audio 5004 RTP/AVP 0
      m=text 60000 TCP/WSS t140
      """

      assert {:ok, [audio, text]} = Sdp.parse(sdp_str)
      assert audio.supported?
      refute text.supported?
      assert text.type == :text
      assert text.protocol == "TCP/WSS"
      assert text.raw_fmt == "t140"
    end

    test "garbage input is an error" do
      assert {:error, _} = Sdp.parse("this is not sdp")
    end

    test "direction and b=AS bandwidth round-trip" do
      sdp_str =
        Sdp.build(%{
          ip: "10.0.0.1",
          medias: [
            %{type: :audio, port: 22_000, codecs: ["PCMU"]},
            %{type: :video, port: 22_002, codecs: ["H264"], bandwidth: 800, direction: :sendonly}
          ]
        })

      assert sdp_str =~ "a=sendrecv"
      assert sdp_str =~ "b=AS:800"
      assert sdp_str =~ "a=sendonly"

      assert {:ok, [audio, video]} = Sdp.parse(sdp_str)
      assert audio.direction == :sendrecv
      assert audio.bandwidth == nil
      assert video.direction == :sendonly
      assert video.bandwidth == 800
    end
  end

  # ── negotiate_bandwidth/2 and reverse_direction/1 ───────────────────────────

  describe "negotiate_bandwidth/2" do
    test "caps our bandwidth to the offered one" do
      assert Sdp.negotiate_bandwidth(600, 800) == 600
      assert Sdp.negotiate_bandwidth(1200, 800) == 800
    end

    test "falls back to the declared side" do
      assert Sdp.negotiate_bandwidth(nil, 800) == 800
      assert Sdp.negotiate_bandwidth(600, 0) == 600
      assert Sdp.negotiate_bandwidth(nil, 0) == 0
    end
  end

  describe "reverse_direction/1" do
    test "mirrors one-way directions and keeps the others" do
      assert Sdp.reverse_direction(:sendonly) == :recvonly
      assert Sdp.reverse_direction(:recvonly) == :sendonly
      assert Sdp.reverse_direction(:sendrecv) == :sendrecv
      assert Sdp.reverse_direction(:inactive) == :inactive
    end
  end

  # ── negotiate/3 ─────────────────────────────────────────────────────────────

  describe "negotiate/3" do
    setup do
      {:ok, [audio]} =
        Sdp.parse("""
        v=0
        o=- 1 1 IN IP4 172.16.0.1
        s=call
        c=IN IP4 172.16.0.1
        t=0 0
        m=audio 5004 RTP/AVP 0 8 101
        a=rtpmap:0 PCMU/8000
        a=rtpmap:8 PCMA/8000
        a=rtpmap:101 telephone-event/8000
        """)

      %{offer: audio}
    end

    test "intersects codecs and keeps remote PT numbering", %{offer: offer} do
      assert {:ok, %{codecs: ["PCMA"], dtmf: true, rtp_map: rtp_map}} =
               Sdp.negotiate(offer, ["pcma", "OPUS"])

      assert rtp_map == %{"8" => 8, "101" => 100}
    end

    test "dtmf can be declined", %{offer: offer} do
      assert {:ok, %{dtmf: false, rtp_map: rtp_map}} =
               Sdp.negotiate(offer, ["PCMU"], false)

      assert rtp_map == %{"0" => 0}
    end

    test "no common codec is an error", %{offer: offer} do
      assert {:error, :no_common_codec} = Sdp.negotiate(offer, ["OPUS"])
    end

    test "text offer with red (RFC 4103) negotiates T140 + T140RED" do
      {:ok, [text]} =
        Sdp.parse("""
        v=0
        o=- 1 1 IN IP4 172.16.0.1
        s=call
        c=IN IP4 172.16.0.1
        t=0 0
        m=text 2918 RTP/AVP 98 99
        a=rtpmap:98 t140/1000
        a=fmtp:98 cps=30
        a=rtpmap:99 red/1000
        a=fmtp:99 98/98/98
        """)

      assert text.codecs == ["T140", "T140RED"]

      assert {:ok, %{codecs: ["T140", "T140RED"], dtmf: false, rtp_map: rtp_map}} =
               Sdp.negotiate(text, ["T140", "T140RED"], false)

      assert rtp_map == %{"98" => 106, "99" => 105}
    end

    # G10 — Chrome offers one telephone-event PT per clock (110@48000, 126@8000)
    setup do
      {:ok, [dual]} =
        Sdp.parse("""
        v=0
        o=- 1 1 IN IP4 172.16.0.1
        s=call
        c=IN IP4 172.16.0.1
        t=0 0
        m=audio 5004 UDP/TLS/RTP/SAVPF 111 0 110 126
        a=rtpmap:111 opus/48000/2
        a=rtpmap:0 PCMU/8000
        a=rtpmap:110 telephone-event/48000
        a=rtpmap:126 telephone-event/8000
        """)

      %{dual: dual}
    end

    test "telephone-event PT matches the primary codec clock (OPUS → 48000)", %{dual: dual} do
      assert {:ok, %{dtmf: true, dtmf_pt: 110, dtmf_clock: 48_000, rtp_map: rtp_map}} =
               Sdp.negotiate(dual, ["OPUS", "PCMU"])

      # both common codecs kept; only the matched telephone-event PT (110@48000,
      # not 126@8000) is retained in the send map
      assert rtp_map == %{"0" => 0, "111" => 98, "110" => 100}
    end

    test "telephone-event PT matches the primary codec clock (PCMU → 8000)", %{dual: dual} do
      assert {:ok, %{dtmf: true, dtmf_pt: 126, dtmf_clock: 8000, rtp_map: rtp_map}} =
               Sdp.negotiate(dual, ["PCMU", "OPUS"])

      assert rtp_map == %{"0" => 0, "111" => 98, "126" => 100}
    end

    test "only the matched telephone-event PT survives when a single codec is picked",
         %{dual: dual} do
      assert {:ok, %{dtmf: true, dtmf_pt: 110, dtmf_clock: 48_000, rtp_map: rtp_map}} =
               Sdp.negotiate(dual, ["OPUS"])

      assert rtp_map == %{"111" => 98, "110" => 100}
    end
  end

  # ── answer_rtpmaps/2 ────────────────────────────────────────────────────────

  describe "answer_rtpmaps/2" do
    test "emits the telephone-event PT with its negotiated clock (G10)" do
      neg = %{rtp_map: %{"111" => 98, "110" => 100}, dtmf_clock: 48_000}

      assert Sdp.answer_rtpmaps(:audio, neg) == [
               %{pt: 110, encoding: "telephone-event", clock: 48_000, channels: nil},
               %{pt: 111, encoding: "opus", clock: 48_000, channels: 2}
             ]
    end

    test "defaults the telephone-event clock to 8000 when unspecified" do
      neg = %{rtp_map: %{"0" => 0, "101" => 100}}

      assert Sdp.answer_rtpmaps(:audio, neg) == [
               %{pt: 0, encoding: "PCMU", clock: 8000, channels: nil},
               %{pt: 101, encoding: "telephone-event", clock: 8000, channels: nil}
             ]
    end
  end

  # ── parse_media_candidate/1 ─────────────────────────────────────────────────

  describe "parse_media_candidate/1" do
    test "decodes rtp://ip:port" do
      assert {:ok, "192.168.1.10", 22_000} =
               Sdp.parse_media_candidate("rtp://192.168.1.10:22000")
    end

    test "decodes bracketed IPv6" do
      assert {:ok, "2001:db8::1", 9000} =
               Sdp.parse_media_candidate("rtp://[2001:db8::1]:9000")
    end

    test "rejects malformed candidates" do
      assert {:error, {:bad_candidate, _}} = Sdp.parse_media_candidate("nonsense")
      assert {:error, {:bad_candidate, _}} = Sdp.parse_media_candidate("rtp://hostonly")
    end
  end

  # ── Delegated SDP negotiation (enriched EndpointStartReceiving) ──────────────

  describe "accepted_pts/2" do
    test "keeps only proposed PTs, preserving (possibly empty) fmtp" do
      proposed = %{"0" => 0, "96" => 99, "101" => 100}

      struct = %{
        "0" => "",
        "96" => "profile-level-id=42801f;packetization-mode=1",
        "101" => "0-16"
      }

      assert Sdp.accepted_pts(proposed, struct) == struct
    end

    test "a proposed PT absent from the struct was filtered by the server" do
      proposed = %{"0" => 0, "96" => 99}
      # server dropped H264 (96): only PCMU accepted
      assert Sdp.accepted_pts(proposed, %{"0" => ""}) == %{"0" => ""}
    end

    test "an unproposed PT returned by the server is dropped and logged" do
      proposed = %{"0" => 0}

      log =
        capture_log(fn ->
          assert Sdp.accepted_pts(proposed, %{"0" => "", "99" => "some=fmtp"}) == %{"0" => ""}
        end)

      assert log =~ "unproposed payload type 99"
    end

    test "nil struct (older server) yields nil → legacy path" do
      assert Sdp.accepted_pts(%{"0" => 0}, nil) == nil
    end
  end

  describe "pt_rtpmap/2 and code_rtpmap/2" do
    test "pt_rtpmap resolves our offered payload types" do
      assert Sdp.pt_rtpmap(:audio, 0) == {"PCMU", 8000, nil}
      assert Sdp.pt_rtpmap(:audio, 98) == {"opus", 48_000, 2}
      assert Sdp.pt_rtpmap(:audio, 101) == {"telephone-event", 8000, nil}
      assert Sdp.pt_rtpmap(:video, 99) == {"H264", 90_000, nil}
      assert Sdp.pt_rtpmap(:text, 105) == {"red", 1000, nil}
      assert Sdp.pt_rtpmap(:audio, 42) == :unknown
    end

    test "code_rtpmap resolves from the Mendooze codec code (answer side)" do
      assert Sdp.code_rtpmap(:audio, 0) == {"PCMU", 8000, nil}
      assert Sdp.code_rtpmap(:audio, 98) == {"opus", 48_000, 2}
      assert Sdp.code_rtpmap(:audio, 100) == {"telephone-event", 8000, nil}
      assert Sdp.code_rtpmap(:video, 99) == {"H264", 90_000, nil}
      assert Sdp.code_rtpmap(:audio, 42) == :unknown
    end
  end

  describe "restrict_send_map/3" do
    test "drops codes the server filtered on receive" do
      # we proposed PCMU/H264/dtmf on receive; the server accepted PCMU + dtmf
      proposed_recv = %{"0" => 0, "96" => 99, "101" => 100}
      accepted = %{"0" => "", "101" => "0-16"}
      # send map uses the remote numbering (H264 on 120 here)
      send_map = %{"0" => 0, "120" => 99, "101" => 100}

      assert Sdp.restrict_send_map(send_map, proposed_recv, accepted) ==
               %{"0" => 0, "101" => 100}
    end

    test "nil accepted (older server) leaves the send map unchanged" do
      send_map = %{"0" => 0, "8" => 8}
      assert Sdp.restrict_send_map(send_map, %{"0" => 0}, nil) == send_map
    end
  end

  describe "build/1 server-driven codec section" do
    test "audio: emits accepted rtpmap entries + fmtp verbatim, none for empty fmtp" do
      sdp_str =
        Sdp.build(%{
          ip: "192.168.1.10",
          medias: [
            %{
              type: :audio,
              port: 22_000,
              rtpmaps: [
                %{pt: 0, encoding: "PCMU", clock: 8000},
                %{pt: 111, encoding: "opus", clock: 48_000, channels: 2},
                %{pt: 101, encoding: "telephone-event", clock: 8000}
              ],
              fmtp: %{"0" => "", "111" => "minptime=10;useinbandfec=1", "101" => "0-16"}
            }
          ]
        })

      assert sdp_str =~ "m=audio 22000 RTP/AVP 0 111 101"
      assert sdp_str =~ "a=rtpmap:0 PCMU/8000"
      assert sdp_str =~ "a=rtpmap:111 opus/48000/2"
      assert sdp_str =~ "a=rtpmap:101 telephone-event/8000"
      assert sdp_str =~ "a=fmtp:111 minptime=10;useinbandfec=1"
      assert sdp_str =~ "a=fmtp:101 0-16"
      # PCMU has an empty fmtp → no a=fmtp line for PT 0
      refute sdp_str =~ "a=fmtp:0 "

      assert {:ok, [audio]} = Sdp.parse(sdp_str)
      assert audio.rtp_map == %{"0" => 0, "111" => 98, "101" => 100}
    end

    test "video: H264 fmtp is forwarded verbatim and the SDP round-trips" do
      fmtp = "profile-level-id=42801f;packetization-mode=1"

      sdp_str =
        Sdp.build(%{
          ip: "10.0.0.1",
          medias: [
            %{
              type: :video,
              port: 30_000,
              rtpmaps: [%{pt: 96, encoding: "H264", clock: 90_000}],
              fmtp: %{"96" => fmtp},
              bandwidth: 800
            }
          ]
        })

      assert sdp_str =~ "m=video 30000 RTP/AVP 96"
      assert sdp_str =~ "a=rtpmap:96 H264/90000"
      assert sdp_str =~ "a=fmtp:96 #{fmtp}"
      assert sdp_str =~ "b=AS:800"

      assert {:ok, [video]} = Sdp.parse(sdp_str)
      assert video.type == :video
      assert video.port == 30_000
    end

    test "server-driven fields win, and transport/crypto still apply" do
      sdp_str =
        Sdp.build(%{
          ip: "10.0.0.2",
          medias: [
            %{
              type: :audio,
              port: 40_000,
              rtpmaps: [%{pt: 8, encoding: "PCMA", clock: 8000}],
              fmtp: %{"8" => ""},
              crypto: {:sdes, "AES_CM_128_HMAC_SHA1_80", "key0123456789"},
              direction: :sendonly
            }
          ]
        })

      assert sdp_str =~ "m=audio 40000 RTP/SAVP 8"
      assert sdp_str =~ "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:key0123456789"
      assert sdp_str =~ "a=sendonly"
    end
  end

  # ── WebRTC transport plane (phase 1) ────────────────────────────────────────

  describe "host_candidates/3" do
    test "rtcp-mux: a single component-1 candidate with the RFC 8445 priority" do
      assert Sdp.host_candidates("192.168.1.10", 22_000, true) ==
               [
                 %{
                   foundation: "1",
                   component: 1,
                   protocol: :udp,
                   priority: 2_130_706_431,
                   ip: "192.168.1.10",
                   port: 22_000,
                   type: :host
                 }
               ]
    end

    test "no rtcp-mux: adds a component-2 candidate on port+1 (priority - 1)" do
      assert [rtp, rtcp] = Sdp.host_candidates("192.168.1.10", 22_000, false)
      assert rtp.component == 1 and rtp.port == 22_000 and rtp.priority == 2_130_706_431
      assert rtcp.component == 2 and rtcp.port == 22_001 and rtcp.priority == 2_130_706_430
    end

    test "IPv6 candidate is rendered verbatim" do
      [c] = Sdp.host_candidates("2a01:cb15::b8cd", 40_000, true)

      assert Sdp.candidate_line(c) ==
               "1 1 udp 2130706431 2a01:cb15::b8cd 40000 typ host"
    end
  end

  describe "build/1 WebRTC offer (transport plane)" do
    setup do
      fp = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01"
      ice = %{ufrag: "ufrag1", pwd: "pwd1234567890123456789012"}
      %{fp: fp, ice: ice}
    end

    test "emits UDP/TLS/RTP/SAVPF, setup:actpass, mux, mid, candidates, rtcp-fb per video PT",
         %{fp: fp, ice: ice} do
      crypto = {:dtls, :actpass, "sha-256", fp}

      sdp_str =
        Sdp.build(%{
          ip: "192.168.1.10",
          medias: [
            %{
              type: :audio,
              port: 22_000,
              rtpmaps: [%{pt: 111, encoding: "opus", clock: 48_000, channels: 2}],
              fmtp: %{"111" => "minptime=10;useinbandfec=1"},
              crypto: crypto,
              ice: ice,
              rtcp_mux: true,
              mid: "0",
              candidates: Sdp.host_candidates("192.168.1.10", 22_000, true),
              rtcp_fb: false
            },
            %{
              type: :video,
              port: 22_002,
              rtpmaps: [
                %{pt: 96, encoding: "H264", clock: 90_000},
                %{pt: 98, encoding: "VP8", clock: 90_000}
              ],
              fmtp: %{"96" => "profile-level-id=42801f;packetization-mode=1"},
              crypto: crypto,
              ice: ice,
              rtcp_mux: true,
              mid: "1",
              candidates: Sdp.host_candidates("192.168.1.10", 22_002, true),
              rtcp_fb: true
            }
          ]
        })

      assert sdp_str =~ "m=audio 22000 UDP/TLS/RTP/SAVPF 111"
      assert sdp_str =~ "m=video 22002 UDP/TLS/RTP/SAVPF 96 98"
      assert sdp_str =~ "a=setup:actpass"
      assert sdp_str =~ "a=rtcp-mux"
      assert sdp_str =~ "a=mid:0"
      assert sdp_str =~ "a=mid:1"
      assert sdp_str =~ "a=candidate:1 1 udp 2130706431 192.168.1.10 22000 typ host"
      assert sdp_str =~ "a=candidate:1 1 udp 2130706431 192.168.1.10 22002 typ host"

      # rtcp-fb on every video PT, none on audio
      for pt <- [96, 98] do
        assert sdp_str =~ "a=rtcp-fb:#{pt} nack"
        assert sdp_str =~ "a=rtcp-fb:#{pt} ccm fir"
        assert sdp_str =~ "a=rtcp-fb:#{pt} goog-remb"
      end

      refute sdp_str =~ "a=rtcp-fb:111"

      # no session ice-lite in offers (D7)
      refute sdp_str =~ "a=ice-lite"

      assert {:ok, [audio, video]} = Sdp.parse(sdp_str)
      assert audio.mid == "0"
      assert video.mid == "1"
      assert Map.keys(video.rtcp_fb) |> Enum.sort() == [96, 98]
      assert video.rtcp_fb[96] |> Enum.sort() == ["ccm fir", "goog-remb", "nack"]
      assert audio.rtcp_fb == %{}
    end

    test "legacy codec branch also emits the transport plane", %{fp: fp, ice: ice} do
      crypto = {:dtls, :actpass, "sha-256", fp}

      sdp_str =
        Sdp.build(%{
          ip: "10.0.0.1",
          medias: [
            %{
              type: :video,
              port: 30_002,
              codecs: ["H264", "VP8"],
              crypto: crypto,
              ice: ice,
              rtcp_mux: true,
              mid: "1",
              candidates: Sdp.host_candidates("10.0.0.1", 30_002, true),
              rtcp_fb: true
            }
          ]
        })

      assert sdp_str =~ "m=video 30002 UDP/TLS/RTP/SAVPF 99 107"
      assert sdp_str =~ "a=mid:1"
      assert sdp_str =~ "a=candidate:1 1 udp 2130706431 10.0.0.1 30002 typ host"
      # H264 default PT is 99, VP8 is 107 (codec table)
      assert sdp_str =~ "a=rtcp-fb:99 nack"
      assert sdp_str =~ "a=rtcp-fb:107 goog-remb"
    end
  end

  describe "build/1 WebRTC answer (mirroring + ice-lite)" do
    test "session ice-lite, mirrored protocol/mid, setup:passive" do
      sdp_str =
        Sdp.build(%{
          ip: "10.0.0.9",
          ice_lite: true,
          medias: [
            %{
              type: :audio,
              port: 40_000,
              rtpmaps: [%{pt: 0, encoding: "PCMU", clock: 8000}],
              fmtp: %{"0" => ""},
              crypto: {:dtls, :passive, "sha-256", "AA:BB"},
              ice: %{ufrag: "u", pwd: "p234567890123456789012345"},
              protocol: "UDP/TLS/RTP/SAVPF",
              rtcp_mux: true,
              mid: "0"
            }
          ]
        })

      assert sdp_str =~ "a=ice-lite"
      assert sdp_str =~ "m=audio 40000 UDP/TLS/RTP/SAVPF 0"
      assert sdp_str =~ "a=setup:passive"
      assert sdp_str =~ "a=mid:0"
    end
  end

  describe "parse/1 WebRTC extensions and §1.8 tolerance" do
    test "non-WebRTC SDP yields empty transport-plane defaults (regression guard)" do
      {:ok, [audio]} =
        Sdp.parse("""
        v=0
        o=- 1 1 IN IP4 172.16.0.1
        s=call
        c=IN IP4 172.16.0.1
        t=0 0
        m=audio 5004 RTP/AVP 0 8
        """)

      assert audio.mid == nil
      assert audio.rtcp_fb == %{}
      assert audio.candidates == []
    end

    test "parses the captured Chrome 142 offer without choking" do
      sdp_str = File.read!(Path.join(__DIR__, "SDP-chrome-142-offer.txt"))

      assert {:ok, [audio, video, text]} = Sdp.parse(sdp_str)
      assert audio.supported? and video.supported?

      # numeric mids echoed verbatim
      assert audio.mid == "0"
      assert video.mid == "1"

      # G10: telephone-event PTs collected per clock (110@48000, 126@8000)
      assert audio.dtmf_pts == %{48_000 => 110, 8000 => 126}

      # candidates kept raw (host + tcp lines), never used for addressing
      assert Enum.any?(audio.candidates, &String.contains?(&1, "172.22.0.4 53521 typ host"))
      assert length(audio.candidates) == 6

      # rtcp-fb parsed per video PT (six H264 + VP8)
      assert Map.has_key?(video.rtcp_fb, 39)
      assert "nack" in video.rtcp_fb[96]
      assert "goog-remb" in video.rtcp_fb[96]

      # tolerated attributes do not break parsing; mux detected
      assert audio.rtcp_mux == true
      assert video.rtcp_mux == true

      # G9: the non-RTP text section (m=text TCP/WSS t140) is returned as an
      # unsupported stub so the answerer can decline it with port 0.
      refute text.supported?
      assert text.type == :text
      assert text.protocol == "TCP/WSS"
      assert text.raw_fmt == "t140"
    end
  end
end
