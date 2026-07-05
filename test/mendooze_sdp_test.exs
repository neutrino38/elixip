defmodule Mendooze.SdpTest do
  use ExUnit.Case, async: true

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
      assert audio.dtmf_pt == 101
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

      assert sdp_str =~ "m=audio 30000 RTP/SAVPF 98 101"
      assert sdp_str =~ "m=video 30002 RTP/SAVPF 107"
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
      assert video.dtmf_pt == nil
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
      assert audio.dtmf_pt == 101
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
      assert audio.dtmf_pt == 110
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

    test "non audio/video medias are ignored" do
      sdp_str = """
      v=0
      o=- 1 1 IN IP4 172.16.0.1
      s=call
      c=IN IP4 172.16.0.1
      t=0 0
      m=audio 5004 RTP/AVP 0
      m=application 5006 UDP/BFCP *
      """

      assert {:ok, [%{type: :audio}]} = Sdp.parse(sdp_str)
    end

    test "garbage input is an error" do
      assert {:error, _} = Sdp.parse("this is not sdp")
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
end
