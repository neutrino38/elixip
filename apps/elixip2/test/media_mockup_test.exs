defmodule MediaMockupTest do
  use ExUnit.Case, async: true

  alias MediaServer.Mockup

  # ── Helpers ─────────────────────────────────────────────────────────────────

  defp start_conn(opts \\ []) do
    {:ok, conn} = Mockup.create_peer_connection(nil, self(), opts)
    on_exit(fn -> if Process.alive?(conn), do: Mockup.close_peer_connection(conn) end)
    conn
  end

  # The mockup conn binds a single RTP socket; every media line advertises its
  # (ephemeral) port. Extract it from the local offer.
  defp media_port(conn) do
    {:ok, sdp_str} = Mockup.get_local_offer(conn)
    {:ok, sdp} = ExSDP.parse(sdp_str)
    [%ExSDP.Media{port: port} | _] = sdp.media
    port
  end

  defp open_probe_socket do
    {:ok, sock} = Socket.UDP.open(mode: :active)
    :ok = Socket.UDP.process(sock, self())
    on_exit(fn -> Socket.close(sock) end)
    sock
  end

  defp send_probe(sock, port, payload),
    do: :ok = Socket.Datagram.send(sock, payload, {{127, 0, 0, 1}, port})

  # ── Recorder echo option ────────────────────────────────────────────────────

  test "recorder with echo: true loops media back while recording, stops on stop" do
    conn = start_conn()
    port = media_port(conn)

    {:ok, rec} = Mockup.create_recorder(conn, "/rec/call.mp4", 0, echo: true)
    :ok = Mockup.start_recorder(rec)
    assert_receive {:ms_event, ^rec, :recorder_started}

    sock = open_probe_socket()
    send_probe(sock, port, "ping")
    assert_receive {:udp, _s, _ip, _port, packet}, 1_000
    assert IO.iodata_to_binary(packet) == "ping"

    :ok = Mockup.stop_recorder(rec)
    assert_receive {:ms_event, ^rec, {:recorder_stopped, :caller}}

    # the loopback stops with the recording
    send_probe(sock, port, "ping2")
    refute_receive {:udp, _, _, _, _}, 300
  end

  test "recorder without echo does not loop media back" do
    conn = start_conn()
    port = media_port(conn)

    {:ok, rec} = Mockup.create_recorder(conn, "/rec/call.mp4", 0, [])
    :ok = Mockup.start_recorder(rec)
    assert_receive {:ms_event, ^rec, :recorder_started}

    sock = open_probe_socket()
    send_probe(sock, port, "ping")
    refute_receive {:udp, _, _, _, _}, 300
  end

  test "recorder echo stops when the max duration elapses" do
    conn = start_conn()
    port = media_port(conn)

    {:ok, rec} = Mockup.create_recorder(conn, "/rec/call.mp4", 100, echo: true)
    :ok = Mockup.start_recorder(rec)
    assert_receive {:ms_event, ^rec, {:recorder_stopped, :duration}}, 1_000

    sock = open_probe_socket()
    send_probe(sock, port, "ping")
    refute_receive {:udp, _, _, _, _}, 300
  end

  # ── Recorder wait_video option ──────────────────────────────────────────────

  test "wait_video defaults to true when video is negotiated" do
    conn = start_conn(media: :audio_video)
    {:ok, rec} = Mockup.create_recorder(conn, "/rec/call.mp4", 0, [])
    assert :sys.get_state(rec).wait_video
  end

  test "wait_video can be disabled explicitly" do
    conn = start_conn(media: :audio_video)
    {:ok, rec} = Mockup.create_recorder(conn, "/rec/call.mp4", 0, wait_video: false)
    refute :sys.get_state(rec).wait_video
  end

  test "wait_video is auto-disabled when the connection has no video" do
    conn = start_conn(media: :audio)
    {:ok, rec} = Mockup.create_recorder(conn, "/rec/call.mp4", 0, wait_video: true)
    refute :sys.get_state(rec).wait_video
  end

  # ── WebRTC offer/answer (§2.6 — converged on MediaServer.Mendooze.Sdp) ───────

  alias MediaServer.Mendooze.Sdp

  describe "get_local_offer asymmetry" do
    test "webrtc_support: :yes produces a browser-shaped WebRTC offer" do
      conn = start_conn(media: :audio_video, webrtc_support: :yes)
      {:ok, offer} = Mockup.get_local_offer(conn)

      assert offer =~ "UDP/TLS/RTP/SAVPF"
      assert offer =~ "a=setup:actpass"
      assert offer =~ "a=fingerprint:sha-256 "
      assert offer =~ "a=ice-ufrag:"
      assert offer =~ "a=rtcp-mux"
      assert offer =~ "a=mid:audio"
      assert offer =~ "a=mid:video"
      assert offer =~ ~r{a=candidate:\d+ 1 udp \d+ }
      assert offer =~ ~r{a=rtcp-fb:\d+ nack}
      # offers do not claim ice-lite (D7)
      refute offer =~ "a=ice-lite"
    end

    test "webrtc_support: :if_offered produces a plain RTP/AVP offer (not SAVPF)" do
      conn = start_conn(media: :audio, webrtc_support: :if_offered)
      {:ok, offer} = Mockup.get_local_offer(conn)

      assert offer =~ "RTP/AVP "
      refute offer =~ "SAVPF"
      refute offer =~ "a=fingerprint"
    end
  end

  describe "set_remote_offer answers gateway-like" do
    test "a WebRTC offer is answered setup:passive, ice-lite, mirrored mux/mid" do
      # caller builds a browser-shaped offer
      offer =
        Sdp.build(%{
          ip: "10.1.2.3",
          medias: [
            %{
              type: :audio,
              port: 5000,
              codecs: ["PCMU"],
              dtmf: true,
              crypto: {:dtls, :actpass, "sha-256", "AA:BB:CC"},
              ice: %{ufrag: "calleruf", pwd: "callerpwd-01234567890123"},
              protocol: "UDP/TLS/RTP/SAVPF",
              rtcp_mux: true,
              mid: "0"
            }
          ]
        })

      conn = start_conn(media: :audio, audio_codec: "PCMU", webrtc_support: :if_offered)
      {:ok, answer} = Mockup.set_remote_offer(conn, offer)

      assert answer =~ "a=ice-lite"
      assert answer =~ "UDP/TLS/RTP/SAVPF"
      assert answer =~ "a=setup:passive"
      assert answer =~ "a=rtcp-mux"
      assert answer =~ "a=mid:0"
      assert answer =~ ~r{a=candidate:\d+ 1 udp \d+ }

      # offerer PT numbering is preserved (PCMU on 0)
      assert {:ok, [aud]} = Sdp.parse(answer)
      assert aud.mid == "0"
      assert aud.rtp_map == %{"0" => 0, "101" => 100}
    end

    test "the captured Chrome 142 offer is answered completely (G9/G10)" do
      offer = File.read!(Path.join(__DIR__, "SDP-chrome-142-offer.txt"))

      # G.711 selected so the 8000 Hz telephone-event PT (126) is chosen, not
      # the 48000 Hz one (110). Video accepts the offered VP8/H264.
      conn =
        start_conn(
          media: :audio_video,
          audio_codec: ["PCMU"],
          video_codec: ["VP8", "H264"],
          webrtc_support: :if_offered
        )

      {:ok, answer} = Mockup.set_remote_offer(conn, offer)

      # G9: one answer m= per offered m=, in order — the non-RTP text section is
      # declined with port 0 while audio/video carry real answers.
      assert {:ok, [aud, vid, txt]} = Sdp.parse(answer)
      assert aud.type == :audio and aud.port != 0
      assert vid.type == :video and vid.port != 0
      refute txt.supported?
      assert txt.port == 0
      assert answer =~ "m=text 0 TCP/WSS t140"

      # numeric mids echoed verbatim, gateway-shaped DTLS role
      assert aud.mid == "0"
      assert vid.mid == "1"
      assert answer =~ "a=setup:passive"

      # G10: the 8000 Hz telephone-event PT (126) is answered, not 110@48000
      assert aud.rtp_map == %{"0" => 0, "126" => 100}
      assert answer =~ "a=rtpmap:126 telephone-event/8000"
      refute answer =~ "telephone-event/48000"

      # offerer PT numbering preserved on video (VP8 was PT 96 in the offer)
      assert Map.get(vid.rtp_map, "96") == 107
    end

    test "a DTLS offer with webrtc_support: :no is refused" do
      offer =
        Sdp.build(%{
          ip: "10.1.2.3",
          medias: [
            %{
              type: :audio,
              port: 5000,
              codecs: ["PCMU"],
              crypto: {:dtls, :actpass, "sha-256", "AA:BB"}
            }
          ]
        })

      conn = start_conn(media: :audio, webrtc_support: :no)
      assert {:error, :webrtc_not_supported} = Mockup.set_remote_offer(conn, offer)
      # the failure is also signalled asynchronously as a capturable event
      assert_receive {:ms_event, ^conn, {:media_error, :webrtc_not_supported}}
    end

    test "an unparseable remote answer emits a {:media_error, _} event" do
      conn = start_conn(media: :audio, webrtc_support: :yes)
      assert {:error, _} = Mockup.set_remote_answer(conn, "not an sdp")
      assert_receive {:ms_event, ^conn, {:media_error, _reason}}
    end
  end

  test "WebRTC bridge: UAC offer → gateway-like Mockup answer → :ice_connected" do
    # This is the CI stand-in for the IVeS gateway (§2.5/§2.6): a WebRTC UAC
    # Mockup offers, a second Mockup answers gateway-like, the UAC consumes it.
    uac = start_conn(media: :audio_video, webrtc_support: :yes, ice_delay_ms: 0)
    {:ok, offer} = Mockup.get_local_offer(uac)

    gateway = start_conn(media: :audio_video, webrtc_support: :if_offered)
    {:ok, answer} = Mockup.set_remote_offer(gateway, offer)

    assert answer =~ "a=setup:passive"
    assert answer =~ "a=ice-lite"

    assert :ok = Mockup.set_remote_answer(uac, answer)
    assert_receive {:ms_event, ^uac, :ice_connected}, 1_000
  end
end
