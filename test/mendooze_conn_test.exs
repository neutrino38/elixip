Code.require_file("support/jsr309_fake_server.exs", __DIR__)

defmodule Mendooze.ConnTest do
  # app env tweaks are global — keep this file synchronous
  use ExUnit.Case, async: false

  alias MediaServer.Mendooze
  alias MediaServer.Mendooze.Sdp

  @fp "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01"

  # Scripted RPC behaviour: ids and ports are deterministic so the tests can
  # assert on them. EndpointStartReceiving returns 22000 for audio, 22002
  # for video.
  defp rpc_handler("EventQueueCreate", _), do: {:ok, [7, "/events/jsr309/7"]}
  defp rpc_handler("MediaSessionCreate", _), do: {:ok, [3]}
  defp rpc_handler("EndpointCreate", _), do: {:ok, [4]}
  defp rpc_handler("EndpointStartReceiving", [_, _, 0, _]), do: {:ok, [22_000]}
  defp rpc_handler("EndpointStartReceiving", [_, _, 1, _]), do: {:ok, [22_002]}

  defp rpc_handler("GetMediaCandidates", [_, _, 0, media]),
    do: {:ok, ["rtp://192.168.5.5:#{22_000 + 2 * media}"]}

  defp rpc_handler("EndpointGetLocalCryptoDTLSFingerprint", ["sha-256"]), do: {:ok, [@fp]}
  defp rpc_handler(_method, _params), do: {:ok, []}

  defp start_media_server(handler \\ &rpc_handler/2) do
    fake = Jsr309FakeServer.start(self(), handler)
    {:ok, server} = Mendooze.connect({fake.host, fake.port})
    on_exit(fn -> if Process.alive?(server), do: Mendooze.disconnect(server) end)

    assert_receive {:jsr309_call, "EventQueueCreate", []}, 1_000
    assert_receive {:stream_conn, stream, _}, 1_000
    %{fake: fake, server: server, stream: stream}
  end

  defp remote_answer(opts \\ []) do
    Sdp.build(%{
      ip: Keyword.get(opts, :ip, "10.9.8.7"),
      medias: [
        Keyword.get(opts, :audio, %{type: :audio, port: 40_000, codecs: ["PCMU"], dtmf: true})
      ]
    })
  end

  # ── Connection setup ────────────────────────────────────────────────────────

  test "create_peer_connection creates the session and endpoint" do
    %{server: server} = start_media_server()

    assert {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)

    assert_receive {:jsr309_call, "MediaSessionCreate", [sess_tag, 7]}
    assert sess_tag =~ ~r/^cx-\d+$/
    assert_receive {:jsr309_call, "EndpointCreate", [3, ^sess_tag, true, false, false]}
    assert Process.alive?(conn)
  end

  test "audio_video connections request both media flags" do
    %{server: server} = start_media_server()

    assert {:ok, _conn} = Mendooze.create_peer_connection(server, self())
    assert_receive {:jsr309_call, "EndpointCreate", [3, _tag, true, true, false]}
  end

  test "a session create failure is reported and nothing leaks" do
    fake =
      Jsr309FakeServer.start(self(), fn
        "EventQueueCreate", _ -> {:ok, [7, "/events/jsr309/7"]}
        "MediaSessionCreate", _ -> {:error, "quota exceeded"}
        m, p -> rpc_handler(m, p)
      end)

    {:ok, server} = Mendooze.connect({fake.host, fake.port})
    on_exit(fn -> if Process.alive?(server), do: Mendooze.disconnect(server) end)

    assert {:error, {:jsr309_error, "quota exceeded"}} =
             Mendooze.create_peer_connection(server, self(), media: :audio)
  end

  # ── UAC: offer then answer, plain RTP audio ─────────────────────────────────

  test "get_local_offer starts receiving and builds the offer from GetMediaCandidates" do
    %{server: server} = start_media_server()

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(), media: :audio, audio_codec: "PCMU")

    assert {:ok, offer} = Mendooze.get_local_offer(conn)

    assert_receive {:jsr309_call, "EndpointStartReceiving", [3, 4, 0, rtp_map]}
    assert rtp_map == %{"0" => 0, "101" => 100}
    assert_receive {:jsr309_call, "GetMediaCandidates", [3, 4, 0, 0]}

    assert offer =~ "m=audio 22000 RTP/AVP 0 101"
    assert offer =~ "c=IN IP4 192.168.5.5"

    # the offer is parseable by our own SDP layer
    assert {:ok, [%{type: :audio, port: 22_000, ip: "192.168.5.5"}]} = Sdp.parse(offer)
  end

  test "set_remote_answer starts sending with the remote map then arms the watchdog" do
    %{server: server, stream: stream} = start_media_server()

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(), media: :audio, audio_codec: "PCMU")

    assert_receive {:jsr309_call, "MediaSessionCreate", [sess_tag, _q]}

    {:ok, _offer} = Mendooze.get_local_offer(conn)
    assert :ok = Mendooze.set_remote_answer(conn, remote_answer())

    assert_receive {:jsr309_call, "EndpointStartSending", [3, 4, 0, "10.9.8.7", 40_000, send_map]}
    assert send_map == %{"0" => 0, "101" => 100}

    # watchdog armed after the answer is processed, never before
    assert_receive {:jsr309_call, "EndpointStartRTPTimeout", [3, 4, 0, timeout]}
    assert timeout > 0

    # :ice_connected is no longer emitted on the answer: it now reflects the
    # first validated RTP packet the server reports (EndpointConnectedEvent, 7)
    refute_receive {:ms_event, ^conn, :ice_connected}, 100
    send(stream, {:chunk, Jsr309FakeServer.event_frame([7, sess_tag, 4, 0, 0])})
    assert_receive {:ms_event, ^conn, :ice_connected}
  end

  test "the connection-level :ice_connected is emitted once across medias" do
    %{server: server, stream: stream} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio_video)
    assert_receive {:jsr309_call, "MediaSessionCreate", [sess_tag, _q]}

    # first validated packet on audio then video: only one :ice_connected
    send(stream, {:chunk, Jsr309FakeServer.event_frame([7, sess_tag, 4, 0, 0])})
    assert_receive {:ms_event, ^conn, :ice_connected}

    send(stream, {:chunk, Jsr309FakeServer.event_frame([7, sess_tag, 4, 1, 0])})
    refute_receive {:ms_event, ^conn, :ice_connected}, 200
  end

  test "an answer without any common codec tears the connection down" do
    %{server: server} = start_media_server()

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(), media: :audio, audio_codec: "OPUS")

    {:ok, _offer} = Mendooze.get_local_offer(conn)

    answer = remote_answer(audio: %{type: :audio, port: 40_000, codecs: ["PCMA"]})
    assert {:error, :no_common_codec} = Mendooze.set_remote_answer(conn, answer)

    # the failed setup freed the server-side resources
    assert_receive {:jsr309_call, "EndpointDelete", [3, 4]}
    assert_receive {:jsr309_call, "MediaSessionDelete", [3]}
    assert_receive {:ms_event, ^conn, :closed}
    refute Process.alive?(conn)
  end

  # ── UAC: DTLS + ICE ─────────────────────────────────────────────────────────

  test "webrtc offer carries DTLS fingerprint and ICE credentials" do
    %{server: server} = start_media_server()

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(),
        media: :audio,
        audio_codec: "OPUS",
        webrtc_support: :yes
      )

    assert {:ok, offer} = Mendooze.get_local_offer(conn)

    assert_receive {:jsr309_call, "EndpointGetLocalCryptoDTLSFingerprint", ["sha-256"]}
    assert_receive {:jsr309_call, "EndpointSetLocalSTUNCredentials", [3, 4, 0, ufrag, pwd]}
    assert is_binary(ufrag) and is_binary(pwd)

    assert {:ok, [audio]} = Sdp.parse(offer)
    assert audio.crypto == {:dtls, :actpass, "sha-256", @fp}
    assert audio.ice == %{ufrag: ufrag, pwd: pwd}
  end

  test "a DTLS answer sets remote crypto and credentials before sending" do
    %{server: server} = start_media_server()

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(),
        media: :audio,
        audio_codec: "OPUS",
        webrtc_support: :yes
      )

    {:ok, _offer} = Mendooze.get_local_offer(conn)

    answer =
      Sdp.build(%{
        ip: "10.9.8.7",
        medias: [
          %{
            type: :audio,
            port: 40_000,
            codecs: ["OPUS"],
            crypto: {:dtls, :active, "sha-256", @fp},
            ice: %{ufrag: "remote-uf", pwd: "remote-pwd-123456789012345"},
            rtcp_mux: true
          }
        ]
      })

    assert :ok = Mendooze.set_remote_answer(conn, answer)

    assert_receive {:jsr309_call, "EndpointSetRTPProperties", [3, 4, 0, %{"rtcp-mux" => "1"}]}

    assert_receive {:jsr309_call, "EndpointSetRemoteCryptoDTLS",
                    [3, 4, 0, "active", "sha-256", @fp]}

    assert_receive {:jsr309_call, "EndpointSetRemoteSTUNCredentials",
                    [3, 4, 0, "remote-uf", "remote-pwd-123456789012345"]}

    # crypto/credentials must precede the media start
    assert_receive {:jsr309_call, "EndpointStartSending", [3, 4, 0, "10.9.8.7", 40_000, _]}
    assert_receive {:jsr309_call, "EndpointStartRTPTimeout", [3, 4, 0, _]}
  end

  test "webrtc offer carries the full transport plane (mux, mid, candidates, rtcp-fb)" do
    %{server: server} = start_media_server()

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(), media: :audio_video, webrtc_support: :yes)

    assert {:ok, offer} = Mendooze.get_local_offer(conn)

    # ICE credentials pushed per media
    assert_receive {:jsr309_call, "EndpointSetLocalSTUNCredentials", [3, 4, 0, _, _]}
    assert_receive {:jsr309_call, "EndpointSetLocalSTUNCredentials", [3, 4, 1, _, _]}

    assert offer =~ "m=audio 22000 UDP/TLS/RTP/SAVPF"
    assert offer =~ "m=video 22002 UDP/TLS/RTP/SAVPF"
    assert offer =~ "a=setup:actpass"
    assert offer =~ "a=rtcp-mux"
    assert offer =~ "a=mid:audio"
    assert offer =~ "a=mid:video"
    assert offer =~ "a=candidate:1 1 udp 2130706431 192.168.5.5 22000 typ host"
    assert offer =~ "a=candidate:1 1 udp 2130706431 192.168.5.5 22002 typ host"

    # rtcp-fb only on the video PTs (H264 99, VP8 107 in the codec table)
    assert offer =~ "a=rtcp-fb:99 nack"
    assert offer =~ "a=rtcp-fb:107 goog-remb"

    # D7: no session-level a=ice-lite in offers (browser-shaped)
    refute offer =~ "a=ice-lite"
  end

  test "a gateway answer with setup:passive is forwarded and enables useNACK/tmmbr" do
    %{server: server} = start_media_server()

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(),
        media: :video,
        video_codec: "H264",
        webrtc_support: :yes
      )

    {:ok, _offer} = Mendooze.get_local_offer(conn)

    # gateway-shaped answer: ICE-lite, mirrored mux, setup:passive
    answer =
      Sdp.build(%{
        ip: "10.9.8.7",
        ice_lite: true,
        medias: [
          %{
            type: :video,
            port: 40_000,
            codecs: ["H264"],
            crypto: {:dtls, :passive, "sha-256", @fp},
            ice: %{ufrag: "gw-uf", pwd: "gw-pwd-1234567890123456789"},
            protocol: "UDP/TLS/RTP/SAVPF",
            rtcp_mux: true
          }
        ]
      })

    assert :ok = Mendooze.set_remote_answer(conn, answer)

    # remote setup:passive is forwarded verbatim; the server inverts it so our
    # endpoint runs the DTLS handshake as client (Q4, resolved server-side)
    assert_receive {:jsr309_call, "EndpointSetRemoteCryptoDTLS",
                    [3, 4, 1, "passive", "sha-256", @fp]}

    # AVPF answer → NACK/TMMBR hints merged into the single properties call (G6)
    assert_receive {:jsr309_call, "EndpointSetRTPProperties", [3, 4, 1, props]}
    assert props == %{"rtcp-mux" => "1", "useNACK" => "1", "tmmbr" => "1"}
  end

  test "add_remote_candidate feeds EndpointAddICECandidate" do
    %{server: server} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)

    candidate = "candidate:1 1 UDP 2130706431 192.168.1.5 54321 typ host"
    assert :ok = Mendooze.add_remote_candidate(conn, candidate)

    assert_receive {:jsr309_call, "EndpointAddICECandidate", [3, 4, 0, ^candidate]}
  end

  # ── UAS: offer in, answer out ───────────────────────────────────────────────

  test "set_remote_offer answers with negotiated codecs on our local port" do
    %{server: server, stream: stream} = start_media_server()

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(), audio_codec: ["PCMA", "PCMU"])

    assert_receive {:jsr309_call, "MediaSessionCreate", [sess_tag, _q]}

    offer =
      Sdp.build(%{
        ip: "10.9.8.7",
        medias: [%{type: :audio, port: 40_000, codecs: ["PCMU"], dtmf: true}]
      })

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, offer)

    # receive side opened with our full codec list, send side negotiated
    assert_receive {:jsr309_call, "EndpointStartReceiving", [3, 4, 0, _]}
    assert_receive {:jsr309_call, "EndpointStartSending", [3, 4, 0, "10.9.8.7", 40_000, send_map]}
    assert send_map == %{"0" => 0, "101" => 100}
    assert_receive {:jsr309_call, "EndpointStartRTPTimeout", [3, 4, 0, _]}

    # :ice_connected follows the first validated RTP packet, not the answer
    refute_receive {:ms_event, ^conn, :ice_connected}, 100
    send(stream, {:chunk, Jsr309FakeServer.event_frame([7, sess_tag, 4, 0, 0])})
    assert_receive {:ms_event, ^conn, :ice_connected}

    assert {:ok, [audio]} = Sdp.parse(answer)
    assert audio.port == 22_000
    assert audio.ip == "192.168.5.5"
    # only the codec common with the offer is advertised
    assert audio.codecs == ["PCMU"]
    assert audio.dtmf_pts != %{}
  end

  test "the answer only covers the medias present in the offer" do
    %{server: server} = start_media_server()

    # audio+video connection receiving an audio-only offer
    {:ok, conn} = Mendooze.create_peer_connection(server, self())

    offer =
      Sdp.build(%{
        ip: "10.9.8.7",
        medias: [%{type: :audio, port: 40_000, codecs: ["PCMU"]}]
      })

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, offer)
    assert {:ok, [%{type: :audio}]} = Sdp.parse(answer)
    refute answer =~ "m=video"
  end

  test "an offered media we don't carry is declined with a port-0 rejection (G9)" do
    %{server: server} = start_media_server()

    # audio-only connection receiving an audio+video offer
    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)

    offer =
      Sdp.build(%{
        ip: "10.9.8.7",
        medias: [
          %{type: :audio, port: 40_000, codecs: ["PCMU"]},
          %{type: :video, port: 40_002, codecs: ["H264"]}
        ]
      })

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, offer)

    # G9: RFC 3264 §6 — one answer m= per offered m=; the unconfigured video is
    # echoed with port 0 and the offered format list, keeping the m= line count.
    assert {:ok, [aud, vid]} = Sdp.parse(answer)
    assert aud.type == :audio and aud.port == 22_000
    assert vid.type == :video and vid.port == 0
    assert answer =~ "m=video 0 RTP/AVP 99"
  end

  test "an offered media with no common codec is declined with port 0, not a failure (G9)" do
    %{server: server} = start_media_server()

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(), media: :audio_video, video_codec: "H264")

    # video offers only VP8 — no common codec with our H264-only config
    offer =
      Sdp.build(%{
        ip: "10.9.8.7",
        medias: [
          %{type: :audio, port: 40_000, codecs: ["PCMU"]},
          %{type: :video, port: 40_002, codecs: ["VP8"]}
        ]
      })

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, offer)

    assert {:ok, [aud, vid]} = Sdp.parse(answer)
    assert aud.type == :audio and aud.port == 22_000
    assert vid.port == 0
    assert answer =~ "m=video 0 "
  end

  test "a DTLS offer is answered with DTLS when webrtc is allowed" do
    %{server: server} = start_media_server()

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(),
        media: :audio,
        audio_codec: "OPUS",
        webrtc_support: :if_offered
      )

    # browser-shaped offer: DTLS actpass, rtcp-mux, mid
    offer =
      Sdp.build(%{
        ip: "10.9.8.7",
        medias: [
          %{
            type: :audio,
            port: 40_000,
            codecs: ["OPUS"],
            crypto: {:dtls, :actpass, "sha-256", @fp},
            ice: %{ufrag: "remote-uf", pwd: "remote-pwd-123456789012345"},
            protocol: "UDP/TLS/RTP/SAVPF",
            rtcp_mux: true,
            mid: "0"
          }
        ]
      })

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, offer)

    assert_receive {:jsr309_call, "EndpointSetRemoteCryptoDTLS",
                    [3, 4, 0, "actpass", "sha-256", @fp]}

    assert {:ok, [audio]} = Sdp.parse(answer)
    # G3: the answer is setup:passive (mendooze is the DTLS server)
    assert {:dtls, :passive, "sha-256", @fp} = audio.crypto
    assert audio.ice != nil
    # G7: the offer's mid is echoed; ice-lite is advertised in answers (D7)
    assert audio.mid == "0"
    assert answer =~ "a=ice-lite"
    assert answer =~ ~r{a=candidate:\d+ 1 udp \d+ 192.168.5.5 22000 typ host}
  end

  test "a DTLS offer is rejected when webrtc is disabled" do
    %{server: server} = start_media_server()

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(),
        media: :audio,
        webrtc_support: :no
      )

    offer =
      Sdp.build(%{
        ip: "10.9.8.7",
        medias: [
          %{
            type: :audio,
            port: 40_000,
            codecs: ["PCMU"],
            crypto: {:dtls, :actpass, "sha-256", @fp}
          }
        ]
      })

    assert {:error, :webrtc_not_supported} = Mendooze.set_remote_offer(conn, offer)
    # the setup failure is also signalled asynchronously (scenario-capturable)
    assert_receive {:ms_event, ^conn, {:media_error, :webrtc_not_supported}}
  end

  # ── Delegated SDP negotiation (enriched EndpointStartReceiving) ──────────────

  # rpc_handler variant whose EndpointStartReceiving returns [port, fmtpStruct]
  defp delegating_handler(audio_fmtp, video_fmtp \\ nil) do
    fn
      "EndpointStartReceiving", [_, _, 0, _] -> {:ok, [22_000, audio_fmtp]}
      "EndpointStartReceiving", [_, _, 1, _] -> {:ok, [22_002, video_fmtp]}
      m, p -> rpc_handler(m, p)
    end
  end

  test "delegated offer emits the server fmtp verbatim and no fmtp for fmtp-less codecs" do
    %{server: server} =
      start_media_server(delegating_handler(%{"0" => "", "101" => "0-16"}))

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(), media: :audio, audio_codec: "PCMU")

    assert {:ok, offer} = Mendooze.get_local_offer(conn)

    # the receive map we proposed is unchanged
    assert_receive {:jsr309_call, "EndpointStartReceiving", [3, 4, 0, %{"0" => 0, "101" => 100}]}

    assert offer =~ "m=audio 22000 RTP/AVP 0 101"
    assert offer =~ "a=rtpmap:0 PCMU/8000"
    assert offer =~ "a=rtpmap:101 telephone-event/8000"
    # telephone-event fmtp comes from the server, verbatim
    assert offer =~ "a=fmtp:101 0-16"
    # PCMU is fmtp-less (empty value) → no a=fmtp:0 line
    refute offer =~ "a=fmtp:0 "

    assert {:ok, [%{type: :audio, codecs: ["PCMU"], dtmf_pts: %{8000 => 101}}]} = Sdp.parse(offer)
  end

  test "delegated H264 offer carries the server profile-level-id verbatim" do
    fmtp = "profile-level-id=42801f;packetization-mode=1"

    %{server: server} =
      start_media_server(delegating_handler(nil, %{"99" => fmtp}))

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(), media: :video, video_codec: "H264")

    assert {:ok, offer} = Mendooze.get_local_offer(conn)

    assert offer =~ "m=video 22002 RTP/AVP 99"
    assert offer =~ "a=rtpmap:99 H264/90000"
    # the exact server string survives a build → parse round-trip
    assert offer =~ "a=fmtp:99 #{fmtp}"
  end

  test "delegated answer honors offerer numbering and the server fmtp" do
    %{server: server} =
      start_media_server(delegating_handler(%{"0" => "", "8" => "", "101" => "0-16"}))

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(), audio_codec: ["PCMA", "PCMU"])

    offer =
      Sdp.build(%{
        ip: "10.9.8.7",
        medias: [%{type: :audio, port: 40_000, codecs: ["PCMU"], dtmf: true}]
      })

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, offer)

    # send side is the offerer numbering restricted to the accepted set
    assert_receive {:jsr309_call, "EndpointStartSending", [3, 4, 0, "10.9.8.7", 40_000, send_map]}
    assert send_map == %{"0" => 0, "101" => 100}

    assert {:ok, [audio]} = Sdp.parse(answer)
    assert audio.codecs == ["PCMU"]
    assert audio.dtmf_pts == %{8000 => 101}
    assert answer =~ "a=rtpmap:0 PCMU/8000"
    assert answer =~ "a=fmtp:101 0-16"
  end

  test "the send map drops codecs the server filtered on receive" do
    # the server accepts PCMU + telephone-event but filters PCMA (no "8" key)
    %{server: server} =
      start_media_server(delegating_handler(%{"0" => "", "101" => "0-16"}))

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(),
        media: :audio,
        audio_codec: ["PCMU", "PCMA"]
      )

    {:ok, _offer} = Mendooze.get_local_offer(conn)

    # the peer answers with both PCMU and PCMA
    answer =
      Sdp.build(%{
        ip: "10.9.8.7",
        medias: [%{type: :audio, port: 40_000, codecs: ["PCMU", "PCMA"], dtmf: true}]
      })

    assert :ok = Mendooze.set_remote_answer(conn, answer)

    assert_receive {:jsr309_call, "EndpointStartSending", [3, 4, 0, "10.9.8.7", 40_000, send_map]}
    # PCMA (pt 8) is dropped: the server never accepted it on receive
    assert send_map == %{"0" => 0, "101" => 100}
  end

  test "a one-element EndpointStartReceiving return falls back to the codec tables" do
    # delegating_handler is not used → shared handler returns [22_000] only
    %{server: server} = start_media_server()

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(), media: :audio, audio_codec: "PCMU")

    assert {:ok, offer} = Mendooze.get_local_offer(conn)

    # identical to the pre-delegation output (legacy client-side path)
    assert offer =~ "m=audio 22000 RTP/AVP 0 101"
    assert offer =~ "a=fmtp:101 0-16"
  end

  # ── Teardown and events ─────────────────────────────────────────────────────

  test "close_peer_connection tears down per media then deletes endpoint and session" do
    %{server: server} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)
    {:ok, _offer} = Mendooze.get_local_offer(conn)

    :ok =
      Mendooze.set_remote_answer(
        conn,
        remote_answer(audio: %{type: :audio, port: 40_000, codecs: ["PCMU", "PCMA"]})
      )

    assert :ok = Mendooze.close_peer_connection(conn)

    assert_receive {:jsr309_call, "EndpointStopSending", [3, 4, 0]}
    assert_receive {:jsr309_call, "EndpointStopReceiving", [3, 4, 0]}
    assert_receive {:jsr309_call, "EndpointDelete", [3, 4]}
    assert_receive {:jsr309_call, "MediaSessionDelete", [3]}
    assert_receive {:ms_event, ^conn, :closed}
    refute Process.alive?(conn)

    # idempotent
    assert :ok = Mendooze.close_peer_connection(conn)
  end

  test "an RTP timeout event surfaces as :media_timeout on the event sink" do
    %{server: server, stream: stream} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)

    # recover the session tag from the create call to build the event
    assert_receive {:jsr309_call, "MediaSessionCreate", [sess_tag, 7]}

    send(stream, {:chunk, Jsr309FakeServer.event_frame([6, sess_tag, 4, 0, 0])})

    assert_receive {:ms_event, ^conn, :media_timeout}, 1_000
  end

  test "an external FIR request triggers EndpointRequestUpdate" do
    %{server: server, stream: stream} = start_media_server()

    {:ok, _conn} = Mendooze.create_peer_connection(server, self())
    assert_receive {:jsr309_call, "MediaSessionCreate", [sess_tag, 7]}

    send(stream, {:chunk, Jsr309FakeServer.event_frame([2, sess_tag, 4, 1, 0])})

    assert_receive {:jsr309_call, "EndpointRequestUpdate", [3, 4, 1]}, 1_000
  end
end
