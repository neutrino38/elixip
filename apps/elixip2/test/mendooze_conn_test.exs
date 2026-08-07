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
  # both arities: legacy [sess, ep, media, rtpMap] and P8a [... , offer]
  defp rpc_handler("EndpointStartReceiving", [_, _, 0 | _]), do: {:ok, [22_000]}
  defp rpc_handler("EndpointStartReceiving", [_, _, 1 | _]), do: {:ok, [22_002]}
  defp rpc_handler("EndpointStartReceiving", [_, _, 2 | _]), do: {:ok, [22_004]}

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

  test "a gateway answer with setup:passive enables exactly the agreed feedback switches" do
    %{server: server} = start_media_server()

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(),
        media: :video,
        video_codec: "H264",
        webrtc_support: :yes
      )

    {:ok, _offer} = Mendooze.get_local_offer(conn)

    # gateway-shaped answer: ICE-lite, mirrored mux, setup:passive, and the
    # feedback types the gateway agreed to (a=rtcp-fb per PT)
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
            rtcp_mux: true,
            rtcp_fb: ["nack", "ccm tmmbr"]
          }
        ]
      })

    assert :ok = Mendooze.set_remote_answer(conn, answer)

    # remote setup:passive is a committed role and is forwarded as-is
    assert_receive {:jsr309_call, "EndpointSetRemoteCryptoDTLS",
                    [3, 4, 1, "passive", "sha-256", @fp]}

    # the switches behind the feedback types the answer agreed — and none other
    # (no useRtcpFIR: the answer never stated `ccm fir`)
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

    # the offered fmtp (telephone-event range) rides in the offer struct (P8a)
    assert_receive {:jsr309_call, "EndpointStartReceiving",
                    [3, 4, 0, _, %{"fmtp" => %{"101" => "0-16"}}]}

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

  # ── Symmetric-NAT latching (natLatch) ───────────────────────────────────────

  test "answering an offer asks the server to latch onto a symmetric NAT" do
    %{server: server} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)

    offer =
      Sdp.build(%{
        ip: "10.9.8.7",
        medias: [%{type: :audio, port: 40_000, codecs: ["PCMU"]}]
      })

    assert {:ok, _answer} = Mendooze.set_remote_offer(conn, offer)

    # plain RTP/AVP without mux: natLatch is the only property, so the call exists
    # solely because we are the answerer
    assert_receive {:jsr309_call, "EndpointSetRTPProperties", [3, 4, 0, props]}
    assert props == %{"natLatch" => "1"}
  end

  test "the answer to an offer of ours never asks for latching" do
    %{server: server} = start_media_server()

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(), media: :audio, audio_codec: "PCMU")

    {:ok, _offer} = Mendooze.get_local_offer(conn)
    assert :ok = Mendooze.set_remote_answer(conn, remote_answer())

    # the peer answered knowing its own NAT: its address is the one to trust
    assert_receive {:jsr309_call, "EndpointStartSending", [3, 4, 0, "10.9.8.7", 40_000, _]}
    refute_receive {:jsr309_call, "EndpointSetRTPProperties", _}, 100
  end

  test "nat_latch overrides the direction it is inferred from, either way" do
    %{server: server} = start_media_server()

    # forced on for a leg that offered
    {:ok, uac} =
      Mendooze.create_peer_connection(server, self(),
        media: :audio,
        audio_codec: "PCMU",
        nat_latch: true
      )

    {:ok, _offer} = Mendooze.get_local_offer(uac)
    assert :ok = Mendooze.set_remote_answer(uac, remote_answer())
    assert_receive {:jsr309_call, "EndpointSetRTPProperties", [3, 4, 0, %{"natLatch" => "1"}]}

    # forced off for a leg that answers
    {:ok, uas} = Mendooze.create_peer_connection(server, self(), media: :audio, nat_latch: false)

    offer =
      Sdp.build(%{
        ip: "10.9.8.7",
        medias: [%{type: :audio, port: 40_000, codecs: ["PCMU"]}]
      })

    assert {:ok, _answer} = Mendooze.set_remote_offer(uas, offer)
    refute_receive {:jsr309_call, "EndpointSetRTPProperties", _}, 100
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

  test "an offered media with no codec we can name is declined with port 0, not a failure (G9)" do
    %{server: server} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio_video)

    # the video section offers only a codec outside the vocabulary: nothing is
    # nameable to the server, so the media is declined — the configured codec
    # list no longer arbitrates an answer (delegated negotiation)
    offer =
      Sdp.build(%{
        ip: "10.9.8.7",
        medias: [
          %{type: :audio, port: 40_000, codecs: ["PCMU"]},
          %{
            type: :video,
            port: 40_002,
            rtpmaps: [%{pt: 96, encoding: "H263-1998", clock: 90_000}],
            fmtp: %{}
          }
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

    # the peer's RESOLVED role, never the literal actpass: we answer passive,
    # so the offerer becomes the DTLS client
    assert_receive {:jsr309_call, "EndpointSetRemoteCryptoDTLS",
                    [3, 4, 0, "active", "sha-256", @fp]}

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
      "EndpointStartReceiving", [_, _, 0 | _] -> {:ok, [22_000, audio_fmtp]}
      "EndpointStartReceiving", [_, _, 1 | _] -> {:ok, [22_002, video_fmtp]}
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

  # ── UAS delegated negotiation (the offer is the menu) ───────────────────────

  test "the offer is the menu: its own payload types are proposed and answered in its order" do
    # verdict accepts everything proposed; OPUS carries a server fmtp
    %{server: server} =
      start_media_server(
        delegating_handler(%{
          "111" => "minptime=10;useinbandfec=1",
          "0" => "",
          "110" => "0-16",
          "126" => "0-16"
        })
      )

    # audio_codec config no longer arbitrates the answer: the offer decides
    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(), media: :audio, audio_codec: "PCMU")

    # Chrome-shaped audio: OPUS first, one telephone-event PT per clock
    offer =
      Sdp.build(%{
        ip: "10.9.8.7",
        medias: [
          %{
            type: :audio,
            port: 40_000,
            rtpmaps: [
              %{pt: 111, encoding: "opus", clock: 48_000, channels: 2},
              %{pt: 0, encoding: "PCMU", clock: 8_000},
              %{pt: 110, encoding: "telephone-event", clock: 48_000},
              %{pt: 126, encoding: "telephone-event", clock: 8_000}
            ],
            fmtp: %{}
          }
        ]
      })

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, offer)

    # the receive map proposed to the server is the OFFER's numbering, complete
    assert_receive {:jsr309_call, "EndpointStartReceiving", [3, 4, 0, rtp_map]}
    assert rtp_map == %{"111" => 98, "0" => 0, "110" => 100, "126" => 100}

    # the answer's format order is the caller's own preference, not ascending PT
    assert answer =~ "m=audio 22000 RTP/AVP 111 0 110 126"
    assert answer =~ "a=rtpmap:111 opus/48000/2"
    # each telephone-event PT keeps the clock the OFFER gave it
    assert answer =~ "a=rtpmap:110 telephone-event/48000"
    assert answer =~ "a=rtpmap:126 telephone-event/8000"
    # server fmtp copied out verbatim; fmtp-less PCMU gets no a=fmtp line
    assert answer =~ "a=fmtp:111 minptime=10;useinbandfec=1"
    refute answer =~ "a=fmtp:0 "

    # audio sends on the whole accepted set (telephone-event rides alongside)
    assert_receive {:jsr309_call, "EndpointStartSending", [3, 4, 0, "10.9.8.7", 40_000, send_map]}
    assert send_map == %{"111" => 98, "0" => 0, "110" => 100, "126" => 100}
  end

  test "an empty verdict declines the media with port 0 and closes its receive plane" do
    %{server: server} = start_media_server(delegating_handler(%{"0" => ""}, %{}))

    {:ok, conn} = Mendooze.create_peer_connection(server, self())

    offer =
      Sdp.build(%{
        ip: "10.9.8.7",
        medias: [
          %{type: :audio, port: 40_000, codecs: ["PCMU"]},
          %{type: :video, port: 40_002, codecs: ["H264"]}
        ]
      })

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, offer)

    # the port the server held for the declined media is released
    assert_receive {:jsr309_call, "EndpointStopReceiving", [3, 4, 1]}

    assert {:ok, [aud, vid]} = Sdp.parse(answer)
    assert aud.type == :audio and aud.port == 22_000
    assert vid.port == 0
  end

  test "a verdict entry contradicting the offered H.264 identity is dropped (RFC 6184 §8.2.2)" do
    # the server answers BOTH payload types with the second one's profile
    bad = "profile-level-id=64001f;packetization-mode=1"

    %{server: server} =
      start_media_server(delegating_handler(nil, %{"97" => bad, "99" => bad}))

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :video)

    offer =
      Sdp.build(%{
        ip: "10.9.8.7",
        medias: [
          %{
            type: :video,
            port: 40_002,
            rtpmaps: [
              %{pt: 97, encoding: "H264", clock: 90_000},
              %{pt: 99, encoding: "H264", clock: 90_000}
            ],
            fmtp: %{
              "97" => "profile-level-id=42e01f;packetization-mode=1",
              "99" => "profile-level-id=64001f;packetization-mode=1"
            }
          }
        ]
      })

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, offer)

    # each offered profile rides per PT in the offer struct (P8a)
    assert_receive {:jsr309_call, "EndpointStartReceiving", [3, 4, 1, _, %{"fmtp" => sent}]}
    assert sent["97"] =~ "42e01f"
    assert sent["99"] =~ "64001f"

    # pt 97 (baseline offered, high answered) cannot be stated; pt 99 matches
    assert answer =~ "m=video 22002 RTP/AVP 99"
    refute answer =~ "a=rtpmap:97"
    assert answer =~ "a=fmtp:99 #{bad}"

    # video sends on exactly one payload type, the primary of the accepted set
    assert_receive {:jsr309_call, "EndpointStartSending", [3, 4, 1, "10.9.8.7", 40_002, send_map]}
    assert send_map == %{"99" => 99}
  end

  test "the offered fmtp is relayed as codec properties before EndpointStartReceiving" do
    %{server: server} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :video)

    fmtp = "profile-level-id=42e01f;packetization-mode=1"

    offer =
      Sdp.build(%{
        ip: "10.9.8.7",
        medias: [
          %{
            type: :video,
            port: 40_002,
            rtpmaps: [%{pt: 99, encoding: "H264", clock: 90_000}],
            fmtp: %{"99" => fmtp}
          }
        ]
      })

    assert {:ok, _answer} = Mendooze.set_remote_offer(conn, offer)

    # the per-codec channel: codec.<name>.fmtp, the raw string — kept alongside
    # the offer struct for servers that predate the offer parameter
    assert_receive {:jsr309_call, "EndpointSetRTPProperties",
                    [3, 4, 1, %{"codec.h264.fmtp" => ^fmtp}]}
  end

  test "a server predating the offer parameter gets one legacy retry" do
    handler = fn
      # the 5-param form faults (pre-P8a server); the legacy form succeeds
      "EndpointStartReceiving", [_, _, 0, _, _] -> {:error, "parse error"}
      "EndpointStartReceiving", [_, _, 0, _] -> {:ok, [22_000]}
      m, p -> rpc_handler(m, p)
    end

    %{server: server} = start_media_server(handler)

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)

    offer =
      Sdp.build(%{
        ip: "10.9.8.7",
        medias: [%{type: :audio, port: 40_000, codecs: ["PCMU"], dtmf: true}]
      })

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, offer)

    # tried with the offer struct first, then downgraded to the 4-param form
    assert_receive {:jsr309_call, "EndpointStartReceiving", [3, 4, 0, _, %{"fmtp" => _}]}
    assert_receive {:jsr309_call, "EndpointStartReceiving", [3, 4, 0, _]}
    assert answer =~ "m=audio 22000"
  end

  # ── UAS answer-side security (SDES) ─────────────────────────────────────────

  test "one offered SDES line is selected, its tag echoed, and both keys pushed" do
    %{server: server} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)

    peer_key = "UGVlcktleVBlZXJLZXlQZWVyS2V5UGVlcktleVBlZXI="

    # Linphone-shaped: the preferred suite (GCM) is one we do not implement
    offer = """
    v=0
    o=- 1 1 IN IP4 10.9.8.7
    s=call
    c=IN IP4 10.9.8.7
    t=0 0
    m=audio 40000 RTP/SAVP 0
    a=rtpmap:0 PCMU/8000
    a=crypto:1 AEAD_AES_128_GCM inline:Z2NtZ2NtZ2NtZ2NtZ2NtZ2NtZ2NtZ2NtZ2NtZ2NtZ2Nt
    a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:#{peer_key}
    """

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, offer)

    # our key is generated for the SELECTED suite and pushed before receiving
    assert_receive {:jsr309_call, "EndpointSetLocalCryptoSDES",
                    [3, 4, 0, "AES_CM_128_HMAC_SHA1_80", local_key]}

    assert {:ok, raw} = Base.decode64(local_key)
    assert byte_size(raw) == 30

    # the peer key handed to the server is the SELECTED line's, not the first's
    assert_receive {:jsr309_call, "EndpointSetRemoteCryptoSDES",
                    [3, 4, 0, "AES_CM_128_HMAC_SHA1_80", ^peer_key]}

    # the answer mirrors the transport and echoes the accepted line's TAG
    assert answer =~ "m=audio 22000 RTP/SAVP 0"
    assert answer =~ "a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:#{local_key}"

    assert {:ok, [audio]} = Sdp.parse(answer)
    assert {:sdes, "AES_CM_128_HMAC_SHA1_80", ^local_key} = audio.crypto
  end

  test "an offer with no SDES suite we support is refused, not half-keyed" do
    %{server: server} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)

    offer = """
    v=0
    o=- 1 1 IN IP4 10.9.8.7
    s=call
    c=IN IP4 10.9.8.7
    t=0 0
    m=audio 40000 RTP/SAVP 0
    a=rtpmap:0 PCMU/8000
    a=crypto:1 AEAD_AES_128_GCM inline:Z2NtZ2NtZ2NtZ2NtZ2NtZ2NtZ2NtZ2NtZ2NtZ2NtZ2Nt
    """

    assert {:error, :no_common_sdes_suite} = Mendooze.set_remote_offer(conn, offer)
    assert_receive {:ms_event, ^conn, {:media_error, :no_common_sdes_suite}}
  end

  # ── RFC 5939 capability negotiation and rtcp-fb intersection ────────────────

  test "an offered AVPF potential configuration is accepted and answered with real feedback" do
    %{server: server} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :video)

    offer = """
    v=0
    o=- 1 1 IN IP4 10.9.8.7
    s=call
    c=IN IP4 10.9.8.7
    t=0 0
    m=video 40002 RTP/AVP 99
    a=rtpmap:99 H264/90000
    a=tcap:1 RTP/AVPF
    a=pcfg:1 t=1
    a=rtcp-fb:* nack
    a=rtcp-fb:* ccm fir
    a=rtcp-fb:* goog-remb
    """

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, offer)

    # the m= line carries the upgraded profile AND names the taken configuration
    assert answer =~ "m=video 22002 RTP/AVPF 99"
    assert answer =~ "a=acfg:1 t=1"
    # the intersection of asked-for and implemented, per explicit PT
    assert answer =~ "a=rtcp-fb:99 nack"
    assert answer =~ "a=rtcp-fb:99 ccm fir"
    # goog-remb has no server switch and is deliberately not answered
    refute answer =~ "goog-remb"

    # exactly the switches behind the answered feedback types
    assert_receive {:jsr309_call, "EndpointSetRTPProperties", [3, 4, 1, props]}
    assert props == %{"useNACK" => "1", "useRtcpFIR" => "1", "natLatch" => "1"}
  end

  # ── Answer shape: WS text omission, mid, ICE tokens, watchdog ───────────────

  test "a text section offered over WebSocket is omitted from the answer, not declined" do
    %{server: server} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)

    offer = """
    v=0
    o=- 1 1 IN IP4 10.9.8.7
    s=call
    c=IN IP4 10.9.8.7
    t=0 0
    m=audio 40000 RTP/AVP 0
    a=rtpmap:0 PCMU/8000
    m=text 9 TCP/WSS t140
    """

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, offer)

    # one answer section, not two: no m=text echo of any kind
    refute answer =~ "m=text"
    assert {:ok, [%{type: :audio}]} = Sdp.parse(answer)
  end

  test "the offer's a=mid is echoed on a plain-RTP answer too" do
    %{server: server} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)

    offer =
      Sdp.build(%{
        ip: "10.9.8.7",
        medias: [%{type: :audio, port: 40_000, codecs: ["PCMU"], mid: "0"}]
      })

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, offer)
    assert answer =~ "a=mid:0"
  end

  test "ICE credentials are emitted in the ice-char alphabet (hex)" do
    %{server: server} = start_media_server()

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(),
        media: :audio,
        audio_codec: "OPUS",
        webrtc_support: :if_offered
      )

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
            rtcp_mux: true
          }
        ]
      })

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, offer)

    assert {:ok, [audio]} = Sdp.parse(answer)
    # base64url would leak `-`/`_`, outside RFC 8839's ice-char grammar
    assert audio.ice.ufrag =~ ~r/^[0-9a-f]{16}$/
    assert audio.ice.pwd =~ ~r/^[0-9a-f]{48}$/
  end

  test "the RTP watchdog follows the offer's directions, and text is never armed" do
    %{server: server} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :tc)

    offer =
      Sdp.build(%{
        ip: "10.9.8.7",
        medias: [
          %{type: :audio, port: 40_000, codecs: ["PCMU"]},
          # the peer declares it will not send video: watching it would reap a
          # working call at the first hold
          %{type: :video, port: 40_002, codecs: ["H264"], direction: :recvonly},
          %{type: :text, port: 40_004, codecs: ["T140"]}
        ]
      })

    assert {:ok, _answer} = Mendooze.set_remote_offer(conn, offer)

    # audio: armed; video: explicitly disarmed; text: never armed at all
    assert_receive {:jsr309_call, "EndpointStartRTPTimeout", [3, 4, 0, audio_ms]}
    assert audio_ms > 0
    assert_receive {:jsr309_call, "EndpointStartRTPTimeout", [3, 4, 1, 0]}
    refute_received {:jsr309_call, "EndpointStartRTPTimeout", [3, 4, 2, _]}
  end

  # ── Text over WebSocket (jsr309_text_over_wss.md) ───────────────────────────

  # The section the Elioz/WebRTComm client injects into its own SDP after
  # setLocalDescription: TCP/WS, port 60000, c= 127.0.0.1, a=setup:active.
  @elioz_offer """
  v=0
  o=- 3 1 IN IP4 10.9.8.7
  s=-
  c=IN IP4 10.9.8.7
  t=0 0
  m=audio 40000 RTP/AVP 0
  a=rtpmap:0 PCMU/8000
  m=text 60000 TCP/WS t140
  c=IN IP4 127.0.0.1
  a=setup:active
  a=connection:new
  a=sendrecv
  """

  defp ws_handler() do
    fn
      "GetMediaCandidates", [_, _, 2, 2] -> {:ok, ["ws://192.168.5.5:9090"]}
      "EndpointStartReceiving", [_, _, 2, _] -> {:ok, [9090]}
      m, p -> rpc_handler(m, p)
    end
  end

  test "a text-over-WebSocket offer is configured and answered with its URL" do
    %{server: server} = start_media_server(ws_handler())

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: [:audio, :text])

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, @elioz_offer)

    # the port is switched to a WebSocket one BEFORE the receive plane opens:
    # the token has to exist before a browser can use it
    assert_receive {:jsr309_call, "ConfigureMediaConnection", [3, 4, 2, 0, 2, token, "t140"]}

    assert token =~ ~r/^[0-9a-f-]{36}$/

    assert_receive {:jsr309_call, "GetMediaCandidates", [3, 4, 2, 2]}

    # T.140 AND its RFC 4103 redundancy: the rtpMap is what switches RED on
    # server-side, and redundancy is what the RTP leg facing us needs
    assert_receive {:jsr309_call, "EndpointStartReceiving", [3, 4, 2, rtp_map]}
    assert rtp_map == %{"106" => 106, "105" => 105}

    # a WebSocket leg has no remote RTP side: nothing to send to, nothing to key,
    # nothing for the watchdog to watch
    refute_received {:jsr309_call, "EndpointStartSending", [3, 4, 2, _, _, _]}
    refute_received {:jsr309_call, "EndpointStartRTPTimeout", [3, 4, 2, _]}

    # the answer mirrors the offered transport, states the literal t140, and
    # publishes the URL the way the historical gateway did: protocol-relative
    # value, scheme in the attribute name — so the line reads a=ws://…
    assert answer =~ "m=text 9090 TCP/WS t140"
    assert answer =~ "a=setup:passive"
    assert answer =~ "a=connection:new"
    assert answer =~ "a=ws://192.168.5.5:9090/jsr309/3/#{token}"
    # no payload types and no fmtp on a WebSocket section
    refute answer =~ "a=rtpmap:106"

    # and the audio leg is unaffected
    assert answer =~ "m=audio 22000 RTP/AVP 0"
  end

  test "a secure media server carries the scheme in the attribute name (a=wss)" do
    handler = fn
      "GetMediaCandidates", [_, _, 2, 2] -> {:ok, ["wss://192.168.5.5:9090"]}
      m, p -> ws_handler().(m, p)
    end

    %{server: server} = start_media_server(handler)
    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :text)

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, @elioz_offer)

    # TLS moves the scheme to the attribute NAME, the value stays relative —
    # exactly what the gateway emitted (WebSocketLeg.java:123-142)
    assert answer =~ "a=wss://192.168.5.5:9090/jsr309/3/"
    # and the port is NOT incremented: the server listens on one port and
    # switches TLS in place, so the gateway's historical +1 would point nowhere
    assert answer =~ "m=text 9090 TCP/WS t140"
  end

  test "a peer committed to setup:passive is declined, not answered" do
    %{server: server} = start_media_server(ws_handler())
    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: [:audio, :text])

    # nobody would connect: we are the WebSocket server
    offer = String.replace(@elioz_offer, "a=setup:active", "a=setup:passive")

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, offer)

    refute_received {:jsr309_call, "ConfigureMediaConnection", _}
    # omitted rather than echoed with port 0 (the client cannot digest that)
    refute answer =~ "m=text"
    assert answer =~ "m=audio 22000"
  end

  test "a media server that cannot host the WebSocket loses the text, not the call" do
    handler = fn
      "ConfigureMediaConnection", _ -> {:error, "not supported"}
      m, p -> ws_handler().(m, p)
    end

    %{server: server} = start_media_server(handler)
    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: [:audio, :text])

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, @elioz_offer)
    refute answer =~ "m=text"
    assert answer =~ "m=audio 22000"
  end
end
