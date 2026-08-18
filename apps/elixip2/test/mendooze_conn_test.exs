Code.require_file("support/jsr309_fake_server.exs", __DIR__)

defmodule Mendooze.ConnTest do
  # app env tweaks are global — keep this file synchronous
  # async: every test builds its own fake JSR309 server and its own Mendooze
  # GenServers; nothing here is named or shared, and no application env is touched
  # (the poller tuning that keeps mendooze_server_test synchronous is set there).
  use ExUnit.Case, async: true

  alias MediaServer.Mendooze
  alias MediaServer.Mendooze.Sdp

  @fp "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01"

  # Medooze codec codes (Sdp's own tables), for asserting what a transcoder was
  # told to PRODUCE — the one place the cross-leg selection becomes observable.
  @opus 98
  @pcmu 0

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
    # force: a Conn is not linked to the server process, so stopping the server
    # alone leaves every peer connection of the test running — retrying RPCs
    # against a fake server that is gone, and holding httpc sessions the whole
    # run shares. That is enough to make unrelated timing-sensitive suites fail.
    on_exit(fn -> if Process.alive?(server), do: Mendooze.disconnect(server, force: true) end)

    assert_receive {:jsr309_call, "EventQueueCreate", []}, 1_000
    assert_receive {:stream_conn, stream, _}, 1_000
    Jsr309FakeServer.await_streaming(server, stream)
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

  # ── Two endpoints in one session (P3 R3b/R3c) ───────────────────────────────

  # The stock handler gives every endpoint id 4, which cannot express a session
  # holding two of them. Endpoint tags are distinct by construction, so they are
  # what the ids key off here.
  defp two_leg_handler("EndpointCreate", [_sess, tag | _]) do
    if String.ends_with?(tag, "-outbound"), do: {:ok, [5]}, else: {:ok, [4]}
  end

  # Transcoders are session resources with ids of their own; 30/31 keeps them
  # clearly apart from the endpoints (4/5) in the assertions below.
  defp two_leg_handler("AudioTranscoderCreate", [_sess, tag]),
    do: {:ok, [if(String.contains?(tag, "outbound"), do: 31, else: 30)]}

  defp two_leg_handler("VideoTranscoderCreate", [_sess, tag]),
    do: {:ok, [if(String.contains?(tag, "outbound"), do: 31, else: 30)]}

  defp two_leg_handler(method, params), do: rpc_handler(method, params)

  # Both legs negotiated on PCMU, which is what lets them be attached directly.
  defp two_negotiated_legs(server) do
    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)
    assert_receive {:jsr309_call, "MediaSessionCreate", [sess_tag, _q]}, 1_000

    {:ok, out} =
      Mendooze.create_peer_connection(server, self(),
        media: :audio,
        audio_codec: "PCMU",
        bridge_with: conn
      )

    # inbound answers an offer, outbound offers and reads an answer: the two
    # directions a B2BUA actually uses.
    {:ok, _answer} = Mendooze.set_remote_offer(conn, remote_answer())
    {:ok, _offer} = Mendooze.get_local_offer(out)
    :ok = Mendooze.set_remote_answer(out, remote_answer(ip: "10.9.8.6"))

    {conn, out, sess_tag}
  end

  test "a second leg is an endpoint of the SAME session, not a second session" do
    %{server: server} = start_media_server(&two_leg_handler/2)

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)
    assert_receive {:jsr309_call, "MediaSessionCreate", [sess_tag, _q]}, 1_000
    assert_receive {:jsr309_call, "EndpointCreate", [3, ^sess_tag, true, false, false]}, 1_000

    {:ok, out} =
      Mendooze.create_peer_connection(server, self(),
        media: :audio_video,
        bridge_with: conn
      )

    # Named, and sharing the process that owns the session — that is what
    # `MediaServer.conn_ref/0` is for.
    assert out == {conn, :outbound}

    # A second Endpoint in session 3, with ITS media selection…
    out_tag = "#{sess_tag}-outbound"
    assert_receive {:jsr309_call, "EndpointCreate", [3, ^out_tag, true, true, false]}, 1_000

    # …and no second MediaSession: EndpointAttachToEndpoint takes one session id,
    # so a second session would make the two legs unbridgeable.
    refute_receive {:jsr309_call, "MediaSessionCreate", _}, 200
  end

  test "a leg cannot be added twice" do
    %{server: server} = start_media_server(&two_leg_handler/2)
    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)
    {:ok, _out} = Mendooze.create_peer_connection(server, self(), bridge_with: conn)

    assert {:error, {:leg_exists, :outbound}} =
             Mendooze.create_peer_connection(server, self(), bridge_with: conn)
  end

  # `:forbid` is now the only policy that wires a plain Endpoint <-> Endpoint: it
  # is the one that says the media may never be transcoded, so nothing else can
  # ever produce a packet on that path — which is what makes preserving the
  # peer's own numbering safe.
  test "forbid attaches both directions and keeps the original sequence numbers" do
    %{server: server} = start_media_server(&two_leg_handler/2)
    {conn, out, _tag} = two_negotiated_legs(server)

    assert {:ok, %{inbound_answer: _}} =
             Mendooze.bridge(conn, out, audio: :forbid, video: :forbid)

    # Both directions — a bridge is two one-way attaches, not one call.
    assert_receive {:jsr309_call, "EndpointAttachToEndpoint", [3, 4, 5, 0]}, 1_000
    assert_receive {:jsr309_call, "EndpointAttachToEndpoint", [3, 5, 4, 0]}, 1_000

    # …and the rule that goes with relaying rather than transcoding: without it
    # the server restamps the stream and the far end sees a discontinuity.
    assert_receive {:jsr309_call, "EndpointSetRTPProperties",
                    [3, 4, 0, %{"useOriSeqNum" => "1"}]},
                   1_000

    assert_receive {:jsr309_call, "EndpointSetRTPProperties",
                    [3, 5, 0, %{"useOriSeqNum" => "1"}]},
                   1_000
  end

  # Two legs that did NOT settle on the same codec. What happens then is the
  # policy's to say, and each answer is different.
  test "legs that settled on different codecs follow the policy, in its own words" do
    %{server: server} = start_media_server(&two_leg_handler/2)

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)
    assert_receive {:jsr309_call, "MediaSessionCreate", [_tag, _q]}, 1_000

    {:ok, out} =
      Mendooze.create_peer_connection(server, self(),
        media: :audio,
        audio_codec: ["PCMA"],
        bridge_with: conn
      )

    {:ok, _answer} = Mendooze.set_remote_offer(conn, remote_answer())
    {:ok, _offer} = Mendooze.get_local_offer(out)

    pcma = %{type: :audio, port: 40_000, codecs: ["PCMA"], dtmf: false}
    :ok = Mendooze.set_remote_answer(out, remote_answer(audio: pcma))

    # :forbid says what it means — the call fails rather than being transcoded.
    assert {:error, {:no_common_codec, :audio}} = Mendooze.bridge(conn, out, audio: :forbid)
    refute_receive {:jsr309_call, "AudioTranscoderCreate", _}, 200

    # :avoid wanted a common codec, there is none, so it transcodes: one chain
    # per direction, each encoding for the leg it FEEDS.
    assert :ok = Mendooze.bridge(conn, out, audio: :avoid)

    assert_receive {:jsr309_call, "AudioTranscoderCreate", [3, _tag_a]}, 1_000
    # sink ← transcoder, then transcoder ← source: endpoint 4 is fed by 30,
    # which draws from endpoint 5.
    assert_receive {:jsr309_call, "EndpointAttachToAudioTranscoder", [3, 4, 30]}, 1_000
    assert_receive {:jsr309_call, "AudioTranscoderAttachToEndpoint", [3, 30, 5]}, 1_000
    # …and the mirror chain.
    assert_receive {:jsr309_call, "EndpointAttachToAudioTranscoder", [3, 5, 31]}, 1_000
    assert_receive {:jsr309_call, "AudioTranscoderAttachToEndpoint", [3, 31, 4]}, 1_000

    # Nothing was attached endpoint-to-endpoint: that is the point of a
    # transcoder standing between them.
    refute_receive {:jsr309_call, "EndpointAttachToEndpoint", _}, 200
  end

  # :force transcodes even when the codecs AGREE — which is what it buys: each
  # leg is served the codec it asked for, whatever the other settled on.
  # Two legs whose lists OVERLAP but whose first choices differ — the one fixture
  # that tells `:avoid` and `:force` apart, since every other pair here agrees or
  # disagrees on everything at once.
  #
  #     L  = [opus, PCMU]   the caller prefers opus
  #     L' = [PCMU, opus]   the callee prefers PCMU
  defp two_crossed_legs(server) do
    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)
    assert_receive {:jsr309_call, "MediaSessionCreate", [_tag, _q]}, 1_000

    {:ok, out} =
      Mendooze.create_peer_connection(server, self(),
        media: :audio,
        audio_codec: ["PCMU", "OPUS"],
        bridge_with: conn
      )

    assert {:ok, _answer} =
             Mendooze.set_remote_offer(conn, crossed_sdp("10.9.8.7", "96 0", "96"))

    {:ok, _offer} = Mendooze.get_local_offer(out)
    :ok = Mendooze.set_remote_answer(out, crossed_sdp("10.9.8.6", "0 98", "98"))

    {conn, out}
  end

  defp crossed_sdp(ip, fmt, opus_pt) do
    Enum.join(
      [
        "v=0",
        "o=- 1 1 IN IP4 #{ip}",
        "s=-",
        "c=IN IP4 #{ip}",
        "t=0 0",
        "m=audio 40000 RTP/AVP #{fmt}",
        "a=rtpmap:#{opus_pt} opus/48000/2",
        ""
      ],
      "\r\n"
    )
  end

  # `:avoid` walks L and takes the first codec L' also carries: opus, though the
  # callee would have preferred PCMU. ONE selection for both legs, so a straight
  # relay — and the caller's preference is the one that decides.
  test ":avoid walks the caller's order to a codec both legs carry" do
    %{server: server} = start_media_server(&verdict_handler/2)
    {conn, out} = two_crossed_legs(server)

    assert {:ok, %{inbound_answer: rebuilt}} = Mendooze.bridge(conn, out, audio: :avoid)

    # opus is the first codec of L that L' also carries, though the callee ranked
    # PCMU first. ONE selection, so BOTH chains encode it — and the transcoder they
    # sit in will bridge rather than convert for as long as that holds.
    assert_receive {:jsr309_call, "AudioTranscoderSetCodec", [3, _tr_a, @opus, %{}]}, 1_000
    assert_receive {:jsr309_call, "AudioTranscoderSetCodec", [3, _tr_b, @opus, %{}]}, 1_000

    # `:avoid` is expressed in the ANSWER too: nothing is removed — a transcoder
    # can convert anything the caller offered — but the codecs both legs carry come
    # first, so the caller's natural pick is the one that needs no conversion.
    assert rebuilt =~ "opus/48000/2"
    assert rebuilt =~ "PCMU/8000"

    # the caller numbered opus 96 and PCMU 0; the format list must now lead with 96
    assert [_, fmt] = Regex.run(~r{m=audio \d+ RTP/AVP ([\d ]+)}, rebuilt)
    assert ["96" | _] = String.split(fmt, " ", trim: true)
  end

  # ── Renegotiation: an offer and an answer are shaped by the OTHER leg ────────
  #
  # Traffic of 2026-08-13, the call this whole section exists for. Alice offers
  # VP8 alone; Bob answers AV1+VP8 and the first bridge relays VP8. Bob then
  # re-INVITEs (camera on) offering `110 107` — and both descriptions we produced
  # in reply put AV1 first, because neither had ever been told what the other leg
  # carries: the offer relayed to Alice, and above all the ANSWER to Bob, sent
  # 28 ms AFTER Alice had answered VP8-only. Bob duly sent AV1, and the media
  # server spent the call decoding AV1 and re-encoding VP8 for two peers that
  # both spoke VP8.

  @vp8 107
  @av1 110

  # Alice: VP8 and nothing else, on HER numbering (96, as Linphone numbers it).
  defp vp8_only_offer(port \\ 57_573) do
    Enum.join(
      [
        "v=0",
        "o=- 1 1 IN IP4 172.22.0.4",
        "s=Talk",
        "c=IN IP4 172.22.0.4",
        "t=0 0",
        "m=video #{port} RTP/AVP 96",
        "a=rtpmap:96 VP8/90000",
        ""
      ],
      "\r\n"
    )
  end

  # Bob, in OUR numbering — he is answering (or re-offering against) our offer.
  defp bob_video(fmt) do
    rtpmaps =
      fmt
      |> String.split(" ", trim: true)
      |> Enum.map(fn
        "110" -> "a=rtpmap:110 AV1/90000"
        "107" -> "a=rtpmap:107 VP8/90000"
        "99" -> "a=rtpmap:99 H264/90000"
      end)

    Enum.join(
      ["v=0", "o=- 1 1 IN IP4 172.22.0.2", "s=-", "c=IN IP4 172.22.0.2", "t=0 0"] ++
        ["m=video 52052 RTP/AVP #{fmt}"] ++ rtpmaps ++ [""],
      "\r\n"
    )
  end

  defp video_fmt(sdp) do
    assert [_, fmt] = Regex.run(~r{m=video \d+ RTP/AVP ([\d ]+)}, sdp)
    String.split(fmt, " ", trim: true)
  end

  defp alice_and_bob(server, policy) do
    {:ok, conn} = Mendooze.create_peer_connection(server, self(), [media: :video] ++ policy)
    assert_receive {:jsr309_call, "MediaSessionCreate", [_tag, _q]}, 1_000

    {:ok, out} =
      Mendooze.create_peer_connection(
        server,
        self(),
        [media: :video, bridge_with: conn] ++ policy
      )

    assert {:ok, _answer} = Mendooze.set_remote_offer(conn, vp8_only_offer())
    {conn, out}
  end

  # The offer relayed to the callee — trame 96 of the capture, which read
  # `m=video 55488 RTP/AVP 110 99 107` for a caller that had just said VP8 and
  # only VP8.
  test "our offer leads with what the other leg already carries" do
    %{server: server} = start_media_server(&two_leg_verdict_handler/2)
    {_conn, out} = alice_and_bob(server, transcode: [video: :avoid])

    assert {:ok, offer} = Mendooze.get_local_offer(out)

    # A permutation, not a restriction: AV1 and H.264 are still on the menu, so a
    # callee that cannot do VP8 still has something to accept and the transcoder
    # still has somewhere to go. VP8 simply leads.
    assert ["107", "110", "99"] == video_fmt(offer)
  end

  # ── prefer_codecs: the scenario's own ranking of the answer ────────────────

  # The recording case (scenarios/record.exs): the caller offers AV1/H264/VP8 in
  # its own order; the scenario wants H264 first in the answer because that is
  # what the MP4 container records without transcoding — and the answer's order
  # is what steers which codec the caller then sends.
  test "prefer_codecs reranks the answer's video formats" do
    %{server: server} = start_media_server(&verdict_handler/2)

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(),
        media: :video,
        prefer_codecs: [video: ["H264"]]
      )

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, av1_first_offer())

    # A permutation, not a restriction: H264 leads, the payload types the
    # scenario did not rank keep the offer's own order behind it.
    assert ["99", "110", "107"] == video_fmt(answer)
  end

  test "without prefer_codecs the answer keeps the offer's order" do
    %{server: server} = start_media_server(&verdict_handler/2)

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :video)

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, av1_first_offer())

    assert ["110", "99", "107"] == video_fmt(answer)
  end

  test "prefer_codecs never adds a codec the offer lacks" do
    %{server: server} = start_media_server(&verdict_handler/2)

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(),
        media: :video,
        prefer_codecs: [video: ["H264"]]
      )

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, vp8_only_offer())

    # The caller only speaks VP8: the preference has nothing to float and the
    # answer is exactly what it would have been without it (RFC 3264 §6.1 — an
    # answer may only carry payload types the offer declared).
    assert ["96"] == video_fmt(answer)
  end

  test "an unknown prefer_codecs name fails the creation, not an answer" do
    %{server: server} = start_media_server()

    assert {:error, _} =
             Mendooze.create_peer_connection(server, self(),
               media: :video,
               prefer_codecs: [video: ["H265"]]
             )

    assert {:error, _} =
             Mendooze.create_peer_connection(server, self(),
               media: :video,
               prefer_codecs: [application: ["H264"]]
             )
  end

  # `:forbid` says the media may never be converted, so a codec the far end
  # cannot carry has no business being offered: whatever the peer picks from it,
  # a relay would have nothing to do with.
  test "under :forbid our offer is restricted to what the other leg carries" do
    %{server: server} = start_media_server(&two_leg_verdict_handler/2)
    {_conn, out} = alice_and_bob(server, transcode: [video: :forbid])

    assert {:ok, offer} = Mendooze.get_local_offer(out)
    assert ["107"] == video_fmt(offer)
  end

  # `:force` states no cross-leg preference — each leg keeps the head of its own
  # list — so it is the one policy that leaves our menu exactly as configured.
  test "under :force our offer is the menu as configured" do
    %{server: server} = start_media_server(&two_leg_verdict_handler/2)
    {_conn, out} = alice_and_bob(server, transcode: [video: :force])

    assert {:ok, offer} = Mendooze.get_local_offer(out)
    assert ["110", "99", "107"] == video_fmt(offer)
  end

  # Trame 2162: the answer to Bob's re-INVITE. It went out AFTER Alice had
  # answered VP8 only, and still led with AV1 — so Bob sent AV1.
  test "an answer to a re-offer floats the codecs both legs carry to the front" do
    %{server: server} = start_media_server(&two_leg_verdict_handler/2)
    {conn, out} = alice_and_bob(server, transcode: [video: :avoid])

    {:ok, _offer} = Mendooze.get_local_offer(out)
    :ok = Mendooze.set_remote_answer(out, bob_video("110 107"))
    assert {:ok, _} = Mendooze.bridge(conn, out, video: :avoid)

    # Bob re-offers, AV1 first — his own preference, and his right to state it.
    assert {:ok, answer} = Mendooze.set_remote_offer(out, bob_video("110 107"))

    # Ours is the codec both legs carry. Nothing is removed (`:avoid` converts
    # rather than refuses), but VP8 leads, so Bob's own reading of the answer
    # points him at the codec that needs no conversion.
    assert ["107", "110"] == video_fmt(answer)
  end

  # The other half of the same re-INVITE: the selection itself. Bob now carries
  # AV1 *and* VP8 where he carried AV1 first; the transcoder feeding Alice must
  # still produce VP8, and the one feeding Bob must be moved onto VP8 — without
  # tearing down a media path on a call that is up.
  test "a renegotiation re-takes the selection and re-tunes, it does not re-wire" do
    %{server: server} = start_media_server(&two_leg_verdict_handler/2)
    {conn, out} = alice_and_bob(server, transcode: [video: :avoid])

    {:ok, _offer} = Mendooze.get_local_offer(out)
    # Bob answers AV1 only: no common codec, so each leg keeps its own head and
    # the two transcoders are set to different codecs.
    :ok = Mendooze.set_remote_answer(out, bob_video("110"))
    assert :ok = Mendooze.bridge(conn, out, video: :avoid)

    assert_receive {:jsr309_call, "VideoTranscoderCreate", [3, _tag_a]}, 1_000
    assert_receive {:jsr309_call, "VideoTranscoderCreate", [3, _tag_b]}, 1_000
    assert_receive {:jsr309_call, "VideoTranscoderSetCodec", [3, 30, @vp8 | _]}, 1_000
    assert_receive {:jsr309_call, "VideoTranscoderSetCodec", [3, 31, @av1 | _]}, 1_000

    # Bob re-offers with VP8 too: the intersection is no longer empty and the
    # selection moves to VP8 on BOTH legs. Re-taking it is the controller's call
    # — `bridge/3` again, which is what `SIP.Session.B2bua` does on every
    # renegotiation; the connection does not decide on its own when a call is
    # settled enough to re-select.
    assert {:ok, _answer} = Mendooze.set_remote_offer(out, bob_video("110 107"))
    assert {:ok, _} = Mendooze.bridge(conn, out, video: :avoid)

    # Alice's transcoder was already producing VP8 and is left alone; only Bob's
    # is re-tuned. `VideoTranscoderSetCodec` restarts an encoder — re-issuing it
    # for an unchanged codec costs a keyframe and a visible freeze.
    assert_receive {:jsr309_call, "VideoTranscoderSetCodec", [3, 31, @vp8 | _]}, 1_000
    refute_receive {:jsr309_call, "VideoTranscoderSetCodec", [3, 30, _ | _]}, 200

    # …and nothing was rebuilt: no new transcoder, none deleted.
    refute_receive {:jsr309_call, "VideoTranscoderCreate", _}, 200
    refute_receive {:jsr309_call, "VideoTranscoderDelete", _}, 200
  end

  # The wiring `:avoid` now gets, and the property that goes with it: no
  # `useOriSeqNum`. It also sets `useOriTS` and copies both numbers off the
  # incoming packet — right while the transcoder bridges, wrong the moment its
  # encoder produces the packet instead.
  test ":avoid wires a transcoder and does not preserve the peer's numbering" do
    %{server: server} = start_media_server(&verdict_handler/2)
    {conn, out} = two_crossed_legs(server)

    assert {:ok, _} = Mendooze.bridge(conn, out, audio: :avoid)

    assert_receive {:jsr309_call, "AudioTranscoderCreate", [3, _tag]}, 1_000
    refute_receive {:jsr309_call, "EndpointAttachToEndpoint", _}, 200

    refute_receive {:jsr309_call, "EndpointSetRTPProperties", [_, _, _, %{"useOriSeqNum" => _}]},
                   200
  end

  # The narrowing that makes a relay honest. The caller offers three codecs, the
  # callee answers one: on a relayed media the answer may only keep that one, or
  # the caller is free to switch to something the far end cannot receive — and a
  # relay has nothing to convert it with.
  test "a relayed media (:forbid) answers only the codecs both legs carry" do
    %{server: server} = start_media_server(&verdict_handler/2)

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)
    assert_receive {:jsr309_call, "MediaSessionCreate", [_tag, _q]}, 1_000

    {:ok, out} =
      Mendooze.create_peer_connection(server, self(),
        media: :audio,
        audio_codec: ["PCMU", "OPUS", "PCMA"],
        bridge_with: conn
      )

    offer =
      Enum.join(
        [
          "v=0",
          "o=- 1 1 IN IP4 10.9.8.7",
          "s=-",
          "c=IN IP4 10.9.8.7",
          "t=0 0",
          "m=audio 40000 RTP/AVP 96 0 8 101",
          "a=rtpmap:96 opus/48000/2",
          "a=rtpmap:101 telephone-event/8000",
          ""
        ],
        "\r\n"
      )

    assert {:ok, first_pass} = Mendooze.set_remote_offer(conn, offer)
    # the first pass cannot know better: it answers everything the server accepted
    assert first_pass =~ "opus/48000/2"

    {:ok, _offer} = Mendooze.get_local_offer(out)
    pcmu = %{type: :audio, port: 40_000, codecs: ["PCMU"], dtmf: true}
    :ok = Mendooze.set_remote_answer(out, remote_answer(audio: pcmu))

    assert {:ok, %{inbound_answer: rebuilt}} = Mendooze.bridge(conn, out, audio: :forbid)
    assert_receive {:jsr309_call, "EndpointAttachToEndpoint", [3, 4, 5, 0]}, 1_000

    # PCMU is the whole intersection; opus and PCMA are gone, DTMF stays
    assert rebuilt =~ "PCMU/8000"
    refute rebuilt =~ "opus"
    refute rebuilt =~ "PCMA"
    assert rebuilt =~ "telephone-event"
    # one m= per offered m=, still (RFC 3264 §6)
    assert length(String.split(rebuilt, "m=audio")) == 2
  end

  # Traffic of 2026-08-12: Alice offered AV1, our outbound offer carried H.264 and
  # VP8 only, so Bob declined the video — and the whole call died on
  # `{:not_negotiated, :video}`, audio included, with a 488 to a caller whose
  # audio was perfectly fine. A media one leg does not carry is not a policy
  # failure: there is simply nothing to bridge.
  test "a media the callee declined is declined in the answer, not fatal to the call" do
    %{server: server} = start_media_server(&verdict_handler/2)

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio_video)
    assert_receive {:jsr309_call, "MediaSessionCreate", [_tag, _q]}, 1_000

    {:ok, out} =
      Mendooze.create_peer_connection(server, self(),
        media: :audio_video,
        audio_codec: ["OPUS"],
        bridge_with: conn
      )

    offer =
      Sdp.build(%{
        ip: "10.9.8.7",
        medias: [
          %{type: :audio, port: 40_000, codecs: ["OPUS"], dtmf: true},
          %{type: :video, port: 40_002, codecs: ["VP8"]}
        ]
      })

    assert {:ok, first_pass} = Mendooze.set_remote_offer(conn, offer)
    assert first_pass =~ "VP8/90000"

    # the callee answers audio only — it wants no video at all
    {:ok, _offer} = Mendooze.get_local_offer(out)

    :ok =
      Mendooze.set_remote_answer(
        out,
        remote_answer(audio: %{type: :audio, port: 40_000, codecs: ["OPUS"], dtmf: true})
      )

    # the call lives: audio is bridged…
    assert {:ok, %{inbound_answer: rebuilt}} =
             Mendooze.bridge(conn, out, audio: :avoid, video: :avoid)

    assert_receive {:jsr309_call, "AudioTranscoderCreate", [3, _]}, 1_000

    # …and the caller is TOLD there is no video, rather than left believing there is
    assert rebuilt =~ ~r/m=video 0 /
    refute rebuilt =~ "VP8/90000"
    assert rebuilt =~ "opus/48000/2"
  end

  # What `:force` buys: each peer stays on the codec IT put first — opus toward
  # the caller, PCMU toward the callee — which is a transcoder, though a common
  # codec existed and `:avoid` would have relayed.
  test "with :force, each leg keeps the head of its own list" do
    %{server: server} = start_media_server(&verdict_handler/2)
    {conn, out} = two_crossed_legs(server)

    assert :ok = Mendooze.bridge(conn, out, audio: :force)

    assert_receive {:jsr309_call, "EndpointAttachToAudioTranscoder", [3, 4, 30]}, 1_000
    refute_receive {:jsr309_call, "EndpointAttachToEndpoint", _}, 200
  end

  # ── The send map and the cross-leg selection must agree ─────────────────────
  #
  # Traffic of 2026-08-12, the half that was left. The video send map was pinned to
  # the caller's PRIMARY payload type ALONE, so the endpoint could only ever stamp
  # one codec — while the cross-leg selection is free to pick any codec both legs
  # carry. And the media server cannot refuse in SDP: `SetSendingCodec` fails, it
  # keeps the previous payload type, and the stream goes out mislabelled.

  # Linphone's real video offer: AV1 first, then H.264, then VP8.
  defp av1_first_offer do
    Sdp.build(%{
      ip: "10.9.8.7",
      medias: [
        %{
          type: :video,
          port: 40_002,
          rtpmaps: [
            %{pt: 110, encoding: "AV1", clock: 90_000},
            %{pt: 99, encoding: "H264", clock: 90_000},
            %{pt: 107, encoding: "VP8", clock: 90_000}
          ]
        }
      ]
    })
  end

  test "the video send map carries every accepted codec, one payload type each" do
    %{server: server} = start_media_server(&verdict_handler/2)

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :video)

    assert {:ok, _answer} = Mendooze.set_remote_offer(conn, av1_first_offer())

    assert_receive {:jsr309_call, "EndpointStartSending",
                    [3, 4, 1, "10.9.8.7", 40_002, send_map]},
                   1_000

    # AV1 is the caller's preference and stays first in the answer, but H.264 and
    # VP8 belong here too: a selection landing on either would be unstampable, and
    # the endpoint would send it under AV1's payload type.
    assert send_map == %{"110" => 110, "99" => 99, "107" => 107}
  end

  test "two payload types of one video codec leave only the preferred one" do
    # The reason the map was pinned in the first place, and it must survive: two
    # H.264 payload types differ by profile, and leaving both would let the server
    # choose which one it stamps with — SetSendingCodec takes the first match.
    # Filtering on the server's verdict does NOT settle it, since a server can
    # accept both.
    %{server: server} = start_media_server(&verdict_handler/2)

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
            ]
          }
        ]
      })

    assert {:ok, _answer} = Mendooze.set_remote_offer(conn, offer)

    assert_receive {:jsr309_call, "EndpointStartSending",
                    [3, 4, 1, "10.9.8.7", 40_002, send_map]},
                   1_000

    # One entry, and it is the payload type the caller listed first.
    assert send_map == %{"97" => 99}
  end

  test "whatever the cross-leg selection picks, the sink leg can stamp it" do
    # THE invariant, end to end and in the exact shape of the traffic: an AV1-first
    # caller reaching an H.264-only callee. `:avoid` selects H.264 for both legs,
    # so the transcoder feeding the CALLER must produce H.264 — and the caller's
    # endpoint must hold a payload type for it. Before the fix it held 110 alone,
    # and the caller decoded H.264 as AV1.
    %{server: server} = start_media_server(&two_leg_verdict_handler/2)

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :video)
    assert_receive {:jsr309_call, "MediaSessionCreate", [_tag, _q]}, 1_000

    {:ok, out} =
      Mendooze.create_peer_connection(server, self(),
        media: :video,
        video_codec: ["H264"],
        bridge_with: conn
      )

    assert {:ok, _answer} = Mendooze.set_remote_offer(conn, av1_first_offer())

    assert_receive {:jsr309_call, "EndpointStartSending",
                    [3, 4, 1, "10.9.8.7", 40_002, send_map]},
                   1_000

    {:ok, _offer} = Mendooze.get_local_offer(out)

    :ok =
      Mendooze.set_remote_answer(
        out,
        Sdp.build(%{
          ip: "10.9.8.6",
          medias: [%{type: :video, port: 40_010, codecs: ["H264"]}]
        })
      )

    # `:avoid` reshapes the caller's answer as well — H.264 floated to the front,
    # a permutation and not a restriction, so a caller that follows the `m=` order
    # rather than the payload type also lands on the selected codec.
    assert {:ok, %{inbound_answer: rebuilt}} = Mendooze.bridge(conn, out, video: :avoid)
    assert rebuilt =~ "m=video 22002 RTP/AVP 99 110 107"

    # The transcoder feeding the caller (endpoint 4 ← transcoder 30) is told which
    # codec to produce.
    assert_receive {:jsr309_call, "VideoTranscoderSetCodec", [3, 30, selected | _]}, 1_000

    # The whole point, stated as the invariant rather than as a value: the codec the
    # selection chose is one the sink's send map can label.
    assert selected in Map.values(send_map),
           "selection #{selected} is not in the sink's send map #{inspect(send_map)}"

    # And here it is H.264, since that is all the callee answered.
    assert selected == 99
  end

  # verdict_handler, but with the two-endpoint / two-transcoder id scheme: the
  # bridge tests need endpoints 4 and 5 to be distinct.
  defp two_leg_verdict_handler("EndpointStartReceiving", [_sess, _ep, media, rtp_map | _]) do
    {:ok, [22_000 + 2 * media, Map.new(rtp_map, fn {pt, _code} -> {to_string(pt), ""} end)]}
  end

  defp two_leg_verdict_handler(method, params), do: two_leg_handler(method, params)

  # The server's fmtp verdict, which the stock handler never returns — so every
  # bridge test above exercises the legacy fallback, and NOT the branch a real
  # media server takes. Shaped like the real one: it accepts everything proposed
  # and keys the struct by payload type as a string (XML-RPC has no integer keys).
  defp verdict_handler("EndpointStartReceiving", [_sess, _ep, media, rtp_map | _]) do
    {:ok, [22_000 + 2 * media, Map.new(rtp_map, fn {pt, _code} -> {to_string(pt), ""} end)]}
  end

  defp verdict_handler(method, params), do: two_leg_handler(method, params)

  # Linphone's real offer (traffic of 2026-08-12): opus first in the format list
  # but on a DYNAMIC payload type, with PCMU further down the list.
  defp linphone_offer do
    Enum.join(
      [
        "v=0",
        "o=60273198 242 2460 IN IP4 172.22.0.8",
        "s=Talk",
        "c=IN IP4 172.22.0.8",
        "t=0 0",
        "m=audio 56594 RTP/AVP 96 97 98 0 8 18 101 99 100",
        "a=rtpmap:96 opus/48000/2",
        "a=fmtp:96 useinbandfec=1",
        "a=rtpmap:97 speex/16000",
        "a=fmtp:97 vbr=on",
        "a=rtpmap:98 speex/8000",
        "a=fmtp:98 vbr=on",
        "a=fmtp:18 annexb=yes",
        "a=rtpmap:101 telephone-event/48000",
        "a=rtpmap:99 telephone-event/16000",
        "a=rtpmap:100 telephone-event/8000",
        ""
      ],
      "\r\n"
    )
  end

  # Linphone's real answer to our offer (same traffic). opus is FIRST, and PCMU /
  # PCMA ride along as static payload types with no rtpmap of their own — the
  # shape that decides which codec the leg we OFFERED on settles for.
  defp linphone_answer do
    Enum.join(
      [
        "v=0",
        "o=50815019 1543 2543 IN IP4 172.22.0.3",
        "s=Talk",
        "c=IN IP4 172.22.0.3",
        "t=0 0",
        "m=audio 35767 RTP/AVP 98 0 8 101",
        "a=rtpmap:98 opus/48000/2",
        "a=fmtp:98 useinbandfec=1",
        "a=rtpmap:101 telephone-event/8000",
        ""
      ],
      "\r\n"
    )
  end

  # Both legs carry opus; each side numbered it differently (the caller 96, our
  # own offer 98). The codec each leg settled on is what `:avoid` compares, and it
  # must be the CODEC each side put first — not the lowest payload type that
  # happens to be listed. PCMU sits at 0 in both SDPs, so a numeric reading picks
  # it every time, and the whole `:avoid` policy silently inverts.
  test "legs that both settled on opus are relayed, whatever payload type numbered it" do
    %{server: server} = start_media_server(&verdict_handler/2)

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)
    assert_receive {:jsr309_call, "MediaSessionCreate", [_tag, _q]}, 1_000

    {:ok, out} =
      Mendooze.create_peer_connection(server, self(),
        media: :audio,
        audio_codec: ["OPUS", "PCMU", "PCMA"],
        bridge_with: conn
      )

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, linphone_offer())
    assert answer =~ "opus/48000/2"

    {:ok, _offer} = Mendooze.get_local_offer(out)
    :ok = Mendooze.set_remote_answer(out, linphone_answer())

    assert {:ok, %{inbound_answer: rebuilt}} = Mendooze.bridge(conn, out, audio: :avoid)

    # The regression, stated where it is now visible: BOTH chains encode opus. It
    # read PCMU on the leg we offered on, because an answer of `98 0 8 101` with
    # opus at 98 sorts as PCMU when the only tiebreak left is the payload NUMBER.
    assert_receive {:jsr309_call, "AudioTranscoderSetCodec", [3, _tr_a, @opus, %{}]}, 1_000
    assert_receive {:jsr309_call, "AudioTranscoderSetCodec", [3, _tr_b, @opus, %{}]}, 1_000
    refute_receive {:jsr309_call, "AudioTranscoderSetCodec", [3, _, @pcmu, %{}]}, 200

    # Both legs carry opus, so the transcoder will spend the call bridging — and
    # the answer keeps every codec the caller offered that the server accepted,
    # since a transcoder can convert any of them. Wideband speex (PT 97) is one
    # of those since the codec table names it; narrowband speex/8000 (PT 98) is
    # absent because the table's clock is part of the codec's identity and the
    # server factory carries no 8 kHz variant — `parse/1` dropped it up front.
    assert rebuilt =~ "opus/48000/2"
    assert rebuilt =~ "speex/16000"
    refute rebuilt =~ "speex/8000"
    # DTMF is not a codec choice and rides alongside whichever one wins
    assert rebuilt =~ "telephone-event"
  end

  # The callee's answer declines the audio (`m=audio 0`, RFC 3264 §6) but keeps
  # the video. Traffic of 2026-08-14: this used to be processed as a live media —
  # StartSending aimed at port 0, a transcoder pair bridging into the void, and a
  # caller granted `sendrecv` audio it could never hear. The decline must
  # propagate: nothing started on that media, no audio bridge, and the caller's
  # rebuilt answer declining it too, while the video lives on.
  test "an answer declining one media declines it on the other leg too" do
    %{server: server} = start_media_server(&two_leg_handler/2)

    {:ok, conn} = Mendooze.create_peer_connection(server, self())
    assert_receive {:jsr309_call, "MediaSessionCreate", [_tag, _q]}, 1_000
    {:ok, out} = Mendooze.create_peer_connection(server, self(), bridge_with: conn)

    caller_offer =
      Enum.join(
        [
          "v=0",
          "o=60273198 242 2460 IN IP4 172.22.0.2",
          "s=Talk",
          "c=IN IP4 172.22.0.2",
          "t=0 0",
          "m=audio 57017 RTP/AVP 96 0 8 101",
          "a=rtpmap:96 opus/48000/2",
          "a=rtpmap:101 telephone-event/48000",
          "m=video 57019 RTP/AVP 96",
          "a=rtpmap:96 VP8/90000",
          ""
        ],
        "\r\n"
      )

    callee_answer =
      Enum.join(
        [
          "v=0",
          "o=50815019 1543 2543 IN IP4 172.22.0.6",
          "s=Talk",
          "c=IN IP4 172.22.0.6",
          "t=0 0",
          "m=audio 0 RTP/AVP 0",
          "a=inactive",
          "m=video 53291 RTP/AVP 107",
          "a=rtpmap:107 VP8/90000",
          "a=recvonly",
          ""
        ],
        "\r\n"
      )

    assert {:ok, first_answer} = Mendooze.set_remote_offer(conn, caller_offer)
    # first pass: the other leg is unknown, so the audio is still answered live
    assert first_answer =~ "m=audio 22000"

    {:ok, _offer} = Mendooze.get_local_offer(out)
    :ok = Mendooze.set_remote_answer(out, callee_answer)

    assert {:ok, %{inbound_answer: rebuilt}} = Mendooze.bridge(conn, out, audio: :avoid)

    # the caller learns its audio has no far end; its video stands
    assert rebuilt =~ "m=audio 0 "
    assert rebuilt =~ "m=video 22002"
    assert rebuilt =~ "VP8/90000"

    # the video is wired; the dead audio never is, and nothing was ever sent
    # towards the declined media's port 0
    assert_receive {:jsr309_call, "VideoTranscoderCreate", _}, 1_000
    refute_receive {:jsr309_call, "AudioTranscoderCreate", _}, 200
    refute_receive {:jsr309_call, "EndpointStartSending", [3, 5, 0 | _]}, 200
  end

  # A transcoder is a session resource, not a wire: detaching the endpoints
  # leaves it running for the life of the call.
  test "unbridging a transcoded media deletes the transcoders, not just the attaches" do
    %{server: server} = start_media_server(&verdict_handler/2)
    {conn, out} = two_crossed_legs(server)
    :ok = Mendooze.bridge(conn, out, audio: :force)

    assert :ok = Mendooze.unbridge(conn, out)

    assert_receive {:jsr309_call, "AudioTranscoderDettach", [3, 30]}, 1_000
    assert_receive {:jsr309_call, "AudioTranscoderDelete", [3, 30]}, 1_000
    assert_receive {:jsr309_call, "AudioTranscoderDettach", [3, 31]}, 1_000
    assert_receive {:jsr309_call, "AudioTranscoderDelete", [3, 31]}, 1_000
  end

  test "a media neither leg has negotiated is not attached" do
    %{server: server} = start_media_server(&two_leg_handler/2)
    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)
    {:ok, out} = Mendooze.create_peer_connection(server, self(), media: :audio, bridge_with: conn)

    assert {:error, {:not_negotiated, :audio}} = Mendooze.bridge(conn, out, [])
  end

  test "unbridge detaches both endpoints, and a bad pair is not an error" do
    %{server: server} = start_media_server(&two_leg_handler/2)
    {conn, out, _tag} = two_negotiated_legs(server)
    {:ok, %{inbound_answer: _}} = Mendooze.bridge(conn, out, audio: :avoid)

    assert :ok = Mendooze.unbridge(conn, out)
    assert_receive {:jsr309_call, "EndpointDettach", [3, 4, 0]}, 1_000
    assert_receive {:jsr309_call, "EndpointDettach", [3, 5, 0]}, 1_000
  end

  test "two legs of different connections cannot be bridged" do
    %{server: server} = start_media_server(&two_leg_handler/2)
    {:ok, a} = Mendooze.create_peer_connection(server, self(), media: :audio)
    {:ok, b} = Mendooze.create_peer_connection(server, self(), media: :audio)

    assert {:error, :not_same_media_session} = Mendooze.bridge(a, b, [])
  end

  test "closing one leg deletes its endpoint; the session goes with the last one" do
    %{server: server} = start_media_server(&two_leg_handler/2)
    {conn, out, _tag} = two_negotiated_legs(server)

    :ok = Mendooze.close_peer_connection(out)
    assert_receive {:jsr309_call, "EndpointDelete", [3, 5]}, 1_000
    refute_receive {:jsr309_call, "MediaSessionDelete", _}, 200
    assert Process.alive?(conn)

    :ok = Mendooze.close_peer_connection(conn)
    assert_receive {:jsr309_call, "EndpointDelete", [3, 4]}, 1_000
    assert_receive {:jsr309_call, "MediaSessionDelete", [3]}, 1_000
    refute Process.alive?(conn)
  end

  # The order the media mixin releases in — inbound first, since that is the
  # order the legs were created. "The inbound leg owns the session" would have
  # deleted the outbound endpoint out from under itself.
  test "releasing the inbound leg first does not take the outbound endpoint with it" do
    %{server: server} = start_media_server(&two_leg_handler/2)
    {conn, out, _tag} = two_negotiated_legs(server)

    :ok = Mendooze.close_peer_connection(conn)
    assert_receive {:jsr309_call, "EndpointDelete", [3, 4]}, 1_000
    refute_receive {:jsr309_call, "MediaSessionDelete", _}, 200
    assert Process.alive?(conn)

    :ok = Mendooze.close_peer_connection(out)
    assert_receive {:jsr309_call, "MediaSessionDelete", [3]}, 1_000
  end

  # One session, two endpoints, one event queue: what tells the legs apart is
  # the endpoint id the event carries. Emitting both legs' events under the same
  # handle would leave a B2BUA unable to say WHICH side went silent.
  test "an endpoint event is attributed to the leg whose endpoint it names" do
    %{server: server, stream: stream} = start_media_server(&two_leg_handler/2)
    {conn, out, sess_tag} = two_negotiated_legs(server)

    # endpoint 5 is the outbound one
    send(stream, {:chunk, Jsr309FakeServer.event_frame([7, sess_tag, 5, 0, 0])})
    assert_receive {:ms_event, ^out, {:media_connected, :audio}}, 1_000

    # endpoint 4 is the inbound one, and it keeps the bare pid — which is why
    # nothing written before legs existed had to change.
    send(stream, {:chunk, Jsr309FakeServer.event_frame([7, sess_tag, 4, 0, 0])})
    assert_receive {:ms_event, ^conn, {:media_connected, :audio}}, 1_000
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

  test "set_remote_answer starts sending with the remote map, and arms nothing until the call is answered" do
    %{server: server, stream: stream} = start_media_server()

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(), media: :audio, audio_codec: "PCMU")

    assert_receive {:jsr309_call, "MediaSessionCreate", [sess_tag, _q]}

    {:ok, _offer} = Mendooze.get_local_offer(conn)
    assert :ok = Mendooze.set_remote_answer(conn, remote_answer())

    assert_receive {:jsr309_call, "EndpointStartSending", [3, 4, 0, "10.9.8.7", 40_000, send_map]}
    assert send_map == %{"0" => 0, "101" => 100}

    # NOT armed by the answer: the call is not up yet, and the ringing phase it
    # would otherwise supervise is silent by definition
    refute_received {:jsr309_call, "EndpointStartRTPTimeout", [3, 4, 0, _]}

    # armed when — and only when — the call is answered
    assert :ok = Mendooze.call_answered(conn)
    assert_receive {:jsr309_call, "EndpointStartRTPTimeout", [3, 4, 0, timeout]}
    assert timeout > 0

    # idempotent: a second announcement changes nothing
    assert :ok = Mendooze.call_answered(conn)
    refute_received {:jsr309_call, "EndpointStartRTPTimeout", [3, 4, 0, _]}

    # :ice_connected is no longer emitted on the answer: it now reflects the
    # first validated RTP packet the server reports (EndpointConnectedEvent, 7)
    refute_receive {:ms_event, ^conn, :ice_connected}, 100
    send(stream, {:chunk, Jsr309FakeServer.event_frame([7, sess_tag, 4, 0, 0])})
    assert_receive {:ms_event, ^conn, :ice_connected}
  end

  # ── Media connectivity (docs/design/media-connectivity.md) ──────────────────

  # An offer the peer transmits on, media by media. `directions` overrides the
  # default :sendrecv per media type.
  defp av_offer(directions \\ %{}) do
    Sdp.build(%{
      ip: "10.9.8.7",
      medias: [
        %{
          type: :audio,
          port: 40_000,
          codecs: ["PCMU"],
          direction: Map.get(directions, :audio, :sendrecv)
        },
        %{
          type: :video,
          port: 40_002,
          codecs: ["H264"],
          direction: Map.get(directions, :video, :sendrecv)
        }
      ]
    })
  end

  defp connected(stream, sess_tag, media),
    do: send(stream, {:chunk, Jsr309FakeServer.event_frame([7, sess_tag, 4, media, 0])})

  # Rule 2: video is in R, so only video releases the milestone. Releasing it on
  # audio is what sent the opening keyframe into an unlatched video leg.
  test "with video negotiated, only the video connectivity event emits :ice_connected" do
    %{server: server, stream: stream} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio_video)
    assert_receive {:jsr309_call, "MediaSessionCreate", [sess_tag, _q]}
    assert {:ok, _answer} = Mendooze.set_remote_offer(conn, av_offer())

    connected(stream, sess_tag, 0)
    assert_receive {:ms_event, ^conn, {:media_connected, :audio}}
    refute_receive {:ms_event, ^conn, :ice_connected}, 100

    connected(stream, sess_tag, 1)
    assert_receive {:ms_event, ^conn, {:media_connected, :video}}
    assert_receive {:ms_event, ^conn, :ice_connected}
  end

  # Rule 3: no video in R, the first media of R releases it.
  test "with no video negotiated, the first media emits :ice_connected" do
    %{server: server, stream: stream} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)
    assert_receive {:jsr309_call, "MediaSessionCreate", [sess_tag, _q]}
    {:ok, _offer} = Mendooze.get_local_offer(conn)
    assert :ok = Mendooze.set_remote_answer(conn, remote_answer())

    connected(stream, sess_tag, 0)
    assert_receive {:ms_event, ^conn, {:media_connected, :audio}}
    assert_receive {:ms_event, ^conn, :ice_connected}
  end

  # ── Media loss, the mirror of the above (P3 R2b) ────────────────────────────

  defp timed_out(stream, sess_tag, media),
    do: send(stream, {:chunk, Jsr309FakeServer.event_frame([6, sess_tag, 4, media, 0])})

  # The distinction the bare `:media_timeout` could not make, and the one a
  # B2BUA hangs up on: a peer that stopped its camera is still on the call.
  test "one media going silent is reported as itself and is not a lost call" do
    %{server: server, stream: stream} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio_video)
    assert_receive {:jsr309_call, "MediaSessionCreate", [sess_tag, _q]}
    assert {:ok, _answer} = Mendooze.set_remote_offer(conn, av_offer())

    timed_out(stream, sess_tag, 1)
    assert_receive {:ms_event, ^conn, {:media_timeout, :video}}, 1_000
    refute_receive {:ms_event, ^conn, :media_lost}, 200

    # …and the second one completes R, which is a peer that has stopped sending.
    timed_out(stream, sess_tag, 0)
    assert_receive {:ms_event, ^conn, {:media_timeout, :audio}}, 1_000
    assert_receive {:ms_event, ^conn, :media_lost}, 1_000
  end

  test ":media_lost is emitted once, and re-armed by media coming back" do
    %{server: server, stream: stream} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)
    assert_receive {:jsr309_call, "MediaSessionCreate", [sess_tag, _q]}
    {:ok, _offer} = Mendooze.get_local_offer(conn)
    assert :ok = Mendooze.set_remote_answer(conn, remote_answer())

    timed_out(stream, sess_tag, 0)
    assert_receive {:ms_event, ^conn, :media_lost}, 1_000

    # The server re-arms its watchdog on every StartReceiving, so the raw event
    # repeats; the milestone must not.
    timed_out(stream, sess_tag, 0)
    assert_receive {:ms_event, ^conn, {:media_timeout, :audio}}, 1_000
    refute_receive {:ms_event, ^conn, :media_lost}, 200

    # Media flowing again clears the latch: a second silence is a second loss,
    # not a repeat of the first one.
    connected(stream, sess_tag, 0)
    assert_receive {:ms_event, ^conn, {:media_connected, :audio}}, 1_000

    timed_out(stream, sess_tag, 0)
    assert_receive {:ms_event, ^conn, :media_lost}, 1_000
  end

  # The receive plane opens before the far end's SDP arrives — StartReceiving is
  # what allocates the port we advertise — so as a UAC, media reaching us BEFORE
  # the answer is the ordinary case rather than a corner one. R is only learned
  # from that answer, so the raw event was evaluated against an empty R, decided
  # "not ready", and dropped; the server re-arms it only on the next
  # StartReceiving, so :ice_connected never came at all.
  test "media that arrives before the answer still releases :ice_connected" do
    %{server: server, stream: stream} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)
    assert_receive {:jsr309_call, "MediaSessionCreate", [sess_tag, _q]}, 1_000
    {:ok, _offer} = Mendooze.get_local_offer(conn)

    # The callee is already sending — its answer has not reached us yet.
    connected(stream, sess_tag, 0)
    assert_receive {:ms_event, ^conn, {:media_connected, :audio}}, 1_000
    refute_receive {:ms_event, ^conn, :ice_connected}, 200

    # …and now it does. What already arrived counts.
    assert :ok = Mendooze.set_remote_answer(conn, remote_answer())
    assert_receive {:ms_event, ^conn, :ice_connected}, 1_000
  end

  # Rule 2 survives the replay: an audio packet that arrived early must not
  # release a leg that negotiated video — that is the whole reason rule 2 exists
  # (the opening keyframe would go to an unlatched video leg).
  test "media that arrives early does not release a leg that expects video" do
    %{server: server, stream: stream} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio_video)
    assert_receive {:jsr309_call, "MediaSessionCreate", [sess_tag, _q]}, 1_000

    connected(stream, sess_tag, 0)
    assert_receive {:ms_event, ^conn, {:media_connected, :audio}}, 1_000

    assert {:ok, _answer} = Mendooze.set_remote_offer(conn, av_offer())
    refute_receive {:ms_event, ^conn, :ice_connected}, 200

    connected(stream, sess_tag, 1)
    assert_receive {:ms_event, ^conn, :ice_connected}, 1_000
  end

  # Rule 1: R is empty — no connectivity event can ever arrive, so the
  # application is told rather than left waiting.
  test "a peer that transmits on nothing gets :media_send_only and no :ice_connected" do
    %{server: server, stream: stream} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio_video)
    assert_receive {:jsr309_call, "MediaSessionCreate", [sess_tag, _q]}

    offer = av_offer(%{audio: :recvonly, video: :recvonly})
    assert {:ok, _answer} = Mendooze.set_remote_offer(conn, offer)

    assert_receive {:ms_event, ^conn, :media_send_only}

    # even if the server did report one, the rule holds: R is empty
    connected(stream, sess_tag, 0)
    refute_receive {:ms_event, ^conn, :ice_connected}, 100
  end

  # The §4 limitation, asserted so it stays a known behaviour rather than a
  # surprise: video is negotiated but the peer never transmits it, so video is
  # not in R and audio releases the milestone.
  test "video negotiated but not transmitted by the peer falls back to rule 3" do
    %{server: server, stream: stream} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio_video)
    assert_receive {:jsr309_call, "MediaSessionCreate", [sess_tag, _q]}

    offer = av_offer(%{video: :recvonly})
    assert {:ok, _answer} = Mendooze.set_remote_offer(conn, offer)
    refute_receive {:ms_event, ^conn, :media_send_only}, 100

    connected(stream, sess_tag, 0)
    assert_receive {:ms_event, ^conn, :ice_connected}
  end

  # §5: the raw event follows the server's re-arming, the milestone does not.
  test "a second receive cycle re-emits the raw event but not :ice_connected" do
    %{server: server, stream: stream} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio_video)
    assert_receive {:jsr309_call, "MediaSessionCreate", [sess_tag, _q]}
    assert {:ok, _answer} = Mendooze.set_remote_offer(conn, av_offer())

    connected(stream, sess_tag, 1)
    assert_receive {:ms_event, ^conn, {:media_connected, :video}}
    assert_receive {:ms_event, ^conn, :ice_connected}

    connected(stream, sess_tag, 1)
    assert_receive {:ms_event, ^conn, {:media_connected, :video}}
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

  # ── The §7.5 ladder's middle rung ───────────────────────────────────────────

  test "rtp_profile: :avpf offers RTP/AVPF — the feedback profile, and nothing else" do
    %{server: server} = start_media_server()

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(),
        media: :audio_video,
        webrtc_support: :no,
        rtp_profile: :avpf
      )

    assert {:ok, offer} = Mendooze.get_local_offer(conn)
    assert {:ok, descs} = Sdp.parse(offer)

    for desc <- descs do
      assert desc.protocol == "RTP/AVPF"
      # No encryption, no ICE, no muxing: this rung is plain RTP that does
      # feedback, which is the whole point of having it between WebRTC and AVP.
      assert desc.crypto == :none
      assert desc.ice == nil
      refute desc.rtcp_mux
    end

    # Feedback is advertised where it means something (RFC 4585 on video).
    assert %{rtcp_fb: fb} = Enum.find(descs, &(&1.type == :video))
    assert fb != %{}
  end

  test "rtp_profile defaults to :avp, and WebRTC ignores it" do
    %{server: server} = start_media_server()

    {:ok, plain} = Mendooze.create_peer_connection(server, self(), media: :audio)
    assert {:ok, offer} = Mendooze.get_local_offer(plain)
    assert {:ok, [audio]} = Sdp.parse(offer)
    assert audio.protocol == "RTP/AVP"

    {:ok, webrtc} =
      Mendooze.create_peer_connection(server, self(),
        media: :audio,
        webrtc_support: :yes,
        rtp_profile: :avpf
      )

    assert {:ok, offer} = Mendooze.get_local_offer(webrtc)
    assert {:ok, [audio]} = Sdp.parse(offer)
    assert audio.protocol == "UDP/TLS/RTP/SAVPF"
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

    # the watchdog waits for the call to be answered (see the direction test below)
    refute_received {:jsr309_call, "EndpointStartRTPTimeout", [3, 4, 0, _]}
    assert :ok = Mendooze.call_answered(conn)
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

    refute_received {:jsr309_call, "EndpointStartRTPTimeout", [3, 4, 0, _]}
    assert :ok = Mendooze.call_answered(conn)
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
    # solely to carry it
    assert_receive {:jsr309_call, "EndpointSetRTPProperties", [3, 4, 0, props]}
    assert props == %{"natLatch" => "1"}
  end

  # The direction is NOT a criterion, and this is the regression: a NATed callee
  # writes its private address in an ANSWER exactly as an offerer writes it in an
  # offer. Traffic of 2026-08-12: answer `c=IN IP4 172.22.0.3`, RTP arriving from
  # 172.21.104.60, one-way audio for the whole call on every outgoing leg.
  test "an answer to an offer of ours asks for latching just the same" do
    %{server: server} = start_media_server()

    {:ok, conn} =
      Mendooze.create_peer_connection(server, self(), media: :audio, audio_codec: "PCMU")

    {:ok, _offer} = Mendooze.get_local_offer(conn)
    assert :ok = Mendooze.set_remote_answer(conn, remote_answer())

    assert_receive {:jsr309_call, "EndpointSetRTPProperties", [3, 4, 0, %{"natLatch" => "1"}]}
    assert_receive {:jsr309_call, "EndpointStartSending", [3, 4, 0, "10.9.8.7", 40_000, _]}
  end

  # ICE is the one case the server cannot see: it holds the `c=` line, not the
  # candidates, so it cannot know the address was settled by connectivity checks.
  test "a DTLS+ICE leg never asks for latching: candidates settle the address" do
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

    assert {:ok, _answer} = Mendooze.set_remote_offer(conn, offer)

    # the properties call still happens — for rtcp-mux — which is what makes the
    # absence of natLatch an assertion rather than a missing message
    assert_receive {:jsr309_call, "EndpointSetRTPProperties", [3, 4, 0, props]}
    assert Map.has_key?(props, "rtcp-mux")
    refute Map.has_key?(props, "natLatch")
  end

  test "nat_latch overrides the inference, either way" do
    %{server: server} = start_media_server()

    # forced off on a plain leg the inference would have latched
    {:ok, off} = Mendooze.create_peer_connection(server, self(), media: :audio, nat_latch: false)

    offer =
      Sdp.build(%{
        ip: "10.9.8.7",
        medias: [%{type: :audio, port: 40_000, codecs: ["PCMU"]}]
      })

    assert {:ok, _answer} = Mendooze.set_remote_offer(off, offer)
    refute_receive {:jsr309_call, "EndpointSetRTPProperties", _}, 100

    # forced on over the ICE exclusion, for a caller that knows its topology
    {:ok, on} =
      Mendooze.create_peer_connection(server, self(),
        media: :audio,
        audio_codec: "OPUS",
        webrtc_support: :if_offered,
        nat_latch: true
      )

    webrtc_offer =
      Sdp.build(%{
        ip: "10.9.8.7",
        medias: [
          %{
            type: :audio,
            port: 40_000,
            codecs: ["OPUS"],
            crypto: {:dtls, :actpass, "sha-256", @fp},
            ice: %{ufrag: "remote-uf", pwd: "remote-pwd-123456789012345"},
            protocol: "UDP/TLS/RTP/SAVPF"
          }
        ]
      })

    assert {:ok, _answer} = Mendooze.set_remote_offer(on, webrtc_offer)
    assert_receive {:jsr309_call, "EndpointSetRTPProperties", [3, 4, 0, %{"natLatch" => "1"}]}
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

  test "an RTP timeout event surfaces as {:media_timeout, media} on the event sink" do
    %{server: server, stream: stream} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)

    # recover the session tag from the create call to build the event
    assert_receive {:jsr309_call, "MediaSessionCreate", [sess_tag, 7]}

    send(stream, {:chunk, Jsr309FakeServer.event_frame([6, sess_tag, 4, 0, 0])})

    # Which media went silent, not merely that something did: a leg that turned
    # its camera off must be distinguishable from one that has gone quiet.
    assert_receive {:ms_event, ^conn, {:media_timeout, :audio}}, 1_000
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
    # goog-remb has its own server switch since rate-control lot 2
    assert answer =~ "a=rtcp-fb:99 goog-remb"

    # exactly the switches behind the answered feedback types
    assert_receive {:jsr309_call, "EndpointSetRTPProperties", [3, 4, 1, props]}

    assert props == %{
             "useNACK" => "1",
             "useRtcpFIR" => "1",
             "remb" => "1",
             "natLatch" => "1"
           }
  end

  # `[mediaserver] bitrate_feedback` narrows which dialects the answer confirms.
  # An empty list is the OPEN-LOOP rate-control measurement (mediaserver
  # rate_control_plan.md, lot 3): no bitrate target leaves towards the peer, so the
  # incoming rate stops depending on what we estimate. Naming one dialect isolates
  # one feedback path. In every case the rest of the answer is untouched — dropping
  # the wrong attribute would silently cost the call its loss recovery.
  for {allowed, kept, dropped} <- [
        {[], [], ["goog-remb", "ccm tmmbr"]},
        {[:remb], ["goog-remb"], ["ccm tmmbr"]},
        {[:tmmbr], ["ccm tmmbr"], ["goog-remb"]},
        {[:remb, :tmmbr], ["goog-remb", "ccm tmmbr"], []}
      ] do
    test "bitrate_feedback #{inspect(allowed)} answers #{inspect(kept)} and nothing else" do
      allowed = unquote(allowed)
      kept = unquote(kept)
      dropped = unquote(dropped)

      block = Application.get_env(:elixip2, MediaServer.Mendooze, [])

      Application.put_env(
        :elixip2,
        MediaServer.Mendooze,
        Keyword.put(block, :bitrate_feedback, allowed)
      )

      on_exit(fn -> Application.put_env(:elixip2, MediaServer.Mendooze, block) end)

      %{server: server} = start_media_server()
      {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :video)

      offer = """
      v=0
      o=- 1 1 IN IP4 10.0.0.9
      s=-
      c=IN IP4 10.0.0.9
      t=0 0
      m=video 40002 RTP/AVPF 99
      a=rtpmap:99 H264/90000
      a=rtcp-fb:* nack
      a=rtcp-fb:* ccm fir
      a=rtcp-fb:* ccm tmmbr
      a=rtcp-fb:* goog-remb
      """

      assert {:ok, answer} = Mendooze.set_remote_offer(conn, offer)

      for type <- kept, do: assert(answer =~ "a=rtcp-fb:99 #{type}")
      for type <- dropped, do: refute(answer =~ type)

      # The feedback that has nothing to do with rate control is never touched.
      assert answer =~ "a=rtcp-fb:99 nack"
      assert answer =~ "a=rtcp-fb:99 ccm fir"

      # And the server-side switches follow the same set, never the offer's.
      assert_receive {:jsr309_call, "EndpointSetRTPProperties", [_, _, _, props]}
      assert Map.has_key?(props, "remb") == :remb in allowed
      assert Map.has_key?(props, "tmmbr") == :tmmbr in allowed
      assert props["useNACK"] == "1"
      assert props["useRtcpFIR"] == "1"
    end
  end

  # The assumed RFC 4585 §4 deviation (see answered_rtcp_fb/1): endpoints such as
  # Linphone keep a plain RTP/AVP or RTP/SAVP profile while listing a=rtcp-fb, and
  # drive their NACK/FIR off the answer's attributes, not its profile string. The
  # feedback is confirmed; the profile stays what RFC 3264 mirroring dictates.
  test "feedback offered under plain RTP/AVP is confirmed without upgrading the profile" do
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
    a=rtcp-fb:99 nack
    a=rtcp-fb:99 nack pli
    a=rtcp-fb:99 ccm fir
    """

    assert {:ok, answer} = Mendooze.set_remote_offer(conn, offer)

    # no capability negotiation in the offer, so no upgrade and nothing to acfg
    assert answer =~ "m=video 22002 RTP/AVP 99"
    refute answer =~ "RTP/AVPF"
    refute answer =~ "a=acfg"
    # ...but the requested-and-implemented feedback is confirmed anyway,
    # `nack pli` included (it rides the FIR switch, see @supported_rtcp_fb)
    assert answer =~ "a=rtcp-fb:99 nack\r\n"
    assert answer =~ "a=rtcp-fb:99 nack pli"
    assert answer =~ "a=rtcp-fb:99 ccm fir"

    # and the server switches follow the answered set, profile notwithstanding
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

    # nothing at all while the call is not up
    refute_received {:jsr309_call, "EndpointStartRTPTimeout", _}

    assert :ok = Mendooze.call_answered(conn)

    # audio: armed; video: explicitly disarmed; text: never armed at all
    assert_receive {:jsr309_call, "EndpointStartRTPTimeout", [3, 4, 0, audio_ms]}
    assert audio_ms > 0
    assert_receive {:jsr309_call, "EndpointStartRTPTimeout", [3, 4, 1, 0]}
    refute_received {:jsr309_call, "EndpointStartRTPTimeout", [3, 4, 2, _]}
  end

  test "a media the peer holds is disarmed on the spot, and re-armed on resume" do
    %{server: server} = start_media_server()

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio_video)

    assert {:ok, _answer} = Mendooze.set_remote_offer(conn, av_offer())
    assert :ok = Mendooze.call_answered(conn)

    assert_receive {:jsr309_call, "EndpointStartRTPTimeout", [3, 4, 0, ms]} when ms > 0
    assert_receive {:jsr309_call, "EndpointStartRTPTimeout", [3, 4, 1, ms]} when ms > 0

    # hold: the peer says it stops sending video. The re-offer is applied to an
    # ANSWERED leg, so it takes effect at once — waiting for another
    # `call_answered/1` that will never come would leave the media unwatched, and
    # leave a held video watched.
    assert {:ok, _answer} = Mendooze.set_remote_offer(conn, av_offer(%{video: :recvonly}))
    assert_receive {:jsr309_call, "EndpointStartRTPTimeout", [3, 4, 1, 0]}

    # resume: sending again, watched again
    assert {:ok, _answer} = Mendooze.set_remote_offer(conn, av_offer())
    assert_receive {:jsr309_call, "EndpointStartRTPTimeout", [3, 4, 1, ms]} when ms > 0
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
