Code.require_file("support/jsr309_fake_server.exs", __DIR__)

defmodule Mendooze.IntegrationTest do
  # touches the global :mediaserver app env — keep synchronous
  use ExUnit.Case, async: false

  alias MediaServer.Mendooze
  alias SIP.Session.Media

  @moduledoc """
  Phase 8 — adapter selection from the `:mediaserver` application config, plus
  an end-to-end media lifecycle against a real Mendooze server (gated by the
  `MENDOOZE_URL` env var, so `mix test` stays green without one).
  """

  setup do
    previous = Application.get_env(:elixip2, :mediaserver)
    on_exit(fn -> Application.put_env(:elixip2, :mediaserver, previous) end)
    :ok
  end

  # ── Config-driven adapter selection (no real server) ────────────────────────

  test "media_connect/0 selects the Mockup adapter by default" do
    Application.put_env(:elixip2, :mediaserver, module: :mockup, url: "sip:localhost:8080")

    ctx = Media.use_mediaserver(%SIP.Context{})

    assert ctx.mediaservermodule == MediaServer.Mockup
    assert is_pid(ctx.mediaserverpid)

    MediaServer.Mockup.disconnect(ctx.mediaserverpid, [])
  end

  test "media_connect/0 selects the Mendooze adapter and connects at its URL" do
    fake = Jsr309FakeServer.start(self())
    Application.put_env(:elixip2, :mediaserver, module: :mendooze, url: fake.url)

    ctx = Media.use_mediaserver(%SIP.Context{})

    assert ctx.mediaservermodule == MediaServer.Mendooze
    assert is_pid(ctx.mediaserverpid)
    assert_receive {:jsr309_call, "EventQueueCreate", []}, 1_000

    Mendooze.disconnect(ctx.mediaserverpid)
  end

  test "an explicit module also works and defaults the URL" do
    fake = Jsr309FakeServer.start(self())
    Application.put_env(:elixip2, :mediaserver, module: MediaServer.Mendooze, url: fake.url)

    ctx = Media.use_mediaserver(%SIP.Context{})
    assert ctx.mediaservermodule == MediaServer.Mendooze

    Mendooze.disconnect(ctx.mediaserverpid)
  end

  # ── End-to-end against a real Mendooze server ───────────────────────────────
  # Run with: MENDOOZE_URL=http://host:8080 mix test test/mendooze_integration_test.exs

  describe "real Mendooze server" do
    @describetag skip: System.get_env("MENDOOZE_URL") == nil && "MENDOOZE_URL not set"

    setup do
      {:ok, server} = Mendooze.connect(System.get_env("MENDOOZE_URL"))
      on_exit(fn -> if Process.alive?(server), do: Mendooze.disconnect(server) end)
      %{server: server}
    end

    test "offer/answer loopback between two endpoints on the server", %{server: server} do
      # A generates an offer; B answers it (UAS); A consumes B's answer (UAC).
      # Both endpoints live on the same real media server — this exercises the
      # full RPC path (session/endpoint create, receive, candidates, crypto,
      # send, watchdog) against the actual server.
      {:ok, pc_a} = Mendooze.create_peer_connection(server, self(), media: :audio)
      {:ok, offer_a} = Mendooze.get_local_offer(pc_a)
      assert offer_a =~ "m=audio"

      {:ok, pc_b} = Mendooze.create_peer_connection(server, self(), media: :audio)
      {:ok, answer_b} = Mendooze.set_remote_offer(pc_b, offer_a)
      assert answer_b =~ "m=audio"

      assert :ok = Mendooze.set_remote_answer(pc_a, answer_b)
      assert_receive {:ms_event, ^pc_a, :ice_connected}, 5_000

      assert :ok = Mendooze.close_peer_connection(pc_b)
      assert :ok = Mendooze.close_peer_connection(pc_a)
    end

    # The one claim P3 rests on and that no unit test can settle: the server
    # accepts a SECOND Endpoint in a MediaSession it already has, and attaches
    # the two to each other. Everything else in the media B2BUA is built on top
    # of it — EndpointAttachToEndpoint takes a single session id, so if this
    # arrangement were refused there would be no other one.
    #
    # Both legs face a peer of their own, which is what a B2BUA is: the inbound
    # one answers a caller's offer, the outbound one offers and reads an answer.
    # The peers are the other endpoint of a plain loopback pair, so the SDP is
    # the server's own and genuinely negotiable.
    test "a B2BUA call is two endpoints of ONE media session, attached", %{server: server} do
      opts = [media: :audio, audio_codec: "PCMU"]

      # The caller, and the inbound leg answering it.
      {:ok, caller} = Mendooze.create_peer_connection(server, self(), opts)
      {:ok, caller_offer} = Mendooze.get_local_offer(caller)

      {:ok, inbound} = Mendooze.create_peer_connection(server, self(), opts)
      {:ok, our_answer} = Mendooze.set_remote_offer(inbound, caller_offer)
      assert :ok = Mendooze.set_remote_answer(caller, our_answer)

      # The outbound leg: a second endpoint IN THE SAME SESSION.
      {:ok, outbound} = Mendooze.create_peer_connection(server, self(), opts ++ [bridge_with: inbound])
      assert outbound == {inbound, :outbound}

      {:ok, our_offer} = Mendooze.get_local_offer(outbound)
      assert our_offer =~ "m=audio"

      {:ok, callee} = Mendooze.create_peer_connection(server, self(), opts)
      {:ok, callee_answer} = Mendooze.set_remote_offer(callee, our_offer)
      assert :ok = Mendooze.set_remote_answer(outbound, callee_answer)

      # …and the attach the whole mode depends on.
      assert :ok = Mendooze.bridge(inbound, outbound, audio: :avoid)

      # Taking it down again leaves both legs usable — hold, not hangup.
      assert :ok = Mendooze.unbridge(inbound, outbound)
      assert :ok = Mendooze.bridge(inbound, outbound, audio: :avoid)

      # Releasing one leg keeps the session; the last one takes it with it.
      assert :ok = Mendooze.close_peer_connection(inbound)
      assert Process.alive?(inbound)
      assert :ok = Mendooze.close_peer_connection(outbound)
      refute Process.alive?(inbound)

      assert :ok = Mendooze.close_peer_connection(callee)
      assert :ok = Mendooze.close_peer_connection(caller)
    end

    # The transcoder chain, against the server that owns the method names. A
    # wrong spelling or arity is a fault here and nothing at all against a
    # mock — and there IS a wrong spelling to fall into: the Java client says
    # `AudioTranscoderDetach`, the server registers `AudioTranscoderDettach`.
    #
    # `:force` rather than `:avoid` on purpose: both legs are configured alike,
    # so they would agree on a codec and be attached directly. Forcing is how the
    # chain gets built at all.
    test "a transcoded bridge is built and torn down on the server", %{server: server} do
      opts = [media: :audio_video, audio_codec: "PCMU", video_codec: "H264"]

      {:ok, caller} = Mendooze.create_peer_connection(server, self(), opts)
      {:ok, caller_offer} = Mendooze.get_local_offer(caller)

      {:ok, inbound} = Mendooze.create_peer_connection(server, self(), opts)
      {:ok, our_answer} = Mendooze.set_remote_offer(inbound, caller_offer)
      assert :ok = Mendooze.set_remote_answer(caller, our_answer)

      {:ok, outbound} =
        Mendooze.create_peer_connection(server, self(), opts ++ [bridge_with: inbound])

      {:ok, our_offer} = Mendooze.get_local_offer(outbound)
      {:ok, callee} = Mendooze.create_peer_connection(server, self(), opts)
      {:ok, callee_answer} = Mendooze.set_remote_offer(callee, our_offer)
      assert :ok = Mendooze.set_remote_answer(outbound, callee_answer)

      # Audio and video both through a transcoder: four chains, and for video the
      # size/fps/bitrate/intra-period the server's own config.h defines.
      assert :ok = Mendooze.bridge(inbound, outbound, audio: :force, video: :force)

      # …and taken down again, transcoders deleted rather than merely detached.
      assert :ok = Mendooze.unbridge(inbound, outbound)

      # Re-bridging after that must work: a transcoder left behind would still be
      # attached and the second build would fail or leak.
      assert :ok = Mendooze.bridge(inbound, outbound, audio: :force, video: :force)

      assert :ok = Mendooze.close_peer_connection(inbound)
      assert :ok = Mendooze.close_peer_connection(outbound)
      assert :ok = Mendooze.close_peer_connection(callee)
      assert :ok = Mendooze.close_peer_connection(caller)
    end

    # The assertion the loopback tests cannot make on their own: `:ice_connected`
    # is the first VALIDATED media packet, and two endpoints with nothing to send
    # never produce one. Give one of them a media source and it becomes
    # observable — over SRTP, which is the case that had never been exercised at
    # all.
    #
    # Needs a file the media server process can open (it runs as root on dev71)
    # AND that has an audio track:
    #     MENDOOZE_MEDIA=/var/lib/kelixip/rec/record.mp4
    #
    # The track part is not a detail. `A.mp4` next to it is video-only, and with
    # it the server says so plainly and then sends nothing:
    #     MP4Streamer opened [A.mp4] audio:0 video:1 text:0
    # which looks exactly like a broken media path from this side.
    @tag timeout: 60_000
    test "with a media source, media really flows and releases :ice_connected", %{server: server} do
      file = System.get_env("MENDOOZE_MEDIA")

      if is_nil(file) do
        IO.puts("skipped: set MENDOOZE_MEDIA to a file the media server can open")
      else
        opts = [media: :audio, audio_codec: "PCMU", webrtc_support: :yes]

        {:ok, pc_a} = Mendooze.create_peer_connection(server, self(), opts)
        {:ok, offer_a} = Mendooze.get_local_offer(pc_a)
        assert offer_a =~ "UDP/TLS/RTP/SAVPF"

        {:ok, pc_b} = Mendooze.create_peer_connection(server, self(), opts)
        {:ok, answer_b} = Mendooze.set_remote_offer(pc_b, offer_a)
        assert :ok = Mendooze.set_remote_answer(pc_a, answer_b)

        # pc_b now has something to send, so pc_a has something to validate.
        assert {:ok, player} = Mendooze.create_player(pc_b, file, [])
        assert :ok = Mendooze.start_player(player)

        assert_receive {:ms_event, ^pc_a, {:media_connected, :audio}}, 20_000
        assert_receive {:ms_event, ^pc_a, :ice_connected}, 20_000

        assert :ok = Mendooze.stop_player(player)
        assert :ok = Mendooze.close_peer_connection(pc_b)
        assert :ok = Mendooze.close_peer_connection(pc_a)
      end
    end

    test "H264 audio+video loopback carries the server-negotiated fmtp", %{server: server} do
      # Delegated SDP negotiation (§8.1 of docs/design/DESIGN-FRAMEWORK.md#63-the-mendooze-adapter): the media
      # server is authoritative for the H264 fmtp (profile-level-id /
      # packetization-mode). This asserts the fmtp reaches both the offer and the
      # answer, i.e. the enriched EndpointStartReceiving return is threaded
      # end-to-end — the whole point of the delegation work.
      opts = [media: :audio_video, audio_codec: "PCMU", video_codec: "H264"]

      {:ok, pc_a} = Mendooze.create_peer_connection(server, self(), opts)
      {:ok, offer_a} = Mendooze.get_local_offer(pc_a)
      assert offer_a =~ "m=video"
      assert offer_a =~ ~r{a=rtpmap:\d+ H264/90000}
      # the server owns the fmtp — a profile-level-id line is present
      assert offer_a =~ ~r{a=fmtp:\d+ [^\r\n]*profile-level-id}

      {:ok, pc_b} = Mendooze.create_peer_connection(server, self(), opts)
      {:ok, answer_b} = Mendooze.set_remote_offer(pc_b, offer_a)
      assert answer_b =~ "m=video"
      assert answer_b =~ ~r{a=rtpmap:\d+ H264/90000}
      # the answer honors the offerer's payload type and re-attaches the fmtp
      assert answer_b =~ ~r{a=fmtp:\d+ [^\r\n]*profile-level-id}

      assert :ok = Mendooze.set_remote_answer(pc_a, answer_b)
      assert_receive {:ms_event, ^pc_a, :ice_connected}, 5_000

      assert :ok = Mendooze.close_peer_connection(pc_b)
      assert :ok = Mendooze.close_peer_connection(pc_a)
    end

    test "WebRTC-shaped offer/answer loopback (both legs webrtc)", %{server: server} do
      # Phase 4 (DESIGN-FRAMEWORK.md test 9): both endpoints negotiate the
      # WebRTC transport plane. pc_a offers setup:actpass; pc_b answers, so one
      # side runs DTLS as client and the other as server — the split the server
      # side (branch feat/webrtc-improvement) had to support.
      opts = [media: :audio_video, audio_codec: "OPUS", video_codec: "H264", webrtc_support: :yes]

      {:ok, pc_a} = Mendooze.create_peer_connection(server, self(), opts)
      {:ok, offer_a} = Mendooze.get_local_offer(pc_a)

      # the offer carries the full browser-shaped transport plane
      assert offer_a =~ "UDP/TLS/RTP/SAVPF"
      assert offer_a =~ "a=setup:actpass"
      assert offer_a =~ "a=ice-ufrag:"
      assert offer_a =~ "a=fingerprint:sha-256 "
      assert offer_a =~ "a=rtcp-mux"
      assert offer_a =~ "a=mid:audio"
      assert offer_a =~ "a=mid:video"
      assert offer_a =~ ~r{a=candidate:\d+ 1 udp \d+ }
      # rtcp-fb on the video PTs
      assert offer_a =~ ~r{a=rtcp-fb:\d+ nack}

      {:ok, pc_b} = Mendooze.create_peer_connection(server, self(), opts)
      {:ok, answer_b} = Mendooze.set_remote_offer(pc_b, offer_a)
      assert answer_b =~ "a=fingerprint:sha-256 "
      assert answer_b =~ "a=ice-ufrag:"

      assert :ok = Mendooze.set_remote_answer(pc_a, answer_b)

      # Deliberately NOT `assert_receive :ice_connected` — this setup cannot
      # produce it, and asserting it made the test red for as long as it has
      # existed. The server's own log (2026-08-10, dev71) settles why: the DTLS
      # handshake completes on both medias ("DTLS handshake done",
      # "onDTLSSetup for [Audio]" / "[Video]"), and then no connectivity event is
      # emitted at all.
      #
      # Which is correct of it. `:ice_connected` is the first *validated* media
      # packet — for WebRTC, a decrypted SRTP one — and neither endpoint has a
      # media source, so no SRTP media is ever produced. The plain-RTP loopback
      # above happens to produce a packet the server validates; an SRTP pair with
      # nothing to send cannot. Give one of them a player and it does: the
      # MENDOOZE_MEDIA test below asserts exactly that, over SRTP.
      #
      # Asserting connectivity here for real needs a media source — see the
      # `MENDOOZE_MEDIA` test below, which attaches a player and then does assert
      # it. What THIS test establishes is its title: both legs negotiate a
      # browser-shaped transport plane, and each consumes the other's.

      assert :ok = Mendooze.close_peer_connection(pc_b)
      assert :ok = Mendooze.close_peer_connection(pc_a)
    end

    test "player lifecycle on a real endpoint", %{server: server} do
      {:ok, pc} = Mendooze.create_peer_connection(server, self(), media: :audio)
      {:ok, _offer} = Mendooze.get_local_offer(pc)

      file = System.get_env("MENDOOZE_MEDIA", "/tmp/annonce.mp4")

      case Mendooze.create_player(pc, file, []) do
        {:ok, player} ->
          assert :ok = Mendooze.start_player(player)
          # PlayerStartedEvent comes back over the real event stream
          assert_receive {:ms_event, ^player, :player_started}, 5_000
          assert :ok = Mendooze.stop_player(player)

        {:error, reason} ->
          # the media file may be absent on the server — don't fail the suite,
          # the RPC path itself was exercised
          IO.puts("player creation skipped: #{inspect(reason)}")
      end

      assert :ok = Mendooze.close_peer_connection(pc)
    end

    test "echo on a real endpoint", %{server: server} do
      {:ok, pc} = Mendooze.create_peer_connection(server, self(), media: :audio)
      {:ok, _offer} = Mendooze.get_local_offer(pc)

      assert {:ok, echo} = Mendooze.create_echo(pc)
      assert_receive {:ms_event, ^echo, :echo_started}, 2_000
      assert :ok = Mendooze.stop_echo(echo)

      assert :ok = Mendooze.close_peer_connection(pc)
    end
  end
end
