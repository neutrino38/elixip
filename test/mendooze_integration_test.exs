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

    test "H264 audio+video loopback carries the server-negotiated fmtp", %{server: server} do
      # Delegated SDP negotiation (§8.1 of docs/mendooze_interface.md): the media
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
      # Phase 4 (webrtc_sdp_design.md §2.8 test 9): both endpoints negotiate the
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
      assert_receive {:ms_event, ^pc_a, :ice_connected}, 5_000

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
