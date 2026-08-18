defmodule SIP.Test.Media.Bridge do
  @moduledoc """
  `bridge/3` and `unbridge/2` (B2BUA P3 R2 — design
  docs/design/b2bua_media_impl_plan.md §0).

  The verb FSL needs is one call taking two peer connections. What it means
  underneath is not: on a real server the two legs are two endpoints of one
  media session, attached per media once BOTH have negotiated
  (docs/design/mediagw_b2bua_jsr309.md §3). `MediaServer.Mockup` implements it as
  an actual media path rather than a recorded call, so what these tests assert is
  a datagram coming out of the other leg.
  """
  use ExUnit.Case

  alias MediaServer.Mockup

  setup do
    {:ok, server} = Mockup.connect("sip:localhost:8080")
    on_exit(fn -> if Process.alive?(server), do: Mockup.disconnect(server, force: true) end)
    %{server: server}
  end

  # A peer connection with a UA of our own on the far end: the socket that will
  # send into the leg and receive out of it. `answer` is what the leg replied to
  # that UA's offer, which is where the leg listens.
  defp leg_with_peer(server) do
    {:ok, conn} = Mockup.create_peer_connection(server, self(), media: :audio)
    {:ok, socket} = Socket.UDP.open(mode: :active)
    :ok = Socket.UDP.process(socket, self())
    {:ok, {_bound, port}} = Socket.local(socket)

    {:ok, answer} = Mockup.set_remote_offer(conn, offer_sdp(port))
    %{conn: conn, socket: socket, port: port, leg_port: media_port(answer)}
  end

  defp offer_sdp(port) do
    """
    v=0\r
    o=- 1 1 IN IP4 127.0.0.1\r
    s=-\r
    c=IN IP4 127.0.0.1\r
    t=0 0\r
    m=audio #{port} RTP/AVP 0\r
    a=rtpmap:0 PCMU/8000\r
    """
  end

  defp media_port(sdp) do
    [_, port] = Regex.run(~r/^m=audio (\d+)/m, sdp)
    String.to_integer(port)
  end

  # Send a datagram into `leg` as its peer would, from that peer's own socket.
  defp send_into(peer, payload) do
    Socket.Datagram.send(peer.socket, payload, {{127, 0, 0, 1}, peer.leg_port})
  end

  describe "bridge/3" do
    test "media entering one leg comes out of the other", %{server: server} do
      a = leg_with_peer(server)
      b = leg_with_peer(server)

      assert :ok = Mockup.bridge(a.conn, b.conn, audio: :avoid, video: :avoid)

      # A packet from A's peer must reach B's peer — through B's own socket, at
      # the address B's peer announced in its SDP. Nothing had ever been received
      # on B, so this only works because the leg addresses the SDP rather than
      # waiting to be spoken to first.
      send_into(a, "from-a")
      assert_receive {:udp, _sock, _ip, _port, "from-a"}, 2_000

      # …and symmetrically, which is two independent directions and not one
      # loopback: the reply leaves A's socket.
      send_into(b, "from-b")
      assert_receive {:udp, _sock, _ip, _port, "from-b"}, 2_000
    end

    test "a bad transcoding policy is refused at the call, not inside the server", %{
      server: server
    } do
      a = leg_with_peer(server)
      b = leg_with_peer(server)

      assert {:error, {:bad_transcoding_policy, :audio, :sometimes}} =
               Mockup.bridge(a.conn, b.conn, audio: :sometimes)

      assert {:error, {:bad_transcoding_policy, :video, true}} =
               Mockup.bridge(a.conn, b.conn, video: true)

      # …and nothing was wired in the meantime.
      send_into(a, "refused")
      refute_receive {:udp, _sock, _ip, _port, "refused"}, 500
    end

    test "an empty policy is the default, and bridging twice is not an error", %{server: server} do
      a = leg_with_peer(server)
      b = leg_with_peer(server)

      assert :ok = Mockup.bridge(a.conn, b.conn, [])
      assert :ok = Mockup.bridge(a.conn, b.conn, [])

      send_into(a, "once")
      assert_receive {:udp, _sock, _ip, _port, "once"}, 2_000
      refute_receive {:udp, _sock, _ip, _port, "once"}, 500
    end
  end

  describe "unbridge/2" do
    test "takes the media path down and leaves both connections up", %{server: server} do
      a = leg_with_peer(server)
      b = leg_with_peer(server)
      :ok = Mockup.bridge(a.conn, b.conn, [])

      send_into(a, "before")
      assert_receive {:udp, _sock, _ip, _port, "before"}, 2_000

      assert :ok = Mockup.unbridge(a.conn, b.conn)

      send_into(a, "after")
      refute_receive {:udp, _sock, _ip, _port, "after"}, 500

      # Hold, not hangup: both legs are still there and can be re-bridged.
      assert Process.alive?(a.conn) and Process.alive?(b.conn)
      assert :ok = Mockup.bridge(a.conn, b.conn, [])
      send_into(a, "again")
      assert_receive {:udp, _sock, _ip, _port, "again"}, 2_000
    end

    test "a pair that was never bridged is not an error", %{server: server} do
      a = leg_with_peer(server)
      b = leg_with_peer(server)
      assert :ok = Mockup.unbridge(a.conn, b.conn)
    end

    test "a leg that is already gone is not an error", %{server: server} do
      a = leg_with_peer(server)
      b = leg_with_peer(server)
      :ok = Mockup.bridge(a.conn, b.conn, [])

      :ok = Mockup.close_peer_connection(b.conn)
      assert :ok = Mockup.unbridge(a.conn, b.conn)

      # And the surviving leg does not die trying to relay into the dead one.
      send_into(a, "orphan")
      assert Process.alive?(a.conn)
    end
  end

  describe "the policy vocabulary" do
    test "defaults to :avoid on both medias and accepts the three values" do
      assert {:ok, %{audio: :avoid, video: :avoid}} = MediaServer.transcoding_policy([])

      for value <- [:force, :avoid, :forbid] do
        assert {:ok, %{audio: ^value}} = MediaServer.transcoding_policy(audio: value)
        assert {:ok, %{video: ^value}} = MediaServer.transcoding_policy(video: value)
      end
    end
  end
end
