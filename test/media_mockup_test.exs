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
end
