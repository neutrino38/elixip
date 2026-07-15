Code.require_file("support/jsr309_fake_server.exs", __DIR__)

defmodule Mendooze.MediaTest do
  # shares the fake-server + app-env pattern of the other mendooze files
  use ExUnit.Case, async: false

  alias MediaServer.Mendooze

  @moduledoc """
  Player / Recorder / Echo sub-resources of a Mendooze peer connection:
  RPC sequences per the server doc (§6.3/§6.4) and tag-based routing of the
  lifecycle events (types 1, 3, 4, 5).
  """

  defp rpc_handler("EventQueueCreate", _), do: {:ok, [7, "/events/jsr309/7"]}
  defp rpc_handler("MediaSessionCreate", _), do: {:ok, [3]}
  defp rpc_handler("EndpointCreate", _), do: {:ok, [4]}
  defp rpc_handler("EndpointStartReceiving", _), do: {:ok, [22_000]}
  defp rpc_handler("GetMediaCandidates", _), do: {:ok, ["rtp://192.168.5.5:22000"]}
  defp rpc_handler("PlayerCreate", _), do: {:ok, [10]}
  defp rpc_handler("RecorderCreate", _), do: {:ok, [11]}
  defp rpc_handler(_method, _params), do: {:ok, []}

  defp start_conn(conn_opts \\ [media: :audio]) do
    fake = Jsr309FakeServer.start(self(), &rpc_handler/2)
    {:ok, server} = Mendooze.connect({fake.host, fake.port})
    on_exit(fn -> if Process.alive?(server), do: Mendooze.disconnect(server) end)

    assert_receive {:stream_conn, stream, _}, 1_000

    {:ok, conn} = Mendooze.create_peer_connection(server, self(), conn_opts)
    assert_receive {:jsr309_call, "MediaSessionCreate", [sess_tag, 7]}
    %{server: server, conn: conn, stream: stream, sess_tag: sess_tag}
  end

  # ── Player ──────────────────────────────────────────────────────────────────

  test "create_player creates, opens and attaches the player per media" do
    %{conn: conn} = start_conn()

    assert {:ok, {^conn, :player, _ref}} =
             Mendooze.create_player(conn, "/media/annonce.mp4", [])

    assert_receive {:jsr309_call, "PlayerCreate", [3, "p-0"]}
    assert_receive {:jsr309_call, "PlayerOpen", [3, 10, "/media/annonce.mp4"]}
    assert_receive {:jsr309_call, "EndpointAttachToPlayer", [3, 4, 10, 0]}
    refute_received {:jsr309_call, "EndpointAttachToPlayer", _}
  end

  test "an audio+video player attaches both medias and honors start_time" do
    %{conn: conn} = start_conn([])

    assert {:ok, _player} = Mendooze.create_player(conn, "/media/clip.mp4", start_time: 1_500)

    assert_receive {:jsr309_call, "EndpointAttachToPlayer", [3, 4, 10, 0]}
    assert_receive {:jsr309_call, "EndpointAttachToPlayer", [3, 4, 10, 1]}
    assert_receive {:jsr309_call, "PlayerSeek", [3, 10, 1_500]}
  end

  test "a failed PlayerOpen frees the created player" do
    fake =
      Jsr309FakeServer.start(self(), fn
        "PlayerOpen", _ -> {:error, "no such file"}
        m, p -> rpc_handler(m, p)
      end)

    {:ok, server} = Mendooze.connect({fake.host, fake.port})
    on_exit(fn -> if Process.alive?(server), do: Mendooze.disconnect(server) end)
    {:ok, conn} = Mendooze.create_peer_connection(server, self(), media: :audio)

    assert {:error, {:jsr309_error, "no such file"}} =
             Mendooze.create_player(conn, "/media/missing.mp4", [])

    assert_receive {:jsr309_call, "PlayerDelete", [3, 10]}
  end

  test "start_player plays and the server PlayerStartedEvent reaches the sink" do
    %{conn: conn, stream: stream, sess_tag: sess_tag} = start_conn()

    {:ok, player} = Mendooze.create_player(conn, "/media/annonce.mp4", [])

    assert :ok = Mendooze.start_player(player)
    assert_receive {:jsr309_call, "PlayerPlay", [3, 10]}

    send(stream, {:chunk, Jsr309FakeServer.event_frame([3, sess_tag, "p-0"])})
    assert_receive {:ms_event, ^player, :player_started}, 1_000

    send(stream, {:chunk, Jsr309FakeServer.event_frame([1, sess_tag, "p-0"])})
    assert_receive {:ms_event, ^player, :player_ended}, 1_000
  end

  test "a looping player rewinds on end of file instead of reporting it" do
    %{conn: conn, stream: stream, sess_tag: sess_tag} = start_conn()

    {:ok, player} = Mendooze.create_player(conn, "/media/annonce.mp4", loop: true)
    :ok = Mendooze.start_player(player)

    send(stream, {:chunk, Jsr309FakeServer.event_frame([1, sess_tag, "p-0"])})

    assert_receive {:jsr309_call, "PlayerSeek", [3, 10, 0]}, 1_000
    assert_receive {:jsr309_call, "PlayerPlay", [3, 10]}, 1_000
    refute_received {:ms_event, _, :player_ended}
  end

  test "pause_player stops without deleting; stop_player detaches and deletes" do
    %{conn: conn} = start_conn()

    {:ok, player} = Mendooze.create_player(conn, "/media/annonce.mp4", [])

    assert :ok = Mendooze.pause_player(player)
    assert_receive {:jsr309_call, "PlayerStop", [3, 10]}

    assert :ok = Mendooze.stop_player(player)
    assert_receive {:jsr309_call, "PlayerStop", [3, 10]}
    assert_receive {:jsr309_call, "EndpointDettach", [3, 4, 0]}
    assert_receive {:jsr309_call, "PlayerClose", [3, 10]}
    assert_receive {:jsr309_call, "PlayerDelete", [3, 10]}

    # the player handle is gone
    assert {:error, :no_such_player} = Mendooze.start_player(player)
  end

  # ── Recorder ────────────────────────────────────────────────────────────────

  test "recorder lifecycle: create, record with maxDuration, server events, stop" do
    %{conn: conn, stream: stream, sess_tag: sess_tag} = start_conn()

    assert {:ok, {^conn, :recorder, _ref} = recorder} =
             Mendooze.create_recorder(conn, "/rec/call.mp4", 30_000, [])

    assert_receive {:jsr309_call, "RecorderCreate", [3, "r-0"]}
    assert_receive {:jsr309_call, "RecorderAttachToEndpoint", [3, 11, 4, 0]}

    assert :ok = Mendooze.start_recorder(recorder)
    # defaults: waitVideo=1, echoVideo=0
    assert_receive {:jsr309_call, "RecorderRecord", [3, 11, "/rec/call.mp4", 30_000, 1, 0]}

    send(stream, {:chunk, Jsr309FakeServer.event_frame([4, sess_tag, "r-0"])})
    assert_receive {:ms_event, ^recorder, :recorder_started}, 1_000

    # max duration reached server-side
    send(stream, {:chunk, Jsr309FakeServer.event_frame([5, sess_tag, "r-0", 1])})
    assert_receive {:ms_event, ^recorder, {:recorder_stopped, :duration}}, 1_000
  end

  test "recorder options wait_video: false and echo: true map to RecorderRecord params" do
    %{conn: conn} = start_conn()

    {:ok, recorder} =
      Mendooze.create_recorder(conn, "/rec/call.mp4", 0, wait_video: false, echo: true)

    assert :ok = Mendooze.start_recorder(recorder)
    assert_receive {:jsr309_call, "RecorderRecord", [3, 11, "/rec/call.mp4", 0, 0, 1]}
  end

  test "stop_recorder stops, detaches, deletes and routes the final event" do
    %{conn: conn, stream: stream, sess_tag: sess_tag} = start_conn()

    {:ok, recorder} = Mendooze.create_recorder(conn, "/rec/call.mp4", 0, [])
    :ok = Mendooze.start_recorder(recorder)

    assert :ok = Mendooze.stop_recorder(recorder)
    assert_receive {:jsr309_call, "RecorderStop", [3, 11]}
    assert_receive {:jsr309_call, "RecorderDettach", [3, 11, 0]}
    assert_receive {:jsr309_call, "RecorderDelete", [3, 11]}

    # the server confirms with RecorderStoppedEvent(reason=0)
    send(stream, {:chunk, Jsr309FakeServer.event_frame([5, sess_tag, "r-0", 0])})
    assert_receive {:ms_event, ^recorder, {:recorder_stopped, :caller}}, 1_000

    # entry dropped once the final event was delivered
    assert {:error, :no_such_recorder} = Mendooze.start_recorder(recorder)
  end

  # ── Echo ────────────────────────────────────────────────────────────────────

  test "echo attaches the endpoint to itself and reports :echo_started" do
    %{conn: conn} = start_conn([])

    assert {:ok, {^conn, :echo, _ref} = echo} = Mendooze.create_echo(conn)

    assert_receive {:jsr309_call, "EndpointAttachToEndpoint", [3, 4, 4, 0]}
    assert_receive {:jsr309_call, "EndpointAttachToEndpoint", [3, 4, 4, 1]}
    assert_receive {:ms_event, ^echo, :echo_started}

    # only one echo per connection
    assert {:error, :echo_already_started} = Mendooze.create_echo(conn)

    assert :ok = Mendooze.stop_echo(echo)
    assert_receive {:jsr309_call, "EndpointDettach", [3, 4, 0]}
    assert_receive {:jsr309_call, "EndpointDettach", [3, 4, 1]}

    # a second echo can then be started
    assert {:ok, _echo2} = Mendooze.create_echo(conn)
  end
end
