Code.require_file("support/jsr309_fake_server.exs", __DIR__)

defmodule Mendooze.ServerTest do
  # app env tweaks for the poller are global — keep this file synchronous
  use ExUnit.Case, async: false

  alias MediaServer.Mendooze

  setup do
    previous = Application.get_env(:elixip2, MediaServer.Mendooze, [])

    Application.put_env(:elixip2, MediaServer.Mendooze,
      poller_retry_ms: 50,
      poller_max_failures: 3
    )

    on_exit(fn -> Application.put_env(:elixip2, MediaServer.Mendooze, previous) end)
    :ok
  end

  defp connect!(fake) do
    {:ok, server} = Mendooze.connect({fake.host, fake.port})
    on_exit(fn -> if Process.alive?(server), do: Mendooze.disconnect(server) end)
    server
  end

  test "connect creates the event queue and polls the returned source path" do
    fake = Jsr309FakeServer.start(self())
    server = connect!(fake)

    assert_receive {:jsr309_call, "EventQueueCreate", []}, 1_000
    assert_receive {:stream_conn, _conn, "/events/jsr309/7"}, 1_000
    assert Process.alive?(server)
  end

  test "falls back to /events/jsr309/<queueId> when sourceName is absent" do
    fake =
      Jsr309FakeServer.start(self(), fn
        "EventQueueCreate", _ -> {:ok, [12]}
        _, _ -> {:ok, []}
      end)

    connect!(fake)

    assert_receive {:stream_conn, _conn, "/events/jsr309/12"}, 1_000
  end

  test "connect fails cleanly on a JSR309 error" do
    fake =
      Jsr309FakeServer.start(self(), fn
        "EventQueueCreate", _ -> {:error, "no more queues"}
      end)

    assert {:error, {:jsr309_error, "no more queues"}} =
             Mendooze.connect({fake.host, fake.port})
  end

  test "connect fails cleanly when the server is unreachable" do
    {:ok, lsock} = :gen_tcp.listen(0, [])
    {:ok, port} = :inet.port(lsock)
    :gen_tcp.close(lsock)

    assert {:error, {:failed_connect, _}} = Mendooze.connect({"127.0.0.1", port})
  end

  test "routes events to the Conn registered under their session tag" do
    fake = Jsr309FakeServer.start(self())
    server = connect!(fake)

    assert_receive {:stream_conn, conn, _}, 1_000

    # this test process plays the Conn role
    assert :ok = Mendooze.register_conn(server, "cx-1", self())

    send(conn, {:chunk, Jsr309FakeServer.event_frame([3, "cx-1", "p-1"])})
    assert_receive {:mendooze_event, {:player_started, "cx-1", "p-1"}}, 1_000
  end

  test "drops events for unknown or unregistered session tags" do
    fake = Jsr309FakeServer.start(self())
    server = connect!(fake)

    assert_receive {:stream_conn, conn, _}, 1_000

    assert :ok = Mendooze.register_conn(server, "cx-1", self())
    :ok = Mendooze.unregister_conn(server, "cx-1")

    send(conn, {:chunk, Jsr309FakeServer.event_frame([3, "cx-1", "p-1"])})
    send(conn, {:chunk, Jsr309FakeServer.event_frame([3, "cx-9", "p-9"])})

    refute_receive {:mendooze_event, _}, 300
  end

  test "a dead Conn is removed from the registry" do
    fake = Jsr309FakeServer.start(self())
    server = connect!(fake)

    assert_receive {:stream_conn, conn, _}, 1_000

    test_pid = self()

    conn_pid =
      spawn(fn ->
        Mendooze.register_conn(server, "cx-1", test_pid)
        send(test_pid, :registered)

        receive do
          :die -> :ok
        end
      end)

    assert_receive :registered, 1_000
    send(conn_pid, :die)

    # wait for the DOWN to be processed, then the event must be dropped
    Process.sleep(100)
    send(conn, {:chunk, Jsr309FakeServer.event_frame([3, "cx-1", "p-1"])})
    refute_receive {:mendooze_event, _}, 300
  end

  test "broadcasts :server_disconnected to event sinks when the stream is lost" do
    fake = Jsr309FakeServer.start(self())
    server = connect!(fake)

    assert_receive {:stream_conn, conn, _}, 1_000
    assert :ok = Mendooze.register_conn(server, "cx-1", self())

    # kill the server: no more accepts, and drop the live stream
    Jsr309FakeServer.stop_listening(fake)
    send(conn, :abort)

    # 3 failed reconnections at 50 ms → poller gives up → broadcast
    assert_receive {:ms_event, ^server, :server_disconnected}, 2_000
  end

  test "disconnect deletes the event queue and stops the server" do
    fake = Jsr309FakeServer.start(self())
    {:ok, server} = Mendooze.connect({fake.host, fake.port})

    assert_receive {:jsr309_call, "EventQueueCreate", []}, 1_000

    assert :ok = Mendooze.disconnect(server)
    assert_receive {:jsr309_call, "EventQueueDelete", [7]}, 1_000
    refute Process.alive?(server)

    # idempotent
    assert :ok = Mendooze.disconnect(server)
  end

  test "rpc_info exposes the coordinates Conn processes need" do
    fake = Jsr309FakeServer.start(self())
    server = connect!(fake)

    assert %{base_url: url, queue_id: 7} = Mendooze.rpc_info(server)
    assert url == fake.url
  end
end
