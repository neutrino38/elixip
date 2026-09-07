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


  describe "addressing profiles are asked for, never configured" do
    defp profiles_handler(profiles) do
      fn
        "EventQueueCreate", _ -> {:ok, [7, "/events/jsr309/7"]}
        "GetNetworkProfiles", _ -> {:ok, profiles}
        _, _ -> {:ok, []}
      end
    end

    defp profile(name, opts \\ []) do
      %{
        "name" => name,
        "available" => Keyword.get(opts, :available, false),
        "announced" => Keyword.get(opts, :announced, ""),
        "bind" => Keyword.get(opts, :bind, ""),
        "default" => Keyword.get(opts, :default, false)
      }
    end

    test "the four profiles are read at connect and kept as the server states them" do
      fake =
        Jsr309FakeServer.start(
          self(),
          profiles_handler([
            profile("publicv4", available: true, announced: "203.0.113.9", bind: "", default: true),
            profile("publicv6", available: true, announced: "2001:db8::12", bind: "2001:db8::12"),
            profile("internalv4", available: true, announced: "10.0.0.4", bind: "10.0.0.4"),
            profile("internalv6")
          ])
        )

      server = connect!(fake)
      assert_receive {:jsr309_call, "GetNetworkProfiles", []}, 1_000

      profiles = Mendooze.network_profiles(server)

      assert %{
               "publicv4" => %{available: true, announced: "203.0.113.9", default: true},
               "publicv6" => %{available: true, announced: "2001:db8::12", bind: "2001:db8::12"},
               "internalv4" => %{available: true, announced: "10.0.0.4"},
               "internalv6" => %{available: false, announced: "", default: false}
             } = profiles

      # A profile the server does not carry is reported, not omitted: the caller
      # has to be able to tell "not available" from "not answered".
      assert map_size(profiles) == 4
    end

    test "a server that does not know the method is :unsupported, not an error" do
      fake =
        Jsr309FakeServer.start(self(), fn
          "EventQueueCreate", _ -> {:ok, [7, "/events/jsr309/7"]}
          "GetNetworkProfiles", _ -> {:error, "unknown method"}
          _, _ -> {:ok, []}
        end)

      server = connect!(fake)
      assert_receive {:jsr309_call, "GetNetworkProfiles", []}, 1_000

      # Connected all the same: a leg then carries no profile, which is exactly
      # what a controller that never heard of them does.
      assert Process.alive?(server)
      assert Mendooze.network_profiles(server) == :unsupported
    end

    test "an answer naming no profile is :unsupported too" do
      fake = Jsr309FakeServer.start(self(), profiles_handler([]))
      server = connect!(fake)

      assert Mendooze.network_profiles(server) == :unsupported
    end
  end

  describe "the media server's self-description is asked for, never configured" do
    @status %{
      "server" => %{"product" => "mediaserver", "version" => "1.14.0", "uptimeSecs" => 42},
      "capabilities" => %{
        "audio" => %{"decode" => ["OPUS", "PCMU"], "encode" => ["OPUS", "PCMU"]},
        "video" => %{"decode" => ["H264", "VP6"], "encode" => ["H264"]},
        "text" => %{"rfc4103" => true, "rfc8865" => true, "websocket" => true}
      },
      "security" => %{"modes" => ["none", "sdes-srtp", "dtls-srtp"]},
      "load" => %{"conferences" => 0}
    }

    # Mirrors profiles_handler/1: only EventQueueCreate has to answer for real.
    defp status_handler do
      fn
        "EventQueueCreate", _ -> {:ok, [7, "/events/jsr309/7"]}
        _, _ -> {:ok, []}
      end
    end

    test "the body is read at connect and kept exactly as the server stated it" do
      fake = Jsr309FakeServer.start(self(), status_handler(), status: @status)
      server = connect!(fake)

      assert_receive {:status_get, "/status/general"}, 1_000

      # Verbatim. Reshaping it here would be a copy of what the server knows about
      # itself, and a copy drifts — the whole reason this is asked for.
      assert Mendooze.server_status(server) == @status
    end

    test "both codec directions come back, and they are NOT the same list" do
      fake = Jsr309FakeServer.start(self(), status_handler(), status: @status)
      server = connect!(fake)

      caps = Mendooze.server_status(server)["capabilities"]

      # VP6 decodes and never encodes. A caller reading one list for both
      # directions would offer the server a stream it cannot produce.
      assert "VP6" in caps["video"]["decode"]
      refute "VP6" in caps["video"]["encode"]
    end

    test "a server without the endpoint is :unsupported, and still connects" do
      # No `status:` option: the fake answers 404, like an older binary.
      fake = Jsr309FakeServer.start(self())
      server = connect!(fake)

      assert_receive {:status_get, "/status/general"}, 1_000
      assert Process.alive?(server)
      assert Mendooze.server_status(server) == :unsupported
    end

    test "a body that is not JSON is :unsupported, not a crash" do
      fake =
        Jsr309FakeServer.start(self(), status_handler(),
          status: {:raw, "<html>System is running</html>"}
        )

      server = connect!(fake)

      # What the endpoint answered BEFORE it spoke JSON. It must not take the
      # connection down with it.
      assert Process.alive?(server)
      assert Mendooze.server_status(server) == :unsupported
    end

    test "a JSON body that is not an object is :unsupported" do
      fake =
        Jsr309FakeServer.start(self(), status_handler(),
          status: {:raw, "[1,2,3]"}
        )

      server = connect!(fake)

      assert Mendooze.server_status(server) == :unsupported
    end
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
    Jsr309FakeServer.await_streaming(server, conn)

    # this test process plays the Conn role
    assert :ok = Mendooze.register_conn(server, "cx-1", self())

    send(conn, {:chunk, Jsr309FakeServer.event_frame([3, "cx-1", "p-1"])})
    assert_receive {:mendooze_event, {:player_started, "cx-1", "p-1"}}, 1_000
  end

  test "drops events for unknown or unregistered session tags" do
    fake = Jsr309FakeServer.start(self())
    server = connect!(fake)

    assert_receive {:stream_conn, conn, _}, 1_000
    Jsr309FakeServer.await_streaming(server, conn)

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
    Jsr309FakeServer.await_streaming(server, conn)

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

  test "a 404 on the stream path stops the poller instead of retrying for ever" do
    # the queue is gone server-side: every retry would 404 again
    fake =
      Jsr309FakeServer.start(
        self(),
        fn
          "EventQueueCreate", _ -> {:ok, [7, "/events/jsr309/7"]}
          _, _ -> {:ok, []}
        end,
        stream_status: 404
      )

    server = connect!(fake)

    assert_receive {:stream_404, "/events/jsr309/7"}, 1_000
    poller = :sys.get_state(server).poller

    # retry_ms is 50 ms here: a retry loop would show up well within 500 ms
    refute_receive {:stream_404, _}, 500
    refute Process.alive?(poller)
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
