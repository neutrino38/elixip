defmodule Mendooze.EventPollerTest do
  use ExUnit.Case, async: true

  alias MediaServer.Mendooze.EventPoller

  @moduledoc """
  Tests for the JSR309 event poller: pure frame/event decoding, then the
  polling task against an in-test chunked HTTP server driven by messages
  ({:chunk, data} / :finish / :abort).
  """

  defp event_frame(param) do
    XMLRPC.encode!(%XMLRPC.MethodResponse{param: param})
  end

  # ── decode_frames/1 ─────────────────────────────────────────────────────────

  describe "decode_frames/1" do
    test "extracts a single complete frame" do
      frame = event_frame([3, "cx-1", "p-1"])
      assert {[^frame], ""} = EventPoller.decode_frames(frame)
    end

    test "keeps an incomplete frame in the rest" do
      frame = event_frame([3, "cx-1", "p-1"])
      {head, tail} = String.split_at(frame, 40)

      assert {[], rest} = EventPoller.decode_frames(head)
      assert {[full], ""} = EventPoller.decode_frames(rest <> tail)
      assert full == frame
    end

    test "extracts several frames from one buffer" do
      f1 = event_frame([3, "cx-1", "p-1"])
      f2 = event_frame([1, "cx-1", "p-1"])

      assert {[^f1, ^f2], ""} = EventPoller.decode_frames(f1 <> f2)
    end

    test "discards keep-alive CRLF between frames" do
      f1 = event_frame([4, "cx-2", "r-1"])

      assert {[^f1], ""} = EventPoller.decode_frames("\r\n\r\n" <> f1 <> "\r\n")
    end

    test "keep-alive alone yields nothing" do
      assert {[], ""} = EventPoller.decode_frames("\r\n")
    end
  end

  # ── decode_event/1 ──────────────────────────────────────────────────────────

  describe "decode_event/1" do
    test "decodes the seven JSR309 event types" do
      cases = [
        {[1, "cx-1", "p-1"], {:player_end_of_file, "cx-1", "p-1"}},
        {[2, "cx-1", 4, 1, 0], {:external_fir, "cx-1", 4, :video}},
        {[3, "cx-1", "p-1"], {:player_started, "cx-1", "p-1"}},
        {[4, "cx-1", "r-1"], {:recorder_started, "cx-1", "r-1"}},
        {[5, "cx-1", "r-1", 1], {:recorder_stopped, "cx-1", "r-1", :duration}},
        {[6, "cx-1", 4, 0, 0], {:endpoint_disconnected, "cx-1", 4, :audio}},
        {[7, "cx-1", 4, 0, 0], {:endpoint_connected, "cx-1", 4, :audio}}
      ]

      for {param, expected} <- cases do
        assert {:ok, ^expected} = EventPoller.decode_event(event_frame(param))
      end
    end

    test "maps all recorder stop reasons" do
      for {code, reason} <- [{0, :caller}, {1, :duration}, {2, :silence}, {3, :dtmf}] do
        assert {:ok, {:recorder_stopped, _, _, ^reason}} =
                 EventPoller.decode_event(event_frame([5, "cx", "r", code]))
      end
    end

    test "unknown event type is an error" do
      assert {:error, {:unknown_event, [99 | _]}} =
               EventPoller.decode_event(event_frame([99, "cx-1"]))
    end

    test "garbage frame is a decode error" do
      assert {:error, {:decode_error, _}} = EventPoller.decode_event("<not-xmlrpc/>")
    end
  end

  # ── Fake chunked HTTP server ────────────────────────────────────────────────
  # Accepts sequential connections; for each one, sends the chunked response
  # headers, notifies the test with {:stream_conn, pid, path}, then obeys
  # {:chunk, data} / :finish / :abort commands.

  defp start_stream_server(test_pid) do
    {:ok, lsock} =
      :gen_tcp.listen(0, [:binary, packet: :http_bin, active: false, reuseaddr: true])

    {:ok, port} = :inet.port(lsock)
    Task.start_link(fn -> accept_loop(lsock, test_pid) end)
    "http://127.0.0.1:#{port}"
  end

  defp accept_loop(lsock, test_pid) do
    case :gen_tcp.accept(lsock) do
      {:ok, sock} ->
        {:ok, {:http_request, :GET, {:abs_path, path}, _}} = :gen_tcp.recv(sock, 0)
        drain_headers(sock)
        :ok = :inet.setopts(sock, packet: :raw)

        :gen_tcp.send(
          sock,
          "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ncontent-type: text/xml\r\n\r\n"
        )

        send(test_pid, {:stream_conn, self(), path})
        conn_commands(sock)
        accept_loop(lsock, test_pid)

      {:error, _} ->
        :ok
    end
  end

  defp drain_headers(sock) do
    case :gen_tcp.recv(sock, 0) do
      {:ok, :http_eoh} -> :ok
      {:ok, _header} -> drain_headers(sock)
    end
  end

  defp conn_commands(sock) do
    receive do
      {:chunk, data} ->
        :gen_tcp.send(sock, [Integer.to_string(byte_size(data), 16), "\r\n", data, "\r\n"])
        conn_commands(sock)

      :finish ->
        :gen_tcp.send(sock, "0\r\n\r\n")
        :gen_tcp.close(sock)

      :abort ->
        :gen_tcp.close(sock)
    end
  end

  defp start_poller(base_url, opts \\ []) do
    {:ok, poller} =
      EventPoller.start_link(
        Keyword.merge(
          [base_url: base_url, source_path: "/events/jsr309/7", sink: self(), retry_ms: 50],
          opts
        )
      )

    poller
  end

  # ── Poller behaviour ────────────────────────────────────────────────────────

  test "polls the source path and delivers decoded events" do
    base_url = start_stream_server(self())
    start_poller(base_url)

    assert_receive {:stream_conn, conn, "/events/jsr309/7"}, 1_000

    send(conn, {:chunk, event_frame([3, "cx-1", "p-1"])})
    assert_receive {:mendooze_event, {:player_started, "cx-1", "p-1"}}, 1_000

    send(conn, {:chunk, event_frame([5, "cx-1", "r-1", 0])})
    assert_receive {:mendooze_event, {:recorder_stopped, "cx-1", "r-1", :caller}}, 1_000
  end

  test "keep-alive chunks are ignored" do
    base_url = start_stream_server(self())
    start_poller(base_url)

    assert_receive {:stream_conn, conn, _}, 1_000

    send(conn, {:chunk, "\r\n"})
    send(conn, {:chunk, event_frame([1, "cx-1", "p-1"])})

    assert_receive {:mendooze_event, {:player_end_of_file, "cx-1", "p-1"}}, 1_000
    refute_received {:mendooze_event, _}
  end

  test "an event frame split across two chunks is reassembled" do
    base_url = start_stream_server(self())
    start_poller(base_url)

    assert_receive {:stream_conn, conn, _}, 1_000

    frame = event_frame([6, "cx-1", 4, 0, 0])
    {head, tail} = String.split_at(frame, div(byte_size(frame), 2))

    send(conn, {:chunk, head})
    refute_receive {:mendooze_event, _}, 100
    send(conn, {:chunk, tail})

    assert_receive {:mendooze_event, {:endpoint_disconnected, "cx-1", 4, :audio}}, 1_000
  end

  test "reconnects after the stream ends and keeps delivering" do
    base_url = start_stream_server(self())
    start_poller(base_url)

    assert_receive {:stream_conn, conn1, _}, 2_000
    send(conn1, :finish)

    # the poller retries after retry_ms and the server accepts again
    # (generous timeouts: this file runs concurrently with the whole suite)
    assert_receive {:stream_conn, conn2, _}, 2_000
    send(conn2, {:chunk, event_frame([3, "cx-2", "p-9"])})

    assert_receive {:mendooze_event, {:player_started, "cx-2", "p-9"}}, 2_000
  end

  test "gives up and notifies the sink after max_failures consecutive failures" do
    # Reserve a port with nothing listening on it
    {:ok, lsock} = :gen_tcp.listen(0, [])
    {:ok, port} = :inet.port(lsock)
    :gen_tcp.close(lsock)

    {:ok, _poller} =
      EventPoller.start_link(
        base_url: "http://127.0.0.1:#{port}",
        source_path: "/events/jsr309/7",
        sink: self(),
        retry_ms: 50,
        max_failures: 3
      )

    assert_receive {:mendooze_poller_down}, 2_000
  end
end
