defmodule SIP.Test.WSSKeepAliveTest do
  @moduledoc """
  What keeps an inbound WSS connection up, and what used to take it down.

  A SIP-over-WSS connection spends most of its life idle — between two REGISTER
  refreshes nothing is sent — so whether it survives is decided entirely by the
  frames neither side calls traffic: the WebSocket ping/pong of RFC 6455 §5.5.2
  and the CRLF keep-alive of RFC 5626 §4.4.1, which RFC 7118 §4 carries over to
  WebSocket. Every test here is a way a connection was being lost without a
  single SIP message being involved.

  These need no transaction layer: the SIP stack is not on the path of a control
  frame, which is the point of testing them here rather than through a REGISTER.
  """
  use ExUnit.Case, async: false
  import SIP.Test.Wait

  @opts [secure: true, verify: false, versions: [:"tlsv1.2"], protocol: ["sip"]]
  @listener_opts [certfile: "certs/certificate.pem", keyfile: "certs/private_key.pem"]

  setup do
    {:ok, pid} = GenServer.start(SIP.Transport.WSSListener, {:all, 0, @listener_opts})
    {:ok, _ip, port} = GenServer.call(pid, :getlocalipandport)

    on_exit(fn ->
      try do
        GenServer.stop(pid)
      catch
        :exit, _ -> :ok
      end
    end)

    {:ok, listener: pid, port: port}
  end

  defp connect(port) do
    ws = Socket.Web.connect!("127.0.0.1", port, @opts)
    # The connection is only counted once the listener has spawned its transport.
    ws
  end

  # Proves the reader process is still running: it is the only thing that can
  # answer a ping, and its death is exactly the failure mode under test.
  defp alive?(ws) do
    Socket.Web.ping!(ws, "alive?")
    Socket.Web.recv(ws, timeout: 2_000) == {:ok, {:pong, "alive?"}}
  end

  test "a ping is answered with a pong carrying the same payload", %{port: port} do
    ws = connect(port)
    Socket.Web.ping!(ws, "cookie-42")

    # RFC 6455 §5.5.3. An empty pong is what a peer matching its own cookie reads
    # as an unanswered ping, and it closes the connection on the next period.
    assert {:ok, {:pong, "cookie-42"}} = Socket.Web.recv(ws, timeout: 2_000)
    Socket.Web.abort(ws)
  end

  test "an unsolicited pong does not drop the connection", %{listener: pid, port: port} do
    ws = connect(port)
    assert until(fn -> SIP.Transport.WSSListener.connection_count(pid) == 1 end, 2_000)

    # §5.5.3 allows a unidirectional heartbeat, and the reader used to have no
    # clause for it: the CaseClauseError killed the reader, the transport saw the
    # :DOWN and closed a working connection.
    Socket.Web.send!(ws, {:pong, "unsolicited"})

    assert alive?(ws)
    assert SIP.Transport.WSSListener.connection_count(pid) == 1
    Socket.Web.abort(ws)
  end

  test "a binary frame does not drop the connection", %{listener: pid, port: port} do
    ws = connect(port)
    assert until(fn -> SIP.Transport.WSSListener.connection_count(pid) == 1 end, 2_000)

    Socket.Web.send!(ws, {:binary, <<0, 1, 2, 3>>})

    assert alive?(ws)
    assert SIP.Transport.WSSListener.connection_count(pid) == 1
    Socket.Web.abort(ws)
  end

  test "the CRLF keep-alive is answered with a single CRLF", %{port: port} do
    ws = connect(port)
    Socket.Web.send!(ws, {:text, "\r\n\r\n"})

    assert {:ok, {:text, "\r\n"}} = Socket.Web.recv(ws, timeout: 2_000)
    Socket.Web.abort(ws)
  end

  test "a fragmented message is reassembled before it reaches the transport", %{port: port} do
    ws = connect(port)

    # The same double-CRLF ping, split over three frames (RFC 6455 §5.4): the
    # single-CRLF answer can only come back if the three payloads were joined.
    Socket.Web.send!(ws, {:fragmented, :text, "\r"})
    Socket.Web.send!(ws, {:fragmented, :continuation, "\n\r"})
    Socket.Web.send!(ws, {:fragmented, :end, "\n"})

    assert {:ok, {:text, "\r\n"}} = Socket.Web.recv(ws, timeout: 2_000)
    Socket.Web.abort(ws)
  end

  test "a clean close is not a crash", %{listener: pid, port: port} do
    ws = connect(port)
    assert until(fn -> SIP.Transport.WSSListener.connection_count(pid) == 1 end, 2_000)

    # A close with a registered code — what a browser sends on page unload. Only
    # the abnormal one used to be matched, so every clean hang-up crashed the
    # reader on its way out.
    Socket.Web.close(ws, :going_away, wait: false)

    assert until(fn -> SIP.Transport.WSSListener.connection_count(pid) == 0 end, 2_000)
  end

  describe "the upgrade handshake" do
    # A raw client, because what is under test is a header of the 101 itself.
    defp raw_upgrade(port, extra_headers) do
      {:ok, sock} =
        :ssl.connect(~c"127.0.0.1", port,
          [:binary, {:active, false}, {:verify, :verify_none}, {:versions, [:"tlsv1.2"]}], 5_000)

      :ok = :ssl.send(sock,
        "GET / HTTP/1.1\r\n" <>
        "Host: 127.0.0.1:#{port}\r\n" <>
        "Upgrade: websocket\r\n" <>
        "Connection: Upgrade\r\n" <>
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" <>
        "Sec-WebSocket-Version: 13\r\n" <> extra_headers <> "\r\n")

      {:ok, response} = :ssl.recv(sock, 0, 5_000)
      :ssl.close(sock)
      response
    end

    test "the sip subprotocol is echoed when the client offers it", %{port: port} do
      response = raw_upgrade(port, "Sec-WebSocket-Protocol: sip\r\n")

      assert String.starts_with?(response, "HTTP/1.1 101 ")
      assert response =~ "Sec-WebSocket-Protocol: sip"
    end

    test "no subprotocol is named when the client offered none", %{port: port} do
      response = raw_upgrade(port, "")

      # RFC 6455 §4.1: naming one the client did not offer makes the client fail
      # the connection — a browser does it silently, right after a 101 that looked
      # perfectly successful in the server log.
      assert String.starts_with?(response, "HTTP/1.1 101 ")
      refute String.downcase(response) =~ "sec-websocket-protocol"
    end
  end

  describe "server-side keep-alive" do
    setup do
      previous = Application.get_env(:elixip2, :wss_keepalive_period)
      Application.put_env(:elixip2, :wss_keepalive_period, 1)

      on_exit(fn ->
        if is_nil(previous),
          do: Application.delete_env(:elixip2, :wss_keepalive_period),
          else: Application.put_env(:elixip2, :wss_keepalive_period, previous)
      end)

      :ok
    end

    test "the server pings an idle connection", %{port: port} do
      ws = connect(port)

      # Nothing else is sent on this connection: without this ping an idle SIP
      # flow is reaped by the first NAT or reverse proxy on the path.
      assert {:ok, {:ping, _cookie}} = Socket.Web.recv(ws, timeout: 3_000)
      Socket.Web.abort(ws)
    end

    test "a connection that stops answering is closed", %{listener: pid, port: port} do
      ws = connect(port)
      assert until(fn -> SIP.Transport.WSSListener.connection_count(pid) == 1 end, 2_000)

      # The client never reads, so it never pongs — a half-open socket. After
      # @max_missed periods the transport gives up instead of holding a dead flow.
      assert until(fn -> SIP.Transport.WSSListener.connection_count(pid) == 0 end, 8_000)
      Socket.Web.abort(ws)
    end
  end
end
