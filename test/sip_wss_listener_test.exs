defmodule SIP.Test.WSSListenerTest do
  use ExUnit.Case, async: false

  @certfile "certs/certificate.pem"
  @keyfile  "certs/private_key.pem"

  # Socket.Web client options for a WSS connection to a self-signed server.
  # verify: false skips certificate verification (socket2 translates to {:verify, :verify_none}).
  @wss_client_opts [
    secure:   true,
    verify:   false,
    versions: [:"tlsv1.2"],
    protocol: ["sip"]
  ]

  # ---- Setup ------------------------------------------------------------------

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()

    case SIP.Session.ConfigRegistry.start() do
      {:ok, _} -> :ok
      {:error, {:already_started, _}} -> :ok
    end

    :ok = SIP.Session.ConfigRegistry.set_registration_processing_module(TestRegistrar)
    Application.put_env(:elixip2, :proxyusesrv, false)
    :ok
  end

  # Start a fresh WSS listener on an ephemeral port for each test.
  setup do
    {:ok, pid} = GenServer.start(SIP.Transport.WSSListener,
      {:all, 0, [certfile: @certfile, keyfile: @keyfile]})
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

  # ---- Transport-level tests --------------------------------------------------

  test "initial connection count is zero", %{listener: pid} do
    assert SIP.Transport.WSSListener.connection_count(pid) == 0
  end

  test "accepts an inbound WSS connection", %{listener: pid, port: port} do
    ws = Socket.Web.connect!("127.0.0.1", port, @wss_client_opts)
    assert wait_until(fn -> SIP.Transport.WSSListener.connection_count(pid) == 1 end, 2_000) == :ok
    Socket.Web.abort(ws)
  end

  test "tracks multiple simultaneous WSS connections", %{listener: pid, port: port} do
    ws1 = Socket.Web.connect!("127.0.0.1", port, @wss_client_opts)
    ws2 = Socket.Web.connect!("127.0.0.1", port, @wss_client_opts)
    assert wait_until(fn -> SIP.Transport.WSSListener.connection_count(pid) == 2 end, 2_000) == :ok
    Socket.Web.abort(ws1)
    Socket.Web.abort(ws2)
  end

  test "connection removed from map on client disconnect", %{listener: pid, port: port} do
    ws = Socket.Web.connect!("127.0.0.1", port, @wss_client_opts)
    assert wait_until(fn -> SIP.Transport.WSSListener.connection_count(pid) == 1 end, 2_000) == :ok
    Socket.Web.abort(ws)
    assert wait_until(fn -> SIP.Transport.WSSListener.connection_count(pid) == 0 end, 2_000) == :ok
  end

  test "excess connections are rejected when max_connections is reached" do
    {:ok, limited} = GenServer.start(SIP.Transport.WSSListener,
      {:all, 0, [max_connections: 1, certfile: @certfile, keyfile: @keyfile]})
    {:ok, _ip, limited_port} = GenServer.call(limited, :getlocalipandport)

    on_exit(fn ->
      try do
        GenServer.stop(limited)
      catch
        :exit, _ -> :ok
      end
    end)

    ws1 = Socket.Web.connect!("127.0.0.1", limited_port, @wss_client_opts)
    assert wait_until(fn -> SIP.Transport.WSSListener.connection_count(limited) == 1 end, 2_000) == :ok

    # Second connection: WS upgrade succeeds (101 is sent before the limit check),
    # but the server immediately closes the socket. The client sees a closed recv.
    ws2 = Socket.Web.connect!("127.0.0.1", limited_port, @wss_client_opts)
    assert wait_until(fn ->
      case Socket.Web.recv(ws2) do
        {:error, _} -> true
        {:ok, :close} -> true
        {:ok, {:close, _, _}} -> true
        _ -> false
      end
    end, 3_000) == :ok

    assert SIP.Transport.WSSListener.connection_count(limited) == 1
    Socket.Web.abort(ws1)
    Socket.Web.abort(ws2)
  end

  # ---- SIP data-flow tests ----------------------------------------------------

  test "SIP REGISTER over WSS receives a response", %{port: port} do
    ws = Socket.Web.connect!("127.0.0.1", port, @wss_client_opts)
    # Retrieve the local port for Via/Contact headers.
    {:ok, {_ip, from_port}} = :ssl.sockname(ws.socket)

    Socket.Web.send!(ws, {:text, build_register(from_port)})

    response = recv_sip_response(ws, 5_000)
    assert String.starts_with?(response, "SIP/2.0 ")
    Socket.Web.abort(ws)
  end

  # ---- Private helpers --------------------------------------------------------

  defp build_register(from_port) do
    branch = "z9hG4bK#{System.unique_integer([:positive])}"
    tag    = "#{System.unique_integer([:positive])}"
    callid = "wss-test-#{System.unique_integer([:positive])}@127.0.0.1"

    "REGISTER sip:example.com SIP/2.0\r\n" <>
    "Via: SIP/2.0/WSS 127.0.0.1:#{from_port};branch=#{branch}\r\n" <>
    "From: <sip:testuser@example.com>;tag=#{tag}\r\n" <>
    "To: <sip:testuser@example.com>\r\n" <>
    "Call-ID: #{callid}\r\n" <>
    "CSeq: 1 REGISTER\r\n" <>
    "Contact: <sip:testuser@127.0.0.1:#{from_port};transport=wss>\r\n" <>
    "Max-Forwards: 70\r\n" <>
    "Content-Length: 0\r\n\r\n"
  end

  defp recv_sip_response(ws, timeout) do
    case Socket.Web.recv(ws, timeout: timeout) do
      {:ok, {:text, data}} ->
        data

      {:error, reason} ->
        flunk("WSS recv failed: #{inspect(reason)}")

      other ->
        flunk("Unexpected WSS frame: #{inspect(other)}")
    end
  end

  defp wait_until(_fun, remaining) when remaining <= 0, do: :timeout
  defp wait_until(fun, remaining) do
    if fun.() do
      :ok
    else
      Process.sleep(20)
      wait_until(fun, remaining - 20)
    end
  end
end
