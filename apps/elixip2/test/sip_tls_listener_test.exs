defmodule SIP.Test.TLSListenerTest do
  use ExUnit.Case, async: false

  @certfile "certs/certificate.pem"
  @keyfile  "certs/private_key.pem"

  # SSL client options: skip cert verification (self-signed test cert).
  @ssl_client_opts [:binary, verify: :verify_none, versions: [:"tlsv1.2"]]

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

  # Start a fresh TLS listener on an ephemeral port for each test.
  setup do
    {:ok, pid} = GenServer.start(SIP.Transport.TLSListener,
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
    assert SIP.Transport.TLSListener.connection_count(pid) == 0
  end

  test "accepts an inbound TLS connection", %{listener: pid, port: port} do
    {:ok, socket} = :ssl.connect({127, 0, 0, 1}, port, @ssl_client_opts)
    assert wait_until(fn -> SIP.Transport.TLSListener.connection_count(pid) == 1 end, 2_000) == :ok
    :ssl.close(socket)
  end

  test "tracks multiple simultaneous TLS connections", %{listener: pid, port: port} do
    {:ok, s1} = :ssl.connect({127, 0, 0, 1}, port, @ssl_client_opts)
    {:ok, s2} = :ssl.connect({127, 0, 0, 1}, port, @ssl_client_opts)
    assert wait_until(fn -> SIP.Transport.TLSListener.connection_count(pid) == 2 end, 2_000) == :ok
    :ssl.close(s1)
    :ssl.close(s2)
  end

  test "connection removed from map on client disconnect", %{listener: pid, port: port} do
    {:ok, socket} = :ssl.connect({127, 0, 0, 1}, port, @ssl_client_opts)
    assert wait_until(fn -> SIP.Transport.TLSListener.connection_count(pid) == 1 end, 2_000) == :ok
    :ssl.close(socket)
    assert wait_until(fn -> SIP.Transport.TLSListener.connection_count(pid) == 0 end, 2_000) == :ok
  end

  test "excess connections are rejected when max_connections is reached" do
    {:ok, limited} = GenServer.start(SIP.Transport.TLSListener,
      {:all, 0, [max_connections: 1, certfile: @certfile, keyfile: @keyfile]})
    {:ok, _ip, limited_port} = GenServer.call(limited, :getlocalipandport)

    on_exit(fn ->
      try do
        GenServer.stop(limited)
      catch
        :exit, _ -> :ok
      end
    end)

    {:ok, s1} = :ssl.connect({127, 0, 0, 1}, limited_port, @ssl_client_opts)
    assert wait_until(fn -> SIP.Transport.TLSListener.connection_count(limited) == 1 end, 2_000) == :ok

    # Second connection: TLS handshake succeeds but server closes the socket immediately.
    {:ok, s2} = :ssl.connect({127, 0, 0, 1}, limited_port, @ssl_client_opts)
    assert wait_until(fn ->
      case :ssl.recv(s2, 0, 200) do
        {:error, :closed} -> true
        _ -> false
      end
    end, 3_000) == :ok

    assert SIP.Transport.TLSListener.connection_count(limited) == 1
    :ssl.close(s1)
    :ssl.close(s2)
  end

  # ---- SIP data-flow tests ----------------------------------------------------

  test "SIP REGISTER over TLS receives a response", %{port: port} do
    {:ok, socket} = :ssl.connect({127, 0, 0, 1}, port, [{:active, false} | @ssl_client_opts])
    {:ok, {_ip, from_port}} = :ssl.sockname(socket)

    :ssl.send(socket, build_register(from_port))

    response = recv_sip_response(socket, "", 5_000)
    assert String.starts_with?(response, "SIP/2.0 ")
    :ssl.close(socket)
  end

  test "SIP message fragmented across two TLS records is reassembled", %{port: port} do
    {:ok, socket} = :ssl.connect({127, 0, 0, 1}, port, [{:active, false} | @ssl_client_opts])
    {:ok, {_ip, from_port}} = :ssl.sockname(socket)
    msg = build_register(from_port)

    mid = div(byte_size(msg), 2)
    {part1, part2} = String.split_at(msg, mid)

    :ssl.send(socket, part1)
    Process.sleep(50)
    :ssl.send(socket, part2)

    response = recv_sip_response(socket, "", 5_000)
    assert String.starts_with?(response, "SIP/2.0 ")
    :ssl.close(socket)
  end

  # ---- Private helpers --------------------------------------------------------

  defp build_register(from_port) do
    branch = "z9hG4bK#{System.unique_integer([:positive])}"
    tag    = "#{System.unique_integer([:positive])}"
    callid = "tls-test-#{System.unique_integer([:positive])}@127.0.0.1"

    "REGISTER sip:example.com SIP/2.0\r\n" <>
    "Via: SIP/2.0/TLS 127.0.0.1:#{from_port};branch=#{branch}\r\n" <>
    "From: <sip:testuser@example.com>;tag=#{tag}\r\n" <>
    "To: <sip:testuser@example.com>\r\n" <>
    "Call-ID: #{callid}\r\n" <>
    "CSeq: 1 REGISTER\r\n" <>
    "Contact: <sip:testuser@127.0.0.1:#{from_port};transport=tls>\r\n" <>
    "Max-Forwards: 70\r\n" <>
    "Content-Length: 0\r\n\r\n"
  end

  defp recv_sip_response(socket, acc, timeout) do
    case :ssl.recv(socket, 0, timeout) do
      {:ok, data} ->
        full = acc <> data
        if String.contains?(full, "\r\n\r\n") do
          full
        else
          recv_sip_response(socket, full, timeout)
        end

      {:error, reason} ->
        flunk("TLS recv failed: #{inspect(reason)}, received so far: #{inspect(acc)}")
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
