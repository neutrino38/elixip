defmodule SIP.Test.TCPListenerTest do
  use ExUnit.Case, async: false

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

  # Start a fresh listener on an ephemeral port for each test.
  setup do
    {:ok, pid} = GenServer.start(SIP.Transport.TCPListener, {:all, 0, []})
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

  # ---- Transport-level tests (no SIP stack assertions) ------------------------

  test "initial connection count is zero", %{listener: pid} do
    assert SIP.Transport.TCPListener.connection_count(pid) == 0
  end

  test "accepts an inbound TCP connection", %{listener: pid, port: port} do
    {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, {:active, false}])
    assert wait_until(fn -> SIP.Transport.TCPListener.connection_count(pid) == 1 end, 1_000) == :ok
    :gen_tcp.close(socket)
  end

  test "tracks multiple simultaneous connections", %{listener: pid, port: port} do
    {:ok, s1} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, {:active, false}])
    {:ok, s2} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, {:active, false}])
    assert wait_until(fn -> SIP.Transport.TCPListener.connection_count(pid) == 2 end, 1_000) == :ok
    :gen_tcp.close(s1)
    :gen_tcp.close(s2)
  end

  test "connection removed from map on client disconnect", %{listener: pid, port: port} do
    {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, {:active, false}])
    assert wait_until(fn -> SIP.Transport.TCPListener.connection_count(pid) == 1 end, 1_000) == :ok
    :gen_tcp.close(socket)
    assert wait_until(fn -> SIP.Transport.TCPListener.connection_count(pid) == 0 end, 1_000) == :ok
  end

  test "excess connections are rejected when max_connections is reached" do
    {:ok, limited} = GenServer.start(SIP.Transport.TCPListener, {:all, 0, [max_connections: 1]})
    {:ok, _ip, limited_port} = GenServer.call(limited, :getlocalipandport)

    on_exit(fn ->
      try do
        GenServer.stop(limited)
      catch
        :exit, _ -> :ok
      end
    end)

    {:ok, s1} = :gen_tcp.connect({127, 0, 0, 1}, limited_port, [:binary, {:active, false}])
    assert wait_until(fn -> SIP.Transport.TCPListener.connection_count(limited) == 1 end, 1_000) == :ok

    # Second connection: TCP handshake succeeds but server closes the socket immediately.
    {:ok, s2} = :gen_tcp.connect({127, 0, 0, 1}, limited_port, [:binary, {:active, false}])
    assert wait_until(fn ->
      case :gen_tcp.recv(s2, 0, 100) do
        {:error, :closed} -> true
        _ -> false
      end
    end, 2_000) == :ok

    assert SIP.Transport.TCPListener.connection_count(limited) == 1
    :gen_tcp.close(s1)
    :gen_tcp.close(s2)
  end

  # ---- SIP data-flow tests (exercise Depack + transaction layer) --------------

  test "SIP REGISTER over TCP receives a response", %{port: port} do
    {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, {:active, false}])
    {:ok, {_ip, from_port}} = :inet.sockname(socket)

    :gen_tcp.send(socket, build_register(from_port))

    response = recv_sip_response(socket, "", 5_000)
    assert String.starts_with?(response, "SIP/2.0 ")
    :gen_tcp.close(socket)
  end

  test "SIP message fragmented across two TCP segments is reassembled", %{port: port} do
    {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, {:active, false}])
    {:ok, {_ip, from_port}} = :inet.sockname(socket)
    msg = build_register(from_port)

    # Split in the middle of the headers
    mid = div(byte_size(msg), 2)
    {part1, part2} = String.split_at(msg, mid)

    :gen_tcp.send(socket, part1)
    Process.sleep(50)
    :gen_tcp.send(socket, part2)

    response = recv_sip_response(socket, "", 5_000)
    assert String.starts_with?(response, "SIP/2.0 ")
    :gen_tcp.close(socket)
  end

  # ---- Private helpers --------------------------------------------------------

  # Build a minimal valid REGISTER request for TCP.
  defp build_register(from_port) do
    branch = "z9hG4bK#{System.unique_integer([:positive])}"
    tag    = "#{System.unique_integer([:positive])}"
    callid = "tcp-test-#{System.unique_integer([:positive])}@127.0.0.1"

    "REGISTER sip:example.com SIP/2.0\r\n" <>
    "Via: SIP/2.0/TCP 127.0.0.1:#{from_port};branch=#{branch}\r\n" <>
    "From: <sip:testuser@example.com>;tag=#{tag}\r\n" <>
    "To: <sip:testuser@example.com>\r\n" <>
    "Call-ID: #{callid}\r\n" <>
    "CSeq: 1 REGISTER\r\n" <>
    "Contact: <sip:testuser@127.0.0.1:#{from_port};transport=tcp>\r\n" <>
    "Max-Forwards: 70\r\n" <>
    "Content-Length: 0\r\n\r\n"
  end

  # Accumulate TCP data until the SIP end-of-headers marker is present.
  defp recv_sip_response(socket, acc, timeout) do
    case :gen_tcp.recv(socket, 0, timeout) do
      {:ok, data} ->
        full = acc <> data
        if String.contains?(full, "\r\n\r\n") do
          full
        else
          recv_sip_response(socket, full, timeout)
        end

      {:error, reason} ->
        flunk("TCP recv failed: #{inspect(reason)}, received so far: #{inspect(acc)}")
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
