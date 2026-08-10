defmodule SIP.Test.ListenerClient do
  @moduledoc """
  The few operations a listener test needs from a client, so the contract below can
  be stated once and run over TCP, TLS and WSS.

  Everything the three transports differ by lives in an implementation of this
  behaviour: the socket module, its options, how a frame is written, and what a
  peer that was closed on looks like from the client side.
  """

  @type handle :: term()

  @doc "Open a client connection to `port` on the loopback."
  @callback connect(port :: :inet.port_number()) :: handle()

  @doc "Close it. Must tolerate an already-closed peer."
  @callback close(handle()) :: term()

  @doc "The local port, for the Via and Contact of a request sent on this handle."
  @callback local_port(handle()) :: :inet.port_number()

  @doc "Write a whole SIP message."
  @callback send_message(handle(), iodata()) :: term()

  @doc """
  Write a SIP message in two pieces, so the listener has to reassemble it.

  Only meaningful for the stream transports: WebSocket frames are already
  message-delimited, which is why `SIP.Transport.Depack` is not used for WSS.
  """
  @callback send_split(handle(), binary()) :: term()

  @doc "Read one SIP response, accumulating until the end-of-headers marker."
  @callback recv_response(handle(), timeout :: non_neg_integer()) :: binary()

  @doc "Has the server closed on us? Polled, so it must not block for long."
  @callback closed?(handle()) :: boolean()
end

defmodule SIP.Test.ListenerClient.TCP do
  @moduledoc false
  @behaviour SIP.Test.ListenerClient

  @opts [:binary, {:active, false}]

  @impl true
  def connect(port) do
    {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, port, @opts)
    socket
  end

  @impl true
  def close(socket), do: :gen_tcp.close(socket)

  @impl true
  def local_port(socket) do
    {:ok, {_ip, port}} = :inet.sockname(socket)
    port
  end

  @impl true
  def send_message(socket, data), do: :gen_tcp.send(socket, data)

  @impl true
  def send_split(socket, msg) do
    {part1, part2} = String.split_at(msg, div(byte_size(msg), 2))
    :gen_tcp.send(socket, part1)
    Process.sleep(50)
    :gen_tcp.send(socket, part2)
  end

  @impl true
  def recv_response(socket, timeout),
    do: SIP.Test.ListenerCase.stream_recv(socket, timeout, &:gen_tcp.recv/3, "TCP")

  @impl true
  def closed?(socket), do: match?({:error, :closed}, :gen_tcp.recv(socket, 0, 100))
end

defmodule SIP.Test.ListenerClient.TLS do
  @moduledoc false
  @behaviour SIP.Test.ListenerClient

  # self-signed test cert: skip verification
  @opts [:binary, {:active, false}, verify: :verify_none, versions: [:"tlsv1.2"]]

  @impl true
  def connect(port) do
    {:ok, socket} = :ssl.connect({127, 0, 0, 1}, port, @opts)
    socket
  end

  @impl true
  def close(socket), do: :ssl.close(socket)

  @impl true
  def local_port(socket) do
    {:ok, {_ip, port}} = :ssl.sockname(socket)
    port
  end

  @impl true
  def send_message(socket, data), do: :ssl.send(socket, data)

  @impl true
  def send_split(socket, msg) do
    {part1, part2} = String.split_at(msg, div(byte_size(msg), 2))
    :ssl.send(socket, part1)
    Process.sleep(50)
    :ssl.send(socket, part2)
  end

  @impl true
  def recv_response(socket, timeout),
    do: SIP.Test.ListenerCase.stream_recv(socket, timeout, &:ssl.recv/3, "TLS")

  @impl true
  def closed?(socket), do: match?({:error, :closed}, :ssl.recv(socket, 0, 100))
end

defmodule SIP.Test.ListenerClient.WSS do
  @moduledoc false
  @behaviour SIP.Test.ListenerClient

  # verify: false — socket2 translates it to {:verify, :verify_none}
  @opts [secure: true, verify: false, versions: [:"tlsv1.2"], protocol: ["sip"]]

  @impl true
  def connect(port), do: Socket.Web.connect!("127.0.0.1", port, @opts)

  @impl true
  def close(ws), do: Socket.Web.abort(ws)

  @impl true
  def local_port(ws) do
    {:ok, {_ip, port}} = :ssl.sockname(ws.socket)
    port
  end

  @impl true
  def send_message(ws, data), do: Socket.Web.send!(ws, {:text, data})

  @impl true
  def send_split(_ws, _msg) do
    raise "WebSocket frames are message-delimited; there is nothing to reassemble"
  end

  @impl true
  def recv_response(ws, timeout) do
    case Socket.Web.recv(ws, timeout: timeout) do
      {:ok, {:text, data}} -> data
      {:error, reason} -> ExUnit.Assertions.flunk("WSS recv failed: #{inspect(reason)}")
      other -> ExUnit.Assertions.flunk("Unexpected WSS frame: #{inspect(other)}")
    end
  end

  @impl true
  def closed?(ws) do
    case Socket.Web.recv(ws) do
      {:error, _} -> true
      {:ok, :close} -> true
      {:ok, {:close, _, _}} -> true
      _ -> false
    end
  end
end

defmodule SIP.Test.ListenerCase do
  @moduledoc """
  The connection-tracking contract every inbound listener implements, run once per
  transport.

  `SIP.Transport.TCPListener`, `TLSListener` and `WSSListener` each bind a port,
  accept connections, spawn one transport instance per connection and count them.
  That is one contract, and it had been written out three times: normalising the
  socket module away, `sip_tcp_listener_test.exs` and `sip_tls_listener_test.exs`
  differed by about twelve lines, and the WSS file by the handshake and the absence
  of a reassembly test. The five transport-level tests were the same five in all
  three, down to their names — so a change to the contract meant three edits, and
  a divergence between them meant nothing at all.

  Everything genuinely per-transport is a `SIP.Test.ListenerClient`. What stays in
  each test file is what is actually specific to it: WSS has no reassembly test
  because WebSocket frames are already message-delimited (which is why
  `SIP.Transport.Depack` is not in its path), and TLS/WSS need a certificate.

  Reassembly is generated only when `fragmentable: true`; `settle_ms` is how long a
  connection count is given to reach its expected value, which TLS and WSS need more
  of than TCP because of the handshake.
  """

  @doc """
  Read a whole SIP response off a stream transport.

  Shared by the TCP and TLS clients, which differ only in the module the recv comes
  from — the accumulate-until-end-of-headers part is the same, and is the point:
  a response can arrive in as many segments as the network feels like.
  """
  def stream_recv(socket, timeout, recv, label, acc \\ "") do
    case recv.(socket, 0, timeout) do
      {:ok, data} ->
        full = acc <> data

        if String.contains?(full, "\r\n\r\n"),
          do: full,
          else: stream_recv(socket, timeout, recv, label, full)

      {:error, reason} ->
        ExUnit.Assertions.flunk(
          "#{label} recv failed: #{inspect(reason)}, received so far: #{inspect(acc)}"
        )
    end
  end

  defmacro __using__(opts) do
    listener = Keyword.fetch!(opts, :listener)
    client = Keyword.fetch!(opts, :client)
    via = Keyword.fetch!(opts, :via_transport)
    listener_opts = Keyword.get(opts, :listener_opts, [])
    settle = Keyword.get(opts, :settle_ms, 2_000)
    fragmentable = Keyword.get(opts, :fragmentable, false)

    quote do
      # The listener binds a real port and the whole SIP stack is a set of named
      # singletons, so these cannot run concurrently with anything.
      use ExUnit.Case, async: false
      import SIP.Test.Wait

      @listener unquote(listener)
      @client unquote(client)
      @via unquote(via)
      @listener_opts unquote(listener_opts)
      @settle unquote(settle)

      setup_all do
        :ok = SIP.Transac.start()
        :ok = SIP.Transport.Selector.start()
        :ok = SIP.Dialog.start()

        case SIP.Session.ConfigRegistry.start() do
          {:ok, _} -> :ok
          {:error, {:already_started, _}} -> :ok
        end

        :ok = SIP.Session.ConfigRegistry.set_registration_processing_module(TestRegistrar)

        # :proxyusesrv is read by the transport selector on every outbound request,
        # so put back whatever the rest of the suite expects (see SIP.Test.AppEnv).
        SIP.Test.AppEnv.preserve_proxy()
        Application.put_env(:elixip2, :proxyusesrv, false)
        :ok
      end

      # A fresh listener on an ephemeral port per test.
      setup do
        {:ok, pid} = start_listener(@listener_opts)
        {:ok, _ip, port} = GenServer.call(pid, :getlocalipandport)
        {:ok, listener: pid, port: port}
      end

      defp start_listener(opts) do
        {:ok, pid} = GenServer.start(@listener, {:all, 0, opts})

        on_exit(fn ->
          try do
            GenServer.stop(pid)
          catch
            :exit, _ -> :ok
          end
        end)

        {:ok, pid}
      end

      defp count(pid), do: @listener.connection_count(pid)

      # ---- The connection-tracking contract -----------------------------------

      test "initial connection count is zero", %{listener: pid} do
        assert count(pid) == 0
      end

      test "accepts an inbound connection", %{listener: pid, port: port} do
        handle = @client.connect(port)
        assert until(fn -> count(pid) == 1 end, @settle)
        @client.close(handle)
      end

      test "tracks multiple simultaneous connections", %{listener: pid, port: port} do
        h1 = @client.connect(port)
        h2 = @client.connect(port)
        assert until(fn -> count(pid) == 2 end, @settle)
        @client.close(h1)
        @client.close(h2)
      end

      test "connection removed from map on client disconnect", %{listener: pid, port: port} do
        handle = @client.connect(port)
        assert until(fn -> count(pid) == 1 end, @settle)
        @client.close(handle)
        assert until(fn -> count(pid) == 0 end, @settle)
      end

      test "excess connections are rejected when max_connections is reached" do
        {:ok, limited} = start_listener([max_connections: 1] ++ @listener_opts)
        {:ok, _ip, port} = GenServer.call(limited, :getlocalipandport)

        h1 = @client.connect(port)
        assert until(fn -> count(limited) == 1 end, @settle)

        # The connection is established — a TCP handshake, or a WS upgrade whose 101
        # is sent before the limit is checked — and the server then closes on us.
        h2 = @client.connect(port)
        assert until(fn -> @client.closed?(h2) end, @settle + 1_000)

        assert count(limited) == 1
        @client.close(h1)
        @client.close(h2)
      end

      # ---- SIP data flow (through Depack and the transaction layer) -----------

      test "a SIP REGISTER receives a response", %{port: port} do
        handle = @client.connect(port)
        @client.send_message(handle, register_message(@client.local_port(handle)))

        assert String.starts_with?(@client.recv_response(handle, 5_000), "SIP/2.0 ")
        @client.close(handle)
      end

      if unquote(fragmentable) do
        test "a SIP message split in two is reassembled", %{port: port} do
          handle = @client.connect(port)
          @client.send_split(handle, register_message(@client.local_port(handle)))

          assert String.starts_with?(@client.recv_response(handle, 5_000), "SIP/2.0 ")
          @client.close(handle)
        end
      end

      # A minimal valid REGISTER, carrying this transport in Via and Contact.
      defp register_message(from_port) do
        uniq = System.unique_integer([:positive])
        lower = String.downcase(@via)

        """
        REGISTER sip:example.com SIP/2.0\r
        Via: SIP/2.0/#{@via} 127.0.0.1:#{from_port};branch=z9hG4bK#{uniq}\r
        From: <sip:testuser@example.com>;tag=#{uniq}\r
        To: <sip:testuser@example.com>\r
        Call-ID: #{lower}-test-#{uniq}@127.0.0.1\r
        CSeq: 1 REGISTER\r
        Contact: <sip:testuser@127.0.0.1:#{from_port};transport=#{lower}>\r
        Max-Forwards: 70\r
        Content-Length: 0\r
        \r
        """
      end
    end
  end
end
