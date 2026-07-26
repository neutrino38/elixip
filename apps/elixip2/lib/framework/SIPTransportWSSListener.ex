defmodule SIP.Transport.WSSListener do
  @moduledoc """
  WSS listener for inbound SIP connections. Binds a TLS server socket, accepts
  connections, performs the WebSocket HTTP upgrade handshake, and spawns one
  SIP.Transport.WSS instance per accepted connection.

  Configuration keys (application env :elixip2):
    :wss_max_connections  — connection cap (default 100)
    :tls_certfile         — path to PEM certificate (shared with TLS, default "certs/certificate.pem")
    :tls_keyfile          — path to PEM private key  (shared with TLS, default "certs/private_key.pem")

  Ownership and activation sequence
  ----------------------------------
  The accept Task owns each accepted socket and performs both handshakes (TLS then
  WebSocket HTTP upgrade). It calls `GenServer.call(listener, {:spawn_connection,
  ws_socket, peer_ip, peer_port})` to have the Listener create the WSS GenServer and
  register the connection. The Listener returns the WSS pid; the Task then sends an
  :activate_socket cast which starts the Socket.Web reader process inside the WSS
  GenServer. This is different from TLS where ownership is transferred via
  :ssl.controlling_process; here the reader uses passive :ssl.recv so the controlling
  process attribute is not relevant for data delivery.
  """
  use GenServer
  require Logger

  @transport_str "wss"
  def transport_str, do: @transport_str

  @default_max_connections 100
  @handshake_timeout       10_000
  @default_certfile        "certs/certificate.pem"
  @default_keyfile         "certs/private_key.pem"

  # RFC 6455 §4.1 magic suffix for Sec-WebSocket-Accept computation.
  @ws_magic "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

  # ---- Public API -----------------------------------------------------------

  @spec start_link({:all | :inet.ip_address(), :inet.port_number()}) :: GenServer.on_start()
  def start_link({addr, port}), do: GenServer.start_link(__MODULE__, {addr, port, []})

  @spec start({:all | :inet.ip_address(), :inet.port_number()}) :: GenServer.on_start()
  def start({addr, port}), do: GenServer.start(__MODULE__, {addr, port, []})

  @doc "Returns the number of currently active inbound WSS connections."
  @spec connection_count(pid()) :: non_neg_integer()
  def connection_count(pid), do: GenServer.call(pid, :connection_count)

  # ---- GenServer callbacks --------------------------------------------------

  # Accept an optional keyword list as third element for overrides in tests
  # (:max_connections, :certfile, :keyfile).
  @impl true
  def init({addr, port, opts}) do
    localip  = resolve_localip(addr)
    max_conn = Keyword.get(opts, :max_connections,
      Application.get_env(:elixip2, :wss_max_connections, @default_max_connections))
    certfile = Keyword.get(opts, :certfile,
      Application.get_env(:elixip2, :tls_certfile, @default_certfile))
    keyfile  = Keyword.get(opts, :keyfile,
      Application.get_env(:elixip2, :tls_keyfile, @default_keyfile))
    bind_addr = if addr == :all, do: {0, 0, 0, 0}, else: addr

    ssl_opts = [
      :binary, {:packet, :raw}, {:active, false}, {:reuseaddr, true},
      {:ip, bind_addr},
      {:certfile, to_charlist(certfile)},
      {:keyfile,  to_charlist(keyfile)},
      {:versions, [:"tlsv1.2", :"tlsv1.3"]}
    ]

    case :ssl.listen(port, ssl_opts) do
      {:ok, listen_socket} ->
        {:ok, {_, actual_port}} = :ssl.sockname(listen_socket)
        listener_pid = self()
        Task.start_link(fn -> accept_loop(listen_socket, listener_pid) end)
        Logger.info([module: __MODULE__,
                     message: "WSS listener started on #{SIP.NetUtils.ip2string(localip)}:#{actual_port}"])
        state = %{
          localip:         localip,
          localport:       actual_port,
          socket:          listen_socket,
          upperlayer:      nil,
          max_connections: max_conn,
          connections:     %{}
        }
        {:ok, state}

      {:error, reason} ->
        Logger.error([module: __MODULE__,
                      message: "Failed to bind WSS socket on port #{port}: #{inspect(reason)}"])
        {:stop, reason}
    end
  end

  @impl true
  def handle_call({:setupperlayer, ul}, _from, state) when is_pid(ul) or is_function(ul, 2) or is_nil(ul) do
    Enum.each(state.connections, fn {_ref, {_ip, _port, pid}} ->
      GenServer.call(pid, {:setupperlayer, ul})
    end)
    {:reply, :ok, %{state | upperlayer: ul}}
  end

  def handle_call(:connection_count, _from, state) do
    {:reply, map_size(state.connections), state}
  end

  def handle_call(:getlocalipandport, _from, state) do
    {:reply, {:ok, state.localip, state.localport}, state}
  end

  def handle_call({:sendmsg, msg, dest_ip, dest_port}, _from, state) do
    case find_connection(state.connections, dest_ip, dest_port) do
      nil -> {:reply, {:error, :no_connection}, state}
      pid ->
        result = GenServer.call(pid, {:sendmsg, msg, dest_ip, dest_port})
        {:reply, result, state}
    end
  end

  # Called synchronously by the accept Task, which owns the upgraded ws_socket.
  # Returns {:ok, conn_pid} on success or :rejected when the limit is reached.
  def handle_call({:spawn_connection, ws_socket, peer_ip, peer_port}, _from, state) do
    if map_size(state.connections) >= state.max_connections do
      Logger.warning([module: __MODULE__,
        message: "WSS connection limit (#{state.max_connections}) reached — rejecting inbound connection"])
      ws_abort(ws_socket)
      {:reply, :rejected, state}
    else
      case GenServer.start_link(SIP.Transport.WSS,
             {:inbound, ws_socket, state.localip, state.localport, peer_ip, peer_port}) do
        {:ok, conn_pid} ->
          unless is_nil(state.upperlayer) do
            GenServer.call(conn_pid, {:setupperlayer, state.upperlayer})
          end

          ref = Process.monitor(conn_pid)
          connections = Map.put(state.connections, ref, {peer_ip, peer_port, conn_pid})
          Logger.debug([module: __MODULE__,
            message: "Accepted WSS connection from #{SIP.NetUtils.ip2string(peer_ip)}:#{peer_port}"])
          {:reply, {:ok, conn_pid}, %{state | connections: connections}}

        {:error, reason} ->
          Logger.error([module: __MODULE__,
            message: "Failed to start WSS connection handler: #{inspect(reason)}"])
          ws_abort(ws_socket)
          {:reply, :rejected, state}
      end
    end
  end

  @impl true
  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    connections = Map.delete(state.connections, ref)
    {:noreply, %{state | connections: connections}}
  end

  @impl true
  def terminate(_reason, state) do
    :ssl.close(state.socket)
  end

  # ---- Private helpers ------------------------------------------------------

  # The accept loop runs in a Task linked to the Listener. For each accepted
  # connection it performs the TLS handshake, then the WebSocket HTTP upgrade,
  # then delegates connection ownership to the Listener GenServer.
  defp accept_loop(listen_socket, listener_pid) do
    case :ssl.transport_accept(listen_socket) do
      {:ok, tls_transport_socket} ->
        case :ssl.handshake(tls_transport_socket, @handshake_timeout) do
          {:ok, ssl_socket} ->
            case do_ws_upgrade(ssl_socket) do
              {:ok, ws_socket, peer_ip, peer_port} ->
                case GenServer.call(listener_pid,
                       {:spawn_connection, ws_socket, peer_ip, peer_port}) do
                  {:ok, conn_pid} ->
                    GenServer.cast(conn_pid, :activate_socket)
                  :rejected ->
                    :ok   # Listener already closed the socket.
                end

              {:error, reason} ->
                Logger.warning([module: __MODULE__,
                  message: "WSS WebSocket upgrade failed: #{inspect(reason)}"])
                :ssl.close(ssl_socket)
            end

          {:error, reason} ->
            Logger.warning([module: __MODULE__,
              message: "WSS TLS handshake failed: #{inspect(reason)}"])
        end
        accept_loop(listen_socket, listener_pid)

      {:error, :closed} ->
        :ok

      {:error, reason} ->
        Logger.warning([module: __MODULE__, message: "WSS accept error: #{inspect(reason)}"])
        accept_loop(listen_socket, listener_pid)
    end
  end

  # Performs the HTTP WebSocket upgrade handshake on an already-TLS-connected socket.
  # Uses :ssl directly (not Socket.Web.accept!) because the TLS handshake was already
  # completed by :ssl.handshake above; Socket.Web.accept! would try to redo it.
  defp do_ws_upgrade(ssl_socket) do
    try do
      {:ok, {peer_ip, peer_port}} = :ssl.peername(ssl_socket)

      # Switch to HTTP packet mode to parse the Upgrade request.
      :ssl.setopts(ssl_socket, [{:packet, :http_bin}])
      {path, headers} = read_http_request(ssl_socket, nil, %{})

      ws_key = Map.get(headers, "sec-websocket-key")
      unless ws_key, do: raise("missing Sec-WebSocket-Key")

      unless String.downcase(Map.get(headers, "upgrade", "")) == "websocket",
        do: raise("not a WebSocket Upgrade request")

      # Compute Sec-WebSocket-Accept per RFC 6455 §4.2.2.
      accept_key = :crypto.hash(:sha, ws_key <> @ws_magic) |> Base.encode64()

      :ssl.setopts(ssl_socket, [{:packet, :raw}])
      :ssl.send(ssl_socket,
        "HTTP/1.1 101 Switching Protocols\r\n" <>
        "Upgrade: websocket\r\n" <>
        "Connection: Upgrade\r\n" <>
        "Sec-WebSocket-Accept: #{accept_key}\r\n" <>
        "Sec-WebSocket-Version: 13\r\n" <>
        "Sec-WebSocket-Protocol: sip\r\n\r\n")

      ws_socket = %Socket.Web{
        socket:    ssl_socket,
        version:   13,
        path:      path,
        key:       ws_key,
        mask:      nil,     # server MUST NOT mask outgoing frames (RFC 6455 §5.1)
        protocols: ["sip"]
      }
      {:ok, ws_socket, peer_ip, peer_port}
    rescue
      e -> {:error, e}
    end
  end

  # Reads HTTP/1.x request line and headers until the empty line.
  defp read_http_request(ssl_socket, path, headers) do
    case :ssl.recv(ssl_socket, 0, 5_000) do
      {:ok, {:http_request, :GET, {:abs_path, p}, _}} ->
        read_http_request(ssl_socket, to_string(p), headers)

      {:ok, {:http_header, _, field, _, value}} ->
        key = field |> to_string() |> String.downcase()
        read_http_request(ssl_socket, path, Map.put(headers, key, to_string(value)))

      {:ok, :http_eoh} ->
        {path, headers}

      {:error, reason} ->
        raise "HTTP read error during WebSocket upgrade: #{inspect(reason)}"
    end
  end

  defp resolve_localip(:all), do: SIP.NetUtils.get_local_ips([:ipv4]) |> hd()
  defp resolve_localip(ip), do: ip

  defp find_connection(connections, dest_ip, dest_port) do
    connections
    |> Map.values()
    |> Enum.find_value(fn {ip, port, pid} ->
         if ip == dest_ip and port == dest_port, do: pid
       end)
  end

  # Closes the underlying SSL socket of a %Socket.Web{} struct.
  defp ws_abort(%Socket.Web{socket: ssl_socket}), do: :ssl.close(ssl_socket)
  defp ws_abort(_), do: :ok
end
