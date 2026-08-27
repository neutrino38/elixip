defmodule SIP.Transport.TLSListener do
  @moduledoc """
  TLS listener for inbound SIP connections. Binds a TLS server socket, accepts
  and handshakes connections, and spawns one SIP.Transport.TLS instance per
  accepted connection.

  Configuration keys (application env :elixip2):
    :tls_max_connections  — connection cap (default 100)
    :tls_certfile         — path to PEM certificate (default "certs/certificate.pem")
    :tls_keyfile          — path to PEM private key  (default "certs/private_key.pem")

  Ownership transfer sequence
  ----------------------------
  The accept Task owns each accepted socket and performs the TLS handshake.
  It calls `GenServer.call(listener, {:spawn_connection, ssl_socket})` to have the
  Listener create the TLS GenServer and register the connection. The Listener returns
  the TLS pid; the Task then transfers ownership (`Socket.SSL.process/2`) and
  tells the TLS process to activate its socket (`:activate_socket` cast). Only the
  socket owner may transfer ownership, so this sequence must stay in the Task.

  Taking the connection and handshaking it stay two steps — `Socket.SSL.accept/2`
  puts them under one timeout, and the two waits are not the same: waiting for a
  client is unbounded, a handshake must not be.
  """
  use GenServer
  require Logger
  require SIP.Transport.ImplHelpers
  require Socket.SSL

  @transport_str "tls"
  def transport_str, do: @transport_str

  @default_max_connections 100
  @handshake_timeout 10_000
  @default_certfile "certs/certificate.pem"
  @default_keyfile  "certs/private_key.pem"

  # ---- Public API -----------------------------------------------------------

  # The 3-tuple form carries per-listener options (see init/1) — used by kelixip's
  # supervised listeners to pass the per-listener cert/key (kelixip design §3.1).
  @spec start_link({:all | :inet.ip_address(), :inet.port_number()}) :: GenServer.on_start()
  @spec start_link({:all | :inet.ip_address(), :inet.port_number(), keyword()}) ::
          GenServer.on_start()
  def start_link({addr, port}), do: GenServer.start_link(__MODULE__, {addr, port, []})

  def start_link({addr, port, opts}) when is_list(opts),
    do: GenServer.start_link(__MODULE__, {addr, port, opts})

  @spec start({:all | :inet.ip_address(), :inet.port_number()}) :: GenServer.on_start()
  def start({addr, port}), do: GenServer.start(__MODULE__, {addr, port, []})

  @doc "Returns the number of currently active inbound TLS connections."
  @spec connection_count(pid()) :: non_neg_integer()
  def connection_count(pid), do: GenServer.call(pid, :connection_count)

  # ---- GenServer callbacks --------------------------------------------------

  # Accept an optional keyword list as third element for overrides in tests
  # (:max_connections, :certfile, :keyfile). :family (:ipv4 | :ipv6) picks the
  # family of the address advertised in Via/Contact when addr is :all; with an
  # explicit addr the family comes from the address.
  @impl true
  def init({addr, port, opts}) do
    family   = SIP.NetUtils.address_family(addr) || Keyword.get(opts, :family, :ipv4)
    localip = advertised_ip(opts) || resolve_localip(addr, family)
    max_conn = Keyword.get(opts, :max_connections,
      Application.get_env(:elixip2, :tls_max_connections, @default_max_connections))
    certfile = Keyword.get(opts, :certfile,
      Application.get_env(:elixip2, :tls_certfile, @default_certfile))
    keyfile  = Keyword.get(opts, :keyfile,
      Application.get_env(:elixip2, :tls_keyfile, @default_keyfile))
    bind_addr = wildcard_of(addr, family)

    # listen/2 binds passive and with SO_REUSEADDR on its own. No `version:`: the
    # bind address carries its family, and `:all` still binds 0.0.0.0 (see
    # SIP.Transport.TCPListener, and step 4 of docs/design/multi-interface.md).
    ssl_opts = [
      packet: :raw,
      local: [address: bind_addr],
      cert: [path: certfile],
      key: [path: keyfile],
      versions: [:"tlsv1.2", :"tlsv1.3"]
    ]

    case localip && Socket.SSL.listen(port, ssl_opts) do
      {:ok, listen_socket} ->
        {_bound_ip, actual_port} = Socket.local!(listen_socket)
        listener_pid = self()
        Task.start_link(fn -> accept_loop(listen_socket, listener_pid) end)
        Logger.info([module: __MODULE__,
                     message: "TLS listener started on #{SIP.NetUtils.sip_host(localip)}:#{actual_port}"])
        state = %{
          localip:         localip,
          localport:       actual_port,
          socket:          listen_socket,
          upperlayer:      nil,
          max_connections: max_conn,
          connections:     %{}
        }
        {:ok, state}

      nil ->
        Logger.error([module: __MODULE__,
                      message: "No local #{family} address to advertise. Check your network configuration"])
        {:stop, :networkdown}

      {:error, reason} ->
        Logger.error([module: __MODULE__,
                      message: "Failed to bind TLS socket on port #{port}: #{inspect(reason)}"])
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

  # Called synchronously by the accept Task, which owns the handshaked socket.
  # Returns {:ok, conn_pid} on success or :rejected when the limit is reached.
  def handle_call({:spawn_connection, ssl_socket}, _from, state) do
    if map_size(state.connections) >= state.max_connections do
      Logger.warning([module: __MODULE__,
        message: "TLS connection limit (#{state.max_connections}) reached — rejecting inbound connection"])
      Socket.close(ssl_socket)
      {:reply, :rejected, state}
    else
      {:ok, {peer_ip, peer_port}} = Socket.remote(ssl_socket)

      case GenServer.start_link(SIP.Transport.TLS,
             {:inbound, ssl_socket, state.localip, state.localport, peer_ip, peer_port}) do
        {:ok, conn_pid} ->
          unless is_nil(state.upperlayer) do
            GenServer.call(conn_pid, {:setupperlayer, state.upperlayer})
          end

          ref = Process.monitor(conn_pid)
          connections = Map.put(state.connections, ref, {peer_ip, peer_port, conn_pid})
          Logger.debug([module: __MODULE__,
            message: "Accepted TLS connection from #{SIP.NetUtils.ip2string(peer_ip)}:#{peer_port}"])
          {:reply, {:ok, conn_pid}, %{state | connections: connections}}

        {:error, reason} ->
          Logger.error([module: __MODULE__,
            message: "Failed to start TLS connection handler: #{inspect(reason)}"])
          Socket.close(ssl_socket)
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
    Socket.close(state.socket)
  end

  # ---- Private helpers ------------------------------------------------------

  # The accept loop runs in a Task linked to the Listener. It owns each accepted
  # socket, performs the TLS handshake, then delegates to the Listener.
  defp accept_loop(listen_socket, listener_pid) do
    case Socket.SSL.transport_accept(listen_socket) do
      {:ok, tls_transport_socket} ->
        case Socket.SSL.handshake(tls_transport_socket, timeout: @handshake_timeout) do
          {:ok, ssl_socket} ->
            case GenServer.call(listener_pid, {:spawn_connection, ssl_socket}) do
              {:ok, conn_pid} ->
                # Transfer ownership: Task → TLS GenServer.
                Socket.SSL.process(ssl_socket, conn_pid)
                # Ask the TLS process to activate its socket now that it owns it.
                GenServer.cast(conn_pid, :activate_socket)

              :rejected ->
                :ok  # Listener already closed the socket.
            end

          {:error, reason} ->
            Logger.warning([module: __MODULE__,
              message: "TLS handshake failed: #{inspect(reason)}"])
        end
        accept_loop(listen_socket, listener_pid)

      {:error, :closed} ->
        :ok

      {:error, reason} ->
        Logger.warning([module: __MODULE__, message: "TLS accept error: #{inspect(reason)}"])
        accept_loop(listen_socket, listener_pid)
    end
  end

  # The address this listener PUBLISHES, when it is not the one it binds. A VM
  # behind a 1:1 NAT binds a private address and is reached at a public one; the
  # operator knows that address (an AWS EIP does not move), and nothing on the
  # host can derive it.
  #
  # It replaces the advertised address only — `bind_addr` is untouched — so
  # everything that writes an address into a message follows: `localip` is what
  # `get_local_ip_port/1` answers, which is what a Via `sent-by` and a Contact are
  # built from, and what the media layer reads as the address this peer reached.
  defp advertised_ip(opts) do
    case Keyword.get(opts, :advertise) do
      ip when is_tuple(ip) -> ip
      _ -> nil
    end
  end

  # `:all` is every interface **of this listener's family**. It was the IPv4
  # wildcard whatever the family, so a listener told :ipv6 resolved an IPv6
  # address for its Via and its Contact and then bound an IPv4 socket.
  defp wildcard_of(:all, :ipv6), do: {0, 0, 0, 0, 0, 0, 0, 0}
  defp wildcard_of(:all, _family), do: {0, 0, 0, 0}
  defp wildcard_of(addr, _family), do: addr

  # nil when the host carries no address of the requested family: the listener
  # would then have nothing to write in a Via or a Contact.
  defp resolve_localip(:all, family), do: SIP.NetUtils.get_local_ips([family]) |> List.first()
  defp resolve_localip(ip, _family), do: ip

  defp find_connection(connections, dest_ip, dest_port) do
    connections
    |> Map.values()
    |> Enum.find_value(fn {ip, port, pid} ->
         if ip == dest_ip and port == dest_port, do: pid
       end)
  end
end
