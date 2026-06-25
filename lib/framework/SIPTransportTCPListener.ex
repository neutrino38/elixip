defmodule SIP.Transport.TCPListener do
  @moduledoc """
  TCP listener for inbound SIP connections. Binds a server socket, accepts
  connections, and spawns one SIP.Transport.TCP instance per accepted connection.

  Configurable limit: config :elixip2, :tcp_max_connections, 100
  """
  use GenServer
  require Logger
  require SIP.Transport.ImplHelpers

  @transport_str "tcp"
  def transport_str, do: @transport_str

  @default_max_connections 100

  # ---- Public API -----------------------------------------------------------

  @spec start_link({:all | :inet.ip_address(), :inet.port_number()}) :: GenServer.on_start()
  def start_link({addr, port}), do: GenServer.start_link(__MODULE__, {addr, port, []})

  @spec start({:all | :inet.ip_address(), :inet.port_number()}) :: GenServer.on_start()
  def start({addr, port}), do: GenServer.start(__MODULE__, {addr, port, []})

  @doc "Returns the number of currently active inbound connections."
  @spec connection_count(pid()) :: non_neg_integer()
  def connection_count(pid), do: GenServer.call(pid, :connection_count)

  # ---- GenServer callbacks --------------------------------------------------

  # Accept an optional keyword list as third element so tests can override
  # :max_connections without touching the application environment.
  @impl true
  def init({addr, port, opts}) do
    localip = resolve_localip(addr)
    max_conn = Keyword.get(opts, :max_connections,
      Application.get_env(:elixip2, :tcp_max_connections, @default_max_connections))
    bind_addr = if addr == :all, do: {0, 0, 0, 0}, else: addr

    case :gen_tcp.listen(port, [:binary, {:packet, :raw}, {:active, false},
                                {:reuseaddr, true}, {:ip, bind_addr}]) do
      {:ok, listen_socket} ->
        {:ok, actual_port} = :inet.port(listen_socket)
        listener_pid = self()
        Task.start_link(fn -> accept_loop(listen_socket, listener_pid) end)
        Logger.info([module: __MODULE__,
                     message: "TCP listener started on #{SIP.NetUtils.ip2string(localip)}:#{actual_port}"])
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
                      message: "Failed to bind TCP socket on port #{port}: #{inspect(reason)}"])
        {:stop, reason}
    end
  end

  @impl true
  def handle_call({:setupperlayer, ul}, _from, state) when is_pid(ul) or is_function(ul, 2) or is_nil(ul) do
    # Propagate to existing connections
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
      nil ->
        {:reply, {:error, :no_connection}, state}
      pid ->
        result = GenServer.call(pid, {:sendmsg, msg, dest_ip, dest_port})
        {:reply, result, state}
    end
  end

  @impl true
  def handle_info({:new_connection, client_socket}, state) do
    if map_size(state.connections) >= state.max_connections do
      Logger.warning([module: __MODULE__,
        message: "TCP connection limit (#{state.max_connections}) reached — rejecting inbound connection"])
      :gen_tcp.close(client_socket)
      {:noreply, state}
    else
      {:ok, {peer_ip, peer_port}} = :inet.peername(client_socket)

      case GenServer.start_link(SIP.Transport.TCP,
             {:inbound, client_socket, state.localip, state.localport, peer_ip, peer_port}) do
        {:ok, conn_pid} ->
          # Transfer socket ownership before activating — order is critical.
          :gen_tcp.controlling_process(client_socket, conn_pid)
          :inet.setopts(client_socket, [{:active, true}])

          unless is_nil(state.upperlayer) do
            GenServer.call(conn_pid, {:setupperlayer, state.upperlayer})
          end

          ref = Process.monitor(conn_pid)
          connections = Map.put(state.connections, ref, {peer_ip, peer_port, conn_pid})
          Logger.debug([module: __MODULE__,
            message: "Accepted TCP connection from #{SIP.NetUtils.ip2string(peer_ip)}:#{peer_port}"])
          {:noreply, %{state | connections: connections}}

        {:error, reason} ->
          Logger.error([module: __MODULE__,
            message: "Failed to start TCP connection handler: #{inspect(reason)}"])
          :gen_tcp.close(client_socket)
          {:noreply, state}
      end
    end
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    connections = Map.delete(state.connections, ref)
    {:noreply, %{state | connections: connections}}
  end

  @impl true
  def terminate(_reason, state) do
    :gen_tcp.close(state.socket)
  end

  # ---- Private helpers ------------------------------------------------------

  defp accept_loop(listen_socket, listener_pid) do
    case :gen_tcp.accept(listen_socket) do
      {:ok, client_socket} ->
        send(listener_pid, {:new_connection, client_socket})
        accept_loop(listen_socket, listener_pid)

      {:error, :closed} ->
        :ok

      {:error, reason} ->
        Logger.warning([module: __MODULE__, message: "TCP accept error: #{inspect(reason)}"])
        accept_loop(listen_socket, listener_pid)
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
end
