defmodule SIP.Transport.TCP do
  @moduledoc """
  TCP transport layer for SIP — outbound client connections and inbound
  connections accepted by SIP.Transport.TCPListener.
  """
  alias SIP.NetUtils
  use GenServer
  require Logger
  require Socket.TCP
  require SIP.Transport.ImplHelpers

  @transport_str "tcp"
  def transport_str, do: @transport_str

  @spec is_reliable() :: boolean()
  def is_reliable, do: true

  # Outbound connection — opens the socket.
  @impl true
  def init({dest_ip, dest_port}) do
    initial_state = %{t_isreliable: true,
      upperlayer: nil, destip: dest_ip, destport: dest_port,
      buffer: %SIP.Transport.Depack{}}

    try do
      state = SIP.Transport.ImplHelpers.connect(initial_state, :tcp)
      {:ok, state}
    rescue
      err in Socket.Error ->
        dest_ip_str = if is_tuple(dest_ip), do: NetUtils.ip2string(dest_ip), else: dest_ip
        Logger.debug([module: __MODULE__, dest: "#{dest_ip_str}:#{dest_port}",
                      message: "Failed to connect socket: #{err.message}"])
        {:stop, :cnxerror}
    end
  end

  # Inbound connection — socket already open and owned by this process.
  def init({:inbound, socket, localip, localport, peer_ip, peer_port}) do
    state = %{
      t_isreliable: true,
      upperlayer:   nil,
      destip:       peer_ip,
      destport:     peer_port,
      buffer:       %SIP.Transport.Depack{},
      socket:       socket,
      localip:      localip,
      localport:    localport
    }
    {:ok, state}
  end

  # Set the upper layer handler for transactions to process

  @impl true
  def handle_call( {:setupperlayer, ul_pid }, _from, state) when is_pid(ul_pid) do
    { :reply, :ok, Map.put(state, :upperlayer, ul_pid) }
  end

  def handle_call( {:setupperlayer, ul_func }, _from, state) when is_function(ul_func, 2) do
    { :reply, :ok, Map.put(state, :upperlayer, ul_func) }
  end

  def handle_call( {:setupperlayer, nil }, _from, state) do
    { :reply, :ok, Map.put(state, :upperlayer, nil) }
  end

  def handle_call(:getlocalipandport, _from, state) do
    { :reply, { :ok, state.localip, state.localport }, state}
  end


  @spec handle_call({:sendmsg, binary(), :inet.ip_address(), :inet.port_number}, any(), map()) :: {:reply, :ok, map()}
  def handle_call({:sendmsg, msgstr, _destip, _dest_port}, _from, state) do
    destipstr = SIP.NetUtils.ip2string(state.destip)
    Logger.debug("TCP: Message sent to #{destipstr}:#{state.destport} ---->\r\n" <> msgstr <> "\r\n-----------------")
    case tcp_send(state.socket, msgstr) do
      :ok -> {:reply, :ok, state}
      {:error, reason} ->
        Logger.debug([module: __MODULE__, message: "failed to send message. Error: #{reason}"])
        {:reply, :transporterror, state}
    end
  end



  # Activates the socket once the accept Task has transferred ownership.
  # Only meaningful for inbound connections; outbound sockets are already active.
  @impl true
  def handle_cast(:activate_socket, state) do
    :inet.setopts(state.socket, [{:active, true}])
    {:noreply, state}
  end

  # Handle data reception
  @impl true
  def handle_info({:tcp, socket, data}, state ) do
    buf = SIP.Transport.Depack.on_data_received(state.buffer, data,
      fn what, msg ->
        case what do
          :ping -> nil
          :msg -> SIP.Transport.ImplHelpers.process_incoming_message(state, msg, "TCP", __MODULE__, socket, state.destip, state.destport)
        end
      end)
    { :noreply, %{ state | buffer: buf } }
  end

  def handle_info({:tcp_closed, _socket}, state) do
    Logger.debug([module: __MODULE__, message: "Cnx disconnected. stopping transport instance"])
    SIP.Dialog.broadcast({:tcp_client_closed, state.destip, state.destport})
    {:stop, :normal, state}
  end

  @impl true
  def terminate(_reason, state) do
    if not is_nil(state.socket) do
      tcp_close(state.socket)
    end
  end

  # Raw :gen_tcp port for inbound connections; Socket.Stream struct for outbound.
  defp tcp_send(socket, data) when is_port(socket), do: :gen_tcp.send(socket, data)
  defp tcp_send(socket, data), do: Socket.Stream.send(socket, data)

  defp tcp_close(socket) when is_port(socket), do: :gen_tcp.close(socket)
  defp tcp_close(socket), do: Socket.close(socket)
end
