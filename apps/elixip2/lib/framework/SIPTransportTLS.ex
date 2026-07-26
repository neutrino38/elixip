defmodule SIP.Transport.TLS do
  @moduledoc """
  TLS transport layer for SIP — outbound client connections and inbound
  connections accepted by SIP.Transport.TLSListener.
  """
  alias SIP.NetUtils
  use GenServer
  require Logger
  require Socket.SSL
  require SIP.Transport.ImplHelpers

  @transport_str "tls"
  def transport_str, do: @transport_str

  @spec is_reliable() :: boolean()
  def is_reliable, do: true

  # Outbound connection — opens the TLS socket via Socket.SSL.
  @impl true
  def init({dest_ip, dest_port}) do
    initial_state = %{t_isreliable: true,
      upperlayer: nil, destip: dest_ip, destport: dest_port,
      buffer: %SIP.Transport.Depack{}}

    try do
      state = SIP.Transport.ImplHelpers.connect(initial_state, :tls)
      {:ok, state}
    rescue
      err in Socket.Error ->
        dest_ip_str = if is_tuple(dest_ip), do: NetUtils.ip2string(dest_ip), else: dest_ip
        Logger.info([module: __MODULE__, dest: "#{dest_ip_str}:#{dest_port}",
                     message: "Failed to connect socket: #{err.message}"])
        {:stop, :cnxerror}
    end
  end

  # Inbound connection — TLS socket already handshaked and owned by this process.
  def init({:inbound, ssl_socket, localip, localport, peer_ip, peer_port}) do
    state = %{
      t_isreliable: true,
      upperlayer:   nil,
      destip:       peer_ip,
      destport:     peer_port,
      buffer:       %SIP.Transport.Depack{},
      socket:       ssl_socket,
      localip:      localip,
      localport:    localport
    }
    {:ok, state}
  end

  # Set the upper layer handler for transactions to process.

  @impl true
  def handle_call({:setupperlayer, ul_pid}, _from, state) when is_pid(ul_pid) do
    {:reply, :ok, Map.put(state, :upperlayer, ul_pid)}
  end

  def handle_call({:setupperlayer, ul_func}, _from, state) when is_function(ul_func, 2) do
    {:reply, :ok, Map.put(state, :upperlayer, ul_func)}
  end

  def handle_call({:setupperlayer, nil}, _from, state) do
    {:reply, :ok, Map.put(state, :upperlayer, nil)}
  end

  def handle_call(:getlocalipandport, _from, state) do
    {:reply, {:ok, state.localip, state.localport}, state}
  end

  @spec handle_call({:sendmsg, binary(), :inet.ip_address(), :inet.port_number()}, any(), map()) :: {:reply, :ok, map()}
  def handle_call({:sendmsg, msgstr, _destip, _dest_port}, _from, state) do
    destipstr = SIP.NetUtils.ip2string(state.destip)
    Logger.debug("TLS: Message sent to #{destipstr}:#{state.destport} ---->\r\n" <> msgstr <> "\r\n-----------------")
    case tls_send(state.socket, msgstr) do
      :ok -> {:reply, :ok, state}
      {:error, reason} ->
        Logger.debug("TLS: failed to send message. Error: #{reason}")
        {:reply, :transporterror, state}
    end
  end

  # Activates the socket once the accept Task has transferred ownership.
  # Only meaningful for inbound connections; outbound sockets are already active.
  @impl true
  def handle_cast(:activate_socket, state) do
    :ssl.setopts(state.socket, [{:active, true}])
    {:noreply, state}
  end

  # Handle data reception (both outbound Socket.SSL and inbound raw :ssl).
  @impl true
  def handle_info({:ssl, socket, data}, state) do
    buf = SIP.Transport.Depack.on_data_received(state.buffer, data,
      fn what, msg ->
        case what do
          :ping -> nil
          :msg -> SIP.Transport.ImplHelpers.process_incoming_message(state, msg, "TLS", __MODULE__, socket, state.destip, state.destport)
        end
      end)
    {:noreply, %{state | buffer: buf}}
  end

  def handle_info({:ssl_closed, _socket}, state) do
    Logger.debug([module: __MODULE__, message: "TLS connection closed, stopping transport instance"])
    SIP.Dialog.broadcast({:tls_client_closed, state.destip, state.destport})
    {:stop, :normal, state}
  end

  @impl true
  def terminate(_reason, state) do
    if not is_nil(state.socket) do
      tls_close(state.socket)
    end
  end

  # Duality: inbound sockets are raw :sslsocket tuples; outbound are Socket.SSL structs.
  defp tls_send({:sslsocket, _, _} = s, data), do: :ssl.send(s, data)
  defp tls_send(s, data), do: Socket.Stream.send(s, data)

  defp tls_close({:sslsocket, _, _} = s), do: :ssl.close(s)
  defp tls_close(s), do: Socket.close(s)
end
