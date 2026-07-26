defmodule SIP.Transport.WSS do
  @moduledoc """
  WSS (WebSocket over TLS) transport for SIP — outbound client connections and
  inbound connections accepted by SIP.Transport.WSSListener.
  """
  alias SIP.NetUtils
  use GenServer
  require Logger
  require Socket.Web
  require SIP.Transport.ImplHelpers

  @transport_str "wss"
  # @default_local_port 5060
  def transport_str, do: @transport_str

  @spec is_reliable() :: boolean()
  def is_reliable, do: true

  @impl true
  def init({ dest_ip, dest_port}) do
    initial_state = %{ t_isreliable: true,
      upperlayer: nil, destip: dest_ip, destport: dest_port }

    try do
      state = SIP.Transport.ImplHelpers.connect(initial_state, :wss)
      { :ok, state }
    rescue
      err in Socket.Error ->
        dest_ip = if is_tuple(dest_ip) do NetUtils.ip2string(dest_ip) else dest_ip end
        Logger.info([ module: __MODULE__, dest: "#{dest_ip}:#{dest_port}",
                       message: "Failed to connect socket: #{err.message} "])
        Logger.debug( Exception.format_stacktrace(__STACKTRACE__))
        { :stop, :cnxerror }

      err in Protocol.UndefinedError ->
        Logger.info([ module: __MODULE__, dest: "#{dest_ip}:#{dest_port}",
                      message: "Runtime error in connect() "])
        Logger.debug(inspect(err))
        Logger.debug( Exception.format_stacktrace(__STACKTRACE__))
        { :stop, :cnxerror }
    end
  end

  # Inbound connection — %Socket.Web{} already upgraded; reader not yet started.
  def init({:inbound, ws_socket, localip, localport, peer_ip, peer_port}) do
    state = %{
      t_isreliable: true,
      upperlayer:   nil,
      destip:       peer_ip,
      destport:     peer_port,
      socket:       ws_socket,
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


  @spec handle_call(  {:sendmsg, binary(), :inet.ip_address(), :inet.port_number }, any(), map() ) ::  { :reply, :ok, map() }
  def handle_call({ :sendmsg, msgstr, _destip, _dest_port }, _from, state) do
    try do
      Socket.Web.send!(state.socket, {:text, msgstr})
      destipstr = if is_tuple(state.destip), do: SIP.NetUtils.ip2string(state.destip), else: state.destip
      Logger.debug("WSS: Message sent to #{destipstr}:#{state.destport} ---->\r\n" <> msgstr <> "\r\n-----------------")
      { :reply, :ok, state }
      rescue
        err in Socket.Error ->
          Logger.debug("WSS: failed to send message. Error #{err.message}");
          { :reply, :transporterror, state }
    end
  end



  # Activates the WebSocket reader once WSSListener has transferred the connection.
  # Registers self() as target_pid, spawns the Socket.Web reader process, then
  # monitors it so that a silent reader exit (e.g. socket closed by the peer without
  # a WS close frame) propagates to this GenServer via a :DOWN message.
  @impl true
  def handle_cast(:activate_socket, state) do
    ws = Socket.Web.process(state.socket, self()) |> Socket.Web.active(true)
    Process.monitor(ws.active_pid)
    {:noreply, %{state | socket: ws}}
  end

  # Handle data reception. `state.destip` is the dialed hostname for WSS (the
  # resolver delegates DNS to the socket layer), so use the socket's real peer
  # address as the message source — a proper IP tuple, like UDP passes. Falls
  # back to the stored dest only if the peer address is momentarily unavailable.
  @impl true
  def handle_info({:web, socket, data}, state ) do
    { src_ip, src_port } =
      case SIP.Transport.ImplHelpers.remote_address(socket) do
        { ip, port } -> { ip, port }
        nil -> { state.destip, state.destport }
      end

    SIP.Transport.ImplHelpers.process_incoming_message(state, data, "WSS", __MODULE__, socket, src_ip, src_port)
    { :noreply, state }
  end

  def handle_info({:web_closed, _socket}, state) do
    Logger.debug([module: __MODULE__, message: "WSS connection closed by peer (WS close frame)"])
    SIP.Dialog.broadcast({:wss_client_closed, state.destip, state.destport})
    {:stop, :normal, state}
  end

  # The Socket.Web reader process exited (socket closed without WS close frame).
  def handle_info({:DOWN, _ref, :process, _pid, _reason}, state) do
    Logger.debug([module: __MODULE__, message: "WSS reader process exited, stopping transport"])
    SIP.Dialog.broadcast({:wss_client_closed, state.destip, state.destport})
    {:stop, :normal, state}
  end

  @impl true
  def terminate(_reason, state) do
    if not is_nil(state.socket) do
      Socket.close(state.socket)
    end
  end
end
