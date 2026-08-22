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

  # WebSocket keep-alive (RFC 6455 §5.5.2). A SIP-over-WSS connection is idle for
  # minutes at a time — between two REGISTER refreshes nothing is sent — and every
  # box on the path reaps an idle TLS connection: nginx `proxy_read_timeout` is 60 s
  # by default, an ALB 60 s, a home NAT anywhere from 30 s. Nothing here used to send
  # a byte in either direction, so the connection died silently and we only found out
  # on the next INVITE, which then went nowhere.
  #
  # A browser answers a ping in its WebSocket stack, without waking the JS client, so
  # this works against any client. Missed pongs are counted rather than trusted once:
  # @max_missed consecutive silent periods close the connection with a reason in the
  # log, instead of leaving a half-open socket that only fails when a call needs it.
  @default_keepalive_period 30
  @max_missed 3

  @spec is_reliable() :: boolean()
  def is_reliable, do: true

  @impl true
  def init({ dest_ip, dest_port}) do
    initial_state = %{ t_isreliable: true,
      upperlayer: nil, destip: dest_ip, destport: dest_port }

    try do
      state = SIP.Transport.ImplHelpers.connect(initial_state, :wss)
      # Outbound: Socket.Web.connect! has already spawned the reader (mode: :active),
      # so the connection is live and the keep-alive starts here. Inbound starts it
      # in :activate_socket, which is where its reader is spawned.
      { :ok, start_keepalive(state) }
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
    {:noreply, start_keepalive(%{state | socket: ws})}
  end

  # Keep-alive tick: ping, then judge the *previous* period. `rx` is set by every
  # inbound frame — a pong, a SIP message, a CRLF keep-alive — so a connection
  # carrying traffic is never pinged into being declared dead.
  @impl true
  def handle_info(:wss_keepalive, state) do
    state = if state.rx, do: %{state | missed: 0}, else: %{state | missed: state.missed + 1}

    cond do
      state.missed >= @max_missed ->
        Logger.warning([module: __MODULE__, message: "WSS: no answer from #{peer(state)} after " <>
          "#{state.missed} keep-alive periods (#{state.missed * keepalive_period()}s), closing"])
        {:stop, :normal, state}

      true ->
        case Socket.Web.ping(state.socket, <<"elixip">>) do
          {:error, reason} ->
            Logger.warning([module: __MODULE__,
              message: "WSS: keep-alive ping to #{peer(state)} failed (#{inspect(reason)}), closing"])
            {:stop, :normal, state}

          _cookie ->
            Logger.debug([module: __MODULE__, message: "WSS: keep-alive ping -> #{peer(state)}" <>
              (if state.missed > 0, do: " (#{state.missed} period(s) unanswered)", else: "")])
            {:noreply, schedule_keepalive(%{state | rx: false})}
        end
    end
  end

  # The peer answered our ping — the connection is alive whatever else is idle.
  def handle_info({:web_pong, _socket, _cookie}, state) do
    Logger.debug([module: __MODULE__, message: "WSS: pong <- #{peer(state)}"])
    {:noreply, %{state | rx: true, missed: 0}}
  end

  # Handle data reception. `state.destip` is the dialed hostname for WSS (the
  # resolver delegates DNS to the socket layer), so use the socket's real peer
  # address as the message source — a proper IP tuple, like UDP passes. Falls
  # back to the stored dest only if the peer address is momentarily unavailable.
  def handle_info({:web, socket, data}, state ) do
    state = %{state | rx: true, missed: 0}

    # RFC 5626 §4.4.1, which RFC 7118 §4 carries over to WebSocket: a client that
    # sends the double-CRLF ping expects the single-CRLF pong, and treats its
    # absence as a dead flow — it then closes and re-registers, on the period of
    # its own keep-alive timer. Dropping the ping silently (the framework's
    # default policy, SIPMsg.keepalive?/1) is what a *datagram* transport does;
    # a connected transport owes the answer.
    if SIPMsg.keepalive?(data) do
      Logger.debug([module: __MODULE__, message: "WSS: CRLF keep-alive from #{peer(state)}, answering"])

      case Socket.Web.send(socket, {:text, "\r\n"}) do
        :ok -> :ok
        {:error, reason} ->
          Logger.debug([module: __MODULE__,
            message: "WSS: failed to answer the CRLF keep-alive: #{inspect(reason)}"])
      end

      { :noreply, state }
    else
      { src_ip, src_port } =
        case SIP.Transport.ImplHelpers.remote_address(socket) do
          { ip, port } -> { ip, port }
          nil -> { state.destip, state.destport }
        end

      SIP.Transport.ImplHelpers.process_incoming_message(state, data, "WSS", __MODULE__, socket, src_ip, src_port)
      { :noreply, state }
    end
  end

  # Close frame from the peer. The reason is the one thing that tells a normal
  # hang-up from a policy violation or a proxy timing the flow out, so it is
  # logged rather than flattened into "closed".
  def handle_info({:web_closed, _socket, reason}, state) do
    Logger.info([module: __MODULE__,
      message: "WSS connection from #{peer(state)} closed: #{inspect(reason)}"])
    {:stop, :normal, state}
  end

  def handle_info({:web_closed, _socket}, state) do
    Logger.info([module: __MODULE__, message: "WSS connection from #{peer(state)} closed by peer"])
    {:stop, :normal, state}
  end

  # The Socket.Web reader process exited. `:normal` is the loop returning after it
  # reported the close above; anything else is the reader itself dying — a crash in
  # the frame decoder, which drops a working connection and used to leave a single
  # debug line as the only trace.
  def handle_info({:DOWN, _ref, :process, _pid, :normal}, state) do
    Logger.debug([module: __MODULE__, message: "WSS reader process exited, stopping transport"])
    {:stop, :normal, state}
  end

  def handle_info({:DOWN, _ref, :process, _pid, reason}, state) do
    Logger.warning([module: __MODULE__, message: "WSS reader process for #{peer(state)} died: " <>
      "#{inspect(reason)} — dropping the connection"])
    {:stop, :normal, state}
  end

  # ---- keep-alive helpers ---------------------------------------------------

  # Period in seconds; 0 (or any non-positive value) disables the keep-alive, for a
  # deployment that already has one on the path and wants the connection left alone.
  defp keepalive_period do
    Application.get_env(:elixip2, :wss_keepalive_period, @default_keepalive_period)
  end

  defp start_keepalive(state) do
    schedule_keepalive(Map.merge(state, %{rx: false, missed: 0}))
  end

  defp schedule_keepalive(state) do
    period = keepalive_period()

    if is_integer(period) and period > 0 do
      Process.send_after(self(), :wss_keepalive, period * 1000)
    end

    state
  end

  defp peer(state) do
    ip = if is_tuple(state.destip), do: NetUtils.ip2string(state.destip), else: state.destip
    "#{ip}:#{state.destport}"
  end

  # See SIP.Transport.TCP.terminate/2: announced here so a crash says as much as
  # a clean close (design §14.4, R4). Both stop paths above converge on it, which
  # is also why neither announces anything itself.
  @impl true
  def terminate(_reason, state) do
    SIP.Transport.ImplHelpers.notify_transport_down(__MODULE__, state)

    if not is_nil(state.socket) do
      Socket.close(state.socket)
    end
  end
end
