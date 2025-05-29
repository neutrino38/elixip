defmodule SIP.Transport.TCP do
  @moduledoc """
  TCP transport layer for SIP. Client version only for the moment
  """
  alias SIP.NetUtils
  use GenServer
  require Logger
  require Socket.UDP

  @transport_str "tcp"
  # @default_local_port 5060
  def transport_str, do: @transport_str

  @spec is_reliable() :: boolean()
  def is_reliable, do: true

  defp connect(state) do
    sock = Socket.TCP.connect!(state.destip, state.destport, [ timeout: 10000, mode: :active ])
    # Optain local IP and port
    {local_ip, local_port} = Socket.local!(sock)

    #Bind the socket to the GenServer process
    Socket.process!(sock, self())

    # Return the local IP and port inside the state map.
    Map.put(state, :localip, local_ip) |> Map.put(:localport, local_port)
  end

  @impl true
  def init({ dest_ip, dest_port}) do
    initial_state = %{ t_isreliable: true,
      upperlayer: nil, destip: dest_ip, destport: dest_port,
      buffer: %SIP.Transport.Depack{}  }

    try do
      state = connect(initial_state)

      { :ok, state }
    rescue
      err in Socket.Error ->
        Logger.error([ module: __MODULE__, dest: "#{NetUtils.ip2string(dest_ip)}:#{dest_port}}",
                       message: "Failed to connect socket: #{err.message} "])
        { :stop, err.message }
    end
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

  @spec handle_call(  {:sendmsg, binary(), :inet.ip_address(), :inet.port_number }, any(), map() ) ::  { :reply, :ok, map() }
  def handle_call({ :sendmsg, msgstr, _destip, _dest_port }, _from, state) do

    Logger.debug("TCP: Message sent to #{state.destip}:#{state.destport} ---->\r\n" <> msgstr <> "\r\n-----------------")
    case Socket.Stream.send(state.socket, msgstr) do
      :ok -> { :reply, :ok, state }
      { :error, reason } ->
        Logger.debug("TCP: failed to send message. Error: #{reason}");
        { :reply, :transporterror, state }
    end
  end


  def process_incoming_message(state, message, tp_name, tp_mod) do
    case SIP.Transac.process_sip_message(message) do
      :ok -> { :noreply, state }

      { :no_matching_transaction, parsed_msg } ->
        if is_atom(parsed_msg.method) do
          # We need to start a new transaction
          SIP.Transac.start_uas_transaction(parsed_msg,
              { state.localip, state.localport, tp_name, tp_mod, self(), state.upperlayer } , { state.destip, state.destport })
        else
          Logger.error("Received a SIP #{parsed_msg.response} response from #{state.destip}:#{state.destport} not linked to any transaction. Droping it")
          { :noreply, state }
        end

      _ ->
        Logger.error("Received an invalid SIP message from #{NetUtils.ip2string(state.destip)}:#{state.destport}")
        { :noreply, state }
    end
  end

  # Handle data reception
  @impl true
  def handle_info({:tcp, _socket, data}, state ) do
    buf = SIP.Transport.Depack.on_data_received(state.buf, data,
      fn what, msg ->
        case what do
          :ping -> nil
          :msg -> process_incoming_message(state, msg, "TCP", __MODULE__)
        end
      end)
    { :noreply, %{ state | buffer: buf } }
  end

  def handle_info( {:tcp_closed, _socket}, state ) do
    Logger.debug([ module: __MODULE__, message: "TCP cnx disconnected. stopping transport instance" ])

    # Notify all dialogs to give them a chance to restart the TCP connection
    SIP.Dialog.broadcast({ :tcp_client_closed, state.destip, state.destport })
    { :stop, state }
  end

  @impl true
  def terminate(_reason, state) do
    if not is_nil(state.socket) do
      Socket.close(state.socket)
    end
  end
end
