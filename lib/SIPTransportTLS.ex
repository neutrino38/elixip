defmodule SIP.Transport.TLS do
  @moduledoc """
  TLS transport layer for SIP. Client version only for the moment
  """
  alias SIP.NetUtils
  use GenServer
  require Logger
  require Socket.SSL
  require SIP.Transport.ImplHelpers

  @transport_str "tls"
  # @default_local_port 5060
  def transport_str, do: @transport_str

  @spec is_reliable() :: boolean()
  def is_reliable, do: true

  @impl true
  def init({ dest_ip, dest_port}) do
    initial_state = %{ t_isreliable: true,
      upperlayer: nil, destip: dest_ip, destport: dest_port,
      buffer: %SIP.Transport.Depack{}  }

    try do
      state = SIP.Transport.ImplHelpers.connect(initial_state, :tls)
      { :ok, state }
    rescue
      err in Socket.Error ->
        dest_ip = if is_tuple(dest_ip) do
          NetUtils.ip2string(dest_ip)
        else
          dest_ip
        end
        Logger.info([ module: __MODULE__, dest: "#{dest_ip}:#{dest_port}",
                       message: "Failed to connect socket: #{err.message} "])
        { :stop, :cnxerror }
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

  def handle_call(:getlocalipandport, _from, state) do
    { :reply, { :ok, state.localip, state.localport }, state}
  end


  @spec handle_call(  {:sendmsg, binary(), :inet.ip_address(), :inet.port_number }, any(), map() ) ::  { :reply, :ok, map() }
  def handle_call({ :sendmsg, msgstr, _destip, _dest_port }, _from, state) do

    Logger.debug("TLS: Message sent to #{state.destip}:#{state.destport} ---->\r\n" <> msgstr <> "\r\n-----------------")
    case Socket.Stream.send(state.socket, msgstr) do
      :ok -> { :reply, :ok, state }
      { :error, reason } ->
        Logger.debug("TLS: failed to send message. Error: #{reason}");
        { :reply, :transporterror, state }
    end
  end



  # Handle data reception
  @impl true
  def handle_info({:tcp, socket, data}, state ) do
    buf = SIP.Transport.Depack.on_data_received(state.buffer, data,
      fn what, msg ->
        case what do
          :ping -> nil
          :msg -> SIP.Transport.ImplHelpers.process_incoming_message(state, msg, "TLS", __MODULE__, socket, state.destip, state.destport)
        end
      end)
    { :noreply, %{ state | buffer: buf } }
  end

  def handle_info( {:tcp_closed, _socket}, state ) do
    Logger.debug([ module: __MODULE__, message: "Cnx disconnected. stopping transport instance" ])

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
