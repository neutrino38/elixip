defmodule MediaServer.Mockup do
  use GenServer
  require Logger
  require Socket.UDP


  defmodule Echo do
    use GenServer
    defstruct [
      audio_out: nil,
      video_out: nil,
      text_out: nil
    ]

    @impl true
    def init(_arg) do
      state = %Echo{}
      {:ok, state}
    end

    @impl true
    def handle_call({:connect, media, targed_pid}, _from, state) do
      case media do
        :audio -> {:reply, :ok, %{state | audio_out: targed_pid}}
        :video -> {:reply, :ok, %{state | video_out: targed_pid}}
        :text -> {:reply, :ok, %{state | text_out: targed_pid}}
        _ -> {:reply, {:error, :invalid_media}, state}
      end
    end

    @impl true
    def handle_cast({:packet, media, packet}, state) do
      case media do
        :audio when not is_nil(state.audio_out) ->
          GenServer.cast(state.audio_out, {:packet, media, packet})

        :video when not is_nil(state.video_out) ->
          GenServer.cast(state.video_out, {:packet, media, packet})

        :text when not is_nil(state.text_out) ->
          GenServer.cast(state.text_out, {:packet, media, packet})
        _ -> :ok
      end
      {:noreply, state}
    end
  end


  @behaviour MediaServer.Behavior



  ## Client API


  @impl MediaServer.Behavior
  def createRTCConnection(_hostname, event_sink, options) when is_pid(event_sink) and is_list(options) do
    GenServer.start(__MODULE__, { event_sink, options })
  end

  @impl MediaServer.Behavior
  def createMediaEcho(pid) when is_pid(pid) do
    GenServer.call( pid, :create_media_echo )
  end

  @impl MediaServer.Behavior
  def createMediaPlayer(pid, url, loop) when is_pid(pid) and is_binary(url) and is_boolean(loop) do
    GenServer.call(pid, {:create_media_player, url, loop})
  end

  @impl MediaServer.Behavior
  def createMediaRecorder(pid, url, duration, options) when is_pid(pid) and is_binary(url) and is_integer(duration) and is_list(options) do
    GenServer.call(pid, {:create_media_recorder, url, duration, options})
  end

  @impl MediaServer.Behavior
  def connectStream(pid, direction, option, media_resource_type, media_ressource_id) do
    GenServer.call(pid, {:connect_stream, direction, option, media_resource_type, media_ressource_id})
  end

  @impl MediaServer.Behavior
  def disconnectStream(pid, direction, options) do
    GenServer.call(pid, {:disconnect_stream, direction, options})
  end

  @impl MediaServer.Behavior
  def setEventSink(pid, event_sink) when is_pid(pid) and is_pid(event_sink) do
    GenServer.call(pid, {:set_event_sink, event_sink})
  end

  @impl MediaServer.Behavior
  def getLocalOffer(pid) do
    GenServer.call(pid, :get_local_offer)
  end

  @impl MediaServer.Behavior
  def setRemoteOffer(pid, remotesdp) do
    GenServer.call(pid, {:set_remote_offer, remotesdp})
  end

  @impl MediaServer.Behavior
  def close(pid) do
    GenServer.call(pid, :close)
  end

  ## Server Callbacks
  @impl true
  def init({ event_sink, options }) do
    state = %{
      event_sink: event_sink,
      medias: Keyword.get(options, :media_type, {:audio, :video}),
      ice_servers: Keyword.get(options, :ice_servers, []),
      video_bandwidth: Keyword.get(options, :video_bandwidth, 0),
      audio_bandwidth: Keyword.get(options, :audio_bandwidth, 0),
      video_codecs: Keyword.get(options, :video_codec, ["H264", "VP8"]),
      audio_codecs: Keyword.get(options, :audio_codec, ["OPUS", "PCMU"]),
      webrtc_support: Keyword.get(options, :webrtc_support, :if_offered),
      media_resources: %{
        players: %{},
        recorders: %{},
        echos: %{},
        mixers: %{}
      },
      media_streams: %{
        inbound: %{ audio: nil, video: nil, text: nil },
        outbound: %{ audio: nil, video: nil, text: nil }
      },
      rtp_socket: nil
    }

    case Socket.UDP.open([mode: :active]) do
      {:ok, socket} ->
        :ok = Socket.UDP.process(socket, self())
        { :ok, Map.put(state, :rtp_socket, socket) }

      { :error, err } ->
        Logger.error("Failed to allocate RTP port.")
        { :stop, err }
    end
  end

  @impl true
  def handle_call({:set_event_sink, pid }, _from, state) do
    {:reply, :ok, %{ state | event_sink: pid }}
  end

  def handle_call({:create_media_echo}, _from, state) do
    if Enum.count(state.media_resources.echos) < 1 do
      echo_id = :erlang.unique_integer([:positive, :monotonic])
      echo_pid = GenServer.start_link(Echo, [], name: {:global, "echo_#{echo_id}"})
      echos = Map.put(state.media_resources.echos, echo_id, echo_pid)
      {:reply, {:ok, echo_id}, %{state | media_resources: %{state.media_resources | echos: echos}}}
    else
      {:reply, {:error, :echo_already_exists}, state}
    end
  end

  def handle_call({:connect_stream, direction, options, media_resource_type, media_ressource_id}, _from, state) do
    medias = Keyword.get(options, :media_type, state.medias)
    state = Enum.reduce(medias, state, fn media, acc_state ->
      connect_single_stream_to_rtc_connection(acc_state, direction, media_resource_type, media_ressource_id, media)
    end)
    {:reply, {:ok, state}, state}
  end

  defp get_resource_pid(state, resource_type, ressource_id) do
    key = case resource_type do
      :player -> :players
      :recorder -> :recorders
      :echo -> :echos
      :mixer -> :mixers
      _ -> raise "Invalid resource type: #{resource_type}"
    end
    Map.get(state.media_resources, key) |> Map.get(ressource_id)
  end

  defp connect_single_stream_to_rtc_connection(state, direction, res_type, ressource_id, media) when media in [ :audio, :video, :text] do
    res_pid = get_resource_pid(state, res_type, ressource_id)
    case direction do
      :inbound ->
        inbound_streams = Map.put(state.media_streams.inbound, media, res_pid)
        media_streams = Map.put(state.media_streams, :inbound, inbound_streams)
        Map.put(state, :media_streams, media_streams)

      :outbound ->
        GenServer.call(res_pid, {:connect, media, self()})
        state
    end
  end


  @impl true
  @doc "Handle incoming UDP packets from RTP socket"
  def handle_info({:udp, _socket, ip, port, packet}, state) do
    if is_pid(state.media_streams.inbound.audio) do
      GenServer.cast(state.media_streams.inbound.audio, {:packet, :audio, packet})
    end
    {:noreply, Map.put(state, :remoteip, ip) |> Map.put(:remoteport, port)}
  end

  @impl true
  @doc "Handle outbound packets to be sent over the RTPC connection"
  def handle_cast({:packet, _media, packet}, state) do
    if is_tuple(state.remoteip) and state.remoteport > 0 do
      case Socket.Datagram.send(state.rtp_socket, packet, {state.remoteip, state.remoteport}) do
        :ok -> :ok
        {:error, reason} -> Logger.error("Failed to send RTP packet: #{reason}")
      end
    else
      Logger.error("No remote IP or port set for RTP packet.")
    end
    {:noreply, state}
  end


  @impl true
  def terminate(_reason, state) do
    Socket.close(state.rtp_socket)
    Logger.info("MediaServerMockup terminated.")
    :ok
  end
  # Add other callbacks and behavior functions as needed
end
