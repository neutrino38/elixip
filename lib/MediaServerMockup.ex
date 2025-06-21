defmodule MediaServer.Mockup do
  use GenServer
  require Logger
  require Socket.UDP
  require ExSDP


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
  @spec connectStream(
          atom() | pid() | {atom(), any()} | {:via, atom(), any()},
          any(),
          any(),
          any(),
          any()
        ) :: any()
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

  defp add_codec(m, pt) when pt in 0..127 do
    codecs = List.insert_at(m.fmt, pt, -1)
    Map.put(m, :fmt, codecs)
  end

  defp add_codec(m, :audio, "PCMU") do
    ExSDP.add_attribute(m, %ExSDP.Attribute.RTPMapping{ payload_type: 0, encoding: "PCMU", clock_rate: 8000 })
    |> add_codec(0)
  end

  defp add_codec(m, :audio, "OPUS") do
    ExSDP.add_attribute(m, %ExSDP.Attribute.RTPMapping{ payload_type: 99, encoding: "OPUS", clock_rate: 16000 })
    |> ExSDP.add_attribute(%ExSDP.Attribute.FMTP{ pt: 99, useinbandfec: "1",  minptime: "10" })
    |> add_codec(99)
  end

  defp add_codec(m, :video, "H264") do
    ExSDP.add_attribute(m, %ExSDP.Attribute.RTPMapping{ payload_type: 99, encoding: "H264", clock_rate: 90000 })
    |> ExSDP.add_attribute(%ExSDP.Attribute.FMTP{ pt: 99, profile_level_id: "42e01f", packetization_mode: "1" })
    |> add_codec(99)
  end

  defp add_codec(m, :video, "VP8") do
    ExSDP.add_attribute(m, %ExSDP.Attribute.RTPMapping{ payload_type: 100, encoding: "VP8", clock_rate: 90000 })
    |> ExSDP.add_attribute(%ExSDP.Attribute.FMTP{ pt: 100, max_fr: "30" })
    |> add_codec(100)
  end

  defp add_codec(m, :text, "T140") do
    ExSDP.add_attribute(m, %ExSDP.Attribute.RTPMapping{ payload_type: 101, encoding: "T140", clock_rate: 1000 })
    |> add_codec(101)
  end

  defp add_codec(m, :text, "RED") do
    ExSDP.add_attribute(m, %ExSDP.Attribute.RTPMapping{ payload_type: 102, encoding: "RED", clock_rate: 1000 })
    |> ExSDP.add_attribute(%ExSDP.Attribute.FMTP{ pt: 102, redundant_payloads: "101/101/101" })
    |> add_codec(102)
  end

  defp add_codec(m, media, _codec) when media in [ :audio, :video, :text ] do
    m
  end


  defp build_sdp_media(media, port, bw, codecs, webrtc_support) do
    protocol = case webrtc_support do
      yes when yes in [:if_offered, :yes] -> "RTP/SAVPF"
      :no -> "RTP/AVPF"
      _ -> "RTP/AVP"
    end

    # Create the media structure
    m = %ExSDP.Media{ type: media, port: port, protocol: protocol, fmt: [] }
    m = if bw > 0 do
      Map.put(m, :bandwidth, [ %ExSDP.Bandwidth{ type: :AS, bandwidth: bw } ])
    else
      m
    end

    Enum.reduce(codecs, m, fn c, m -> add_codec(m, media, c) end)
  end

  defp create_local_sdp(state) when is_nil(state.local_sdp) do
    { :ok, { ip, port }} = Socket.local(state.rtp_socket)
    cnx = case ip do
      { _a,_b,_c,_d } -> %ExSDP.ConnectionData{ ttl: nil, address_count: 1,
        network_type: "IN", address: { :IP4, ip }}
      { _a, _b, _c, _d, _e, _f, _g, _h } -> %ExSDP.ConnectionData{ ttl: nil, address_count: 1,
        network_type: "IN", address: { :IP6, ip }}
    end

    sdp = ExSDP.new(
      version: 0,
      username: "Elixip2",
      session_id: :erlang.unique_integer([:positive, :monotonic]),
      session_version: 1,
      address: { :IP4, ip },
      connection_data: cnx)

    # Build media
    Enum.reduce(state.medias, sdp, fn media, sdp ->

      # Obtain media codecs and media bandwidth
      { bw, codecs } = case media do
        :video -> { state.video_bandwidth, state.video_codecs }
        :audio -> { state.audio_bandwidth, state.audio_codecs }
        :text -> { 0, [ "T140", "RED" ] }
        _ -> raise "unsupported media #{media}"
      end

      build_sdp_media(media, port, bw, codecs, state.webrtc_support)
      |> ExSDP.add_media(sdp)
    end)

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
      rtp_socket: nil,
      local_sdp: nil
    }

    case Socket.UDP.open([mode: :active]) do
      {:ok, socket} ->
        :ok = Socket.UDP.process(socket, self())
        state = Map.put(state, :rtp_socket, socket) |> create_local_sdp()
        { :ok, state }

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

  def handle_call(:close, _from, state) do
    { :stop, :normal, :ok, state }
  end

  def handle_call(:get_local_offer, _from, state) do
    case state.local_sdp do
      nil ->
        sdp = create_local_sdp(state)
        state = Map.put(state, :local_sdp, sdp)
        {:reply, {:ok, sdp}, state}
      sdp -> {:reply, {:ok, sdp}, state}
    end
  end

  def handle_call({:set_remote_offer, sdpstr}, _from, state) do
    sdp = ExSDP.parse(sdpstr)
    state = Map.put(state, :remote_sdp, sdp)
    { :reply, :ok, state }
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
