defmodule MediaServer.Mockup do
  @moduledoc "In-process stub implementing `MediaServer.Behaviour` for tests."

  @behaviour MediaServer.Behaviour

  # ── Server lifecycle ──────────────────────────────────────────────────────

  @impl MediaServer.Behaviour
  def connect(_server_addr) do
    GenServer.start(__MODULE__.Server, [])
  end

  @impl MediaServer.Behaviour
  def disconnect(server, _opts) do
    GenServer.stop(server, :normal)
    :ok
  end

  # ── Peer connection ───────────────────────────────────────────────────────

  @impl MediaServer.Behaviour
  def create_peer_connection(_server, event_sink, opts) do
    GenServer.start(__MODULE__.Conn, {event_sink, opts})
  end

  @impl MediaServer.Behaviour
  def get_local_offer(conn), do: GenServer.call(conn, :get_local_offer)

  @impl MediaServer.Behaviour
  def set_remote_answer(conn, sdp), do: GenServer.call(conn, {:set_remote_answer, sdp})

  @impl MediaServer.Behaviour
  def set_remote_offer(conn, sdp), do: GenServer.call(conn, {:set_remote_offer, sdp})

  @impl MediaServer.Behaviour
  def add_remote_candidate(conn, candidate),
    do: GenServer.call(conn, {:add_remote_candidate, candidate})

  @impl MediaServer.Behaviour
  def close_peer_connection(conn) do
    GenServer.stop(conn, :normal)
    :ok
  end

  # ── Player ────────────────────────────────────────────────────────────────

  @impl MediaServer.Behaviour
  def create_player(conn, file_path, opts) do
    event_sink = GenServer.call(conn, :get_event_sink)
    GenServer.start(__MODULE__.Player, {event_sink, file_path, opts})
  end

  @impl MediaServer.Behaviour
  def start_player(player), do: GenServer.call(player, :start)

  @impl MediaServer.Behaviour
  def pause_player(player), do: GenServer.call(player, :pause)

  @impl MediaServer.Behaviour
  def stop_player(player) do
    GenServer.stop(player, :normal)
    :ok
  end

  # ── Recorder ─────────────────────────────────────────────────────────────

  @impl MediaServer.Behaviour
  def create_recorder(conn, file_path, duration_ms, opts) do
    event_sink = GenServer.call(conn, :get_event_sink)
    GenServer.start(__MODULE__.Recorder, {event_sink, file_path, duration_ms, opts})
  end

  @impl MediaServer.Behaviour
  def start_recorder(recorder), do: GenServer.call(recorder, :start)

  @impl MediaServer.Behaviour
  def stop_recorder(recorder) do
    GenServer.call(recorder, :stop)
    :ok
  end

  # ── Echo ──────────────────────────────────────────────────────────────────

  @impl MediaServer.Behaviour
  def create_echo(conn) do
    event_sink = GenServer.call(conn, :get_event_sink)
    GenServer.start(__MODULE__.Echo, event_sink)
  end

  @impl MediaServer.Behaviour
  def stop_echo(echo) do
    GenServer.stop(echo, :normal)
    :ok
  end
end

# ── Server ────────────────────────────────────────────────────────────────────

defmodule MediaServer.Mockup.Server do
  use GenServer
  require Logger

  @impl true
  def init([]), do: {:ok, %{}}

  @impl true
  def terminate(_reason, _state) do
    Logger.info("MediaServer.Mockup.Server terminated")
    :ok
  end
end

# ── Peer connection ───────────────────────────────────────────────────────────

defmodule MediaServer.Mockup.Conn do
  use GenServer
  require Logger

  defstruct [
    :event_sink,
    :rtp_socket,
    :local_sdp,
    :remote_sdp,
    :remote_ip,
    :remote_port,
    medias: [:audio, :video],
    ice_servers: [],
    video_bandwidth: 0,
    audio_bandwidth: 0,
    video_codecs: ["H264", "VP8"],
    audio_codecs: ["OPUS", "PCMU"],
    webrtc_support: :if_offered
  ]

  @impl true
  def init({event_sink, opts}) do
    medias =
      case Keyword.get(opts, :media, :audio_video) do
        :audio -> [:audio]
        :video -> [:video]
        :audio_video -> [:audio, :video]
      end

    state = %__MODULE__{
      event_sink: event_sink,
      medias: medias,
      ice_servers: Keyword.get(opts, :ice_servers, []),
      video_bandwidth: Keyword.get(opts, :video_bandwidth, 0),
      audio_bandwidth: Keyword.get(opts, :audio_bandwidth, 0),
      video_codecs: List.wrap(Keyword.get(opts, :video_codec, ["H264", "VP8"])),
      audio_codecs: List.wrap(Keyword.get(opts, :audio_codec, ["OPUS", "PCMU"])),
      webrtc_support: Keyword.get(opts, :webrtc_support, :if_offered)
    }

    case Socket.UDP.open(mode: :active) do
      {:ok, socket} ->
        :ok = Socket.UDP.process(socket, self())
        {:ok, %{state | rtp_socket: socket}}

      {:error, reason} ->
        Logger.error("MediaServer.Mockup.Conn: failed to open RTP socket: #{inspect(reason)}")
        {:stop, reason}
    end
  end

  @impl true
  def handle_call(:get_event_sink, _from, state) do
    {:reply, state.event_sink, state}
  end

  @impl true
  def handle_call(:get_local_offer, _from, state) do
    sdp = state.local_sdp || build_local_sdp(state)
    {:reply, {:ok, to_string(sdp)}, %{state | local_sdp: sdp}}
  end

  @impl true
  def handle_call({:set_remote_answer, sdp_str}, _from, state) do
    case ExSDP.parse(sdp_str) do
      {:ok, sdp} ->
        send(self(), :notify_ice_connected)
        {:reply, :ok, %{state | remote_sdp: sdp}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:set_remote_offer, sdp_str}, _from, state) do
    case ExSDP.parse(sdp_str) do
      {:ok, remote_sdp} ->
        local_sdp = state.local_sdp || build_local_sdp(state)
        send(self(), :notify_ice_connected)
        {:reply, {:ok, to_string(local_sdp)}, %{state | remote_sdp: remote_sdp, local_sdp: local_sdp}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:add_remote_candidate, _candidate}, _from, state) do
    {:reply, :ok, state}
  end

  @impl true
  def handle_info(:notify_ice_connected, state) do
    send(state.event_sink, {:ms_event, self(), :ice_connected})
    {:noreply, state}
  end

  @impl true
  def handle_info({:udp, _socket, ip, port, _packet}, state) do
    {:noreply, %{state | remote_ip: ip, remote_port: port}}
  end

  @impl true
  def terminate(_reason, state) do
    if state.rtp_socket, do: Socket.close(state.rtp_socket)
    send(state.event_sink, {:ms_event, self(), :closed})
    :ok
  end

  # ── SDP helpers ───────────────────────────────────────────────────────────

  defp build_local_sdp(state) do
    {:ok, {ip, port}} = Socket.local(state.rtp_socket)

    cnx =
      case ip do
        {_, _, _, _} ->
          %ExSDP.ConnectionData{
            ttl: nil, address_count: 1,
            network_type: "IN", address: {:IP4, ip}
          }

        {_, _, _, _, _, _, _, _} ->
          %ExSDP.ConnectionData{
            ttl: nil, address_count: 1,
            network_type: "IN", address: {:IP6, ip}
          }
      end

    sdp =
      ExSDP.new(
        version: 0,
        username: "Elixip2",
        session_id: :erlang.unique_integer([:positive, :monotonic]),
        session_version: 1,
        address: {:IP4, ip},
        connection_data: cnx
      )

    Enum.reduce(state.medias, sdp, fn media, acc ->
      {bw, codecs} =
        case media do
          :video -> {state.video_bandwidth, state.video_codecs}
          :audio -> {state.audio_bandwidth, state.audio_codecs}
          :text -> {0, ["T140", "RED"]}
        end

      build_sdp_media(media, port, bw, codecs, state.webrtc_support)
      |> ExSDP.add_media(acc)
    end)
  end

  defp build_sdp_media(media, port, bw, codecs, webrtc_support) do
    protocol =
      case webrtc_support do
        s when s in [:if_offered, :yes] -> "RTP/SAVPF"
        :no -> "RTP/AVPF"
        _ -> "RTP/AVP"
      end

    m = %ExSDP.Media{type: media, port: port, protocol: protocol, fmt: []}

    m =
      if bw > 0 do
        Map.put(m, :bandwidth, [%ExSDP.Bandwidth{type: :AS, bandwidth: bw}])
      else
        m
      end

    Enum.reduce(codecs, m, fn codec, acc -> add_codec(acc, media, codec) end)
  end

  defp append_pt(m, pt), do: Map.put(m, :fmt, m.fmt ++ [pt])

  defp add_codec(m, :audio, "PCMU") do
    ExSDP.add_attribute(m, %ExSDP.Attribute.RTPMapping{
      payload_type: 0, encoding: "PCMU", clock_rate: 8000
    })
    |> append_pt(0)
  end

  defp add_codec(m, :audio, "OPUS") do
    ExSDP.add_attribute(m, %ExSDP.Attribute.RTPMapping{
      payload_type: 99, encoding: "OPUS", clock_rate: 16000
    })
    |> ExSDP.add_attribute(%ExSDP.Attribute.FMTP{pt: 99, useinbandfec: "1", minptime: "10"})
    |> append_pt(99)
  end

  defp add_codec(m, :video, "H264") do
    ExSDP.add_attribute(m, %ExSDP.Attribute.RTPMapping{
      payload_type: 99, encoding: "H264", clock_rate: 90000
    })
    |> ExSDP.add_attribute(%ExSDP.Attribute.FMTP{
      pt: 99, profile_level_id: "42e01f", packetization_mode: "1"
    })
    |> append_pt(99)
  end

  defp add_codec(m, :video, "VP8") do
    ExSDP.add_attribute(m, %ExSDP.Attribute.RTPMapping{
      payload_type: 100, encoding: "VP8", clock_rate: 90000
    })
    |> ExSDP.add_attribute(%ExSDP.Attribute.FMTP{pt: 100, max_fr: "30"})
    |> append_pt(100)
  end

  defp add_codec(m, :text, "T140") do
    ExSDP.add_attribute(m, %ExSDP.Attribute.RTPMapping{
      payload_type: 101, encoding: "T140", clock_rate: 1000
    })
    |> append_pt(101)
  end

  defp add_codec(m, :text, "RED") do
    ExSDP.add_attribute(m, %ExSDP.Attribute.RTPMapping{
      payload_type: 102, encoding: "RED", clock_rate: 1000
    })
    |> ExSDP.add_attribute(%ExSDP.Attribute.FMTP{pt: 102, redundant_payloads: "101/101/101"})
    |> append_pt(102)
  end

  defp add_codec(m, media, _codec) when media in [:audio, :video, :text], do: m
end

# ── Player ────────────────────────────────────────────────────────────────────

defmodule MediaServer.Mockup.Player do
  use GenServer

  defstruct [:event_sink, :file_path, loop: false, status: :idle]

  @impl true
  def init({event_sink, file_path, opts}) do
    {:ok,
     %__MODULE__{
       event_sink: event_sink,
       file_path: file_path,
       loop: Keyword.get(opts, :loop, false)
     }}
  end

  @impl true
  def handle_call(:start, _from, state) do
    send(state.event_sink, {:ms_event, self(), :player_started})
    unless state.loop, do: Process.send_after(self(), :end_of_file, 100)
    {:reply, :ok, %{state | status: :playing}}
  end

  @impl true
  def handle_call(:pause, _from, state) do
    {:reply, :ok, %{state | status: :paused}}
  end

  @impl true
  def handle_info(:end_of_file, state) do
    send(state.event_sink, {:ms_event, self(), :player_ended})
    {:noreply, %{state | status: :ended}}
  end
end

# ── Recorder ──────────────────────────────────────────────────────────────────

defmodule MediaServer.Mockup.Recorder do
  use GenServer

  defstruct [:event_sink, :file_path, :duration_ms, :opts, :timer_ref, status: :idle]

  @impl true
  def init({event_sink, file_path, duration_ms, opts}) do
    {:ok,
     %__MODULE__{
       event_sink: event_sink,
       file_path: file_path,
       duration_ms: duration_ms,
       opts: opts
     }}
  end

  @impl true
  def handle_call(:start, _from, state) do
    send(state.event_sink, {:ms_event, self(), :recorder_started})

    timer_ref =
      if state.duration_ms > 0 do
        Process.send_after(self(), :duration_elapsed, state.duration_ms)
      end

    {:reply, :ok, %{state | status: :recording, timer_ref: timer_ref}}
  end

  @impl true
  def handle_call(:stop, _from, state) do
    if state.timer_ref, do: Process.cancel_timer(state.timer_ref)
    send(state.event_sink, {:ms_event, self(), {:recorder_stopped, :caller}})
    {:reply, :ok, %{state | status: :stopped, timer_ref: nil}}
  end

  @impl true
  def handle_info(:duration_elapsed, state) do
    send(state.event_sink, {:ms_event, self(), {:recorder_stopped, :duration}})
    {:noreply, %{state | status: :stopped, timer_ref: nil}}
  end
end

# ── Echo ──────────────────────────────────────────────────────────────────────

defmodule MediaServer.Mockup.Echo do
  use GenServer

  defstruct [:event_sink]

  @impl true
  def init(event_sink) do
    {:ok, %__MODULE__{event_sink: event_sink}}
  end
end
