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
    GenServer.start(__MODULE__.Recorder, {conn, event_sink, file_path, duration_ms, opts})
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
    :ok = GenServer.call(conn, {:set_echo, true})
    GenServer.start(__MODULE__.Echo, {conn, event_sink})
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
  import Bitwise, only: [band: 2]

  alias MediaServer.Mendooze.Sdp

  # Default simulated delay (ms) between remote SDP negotiation and the
  # :ice_connected event, mimicking ICE/DTLS connectivity checks.
  @default_ice_delay_ms 150

  defstruct [
    :event_sink,
    :rtp_socket,
    :local_sdp,
    :remote_sdp,
    :remote_ip,
    :remote_port,
    :local_ice,
    :local_fingerprint,
    medias: [:audio, :video],
    ice_servers: [],
    video_bandwidth: 0,
    audio_bandwidth: 0,
    video_codecs: ["H264", "VP8"],
    audio_codecs: ["OPUS", "PCMU"],
    text_codecs: ["T140", "T140RED"],
    webrtc_support: :if_offered,
    ice_delay_ms: @default_ice_delay_ms,
    echo: false
  ]

  @impl true
  def init({event_sink, opts}) do
    medias = Keyword.get(opts, :media, :audio_video) |> MediaServer.media_list()

    state = %__MODULE__{
      event_sink: event_sink,
      medias: medias,
      ice_servers: Keyword.get(opts, :ice_servers, []),
      video_bandwidth: Keyword.get(opts, :video_bandwidth, 0),
      audio_bandwidth: Keyword.get(opts, :audio_bandwidth, 0),
      video_codecs: List.wrap(Keyword.get(opts, :video_codec, ["H264", "VP8"])),
      audio_codecs: List.wrap(Keyword.get(opts, :audio_codec, ["OPUS", "PCMU"])),
      text_codecs: List.wrap(Keyword.get(opts, :text_codec, ["T140", "T140RED"])),
      webrtc_support: Keyword.get(opts, :webrtc_support, :if_offered),
      ice_delay_ms: Keyword.get(opts, :ice_delay_ms, @default_ice_delay_ms),
      # Simulated local security material (no real DTLS/ICE stack behind it):
      # enough to build and parse plausible WebRTC SDP.
      local_ice: %{ufrag: random_token(8), pwd: random_token(24)},
      local_fingerprint: random_fingerprint()
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
  def handle_call(:get_medias, _from, state) do
    {:reply, state.medias, state}
  end

  @impl true
  def handle_call(:get_local_offer, _from, state) do
    sdp = state.local_sdp || build_local_sdp(state)
    {:reply, {:ok, sdp}, %{state | local_sdp: sdp}}
  end

  @impl true
  def handle_call({:set_remote_answer, sdp_str}, _from, state) do
    case Sdp.parse(sdp_str) do
      {:ok, _descs} ->
        schedule_ice_connected(state)
        {:reply, :ok, %{state | remote_sdp: sdp_str}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:set_remote_offer, sdp_str}, _from, state) do
    with {:ok, descs} <- Sdp.parse(sdp_str),
         {:ok, answer} <- build_answer(state, descs) do
      schedule_ice_connected(state)
      {:reply, {:ok, answer}, %{state | remote_sdp: sdp_str, local_sdp: answer}}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:add_remote_candidate, _candidate}, _from, state) do
    {:reply, :ok, state}
  end

  # Toggle media loopback (echo). When enabled, incoming RTP is sent back to
  # the remote peer, mimicking the real media server echo primitive.
  def handle_call({:set_echo, enabled}, _from, state) when is_boolean(enabled) do
    {:reply, :ok, %{state | echo: enabled}}
  end

  @impl true
  def handle_info(:notify_ice_connected, state) do
    send(state.event_sink, {:ms_event, self(), :ice_connected})
    {:noreply, state}
  end

  @impl true
  def handle_info({:udp, _socket, ip, port, packet}, state) do
    # Echo: loop every received media packet back to its sender.
    if state.echo and state.rtp_socket do
      Socket.Datagram.send(state.rtp_socket, packet, {ip, port})
    end

    {:noreply, %{state | remote_ip: ip, remote_port: port}}
  end

  # Simulate ICE/DTLS connectivity checks taking a short, non-zero time.
  defp schedule_ice_connected(state) do
    if state.ice_delay_ms > 0 do
      Process.send_after(self(), :notify_ice_connected, state.ice_delay_ms)
    else
      send(self(), :notify_ice_connected)
    end
  end

  @impl true
  def terminate(_reason, state) do
    if state.rtp_socket, do: Socket.close(state.rtp_socket)
    send(state.event_sink, {:ms_event, self(), :closed})
    :ok
  end

  # ── SDP helpers ───────────────────────────────────────────────────────────

  # Pick the first routable local address: prefer IPv4, fall back to IPv6 when
  # the host has no IPv4 interface, and finally loopback when neither exists
  # (e.g. isolated CI environments).
  defp local_media_ip do
    case SIP.NetUtils.get_local_ips([:ipv4]) do
      [ip | _] ->
        ip

      _ ->
        # Skip link-local IPv6 (fe80::/10): it is not routable without a zone
        # id and useless to advertise in SDP. Prefer a global address.
        ipv6 = SIP.NetUtils.get_local_ips([:ipv6])

        case Enum.find(ipv6, &(not link_local_ipv6?(&1))) || List.first(ipv6) do
          nil -> {127, 0, 0, 1}
          ip -> ip
        end
    end
  end

  # fe80::/10 — the top 10 bits are 1111 1110 10, i.e. first group masked with
  # 0xffc0 equals 0xfe80.
  defp link_local_ipv6?({g1, _, _, _, _, _, _, _}), do: band(g1, 0xFFC0) == 0xFE80
  defp link_local_ipv6?(_), do: false

  # Build the local OFFER, reusing MediaServer.Mendooze.Sdp (the pure SDP layer).
  # WebRTC transport plane (DTLS/ICE/mux/mid/candidates/rtcp-fb) iff
  # webrtc_support == :yes; otherwise a plain RTP/AVP offer (§2.6). No
  # session-level a=ice-lite in offers (D7).
  defp build_local_sdp(state) do
    {ip, ip_str, port} = local_media(state)
    webrtc? = state.webrtc_support == :yes

    medias =
      Enum.map(state.medias, fn media -> offer_media_spec(state, media, port, ip_str, webrtc?) end)

    Sdp.build(%{ip: ip, medias: medias})
  end

  defp offer_media_spec(state, media, port, ip_str, webrtc?) do
    base =
      %{type: media, port: port, codecs: codecs_for(state, media), direction: :sendrecv}
      |> maybe_bw(bandwidth_for(state, media))
      |> maybe_dtmf(media)

    if webrtc? do
      Map.merge(base, %{
        crypto: {:dtls, :actpass, "sha-256", state.local_fingerprint},
        ice: state.local_ice,
        rtcp_mux: true,
        mid: to_string(media),
        candidates: Sdp.host_candidates(ip_str, port, true),
        rtcp_fb: media == :video
      })
    else
      base
    end
  end

  # Build a gateway-like ANSWER from the parsed offer (§2.6): answer only the
  # offered medias we support, in the offerer's PT numbering, mirroring
  # protocol/mux/mid/direction, setup:passive, plus session-level a=ice-lite for
  # WebRTC answers (the mock stands in for the ICE-lite IVeS gateway in CI).
  defp build_answer(state, descs) do
    descs = Enum.filter(descs, &(&1.type in state.medias))
    offer_dtls? = Enum.any?(descs, &match?({:dtls, _, _, _}, &1.crypto))

    cond do
      offer_dtls? and state.webrtc_support == :no ->
        {:error, :webrtc_not_supported}

      descs == [] ->
        {:error, :no_common_media}

      true ->
        {ip, ip_str, port} = local_media(state)
        webrtc? = offer_dtls? and state.webrtc_support in [:yes, :if_offered]

        medias =
          Enum.flat_map(descs, fn desc ->
            case Sdp.negotiate(desc, codecs_for(state, desc.type), desc.type == :audio) do
              {:ok, neg} -> [answer_media_spec(state, desc, neg, port, ip_str, webrtc?)]
              {:error, :no_common_codec} -> []
            end
          end)

        if medias == [] do
          {:error, :no_common_codec}
        else
          {:ok, Sdp.build(%{ip: ip, ice_lite: webrtc?, medias: medias})}
        end
    end
  end

  defp answer_media_spec(state, desc, neg, port, ip_str, webrtc?) do
    # offerer PT numbering: derive the rtpmap entries from the negotiated map
    # (offerer pt => codec code). No delegation here, so fmtp stays empty.
    rtpmaps =
      neg.rtp_map
      |> Enum.sort_by(fn {pt, _code} -> String.to_integer(pt) end)
      |> Enum.flat_map(fn {pt_str, code} ->
        case Sdp.code_rtpmap(desc.type, code) do
          :unknown ->
            []

          {enc, clock, ch} ->
            [%{pt: String.to_integer(pt_str), encoding: enc, clock: clock, channels: ch}]
        end
      end)

    base =
      %{
        type: desc.type,
        port: port,
        rtpmaps: rtpmaps,
        fmtp: %{},
        direction: Sdp.reverse_direction(desc.direction),
        protocol: desc.protocol
      }
      |> maybe_bw(Sdp.negotiate_bandwidth(desc.bandwidth, bandwidth_for(state, desc.type)))

    if webrtc? do
      Map.merge(base, %{
        crypto: {:dtls, :passive, "sha-256", state.local_fingerprint},
        ice: state.local_ice,
        rtcp_mux: desc.rtcp_mux,
        mid: desc.mid,
        candidates: Sdp.host_candidates(ip_str, port, desc.rtcp_mux),
        rtcp_fb: desc.type == :video and String.ends_with?(desc.protocol, "F")
      })
    else
      base
    end
  end

  # The RTP socket is bound to the wildcard address (0.0.0.0); advertise the real
  # local IP in the SDP while keeping the socket's ephemeral port.
  defp local_media(state) do
    {:ok, {_bound_ip, port}} = Socket.local(state.rtp_socket)
    ip = local_media_ip()
    {ip, to_string(:inet.ntoa(ip)), port}
  end

  defp codecs_for(state, :audio), do: state.audio_codecs
  defp codecs_for(state, :video), do: state.video_codecs
  defp codecs_for(state, :text), do: state.text_codecs

  defp bandwidth_for(state, :video), do: state.video_bandwidth
  defp bandwidth_for(state, :audio), do: state.audio_bandwidth
  defp bandwidth_for(_state, _media), do: 0

  defp maybe_bw(spec, bw) when is_integer(bw) and bw > 0, do: Map.put(spec, :bandwidth, bw)
  defp maybe_bw(spec, _), do: spec

  defp maybe_dtmf(spec, :audio), do: Map.put(spec, :dtmf, true)
  defp maybe_dtmf(spec, _), do: spec

  defp random_token(len) do
    :crypto.strong_rand_bytes(len) |> Base.url_encode64(padding: false) |> binary_part(0, len)
  end

  # Plausible SHA-256 fingerprint (AA:BB:...) — no real DTLS stack behind it.
  defp random_fingerprint do
    :crypto.strong_rand_bytes(32)
    |> :binary.bin_to_list()
    |> Enum.map_join(":", fn b -> b |> Integer.to_string(16) |> String.pad_leading(2, "0") end)
    |> String.upcase()
  end
end

# ── Player ────────────────────────────────────────────────────────────────────

defmodule MediaServer.Mockup.Player do
  use GenServer

  defstruct [:event_sink, :file_path, loop: false, status: :idle, duration_ms: 15_000]

  @impl true
  def init({event_sink, file_path, opts}) do
    {:ok,
     %__MODULE__{
       event_sink: event_sink,
       file_path: file_path,
       loop: Keyword.get(opts, :loop, false),
       # Simulated playback duration before :player_ended is emitted (default 15 s,
       # overridable via the create_player opts for faster unit tests).
       duration_ms: Keyword.get(opts, :duration_ms, 15_000)
     }}
  end

  @impl true
  def handle_call(:start, _from, state) do
    send(state.event_sink, {:ms_event, self(), :player_started})
    unless state.loop, do: Process.send_after(self(), :end_of_file, state.duration_ms)
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

  defstruct [
    :conn,
    :event_sink,
    :file_path,
    :duration_ms,
    :opts,
    :timer_ref,
    wait_video: true,
    echo: false,
    status: :idle
  ]

  @impl true
  def init({conn, event_sink, file_path, duration_ms, opts}) do
    # waitVideo is auto-disabled when video is not part of the connection,
    # mirroring the real server (no video negotiated → record immediately).
    wait_video =
      Keyword.get(opts, :wait_video, true) and :video in GenServer.call(conn, :get_medias)

    {:ok,
     %__MODULE__{
       conn: conn,
       event_sink: event_sink,
       file_path: file_path,
       duration_ms: duration_ms,
       opts: opts,
       wait_video: wait_video,
       echo: Keyword.get(opts, :echo, false)
     }}
  end

  @impl true
  def handle_call(:start, _from, state) do
    # echo: loop received media back to the sender while recording, using the
    # peer connection loopback (same primitive as the Echo resource).
    if state.echo, do: set_conn_echo(state, true)
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
    if state.echo, do: set_conn_echo(state, false)
    send(state.event_sink, {:ms_event, self(), {:recorder_stopped, :caller}})
    {:reply, :ok, %{state | status: :stopped, timer_ref: nil}}
  end

  @impl true
  def handle_info(:duration_elapsed, state) do
    if state.echo, do: set_conn_echo(state, false)
    send(state.event_sink, {:ms_event, self(), {:recorder_stopped, :duration}})
    {:noreply, %{state | status: :stopped, timer_ref: nil}}
  end

  @impl true
  def terminate(_reason, state) do
    # The echo stops with the recording; make sure it does not outlive a
    # recorder killed while still recording.
    if state.echo and state.status == :recording, do: set_conn_echo(state, false)
    :ok
  end

  defp set_conn_echo(state, enabled) do
    if state.conn && Process.alive?(state.conn) do
      GenServer.call(state.conn, {:set_echo, enabled})
    end
  end
end

# ── Echo ──────────────────────────────────────────────────────────────────────

defmodule MediaServer.Mockup.Echo do
  use GenServer

  defstruct [:conn, :event_sink]

  @impl true
  def init({conn, event_sink}) do
    send(event_sink, {:ms_event, self(), :echo_started})
    {:ok, %__MODULE__{conn: conn, event_sink: event_sink}}
  end

  @impl true
  def terminate(_reason, state) do
    # Disable loopback on the peer connection if it is still alive.
    if state.conn && Process.alive?(state.conn) do
      GenServer.call(state.conn, {:set_echo, false})
    end

    :ok
  end
end
