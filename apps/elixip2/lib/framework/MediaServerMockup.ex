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

  # Nothing to arm: the stub has no RTP to miss. It stays a call rather than a
  # bare `:ok` so a test can assert the framework reached the media layer at the
  # right moment — which is the whole subject of this callback (`answered?/1`).
  @impl MediaServer.Behaviour
  def call_answered(conn), do: GenServer.call(conn, :call_answered)

  @doc "Test hook: has the framework told this leg its call was answered?"
  @spec answered?(pid()) :: boolean()
  def answered?(conn), do: GenServer.call(conn, :answered?)

  @impl MediaServer.Behaviour
  def close_peer_connection(conn) do
    GenServer.stop(conn, :normal)
    :ok
  end

  # ── Bridge ────────────────────────────────────────────────────────────────

  @doc """
  Cross the two connections' media: what arrives on one goes out of the other,
  from that one's own socket to that one's own peer.

  A real bridge rather than a recorded call, so a call-flow test can assert that
  a packet sent into one leg comes out of the other. The transcoding policy is
  validated (a scenario typo must fail here, not silently) but has no effect:
  this stub relays payloads without looking at them, which is `:avoid` finding a
  common codec every time.
  """
  @impl MediaServer.Behaviour
  def bridge(a, b, opts) do
    case MediaServer.transcoding_policy(opts) do
      {:ok, _policy} ->
        :ok = GenServer.call(a, {:set_bridge_peer, b})
        :ok = GenServer.call(b, {:set_bridge_peer, a})

        # The other half of the contract: leg `a`'s answer, REBUILT now that both
        # legs are known. This mock returned a bare `:ok` for its whole life, so no
        # call-flow test ever exercised the branch a real adapter takes — and that
        # is where a caller silently kept the answer held since the INVITE
        # (2026-08-12). Opt-in, so every existing test keeps its plain `:ok`.
        case GenServer.call(a, :rebuilt_answer) do
          sdp when is_binary(sdp) -> {:ok, %{inbound_answer: sdp}}
          _ -> :ok
        end

      {:error, _} = err ->
        err
    end
  end

  @doc """
  Test hook: make the next `bridge/3` hand back `sdp` as leg `conn`'s rebuilt
  answer, the `{:ok, %{inbound_answer: sdp}}` form of the contract.

  A real adapter rebuilds when relaying narrows or reorders the codecs the caller
  was answered with. Nothing in the mock can decide that — it relays payloads
  without looking at them — so the test says what the rebuild produced.
  """
  @spec rebuild_answer_on_bridge(pid(), String.t()) :: :ok
  def rebuild_answer_on_bridge(conn, sdp), do: GenServer.call(conn, {:rebuild_answer, sdp})

  @doc """
  Test hook: play the RTP inactivity watchdog firing for `media` on `conn`.

  The mock has no watchdog of its own — it has no media to lose — but scenarios
  react to loss, so the events have to be producible. `{:media_timeout, media}`
  goes out at once, and `:media_lost` follows when every media the peer was
  sending has timed out, derived exactly as the real adapter derives it.
  """
  @spec simulate_media_timeout(pid(), MediaServer.media()) :: :ok
  def simulate_media_timeout(conn, media), do: GenServer.call(conn, {:media_timeout, media})

  @impl MediaServer.Behaviour
  def unbridge(a, b) do
    clear_bridge_peer(a)
    clear_bridge_peer(b)
    :ok
  end

  defp clear_bridge_peer(conn) do
    if is_pid(conn) and Process.alive?(conn) do
      GenServer.call(conn, {:set_bridge_peer, nil})
    end

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
    # §7.5's middle rung: `:avpf` offers RTP/AVPF (feedback profile, no
    # encryption or ICE); `:avp` — the default — is the plain RTP offer the mock
    # has always built.
    rtp_profile: :avp,
    ice_delay_ms: @default_ice_delay_ms,
    echo: false,
    # The other half of a B2BUA media path: incoming packets are handed to it,
    # and it sends them out of ITS socket toward ITS peer — the same shape a
    # real server's two endpoints have.
    bridge_peer: nil,
    # Answer that `bridge/3` will hand back for this leg, when a test asked for
    # one (see rebuild_answer_on_bridge/2). `nil` — the default — is the plain
    # `:ok` this mock returned for its whole life.
    rebuilt_answer: nil,
    # media-connectivity state, mirroring the real adapter (§4)
    recv_medias: nil,
    ice_notified: false,
    # …and its mirror for loss (see simulate_media_timeout/2)
    timed_out: MapSet.new(),
    lost_notified: false,
    # Whether the framework announced the call answered on this leg. The mock has
    # no watchdog to arm with it; it records the moment so a call-flow test can
    # check it happened, and happened after the ringing rather than during it.
    answered: false
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
      rtp_profile: if(Keyword.get(opts, :rtp_profile) == :avpf, do: :avpf, else: :avp),
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
  def handle_call(:call_answered, _from, state) do
    {:reply, :ok, %{state | answered: true}}
  end

  @impl true
  def handle_call(:answered?, _from, state) do
    {:reply, state.answered, state}
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
      {:ok, descs} ->
        state = state |> learn_remote(descs) |> schedule_connectivity(descs)
        {:reply, :ok, %{state | remote_sdp: sdp_str}}

      {:error, reason} ->
        {:reply, {:error, reason}, media_error(state, reason)}
    end
  end

  @impl true
  def handle_call({:set_remote_offer, sdp_str}, _from, state) do
    with {:ok, descs} <- Sdp.parse(sdp_str),
         {:ok, answer} <- build_answer(state, descs) do
      state = state |> learn_remote(descs) |> schedule_connectivity(descs)
      {:reply, {:ok, answer}, %{state | remote_sdp: sdp_str, local_sdp: answer}}
    else
      {:error, reason} -> {:reply, {:error, reason}, media_error(state, reason)}
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

  # Half of a bridge (MediaServer.Mockup.bridge/3): where this connection's
  # incoming media goes. nil takes the path down again.
  def handle_call({:set_bridge_peer, peer}, _from, state) do
    {:reply, :ok, %{state | bridge_peer: peer}}
  end

  def handle_call({:rebuild_answer, sdp}, _from, state) do
    {:reply, :ok, %{state | rebuilt_answer: sdp}}
  end

  def handle_call(:rebuilt_answer, _from, state) do
    {:reply, state.rebuilt_answer, state}
  end

  # The watchdog firing for one media, and the derived loss when every media of
  # R has fired — the same rule the real adapter applies, so a scenario clause
  # rehearsed here is the one that will run in production.
  def handle_call({:media_timeout, media}, _from, state) do
    send(state.event_sink, {:ms_event, self(), {:media_timeout, media}})

    state = %{state | timed_out: MapSet.put(state.timed_out, media)}
    r = state.recv_medias || MapSet.new()

    state =
      if not state.lost_notified and MapSet.size(r) > 0 and MapSet.subset?(r, state.timed_out) do
        send(state.event_sink, {:ms_event, self(), :media_lost})
        %{state | lost_notified: true}
      else
        state
      end

    {:reply, :ok, state}
  end

  # Media handed over by the other half of the bridge. It leaves through OUR
  # socket toward OUR peer — which is what makes the two directions independent,
  # and what a test asserting "it came out of the other leg" is really watching.
  #
  # A cast, not a call: both connections relay into each other, and two calls
  # crossing would deadlock the pair the first time media flowed both ways.
  @impl true
  def handle_cast({:bridged_media, packet}, state) do
    if state.rtp_socket && state.remote_ip do
      Socket.Datagram.send(state.rtp_socket, packet, {state.remote_ip, state.remote_port})
    end

    {:noreply, state}
  end

  # One simulated connectivity event per media of R, in negotiation order, then
  # the derived :ice_connected — the rule of docs/design/DESIGN-FRAMEWORK.md#66-media-connectivity-when-may-a-scenario-send.
  @impl true
  def handle_info({:notify_media_connected, media}, state) do
    send(state.event_sink, {:ms_event, self(), {:media_connected, media}})

    state = %{
      state
      | timed_out: MapSet.delete(state.timed_out, media),
        lost_notified: false
    }

    {:noreply, maybe_notify_ice_connected(state, media)}
  end

  @impl true
  def handle_info({:udp, _socket, ip, port, packet}, state) do
    # Echo: loop every received media packet back to its sender.
    if state.echo and state.rtp_socket do
      Socket.Datagram.send(state.rtp_socket, packet, {ip, port})
    end

    # Bridge: hand it to the other leg, which sends it on from its own socket.
    if is_pid(state.bridge_peer) and Process.alive?(state.bridge_peer) do
      GenServer.cast(state.bridge_peer, {:bridged_media, packet})
    end

    # Latch onto where the media actually comes from, which is what a NATed peer
    # makes necessary — it overrides the address its SDP announced.
    {:noreply, %{state | remote_ip: ip, remote_port: port}}
  end

  # Emit the async media-negotiation-failure event (Behaviour {:media_error, _}),
  # mirroring MediaServer.Mendooze.Conn.fail/2 so CI scenarios can capture it.
  defp media_error(state, reason) do
    send(state.event_sink, {:ms_event, self(), {:media_error, reason}})
    state
  end

  # Where this connection sends: what the peer's SDP says, taken from the first
  # media it did not decline. Until now the mock only ever learned that from
  # traffic it received, which is enough for an echo (you answer the sender) and
  # not for a bridge — the leg that has to speak first would have nowhere to
  # send. A real server addresses the SDP and only *latches* onto the observed
  # source afterwards, which is what handle_info({:udp, …}) does.
  defp learn_remote(state, descs) do
    case Enum.find(descs, &(Map.get(&1, :port, 0) > 0 and not is_nil(Map.get(&1, :ip)))) do
      %{ip: ip, port: port} ->
        case :inet.parse_address(String.to_charlist(ip)) do
          {:ok, addr} -> %{state | remote_ip: addr, remote_port: port}
          _ -> state
        end

      _ ->
        state
    end
  end

  # Simulate ICE/DTLS connectivity checks taking a short, non-zero time. Video
  # is delivered last on purpose: that is the ordering the real peers show (a
  # camera opens well after the microphone) and the one the rule must survive.
  defp schedule_connectivity(state, descs) do
    r = receiving_medias(descs)

    if MapSet.size(r) == 0 do
      send(state.event_sink, {:ms_event, self(), :media_send_only})
      %{state | recv_medias: r}
    else
      r
      |> Enum.sort_by(&if(&1 == :video, do: 1, else: 0))
      |> Enum.with_index()
      |> Enum.each(fn {media, i} ->
        delay = state.ice_delay_ms + i * div(state.ice_delay_ms, 2)

        if delay > 0 do
          Process.send_after(self(), {:notify_media_connected, media}, delay)
        else
          send(self(), {:notify_media_connected, media})
        end
      end)

      %{state | recv_medias: r}
    end
  end

  defp receiving_medias(descs) do
    for %{transport: t} = d <- descs,
        t != :ws,
        Map.get(d, :direction, :sendrecv) in [:sendrecv, :sendonly],
        into: MapSet.new(),
        do: d.type
  end

  defp maybe_notify_ice_connected(%{ice_notified: true} = state, _media), do: state

  defp maybe_notify_ice_connected(state, media) do
    r = state.recv_medias || MapSet.new()
    ready? = if :video in r, do: media == :video, else: media in r

    if ready? do
      send(state.event_sink, {:ms_event, self(), :ice_connected})
      %{state | ice_notified: true}
    else
      state
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
  # (e.g. isolated CI environments). get_local_ips/1 already leaves out the
  # scopes an SDP c= line must not carry.
  defp local_media_ip do
    case SIP.NetUtils.get_local_ips([:ipv4]) ++ SIP.NetUtils.get_local_ips([:ipv6]) do
      [ip | _] -> ip
      [] -> {127, 0, 0, 1}
    end
  end

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

    cond do
      webrtc? ->
        Map.merge(base, %{
          crypto: {:dtls, :actpass, "sha-256", state.local_fingerprint},
          ice: state.local_ice,
          rtcp_mux: true,
          mid: to_string(media),
          candidates: Sdp.host_candidates(ip_str, port, true),
          rtcp_fb: media == :video
        })

      # The §7.5 middle rung: the feedback profile, nothing else. WebRTC already
      # implies SAVPF, hence the ordering — the two are a ladder, not a matrix.
      state.rtp_profile == :avpf ->
        Map.merge(base, %{protocol: "RTP/AVPF", rtcp_fb: media == :video})

      true ->
        base
    end
  end

  # Build a gateway-like ANSWER from the parsed offer (§2.6): answer only the
  # offered medias we support, in the offerer's PT numbering, mirroring
  # protocol/mux/mid/direction, setup:passive, plus session-level a=ice-lite for
  # WebRTC answers (the mock stands in for the ICE-lite IVeS gateway in CI).
  defp build_answer(state, descs) do
    offer_dtls? = Enum.any?(descs, &match?({:dtls, _, _, _}, Map.get(&1, :crypto)))

    cond do
      offer_dtls? and state.webrtc_support == :no ->
        {:error, :webrtc_not_supported}

      descs == [] ->
        {:error, :no_common_media}

      true ->
        {ip, ip_str, port} = local_media(state)
        webrtc? = offer_dtls? and state.webrtc_support in [:yes, :if_offered]

        # G9: one answer m= per offered m=, in order; sections we can't answer
        # (unsupported transport/type, disabled media, or no common codec) are
        # declined with a port-0 rejection echoing the offered transport + fmt.
        #
        # Except `transport: :ws` (text over a WebSocket): both real adapters
        # OMIT that section rather than decline it — the deployed client does
        # not digest a port-0 echo (S5 plan §D7) — and this stub cannot host a
        # WebSocket anyway. Omitting keeps the mock's dialect converging with
        # the adapters call-flow tests actually rehearse.
        {medias, accepted} =
          descs
          |> Enum.reject(&(Map.get(&1, :transport, :rtp) == :ws))
          |> Enum.map_reduce(0, fn desc, count ->
            case answer_or_reject(state, desc, port, ip_str, webrtc?) do
              {:answer, spec} -> {spec, count + 1}
              {:reject, spec} -> {spec, count}
            end
          end)

        if accepted == 0 do
          {:error, :no_common_codec}
        else
          {:ok, Sdp.build(%{ip: ip, ice_lite: webrtc?, medias: medias})}
        end
    end
  end

  defp answer_or_reject(state, desc, port, ip_str, webrtc?) do
    # the `transport: :rtp` guard is a belt: WS text sections were already
    # omitted upstream (see set_remote_offer)
    if Map.get(desc, :transport, :rtp) == :rtp and
         Map.get(desc, :supported?, false) and desc.type in state.medias do
      case Sdp.negotiate(desc, codecs_for(state, desc.type), desc.type == :audio) do
        {:ok, neg} -> {:answer, answer_media_spec(state, desc, neg, port, ip_str, webrtc?)}
        {:error, :no_common_codec} -> {:reject, reject_media_spec(desc)}
      end
    else
      {:reject, reject_media_spec(desc)}
    end
  end

  # The offer's `a=mid` survives a rejection too (JSEP §5.3.1) — same rule as the real
  # adapter, so the mock's dialect keeps converging with it.
  defp reject_media_spec(desc) do
    %{
      type: desc.type,
      protocol: desc.protocol,
      reject_fmt: Map.get(desc, :raw_fmt, []),
      mid: Map.get(desc, :mid)
    }
  end

  defp answer_media_spec(state, desc, neg, port, ip_str, webrtc?) do
    # offerer PT numbering (offerer pt => codec code); no delegation here, so
    # fmtp stays empty. G10: the telephone-event PT keeps its offered clock.
    rtpmaps = Sdp.answer_rtpmaps(desc.type, neg)

    base =
      %{
        type: desc.type,
        port: port,
        rtpmaps: rtpmaps,
        fmtp: %{},
        direction: Sdp.reverse_direction(desc.direction),
        protocol: desc.protocol,
        # Feedback is answered whenever the offer's profile carries it — which is
        # every WebRTC offer, and a plain RTP/AVPF one (§7.5's middle rung) too.
        rtcp_fb: desc.type == :video and String.ends_with?(desc.protocol, "F")
      }
      |> maybe_bw(Sdp.negotiate_bandwidth(desc.bandwidth, bandwidth_for(state, desc.type)))

    if webrtc? do
      Map.merge(base, %{
        crypto: {:dtls, :passive, "sha-256", state.local_fingerprint},
        ice: state.local_ice,
        rtcp_mux: desc.rtcp_mux,
        mid: desc.mid,
        candidates: Sdp.host_candidates(ip_str, port, desc.rtcp_mux)
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

  # ice-char alphabet (RFC 8839 §5.4): hex, like the real adapters — base64url
  # emits `-`/`_`, which strict SDP parsers reject.
  defp random_token(bytes),
    do: :crypto.strong_rand_bytes(bytes) |> Base.encode16(case: :lower)

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
