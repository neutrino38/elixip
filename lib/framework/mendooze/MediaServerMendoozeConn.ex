defmodule MediaServer.Mendooze.Conn do
  @moduledoc """
  One peer connection of the Mendooze JSR309 adapter: a MediaSession plus
  an Endpoint, driven over XML-RPC following the call flows of the server
  documentation (§9): offer/answer in both directions, security material
  before any media start, and the RTP inactivity watchdog armed after the
  answer has been processed.

  Sub-resources (player, recorder, echo) are entries in this GenServer's
  state, not processes; their opaque handle is `{conn_pid, kind, ref}`.

  On any RPC failure during setup the server-side resources are torn down
  (per-media stops, EndpointDelete, MediaSessionDelete) before the error
  is returned, so nothing leaks on the media server.
  """

  use GenServer
  require Logger

  alias MediaServer.Mendooze
  alias MediaServer.Mendooze.{Sdp, XmlRpc}

  @call_timeout 30_000
  @default_rtp_timeout_ms 10_000

  # MediaFrame::Type wire values
  @media_int %{audio: 0, video: 1, text: 2, application: 3}
  # MediaFrame::MediaProtocol RTP
  @proto_rtp 0

  @default_audio_codecs ["OPUS", "PCMU", "PCMA"]
  @default_video_codecs ["H264", "VP8"]
  @default_text_codecs ["T140", "T140RED"]

  # Receive bandwidth advertised as b=AS: on the video media (kb/s)
  @default_video_bandwidth_kbps 800

  # ── API (called through the MediaServer.Mendooze facade) ───────────────────

  def start(server, event_sink, opts) do
    GenServer.start(__MODULE__, {server, event_sink, opts})
  end

  def get_local_offer(conn), do: GenServer.call(conn, :get_local_offer, @call_timeout)

  def set_remote_answer(conn, sdp),
    do: GenServer.call(conn, {:set_remote_answer, sdp}, @call_timeout)

  def set_remote_offer(conn, sdp),
    do: GenServer.call(conn, {:set_remote_offer, sdp}, @call_timeout)

  def add_remote_candidate(conn, candidate),
    do: GenServer.call(conn, {:add_remote_candidate, candidate}, @call_timeout)

  def close(conn) do
    GenServer.call(conn, :close, @call_timeout)
  catch
    # already stopped (e.g. torn down after a setup failure) — close is idempotent
    :exit, _ -> :ok
  end

  # Sub-resources — handles are {conn_pid, kind, ref} tuples
  def create_player(conn, file_path, opts),
    do: GenServer.call(conn, {:create_player, file_path, opts}, @call_timeout)

  def player_cmd({conn, :player, ref}, cmd),
    do: GenServer.call(conn, {:player_cmd, cmd, ref}, @call_timeout)

  def create_recorder(conn, file_path, duration_ms, opts),
    do: GenServer.call(conn, {:create_recorder, file_path, duration_ms, opts}, @call_timeout)

  def recorder_cmd({conn, :recorder, ref}, cmd),
    do: GenServer.call(conn, {:recorder_cmd, cmd, ref}, @call_timeout)

  def create_echo(conn), do: GenServer.call(conn, :create_echo, @call_timeout)

  def stop_echo({conn, :echo, ref}), do: GenServer.call(conn, {:stop_echo, ref}, @call_timeout)

  # ── Initialisation ──────────────────────────────────────────────────────────

  @impl true
  def init({server, event_sink, opts}) do
    %{base_url: base_url, queue_id: queue_id} = Mendooze.rpc_info(server)
    sess_tag = "cx-#{:erlang.unique_integer([:positive, :monotonic])}"
    medias = medias_from_opts(opts)

    state = %{
      server: server,
      event_sink: event_sink,
      base_url: base_url,
      opts: opts,
      sess_tag: sess_tag,
      sess_id: nil,
      endpoint_id: nil,
      medias: medias,
      # per-media local data filled by offer/answer processing
      local_ports: %{},
      local_ip: nil,
      local_crypto: :none,
      local_ice: nil,
      # delegated SDP negotiation: the receive rtpMap we proposed and the
      # server-accepted set (pt => fmtp) returned by EndpointStartReceiving.
      # accepted[media] is nil for an older server (fallback to codec tables).
      proposed_recv: %{},
      accepted: %{},
      status: :init,
      # set once the server signals the first validated RTP packet
      # (EndpointConnectedEvent, type 7) so :ice_connected is emitted only once
      connected_notified: false,
      # sub-resources: ref => %{...}; tags "p-<n>"/"r-<n>" route server events
      res_seq: 0,
      players: %{},
      recorders: %{},
      echo: nil
    }

    with {:ok, sess_id} <-
           create(state, "MediaSessionCreate", [sess_tag, queue_id]),
         state = %{state | sess_id: sess_id},
         {:ok, endpoint_id} <-
           create(state, "EndpointCreate", [
             sess_id,
             sess_tag,
             :audio in medias,
             :video in medias,
             :text in medias
           ]) do
      :ok = Mendooze.register_conn(server, sess_tag, event_sink)

      Logger.info(
        module: __MODULE__,
        cnx_tag: state.sess_tag,
        message: "created MediaSession with media #{inspect(state.medias)}"
      )

      Logger.debug(
        module: __MODULE__,
        cnx_tag: state.sess_tag,
        message: "created Endpoint #{endpoint_id} for MediaSession"
      )

      {:ok, %{state | sess_id: sess_id, endpoint_id: endpoint_id}}
    else
      {:error, reason} ->
        # EndpointCreate may have failed with the session already created
        if state.sess_id, do: rpc(state, "MediaSessionDelete", [state.sess_id])
        {:stop, reason}
    end
  end

  defp medias_from_opts(opts) do
    Keyword.get(opts, :media, :audio_video) |> MediaServer.media_list()
  end

  # ── UAC flow: build the offer, then process the answer ─────────────────────

  @impl true
  def handle_call(:get_local_offer, _from, state) do
    with {:ok, state} <- setup_local_security(state),
         {:ok, state} <- start_receiving_all(state) do
      offer =
        Sdp.build(%{
          ip: state.local_ip,
          medias: Enum.map(state.medias, &offer_media_spec(state, &1))
        })

      Logger.debug(
        module: __MODULE__,
        cnx_tag: state.sess_tag,
        message: "local offer built:\n#{inspect(offer)}"
      )

      {:reply, {:ok, offer}, state}
    else
      {:error, reason} -> fail(state, reason)
    end
  end

  def handle_call({:set_remote_answer, sdp}, _from, state) do
    with {:ok, descs} <- Sdp.parse(sdp),
         {:ok, state} <- apply_remote_medias(state, descs) do
      # :ice_connected is no longer emitted here: it now reflects the real media
      # connectivity, surfaced when the server reports the first validated RTP
      # packet (EndpointConnectedEvent, type 7 → handle_server_event below).
      {:reply, :ok, %{state | status: :active}}
    else
      {:error, reason} -> fail(state, reason)
    end
  end

  # ── UAS flow: process the offer and build the answer ───────────────────────

  def handle_call({:set_remote_offer, sdp}, _from, state) do
    with {:ok, descs} <- Sdp.parse(sdp),
         # G9: keep every offered m= section; the ones we can answer with real
         # media are the supported RTP sections of a configured media type. The
         # rest (unknown type, non-RTP transport, disabled media) are echoed as
         # port-0 rejections so the answer keeps one m= per offer m= (RFC 3264).
         answerable = Enum.filter(descs, &answerable?(&1, state.medias)),
         :ok <- ensure_media_present(answerable),
         _ =
           Logger.info(
             module: __MODULE__,
             cnx_tag: state.sess_tag,
             message:
               "remote offer medias: #{inspect(Enum.map(descs, & &1.type))}, " <>
                 "allowed: #{inspect(state.medias)}, " <>
                 "answering: #{inspect(Enum.map(answerable, & &1.type))}"
           ),
         # open the receive plane only for what we actually answer
         state = %{state | medias: Enum.map(answerable, & &1.type)},
         {:ok, state} <- setup_local_security_for_offer(state, answerable),
         {:ok, state} <- start_receiving_all(state),
         {:ok, state, negotiated} <- apply_remote_medias_negotiated(state, answerable) do
      answer =
        Sdp.build(%{
          ip: state.local_ip,
          # D7: a=ice-lite is advertised in answers only (Elixip behaves
          # gateway-like there); emitted only for WebRTC (DTLS) answers.
          ice_lite: match?({:dtls, _, _}, state.local_crypto),
          # every offered section, in order: a real answer for the negotiated
          # ones, a port-0 rejection for the rest.
          medias: Enum.map(descs, &answer_or_reject(state, negotiated, &1))
        })

      # :ice_connected deferred to the first validated RTP packet (type 7);
      # see the set_remote_answer path and handle_server_event below.
      {:reply, {:ok, answer}, %{state | status: :active}}
    else
      {:error, reason} -> fail(state, reason)
    end
  end

  def handle_call({:add_remote_candidate, candidate}, _from, state) do
    # media selection is not carried by the candidate line: apply to audio
    case rpc(state, "EndpointAddICECandidate", [
           state.sess_id,
           state.endpoint_id,
           @media_int.audio,
           candidate
         ]) do
      {:ok, _} -> {:reply, :ok, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:close, _from, state) do
    state = teardown(state)
    {:stop, :normal, :ok, state}
  end

  # ── Player (server doc §6.3) ────────────────────────────────────────────────

  def handle_call({:create_player, file_path, opts}, _from, state) do
    tag = "p-#{state.res_seq}"
    state = %{state | res_seq: state.res_seq + 1}

    with {:ok, player_id} <- create(state, "PlayerCreate", [state.sess_id, tag]),
         :ok <- cleanup_on_error(state, player_id, attach_player_all(state, player_id)),
         {:ok, _} <-
           cleanup_on_error(
             state,
             player_id,
             rpc(state, "PlayerOpen", [state.sess_id, player_id, file_path])
           ),
         :ok <- maybe_seek(state, player_id, Keyword.get(opts, :start_time)) do
      ref = make_ref()

      players =
        Map.put(state.players, ref, %{player_id: player_id, tag: tag, file: file_path, opts: opts})

      Logger.info(
        module: __MODULE__,
        cnx_tag: state.sess_tag,
        message: "created Player for file #{file_path}"
      )

      {:reply, {:ok, {self(), :player, ref}}, %{state | players: players}}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:player_cmd, cmd, ref}, _from, state) do
    case Map.get(state.players, ref) do
      nil ->
        {:reply, {:error, :no_such_player}, state}

      player ->
        do_player_cmd(cmd, ref, player, state)
    end
  end

  # ── Recorder (server doc §6.4) ──────────────────────────────────────────────

  def handle_call({:create_recorder, file_path, duration_ms, opts}, _from, state) do
    warn_unsupported_recorder_opts(opts, state)
    tag = "r-#{state.res_seq}"
    state = %{state | res_seq: state.res_seq + 1}

    with {:ok, recorder_id} <- create(state, "RecorderCreate", [state.sess_id, tag]),
         :ok <- attach_recorder_all(state, recorder_id) do
      ref = make_ref()

      recorders =
        Map.put(state.recorders, ref, %{
          recorder_id: recorder_id,
          tag: tag,
          file: file_path,
          duration_ms: duration_ms,
          opts: opts,
          stopping: false
        })

      {:reply, {:ok, {self(), :recorder, ref}}, %{state | recorders: recorders}}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:recorder_cmd, cmd, ref}, _from, state) do
    case Map.get(state.recorders, ref) do
      nil ->
        {:reply, {:error, :no_such_recorder}, state}

      recorder ->
        do_recorder_cmd(cmd, ref, recorder, state)
    end
  end

  # ── Echo (server doc §4.16: the endpoint is attached to itself) ────────────

  def handle_call(:create_echo, _from, %{echo: nil} = state) do
    case attach_endpoint_to_itself(state) do
      :ok ->
        ref = make_ref()
        send(state.event_sink, {:ms_event, {self(), :echo, ref}, :echo_started})
        {:reply, {:ok, {self(), :echo, ref}}, %{state | echo: ref}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:create_echo, _from, state),
    do: {:reply, {:error, :echo_already_started}, state}

  def handle_call({:stop_echo, ref}, _from, %{echo: ref} = state) do
    detach_all(state)
    {:reply, :ok, %{state | echo: nil}}
  end

  def handle_call({:stop_echo, _ref}, _from, state),
    do: {:reply, {:error, :no_such_echo}, state}

  # ── Server events routed by MediaServer.Mendooze ────────────────────────────

  @impl true
  def handle_info({:mendooze_event, event}, state) do
    handle_server_event(event, state)
  end

  defp handle_server_event({:endpoint_disconnected, _tag, _ep, media}, state) do
    Logger.warning(module: __MODULE__, session: state.sess_tag, message: "timeout on #{media}")
    send(state.event_sink, {:ms_event, self(), :media_timeout})
    {:noreply, state}
  end

  # First validated RTP/SRTP packet received for this connection (server
  # EndpointConnectedEvent, type 7). A decrypted SRTP packet means ICE + DTLS
  # completed (WebRTC case); a plain RTP packet is simply the first media packet
  # (non-WebRTC). The server fires it per media and re-arms it on each
  # StartReceiving, so surface a single connection-level :ice_connected.
  defp handle_server_event(
         {:endpoint_connected, _tag, _ep, _media},
         %{connected_notified: true} = state
       ) do
    {:noreply, state}
  end

  defp handle_server_event({:endpoint_connected, _tag, _ep, media}, state) do
    Logger.info(
      module: __MODULE__,
      session: state.sess_tag,
      message: "media connected on #{media}"
    )

    send(state.event_sink, {:ms_event, self(), :ice_connected})
    {:noreply, %{state | connected_notified: true, status: :active}}
  end

  defp handle_server_event({:external_fir, _tag, _ep, media}, state) do
    # remote peer asked for a full intra frame: forward the update request
    rpc(state, "EndpointRequestUpdate", [state.sess_id, state.endpoint_id, @media_int[media]])
    {:noreply, state}
  end

  defp handle_server_event({:player_started, _tag, player_tag}, state) do
    with_player(state, player_tag, fn ref, _player ->
      send(state.event_sink, {:ms_event, {self(), :player, ref}, :player_started})
      {:noreply, state}
    end)
  end

  defp handle_server_event({:player_end_of_file, _tag, player_tag}, state) do
    with_player(state, player_tag, fn ref, player ->
      if Keyword.get(player.opts, :loop, false) do
        # loop: rewind and replay without surfacing the end of file
        rpc(state, "PlayerSeek", [state.sess_id, player.player_id, 0])
        rpc(state, "PlayerPlay", [state.sess_id, player.player_id])
        {:noreply, state}
      else
        send(state.event_sink, {:ms_event, {self(), :player, ref}, :player_ended})
        {:noreply, state}
      end
    end)
  end

  defp handle_server_event({:recorder_started, _tag, recorder_tag}, state) do
    with_recorder(state, recorder_tag, fn ref, _recorder ->
      send(state.event_sink, {:ms_event, {self(), :recorder, ref}, :recorder_started})
      {:noreply, state}
    end)
  end

  defp handle_server_event({:recorder_stopped, _tag, recorder_tag, reason}, state) do
    with_recorder(state, recorder_tag, fn ref, recorder ->
      send(state.event_sink, {:ms_event, {self(), :recorder, ref}, {:recorder_stopped, reason}})

      # a stop requested by stop_recorder/1 completes here
      state =
        if recorder.stopping,
          do: %{state | recorders: Map.delete(state.recorders, ref)},
          else: state

      {:noreply, state}
    end)
  end

  defp handle_server_event(event, state) do
    Logger.debug("Mendooze.Conn #{state.sess_tag}: unhandled event #{inspect(event)}")
    {:noreply, state}
  end

  defp with_player(state, tag, fun) do
    case Enum.find(state.players, fn {_ref, p} -> p.tag == tag end) do
      {ref, player} ->
        fun.(ref, player)

      nil ->
        Logger.debug("Mendooze.Conn #{state.sess_tag}: event for unknown player #{tag}")
        {:noreply, state}
    end
  end

  defp with_recorder(state, tag, fun) do
    case Enum.find(state.recorders, fn {_ref, r} -> r.tag == tag end) do
      {ref, recorder} ->
        fun.(ref, recorder)

      nil ->
        Logger.debug("Mendooze.Conn #{state.sess_tag}: event for unknown recorder #{tag}")
        {:noreply, state}
    end
  end

  @impl true
  def terminate(reason, state) do
    if reason != :normal and state.status != :closed do
      # crash path — still try to free the server-side resources
      teardown(state)
    end

    :ok
  end

  # ── Local side: security and receiving ──────────────────────────────────────

  # UAC: local security material derives from conn_opts only.
  defp setup_local_security(state) do
    if webrtc?(state) do
      setup_dtls_ice(state)
    else
      {:ok, state}
    end
  end

  # UAS: follow the offer — DTLS when the offer is DTLS (and we allow it).
  defp setup_local_security_for_offer(state, descs) do
    offer_dtls? = Enum.any?(descs, &match?({:dtls, _, _, _}, &1.crypto))

    cond do
      offer_dtls? and webrtc_allowed?(state) -> setup_dtls_ice(state)
      offer_dtls? -> {:error, :webrtc_not_supported}
      true -> {:ok, state}
    end
  end

  defp setup_dtls_ice(state) do
    with {:ok, [fingerprint | _]} <-
           rpc(state, "EndpointGetLocalCryptoDTLSFingerprint", ["sha-256"]),
         ice = %{ufrag: random_token(8), pwd: random_token(24)},
         :ok <- set_local_stun_all(state, ice) do
      {:ok, %{state | local_crypto: {:dtls, "sha-256", fingerprint}, local_ice: ice}}
    end
  end

  defp set_local_stun_all(state, ice) do
    Enum.reduce_while(state.medias, :ok, fn media, :ok ->
      case rpc(state, "EndpointSetLocalSTUNCredentials", [
             state.sess_id,
             state.endpoint_id,
             @media_int[media],
             ice.ufrag,
             ice.pwd
           ]) do
        {:ok, _} -> {:cont, :ok}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp start_receiving_all(state) do
    Enum.reduce_while(state.medias, {:ok, state}, fn media, {:ok, st} ->
      rtp_map = Sdp.local_rtp_map(media, codecs(st, media), dtmf?(st, media))

      with {:ok, [port | rest]} <-
             rpc(st, "EndpointStartReceiving", [
               st.sess_id,
               st.endpoint_id,
               @media_int[media],
               rtp_map
             ]),
           {:ok, [candidate | _]} <-
             rpc(st, "GetMediaCandidates", [
               st.sess_id,
               st.endpoint_id,
               @proto_rtp,
               @media_int[media]
             ]),
           {:ok, ip, _cport} <- Sdp.parse_media_candidate(candidate) do
        # returnVal[1] (when present) is the fmtp-per-payload-type struct the
        # server accepted; nil on an older server → codec-table fallback.
        accepted = Sdp.accepted_pts(rtp_map, List.first(rest))

        {:cont,
         {:ok,
          %{
            st
            | local_ports: Map.put(st.local_ports, media, port),
              local_ip: ip,
              proposed_recv: Map.put(st.proposed_recv, media, rtp_map),
              accepted: Map.put(st.accepted, media, accepted)
          }}}
      else
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  # ── Remote side: security, sending, watchdog ───────────────────────────────

  defp apply_remote_medias(state, descs) do
    descs = Enum.filter(descs, &answerable?(&1, state.medias))

    with :ok <- ensure_media_present(descs),
         {:ok, state, negotiated} <- apply_remote_medias_negotiated(state, descs),
         :ok <- ensure_negotiated(negotiated) do
      {:ok, state}
    end
  end

  # Applies §9 steps for each remote media and returns the negotiation results
  # (%{media => %{codecs:, dtmf:, rtp_map:, send_map:, ...}}) for answer
  # building. A media with no common codec is skipped (G9: it becomes a port-0
  # rejection), not a call failure; RPC errors still abort the whole offer.
  defp apply_remote_medias_negotiated(state, descs) do
    Enum.reduce_while(descs, {:ok, state, %{}}, fn desc, {:ok, st, acc} ->
      case apply_remote_media(st, desc) do
        {:ok, st, negotiated} -> {:cont, {:ok, st, Map.put(acc, desc.type, negotiated)}}
        {:skip, st} -> {:cont, {:ok, st, acc}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp apply_remote_media(state, desc) do
    m = @media_int[desc.type]

    case Sdp.negotiate(desc, codecs(state, desc.type), dtmf?(state, desc.type)) do
      {:error, :no_common_codec} ->
        {:skip, state}

      {:ok, negotiated} ->
        # never send a codec the server just filtered on receive (no-op when
        # the server did not delegate, i.e. accepted[media] is nil)
        send_map =
          Sdp.restrict_send_map(
            negotiated.rtp_map,
            Map.get(state.proposed_recv, desc.type, %{}),
            Map.get(state.accepted, desc.type)
          )

        with :ok <- set_rtp_properties(state, m, desc),
             :ok <- set_remote_crypto(state, m, desc),
             {:ok, _} <-
               rpc(state, "EndpointStartSending", [
                 state.sess_id,
                 state.endpoint_id,
                 m,
                 desc.ip,
                 desc.port,
                 send_map
               ]),
             # the watchdog is armed last, once the answer has been processed
             {:ok, _} <-
               rpc(state, "EndpointStartRTPTimeout", [
                 state.sess_id,
                 state.endpoint_id,
                 m,
                 rtp_timeout_ms()
               ]) do
          {:ok, state, Map.put(negotiated, :send_map, send_map)}
        end
    end
  end

  # rtcp-mux (mirrored from the peer) and, on AVPF media, the RTCP-feedback hints
  # useNACK/tmmbr (G6) are merged into a single EndpointSetRTPProperties call.
  # The "secure" hint is intentionally omitted: it is a no-op once DTLS/SDES
  # crypto is configured (server audit, webrtc_sdp_design.md Q2).
  defp set_rtp_properties(state, m, desc) do
    props =
      %{}
      |> maybe_put(Map.get(desc, :rtcp_mux, false), "rtcp-mux", "1")
      |> maybe_put(avpf?(desc), "useNACK", "1")
      |> maybe_put(avpf?(desc), "tmmbr", "1")

    if props == %{} do
      :ok
    else
      case rpc(state, "EndpointSetRTPProperties", [state.sess_id, state.endpoint_id, m, props]) do
        {:ok, _} -> :ok
        {:error, _} = err -> err
      end
    end
  end

  defp avpf?(%{protocol: protocol}) when is_binary(protocol), do: String.ends_with?(protocol, "F")
  defp avpf?(_), do: false

  defp maybe_put(map, true, key, value), do: Map.put(map, key, value)
  defp maybe_put(map, false, _key, _value), do: map

  defp set_remote_crypto(state, m, desc) do
    crypto_calls =
      case desc.crypto do
        {:dtls, setup, hash, fingerprint} ->
          [{"EndpointSetRemoteCryptoDTLS", [to_string(setup), hash, fingerprint]}]

        {:sdes, suite, key} ->
          [{"EndpointSetRemoteCryptoSDES", [suite, key]}]

        :none ->
          []
      end

    ice_calls =
      case desc.ice do
        %{ufrag: ufrag, pwd: pwd} -> [{"EndpointSetRemoteSTUNCredentials", [ufrag, pwd]}]
        nil -> []
      end

    Enum.reduce_while(crypto_calls ++ ice_calls, :ok, fn {method, args}, :ok ->
      case rpc(state, method, [state.sess_id, state.endpoint_id, m | args]) do
        {:ok, _} -> {:cont, :ok}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  # ── SDP spec builders ───────────────────────────────────────────────────────

  defp offer_media_spec(state, media) do
    base =
      %{
        type: media,
        port: Map.fetch!(state.local_ports, media),
        bandwidth: bandwidth_kbps(state, media),
        direction: :sendrecv,
        crypto: local_crypto_spec(state, :actpass),
        ice: state.local_ice,
        rtcp_mux: false
      }
      |> add_offer_webrtc(state, media)

    case Map.get(state.accepted, media) do
      nil ->
        # legacy: the client-side codec tables synthesize the codec section
        Map.merge(base, %{codecs: codecs(state, media), dtmf: dtmf?(state, media)})

      accepted ->
        # delegated: build the codec section from the server-accepted set,
        # using our payload-type numbering (this is an offer)
        Map.merge(base, server_driven_offer(state, media, accepted))
    end
  end

  # WebRTC answer transport plane (§2.4). Mirror the offer's mid (G7), emit host
  # candidates on the receive port (component-2 iff the offer had no rtcp-mux),
  # and advertise rtcp-fb per video PT when the offer is AVPF. Session-level
  # a=ice-lite is added in set_remote_offer (D7 — answers only).
  defp add_answer_webrtc(base, state, desc) do
    if match?({:dtls, _, _}, state.local_crypto) do
      Map.merge(base, %{
        mid: desc.mid,
        candidates:
          Sdp.host_candidates(
            state.local_ip,
            Map.fetch!(state.local_ports, desc.type),
            desc.rtcp_mux
          ),
        rtcp_fb: desc.type == :video and String.ends_with?(desc.protocol, "F")
      })
    else
      base
    end
  end

  # WebRTC offer transport plane (§2.4). rtcp-mux is always offered (G5), mid is
  # our media name (mirrored back by the peer), candidates are host-only with the
  # receive port (D6), and rtcp-fb is advertised per video PT. No a=ice-lite in
  # offers (D7): we emulate a browser-shaped offer.
  defp add_offer_webrtc(base, state, media) do
    if webrtc?(state) do
      Map.merge(base, %{
        rtcp_mux: true,
        mid: to_string(media),
        candidates:
          Sdp.host_candidates(state.local_ip, Map.fetch!(state.local_ports, media), true),
        rtcp_fb: media == :video
      })
    else
      base
    end
  end

  # G9: one answer m= per offered m=. A negotiated section gets a full answer
  # spec; anything else (unsupported, media-type not configured, or no common
  # codec — hence absent from `negotiated`) is declined with a port-0 rejection
  # echoing the offered transport and format list verbatim (RFC 3264 §6).
  defp answer_or_reject(state, negotiated, desc) do
    if answerable?(desc, state.medias) and Map.has_key?(negotiated, desc.type) do
      answer_media_spec(state, negotiated, desc)
    else
      reject_media_spec(desc)
    end
  end

  defp reject_media_spec(desc) do
    %{type: desc.type, protocol: desc.protocol, reject_fmt: desc.raw_fmt}
  end

  defp answer_media_spec(state, negotiated, desc) do
    neg = Map.fetch!(negotiated, desc.type)

    base =
      %{
        type: desc.type,
        port: Map.fetch!(state.local_ports, desc.type),
        bandwidth: Sdp.negotiate_bandwidth(desc.bandwidth, bandwidth_kbps(state, desc.type)),
        direction: Sdp.reverse_direction(desc.direction),
        # G3: mendooze answers DTLS as server (setup:passive) — the safe role a
        # browser/gateway expects from the answerer. Ignored for non-DTLS crypto.
        crypto: local_crypto_spec(state, :passive),
        ice: state.local_ice,
        rtcp_mux: desc.rtcp_mux,
        # mirror the transport of the offer
        protocol: desc.protocol
      }
      |> add_answer_webrtc(state, desc)

    case Map.get(state.accepted, desc.type) do
      nil ->
        # legacy: client-side codec tables (our payload-type numbering)
        Map.merge(base, %{codecs: neg.codecs, dtmf: neg.dtmf})

      accepted ->
        # delegated: build from the server-accepted set, honoring the
        # offerer's payload-type numbering (RFC 3264)
        Map.merge(base, server_driven_answer(desc.type, neg, accepted, state.proposed_recv))
    end
  end

  # ── Delegated codec section (server-driven build path) ──────────────────────

  # Offer: our payload-type numbering. Order the m= fmt list by our proposal
  # preference (the server fmtp struct is unordered — plan §9 Q).
  defp server_driven_offer(state, media, accepted) do
    ordered = Enum.filter(proposed_pts(state, media), &Map.has_key?(accepted, &1))

    rtpmaps =
      Enum.flat_map(ordered, fn pt_str ->
        pt = String.to_integer(pt_str)
        rtpmap_entry(pt, Sdp.pt_rtpmap(media, pt))
      end)

    %{rtpmaps: rtpmaps, fmtp: Map.take(accepted, ordered)}
  end

  # Answer: the offerer's payload-type numbering. `neg.send_map` is the send
  # rtpMap already restricted to the codecs the server accepted on receive
  # (offerer pt => codec code), so it is exactly the accepted-and-common set.
  defp server_driven_answer(media, neg, accepted, proposed_recv) do
    # server fmtp is keyed by our receive pt; bridge to the codec code so it
    # can be re-attached to the offerer's pt numbering
    code_fmtp =
      Map.new(accepted, fn {our_pt, fmtp} ->
        {Map.get(Map.get(proposed_recv, media, %{}), our_pt), fmtp}
      end)

    ordered = Enum.sort_by(neg.send_map, fn {pt, _code} -> String.to_integer(pt) end)

    # G10: the telephone-event PT keeps its offered clock. Use the restricted
    # send map (never a codec the server filtered on receive).
    rtpmaps = Sdp.answer_rtpmaps(media, %{rtp_map: neg.send_map, dtmf_clock: neg.dtmf_clock})

    fmtp =
      for {pt_str, code} <- ordered,
          params = Map.get(code_fmtp, code),
          params not in [nil, ""],
          into: %{},
          do: {pt_str, params}

    %{rtpmaps: rtpmaps, fmtp: fmtp}
  end

  defp rtpmap_entry(_pt, :unknown), do: []

  defp rtpmap_entry(pt, {encoding, clock, channels}),
    do: [%{pt: pt, encoding: encoding, clock: clock, channels: channels}]

  # Payload types we proposed on receive for this media, in our preference
  # order (codec-config order, telephone-event last).
  defp proposed_pts(state, media) do
    codec_pts =
      Enum.flat_map(codecs(state, media), fn name ->
        Map.keys(Sdp.local_rtp_map(media, [name]))
      end)

    if dtmf?(state, media) and media == :audio do
      codec_pts ++ Map.keys(Sdp.local_rtp_map(:audio, [], true))
    else
      codec_pts
    end
  end

  defp local_crypto_spec(state, setup) do
    case state.local_crypto do
      {:dtls, hash, fingerprint} -> {:dtls, setup, hash, fingerprint}
      :none -> :none
    end
  end

  # ── Player / recorder / echo helpers ────────────────────────────────────────

  # :start / :pause rely on server events (PlayerStartedEvent) — no synthesis.
  defp do_player_cmd(:start, _ref, player, state) do
    case rpc(state, "PlayerPlay", [state.sess_id, player.player_id]) do
      {:ok, _} -> {:reply, :ok, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  defp do_player_cmd(:pause, _ref, player, state) do
    # PlayerStop pauses; the file position is kept until PlayerPlay/PlayerSeek
    case rpc(state, "PlayerStop", [state.sess_id, player.player_id]) do
      {:ok, _} -> {:reply, :ok, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  defp do_player_cmd(:stop, ref, player, state) do
    rpc(state, "PlayerStop", [state.sess_id, player.player_id])
    detach_all(state)
    rpc(state, "PlayerClose", [state.sess_id, player.player_id])
    rpc(state, "PlayerDelete", [state.sess_id, player.player_id])
    {:reply, :ok, %{state | players: Map.delete(state.players, ref)}}
  end

  defp do_recorder_cmd(:start, _ref, recorder, state) do
    # maxDuration is enforced server-side (RecorderStoppedEvent reason=1).
    # waitVideo (server default 1) and echoVideo (server default 0) are the
    # optional 5th/6th RecorderRecord parameters (server doc §6.4).
    wait_video = if Keyword.get(recorder.opts, :wait_video, true), do: 1, else: 0
    echo_video = if Keyword.get(recorder.opts, :echo, false), do: 1, else: 0

    case rpc(state, "RecorderRecord", [
           state.sess_id,
           recorder.recorder_id,
           recorder.file,
           recorder.duration_ms,
           wait_video,
           echo_video
         ]) do
      {:ok, _} -> {:reply, :ok, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  defp do_recorder_cmd(:stop, ref, recorder, state) do
    rpc(state, "RecorderStop", [state.sess_id, recorder.recorder_id])

    Enum.each(state.medias, fn media ->
      rpc(state, "RecorderDettach", [state.sess_id, recorder.recorder_id, @media_int[media]])
    end)

    rpc(state, "RecorderDelete", [state.sess_id, recorder.recorder_id])

    # keep the entry until the server RecorderStoppedEvent(reason=0) is
    # routed to the event sink, then drop it (see handle_server_event)
    recorders = Map.put(state.recorders, ref, %{recorder | stopping: true})
    {:reply, :ok, %{state | recorders: recorders}}
  end

  defp attach_player_all(state, player_id) do
    each_media_rpc(state, fn m ->
      {"EndpointAttachToPlayer", [state.sess_id, state.endpoint_id, player_id, m]}
    end)
  end

  defp attach_recorder_all(state, recorder_id) do
    each_media_rpc(state, fn m ->
      {"RecorderAttachToEndpoint", [state.sess_id, recorder_id, state.endpoint_id, m]}
    end)
  end

  defp attach_endpoint_to_itself(state) do
    each_media_rpc(state, fn m ->
      {"EndpointAttachToEndpoint", [state.sess_id, state.endpoint_id, state.endpoint_id, m]}
    end)
  end

  defp detach_all(state) do
    Enum.each(state.medias, fn media ->
      rpc(state, "EndpointDettach", [state.sess_id, state.endpoint_id, @media_int[media]])
    end)
  end

  defp each_media_rpc(state, call_fun) do
    Enum.reduce_while(state.medias, :ok, fn media, :ok ->
      {method, params} = call_fun.(@media_int[media])

      case rpc(state, method, params) do
        {:ok, _} -> {:cont, :ok}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp maybe_seek(_state, _player_id, nil), do: :ok

  defp maybe_seek(state, player_id, start_time_ms) do
    case rpc(state, "PlayerSeek", [state.sess_id, player_id, start_time_ms]) do
      {:ok, _} -> :ok
      {:error, _} = err -> err
    end
  end

  # Free a half-created player when a later setup step fails.
  defp cleanup_on_error(_state, _player_id, {:ok, _} = ok), do: ok
  defp cleanup_on_error(_state, _player_id, :ok), do: :ok

  defp cleanup_on_error(state, player_id, {:error, _} = err) do
    rpc(state, "PlayerDelete", [state.sess_id, player_id])
    err
  end

  defp warn_unsupported_recorder_opts(opts, state) do
    for opt <- [:stop_on_silence, :stop_on_dtmf], Keyword.get(opts, opt, false) do
      Logger.warning(
        "Mendooze.Conn #{state.sess_tag}: recorder option #{opt} is not implemented " <>
          "by the media server yet and will be ignored"
      )
    end
  end

  # ── Teardown (server doc §9.5) ──────────────────────────────────────────────

  defp teardown(%{status: :closed} = state), do: state

  defp teardown(state) do
    Enum.each(state.medias, fn media ->
      m = @media_int[media]
      rpc(state, "EndpointStopSending", [state.sess_id, state.endpoint_id, m])
      rpc(state, "EndpointStopReceiving", [state.sess_id, state.endpoint_id, m])
    end)

    if state.endpoint_id, do: rpc(state, "EndpointDelete", [state.sess_id, state.endpoint_id])
    if state.sess_id, do: rpc(state, "MediaSessionDelete", [state.sess_id])

    Mendooze.unregister_conn(state.server, state.sess_tag)
    send(state.event_sink, {:ms_event, self(), :closed})
    %{state | status: :closed}
  end

  # On a setup failure: free the server-side resources, reply with the error
  # and stop — a later close_peer_connection on this pid is a no-op.
  defp fail(state, reason) do
    Logger.error("Mendooze.Conn #{state.sess_tag}: setup failed: #{inspect(reason)}")
    # Async, scenario-capturable signal of the setup/negotiation failure (the
    # failing call also returns {:error, reason} synchronously). Sent before
    # teardown so the pid in the event is still the one the app knows.
    send(state.event_sink, {:ms_event, self(), {:media_error, reason}})
    state = teardown(state)
    {:stop, :normal, {:error, reason}, state}
  end

  # ── Helpers ─────────────────────────────────────────────────────────────────

  defp rpc(state, method, params), do: XmlRpc.call(state.base_url, method, params)

  defp create(state, method, params), do: XmlRpc.created_id(rpc(state, method, params))

  defp codecs(state, :audio),
    do: List.wrap(Keyword.get(state.opts, :audio_codec, @default_audio_codecs))

  defp codecs(state, :video),
    do: List.wrap(Keyword.get(state.opts, :video_codec, @default_video_codecs))

  defp codecs(state, :text),
    do: List.wrap(Keyword.get(state.opts, :text_codec, @default_text_codecs))

  defp dtmf?(state, :audio), do: Keyword.get(state.opts, :dtmf, true)
  defp dtmf?(_state, _media), do: false

  # Receive bandwidth (b=AS, kb/s) per media; 0 = no b= line. Overridable per
  # connection (:video_bandwidth opt) and globally (:video_bandwidth_kbps in
  # the MediaServer.Mendooze config block).
  defp bandwidth_kbps(state, :video) do
    Keyword.get_lazy(state.opts, :video_bandwidth, fn ->
      Application.get_env(:elixip2, MediaServer.Mendooze, [])
      |> Keyword.get(:video_bandwidth_kbps, @default_video_bandwidth_kbps)
    end)
  end

  defp bandwidth_kbps(_state, _media), do: 0

  defp webrtc?(state), do: Keyword.get(state.opts, :webrtc_support, :no) == :yes

  defp webrtc_allowed?(state),
    do: Keyword.get(state.opts, :webrtc_support, :no) in [:yes, :if_offered]

  defp ensure_media_present([]), do: {:error, :no_common_media}
  defp ensure_media_present(_descs), do: :ok

  # A section we can answer with real media (G9): a supported RTP media_desc
  # whose type is one we are configured to handle. Stubs (supported?: false) and
  # media types we don't carry are declined with a port-0 rejection instead.
  defp answerable?(desc, medias),
    do: Map.get(desc, :supported?, false) and desc.type in medias

  # After negotiation, at least one media must have produced a real answer
  # (G9: skipped :no_common_codec sections do not count).
  defp ensure_negotiated(negotiated) when map_size(negotiated) == 0,
    do: {:error, :no_common_codec}

  defp ensure_negotiated(_negotiated), do: :ok

  defp rtp_timeout_ms() do
    Application.get_env(:elixip2, MediaServer.Mendooze, [])
    |> Keyword.get(:rtp_timeout_ms, @default_rtp_timeout_ms)
  end

  defp random_token(len) do
    :crypto.strong_rand_bytes(len)
    |> Base.url_encode64(padding: false)
    |> binary_part(0, len)
  end
end
