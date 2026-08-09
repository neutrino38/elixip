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
  # MediaFrame::MediaProtocol WS — the transport of a text-over-WebSocket media
  @proto_ws 2
  # MediaRole::VIDEO_MAIN. For a text media this is not a mistake: it is the
  # "main" port of any media, whatever its type (Endpoint::GetPort).
  @role_main 0

  @default_audio_codecs ["OPUS", "PCMU", "PCMA"]
  @default_video_codecs ["H264", "VP8"]
  @default_text_codecs ["T140", "T140RED"]

  # Receive bandwidth advertised as b=AS: on the video media (kb/s)
  @default_video_bandwidth_kbps 800

  # telephone-event's Medooze codec constant: a payload type never selected as a
  # primary codec (see primary_entry/1).
  @dtmf_code 100

  # SDES suites this adapter implements, in our preference order. RFC 4568 §6.2:
  # the answerer picks ONE offered `a=crypto` line — one whose suite it actually
  # supports — echoes that line's tag, and keys its own direction with the same
  # suite. An offer whose every line names something else is refused
  # (`:no_common_sdes_suite`): the alternative is a call that decrypts nothing.
  @sdes_suites ["AES_CM_128_HMAC_SHA1_80", "AES_CM_128_HMAC_SHA1_32"]

  # The feedback types this adapter can honour, each with the server-side switch
  # that implements it. `nack pli` shares the FIR switch: the server treats an
  # incoming PLI exactly like a FIR (both land in onFPURequested,
  # rtpsession.cpp) so there is nothing more to enable — but a peer that
  # negotiated `nack pli` may send PLI *instead of* FIR (Linphone does), so it
  # must be confirmed in the answer, not dropped. NOT `useNACK`: PLI is a
  # keyframe request, not a retransmission request, and switching the NACK/rtx
  # machinery on for it would enable feedback the peer never asked for.
  # `goog-remb` stays absent (announcing congestion feedback the server never
  # sends invites the peer to wait for it).
  @supported_rtcp_fb %{
    "nack" => "useNACK",
    "nack pli" => "useRtcpFIR",
    "ccm fir" => "useRtcpFIR",
    "ccm tmmbr" => "tmmbr"
  }

  # Text-over-WebSocket codecs proposed to the media server: T.140 and its RFC
  # 4103 redundancy. The rtpMap is what switches redundancy on server-side
  # (`Endpoint::StartReceiving` case WS), and it is on the RTP leg facing us that
  # redundancy earns its keep — the WebSocket itself only ever carries plain
  # de-redundified text.
  @ws_text_codecs ["T140", "T140RED"]

  # ── API (called through the MediaServer.Mendooze facade) ───────────────────

  def start(server, event_sink, opts) do
    GenServer.start(__MODULE__, {server, event_sink, opts})
  end

  # Every entry point takes a `MediaServer.conn_ref/0`: a bare pid names the
  # inbound (or only) leg, `{pid, name}` names another endpoint of the same
  # session. Splitting it here means the handlers below never see the two forms.
  defp ref(conn) when is_pid(conn), do: {conn, :inbound}
  defp ref({conn, name}) when is_pid(conn) and is_atom(name), do: {conn, name}

  def get_local_offer(conn) do
    {pid, name} = ref(conn)
    GenServer.call(pid, {:get_local_offer, name}, @call_timeout)
  end

  def set_remote_answer(conn, sdp) do
    {pid, name} = ref(conn)
    GenServer.call(pid, {:set_remote_answer, name, sdp}, @call_timeout)
  end

  def set_remote_offer(conn, sdp) do
    {pid, name} = ref(conn)
    GenServer.call(pid, {:set_remote_offer, name, sdp}, @call_timeout)
  end

  def add_remote_candidate(conn, candidate) do
    {pid, name} = ref(conn)
    GenServer.call(pid, {:add_remote_candidate, name, candidate}, @call_timeout)
  end

  def close(conn) do
    {pid, name} = ref(conn)
    GenServer.call(pid, {:close, name}, @call_timeout)
  catch
    # already stopped (e.g. torn down after a setup failure) — close is idempotent
    :exit, _ -> :ok
  end

  # Sub-resources — handles are {conn_pid, kind, ref} tuples
  def create_player(conn, file_path, opts) do
    {pid, name} = ref(conn)
    GenServer.call(pid, {:create_player, name, file_path, opts}, @call_timeout)
  end

  def player_cmd({conn, :player, ref}, cmd),
    do: GenServer.call(conn, {:player_cmd, cmd, ref}, @call_timeout)

  def create_recorder(conn, file_path, duration_ms, opts) do
    {pid, name} = ref(conn)
    GenServer.call(pid, {:create_recorder, name, file_path, duration_ms, opts}, @call_timeout)
  end

  def recorder_cmd({conn, :recorder, ref}, cmd),
    do: GenServer.call(conn, {:recorder_cmd, cmd, ref}, @call_timeout)

  def create_echo(conn) do
    {pid, name} = ref(conn)
    GenServer.call(pid, {:create_echo, name}, @call_timeout)
  end

  def stop_echo({conn, :echo, ref}), do: GenServer.call(conn, {:stop_echo, ref}, @call_timeout)

  # ── Initialisation ──────────────────────────────────────────────────────────

  # ── Legs ────────────────────────────────────────────────────────────────────
  #
  # A B2BUA call is ONE MediaSession holding TWO Endpoints, because
  # `EndpointAttachToEndpoint` takes a single session id and two endpoints are
  # connectable only inside one session (docs/design/mediagw_b2bua_jsr309.md §2).
  # So this process owns the session and one *leg* per SIP leg.
  #
  # A leg is a plain map carrying its own endpoint state AND a copy of the
  # connection's immutable fields (`sess_id`, `base_url`, `sess_tag`,
  # `event_sink`, `server`, `opts`). That denormalisation is deliberate: it makes
  # a leg look exactly like the flat state every per-endpoint function in this
  # module already takes, so those functions — SDP building, security, the
  # receive and send planes, the watchdog — did not change at all. The fields it
  # duplicates are set once in `init/1` and never written again.
  defp new_leg(state, name, endpoint_id, medias) do
    %{
      # connection-level, immutable
      server: state.server,
      base_url: state.base_url,
      sess_id: state.sess_id,
      sess_tag: state.sess_tag,
      event_sink: state.event_sink,
      opts: state.opts,
      # this leg
      leg: name,
      endpoint_id: endpoint_id,
      medias: medias,
      local_ports: %{},
      local_ip: nil,
      local_crypto: :none,
      local_ice: nil,
      local_sdes: %{},
      ws_urls: %{},
      proposed_recv: %{},
      accepted: %{},
      status: :init,
      connected: MapSet.new(),
      recv_medias: nil,
      ice_notified: false,
      timed_out: MapSet.new(),
      lost_notified: false
    }
  end

  defp leg(state, name), do: Map.get(state.legs, name)

  defp put_leg(state, name, leg), do: %{state | legs: Map.put(state.legs, name, leg)}

  defp drop_leg(state, name), do: %{state | legs: Map.delete(state.legs, name)}

  # Run a per-leg handler and fold its result back into the connection. The
  # handlers speak in leg views and say `{:fail, reason}` rather than tearing the
  # connection down themselves — ending the session is a connection-level
  # decision, and with two legs it is no longer the same thing as one leg
  # failing.
  defp on_leg(state, name, fun) do
    case leg(state, name) do
      nil ->
        {:reply, {:error, {:no_such_leg, name}}, state}

      leg ->
        case fun.(leg) do
          {:reply, reply, leg} -> {:reply, reply, put_leg(state, name, leg)}
          {:noreply, leg} -> {:noreply, put_leg(state, name, leg)}
          {:fail, reason} -> fail(state, reason)
        end
    end
  end

  # The handle an event or a returned reference carries for a leg. The inbound
  # (or only) leg keeps the bare pid every existing scenario, adapter caller and
  # test matches on; any other leg is named — `MediaServer.conn_ref/0`.
  defp handle_of(:inbound), do: self()
  defp handle_of(name), do: {self(), name}

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
      # The endpoint(s) this session holds — see new_leg/4. `medias` and
      # `endpoint_id` stay here only until the first leg exists: EndpointCreate
      # needs them and there is no leg to read them from yet.
      medias: medias,
      endpoint_id: nil,
      legs: %{},
      status: :init,
      # sub-resources: ref => %{...}; tags "p-<n>"/"r-<n>" route server events.
      # Each records the leg whose endpoint it is attached to.
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

      state = %{state | sess_id: sess_id, endpoint_id: endpoint_id}
      {:ok, put_leg(state, :inbound, new_leg(state, :inbound, endpoint_id, medias))}
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
  def handle_call({:get_local_offer, name}, _from, state),
    do: on_leg(state, name, &do_get_local_offer/1)

  def handle_call({:set_remote_answer, name, sdp}, _from, state),
    do: on_leg(state, name, &do_set_remote_answer(&1, sdp))

  def handle_call({:set_remote_offer, name, sdp}, _from, state),
    do: on_leg(state, name, &do_set_remote_offer(&1, sdp))

  def handle_call({:add_remote_candidate, name, candidate}, _from, state),
    do: on_leg(state, name, &do_add_remote_candidate(&1, candidate))

  # Closing a leg deletes ITS endpoint; the session — and this process — go when
  # the last leg is closed. Order-independent on purpose: the media mixin walks
  # the legs in creation order, so the inbound one is released first, and a rule
  # that tore the session down with it would take the outbound endpoint with it.
  def handle_call({:close, name}, _from, state) do
    case leg(state, name) do
      nil ->
        {:reply, :ok, state}

      leg ->
        state = state |> release_leg(leg) |> drop_leg(name)

        if map_size(state.legs) == 0 do
          {:stop, :normal, :ok, teardown(state)}
        else
          {:reply, :ok, state}
        end
    end
  end

  # ── Player (server doc §6.3) ────────────────────────────────────────────────

  def handle_call({:create_player, name, file_path, opts}, _from, state) do
    tag = "p-#{state.res_seq}"
    state = %{state | res_seq: state.res_seq + 1}
    l = leg(state, name)

    with {:ok, player_id} <- create(state, "PlayerCreate", [state.sess_id, tag]),
         :ok <- cleanup_on_error(state, player_id, attach_player_all(l, player_id)),
         {:ok, _} <-
           cleanup_on_error(
             state,
             player_id,
             rpc(state, "PlayerOpen", [state.sess_id, player_id, file_path])
           ),
         :ok <- maybe_seek(state, player_id, Keyword.get(opts, :start_time)) do
      ref = make_ref()

      players =
        Map.put(state.players, ref, %{
          player_id: player_id,
          tag: tag,
          file: file_path,
          opts: opts,
          leg: name
        })

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

  def handle_call({:create_recorder, name, file_path, duration_ms, opts}, _from, state) do
    warn_unsupported_recorder_opts(opts, state)
    tag = "r-#{state.res_seq}"
    state = %{state | res_seq: state.res_seq + 1}
    l = leg(state, name)

    with {:ok, recorder_id} <- create(state, "RecorderCreate", [state.sess_id, tag]),
         :ok <- attach_recorder_all(l, recorder_id) do
      ref = make_ref()

      recorders =
        Map.put(state.recorders, ref, %{
          recorder_id: recorder_id,
          tag: tag,
          file: file_path,
          duration_ms: duration_ms,
          opts: opts,
          stopping: false,
          leg: name
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

  def handle_call({:create_echo, name}, _from, %{echo: nil} = state) do
    case attach_endpoint_to_itself(leg(state, name)) do
      :ok ->
        ref = make_ref()
        send(state.event_sink, {:ms_event, {self(), :echo, ref}, :echo_started})
        {:reply, {:ok, {self(), :echo, ref}}, %{state | echo: {ref, name}}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:create_echo, _name}, _from, state),
    do: {:reply, {:error, :echo_already_started}, state}

  def handle_call({:stop_echo, ref}, _from, %{echo: {ref, name}} = state) do
    detach_all(leg(state, name))
    {:reply, :ok, %{state | echo: nil}}
  end

  def handle_call({:stop_echo, _ref}, _from, state),
    do: {:reply, {:error, :no_such_echo}, state}

  # ── Per-leg handlers (run through on_leg/3) ─────────────────────────────────

  defp do_get_local_offer(state) do
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
      {:error, reason} -> {:fail, reason}
    end
  end

  defp do_set_remote_answer(state, sdp) do
    with {:ok, descs} <- Sdp.parse(sdp),
         {:ok, state} <- apply_remote_medias(state, descs) do
      # :ice_connected is no longer emitted here: it now reflects the real media
      # connectivity, surfaced when the server reports the first validated RTP
      # packet (EndpointConnectedEvent, type 7 → handle_server_event below).
      {:reply, :ok, %{state | status: :active}}
    else
      {:error, reason} -> {:fail, reason}
    end
  end

  # ── UAS flow: process the offer and build the answer ───────────────────────

  defp do_set_remote_offer(state, sdp) do
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
         # delegated negotiation: the offer is the menu — propose its own payload
         # types to the server and answer from its verdict (a media with nothing
         # accepted is declined with port 0, not a call failure)
         {:ok, state, negotiated} <- open_offered_receive_plane(state, answerable),
         :ok <- ensure_negotiated(negotiated),
         # `true`: we are answering the peer's offer — see nat_latch?/2
         {:ok, state, negotiated} <- apply_offered_medias(state, answerable, negotiated) do
      answer =
        Sdp.build(%{
          ip: state.local_ip,
          # D7: a=ice-lite is advertised in answers only (Elixip behaves
          # gateway-like there); emitted only for WebRTC (DTLS) answers.
          ice_lite: match?({:dtls, _, _}, state.local_crypto),
          # every offered section, in order: a real answer for the negotiated
          # ones, a port-0 rejection for the rest — except the WebSocket text
          # section, which is omitted (see ws_text_section?/1).
          medias:
            descs
            |> Enum.reject(&omit_from_answer?(&1, negotiated))
            |> Enum.map(&answer_or_reject(state, negotiated, &1))
        })

      # :ice_connected deferred to the first validated RTP packet (type 7);
      # see the set_remote_answer path and handle_server_event below. Every
      # StartSending has been issued at this point, so R is known (§4).
      state =
        state
        |> note_receiving_medias(Enum.filter(answerable, &Map.has_key?(negotiated, &1.type)))

      {:reply, {:ok, answer}, %{state | status: :active}}
    else
      {:error, reason} -> {:fail, reason}
    end
  end

  defp do_add_remote_candidate(state, candidate) do
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

  # ── Server events routed by MediaServer.Mendooze ────────────────────────────

  @impl true
  def handle_info({:mendooze_event, event}, state) do
    handle_server_event(event, state)
  end

  # The RTP inactivity watchdog fired for ONE media. It carries which one: the
  # bare `:media_timeout` this used to send threw that away, and a leg that has
  # merely stopped its camera cannot then be told from one that has gone silent
  # altogether — which for a B2BUA is the difference between a media problem and
  # a dead call.
  # Endpoint events name the endpoint they concern (the JSR309 `joinableId`),
  # which is how one session holding two of them tells its legs apart. An id that
  # matches none of them falls back to the inbound leg: older servers do not
  # always carry it, and a connectivity event attributed to the only leg there is
  # cannot be attributed wrongly.
  defp leg_by_endpoint(state, ep) do
    case Enum.find(state.legs, fn {_name, l} -> l.endpoint_id == ep end) do
      {name, _leg} -> name
      nil -> :inbound
    end
  end

  # Everything a leg's endpoint reports is emitted with THAT leg's handle, so a
  # B2BUA scenario can tell "the callee stopped sending" from "the caller did".
  # The inbound leg keeps the bare pid (handle_of/1), which is why no existing
  # scenario or test had to change.
  defp on_endpoint_event(state, ep, fun) do
    name = leg_by_endpoint(state, ep)

    case leg(state, name) do
      nil -> {:noreply, state}
      l -> {:noreply, put_leg(state, name, fun.(l, handle_of(name)))}
    end
  end

  defp handle_server_event({:endpoint_disconnected, _tag, ep, media}, state) do
    on_endpoint_event(state, ep, fn l, handle ->
      Logger.warning(module: __MODULE__, session: l.sess_tag, message: "timeout on #{media}")
      send(l.event_sink, {:ms_event, handle, {:media_timeout, media}})

      %{
        l
        | timed_out: MapSet.put(l.timed_out, media),
          connected: MapSet.delete(l.connected, media)
      }
      |> maybe_notify_media_lost(handle)
    end)
  end

  # First validated RTP/SRTP packet on one media (server EndpointConnectedEvent,
  # type 7). A decrypted SRTP packet means ICE + DTLS completed (WebRTC case); a
  # plain RTP packet is simply the first media packet. The server re-arms it on
  # each StartReceiving, so the raw event repeats on renegotiation while
  # :ice_connected stays one-shot — docs/design/media-connectivity.md §3, §5.
  defp handle_server_event({:endpoint_connected, _tag, ep, media}, state) do
    on_endpoint_event(state, ep, fn l, handle ->
      Logger.info(module: __MODULE__, session: l.sess_tag, message: "media connected on #{media}")
      send(l.event_sink, {:ms_event, handle, {:media_connected, media}})

      # Media flowing again clears both the media's own timeout and the one-shot
      # latch, so a second silence produces a second `:media_lost` rather than
      # being swallowed by the first.
      %{
        l
        | connected: MapSet.put(l.connected, media),
          timed_out: MapSet.delete(l.timed_out, media),
          lost_notified: false,
          status: :active
      }
      |> maybe_notify_ice_connected(media, handle)
    end)
  end

  defp handle_server_event({:external_fir, _tag, ep, media}, state) do
    on_endpoint_event(state, ep, fn l, _handle ->
      # remote peer asked for a full intra frame: forward the update request
      rpc(l, "EndpointRequestUpdate", [l.sess_id, l.endpoint_id, @media_int[media]])
      l
    end)
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

  # The derivation rule of docs/design/media-connectivity.md §4, on the media
  # that just connected. R (`recv_medias`) is the set of medias the peer
  # transmits on; rule 1 (R empty) never reaches here since no event can arrive.
  defp maybe_notify_ice_connected(%{ice_notified: true} = state, _media, _handle), do: state

  defp maybe_notify_ice_connected(state, media, handle) do
    r = state.recv_medias || MapSet.new()

    ready? =
      cond do
        # rule 2: video is expected, and only video releases the milestone
        :video in r -> media == :video
        # rule 3: no video expected, the first media of R releases it
        true -> media in r
      end

    if ready? do
      send(state.event_sink, {:ms_event, handle, :ice_connected})
      %{state | ice_notified: true}
    else
      state
    end
  end

  # `:media_lost` — the peer has stopped sending, full stop. Derived from
  # `{:media_timeout, media}` the way `:ice_connected` is derived from
  # `{:media_connected, media}`, and exact rather than heuristic for the same
  # reason: the watchdog is armed on precisely the medias of R (`peer_sends?/1`
  # at StartRTPTimeout time), so R being covered means every media that could
  # have gone silent has.
  #
  # One dead media is a media problem — a camera switched off, a video codec the
  # peer gave up on — and only every dead media is a dead call. A B2BUA hangs up
  # on this one; it must not hang up on the other.
  defp maybe_notify_media_lost(%{lost_notified: true} = state, _handle), do: state

  defp maybe_notify_media_lost(state, handle) do
    r = state.recv_medias || MapSet.new()

    if MapSet.size(r) > 0 and MapSet.subset?(r, state.timed_out) do
      Logger.warning(
        module: __MODULE__,
        cnx_tag: state.sess_tag,
        message: "every media the peer was sending has gone silent"
      )

      send(state.event_sink, {:ms_event, handle, :media_lost})
      %{state | lost_notified: true}
    else
      state
    end
  end

  # R: the negotiated medias the peer transmits on, normalised to our point of
  # view (§4). A text-over-WebSocket section carries no RTP leg and can never
  # produce a connectivity event, so it is excluded.
  defp receiving_medias(descs) do
    for %{transport: t} = d <- descs,
        t != :ws,
        Map.get(d, :direction, :sendrecv) in [:sendrecv, :sendonly],
        into: MapSet.new(),
        do: d.type
  end

  # Called once the send plane is up for every media. With R empty no
  # connectivity event will ever arrive, so the application is told that
  # :ice_connected is not coming (§4 rule 1) rather than left waiting.
  defp note_receiving_medias(state, descs) do
    r = receiving_medias(descs)

    if MapSet.size(r) == 0 do
      Logger.info(
        module: __MODULE__,
        cnx_tag: state.sess_tag,
        message: "no media the peer transmits on; :ice_connected will not be emitted"
      )

      send(state.event_sink, {:ms_event, self(), :media_send_only})
    end

    %{state | recv_medias: r}
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

  # UAS: follow the offer — DTLS when the offer is DTLS (and we allow it), our
  # own SDES key per media when the offer carries `a=crypto` lines. Both go in
  # BEFORE EndpointStartReceiving: the receive plane must be keyed before it
  # opens, or the first packets arrive on a session that cannot decrypt them.
  defp setup_local_security_for_offer(state, descs) do
    offer_dtls? = Enum.any?(descs, &match?({:dtls, _, _, _}, &1.crypto))

    cond do
      offer_dtls? and webrtc_allowed?(state) -> setup_dtls_ice(state)
      offer_dtls? -> {:error, :webrtc_not_supported}
      true -> setup_sdes(state, descs)
    end
  end

  # One SDES line selected per media (RFC 4568 §6.2): the first offered line whose
  # suite we implement — the OFFERER's preference, honoured. All three of suite,
  # tag and the peer's key come from that same line; our own key is generated here
  # and pushed to the server, and it is the one the answer advertises. Reading only
  # the first offered line breaks on any modern client: Linphone 6.2 offers four,
  # AEAD_AES_128_GCM first — a suite the server does not do — and answering
  # AES_CM_128_HMAC_SHA1_80 while handing the server the GCM line's key produced a
  # call that established and decrypted nothing in either direction.
  defp setup_sdes(state, descs) do
    descs
    |> Enum.filter(&(Map.get(&1, :sdes_offers, []) != []))
    |> Enum.reduce_while({:ok, state}, fn desc, {:ok, st} ->
      case pick_sdes(desc) do
        nil ->
          Logger.warning(
            module: __MODULE__,
            cnx_tag: st.sess_tag,
            message:
              "#{desc.type} offers no SDES suite we support " <>
                "(#{desc.sdes_offers |> Enum.map(& &1.suite) |> Enum.join(", ")}); " <>
                "we do #{Enum.join(@sdes_suites, ", ")}"
          )

          {:halt, {:error, :no_common_sdes_suite}}

        %{tag: tag, suite: suite, key: peer_key} ->
          key = random_sdes_key()

          case rpc(st, "EndpointSetLocalCryptoSDES", [
                 st.sess_id,
                 st.endpoint_id,
                 @media_int[desc.type],
                 suite,
                 key
               ]) do
            {:ok, _} ->
              chosen = %{tag: tag, suite: suite, key: key, peer_key: peer_key}
              {:cont, {:ok, %{st | local_sdes: Map.put(st.local_sdes, desc.type, chosen)}}}

            {:error, _} = err ->
              {:halt, err}
          end
      end
    end)
  end

  defp pick_sdes(desc) do
    Enum.find(Map.get(desc, :sdes_offers, []), &(&1.suite in @sdes_suites))
  end

  # AES_CM_128 keying material is a 16-byte key plus a 14-byte salt, carried
  # base64 in the a=crypto line (RFC 4568 §6.1).
  defp random_sdes_key(), do: :crypto.strong_rand_bytes(30) |> Base.encode64()

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

  # ── UAS receive plane: delegated negotiation (the offer is the menu) ────────

  # Per answerable media, in offer order: propose the OFFER's own payload types
  # to the server and keep its verdict. A media with nothing to propose or an
  # empty verdict is skipped (G9: it becomes a port-0 rejection), not a call
  # failure; RPC errors still abort the whole offer.
  defp open_offered_receive_plane(state, descs) do
    Enum.reduce_while(descs, {:ok, state, %{}}, fn desc, {:ok, st, acc} ->
      case open_offered_receive(st, desc) do
        {:ok, st, neg} -> {:cont, {:ok, st, Map.put(acc, desc.type, neg)}}
        {:skip, st} -> {:cont, {:ok, st, acc}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  # Delegated negotiation (the MCU adapter's P8a, transposed): no local codec
  # arbitration. Every payload type the offer names that the codec table can turn
  # into a Medooze constant is proposed to `EndpointStartReceiving` — both rtpMaps
  # keyed with the OFFERED payload types, no local renumbering — and the enriched
  # return's fmtpByPt struct is the verdict the answer is built from. `nil` means
  # a media server that predates the delegation, which selects the legacy
  # reflection path in answer_codecs/2.
  # Text over WebSocket: the peer opens a WebSocket towards the media server, so
  # the receive plane is configured rather than negotiated — there is no codec to
  # arbitrate (`t140` is the whole vocabulary) and no payload type to allocate.
  # Three RPCs, in this order: switch the port to a WebSocket one (which mints
  # the token the URL carries), ask the server for its own WebSocket address,
  # then open the plane — the token has to exist before a browser can use it.
  defp open_offered_receive(state, %{transport: :ws} = desc) do
    media = desc.type
    m = @media_int[media]

    # RFC 4145: we are the WebSocket server, so the peer must be the one
    # connecting. A peer committed to `passive` is waiting for a connection we
    # will never make — decline the section rather than answer a dead one.
    if Map.get(desc, :setup, :actpass) == :passive do
      Logger.warning(
        module: __MODULE__,
        cnx_tag: state.sess_tag,
        message:
          "text over WebSocket offered with a=setup:passive; we are the server, " <>
            "so nobody would connect — declining the section"
      )

      {:skip, state}
    else
      token = ws_token()
      rtp_map = Sdp.local_rtp_map(media, @ws_text_codecs)

      with {:ok, _} <-
             rpc(state, "ConfigureMediaConnection", [
               state.sess_id,
               state.endpoint_id,
               m,
               @role_main,
               @proto_ws,
               token,
               "t140"
             ]),
           {:ok, candidates} when candidates != [] <-
             rpc(state, "GetMediaCandidates", [
               state.sess_id,
               state.endpoint_id,
               @proto_ws,
               m
             ]),
           {:ok, [port | _rest]} <-
             rpc(state, "EndpointStartReceiving", [
               state.sess_id,
               state.endpoint_id,
               m,
               rtp_map
             ]) do
        # `<base>/jsr309/<sessionId>/<token>` — the path the server's WebSocket
        # handler parses, and the token is the only thing tying that URL to this
        # endpoint's text port. Published the way the gateway did: value relative
        # to the protocol, scheme in the attribute name (`ws`/`wss`).
        base = candidates |> List.last() |> to_string() |> String.trim_trailing("/")
        {attribute, url} = Sdp.ws_url_attribute("#{base}/jsr309/#{state.sess_id}/#{token}")

        Logger.info(
          module: __MODULE__,
          cnx_tag: state.sess_tag,
          message: "text over WebSocket at a=#{attribute}:#{url}"
        )

        {:ok,
         %{
           state
           | local_ports: Map.put(state.local_ports, media, port),
             ws_urls: Map.put(state.ws_urls, media, {attribute, url}),
             proposed_recv: Map.put(state.proposed_recv, media, rtp_map),
             # A text-only WebSocket leg has no RTP address, and the session
             # still needs a `c=` line (RFC 4566 §5.7). The WebSocket's own host
             # is the honest answer — it IS where this media lives. An RTP media
             # in the same session stays authoritative.
             local_ip: state.local_ip || ws_url_host(url)
         }, %{transport: :ws, rtp_map: rtp_map, send_map: %{}, codecs: ["T140"], dtmf: false}}
      else
        {:error, reason} ->
          # A media server that cannot host the WebSocket is not a reason to
          # refuse the call: the section is declined (in fact omitted, see
          # answer_or_reject/3) and the audio/video legs stand.
          Logger.warning(
            module: __MODULE__,
            cnx_tag: state.sess_tag,
            message:
              "could not configure text over WebSocket (#{inspect(reason)}); " <>
                "the text section will be left out of the answer"
          )

          {:skip, state}

        {:ok, []} ->
          Logger.warning(
            module: __MODULE__,
            cnx_tag: state.sess_tag,
            message: "media server returned no WebSocket address; text section left out"
          )

          {:skip, state}
      end
    end
  end

  defp open_offered_receive(state, desc) do
    media = desc.type
    m = @media_int[media]

    case Sdp.propose_all(desc, dtmf?(state, media)) do
      # nothing nameable to propose on this media: declined (port 0)
      {:error, :no_common_codec} ->
        {:skip, state}

      {:ok, neg} ->
        rtp_map = neg.rtp_map
        # best-effort, BEFORE StartReceiving (the negotiator reads the endpoint's
        # codec properties when it runs)
        relay_offered_fmtp(state, m, desc, rtp_map)

        with {:ok, [port | rest]} <- start_receiving_offered(state, m, desc, rtp_map),
             {:ok, [candidate | _]} <-
               rpc(state, "GetMediaCandidates", [
                 state.sess_id,
                 state.endpoint_id,
                 @proto_rtp,
                 m
               ]),
             {:ok, ip, _cport} <- Sdp.parse_media_candidate(candidate) do
          # the server's verdict, minus any entry that cannot legally be stated in
          # an answer to THIS offer (RFC 3264 §6.1 / RFC 6184 §8.2.2)
          {accepted, dropped} =
            rtp_map
            |> Sdp.accepted_pts(List.first(rest))
            |> Sdp.conformant_pts(desc, rtp_map)

          Enum.each(dropped, fn %{pt: pt, offered: offered, answered: answered} ->
            Logger.warning(
              module: __MODULE__,
              cnx_tag: state.sess_tag,
              message:
                "video: dropped pt #{pt} from the verdict — the media server answered " <>
                  "H.264 #{answered} where the offer declared #{offered} for that payload " <>
                  "type (RFC 6184 §8.2.2); announcing it would be a codec the caller " <>
                  "never offered, and a browser refuses the whole answer over it"
            )
          end)

          Logger.info(
            module: __MODULE__,
            cnx_tag: state.sess_tag,
            message:
              "#{media}: proposed #{map_size(rtp_map)} pt, " <>
                if(accepted,
                  do: "accepted #{map_size(accepted)} negotiated-by=server",
                  else: "negotiated-by=local (media server predates the delegation)"
                )
          )

          if accepted == %{} do
            # nothing the verdict accepted survives: decline the media rather than
            # answer a codec the caller cannot match — and close the receive plane
            # we just opened, or the server holds a port for a media the answer
            # says is off
            rpc(state, "EndpointStopReceiving", [state.sess_id, state.endpoint_id, m])
            {:skip, state}
          else
            st = %{
              state
              | local_ports: Map.put(state.local_ports, media, port),
                local_ip: ip,
                proposed_recv: Map.put(state.proposed_recv, media, rtp_map),
                accepted: Map.put(state.accepted, media, accepted)
            }

            neg =
              neg
              |> Map.put(:accepted, accepted)
              # the offer's own format order, kept for the places that must agree
              # about the caller's preference: the answer's rtpmap order and the
              # payload type we send on
              |> Map.put(:fmt_order, Map.get(desc, :raw_fmt, []))
              |> Map.put(:dtmf_pts, Map.get(desc, :dtmf_pts, %{}))

            {:ok, st, Map.put(neg, :send_map, send_map(media, neg))}
          end
        else
          {:error, _} = err -> err
        end
    end
  end

  # P8a parity (server side landed 2026-08-06): the offer's fmtp travels as the
  # `offer` struct, EndpointStartReceiving's optional 5th parameter — per PAYLOAD
  # TYPE, the granularity a browser offer needs (several H.264 PTs, one
  # (profile, packetization-mode) pair each). A media server that predates the
  # parameter faults on the extra argument, so the legacy 4-parameter form is
  # retried once — the codec.* relay (relay_offered_fmtp/4) already handed that
  # server the fmtp per codec, its own best granularity.
  defp start_receiving_offered(state, m, desc, rtp_map) do
    offer_fmtp = Map.take(Map.get(desc, :fmtp_raw, %{}), Map.keys(rtp_map))
    args = [state.sess_id, state.endpoint_id, m, rtp_map]

    if offer_fmtp == %{} do
      rpc(state, "EndpointStartReceiving", args)
    else
      case rpc(state, "EndpointStartReceiving", args ++ [%{"fmtp" => offer_fmtp}]) do
        {:ok, _} = ok ->
          ok

        {:error, reason} ->
          Logger.warning(
            module: __MODULE__,
            cnx_tag: state.sess_tag,
            message:
              "EndpointStartReceiving with the offer struct failed (#{inspect(reason)}); " <>
                "retrying the legacy form — media server predates the offer parameter"
          )

          rpc(state, "EndpointStartReceiving", args)
      end
    end
  end

  # The `codec.<name>.fmtp` channel — per CODEC, the coarser of the two relays —
  # is kept alongside the offer struct: it is what a server that predates the
  # offer parameter reads (the retry path above), and on a current server the
  # per-PT offer wins for every payload type it covers (xmlrpc_jsr309_api.md
  # §6.7). The primary (offer-order) payload type of each codec elects the
  # relayed string. Best-effort: an older server logs an unknown property and
  # moves on, and a leg that negotiates is worth more than a relay.
  defp relay_offered_fmtp(state, m, desc, rtp_map) do
    fmtp_raw = Map.get(desc, :fmtp_raw, %{})

    props =
      rtp_map
      |> Enum.sort_by(&Sdp.pt_rank(&1, Map.get(desc, :raw_fmt, [])))
      |> Enum.reduce(%{}, fn {pt, code}, acc ->
        with true <- code != @dtmf_code,
             params when is_binary(params) and params != "" <- Map.get(fmtp_raw, pt),
             {encoding, _clock, _ch} <- Sdp.code_rtpmap(desc.type, code) do
          Map.put_new(acc, "codec." <> String.downcase(encoding) <> ".fmtp", params)
        else
          _ -> acc
        end
      end)

    with false <- props == %{},
         {:error, reason} <-
           rpc(state, "EndpointSetRTPProperties", [state.sess_id, state.endpoint_id, m, props]) do
      Logger.warning(
        module: __MODULE__,
        cnx_tag: state.sess_tag,
        message:
          "could not relay the offered fmtp (#{inspect(reason)}) — " <>
            "the server negotiates against its own configuration"
      )
    end

    :ok
  end

  # ── Remote side: security, sending, watchdog ───────────────────────────────

  # UAC: the peer's *answer* to an offer we made. Its SDP is a selection among
  # what we offered, so intersecting with the configured codec list is still the
  # right reading here (the delegated path is answer-side only — see
  # open_offered_receive/2).
  defp apply_remote_medias(state, descs) do
    descs = Enum.filter(descs, &answerable?(&1, state.medias))

    with :ok <- ensure_media_present(descs),
         {:ok, state, negotiated} <- apply_answered_medias(state, descs),
         :ok <- ensure_negotiated(negotiated) do
      # every StartSending has been issued: R is known (§4)
      {:ok, note_receiving_medias(state, Enum.filter(descs, &Map.has_key?(negotiated, &1.type)))}
    end
  end

  defp apply_answered_medias(state, descs) do
    Enum.reduce_while(descs, {:ok, state, %{}}, fn desc, {:ok, st, acc} ->
      case Sdp.negotiate(desc, codecs(st, desc.type), dtmf?(st, desc.type)) do
        {:error, :no_common_codec} ->
          {:cont, {:ok, st, acc}}

        {:ok, neg} ->
          # never send a codec the server just filtered on receive (no-op when
          # the server did not delegate, i.e. accepted[media] is nil)
          send_map =
            Sdp.restrict_send_map(
              neg.rtp_map,
              Map.get(st.proposed_recv, desc.type, %{}),
              Map.get(st.accepted, desc.type)
            )

          # `false`: we offered — see nat_latch?/2
          case apply_remote_media(st, desc, Map.put(neg, :send_map, send_map), false) do
            {:ok, st, neg} -> {:cont, {:ok, st, Map.put(acc, desc.type, neg)}}
            {:error, _} = err -> {:halt, err}
          end
      end
    end)
  end

  # UAS: the send plane for the medias the delegated receive plane negotiated,
  # in offer order.
  defp apply_offered_medias(state, descs, negotiated) do
    descs
    |> Enum.filter(&Map.has_key?(negotiated, &1.type))
    |> Enum.reduce_while({:ok, state, negotiated}, fn desc, {:ok, st, acc} ->
      case apply_remote_media(st, desc, Map.fetch!(acc, desc.type), true) do
        {:ok, st, neg} -> {:cont, {:ok, st, Map.put(acc, desc.type, neg)}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  # A text-over-WebSocket leg has no remote side to configure: no RTP
  # destination to send to (the peer connects to us), no crypto (the WebSocket's
  # own TLS carries it) and nothing for the RTP watchdog to watch — T.140 is
  # legitimately silent between keystrokes anyway.
  defp apply_remote_media(state, %{transport: :ws}, neg, _answering_offer?),
    do: {:ok, state, neg}

  # Applies the §9 remote-side steps for one media: transport properties, the
  # peer's security material, StartSending, then the watchdog — armed last, once
  # the answer has been processed.
  defp apply_remote_media(state, desc, neg, answering_offer?) do
    m = @media_int[desc.type]

    with :ok <- set_rtp_properties(state, m, desc, answering_offer?),
         :ok <- set_remote_crypto(state, m, desc),
         {:ok, _} <-
           rpc(state, "EndpointStartSending", [
             state.sess_id,
             state.endpoint_id,
             m,
             desc.ip,
             desc.port,
             neg.send_map
           ]),
         :ok <- arm_watchdog(state, m, desc) do
      {:ok, state, neg}
    end
  end

  # What `EndpointStartSending` may use, in the offerer's numbering.
  #
  # **Video: exactly one payload type**, the primary. One encoder means one
  # profile, and leaving several H.264 payload types in the map would let the
  # server pick which one it stamps the stream with. Audio and text keep the
  # whole accepted set: the extra entries are the telephone-event stream the
  # audio rides alongside. A nil verdict (legacy server) leaves the map alone.
  defp send_map(:video, %{accepted: accepted, rtp_map: rtp_map} = neg) when is_map(accepted) do
    case primary_entry(neg) do
      {pt, _code} -> Map.take(rtp_map, [pt])
      nil -> Map.take(rtp_map, Map.keys(accepted))
    end
  end

  defp send_map(_media, %{accepted: accepted, rtp_map: rtp_map}) when is_map(accepted),
    do: Map.take(rtp_map, Map.keys(accepted))

  defp send_map(_media, %{rtp_map: rtp_map}), do: rtp_map

  # The caller's own first choice (offer order) among what the server accepted,
  # telephone-event excluded. The answer's rtpmap order and the payload type we
  # send on must be the same reading of that preference (`Sdp.pt_rank/2`).
  defp primary_entry(%{accepted: accepted} = neg) when is_map(accepted) do
    neg.rtp_map
    |> Map.take(Map.keys(accepted))
    |> Enum.reject(fn {_pt, code} -> code == @dtmf_code end)
    |> Enum.sort_by(&Sdp.pt_rank(&1, Map.get(neg, :fmt_order)))
    |> List.first()
  end

  defp primary_entry(_neg), do: nil

  # ── RTP inactivity watchdog (direction-aware) ───────────────────────────────

  # Whether the PEER will send RTP to us on this media — the only thing a
  # *receive* watchdog can observe. A caller holding with `a=sendonly` keeps
  # sending (music on hold), so it stays armed; what starves our reception is the
  # peer declaring it will not send — `a=recvonly`, `a=inactive` — or blackholing
  # the media with `c=0.0.0.0` (RFC 3264 §8.4, the legacy hold).
  defp peer_sends?(desc) do
    Map.get(desc, :direction, :sendrecv) not in [:recvonly, :inactive] and
      Map.get(desc, :ip) != "0.0.0.0"
  end

  # Text is never armed at all: T.140 is legitimately silent between keystrokes,
  # so watching it would reap a leg the moment its user stops typing.
  defp arm_watchdog(_state, _m, %{type: :text}), do: :ok

  defp arm_watchdog(state, m, desc) do
    timeout = if peer_sends?(desc), do: rtp_timeout_ms(), else: 0

    case rpc(state, "EndpointStartRTPTimeout", [state.sess_id, state.endpoint_id, m, timeout]) do
      {:ok, _} -> :ok
      {:error, _} = err -> err
    end
  end

  # rtcp-mux (mirrored from the peer) and the RTCP-feedback switches behind the
  # feedback types the answer advertises (never the old unconditional
  # useNACK+tmmbr pair: announcing `ccm fir` while never asking for RTCP FIR
  # tells the peer it has a capability nothing implements) are merged into a
  # single EndpointSetRTPProperties call. The "secure" hint is intentionally
  # omitted: it is a no-op once DTLS/SDES crypto is configured (server audit,
  # webrtc_sdp_design.md Q2).
  defp set_rtp_properties(state, m, desc, answering_offer?) do
    props =
      %{}
      |> maybe_put(Map.get(desc, :rtcp_mux, false), "rtcp-mux", "1")
      |> Map.merge(rtcp_fb_props(desc))
      |> maybe_put(nat_latch?(state, answering_offer?), "natLatch", "1")

    if props == %{} do
      :ok
    else
      case rpc(state, "EndpointSetRTPProperties", [state.sess_id, state.endpoint_id, m, props]) do
        {:ok, _} -> :ok
        {:error, _} = err -> err
      end
    end
  end

  # The server-side switch for each feedback type we answered, and nothing else.
  defp rtcp_fb_props(desc) do
    case answered_rtcp_fb(desc) do
      types when is_list(types) ->
        Map.new(types, fn type -> {Map.fetch!(@supported_rtcp_fb, type), "1"} end)

      _ ->
        %{}
    end
  end

  # Symmetric-NAT latching: the server re-targets its send address *and* port to
  # wherever the RTP is actually coming from, but only when the destination we gave
  # it is a private (RFC1918/CGNAT/link-local) address and ICE is not in play. It
  # is disabled server-side unless we ask for it, and we only ask on the direction
  # where the peer picked that destination for us: when we ANSWER an offer, the
  # send address is whatever the peer wrote in its own SDP, which for a NATed
  # handset is its private address. On the direction we offered, the peer answered
  # knowing its own NAT — a mismatch there is a routing fault we would be papering
  # over, not a mapping worth following.
  #
  # `nat_latch: true | false` overrides the inference for a caller that knows its
  # topology; the kelixip MCU sets it explicitly rather than relying on the fact
  # that a conference leg happens to always answer.
  defp nat_latch?(state, answering_offer?) do
    case Keyword.get(state.opts, :nat_latch, :auto) do
      :auto -> answering_offer?
      enabled -> enabled == true
    end
  end

  defp maybe_put(map, true, key, value), do: Map.put(map, key, value)
  defp maybe_put(map, false, _key, _value), do: map

  defp set_remote_crypto(state, m, desc) do
    crypto_calls =
      case {desc.crypto, Map.get(state.local_sdes, desc.type)} do
        {{:dtls, setup, hash, fingerprint}, _} ->
          # the peer's RESOLVED role, never the literal actpass: the server would
          # otherwise have to resolve it exactly as we did, and a disagreement
          # about who initiates produces a DTLS stall neither side reports
          [
            {"EndpointSetRemoteCryptoDTLS", [peer_setup(setup) |> to_string(), hash, fingerprint]}
          ]

        {_, %{suite: suite, peer_key: peer_key}} ->
          # the suite and key of the ONE line setup_sdes/2 selected — never the
          # first line of the offer, which may name a suite the server cannot do
          [{"EndpointSetRemoteCryptoSDES", [suite, peer_key]}]

        {{:sdes, suite, key}, nil} ->
          # UAC path: the peer's answer selected one of our offered lines
          [{"EndpointSetRemoteCryptoSDES", [suite, key]}]

        _ ->
          []
      end

    # only when we answered with ICE ourselves: pushing the peer's credentials to
    # a session that has none of its own leaves the check pairs half-configured
    ice_calls =
      case {desc.ice, state.local_ice} do
        {%{ufrag: ufrag, pwd: pwd}, %{}} ->
          [{"EndpointSetRemoteSTUNCredentials", [ufrag, pwd]}]

        _ ->
          []
      end

    Enum.reduce_while(crypto_calls ++ ice_calls, :ok, fn {method, args}, :ok ->
      case rpc(state, method, [state.sess_id, state.endpoint_id, m | args]) do
        {:ok, _} -> {:cont, :ok}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  # The peer's resolved DTLS role: its own choice when the offer made one, the
  # complement of ours (we answer as the DTLS server) when it left it open.
  defp peer_setup(:actpass), do: :active
  defp peer_setup(role), do: role

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
    cond do
      # A configured text-over-WebSocket section is answered for real, URL
      # included — this is the section the client is waiting for to open its chat.
      match?(%{transport: :ws}, desc) and Map.has_key?(negotiated, desc.type) ->
        ws_answer_spec(state, desc)

      answerable?(desc, state.medias) and Map.has_key?(negotiated, desc.type) ->
        answer_media_spec(state, negotiated, desc)

      true ->
        reject_media_spec(desc)
    end
  end

  # The answer to a text-over-WebSocket offer (design §5.3): the offered
  # transport mirrored, the literal `t140`, `a=setup:passive` (we are the
  # server), `a=connection:new`, and the URL under `a=ws`/`a=wss`. The port is
  # the one `EndpointStartReceiving` returned, which for a WebSocket port is the
  # media server's WebSocket port.
  defp ws_answer_spec(state, desc) do
    {attribute, url} = Map.fetch!(state.ws_urls, desc.type)

    %{
      ws_text: url,
      ws_attribute: attribute,
      type: :text,
      port: Map.fetch!(state.local_ports, desc.type),
      protocol: desc.protocol,
      setup: :passive,
      direction: Sdp.reverse_direction(desc.direction),
      mid: Map.get(desc, :mid)
    }
  end

  # The host of a protocol-relative WebSocket URL (`//host:port/path`), for the
  # session's `c=` line. `URI.parse/1` reads the authority of such a URL without
  # needing a scheme.
  defp ws_url_host(url) do
    case URI.parse(url) do
      %URI{host: host} when is_binary(host) and host != "" -> host
      _ -> "0.0.0.0"
    end
  end

  # 128 random bits in the UUID shape the historical gateway used — the server
  # treats it as an opaque token (`StringParser::ParseToken`), so what matters is
  # that it is unguessable, not that the version bits are set. One per
  # configuration: a re-negotiation mints a new URL, which the answer re-signals.
  defp ws_token() do
    <<a::binary-4, b::binary-2, c::binary-2, d::binary-2, e::binary-6>> =
      :crypto.strong_rand_bytes(16)

    [a, b, c, d, e]
    |> Enum.map_join("-", &Base.encode16(&1, case: :lower))
  end

  # A declined section still carries the offer's `a=mid` (JSEP §5.3.1): it is how the
  # peer knows *which* of its sections we turned down.
  defp reject_media_spec(desc) do
    %{
      type: desc.type,
      protocol: desc.protocol,
      reject_fmt: desc.raw_fmt,
      mid: Map.get(desc, :mid)
    }
  end

  defp answer_media_spec(state, negotiated, desc) do
    neg = Map.fetch!(negotiated, desc.type)
    {rtpmaps, fmtp} = answer_codecs(desc, neg)

    %{
      type: desc.type,
      port: Map.fetch!(state.local_ports, desc.type),
      # the offerer's payload-type numbering, in ITS preference order
      rtpmaps: rtpmaps,
      fmtp: fmtp,
      bandwidth: Sdp.negotiate_bandwidth(desc.bandwidth, bandwidth_kbps(state, desc.type)),
      direction: Sdp.reverse_direction(desc.direction),
      # G3: mendooze answers DTLS as server (setup:passive) — the safe role a
      # browser/gateway expects from the answerer; an offer that already
      # committed to a role is mirrored. Or the SDES key we generated.
      crypto: answer_crypto(state, desc),
      # RFC 4568 §6.2: the tag of the offered line we accepted, never a fresh 1
      crypto_tag: answer_crypto_tag(state, desc),
      ice: state.local_ice,
      rtcp_mux: desc.rtcp_mux,
      # mirror the transport of the offer, unless we accept an RFC 5939
      # potential configuration that upgrades it
      protocol: answered_protocol(desc),
      acfg: accepted_capneg(desc),
      # the feedback types actually agreed, per video PT — never the offerer form
      rtcp_fb: answered_rtcp_fb(desc),
      # the offer's a=mid, echoed verbatim on EVERY answered section (JSEP
      # §5.3.1), not only the DTLS ones: a SIP peer that names its sections
      # would otherwise get an anonymous answer
      mid: Map.get(desc, :mid),
      # host candidates on the receive port, component 2 iff no rtcp-mux
      candidates: answer_candidates(state, desc)
    }
  end

  # DELEGATED: the accepted payload types and their fmtp are the media server's,
  # copied out verbatim — the party that will encode is the one that says what it
  # accepts and with which parameters. Both maps are keyed with the OFFERED
  # payload types (open_offered_receive/2 proposed the offer's own numbering), so
  # the verdict needs no bridging. An empty fmtp value means "accepted, no
  # a=fmtp line" and is dropped rather than emitted empty.
  defp answer_codecs(desc, %{accepted: accepted} = neg) when is_map(accepted) do
    accepted_map = Map.take(neg.rtp_map, Map.keys(accepted))

    rtpmaps =
      Sdp.answer_rtpmaps(
        desc.type,
        # `dtmf_pts` travels with the accepted set: the server picks which
        # telephone-event PT it keeps, and the answer must re-announce that PT
        # with the clock the OFFER gave it (Chrome offers one per clock).
        # `fmt_order` is the caller's own preference order: in an answer the
        # order IS a preference statement, and a gateway has none of its own.
        %{neg | rtp_map: accepted_map}
        |> Map.put(:dtmf_pts, Map.get(desc, :dtmf_pts, %{}))
        |> Map.put(:fmt_order, Map.get(desc, :raw_fmt, []))
      )

    fmtp = for {pt, params} <- accepted, params != "", into: %{}, do: {pt, params}
    {rtpmaps, fmtp}
  end

  # LEGACY: a media server that predates the delegation returned no verdict —
  # answer everything we proposed (still the offerer's numbering) and synthesize
  # the fmtp client-side: telephone-event range, RFC 4103 red redundancy, and
  # the reflected H.264 identity (the rolling-upgrade path).
  defp answer_codecs(desc, neg) do
    rtpmaps =
      Sdp.answer_rtpmaps(
        desc.type,
        neg
        |> Map.put(:dtmf_pts, Map.get(desc, :dtmf_pts, %{}))
        |> Map.put(:fmt_order, Map.get(desc, :raw_fmt, []))
      )

    fmtp =
      dtmf_fmtp(neg)
      |> Map.merge(codec_fmtp(desc, rtpmaps))
      |> Map.merge(red_fmtp(desc.type, rtpmaps))

    {rtpmaps, fmtp}
  end

  # ── RTCP feedback and RFC 5939 (answer-side policy) ─────────────────────────

  # The AVPF upgrade is only taken on VIDEO: there is no audio or text feedback
  # to switch on, so accepting it there would announce a profile nothing uses.
  # Only worth taking when the offered configuration is a feedback profile AND
  # the offer asks for feedback we can honour.
  defp accepted_capneg(%{type: :video} = desc) do
    case Map.get(desc, :capneg) do
      %{protocol: protocol} = capneg ->
        if String.ends_with?(protocol, "F") and requested_rtcp_fb(desc) != [],
          do: capneg,
          else: nil

      _ ->
        nil
    end
  end

  defp accepted_capneg(_desc), do: nil

  defp answered_protocol(desc) do
    case accepted_capneg(desc) do
      %{protocol: protocol} -> protocol
      nil -> desc.protocol
    end
  end

  # The feedback the offer asks for on this media, wildcard included:
  # `a=rtcp-fb:*` (parsed as payload type -1) applies to every format.
  defp requested_rtcp_fb(desc) do
    Map.get(desc, :rtcp_fb, %{})
    |> Map.values()
    |> List.flatten()
    |> Enum.uniq()
    |> Enum.filter(&Map.has_key?(@supported_rtcp_fb, &1))
  end

  # What the answer advertises: the INTERSECTION of what the offer asked for
  # with what the server implements — deliberately NOT gated on a feedback
  # profile. RFC 4585 §4 defines `a=rtcp-fb` for AVPF, but real endpoints —
  # Linphone 6.2.0 is the motivating one: its SRTP offer says RTP/SAVP yet lists
  # `a=rtcp-fb:* ccm tmmbr`, `ccm fir` and more — keep a plain RTP/AVP or
  # RTP/SAVP profile while listing `a=rtcp-fb` lines, and drive their
  # NACK/FIR/TMMBR off the answer's attributes, not its profile string;
  # refusing to confirm them cost those calls their loss recovery. This is an
  # assumed deviation from the RFC (same policy as the H.264
  # packetization-mode default). The profile we ANSWER is untouched — RFC
  # 3264 mirroring and the RFC 5939 capneg upgrade (accepted_capneg/1) decide
  # it as before; only the attribute emission is decoupled from it, and the
  # server-side switches (rtcp_fb_props/1) follow the same set. An offer that
  # asks for no usable feedback still gets none back.
  defp answered_rtcp_fb(desc) do
    if desc.type == :video,
      do: requested_rtcp_fb(desc),
      else: false
  end

  # ── Answer-side security material ────────────────────────────────────────────

  defp answer_crypto(%{local_crypto: {:dtls, hash, fingerprint}}, desc),
    do: {:dtls, our_setup(desc.crypto), hash, fingerprint}

  defp answer_crypto(state, desc) do
    case Map.get(state.local_sdes, desc.type) do
      %{suite: suite, key: key} -> {:sdes, suite, key}
      nil -> :none
    end
  end

  defp answer_crypto_tag(state, desc) do
    case Map.get(state.local_sdes, desc.type) do
      %{tag: tag} -> tag
      nil -> 1
    end
  end

  # We answer as the DTLS server unless the offer committed to passive itself.
  defp our_setup({:dtls, :active, _hash, _fp}), do: :passive
  defp our_setup({:dtls, :passive, _hash, _fp}), do: :active
  defp our_setup(_crypto), do: :passive

  defp answer_candidates(%{local_ice: nil}, _desc), do: []

  defp answer_candidates(state, desc) do
    Sdp.host_candidates(
      state.local_ip,
      Map.fetch!(state.local_ports, desc.type),
      Map.get(desc, :rtcp_mux, false)
    )
  end

  # ── Legacy (no-verdict) answer fmtp synthesis ───────────────────────────────

  # RFC 4733: the telephone-event PT carries the tone range it accepts.
  defp dtmf_fmtp(%{dtmf: true, dtmf_pt: pt}) when is_integer(pt),
    do: %{Integer.to_string(pt) => "0-16"}

  defp dtmf_fmtp(_neg), do: %{}

  # H.264 interop on the no-verdict path: `profile-level-id` must match for the
  # two ends to decode each other, so the offered value is reflected (with
  # `packetization-mode` when the offer states one). Deliberately NOT reflected:
  # `sprop-parameter-sets`, which describes the offerer's own encoder.
  defp codec_fmtp(desc, rtpmaps) do
    offered = Map.get(desc, :fmtp, %{})

    Enum.reduce(rtpmaps, %{}, fn %{pt: pt}, acc ->
      case reflected_params(Map.get(offered, Integer.to_string(pt))) do
        "" -> acc
        params -> Map.put(acc, Integer.to_string(pt), params)
      end
    end)
  end

  defp reflected_params(%{profile_level_id: plid} = fmtp) when is_integer(plid) do
    ["profile-level-id=" <> hex6(plid)]
    |> then(fn acc ->
      case Map.get(fmtp, :packetization_mode) do
        mode when is_integer(mode) -> acc ++ ["packetization-mode=#{mode}"]
        _ -> acc
      end
    end)
    |> Enum.join(";")
  end

  defp reflected_params(_fmtp), do: ""

  # profile-level-id is three hex bytes, lower-case, zero-padded (RFC 6184 §8.1)
  defp hex6(value),
    do: value |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(6, "0")

  # RFC 4103 §5: `red` carries an fmtp listing its generations, each naming the
  # T.140 payload type — in the offerer's numbering, and only when T.140 itself
  # is answered alongside.
  defp red_fmtp(:text, rtpmaps) do
    with %{pt: red_pt} <- Enum.find(rtpmaps, &(&1.encoding == "red")),
         %{pt: t140_pt} <- Enum.find(rtpmaps, &(&1.encoding == "t140")) do
      %{Integer.to_string(red_pt) => "#{t140_pt}/#{t140_pt}/#{t140_pt}"}
    else
      _ -> %{}
    end
  end

  defp red_fmtp(_media, _rtpmaps), do: %{}

  # ── Offer-side delegated codec section (UAC, our numbering) ─────────────────

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
    # Whatever legs are left — `close` releases them one at a time, a crash or a
    # setup failure leaves them all.
    Enum.each(Map.values(state.legs), &release_leg(state, &1))

    if state.sess_id, do: rpc(state, "MediaSessionDelete", [state.sess_id])

    Mendooze.unregister_conn(state.server, state.sess_tag)
    send(state.event_sink, {:ms_event, self(), :closed})
    %{state | status: :closed, legs: %{}}
  end

  # One endpoint: stop both planes per media, then delete it. The session is not
  # this function's business — it belongs to the connection, not to a leg.
  defp release_leg(state, nil), do: state

  defp release_leg(state, leg) do
    Enum.each(leg.medias, fn media ->
      m = @media_int[media]
      rpc(leg, "EndpointStopSending", [leg.sess_id, leg.endpoint_id, m])
      rpc(leg, "EndpointStopReceiving", [leg.sess_id, leg.endpoint_id, m])
    end)

    if leg.endpoint_id, do: rpc(leg, "EndpointDelete", [leg.sess_id, leg.endpoint_id])
    state
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

  # A deliberate RFC 3264 §6 violation, scoped to one case: a text-over-WebSocket
  # section we could NOT configure is OMITTED from the answer rather than
  # declined with port 0. The Elioz/WebRTComm client injects `m=text … TCP/WS
  # t140` into the wire SDP after setLocalDescription and strips the answer's text
  # section before setRemoteDescription — but its strip does not recognise the
  # port-0 echo, so the browser saw three answer sections against its two-section
  # local offer and libwebrtc rejected the whole answer
  # (kMlineMismatchInAnswer).
  #
  # A section we DID configure is answered for real (`ws_answer_spec/2`): that
  # answer, and its `a=ws` URL, is precisely what the client is waiting for to
  # open its chat — and it removes the section itself before handing the SDP to
  # the browser.
  defp omit_from_answer?(%{transport: :ws} = desc, negotiated),
    do: not Map.has_key?(negotiated, desc.type)

  defp omit_from_answer?(_desc, _negotiated), do: false

  # After negotiation, at least one media must have produced a real answer
  # (G9: skipped :no_common_codec sections do not count).
  defp ensure_negotiated(negotiated) when map_size(negotiated) == 0,
    do: {:error, :no_common_codec}

  defp ensure_negotiated(_negotiated), do: :ok

  defp rtp_timeout_ms() do
    Application.get_env(:elixip2, MediaServer.Mendooze, [])
    |> Keyword.get(:rtp_timeout_ms, @default_rtp_timeout_ms)
  end

  # ICE credentials, in the alphabet ICE actually defines for them: `ice-char =
  # ALPHA / DIGIT / "+" / "/"` (RFC 8839 §5.4). Base64**url** — which this used —
  # produces `-` and `_`, outside that grammar: browsers happen not to check,
  # strict SDP parsers (the Glassfish gateway's among them) do. Hex is a strict
  # subset. 8 bytes → a 16-char ufrag, 24 → a 48-char pwd (minimum 4 and 22).
  defp random_token(bytes),
    do: :crypto.strong_rand_bytes(bytes) |> Base.encode16(case: :lower)
end
