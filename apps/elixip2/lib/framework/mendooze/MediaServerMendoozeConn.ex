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

  # How long a caller waits for this GenServer, as opposed to how long ONE
  # XML-RPC request waits (`xmlrpc_timeout_ms`, default 2 s). The two-level
  # arrangement is deliberate: the inner one must fire first, so a slow server
  # makes a call RETURN an error instead of exiting. The outer one is for a Conn
  # wedged somewhere other than in an RPC.
  #
  # It matters more since one process serves both legs of a B2BUA: a slow
  # `EndpointStartReceiving` on one leg now blocks the other at the head of the
  # queue, and this timeout is counted by the CALLER — so the second leg can
  # expire having never been served. Hence configurable, and hence the floor.
  # Sized on the same reading as the XML-RPC timeout it floors (2 s): one setup
  # sequence issues a dozen RPCs, but they fail as a chain — the first one to time
  # out ends the `with`, so the realistic worst case is one slow RPC plus a handful
  # of fast ones, not a dozen slow ones. Ten seconds covers that with room to
  # spare, and it is what a scenario waits before it may act on its own.
  @default_call_timeout 10_000
  @min_call_timeout_factor 3

  @default_rtp_timeout_ms 10_000

  # Video sizes, from the server's own config.h (CIF = 1 → 352x288). Read there
  # rather than from the Java client's constants: the client spells one of the
  # transcoder RPCs `AudioTranscoderDetach` while the server registers
  # `AudioTranscoderDettach`, which is a good reminder of which side is
  # authoritative.
  @video_sizes %{
    qcif: 0,
    cif: 1,
    vga: 2,
    pal: 3,
    hvga: 4,
    qvga: 5,
    hd720p: 6,
    wqvga: 7,
    fourcif: 12,
    foursif: 13,
    xga: 14,
    dcif: 16
  }

  # What the Java gateway passes, and what a transcoded leg gets unless the
  # connection opts say otherwise (`:video_size`, `:video_fps`,
  # `:video_intra_period`).
  @default_video_size :cif
  @default_video_fps 20
  @default_video_intra_period 200

  # MediaFrame::Type wire values
  @media_int %{audio: 0, video: 1, text: 2, application: 3}
  # MediaFrame::MediaProtocol RTP
  @proto_rtp 0
  # MediaFrame::MediaProtocol WS — the transport of a text-over-WebSocket media
  @proto_ws 2
  # MediaRole::VIDEO_MAIN. For a text media this is not a mistake: it is the
  # "main" port of any media, whatever its type (Endpoint::GetPort).
  @role_main 0

  # SPEEX (wideband, the one variant the server factory carries) closes the same
  # hole one media down: a speex-only callee offered this menu without it
  # declined the audio outright (traffic of 2026-08-14), while the server could
  # have transcoded it all along. This list remains a copy of the factory —
  # the honest fix is the capability query (`codec_capabilities_plan.md`).
  @default_audio_codecs ["OPUS", "PCMU", "PCMA", "SPEEX"]
  # AV1 belongs here: the media server carries it end to end (`AV1Decoder`,
  # `AV1Encoder` over libsvtav1, `AV1Encoder::ResolveNegotiation` for the fmtp,
  # `ClampToLevel` for the level bound) and `Sdp`'s codec table names it. Leaving
  # it out of the OFFER meant a caller doing AV1 got answered AV1 on its own leg —
  # its offer is the menu there — while the callee was offered H.264 and VP8 only,
  # declined the video, and the call died on `{:not_negotiated, :video}`.
  @default_video_codecs ["AV1", "H264", "VP8"]
  @default_text_codecs ["T140", "T140RED"]

  # Video bitrate (kb/s): what a transcoded leg is encoded at, and the bandwidth
  # advertised as b=AS: on the video media. Same value as the mcu module's
  # `video_bitrate`, both defaulting to `[mediaserver] video_bitrate` on a kelixip
  # node — one bitrate per node, whichever media path carries the call.
  @default_video_bandwidth_kbps 1500

  # telephone-event's Medooze codec constant: never a codec a leg is said to
  # "carry" — it is excluded from `peer_codecs/1`, so the cross-leg selection can
  # never land on it, and from `one_pt_per_codec/3`.
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
  #
  # `goog-remb` (draft-alvestrand-rmcat-remb-03) says the same thing as
  # `ccm tmmbr` in the browsers' dialect, and it now has its own server-side
  # mode (rate-control lot 2). It matters because Chrome and Firefox offer
  # `goog-remb` and never `ccm tmmbr`: without it, no congestion feedback ever
  # left towards a browser. Neither dialect is emitted un-negotiated — the
  # property posted here is what turns it on, and TMMBR wins when a peer asks
  # for both.
  #
  # `transport-cc` is deliberately ABSENT: the attribute alone switches nothing on. Its
  # server-side property is keyed by the RTP header extension's URI and valued with the
  # negotiated extmap id (`transport_cc_props/1`), so it cannot ride this
  # attribute-to-switch table. It is still confirmed in the answer
  # (`answered_transport_cc_fb/1`).
  @supported_rtcp_fb %{
    "nack" => "useNACK",
    "nack pli" => "useRtcpFIR",
    "ccm fir" => "useRtcpFIR",
    "ccm tmmbr" => "tmmbr",
    "goog-remb" => "remb"
  }

  # The two dialects that carry a bitrate target back to the sender, and the name
  # `[mediaserver] bitrate_feedback` allows each by. Narrowing that list drops the
  # others from the answer, which is what an OPEN-LOOP measurement needs: with
  # nothing leaving towards the peer, the source keeps emitting at its own rate and
  # the incoming bitrate stops depending on our estimate. It is the only
  # configuration in which the server's recovery time measures its own estimator
  # rather than the loop it forms with the browser's congestion control — five
  # closed-loop sessions (mediaserver rate_control_plan.md, lot 3) could not tell
  # the two apart. Naming one dialect isolates one path; naming none leaves the call
  # without any congestion control from us, so production wants both.
  @rate_control_rtcp_fb %{"goog-remb" => :remb, "ccm tmmbr" => :tmmbr}
  @default_bitrate_feedback [:remb, :tmmbr]

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

  @doc """
  Add a second endpoint to the media session `sibling` already owns, and return
  its handle.

  This is what `create_peer_connection(server, sink, bridge_with: <ref>)` routes
  to. The B2BUA's outbound leg is not a second connection: two endpoints can only
  be attached to each other inside one `MediaSession`
  (docs/design/notes/mediagw_b2bua_jsr309.md §2), so the placement has to be decided
  when the endpoint is created and cannot be repaired later by `bridge/3`.

  `opts` are the new leg's OWN — codecs, `:media`, `:webrtc_support`, bandwidth.
  Two legs of a gateway call rarely agree on them; that asymmetry is the point.
  """
  def add_leg(sibling, opts) do
    {pid, _name} = ref(sibling)
    GenServer.call(pid, {:add_leg, :outbound, opts}, call_timeout())
  end

  # Every entry point takes a `MediaServer.conn_ref/0`: a bare pid names the
  # inbound (or only) leg, `{pid, name}` names another endpoint of the same
  # session. Splitting it here means the handlers below never see the two forms.
  defp ref(conn) when is_pid(conn), do: {conn, :inbound}
  defp ref({conn, name}) when is_pid(conn) and is_atom(name), do: {conn, name}

  def get_local_offer(conn) do
    {pid, name} = ref(conn)
    GenServer.call(pid, {:get_local_offer, name}, call_timeout())
  end

  def set_remote_answer(conn, sdp) do
    {pid, name} = ref(conn)
    GenServer.call(pid, {:set_remote_answer, name, sdp}, call_timeout())
  end

  def set_remote_offer(conn, sdp) do
    {pid, name} = ref(conn)
    GenServer.call(pid, {:set_remote_offer, name, sdp}, call_timeout())
  end

  def add_remote_candidate(conn, candidate) do
    {pid, name} = ref(conn)
    GenServer.call(pid, {:add_remote_candidate, name, candidate}, call_timeout())
  end

  @doc """
  This leg's call has been answered: arm the RTP inactivity watchdog on every
  media the peer said it would send, and on no other (§16.1, and see
  `MediaServer.Behaviour.call_answered/1` for why not a moment earlier).

  Idempotent — a second call changes nothing.
  """
  def call_answered(conn) do
    {pid, name} = ref(conn)
    GenServer.call(pid, {:call_answered, name}, call_timeout())
  end

  @doc """
  Attach two of this session's endpoints to each other, per media, in both
  directions — the `buildBridge` moment. Both refs must name legs of the SAME
  connection: that is what "two endpoints of one MediaSession" means, and it is
  decided by `add_leg/2`, not here.
  """
  def bridge(a, b, opts) do
    {pid_a, name_a} = ref(a)
    {pid_b, name_b} = ref(b)

    if pid_a == pid_b do
      GenServer.call(pid_a, {:bridge, name_a, name_b, opts}, call_timeout())
    else
      {:error, :not_same_media_session}
    end
  end

  def unbridge(a, b) do
    {pid_a, name_a} = ref(a)
    {pid_b, name_b} = ref(b)

    if pid_a == pid_b do
      GenServer.call(pid_a, {:unbridge, name_a, name_b}, call_timeout())
    else
      :ok
    end
  catch
    :exit, _ -> :ok
  end

  def close(conn) do
    {pid, name} = ref(conn)
    GenServer.call(pid, {:close, name}, call_timeout())
  catch
    # already stopped (e.g. torn down after a setup failure) — close is idempotent
    :exit, _ -> :ok
  end

  # Sub-resources — handles are {conn_pid, kind, ref} tuples
  def create_player(conn, file_path, opts) do
    {pid, name} = ref(conn)
    GenServer.call(pid, {:create_player, name, file_path, opts}, call_timeout())
  end

  def player_cmd({conn, :player, ref}, cmd),
    do: GenServer.call(conn, {:player_cmd, cmd, ref}, call_timeout())

  def create_recorder(conn, file_path, duration_ms, opts) do
    {pid, name} = ref(conn)
    GenServer.call(pid, {:create_recorder, name, file_path, duration_ms, opts}, call_timeout())
  end

  def recorder_cmd({conn, :recorder, ref}, cmd),
    do: GenServer.call(conn, {:recorder_cmd, cmd, ref}, call_timeout())

  def create_echo(conn) do
    {pid, name} = ref(conn)
    GenServer.call(pid, {:create_echo, name}, call_timeout())
  end

  def stop_echo({conn, :echo, ref}), do: GenServer.call(conn, {:stop_echo, ref}, call_timeout())

  # ── Initialisation ──────────────────────────────────────────────────────────

  # ── Legs ────────────────────────────────────────────────────────────────────
  #
  # A B2BUA call is ONE MediaSession holding TWO Endpoints, because
  # `EndpointAttachToEndpoint` takes a single session id and two endpoints are
  # connectable only inside one session (docs/design/notes/mediagw_b2bua_jsr309.md §2).
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
      prefer: state.prefer,
      network_profiles: state.network_profiles,
      # this leg
      leg: name,
      endpoint_id: endpoint_id,
      medias: medias,
      local_ports: %{},
      # The media server's announced address for this leg — NOT ours. Filled from
      # what EndpointStartReceiving and GetMediaCandidates answer.
      local_ip: nil,
      # The profile of the address of OURS this peer reached (`local_ip:` on
      # create_peer_connection), which is this leg's own: two legs of a gateway
      # call face two sides of the network. nil on a leg we placed, which had no
      # transport when it was created.
      sip_profile: sip_profile(state.opts),
      # The profile asked of the media server, fixed on this leg's first
      # StartReceiving and repeated verbatim afterwards.
      address_profile: nil,
      local_crypto: :none,
      local_ice: nil,
      local_sdes: %{},
      ws_urls: %{},
      proposed_recv: %{},
      accepted: %{},
      # The Medooze codec CODE this leg settled on, per media. Payload types are
      # each peer's own numbering and mean nothing across legs; the code is the
      # codec itself, which is what makes `bridge/3`'s "do these two agree?"
      # exact rather than a guess.
      negotiated: %{},
      # Every code this peer can carry, per media, in the peer's OWN preference
      # order — `codecsPri` in the Java gateway's vocabulary
      # (mediagw_b2bua_jsr309.md §5). The head of it is what `negotiated` holds;
      # the tail is what makes the cross-leg selection possible at all, because
      # "is there a codec BOTH peers support" cannot be answered from two heads.
      peer_codecs: %{},
      # Le mode de mise en paquets H.264 que ce pair sait RECEVOIR, par média
      # (`Sdp.h264_receive_mode/1`, absence = 0 au sens de la RFC 6184 §8.1).
      # Lu par la sélection croisée : deux pattes en H.264 ne se relaient que si
      # elles s'accordent dessus, sinon ce qui sort de l'une est indépaquetisable
      # par l'autre.
      peer_h264_mode: %{},
      # The medias this peer explicitly turned down — a port-0 m= in its answer
      # (RFC 3264 §6) or in its re-offer (§5.1). Distinct from a media that is
      # merely not negotiated YET: a decline is the peer's definite verdict, and
      # `bridgeable_medias/3` propagates it to the other leg's answer instead of
      # bridging a channel one end of which does not exist. Cleared the moment a
      # later offer/answer re-establishes the media.
      declined: MapSet.new(),
      # What it takes to build this leg's answer a SECOND time, once the other
      # leg has answered and the selection is known: every offered section (the
      # port-0 rejections included, so the answer keeps one m= per offered m=)
      # and the per-media negotiation the first pass produced. Only set on a leg
      # that answered an offer — a leg we offered on has no answer to rebuild.
      offer_descs: nil,
      negs: %{},
      status: :init,
      connected: MapSet.new(),
      recv_medias: nil,
      ice_notified: false,
      timed_out: MapSet.new(),
      lost_notified: false,
      # The RTP inactivity watchdog, in two halves. `watchdogs` is what the last
      # negotiation asks for, per media (ms, `0` = disarmed because the peer said
      # it will not send); `answered` says whether the call is up, which is the
      # only moment any of it may be pushed to the server (`do_call_answered/1`).
      # A renegotiation on an answered leg applies straight away — that is the
      # hold/resume path, and it must not wait for an answer that has already
      # happened.
      watchdogs: %{},
      answered: false
    }
  end

  defp leg(state, name), do: Map.get(state.legs, name)

  # What building a description for `name` needs to know about the REST of the
  # call: the policy, and what the other leg carries per media.
  #
  # This is the whole difference between a first offer and a renegotiation. On
  # the first INVITE of the callee's leg the caller has already been negotiated,
  # and by the time anything is re-offered BOTH legs have been; ignoring that and
  # emitting the same static menu every time is what put AV1 at the head of a
  # re-INVITE relayed to a peer known to speak VP8 only (traffic of 2026-08-13).
  #
  # Two legs is what a B2BUA has, so "the other leg" is the other entry of the
  # map. A connection with one leg (a plain UAS, a conference leg) gets an empty
  # `carried`, and every rule built on it degrades to the static menu used before.
  defp cross(state, name) do
    other =
      case Enum.find(state.legs, fn {n, _leg} -> n != name end) do
        {_n, leg} -> leg
        nil -> nil
      end

    %{policy: state.policy, carried: (other && other.peer_codecs) || %{}}
  end

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
    %{base_url: base_url, queue_id: queue_id, network_profiles: network_profiles} =
      Mendooze.rpc_info(server)
    sess_tag = "cx-#{:erlang.unique_integer([:positive, :monotonic])}"
    medias = medias_from_opts(opts)

    state = %{
      server: server,
      event_sink: event_sink,
      base_url: base_url,
      opts: opts,
      # What the media server says it can announce (§6.7 ter), read once when the
      # connection was made. `:unsupported` on a server whose API predates it, and
      # then no leg asks for a profile at all.
      network_profiles: network_profiles,
      # The scenario's codec ranking for this connection's answers, per media
      # (`prefer_codecs:` on create_peer_connection), resolved to codec CODES
      # once, here — so a typo in a codec name fails the creation, not an
      # answer mid-call. Empty map when the scenario stated nothing.
      prefer: scenario_preference(opts),
      sess_tag: sess_tag,
      sess_id: nil,
      # The endpoint(s) this session holds — see new_leg/4. `medias` and
      # `endpoint_id` stay here only until the first leg exists: EndpointCreate
      # needs them and there is no leg to read them from yet.
      medias: medias,
      endpoint_id: nil,
      legs: %{},
      # What each media is wired with: %{media => :attach | {:transcode, [ids]}}.
      # The transcoder ids are why this is kept — they are session resources and
      # have to be deleted, not merely detached.
      bridges: %{},
      # The pair `bridges` was built for, in the order `bridge/3` was given them,
      # and the codec selected for each leg: %{media => {code_a, code_b}}. Both
      # exist for the RE-negotiation path — a re-INVITE changes what a leg
      # carries, so the selection has to be taken again, and re-taking it is only
      # cheap if we can tell what changed (`rebridge/4`).
      bridge_legs: nil,
      selection: %{},
      # The per-media transcoding policy, remembered rather than passed around:
      # `bridge/3` receives it, but an OFFER is built long before any bridge and
      # is shaped by it too (`offer_codecs/3`). Kept at connection level because
      # it is a property of the CALL, not of one leg.
      policy: policy_from_opts(opts),
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

  # The transcoding policy as the connection options state it, defaulting to
  # `:avoid` per media — the same default `bridge/3` applies, and it has to be
  # the same one: an offer shaped under one policy and bridged under another
  # would state a preference the selection then contradicts.
  #
  # Accepts the keyword form the `transcode:` option is written in and the map
  # form `MediaServer.transcoding_policy/1` returns, because the B2BUA computes
  # the policy once and hands the same value to both.
  defp policy_from_opts(opts) do
    case Keyword.get(opts, :transcode) do
      nil -> %{}
      policy when is_map(policy) -> policy
      kw when is_list(kw) -> Map.new(kw)
    end
  end

  # `prefer_codecs:` as the connection options state it — the scenario's codec
  # ranking for this connection's answers, per media, names as the Sdp codec
  # tables spell them: `[video: ["H264", "VP8"], audio: ["OPUS"]]` (keyword or
  # map). Resolved to codec codes here so that an unknown media or codec name
  # raises at create_peer_connection time (`Sdp.codec_codes/2` raises), the
  # moment the scenario author is looking.
  defp scenario_preference(opts) do
    case Keyword.get(opts, :prefer_codecs) do
      nil ->
        %{}

      prefs when is_list(prefs) or is_map(prefs) ->
        for {media, names} <- prefs, into: %{} do
          if media not in [:audio, :video, :text] do
            raise ArgumentError, "prefer_codecs: unknown media #{inspect(media)}"
          end

          {media, Sdp.codec_codes(media, names)}
        end
    end
  end

  # ── UAC flow: build the offer, then process the answer ─────────────────────

  @impl true
  def handle_call({:get_local_offer, name}, _from, state),
    do: on_leg(state, name, &do_get_local_offer(&1, cross(state, name)))

  def handle_call({:set_remote_answer, name, sdp}, _from, state),
    do: on_leg(state, name, &do_set_remote_answer(&1, sdp))

  def handle_call({:set_remote_offer, name, sdp}, _from, state),
    do: on_leg(state, name, &do_set_remote_offer(&1, sdp, cross(state, name)))

  def handle_call({:add_remote_candidate, name, candidate}, _from, state),
    do: on_leg(state, name, &do_add_remote_candidate(&1, candidate))

  def handle_call({:call_answered, name}, _from, state),
    do: on_leg(state, name, &do_call_answered/1)

  def handle_call({:add_leg, name, opts}, _from, state) do
    cond do
      leg(state, name) != nil ->
        {:reply, {:error, {:leg_exists, name}}, state}

      is_nil(state.sess_id) ->
        {:reply, {:error, :no_media_session}, state}

      true ->
        medias = medias_from_opts(opts)
        tag = "#{state.sess_tag}-#{name}"

        case create(state, "EndpointCreate", [
               state.sess_id,
               tag,
               :audio in medias,
               :video in medias,
               :text in medias
             ]) do
          {:ok, endpoint_id} ->
            Logger.info(
              module: __MODULE__,
              cnx_tag: state.sess_tag,
              message:
                "created Endpoint #{endpoint_id} (#{name}) in the same MediaSession, " <>
                  "media #{inspect(medias)}"
            )

            # The leg carries ITS opts, not the connection's: an inbound WebRTC
            # leg and an outbound plain-RTP one is the gateway case, and it is
            # `opts` that says which is which.
            l = new_leg(%{state | opts: opts}, name, endpoint_id, medias)

            # The policy is the CALL's, so a second leg naming it settles it for
            # both — the B2BUA passes the same `transcode:` to each leg, and a
            # call created leg-by-leg must not end up shaping one of them under
            # a default the other never agreed to.
            state = %{state | policy: Map.merge(state.policy, policy_from_opts(opts))}

            {:reply, {:ok, handle_of(name)}, put_leg(state, name, l)}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end
    end
  end

  # ── The bridge (docs/design/notes/mediagw_b2bua_jsr309.md §3) ─────────────────────

  # Called once when both legs have first answered, and AGAIN after every
  # renegotiation — a re-INVITE changes what a leg carries, so the cross-leg
  # selection has to be taken again on the new lists. Taking it again is not
  # rebuilding it: `apply_wiring/6` keeps the wiring that is still right and
  # re-issues only what changed, so a re-INVITE that settles on the same codecs
  # costs nothing on the wire.
  def handle_call({:bridge, a, b, opts}, _from, state) do
    with {:ok, policy} <- MediaServer.transcoding_policy(opts),
         {:ok, la, lb} <- both_legs(state, a, b),
         state = %{state | policy: policy},
         {:ok, medias} <- bridgeable_medias(la, lb, policy) do
      case Enum.reduce_while(medias, {:ok, state}, fn {media, how, sel}, {:ok, st} ->
             case apply_wiring(st, la, lb, media, how, sel) do
               {:ok, st} -> {:cont, {:ok, st}}
               err -> {:halt, err}
             end
           end) do
        {:ok, state} ->
          Logger.info(
            module: __MODULE__,
            cnx_tag: state.sess_tag,
            message:
              "bridged #{la.leg} <-> #{lb.leg} on " <>
                inspect(Enum.map(medias, fn {m, how, _sel} -> {m, how} end))
          )

          {:reply, bridge_reply(la, lb, medias, policy), %{state | bridge_legs: {la.leg, lb.leg}}}

        err ->
          {:reply, err, state}
      end
    else
      {:error, _} = err -> {:reply, err, state}
    end
  end

  def handle_call({:unbridge, a, b}, _from, state) do
    case both_legs(state, a, b) do
      {:ok, la, lb} ->
        Enum.each([la, lb], &detach_all/1)
        {:reply, :ok, release_transcoders(state)}

      {:error, _} ->
        {:reply, :ok, release_transcoders(state)}
    end
  end

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

  # Detaching the endpoints is not enough: a transcoder is a session resource of
  # its own, and one left behind survives every re-bridge for the life of the
  # call. The Java gateway deletes them for the same reason.
  defp release_transcoders(state) do
    Enum.each(state.bridges, fn
      {media, {:transcode, ids}} ->
        kind = transcoder_kind(media)

        Enum.each(ids, fn tr ->
          rpc(state, "#{kind}TranscoderDettach", [state.sess_id, tr])
          rpc(state, "#{kind}TranscoderDelete", [state.sess_id, tr])
        end)

      {_media, :attach} ->
        :ok
    end)

    %{state | bridges: %{}, selection: %{}, bridge_legs: nil}
  end

  defp both_legs(state, a, b) do
    case {leg(state, a), leg(state, b)} do
      {nil, _} -> {:error, {:no_such_leg, a}}
      {_, nil} -> {:error, {:no_such_leg, b}}
      {la, lb} -> {:ok, la, lb}
    end
  end

  # Which medias can be connected directly, and what to do about the ones that
  # cannot.
  #
  # Text is never transcoded — the Java gateway does not either, and the T.140 /
  # text-over-WebSocket gateway depends on it being a straight attach.
  defp bridgeable_medias(la, lb, policy) do
    # A media either peer explicitly declined (a port-0 answer or re-offer
    # section — `leg.declined`) is dead on the WHOLE call, audio included: a
    # B2BUA cannot honour a media it holds only one end of. It is not bridged,
    # and `leg_shaping/4` turns each `:decline` entry into a port-0 section of
    # the other leg's rebuilt answer — that propagation is what tells the
    # caller its audio has no far end, instead of a `sendrecv` grant into the
    # void (traffic of 2026-08-14). This is distinct from the "nothing
    # negotiated" errors below: a decline is a definite verdict, not a hole.
    declined = MapSet.union(la.declined, lb.declined)
    common = Enum.filter(la.medias, &(&1 in lb.medias and &1 not in declined))
    declines = Enum.map(declined, &{&1, :decline, nil})

    Enum.reduce_while(common, {:ok, declines}, fn media, {:ok, acc} ->
      case bridge_decision(la, lb, media, policy) do
        # One leg carries nothing at all on this media — nobody offered it.
        # There is no bridge to build and no policy to apply: it is simply not
        # part of this call. Fatal only for audio, on §11's own reasoning that a
        # call with no audio is not a call; for anything else the media is
        # declined in the answer and the call goes on. Killing an otherwise good
        # call over a video leg nobody offered is the worst of both.
        {:error, {:not_negotiated, m}} when m != :audio ->
          {:cont, {:ok, acc ++ [{m, :decline, nil}]}}

        {:error, _} = err ->
          {:halt, err}

        {how, sel} ->
          {:cont, {:ok, acc ++ [{media, how, sel}]}}
      end
    end)
  end

  defp bridge_decision(_la, _lb, :text, _policy), do: {:attach, nil}

  # The wiring is the POLICY's, not the selection's. `:forbid` says the media may
  # never be transcoded, so it is the only one that gets a direct
  # `Endpoint ↔ Endpoint`; `:avoid` and `:force` both get
  # `Endpoint ↔ Transcoder ↔ Endpoint`.
  #
  # Putting a transcoder in `:avoid`'s path may read backwards — its whole point is
  # to avoid transcoding — but the transcoder is what makes "avoid" hold WITHOUT a
  # renegotiation. It decides per incoming packet: `TryCodec` asks the sink whether
  # it can carry the codec that just arrived and, when it can, the packet is
  # forwarded untouched (`RTPMultiplexer::Multiplex` copies nothing —
  # `AudioTranscoder` since always, `VideoTranscoder` since the bridging pass of
  # 2026-08-12). So the steady state of an `:avoid` call whose legs agree is still a
  # relay, and the day a peer switches codec mid-stream the path follows instead of
  # breaking. A plain attach cannot: it would relay a codec the far end never
  # accepted.
  #
  # `useOriSeqNum` is deliberately NOT set on that path, and this is not an
  # oversight. It also sets `useOriTS` (`rtpsession.cpp:526-529`) and copies both
  # numbers off the incoming packet — right while bridging, wrong the moment the
  # encoder produces the packet instead, since an encoded frame carries no
  # meaningful sequence of the source's. Re-stamping is safe either way:
  # `RTPEndpoint::onRTPPacket` advances the outgoing timestamp by the incoming
  # DELTA, so packets of one frame keep one timestamp and frame grouping survives.
  # Only on the static attach path, where nothing else can ever produce a packet,
  # is preserving the original numbering both safe and worth it.
  defp bridge_decision(la, lb, media, policy) do
    case select_codecs(la, lb, media, policy) do
      {:error, _} = err ->
        err

      {:ok, code_a, code_b} ->
        how = if Map.get(policy, media, :avoid) == :forbid, do: :attach, else: :transcode
        {how, {code_a, code_b}}
    end
  end

  # The cross-leg codec selection (mediagw_b2bua_jsr309.md §5): ONE decision for
  # both legs, not two independent ones joined afterwards. Naming the two lists as
  # the policy does (§11):
  #
  #     L  = what the caller offered,  in the CALLER's order   (leg A)
  #     L' = what the callee answered, in the CALLEE's order   (leg B)
  #
  #   :force  → `{hd(L), hd(L')}` — each leg keeps the head of its own list, so
  #             each peer is served the codec IT asked for whatever the other did;
  #   :avoid  → the first codec of L that also appears in L', for BOTH legs. L's
  #             order decides, because the caller's preference is the one a
  #             gateway has no business overruling. No common codec → fall back to
  #             `{hd(L), hd(L')}`;
  #   :forbid → the same selection, but no common codec refuses the media outright
  #             rather than transcoding it.
  #
  # Transcoding is then not a decision of its own: it is simply what two different
  # selections mean, and a direct attach is what one selection twice means. That
  # is the whole reason this returns codes rather than `:attach | :transcode` —
  # the old shape compared two independently-settled heads, which reads "no common
  # codec" out of two peers that both offered opus second.
  defp select_codecs(la, lb, media, policy) do
    l = Map.get(la.peer_codecs, media, [])
    lp = Map.get(lb.peer_codecs, media, [])

    case {l, lp} do
      # Nothing settled on this media yet: bridging would connect two endpoints
      # that have not agreed on anything.
      {[], _} ->
        {:error, {:not_negotiated, media}}

      {_, []} ->
        {:error, {:not_negotiated, media}}

      {[a | _], [b | _]} ->
        mode = Map.get(policy, media, :avoid)

        case {mode, Enum.find(l, &relayable?(&1, la, lb, media))} do
          {:force, _} -> {:ok, a, b}
          {_, nil} when mode == :forbid -> {:error, {:no_common_codec, media}}
          {_, nil} -> {:ok, a, b}
          {_, common} -> {:ok, common, common}
        end
    end
  end

  # Is this codec one the two legs can RELAY to each other — not merely one they
  # both name? For every codec but H.264 the two questions are the same. H.264's
  # payload-type identity includes its `packetization-mode` (RFC 6184 §8.2.2), and
  # in relay mode nothing converts it: what leaves one leg is the packetization the
  # OTHER peer negotiated with us, handed over untouched.
  #
  # Traffic of 2026-08-21. Linphone offered `a=fmtp:99 profile-level-id=42801F`
  # with no packetization-mode — single NAL unit mode, no FU-A, no STAP-A. Chrome
  # had negotiated mode 1 with us and was fragmenting at 1170 bytes. Both legs
  # said "H264", so the bridge relayed, and Linphone's decoder answered
  # `dsNoParamSets` for the whole call on a stream the capture proves was
  # delivered byte for byte. Transcoding was always available and never chosen,
  # because "a codec both legs carry" was read off the codec NAME alone.
  #
  # Equality rather than "the sink can receive at least what the source sends":
  # one selection serves BOTH directions, so the weaker end decides either way.
  defp relayable?(code, la, lb, media) do
    code in Map.get(lb.peer_codecs, media, []) and h264_modes_agree?(code, la, lb, media)
  end

  defp h264_modes_agree?(code, la, lb, media) do
    if Sdp.codec_name(media, code) == "H264" do
      mine = Map.get(la.peer_h264_mode, media)
      theirs = Map.get(lb.peer_h264_mode, media)

      if mine == theirs do
        true
      else
        Logger.warning(
          module: __MODULE__,
          session: la.sess_tag,
          message:
            "H264 bridge refused because of incompatible packetization mode " <>
              "(#{la.leg} receives pm=#{mine}, #{lb.leg} receives pm=#{theirs}) — " <>
              "transcoding instead"
        )

        false
      end
    else
      true
    end
  end

  # Nothing to remember when the peer offers no H.264 on this media: leaving the
  # key absent would make two such legs "agree" on nil, which is exactly right —
  # they never reach h264_modes_agree?/4 anyway, H264 not being in their lists.
  defp note_h264_mode(state, desc) do
    case Sdp.h264_receive_mode(desc) do
      nil -> state
      pm -> %{state | peer_h264_mode: Map.put(state.peer_h264_mode, desc.type, pm)}
    end
  end

  # What the bridge owes this media, given what it is already wired with. Four
  # cases, and the middle one is the point of the whole re-selection path:
  #
  #   nothing wired yet          → wire it;
  #   transcoded, still transcoded → keep the transcoders, re-issue SetCodec on
  #                                the direction whose selected codec CHANGED.
  #                                Tearing the pair down and rebuilding it would
  #                                drop the media for as long as it takes, on a
  #                                call that is up;
  #   attached, still attached   → nothing at all: a direct attach carries
  #                                whatever both sides accepted, and the selection
  #                                does not parameterise it;
  #   anything else              → release this media's transcoders and wire it
  #                                afresh (a media that became declinable, a
  #                                bridge re-taken with the legs the other way
  #                                round).
  #
  # `bridge_legs` guards the direction: `bridges` stores `[tr_a, tr_b]` in the
  # order the pair was given, and re-tuning `tr_a` with `lb`'s codec would encode
  # each leg for the other one.
  defp apply_wiring(state, la, lb, media, how, sel) do
    same_pair? = state.bridge_legs in [nil, {la.leg, lb.leg}]

    case {Map.get(state.bridges, media), how, same_pair?} do
      {nil, _, _} ->
        wire_media(state, la, lb, media, how, sel) |> note_selection(media, sel)

      {{:transcode, [tr_a, tr_b]}, :transcode, true} ->
        retune(state, la, lb, media, {tr_a, tr_b}, sel)

      {:attach, :attach, true} ->
        {:ok, note_sel(state, media, sel)}

      _ ->
        state
        |> release_media(media)
        |> wire_media(la, lb, media, how, sel)
        |> note_selection(media, sel)
    end
  end

  # Only what changed: a leg whose selected codec is unchanged is not told about
  # it again. `VideoTranscoderSetCodec` restarts the encoder, so re-issuing it on
  # every re-INVITE would cost a keyframe and a visible freeze for nothing.
  defp retune(state, la, lb, media, {tr_a, tr_b}, {code_a, code_b} = sel) do
    {old_a, old_b} = Map.get(state.selection, media, {nil, nil})

    with :ok <- retune_one(state, la, media, tr_a, code_a, old_a),
         :ok <- retune_one(state, lb, media, tr_b, code_b, old_b) do
      {:ok, note_sel(state, media, sel)}
    else
      {:error, reason} -> {:error, {:transcode_failed, media, reason}}
    end
  end

  defp retune_one(_state, _sink, _media, _tr, code, code), do: :ok

  defp retune_one(state, sink, media, tr, code, old) do
    Logger.info(
      module: __MODULE__,
      cnx_tag: state.sess_tag,
      message: "renegotiation moved #{sink.leg}'s #{media} from codec #{inspect(old)} to #{code}"
    )

    set_transcoder_codec(state, sink, media, tr, code)
  end

  defp release_media(state, media) do
    case Map.get(state.bridges, media) do
      {:transcode, ids} ->
        kind = transcoder_kind(media)

        Enum.each(ids, fn tr ->
          rpc(state, "#{kind}TranscoderDettach", [state.sess_id, tr])
          rpc(state, "#{kind}TranscoderDelete", [state.sess_id, tr])
        end)

        %{state | bridges: Map.delete(state.bridges, media)}

      _ ->
        %{state | bridges: Map.delete(state.bridges, media)}
    end
  end

  defp note_selection({:ok, state}, media, sel), do: {:ok, note_sel(state, media, sel)}
  defp note_selection(err, _media, _sel), do: err

  defp note_sel(state, _media, nil), do: state
  defp note_sel(state, media, sel), do: %{state | selection: Map.put(state.selection, media, sel)}

  defp wire_media(state, _la, _lb, _media, :decline, _sel), do: {:ok, state}

  defp wire_media(state, la, lb, media, :attach, _sel) do
    case attach_pair(state, la, lb, media) do
      :ok -> {:ok, put_bridge(state, media, :attach)}
      err -> err
    end
  end

  defp wire_media(state, la, lb, media, :transcode, sel) do
    case transcode_pair(state, la, lb, media, sel) do
      {:ok, ids} -> {:ok, put_bridge(state, media, {:transcode, ids})}
      err -> err
    end
  end

  defp put_bridge(state, media, how), do: %{state | bridges: Map.put(state.bridges, media, how)}

  # Two chains, one per direction — a transcoder is one-way. Reading the
  # attach direction right is the whole difference between a working call and a
  # silent one, and both RPCs put the SINK first and the SOURCE second, exactly
  # like EndpointAttachToEndpoint:
  #
  #   EndpointAttachTo<Kind>Transcoder(S, EP, TR)  →  EP  ← TR
  #   <Kind>TranscoderAttachToEndpoint(S, TR, EP)  →  TR  ← EP
  #
  # so `la ← tr_a ← lb` is what feeds la with lb's media, re-encoded. The codec
  # set on tr_a is therefore LA's: the transcoder produces what the leg it feeds
  # asked for. That is what makes `:force` mean something — each side is served
  # its own codec whatever the other settled on.
  defp transcode_pair(state, la, lb, media, {code_a, code_b}) do
    with {:ok, tr_a} <- build_chain(state, la, lb, media, code_a),
         {:ok, tr_b} <- build_chain(state, lb, la, media, code_b) do
      {:ok, [tr_a, tr_b]}
    else
      {:error, reason} -> {:error, {:transcode_failed, media, reason}}
    end
  end

  # One direction: `sink ← transcoder ← source`, encoding for `sink`.
  defp build_chain(state, sink, source, media, code) do
    kind = transcoder_kind(media)
    tag = "#{media} transcoder #{sink.leg}"

    with {:ok, tr} <- create(state, "#{kind}TranscoderCreate", [state.sess_id, tag]),
         {:ok, _} <-
           rpc(state, "EndpointAttachTo#{kind}Transcoder", [
             state.sess_id,
             sink.endpoint_id,
             tr
           ]),
         {:ok, _} <-
           rpc(state, "#{kind}TranscoderAttachToEndpoint", [
             state.sess_id,
             tr,
             source.endpoint_id
           ]),
         :ok <- set_transcoder_codec(state, sink, media, tr, code) do
      {:ok, tr}
    else
      {:error, _} = err -> err
    end
  end

  # `:ok`, or the caller's answer to hand back when bridging changed what it
  # should say. Only a leg that ANSWERED an offer has one to give, which is why
  # the outbound-first call shape returns a plain `:ok`.
  # Both legs, not just the first: a re-offer can arrive on EITHER leg, and the
  # answer owed to the leg that sent it is decided here for the same reason the
  # caller's is — it is the first moment both sides are known (principle 4). The
  # answer held since the re-offer arrived was built against what the far end
  # carried BEFORE it answered; this one is built against what it carries now.
  #
  # `inbound_answer` is kept alongside `answers` because it is what the initial
  # INVITE's caller reads, and it is a contract other adapters implement.
  defp bridge_reply(la, lb, medias, policy) do
    answers =
      for leg <- [la, lb],
          other = if(leg.leg == la.leg, do: lb, else: la),
          shaping = leg_shaping(leg, other, medias, policy),
          shaping != %{},
          sdp = rebuilt_answer(leg, shaping),
          is_binary(sdp),
          into: %{},
          do: {leg.leg, sdp}

    # Nothing to say differently: the first pass's answer still stands, and saying
    # so beats handing back a byte-identical rebuild.
    case answers do
      empty when empty == %{} ->
        :ok

      answers ->
        reply = %{answers: answers}

        case Map.fetch(answers, la.leg) do
          {:ok, sdp} -> {:ok, Map.put(reply, :inbound_answer, sdp)}
          :error -> {:ok, reply}
        end
    end
  end

  defp leg_shaping(leg, other, medias, policy) do
    for {media, how, _sel} <- medias,
        media != :text,
        shape = shape_for(how, Map.get(policy, media, :avoid)),
        shape != nil,
        codes = codec_intersection(leg, other, media),
        shape == :decline or codes != [],
        into: %{},
        do: {media, {shape, codes}}
  end

  # What the caller may be told, per media, once both legs are known.
  #
  # A RELAYED media may announce ONLY what both legs carry: anything else is a
  # codec the relay could not honour if the caller picked it.
  #
  # A TRANSCODED one may announce everything the caller offered — the transcoder
  # converts whatever arrives — so nothing is removed. Under `:avoid` the codecs
  # both legs carry are floated to the FRONT, which is how "avoid" is expressed in
  # SDP rather than in wiring: the caller's natural pick is then the one that needs
  # no conversion, and the transcoder spends the call bridging. `:force` states no
  # such preference — each leg is meant to keep the head of its own list — so its
  # answer is left exactly as the offer ordered it.
  defp shape_for(:decline, _mode), do: :decline
  defp shape_for(_wiring, mode), do: shape_for_mode(mode)

  # The same reading, taken from the policy alone — what an answer may say before
  # any wiring decision has been made, which is the case of a re-offer answered
  # while the far end has yet to reply. `:attach` only ever arises under
  # `:forbid`, so the two agree by construction.
  defp shape_for_mode(:forbid), do: :only
  defp shape_for_mode(:avoid), do: :prefer
  defp shape_for_mode(_force), do: nil

  # The shaping to build one leg's answer with, from what the other leg carries
  # RIGHT NOW — the cross-leg knowledge available at answer time, as opposed to
  # `bridge_reply/4`'s, which is the same thing once both legs have answered.
  #
  # Text is exempt (principle 7: never converted, never restricted), and a media
  # whose intersection is empty is left alone: `:only` would empty the answer and
  # `:prefer` would have nothing to float. Under `:avoid` that is exactly the
  # "no common codec" case the transcoder serves; under `:forbid` it is the
  # bridge's refusal to make, not the answer's.
  defp answer_shaping(leg, cross, medias) do
    for media <- medias,
        media != :text,
        shape = shape_for_mode(Map.get(cross.policy, media, :avoid)),
        shape != nil,
        codes = intersect_codes(leg, cross, media),
        codes != [],
        into: %{},
        do: {media, {shape, codes}}
  end

  defp intersect_codes(leg, cross, media) do
    carried = Map.get(cross.carried, media, [])
    Enum.filter(Map.get(leg.peer_codecs, media, []), &(&1 in carried))
  end

  # In leg A's order: it is A's answer we are restricting, and A's preference the
  # selection rule already defers to.
  defp codec_intersection(la, lb, media) do
    lp = Map.get(lb.peer_codecs, media, [])
    Enum.filter(Map.get(la.peer_codecs, media, []), &(&1 in lp))
  end

  # The caller's answer, rebuilt now that the other leg has answered and the
  # selection is known (mediagw_b2bua_jsr309.md §5: "the answer sent on leg A is a
  # function of the answer received on leg B"). `nil` when there is nothing to
  # rebuild — a leg we offered on, or one whose first pass never ran.
  #
  # `shape_for/2` says what each media may announce; both shapes work by codec
  # CODE, and the telephone-event payload types are never touched — DTMF is not a
  # codec choice and rides alongside whichever one wins.
  #
  # Whatever the shape, nothing is ever ADDED: an answer may only carry payload
  # types the offer declared (RFC 3264 §6.1), because a payload-type number means
  # nothing outside the SDP that declared it. The callee's codecs that the caller
  # never offered are therefore unannounceable here, however well the transcoder
  # could serve them; only the mirror set exists — the caller's codecs the callee
  # lacks — and that is exactly what a transcoder is for.
  defp rebuilt_answer(leg, shaping) when is_map(shaping) do
    case leg.offer_descs do
      nil ->
        nil

      descs ->
        negs =
          leg.negs
          # a declined media leaves `negs` entirely: `answer_or_reject/3` then
          # emits the RFC 3264 §6 port-0 rejection for it, which is how the
          # caller learns there is no video after all
          |> Enum.reject(fn {media, _} ->
            match?({:ok, {:decline, _}}, Map.fetch(shaping, media))
          end)
          |> Map.new(fn {media, neg} -> {media, restrict_neg(neg, shaping, media)} end)

        Sdp.build(%{
          ip: leg.local_ip,
          ice_lite: match?({:dtls, _, _}, leg.local_crypto),
          medias:
            descs
            |> Enum.reject(&omit_from_answer?(&1, negs))
            |> Enum.map(&prefer_first(&1, negs, shaping))
            |> Enum.map(&scenario_prefer(&1, negs, leg))
            |> Enum.map(&answer_or_reject(leg, negs, &1))
        })
    end
  end

  # `:prefer` is expressed by reordering the OFFER's own format list, which is
  # where `answer_codecs/2` reads the answer's order from. The codecs both legs
  # carry come first, each group keeping the caller's relative order among itself:
  # a permutation, never an addition or a removal.
  defp prefer_first(desc, negs, shaping) do
    with {:ok, {:prefer, codes}} <- Map.fetch(shaping, Map.get(desc, :type)),
         neg when is_map(neg) <- Map.get(negs, desc.type),
         fmt when is_list(fmt) <- Map.get(desc, :raw_fmt) do
      {carried, rest} =
        Enum.split_with(fmt, fn pt -> Map.get(neg.rtp_map, to_string(pt)) in codes end)

      %{desc | raw_fmt: carried ++ rest}
    else
      _ -> desc
    end
  end

  # The scenario's own ranking (`prefer_codecs:`), applied AFTER the cross-leg
  # shaping: an explicit instruction from the script outranks the policy's soft
  # float, while payload types the scenario does not mention keep whatever order
  # the shaping (or the offer) left them in — `Enum.sort_by/2` is stable. Same
  # contract as `prefer_first/3` otherwise: a permutation of the OFFER's own
  # format list, never an addition or a removal — but ranked by the scenario's
  # list rather than keeping the offer's relative order, because a preference
  # list IS a ranking and its order is the point.
  defp scenario_prefer(desc, negs, leg) do
    with codes when codes != [] <- Map.get(leg.prefer, Map.get(desc, :type), []),
         neg when is_map(neg) <- Map.get(negs, desc.type),
         fmt when is_list(fmt) <- Map.get(desc, :raw_fmt) do
      rank = fn pt ->
        Enum.find_index(codes, &(&1 == Map.get(neg.rtp_map, to_string(pt)))) || length(codes)
      end

      %{desc | raw_fmt: Enum.sort_by(fmt, rank)}
    else
      _ -> desc
    end
  end

  defp restrict_neg(neg, shaping, media) do
    case Map.fetch(shaping, media) do
      {:ok, {:only, codes}} ->
        keep = fn pt ->
          code = Map.get(neg.rtp_map, pt)
          code == @dtmf_code or code in codes
        end

        case Map.get(neg, :accepted) do
          accepted when is_map(accepted) ->
            %{neg | rtp_map: Map.filter(neg.rtp_map, fn {pt, _} -> keep.(pt) end)}
            |> Map.put(:accepted, Map.filter(accepted, fn {pt, _} -> keep.(pt) end))

          _ ->
            %{neg | rtp_map: Map.filter(neg.rtp_map, fn {pt, _} -> keep.(pt) end)}
        end

      # `:prefer` reorders, it does not restrict; nothing shaped, nothing to do
      _ ->
        neg
    end
  end

  defp transcoder_kind(:audio), do: "Audio"
  defp transcoder_kind(:video), do: "Video"

  # The codec the transcoder must PRODUCE: the one SELECTED for its sink (§5), not
  # merely the head of that leg's list. Under `:avoid` the selection is the codec
  # both legs carry, which may sit anywhere in either list — encoding the head
  # instead would produce a codec the far end did not settle on.
  #
  # Video carries a size, a frame rate, a bitrate and an intra period; audio
  # carries none of that. The codec parameters (an H.264 profile-level-id, say)
  # are NOT forwarded yet — the props map is empty, so the server picks its own
  # default. Worth knowing before trusting this with a picky H.264 endpoint.
  defp set_transcoder_codec(state, sink, :video, tr, code) do
    size = Map.fetch!(@video_sizes, Keyword.get(sink.opts, :video_size, @default_video_size))
    fps = Keyword.get(sink.opts, :video_fps, @default_video_fps)
    intra = Keyword.get(sink.opts, :video_intra_period, @default_video_intra_period)

    args = [
      state.sess_id,
      tr,
      code,
      size,
      fps,
      bandwidth_kbps(sink, :video),
      intra,
      %{}
    ]

    case rpc(state, "VideoTranscoderSetCodec", args) do
      {:ok, _} -> :ok
      err -> err
    end
  end

  defp set_transcoder_codec(state, _sink, :audio, tr, code) do
    args = [state.sess_id, tr, code, %{}]

    case rpc(state, "AudioTranscoderSetCodec", args) do
      {:ok, _} -> :ok
      err -> err
    end
  end

  # Both directions, plus the sequence-number rule the Java gateway applies when
  # it relays rather than transcodes: without `useOriSeqNum` the server restamps
  # the stream and the far end sees a discontinuity on every re-bridge.
  defp attach_pair(state, la, lb, media) do
    m = @media_int[media]
    props = %{"useOriSeqNum" => "1"}

    with {:ok, _} <-
           rpc(state, "EndpointAttachToEndpoint", [
             state.sess_id,
             la.endpoint_id,
             lb.endpoint_id,
             m
           ]),
         {:ok, _} <-
           rpc(state, "EndpointAttachToEndpoint", [
             state.sess_id,
             lb.endpoint_id,
             la.endpoint_id,
             m
           ]),
         {:ok, _} <-
           rpc(state, "EndpointSetRTPProperties", [state.sess_id, la.endpoint_id, m, props]),
         {:ok, _} <-
           rpc(state, "EndpointSetRTPProperties", [state.sess_id, lb.endpoint_id, m, props]) do
      :ok
    else
      {:error, reason} -> {:error, {:attach_failed, media, reason}}
    end
  end

  # ── Per-leg handlers (run through on_leg/3) ─────────────────────────────────

  defp do_get_local_offer(state, cross) do
    with {:ok, state} <- setup_local_security(state),
         {:ok, state} <- start_receiving_all(state, cross) do
      offer =
        Sdp.build(%{
          ip: state.local_ip,
          medias: Enum.map(state.medias, &offer_media_spec(state, &1, cross))
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

  defp do_set_remote_offer(state, sdp, cross) do
    with {:ok, descs} <- Sdp.parse(sdp),
         # G9: keep every offered m= section; the ones we can answer with real
         # media are the supported RTP sections of a configured media type. The
         # rest (unknown type, non-RTP transport, disabled media) are echoed as
         # port-0 rejections so the answer keeps one m= per offer m= (RFC 3264).
         # A supported section offered at port 0 is the peer WITHDRAWING that
         # media (§5.1): no receive plane is opened for it, it is echoed port-0
         # like the rest, and the leg records the decline so `bridge/3`
         # propagates it to the other leg instead of keeping a dead bridge.
         {withdrawn, answerable} =
           descs
           |> Enum.filter(&answerable?(&1, state.medias))
           |> Enum.split_with(&(&1.port == 0)),
         state = Enum.reduce(withdrawn, state, &note_declined(&2, &1.type)),
         state = Enum.reduce(answerable, state, &clear_declined(&2, &1.type)),
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
         {:ok, state, negotiated} <- apply_offered_medias(state, answerable, negotiated) do
      # :ice_connected deferred to the first validated RTP packet (type 7);
      # see the set_remote_answer path and handle_server_event below. Every
      # StartSending has been issued at this point, so R is known (§4).
      state =
        state
        |> note_receiving_medias(Enum.filter(answerable, &Map.has_key?(negotiated, &1.type)))

      state = %{state | status: :active, offer_descs: descs, negs: negotiated}

      # The answer is shaped by what the OTHER leg carries, whenever that is
      # already known — which it is on every offer but the very first one of a
      # call. An empty shaping rebuilds byte-for-byte what this used to build
      # directly, so there is one answer builder rather than two that must be
      # kept in step (`rebuilt_answer/2`).
      #
      # A re-offer is the case this exists for: the far end is already
      # negotiated, so `:avoid` can float the codecs both legs carry to the front
      # of the answer straight away and the peer's next packet is one we can
      # relay. What it cannot know here is an answer the far end has not sent
      # yet — a relayed re-offer is answered a second time from `bridge/3`, once
      # it has (principle 4).
      answer = rebuilt_answer(state, answer_shaping(state, cross, Map.keys(negotiated)))

      {:reply, {:ok, answer}, state}
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
  # :ice_connected stays one-shot — docs/design/DESIGN-FRAMEWORK.md#66-media-connectivity-when-may-a-scenario-send.
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

  # The derivation rule of docs/design/DESIGN-FRAMEWORK.md#66-media-connectivity-when-may-a-scenario-send, on the media
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
  #
  # "The peer transmits on it" is `peer_sends?/1` and nothing else — the SAME
  # predicate the watchdog is armed on, which is what `maybe_notify_media_lost/2`
  # relies on when it declares a leg dead the moment R is covered by `timed_out`.
  # This used to read the direction here and the direction *plus* `c=0.0.0.0`
  # there: a peer holding the legacy way (RFC 3264 §8.4) then sat in R while
  # nothing watched it, so `:media_lost` could never be reached again — the leg
  # stayed "alive" for the rest of the call however silent it went.
  defp receiving_medias(descs) do
    for %{transport: t} = d <- descs, t != :ws, peer_sends?(d), into: MapSet.new(), do: d.type
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

    %{state | recv_medias: r} |> replay_connectivity()
  end

  # Media can arrive BEFORE we know which media to expect.
  #
  # The receive plane opens early — `EndpointStartReceiving` is what allocates
  # the port we then advertise — so the far end can be sending to us well before
  # its SDP reaches us. As a UAC that is the ordinary case, not a corner one: we
  # offer, the callee starts sending, and its answer arrives afterwards. Early
  # media makes the gap wider still.
  #
  # `maybe_notify_ice_connected/3` needs R, and R is only learned here. Each raw
  # `{:media_connected, media}` was therefore evaluated against an empty R,
  # decided "not ready", and thrown away — and since the server re-arms that
  # event only on the next `StartReceiving`, `:ice_connected` never came at all.
  # A UAC scenario waiting on it waited for ever; against a real server that is
  # exactly what happened, on every offering leg.
  #
  # `connected` has been accumulating those medias all along, so the fix is to
  # re-run the derivation over them the moment R becomes known. Rule 2 still
  # holds: with video expected, an audio packet that arrived early does not
  # release the milestone — we go on waiting for video's own event.
  defp replay_connectivity(%{ice_notified: true} = state), do: state

  defp replay_connectivity(state) do
    Enum.reduce(state.connected, state, fn media, acc ->
      maybe_notify_ice_connected(acc, media, handle_of(acc.leg))
    end)
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

  # UAC: local security material derives from conn_opts only — `:if_offered` is
  # not a decision here, it reads an offer, and this is the side that writes one.
  #
  # A leg that already has its DTLS+ICE material keeps it: this runs again on
  # every re-offer, and minting fresh ICE credentials mid-call is an ICE restart
  # — connectivity checks re-run and the media stalls while they do — asked for
  # by nothing but the fact that we are speaking again.
  defp setup_local_security(state) do
    cond do
      not is_nil(state.local_ice) -> {:ok, state}
      Keyword.get(state.opts, :webrtc_support, :no) == :yes -> setup_dtls_ice(state)
      true -> {:ok, state}
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

  defp start_receiving_all(state, cross) do
    Enum.reduce_while(state.medias, {:ok, state}, fn media, {:ok, st} ->
      rtp_map = Sdp.local_rtp_map(media, offer_codecs(st, media, cross), dtmf?(st, media))

      # No peer SDP yet on this leg: its side of the network is all that speaks.
      with {:ok, st, profile} <- leg_profile(st, nil),
           {:ok, [port | rest]} <-
             rpc(
               st,
               "EndpointStartReceiving",
               start_receiving_args(st, @media_int[media], rtp_map, nil, profile)
             ),
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
           # StartReceiving FIRST: it is the call that carries the addressing
           # profile, and the server applies it there. Asking for the candidates
           # before it would publish a URL bearing the DEFAULT profile's address
           # (§6.7 bis, "poser le profil avant de publier le port").
           {:ok, state, profile} <- leg_profile(state, nil),
           {:ok, [port | _rest]} <-
             rpc(state, "EndpointStartReceiving",
               start_receiving_args(state, m, rtp_map, nil, profile)),
           {:ok, candidates} when candidates != [] <-
             rpc(state, "GetMediaCandidates", [
               state.sess_id,
               state.endpoint_id,
               @proto_ws,
               m
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

        with {:ok, state, profile} <- leg_profile(state, desc),
             {:ok, [port | rest]} <- start_receiving_offered(state, m, desc, rtp_map, profile),
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
              |> Map.put(:fmt_order, Sdp.fmt_order(desc))
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
  #
  # That retry is for the offer struct ALONE. A leg carrying an addressing profile
  # never falls back (§6.7 bis): the older form would place its media on the
  # server's default interface, and answer 200 with an address the peer may have
  # no route to, with nothing to say so. A profile is only ever asked of a server
  # that answered GetNetworkProfiles, so the case is unreachable rather than
  # merely refused — and it stays written down.
  defp start_receiving_offered(state, m, desc, rtp_map, profile) do
    offer_fmtp = Map.take(Map.get(desc, :fmtp_raw, %{}), Map.keys(rtp_map))
    args = start_receiving_args(state, m, rtp_map, offer_fmtp, profile)

    cond do
      not is_nil(profile) or offer_fmtp == %{} ->
        rpc(state, "EndpointStartReceiving", args)

      true ->
        case rpc(state, "EndpointStartReceiving", args) do
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

            rpc(state, "EndpointStartReceiving", [state.sess_id, state.endpoint_id, m, rtp_map])
        end
    end
  end

  # The addressing profile this leg asks the media server for (§6.7 bis), decided
  # ONCE — on its first StartReceiving — and then repeated verbatim: the server
  # fixes it per leg, because in symmetric RTP the socket is the same in both
  # directions, and it refuses a second, different one rather than rebind a media
  # under a port it has already published.
  #
  # **The node's configured family decides nothing.** It describes every interface
  # at once, and on a B2BUA bridging two of them it is right for one leg and wrong
  # for the other — a session carrying two different profiles is the objective of
  # docs/design/multi-interface.md, not an edge case. Three parties decide, each
  # asked only what it alone knows:
  #
  #  * **the peer's offer**, when there is one, says which families it can receive
  #    media on — the permission. Under ICE the `c=` holds only the default
  #    candidate the peer elected, often a private address, and the `a=candidate`
  #    lines name the rest; `Sdp.peer_families/1` reads both;
  #  * **the address of ours this peer reached** (`sip_profile`) says which of our
  #    interfaces it demonstrably has a route to — the preference. It only ever
  #    REORDERS what the offer allows, since announcing a family the peer never
  #    offered would be media sent nowhere. On the leg we OFFER first there is no
  #    peer SDP yet, and it is the only thing that speaks;
  #  * **the media server** says which profiles it carries (§6.7 ter) — the
  #    availability.
  #
  # Nothing outside that intersection is served, and an empty one FAILS the leg: a
  # fallback would place the media on the wrong interface and answer 200 with an
  # address the peer cannot reach, with nothing to say so until the silence.
  #
  # Three cases ask for no profile at all, each leaving the server on its own
  # default — exactly what a controller that never heard of profiles obtains: a
  # server that does not carry the notion, an offer naming no address of either
  # family, and a leg on which nothing states a side.
  defp leg_profile(%{address_profile: profile} = leg, _desc) when is_binary(profile),
    do: {:ok, leg, profile}

  defp leg_profile(%{network_profiles: profiles} = leg, _desc) when not is_map(profiles),
    do: {:ok, leg, nil}

  defp leg_profile(leg, desc) do
    case profile_candidates(leg, desc) do
      [] ->
        {:ok, leg, nil}

      candidates ->
        case Enum.find(candidates, &get_in(leg.network_profiles, [&1, :available])) do
          nil -> {:error, {:profile_unavailable, Enum.join(candidates, ", ")}}
          name -> {:ok, %{leg | address_profile: name}, name}
        end
    end
  end

  # No peer SDP — the leg we offer on — so our own side is all there is to go on.
  defp profile_candidates(%{sip_profile: local}, nil), do: List.wrap(local)

  defp profile_candidates(%{sip_profile: local} = leg, desc) do
    case Enum.map(Sdp.peer_families(desc), &profile_name(&1, leg_side(leg))) do
      [] -> []
      offered -> if local in offered, do: Enum.uniq([local | offered]), else: offered
    end
  end

  # The side is the LOCAL address's — ours, the one this peer reached — because an
  # offer says which families a peer can receive media on and nothing about which
  # side of our network it sits on. The name itself is `MediaServer`'s to spell.
  defp profile_name(family, side), do: MediaServer.profile_name(family, side)

  # Both halves come from the local address of this leg, and neither is
  # configured: the address states its family, and `SIP.NetUtils.net_side/1`
  # states its side from the `internal` listeners' networks. A leg we placed
  # ourselves has no local address, so it states no side to prefer.
  defp sip_profile(opts) do
    local_ip = Keyword.get(opts, :local_ip)

    case SIP.NetUtils.address_family(local_ip) do
      nil -> nil
      family -> profile_name(family, SIP.NetUtils.net_side(local_ip))
    end
  end

  # The side every candidate of this leg carries. `sip_profile` already holds the
  # pair, so read it back rather than deriving the side a second time.
  defp leg_side(%{sip_profile: local}) when is_binary(local) do
    if String.starts_with?(local, "internal"), do: :internal, else: :public
  end

  defp leg_side(_leg), do: :public

  # `profile` is positional and SIXTH (xmlrpc_jsr309_api.md §6.7 bis), so `offer`
  # has to be sent to reach it — an empty struct when the offer states no fmtp.
  # With no profile to ask for, the call is byte-for-byte the one a controller
  # that never heard of profiles makes.
  # `profile` is positional and SEVENTH on EndpointStartSending, and it must be the
  # one StartReceiving already fixed for this leg: in symmetric RTP the socket is
  # the same in both directions, and the server refuses a second, different one
  # (§6.7 bis). Repeating it is a no-op, which is why it is read rather than
  # re-derived.
  defp start_sending_args(leg, m, ip, port, send_map) do
    base = [leg.sess_id, leg.endpoint_id, m, ip, port, send_map]

    case leg.address_profile do
      nil -> base
      profile -> base ++ [profile]
    end
  end

  defp start_receiving_args(leg, m, rtp_map, offer_fmtp, nil) do
    base = [leg.sess_id, leg.endpoint_id, m, rtp_map]
    if offer_fmtp in [nil, %{}], do: base, else: base ++ [%{"fmtp" => offer_fmtp}]
  end

  defp start_receiving_args(leg, m, rtp_map, offer_fmtp, profile) do
    [leg.sess_id, leg.endpoint_id, m, rtp_map, %{"fmtp" => offer_fmtp || %{}}, profile]
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
      |> Enum.sort_by(&Sdp.pt_rank(&1, Sdp.fmt_order(desc)))
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

  # RFC 3264 §6: port 0 is the peer DECLINING this media, whatever codecs the
  # section still lists. Treating it as live is how a callee's dead audio got
  # StartSending aimed at port 0, a transcoder bridging into the void, and a
  # caller answered `sendrecv` on a channel that could never carry anything
  # (traffic of 2026-08-14). Nothing is started; the leg records the verdict
  # for `bridgeable_medias/3` to propagate to the other leg's answer.
  defp apply_answered_medias(state, descs) do
    Enum.reduce_while(descs, {:ok, state, %{}}, fn
      %{port: 0} = desc, {:ok, st, acc} ->
        Logger.info(
          module: __MODULE__,
          cnx_tag: st.sess_tag,
          message: "#{desc.type} declined by the peer (port 0) on leg #{st.leg}"
        )

        {:cont, {:ok, note_declined(st, desc.type), acc}}

      desc, {:ok, st, acc} ->
        case Sdp.negotiate(desc, codecs(st, desc.type), dtmf?(st, desc.type)) do
          {:error, :no_common_codec} ->
            {:cont, {:ok, st, acc}}

          {:ok, neg} ->
            st = clear_declined(st, desc.type)

            # never send a codec the server just filtered on receive (no-op when
            # the server did not delegate, i.e. accepted[media] is nil), and never
            # leave two payload types of one video codec for the server to choose
            # between (see one_pt_per_codec/3)
            send_map =
              Sdp.restrict_send_map(
                neg.rtp_map,
                Map.get(st.proposed_recv, desc.type, %{}),
                Map.get(st.accepted, desc.type)
              )
              |> one_pt_per_codec(desc.type, neg)

            case apply_remote_media(st, desc, Map.put(neg, :send_map, send_map)) do
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
      case apply_remote_media(st, desc, Map.fetch!(acc, desc.type)) do
        {:ok, st, neg} -> {:cont, {:ok, st, Map.put(acc, desc.type, neg)}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  # A text-over-WebSocket leg has no remote side to configure: no RTP
  # destination to send to (the peer connects to us), no crypto (the WebSocket's
  # own TLS carries it) and nothing for the RTP watchdog to watch — T.140 is
  # legitimately silent between keystrokes anyway.
  defp apply_remote_media(state, %{transport: :ws}, neg),
    do: {:ok, state, neg}

  # Applies the §9 remote-side steps for one media: transport properties, the
  # peer's security material, StartSending, then the watchdog — recorded last,
  # once the answer has been processed, and pushed to the server only if the call
  # is already up (`note_watchdog/2` + `apply_watchdog/2`).
  defp apply_remote_media(state, desc, neg) do
    m = @media_int[desc.type]

    with :ok <- set_rtp_properties(state, m, desc),
         :ok <- set_remote_crypto(state, m, desc),
         {:ok, _} <-
           rpc(
             state,
             "EndpointStartSending",
             start_sending_args(state, m, desc.ip, desc.port, neg.send_map)
           ),
         state = note_watchdog(state, desc),
         :ok <- apply_watchdog(state, desc.type) do
      {:ok, note_negotiated(state, desc.type, neg) |> note_h264_mode(desc), neg}
    end
  end

  # A declined media carries nothing: its stale `negotiated`/`peer_codecs`
  # entries go with it, so neither the cross-leg selection nor the answer
  # shaping can keep serving codecs of a channel the peer has closed.
  defp note_declined(state, media) do
    %{
      state
      | declined: MapSet.put(state.declined, media),
        negotiated: Map.delete(state.negotiated, media),
        peer_codecs: Map.delete(state.peer_codecs, media)
    }
  end

  defp clear_declined(state, media),
    do: %{state | declined: MapSet.delete(state.declined, media)}

  defp note_negotiated(state, media, neg) do
    case peer_codecs(neg) do
      [] ->
        state

      [code | _] = codes ->
        %{
          state
          | negotiated: Map.put(state.negotiated, media, code),
            peer_codecs: Map.put(state.peer_codecs, media, codes)
        }
    end
  end

  # Every codec this peer can carry on this media, as Medooze codes, ordered by
  # the peer's OWN `m=` format list — its stated preference, which is the only
  # order that means anything here (a payload-type map has none, and the PT
  # numbers are each peer's private numbering).
  #
  # Restricted to what the media server accepted when it gave a verdict, because
  # a codec the server filtered on receive is not one this leg can carry however
  # much the peer likes it. No verdict (an older server, or one that answers
  # StartReceiving with the port alone) leaves the peer's list as it stands.
  defp peer_codecs(neg) do
    case Map.get(neg, :accepted) do
      accepted when is_map(accepted) -> Map.take(neg.rtp_map, Map.keys(accepted))
      _ -> Map.get(neg, :send_map, Map.get(neg, :rtp_map, %{}))
    end
    |> Enum.reject(fn {_pt, code} -> code == @dtmf_code end)
    |> Enum.sort_by(&Sdp.pt_rank(&1, Map.get(neg, :fmt_order)))
    |> Enum.map(fn {_pt, code} -> code end)
    |> Enum.uniq()
  end

  # What `EndpointStartSending` may use, in the offerer's numbering.
  #
  # **Video: one payload type per accepted CODEC**, the peer's preferred payload
  # type for each. Two rules meet here, and only one of them was being honoured.
  #
  # One PT per codec is the rule that matters to the encoder. Several H.264 payload
  # types differ by profile, and leaving two of them in the map lets the server
  # choose which one it stamps the stream with — `RTPSession::SetSendingCodec`
  # takes the FIRST entry carrying the code. Deduplicating settles it, and it is
  # the only thing that does: filtering on `accepted` does not, since a server can
  # perfectly accept two H.264 payload types.
  #
  # But this used to keep the primary ALONE, which is a different rule and a wrong
  # one: it decides at ANSWER time which single codec the leg may ever send, when
  # that is a decision of the BRIDGE (§5, `select_codecs/4` — the codec both legs
  # carry, which may sit anywhere in either list). Every other selection then
  # became unstampable, and the server has no way to say so in the SDP: it stamped
  # the stream with the primary's payload type and sent it anyway. Traffic of
  # 2026-08-12: Linphone offers AV1(110) H264(99) VP8(107), the server accepts all
  # three, the map is pinned to 110; the callee answers H.264 only; `:avoid` picks
  # H.264 for both legs; the caller receives H.264 packets labelled AV1 and decodes
  # noise. That is the ordinary AV1-caller-to-H.264-callee case, not an exotic one.
  #
  # The invariant this restores, and it is structural rather than sequential: the
  # codecs of a leg's video send map are EXACTLY its `peer_codecs/1` — same source,
  # same filter — so a selection drawn from the intersection of two legs'
  # `peer_codecs` can always be stamped by both. No re-issued `EndpointStartSending`
  # after the bridge, and nothing to keep in step.
  #
  # Audio and text keep the whole accepted set: the extra entries are the
  # telephone-event stream the audio rides alongside, and there is no encoder
  # ambiguity to settle. A nil verdict (legacy server) leaves the map alone.
  defp send_map(:video, %{accepted: accepted, rtp_map: rtp_map} = neg) when is_map(accepted) do
    rtp_map
    |> Map.take(Map.keys(accepted))
    |> one_pt_per_codec(:video, neg)
  end

  defp send_map(_media, %{accepted: accepted, rtp_map: rtp_map}) when is_map(accepted),
    do: Map.take(rtp_map, Map.keys(accepted))

  defp send_map(_media, %{rtp_map: rtp_map}), do: rtp_map

  # One payload type per codec, keeping the peer's preferred one for each — the
  # same reading of preference as `peer_codecs/1` and the answer's rtpmap order
  # (`Sdp.pt_rank/2`), so the three cannot disagree about what "first" means.
  #
  # Video only, and applied on BOTH negotiation paths: an answering leg is a sink
  # too (for the other direction), so an answerer that lists two H.264 payload
  # types would hand the server the same choice we are removing here.
  defp one_pt_per_codec(map, :video, neg) do
    map
    |> Enum.reject(fn {_pt, code} -> code == @dtmf_code end)
    |> Enum.sort_by(&Sdp.pt_rank(&1, Map.get(neg, :fmt_order)))
    |> Enum.uniq_by(fn {_pt, code} -> code end)
    |> Map.new()
  end

  defp one_pt_per_codec(map, _media, _neg), do: map

  # `primary_entry/1` lived here: the caller's first accepted choice, which was
  # what the video send map was restricted to. Nothing needs "the one codec this
  # leg sends" any more, because no such thing exists before the bridge decides —
  # and once it decides, the codec travels as an argument (`set_transcoder_codec/5`)
  # rather than being re-derived. `peer_codecs/1` answers the question that remains,
  # "everything this leg can carry, in the peer's order".

  # ── RTP inactivity watchdog (direction-aware) ───────────────────────────────

  # Whether the PEER will send RTP to us on this media — the only thing a
  # *receive* watchdog can observe. A caller holding with `a=sendonly` keeps
  # sending (music on hold), so it stays armed; what starves our reception is the
  # peer declaring it will not send — `a=recvonly`, `a=inactive` — or blackholing
  # the media (RFC 3264 §8.4, the legacy hold).
  defp peer_sends?(desc) do
    Map.get(desc, :direction, :sendrecv) not in [:recvonly, :inactive] and
      not Sdp.blackholed?(desc)
  end

  # What this media's watchdog must be, from the description just applied: the
  # configured timeout when the peer will send on it, `0` — disarmed — when it
  # will not. Recorded rather than issued: what a negotiation decides is what to
  # watch, and WHEN to watch it is `call_answered/1`'s business.
  #
  # Text never enters the map at all: T.140 is legitimately silent between
  # keystrokes, so watching it would reap a leg the moment its user stops typing.
  defp note_watchdog(state, %{type: :text}), do: state

  defp note_watchdog(state, desc) do
    ms = if peer_sends?(desc), do: rtp_timeout_ms(), else: 0
    %{state | watchdogs: Map.put(state.watchdogs, desc.type, ms)}
  end

  # Push one media's recorded watchdog to the server, if the call is up.
  #
  # Before the call is answered there is nothing to watch: the peer has not been
  # told to start sending (its 200 OK is unsent, or its own answer has not been
  # acknowledged), and the ringing phase that sits in between is silent by
  # definition and lasts as long as the callee takes to pick up. Arming across it
  # reaps every call that rings longer than `rtp_timeout_ms` — see
  # `MediaServer.Behaviour.call_answered/1` for the traffic that proved it.
  #
  # AFTER the call is up, a renegotiation applies immediately: hold and resume
  # travel through exactly this path, and a resumed media left unwatched until
  # some later answer would never be watched again.
  defp apply_watchdog(%{answered: false}, _media), do: :ok

  defp apply_watchdog(state, media) do
    case Map.fetch(state.watchdogs, media) do
      {:ok, ms} -> start_rtp_timeout(state, media, ms)
      :error -> :ok
    end
  end

  defp start_rtp_timeout(state, media, ms) do
    case rpc(state, "EndpointStartRTPTimeout", [
           state.sess_id,
           state.endpoint_id,
           @media_int[media],
           ms
         ]) do
      {:ok, _} -> :ok
      {:error, _} = err -> err
    end
  end

  # The call is up on this leg. Everything the negotiations recorded is pushed to
  # the server here, and this is the first moment any of it is.
  #
  # Best-effort, unlike the negotiation path: the call is already established, so
  # a server that refuses the watchdog must not take a working call down with it.
  # The failure is logged rather than swallowed, so a fleet-wide "nothing is ever
  # armed" cannot pass for working.
  defp do_call_answered(%{answered: true} = state), do: {:reply, :ok, state}

  defp do_call_answered(state) do
    state = %{state | answered: true}

    for {media, ms} <- state.watchdogs do
      case start_rtp_timeout(state, media, ms) do
        :ok ->
          :ok

        {:error, reason} ->
          Logger.warning(
            module: __MODULE__,
            cnx_tag: state.sess_tag,
            message:
              "could not set the #{media} RTP watchdog of leg #{state.leg} to #{ms} ms " <>
                "(#{inspect(reason)}) — a silent leg will only be caught by the " <>
                "scenario's own timeout"
          )
      end
    end

    Logger.debug(
      module: __MODULE__,
      cnx_tag: state.sess_tag,
      message: "call answered on leg #{state.leg}; RTP watchdogs #{inspect(state.watchdogs)}"
    )

    {:reply, :ok, state}
  end

  # rtcp-mux (mirrored from the peer) and the RTCP-feedback switches behind the
  # feedback types the answer advertises (never the old unconditional
  # useNACK+tmmbr pair: announcing `ccm fir` while never asking for RTCP FIR
  # tells the peer it has a capability nothing implements) are merged into a
  # single EndpointSetRTPProperties call. The "secure" hint is intentionally
  # omitted: it is a no-op once DTLS/SDES crypto is configured (server audit,
  # DESIGN-FRAMEWORK.md Q2).
  defp set_rtp_properties(state, m, desc) do
    props =
      %{}
      |> maybe_put(Map.get(desc, :rtcp_mux, false), "rtcp-mux", "1")
      |> Map.merge(rtcp_fb_props(desc))
      |> Map.merge(transport_cc_props(desc))
      |> maybe_put(nat_latch?(state, desc), "natLatch", "1")

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
  # `transport-cc` is dropped here rather than looked up: it is confirmed in the answer
  # but switched on by the extmap property below, whose value is an id and not "1".
  defp rtcp_fb_props(desc) do
    case answered_rtcp_fb(desc) do
      types when is_list(types) ->
        types
        |> Enum.reject(&(&1 == Sdp.transport_cc_fb()))
        |> Map.new(fn type -> {Map.fetch!(@supported_rtcp_fb, type), "1"} end)

      _ ->
        %{}
    end
  end

  # The transport-wide-cc extension, keyed by its URI and valued with the NEGOTIATED
  # id: that is what makes the server write a transport-wide sequence number on every
  # outgoing packet of this leg, pair the incoming fmt 15 reports with its own send
  # history and feed its sender-side estimator. `desc` is the peer's offer when we
  # answer and the peer's answer when we offer, so one reading covers both.
  defp transport_cc_props(desc) do
    case Sdp.transport_cc_extmap(desc) do
      %{id: id} -> %{Sdp.transport_cc_uri() => Integer.to_string(id)}
      nil -> %{}
    end
  end

  # Symmetric-NAT latching: the server re-targets its send address *and* port to
  # wherever the RTP is actually coming from. Asking for it is safe because the
  # decision of whether to act on it is the SERVER's, and it is narrow
  # (`RTPSession::NatCorrectable`): the announced address must be private
  # (RFC1918, CGNAT RFC6598, link-local) — on a public address a divergence is
  # more likely legitimate asymmetric routing than a NAT to correct — and the
  # correction is one-shot per target, the right re-opened by the next
  # `SetRemotePort` (re-INVITE / UPDATE). All we own on this side is the one case
  # the server cannot see: ICE, where the address is settled by candidates and
  # STUN connectivity checks, not by the `c=` line. Latching there would fight
  # the very mechanism that already picked the path.
  #
  # ICE is in play only when BOTH sides do it, which is why the criterion is the
  # same pair that gates `EndpointSetRemoteSTUNCredentials` below. Offering ICE is
  # not practising it: a leg where we advertised candidates and the peer answered
  # without any has no ICE at all — the server drops every inbound check for want
  # of a remote password ("No iceRemotePwd defined yet"), so nothing will ever
  # settle the address. Read off `local_ice` alone, we stood aside for a mechanism
  # that was never running: the call of 2026-08-21, Alice (WebRTC) to Bob
  # (Linphone), where Bob answered `c=IN IP4 172.22.0.5` — a docker interface of
  # his own host — while his RTP arrived from 172.21.104.60. The DTLS handshake
  # completed on both media, which is what made it look like a media problem, and
  # Bob did not receive one RTP packet for the whole call.
  #
  # It is asked for in BOTH directions, and the direction is not a criterion. It
  # used to be — only when we ANSWERED an offer, on the theory that a peer
  # answering OUR offer does so knowing its own NAT, so a mismatch would be a
  # routing fault to surface rather than a mapping to follow. Real traffic said
  # otherwise: a multi-homed or NATed callee writes its private address in an
  # ANSWER exactly as an offerer writes it in an offer. A Linphone handset behind
  # a NAT answered `c=IN IP4 172.22.0.3` while its RTP arrived from
  # 172.21.104.60; we kept sending to the announced address for the whole call,
  # the gateway returned ICMP host-unreachable, and the callee heard nothing —
  # one-way audio on every outgoing leg, and the caller heard fine, which is what
  # made it look like a working call.
  #
  # `nat_latch: true | false` still overrides the inference for a caller that
  # knows its topology; the kelixip MCU adapter carries its own opt-in switch.
  defp nat_latch?(state, desc) do
    case Keyword.get(state.opts, :nat_latch, :auto) do
      :auto -> is_nil(state.local_ice) or is_nil(desc.ice)
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

  defp offer_media_spec(state, media, cross) do
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
      |> add_offer_rtp_profile(state, media)

    case Map.get(state.accepted, media) do
      nil ->
        # legacy: the client-side codec tables synthesize the codec section
        Map.merge(base, %{codecs: offer_codecs(state, media, cross), dtmf: dtmf?(state, media)})

      accepted ->
        # delegated: build the codec section from the server-accepted set,
        # using our payload-type numbering (this is an offer)
        Map.merge(base, server_driven_offer(state, media, accepted, cross))
    end
  end

  # WebRTC offer transport plane (§2.4). rtcp-mux is always offered (G5),
  # candidates are host-only with the receive port (D6), and rtcp-fb is advertised
  # per video PT. No a=ice-lite in offers (D7): we emulate a browser-shaped offer.
  defp add_offer_webrtc(base, state, media) do
    if webrtc?(state) do
      Map.merge(base, %{
        rtcp_mux: true,
        mid: offer_mid(state, media),
        candidates:
          Sdp.host_candidates(state.local_ip, Map.fetch!(state.local_ports, media), true),
        rtcp_fb: media == :video,
        # transport-wide-cc, when configured: the builder pairs it with its
        # `a=rtcp-fb:<pt> transport-cc` lines. The property is posted only if the
        # peer's answer takes it (`transport_cc_props/1`).
        extmaps: List.wrap(Sdp.transport_cc_offer(media))
      })
    else
      base
    end
  end

  # A section's mid does not change once it is negotiated (RFC 8843 §6.3.2, JSEP
  # §5.2.1). On a leg where we ANSWERED, the mid is the peer's — echoed verbatim
  # in that answer — so a re-offer has to name it again rather than the media name
  # we would have invented: libwebrtc associates transceivers BY mid, and a
  # section arriving under a new one is not the section it already has. Our own
  # name is for the offer nobody has answered yet.
  defp offer_mid(state, media) do
    case Enum.find(state.offer_descs || [], &(&1.type == media)) do
      %{mid: mid} when is_binary(mid) -> mid
      _ -> to_string(media)
    end
  end

  # The middle rung of the §7.5 ladder: RTP/AVPF — the feedback profile without
  # encryption, ICE or muxing. It is what an endpoint that refuses WebRTC but
  # does NACK/PLI/TMMBR speaks, and until P5 there was no way to offer it: the
  # offer was binary, DTLS+ICE+SAVPF or plain AVP.
  #
  # WebRTC already implies SAVPF, so this is a no-op there — the two options are
  # a ladder, not a matrix.
  defp add_offer_rtp_profile(base, state, media) do
    if not webrtc?(state) and rtp_profile(state) == :avpf do
      Map.merge(base, %{protocol: "RTP/AVPF", rtcp_fb: media == :video})
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
      # RFC 8285 §5: the extension is confirmed with the offer's OWN id, never
      # renumbered. Empty unless transport-wide-cc is negotiated on this media.
      extmaps: List.wrap(Sdp.transport_cc_extmap(desc)),
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
        |> Map.put(:fmt_order, Sdp.fmt_order(desc))
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
        |> Map.put(:fmt_order, Sdp.fmt_order(desc))
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
    Enum.filter(offered_rtcp_fb(desc), &Map.has_key?(@supported_rtcp_fb, &1))
  end

  # The same list before that filter. `transport-cc` has no entry in
  # @supported_rtcp_fb — its server-side switch comes from the extmap, not from this
  # attribute — so confirming it needs the unfiltered reading.
  defp offered_rtcp_fb(desc) do
    Map.get(desc, :rtcp_fb, %{})
    |> Map.values()
    |> List.flatten()
    |> Enum.uniq()
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
      do: drop_rate_control_fb(requested_rtcp_fb(desc)) ++ answered_transport_cc_fb(desc),
      else: false
  end

  # `transport-cc` is confirmed only when BOTH halves of the mechanism are there: the
  # peer asked for the feedback message, and the extension it reports on is one we
  # negotiate (`Sdp.transport_cc_extmap/1` — video, the switch on, a usable direction).
  # Appended rather than filtered in, because @supported_rtcp_fb maps an attribute to
  # the server switch that implements it and this one has none.
  defp answered_transport_cc_fb(desc) do
    if Sdp.transport_cc_extmap(desc) && Sdp.transport_cc_fb() in offered_rtcp_fb(desc),
      do: [Sdp.transport_cc_fb()],
      else: []
  end

  defp drop_rate_control_fb(types) do
    allowed =
      Application.get_env(:elixip2, MediaServer.Mendooze, [])
      |> Keyword.get(:bitrate_feedback, @default_bitrate_feedback)

    Enum.filter(types, fn type ->
      case Map.fetch(@rate_control_rtcp_fb, type) do
        {:ok, dialect} -> dialect in allowed
        :error -> true
      end
    end)
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
  defp server_driven_offer(state, media, accepted, cross) do
    ordered = Enum.filter(proposed_pts(state, media, cross), &Map.has_key?(accepted, &1))

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
  # order (`offer_codecs/3`'s order, telephone-event last) — the same order the
  # `m=` format list is written in, since it is built from this list.
  defp proposed_pts(state, media, cross) do
    codec_pts =
      Enum.flat_map(offer_codecs(state, media, cross), fn name ->
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
    # Transcoders first: they sit between the endpoints, and deleting the session
    # underneath them is not a reason to leave them to it.
    state = release_transcoders(state)

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

  @doc false
  # `call_timeout_ms` from the MediaServer.Mendooze config block, floored at
  # @min_call_timeout_factor times the XML-RPC timeout. The floor is the
  # invariant, not politeness: a deployment that raised xmlrpc_timeout_ms above
  # this one would turn every slow call into an exit instead of an error, which
  # is precisely the failure mode the two levels exist to avoid.
  def call_timeout do
    cfg = Application.get_env(:elixip2, MediaServer.Mendooze, [])
    configured = Keyword.get(cfg, :call_timeout_ms, @default_call_timeout)
    floor_ms = @min_call_timeout_factor * XmlRpc.timeout_ms()

    max(configured, floor_ms)
  end

  defp create(state, method, params), do: XmlRpc.created_id(rpc(state, method, params))

  defp codecs(state, :audio),
    do: List.wrap(Keyword.get(state.opts, :audio_codec, @default_audio_codecs))

  defp codecs(state, :video),
    do: List.wrap(Keyword.get(state.opts, :video_codec, @default_video_codecs))

  defp codecs(state, :text),
    do: List.wrap(Keyword.get(state.opts, :text_codec, @default_text_codecs))

  defp dtmf?(state, :audio), do: Keyword.get(state.opts, :dtmf, true)
  defp dtmf?(_state, _media), do: false

  # Our menu for this media, SHAPED by what the other leg carries. Same three
  # policies as the answer, in the same words, because an offer and an answer are
  # the two ways of saying the same preference and stating it in one and not the
  # other is what a peer reads as a contradiction:
  #
  #   :force  → the menu as configured. `:force` means each leg keeps the head of
  #             its OWN list, so there is no cross-leg preference to state.
  #   :avoid  → a PERMUTATION: what both legs can carry first, then the rest of
  #             what the other leg carries, then the rest of the menu. Nothing is
  #             removed — the peer keeps the chance to accept a codec we did not
  #             know it had, and the transcoder is still there if it does.
  #   :forbid → a RESTRICTION to what the other leg carries: on a media that may
  #             never be transcoded, offering a codec the far end cannot carry
  #             invites the peer to pick one we could not relay.
  #
  # Why this matters at all: an answerer states its choice by the order of ITS
  # answer, and what it sends is the head of that answer. The order of our offer
  # is the only lever we have on a leg we are the offerer of — and it is the lever
  # that was missing when Bob re-INVITEd with AV1+VP8, was answered AV1-first, and
  # sent AV1 to a leg that had only ever carried VP8 (traffic of 2026-08-13).
  #
  # Three groups, and the order INSIDE each is deliberate. The intersection and
  # the rest of the other leg's list are in the OTHER leg's order — it is the
  # source of the media there, and principle 3 defers to the offerer's preference
  # rather than to a gateway's. Ours only orders what neither leg has stated.
  defp offer_codecs(leg, media, cross) do
    menu = codecs(leg, media)
    mode = Map.get(cross.policy, media, :avoid)

    relayable =
      media
      |> carried_names(Map.get(cross.carried, media, []))
      |> Enum.filter(&(&1 in menu))

    settled = carried_names(media, Map.get(leg.peer_codecs, media, []))

    cond do
      # Nothing known about the other leg (a first INVITE's inbound leg, a
      # single-leg connection, a media the far end declined): no shaping to do,
      # and under `:forbid` nothing to restrict to either — restricting to the
      # empty set would offer no codec at all, which is not a refusal, just a
      # malformed offer.
      relayable == [] or mode == :force ->
        menu

      true ->
        {common, rest} = Enum.split_with(relayable, &(&1 in settled))

        case mode do
          :forbid -> common ++ rest
          _avoid -> common ++ rest ++ (menu -- relayable)
        end
    end
  end

  # Mendooze codec codes → our codec-table names, dropping what the tables do not
  # name (telephone-event above all: never a codec a leg carries).
  defp carried_names(media, codes) do
    codes
    |> Enum.map(&Sdp.codec_name(media, &1))
    |> Enum.reject(&is_nil/1)
  end

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

  # Does this leg CARRY WebRTC — hence rtcp-mux, an a=mid per section and host
  # candidates in what we write on it? Its own resolved transport answers, not the
  # option: `:if_offered` — the value a B2BUA gives its inbound leg — is settled by
  # the offer we answered, and setup_dtls_ice/1 records that decision in
  # `local_ice`, which is also how answer_candidates/2 already reads the question.
  # Both SDP paths set it before any section is built. `nat_latch?/2` asks a
  # narrower one — whether ICE is actually RUNNING — so it weighs the peer's
  # `desc.ice` too.
  #
  # Read off the option instead, an `:if_offered` leg ANSWERED a browser's offer
  # with all three and then RE-OFFERED without any of them. Chrome refuses that
  # SDP outright — rtcpMuxPolicy is "require" and a unified-plan section needs its
  # mid — which is the 488 of 2026-08-21: the callee turned its camera on, the
  # relayed re-offer was refused, and the call died on a leg that was working.
  defp webrtc?(state), do: not is_nil(state.local_ice)

  # Which RTP profile a NON-WebRTC offer is carried in (§7.5). `:avp` — plain
  # RTP — is the default and what every caller got before P5.
  defp rtp_profile(state) do
    case Keyword.get(state.opts, :rtp_profile, :avp) do
      :avpf -> :avpf
      _ -> :avp
    end
  end

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
