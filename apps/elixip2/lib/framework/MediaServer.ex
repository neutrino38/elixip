defmodule MediaServer do
  @moduledoc """
  Types and behaviour for the media server interface.

  Implementations drive a medooze Node.js media server over an IPC channel.
  Use `MediaServer.Mockup` in tests.
  """

  @type server_addr :: {String.t(), pos_integer()}
  @type sdp :: String.t()

  @typedoc """
  Media combination requested for a peer connection (the `:media` conn opt).

  `:tc` / `:total_conversation` / `:audio_video_text` all select audio + video +
  real-time text (T.140) — "Total Conversation" (ITU-T F.703).

  An explicit list of `media()` (e.g. `[:audio, :video, :text]` or `[:audio,
  :text]`) may also be given: it selects exactly those m-lines, in that order.
  Kind atoms are allowed as list elements too and are expanded in place.
  """
  @type media_kind ::
          :audio
          | :video
          | :text
          | :audio_video
          | :audio_video_text
          | :total_conversation
          | :tc
          | [media_kind()]

  @type media :: :audio | :video | :text

  @doc """
  Maps a `media_kind()` option value to the list of individual medias it
  selects. Shared by the adapters so they all accept the same `:media` values.

  Accepts either a kind atom (`:tc`, `:audio_video`, …) or an explicit list of
  medias/kinds. Lists are expanded (a `:tc` element becomes audio+video+text)
  and de-duplicated while preserving order — the order determines the order of
  the offered m-lines. Raises `ArgumentError` on an unknown selection.
  """
  @spec media_list(media_kind()) :: [media()]
  def media_list(:audio), do: [:audio]
  def media_list(:video), do: [:video]
  def media_list(:text), do: [:text]
  def media_list(:audio_video), do: [:audio, :video]

  def media_list(kind) when kind in [:audio_video_text, :total_conversation, :tc],
    do: [:audio, :video, :text]

  def media_list(list) when is_list(list) do
    list
    |> Enum.flat_map(&media_list/1)
    |> Enum.uniq()
  end

  def media_list(other) do
    raise ArgumentError,
          "unknown media selection: #{inspect(other)} " <>
            "(expected :audio | :video | :text | :audio_video | :tc, or a list of these)"
  end

  @doc """
  The media server's addressing profile for a family and a side of the network:
  `"publicv4"`, `"publicv6"`, `"internalv4"`, `"internalv6"`.

  The server carries up to four addresses and names them exactly this way
  (`xmlrpc_jsr309_api.md` §6.7 bis): a family crossed with a side. Written **once**
  here rather than in each adapter and again in whatever selects a server — three
  copies of a four-entry table is how the codec list went wrong.

  A side of `nil` reads as public: it is the side of a node that has not been told
  it has two.
  """
  @spec profile_name(:ipv4 | :ipv6, :internal | :public | nil) :: String.t()
  def profile_name(:ipv6, :internal), do: "internalv6"
  def profile_name(:ipv4, :internal), do: "internalv4"
  def profile_name(:ipv6, _side), do: "publicv6"
  def profile_name(:ipv4, _side), do: "publicv4"

  @doc """
  The addressing profile a leg we ANSWER asks for, from its connection options,
  or `nil` when they say nothing about where it is.

  The two halves come from two different places, and neither is configured:

    * the **family** from `local_ip`, the address of ours this peer reached. That
      is a routing truth — of the addresses this node holds, it is one the peer
      demonstrably has a route to.
    * the **side** from `peer_ip`, the address the peer sent FROM, classified
      against this node's internal networks. `local_ip` cannot answer it: behind a
      1:1 NAT one interface has two faces, the NAT rewrites the destination, and
      an inside peer and an outside peer arrive on the same private address. Our
      own address then discriminates nothing.

  Without `peer_ip` — a leg we placed, a transport that reported no peer — the
  side falls back to `local_ip`'s, which is what it was before a peer address was
  carried at all.

  Written once here because three callers need it: the two adapters and whatever
  constrains a media server pool.
  """
  @spec leg_profile_name(keyword()) :: String.t() | nil
  def leg_profile_name(opts) do
    local_ip = Keyword.get(opts, :local_ip)

    case address_family_of(local_ip) do
      nil ->
        nil

      family ->
        side_source = Keyword.get(opts, :peer_ip) || local_ip
        profile_name(family, SIP.NetUtils.net_side(side_source))
    end
  end

  defp address_family_of(ip), do: SIP.NetUtils.address_family(ip)

  @typedoc """
  Asynchronous events delivered to the `event_sink` pid as `{:ms_event, ref, event}`.

  Media connectivity comes in two events (`docs/design/DESIGN-FRAMEWORK.md#66-media-connectivity-when-may-a-scenario-send`).

  `{:media_connected, media}` is the raw per-media fact: the server validated the
  first incoming packet of that media. Under SRTP/DTLS a successful decrypt
  proves the handshake completed; in the clear it is simply the first received
  packet. The server re-arms it on every `StartReceiving`, so it repeats on
  renegotiation.

  `:ice_connected` is the derived milestone a scenario waits on before sending
  into the leg, emitted **at most once** per connection. It is not "some media
  flows" but "the media that matters flows": when the peer transmits video, only
  video releases it — starting playback on the audio latch while the video leg is
  still unlatched sends the opening keyframe to an address nothing listens on.
  With no video expected, the first media the peer transmits on releases it.

  `:media_send_only` says no `:ice_connected` is coming: the peer transmits on no
  negotiated media, so no connectivity event can ever arrive. It is emitted once
  the send plane is up for every media.

  Loss is the same pair, mirrored. `{:media_timeout, media}` is the raw per-media
  fact — the RTP inactivity watchdog fired for that one — and repeats, since the
  server re-arms it. `:media_lost` is the derived milestone: **every** media of R
  has gone silent, i.e. the peer has stopped sending rather than merely turned
  something off. One dead media is a media problem; every dead media is a dead
  call, and only the second is a reason to hang up.

  Neither the adapter nor the framework arms a timer: a peer that negotiates
  video and never sends any produces no `:ice_connected`. Bounding that wait is
  the scenario's job, with an `after` clause on the `on_events` block.
  """
  # PeerConnection
  @type event ::
          :ice_connected
          | {:media_connected, media :: media()}
          | :media_send_only
          | :ice_failed
          | {:ice_candidate, candidate :: String.t()}
          # Peer-connection setup / SDP negotiation failed (bad remote SDP,
          # no common codec, a control RPC error…). `reason` carries the cause.
          # The connection is torn down; the application should release the call
          # (e.g. hang up). Complements the synchronous {:error, reason} the
          # failing call already returns — this is the async, scenario-capturable
          # signal.
          | {:media_error, reason :: term()}
          # RTP inactivity watchdog fired for ONE media: the peer stopped sending
          # it (emitted by adapters with media-loss detection, e.g. Mendooze).
          # Repeats — the server re-arms the watchdog on every StartReceiving.
          | {:media_timeout, media :: media()}
          # Every media of R has timed out: the peer stopped sending, full stop.
          # The derived milestone, `:ice_connected`'s mirror — emitted at most
          # once per loss episode, and re-armed when any media comes back.
          | :media_lost
          | :closed
          # Player
          | :player_started
          | :player_ended
          | {:player_error, reason :: term()}
          # Recorder
          | :recorder_started
          | {:recorder_stopped, :duration | :dtmf | :silence | :caller}
          | {:recorder_error, reason :: term()}
          # Echo
          | :echo_started
          # Server
          | :server_disconnected

  @typedoc """
  Opaque handle identifying a media resource.

  - `pid()` — used by `MediaServer.Mockup` (each resource is a GenServer)
  - `{conn_pid, kind, ref}` — used by adapter implementations that manage all
    sub-resources inside the connection GenServer (e.g. `MediaServer.Mendooze`)
  """
  @type resource_ref ::
          pid()
          | {conn :: pid(), kind :: :player | :recorder | :echo, ref :: reference()}

  @typedoc """
  Handle of a peer connection.

  A single-leg connection is a bare `pid()` — what every adapter returned before
  B2BUA media existed, and what `MediaServer.Mockup` still returns. A connection
  carrying **two endpoints** (the B2BUA case: one media session per call, one
  endpoint per SIP leg — `docs/design/notes/mediagw_b2bua_jsr309.md` §2) hands out one
  handle per leg, sharing the process that owns the session.

  Callers never inspect it: it is created by `create_peer_connection/3` and
  handed back to the adapter unchanged.
  """
  @type conn_ref :: pid() | {conn :: pid(), leg :: atom()}

  @typedoc """
  What to do when the two legs of a bridge do not agree on a codec, per media.

  * `:force`  — always transcode. Each leg is answered with the first codec of
    its own list, so the answer is what that leg asked for whatever the other
    one settled on. This is what the Java media gateway does for audio.
  * `:avoid`  — the default: pick a codec both legs support and connect them
    directly; transcode only when there is none.
  * `:forbid` — never transcode: with no common codec the call fails.

  Text is not configurable — always bridged, never transcoded (RFC 4103 / T.140
  and the WebSocket text gateway depend on it).
  """
  @type transcoding :: :force | :avoid | :forbid

  @transcoding_values [:force, :avoid, :forbid]

  @doc """
  Read a `bridge/3` transcoding policy, defaulting each media to `:avoid`.

  Lives here, next to `media_list/1`, for the same reason: every adapter must
  accept the same values, and a scenario typo has to fail at the call rather
  than inside the media server.
  """
  @spec transcoding_policy(keyword()) ::
          {:ok, %{audio: transcoding(), video: transcoding()}} | {:error, term()}
  def transcoding_policy(opts) when is_list(opts) do
    audio = Keyword.get(opts, :audio, :avoid)
    video = Keyword.get(opts, :video, :avoid)

    cond do
      audio not in @transcoding_values -> {:error, {:bad_transcoding_policy, :audio, audio}}
      video not in @transcoding_values -> {:error, {:bad_transcoding_policy, :video, video}}
      true -> {:ok, %{audio: audio, video: video}}
    end
  end

  @type ms_event :: {:ms_event, resource_ref(), event()}

  @type conn_opts :: [
          ice_servers: [String.t()],
          video_codec: String.t(),
          audio_codec: String.t(),
          media: media_kind(),
          video_bandwidth: pos_integer(),
          audio_bandwidth: pos_integer(),
          webrtc_support: :yes | :no | :if_offered | :no_avp,
          # Which RTP profile a NON-WebRTC offer is carried in (DESIGN-FRAMEWORK.md
          # §7.5): `:avpf` offers RTP/AVPF — the feedback profile without
          # encryption or ICE — and `:avp` (the default) plain RTP. Ignored when
          # `webrtc_support: :yes`, which already implies SAVPF.
          rtp_profile: :avp | :avpf,
          # let the media server follow a symmetric NAT's mapping instead of the
          # send address the peer signalled. `:auto` (the default) leaves it to the
          # adapter, which asks for it on every leg that is not ICE — a NATed peer
          # hands us its private address in an ANSWER just as readily as in an
          # offer, and under ICE the address is settled by connectivity checks
          # instead. Adapters that cannot latch ignore it.
          nat_latch: boolean() | :auto,
          # The address of OURS this peer reached, set by the framework on a leg we
          # ANSWER (`SIP.Session.Media`, from the transport the request arrived on) —
          # the same address this leg's Contact carries. An adapter that must place
          # media on one of several interfaces reads it; the others ignore it. Absent
          # on an outbound leg, which has no transport when it is created.
          local_ip: :inet.ip_address(),
          # The source address the inbound request came FROM, set by the framework
          # on a leg we ANSWER. It is what says which SIDE of the network this peer
          # sits on — `local_ip` cannot, because behind a 1:1 NAT one interface has
          # two faces and both an inside and an outside peer arrive on the same
          # private address. Absent on an outbound leg, whose side comes from its
          # target instead (`address_profile:` below).
          peer_ip: :inet.ip_address(),
          # The media server's addressing profile this leg's media must be placed
          # on — `MediaServer.profile_name/2`'s output. Set by the framework on a
          # leg we PLACE, where `local_ip` says nothing: we have no address the
          # callee reached, only the address we are about to reach it at, and it is
          # the callee's interface that decides which of ours the media leaves by.
          #
          # An adapter that reads it prefers it over anything it could derive.
          # Absent, and the leg derives what it can — which for an outbound leg is
          # nothing, so the media server applies its own default.
          address_profile: String.t()
        ]

  @type player_opts :: [
          loop: boolean(),
          start_time: non_neg_integer()
        ]

  @type recorder_opts :: [
          # discard audio/text until the first video I-frame so all tracks start
          # together (default true; ignored when video is not negotiated)
          wait_video: boolean(),
          # loop received video back to the sender while recording (default false)
          echo: boolean(),
          stop_on_silence: boolean(),
          silence_timeout_ms: pos_integer(),
          max_record_duration_sec: pos_integer(),
          stop_on_dtmf: boolean()
        ]

  defmodule Behaviour do
    @moduledoc """
    Callbacks that a media server adapter must implement.

    ## Event model

    Asynchronous events are delivered to the `event_sink` pid supplied at
    resource creation time, using the message format:

        {:ms_event, ref :: pid(), event}

    ### Events per resource type

        # PeerConnection
        {:ms_event, conn, {:media_connected, media :: media()}}
        {:ms_event, conn, :ice_connected}
        {:ms_event, conn, :media_send_only}
        {:ms_event, conn, :ice_failed}
        {:ms_event, conn, {:ice_candidate, candidate :: String.t()}}
        {:ms_event, conn, {:media_error, reason :: term()}}
        {:ms_event, conn, {:media_timeout, media :: media()}}
        {:ms_event, conn, :media_lost}
        {:ms_event, conn, :closed}

        # Player
        {:ms_event, player, :player_started}
        {:ms_event, player, :player_ended}
        {:ms_event, player, {:player_error, reason :: term()}}

        # Recorder
        {:ms_event, recorder, :recorder_started}
        {:ms_event, recorder, {:recorder_stopped, :duration | :dtmf | :silence | :caller}}
        {:ms_event, recorder, {:recorder_error, reason :: term()}}

        # Echo
        {:ms_event, echo, :echo_started}

        # Server
        {:ms_event, server, :server_disconnected}

    `:ice_connected` is the notification that media is actually flowing: it is
    emitted on the first validated incoming RTP packet (a decrypted SRTP packet
    for WebRTC — ICE + DTLS done; the first media packet for plain RTP).
    Applications provide the remote SDP via `set_remote_answer/2` or
    `set_remote_offer/2` and then wait for it; it may arrive during early media
    (a 183 answer) before the call is fully answered.

    ## Teardown order

        stop_player / stop_recorder / stop_echo
            -> unbridge
                -> close_peer_connection
                    -> disconnect
    """

    # ── Server lifecycle ────────────────────────────────────────────────────

    @callback connect(MediaServer.server_addr()) ::
                {:ok, server :: pid()} | {:error, term()}

    @doc "Closes all open resources then disconnects from the media server process."
    @callback disconnect(server :: pid(), opts :: [force: boolean()]) :: :ok

    # ── Peer connection ─────────────────────────────────────────────────────

    @callback create_peer_connection(
                server :: pid(),
                event_sink :: pid(),
                MediaServer.conn_opts()
              ) :: {:ok, conn :: pid()} | {:error, term()}

    @doc "Generate a local SDP offer. Call before set_remote_answer/2."
    @callback get_local_offer(conn :: pid()) ::
                {:ok, MediaServer.sdp()} | {:error, term()}

    @doc "Provide the remote SDP answer after SIP negotiation. Starts ICE checks."
    @callback set_remote_answer(conn :: pid(), MediaServer.sdp()) ::
                :ok | {:error, term()}

    @doc "Accept an incoming SDP offer and return the local SDP answer."
    @callback set_remote_offer(conn :: pid(), MediaServer.sdp()) ::
                {:ok, answer :: MediaServer.sdp()} | {:error, term()}

    @doc "Feed a trickle ICE candidate received from the remote peer."
    @callback add_remote_candidate(conn :: pid(), candidate :: String.t()) ::
                :ok | {:error, term()}

    @doc """
    The SIP call this connection serves has been **answered**: the peer may now
    be expected to send RTP, and everything that watches for its absence starts
    here — never at offer/answer time.

    Negotiating an SDP says what a call *would* carry; it says nothing about when
    the media starts. Between the two sits the ringing phase, which is silent by
    definition and lasts as long as a human takes to pick up. An adapter that
    arms its RTP inactivity watchdog when it processes the SDP therefore reaps
    every call that rings longer than the timeout: traffic of 2026-08-13, an
    INVITE answered at 22:12:15, the watchdog fired at 22:12:25 while the callee
    was still ringing, and the 200 OK relayed at 22:12:32 was followed
    immediately by a BYE on both legs — a perfectly good call, killed by its own
    supervision. The same holds for an early answer (183): the callee's SDP is
    known long before anyone picks up.

    Called once per leg, by the framework, at the moment the call is up for that
    leg (`SIP.Session.Media.call_answered/2`). Idempotent, and best-effort by
    contract: a leg that carries media is worth more than a leg that is watched,
    so an adapter reports a failure to arm rather than failing the call.
    """
    @callback call_answered(conn :: MediaServer.conn_ref()) :: :ok | {:error, term()}

    @callback close_peer_connection(conn :: pid()) :: :ok

    # ── Bridging two peer connections ───────────────────────────────────────

    @doc """
    Connect two peer connections so each one's incoming media is sent out of the
    other — the B2BUA media path.

    Called **once both legs have negotiated**, which is the only moment it can be:
    what a leg sends depends on what the other leg can receive. It is therefore
    not the same request as `create_peer_connection/3`'s `bridge_with:` option,
    which says where the endpoint lives and has to be answered at creation time.

    `opts` carries the per-media transcoding policy (see
    `MediaServer.transcoding_policy/1`): `[audio: :avoid, video: :avoid]`.
    `{:error, :no_common_codec}` is the expected refusal under `:forbid`.

    Idempotent: bridging an already-bridged pair changes nothing.

    `{:ok, %{inbound_answer: sdp}}` hands back leg `a`'s answer, **rebuilt** now
    that both legs are known: a relayed media is restricted to the codecs BOTH
    legs carry, so every codec left in the answer is one the media server can
    actually pass through, and the caller may switch between them mid-call with no
    renegotiation. Callers that hold an answer produced when the offer arrived
    must replace it with this one. A plain `:ok` means nothing changed — the
    adapter does not rebuild, or leg `a` never answered an offer.
    """
    @callback bridge(a :: MediaServer.conn_ref(), b :: MediaServer.conn_ref(), opts :: keyword()) ::
                :ok | {:ok, %{inbound_answer: String.t()}} | {:error, term()}

    @doc """
    Take the media path down without closing either connection — putting a call
    on hold, re-pointing a hunt at another target. A pair that is not bridged is
    not an error.
    """
    @callback unbridge(a :: MediaServer.conn_ref(), b :: MediaServer.conn_ref()) :: :ok

    # ── Player ──────────────────────────────────────────────────────────────

    @doc "Attach an MP4 player to `conn`. Media is streamed to the remote peer."
    @callback create_player(
                conn :: pid(),
                file_path :: String.t(),
                MediaServer.player_opts()
              ) :: {:ok, player :: MediaServer.resource_ref()} | {:error, term()}

    @callback start_player(player :: MediaServer.resource_ref()) :: :ok | {:error, term()}
    @callback pause_player(player :: MediaServer.resource_ref()) :: :ok | {:error, term()}
    @callback stop_player(player :: MediaServer.resource_ref()) :: :ok

    # ── Recorder ────────────────────────────────────────────────────────────

    @doc """
    Attach a recorder to `conn`. Media from the remote peer is written to
    `file_path`. Use `duration_ms = 0` for unlimited duration.
    """
    @callback create_recorder(
                conn :: pid(),
                file_path :: String.t(),
                duration_ms :: non_neg_integer(),
                MediaServer.recorder_opts()
              ) :: {:ok, recorder :: MediaServer.resource_ref()} | {:error, term()}

    @callback start_recorder(recorder :: MediaServer.resource_ref()) :: :ok | {:error, term()}
    @callback stop_recorder(recorder :: MediaServer.resource_ref()) :: :ok

    # ── Echo ────────────────────────────────────────────────────────────────

    @doc """
    Start a media loopback (echo) on `conn`: every media packet received from
    the remote peer is sent straight back to it. Emits `:echo_started`.
    """
    @callback create_echo(conn :: pid()) ::
                {:ok, echo :: MediaServer.resource_ref()} | {:error, term()}

    @callback stop_echo(echo :: MediaServer.resource_ref()) :: :ok
  end
end
