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

  @typedoc """
  Asynchronous events delivered to the `event_sink` pid as `{:ms_event, ref, event}`.

  Media connectivity comes in two events (`docs/design/media-connectivity.md`).

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
          # RTP inactivity watchdog fired: the peer stopped sending media
          # (emitted by adapters with media-loss detection, e.g. Mendooze)
          | :media_timeout
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

  @type ms_event :: {:ms_event, resource_ref(), event()}

  @type conn_opts :: [
          ice_servers: [String.t()],
          video_codec: String.t(),
          audio_codec: String.t(),
          media: media_kind(),
          video_bandwidth: pos_integer(),
          audio_bandwidth: pos_integer(),
          webrtc_support: :yes | :no | :if_offered | :no_avp,
          # let the media server follow a symmetric NAT's mapping instead of the
          # send address the peer signalled. `:auto` (the default) leaves it to the
          # adapter, which enables it on the legs that ANSWER a remote offer —
          # the ones where the peer chose that address, and where a NATed peer
          # therefore hands us its private one. Adapters that cannot latch ignore it.
          nat_latch: boolean() | :auto
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

    @callback close_peer_connection(conn :: pid()) :: :ok

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
