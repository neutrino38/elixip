defmodule MediaServer do
  @moduledoc """
  Types and behaviour for the media server interface.

  Implementations drive a medooze Node.js media server over an IPC channel.
  Use `MediaServer.Mockup` in tests.
  """

  @type server_addr :: {String.t(), pos_integer()}
  @type sdp :: String.t()
  @type media_kind :: :audio | :video | :audio_video

  @typedoc """
  Asynchronous events delivered to the `event_sink` pid as `{:ms_event, ref, event}`.

  `:ice_connected` notifies the application that ICE/DTLS connectivity has been
  established on a peer connection — i.e. media can now flow. It is emitted once
  the remote SDP (answer or offer) has been negotiated and connectivity checks
  succeed.
  """
  @type event ::
          # PeerConnection
          :ice_connected
          | :ice_failed
          | {:ice_candidate, candidate :: String.t()}
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

  @type ms_event :: {:ms_event, ref :: pid(), event()}

  @type conn_opts :: [
    ice_servers: [String.t()],
    video_codec: String.t(),
    audio_codec: String.t(),
    media: media_kind(),
    video_bandwidth: pos_integer(),
    audio_bandwidth: pos_integer(),
    webrtc_support: :yes | :no | :if_offered | :no_avp
  ]

  @type player_opts :: [
    loop: boolean(),
    start_time: non_neg_integer()
  ]

  @type recorder_opts :: [
    wait_for_keyframe: boolean(),
    stop_on_silence: boolean(),
    silence_timeout_ms: pos_integer(),
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
        {:ms_event, conn, :ice_connected}
        {:ms_event, conn, :ice_failed}
        {:ms_event, conn, {:ice_candidate, candidate :: String.t()}}
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

    `:ice_connected` is the notification that ICE/DTLS connectivity has been
    established on a peer connection (media can now flow). Applications wait for
    it after providing the remote SDP via `set_remote_answer/2` or
    `set_remote_offer/2`.

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
              ) :: {:ok, player :: pid()} | {:error, term()}

    @callback start_player(player :: pid()) :: :ok | {:error, term()}
    @callback pause_player(player :: pid()) :: :ok | {:error, term()}
    @callback stop_player(player :: pid()) :: :ok

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
              ) :: {:ok, recorder :: pid()} | {:error, term()}

    @callback start_recorder(recorder :: pid()) :: :ok | {:error, term()}
    @callback stop_recorder(recorder :: pid()) :: :ok

    # ── Echo ────────────────────────────────────────────────────────────────

    @doc """
    Start a media loopback (echo) on `conn`: every media packet received from
    the remote peer is sent straight back to it. Emits `:echo_started`.
    """
    @callback create_echo(conn :: pid()) ::
                {:ok, echo :: pid()} | {:error, term()}

    @callback stop_echo(echo :: pid()) :: :ok
  end
end
