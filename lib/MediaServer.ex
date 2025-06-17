defmodule MediaServer do
  defmodule Behavior do

    @moduledoc """
    Defines the behavior for MediaServer modules.
    This module specifies the callbacks that a MediaServer implementation must provide.
    The MediaServer is responsible for managing RTC connections, media players, media recorders, and media echoes.
    """
    @doc """
    Create an RTC connection

    - hostname and port to connect to the media server
    - event_sink is the process id of the event sink that will receive events from the media server
    - `options` is a list of options to configure the connection, such as:
      - `:ice_servers` - List of ICE servers to use for the connection
      - `:video_bandwidth` - Maximum video bandwidth in kbps
      - `:audio_bandwidth` - Maximum audio bandwidth in kbps
      - `:video_codecs` - Video codec to use (e.g., "VP8", "H264")
      - `:audio_codecs` - Audio codec to use (e.g., "OPUS", "PCMU")
      - `:medias` - Tuple of media to handle (e.g., { :audio, :video, :text })
      - `:webrtc_support` - :no | :yes | :if_offered
      - `:event_sink` - Process id of the event sink that will receive events from the media server
    - returns `{:ok, pid()}` on success or `{:error, term()}` on failure
    """
    @callback createRTCConnection(String.t(), pid(), list()) :: {:ok, pid()} | {:error, term()}


    @doc """
    Create a media player

    - `url` is the URL of the media to play
    - `loop` is a boolean indicating whether the media should loop
    - returns `{:ok, term()}` on success or `{:error, term()}` on failure
    """
    @callback createMediaPlayer( pid(), String.t(), boolean()) :: { :ok, term() } | { :error, term() }

    @doc """
    Create a media recorder

    - `url` is the URL of the media to play. Only file:// URLs are supported
    - `duration` is the duration in seconds to record
    - `options` is a list of options for the recorder, e
      - :stop_on_dtmf stop recording if a DTMF is received,
      - :wait_for_first_frame wait for the first frame before starting the recording
      - :stop_on_silence stop recording if no audio is received for a certain time
      - :silence_timeout the time in seconds to wait for silence before stopping the recording
      - :stop_on_text_input: stop recording if a specific text input is received
    - returns `{:ok, term()}` on success or `{:error, term()}` on failure
    """
    @callback createMediaRecorder( pid(), String.t(), integer(), list()) :: { :ok, term() } | { :error, term() }

    @callback createMediaEcho( pid()) :: { :ok, term() } | { :error, term() }

    @doc """
    Connect an media ressource to an exiting RTC connection
    - `pid` is the process id of the RTC connection
    - `direction` is either `:inbound` or `:outbound`
    - `options` is a list of additional parameters:
      - `:media_type` - Tuple of media to handle (e.g., { :audio, :video, :text })
      - `:transcoding` - true | false, whether to transcode the media
    - ressource is a term that can be used to identify the media resource (e.g., a MediaPlayer or MediaRecorder or a MediaEcho)
    - returns `{:ok, term()}` on success or `{:error, term()}` on failure
    """
    @callback connectStream(pid(), :inbound | :outbound, list(), atom(), term()) :: {:ok, term()} | {:error, term()}

    @doc """
    Disconnect a media resource from an existing RTC connection
    - `pid` is the process id of the RTC connection
    - `direction` is either `:inbound` or `:outbound`
    - `options` is a list of additional parameters:
      - `:media_type` - Tuple of media to handle (e.g., { :audio, :video, :text })

    returns `{:ok, term()}` on success or `{:error, term()}` on failure
    """
    @callback disconnectStream(pid(), :inbound | :outbound, list()) :: {:ok, term()} | {:error, term()}

    @doc """
    Set the event sink for the media server
    - `pid` is the process id of the media server
    - `event_sink` is the process id of the event sink that will receive events from the media server
    - returns `:ok` on success or `{:error, term()}` on failure
    """
    @callback setEventSink(pid(), pid()) :: :ok | {:error, term()}

    @doc """
    Get the local offer for an RTC connection
    - `pid` is the process id of the RTC connection
    - returns `{:ok, String.t()}` with the SDP offer on success or `{:error, term()}` on failure
    """
    @callback getLocalOffer(pid) :: {:ok, String.t()} | {:error, term()}

    @doc """
    Set the remote offer for an RTC connection
    - `pid` is the process id of the RTC connection
    - `offer` is the SDP offer to set
    - returns `:ok` on success or `{:error, term()}` on failure
    """
    @callback setRemoteOffer(pid, String.t()) :: :ok | {:error, term()}

    @callback close(pid) :: :ok | {:error, term()}
  end
end
