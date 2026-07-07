defmodule MediaServer.Mendooze.EventPoller do
  @moduledoc """
  Long-poll task reading the Mendooze JSR309 event stream.

  The server does not call the client back: events are fetched with a
  chunked HTTP GET on the queue path returned by `EventQueueCreate`
  (e.g. `/events/jsr309/7`). Each event is one serialized XML-RPC
  `<methodResponse>` whose parameter is a tuple starting with the event
  type integer; a bare `\\r\\n` chunk is a keep-alive (sent when no event
  occurred within the server cycle, ~30 s).

  Decoded events are sent to the `sink` pid (the `MediaServer.Mendooze`
  server GenServer) as:

      {:mendooze_event, event}   # see decode_event/1 for the event terms
      {:mendooze_poller_down}    # after max_failures consecutive failures

  Reconnect policy: on connection drop the poller sleeps `retry_ms` and
  retries; a successful connection resets the failure count. The stream
  closing after `EventQueueDelete` looks like any drop — `disconnect/2`
  stops the task explicitly, so the poller never needs to tell them apart.

  Options: `:base_url`, `:source_path`, `:sink` (required);
  `:retry_ms` (1000), `:max_failures` (5), `:stall_ms` (90000 — three
  missed keep-alive cycles means the connection is dead).
  """

  use Task, restart: :transient
  require Logger

  @default_retry_ms 1_000
  @default_max_failures 5
  @default_stall_ms 90_000

  # Dedicated :httpc profile for the long-poll event stream. The stream request
  # occupies its connection for the whole session, so it MUST NOT share the
  # default profile with the synchronous XML-RPC calls: httpc serializes
  # requests per profile/host and a busy long-poll would block every RPC
  # (MediaSessionCreate, EndpointCreate, …) until they time out.
  @httpc_profile :mendooze_event_poller

  @type event ::
          {:player_end_of_file, session_tag :: String.t(), player_tag :: String.t()}
          | {:player_started, session_tag :: String.t(), player_tag :: String.t()}
          | {:recorder_started, session_tag :: String.t(), recorder_tag :: String.t()}
          | {:recorder_stopped, session_tag :: String.t(), recorder_tag :: String.t(),
             reason :: :caller | :duration | :silence | :dtmf | integer()}
          | {:external_fir, session_tag :: String.t(), endpoint_id :: integer(),
             media :: :audio | :video | :text | integer()}
          | {:endpoint_disconnected, session_tag :: String.t(), endpoint_id :: integer(),
             media :: :audio | :video | :text | integer()}

  def start_link(opts) do
    Task.start_link(__MODULE__, :run, [opts])
  end

  @doc false
  def run(opts) do
    ensure_profile()

    cfg = %{
      url:
        String.to_charlist(Keyword.fetch!(opts, :base_url) <> Keyword.fetch!(opts, :source_path)),
      sink: Keyword.fetch!(opts, :sink),
      retry_ms: Keyword.get(opts, :retry_ms, @default_retry_ms),
      max_failures: Keyword.get(opts, :max_failures, @default_max_failures),
      stall_ms: Keyword.get(opts, :stall_ms, @default_stall_ms)
    }

    connect_loop(cfg, 0)
  end

  # Start the dedicated profile once (idempotent across pollers) and give it a
  # generous session pool so pollers to several media servers never queue.
  defp ensure_profile() do
    case :inets.start(:httpc, [{:profile, @httpc_profile}]) do
      {:ok, _pid} ->
        :httpc.set_options([max_sessions: 100, max_keep_alive_length: 0], @httpc_profile)

      {:error, {:already_started, _pid}} ->
        :ok
    end
  end

  # ── Connection loop ─────────────────────────────────────────────────────────

  defp connect_loop(cfg, failures) when failures > 0 do
    if failures >= cfg.max_failures do
      Logger.error(
        "Mendooze.EventPoller: event stream lost after #{failures} consecutive failures"
      )

      send(cfg.sink, {:mendooze_poller_down})
    else
      Process.sleep(cfg.retry_ms)
      attempt(cfg, failures)
    end
  end

  defp connect_loop(cfg, 0), do: attempt(cfg, 0)

  defp attempt(cfg, failures) do
    case :httpc.request(:get, {cfg.url, []}, [], [sync: false, stream: :self], @httpc_profile) do
      {:ok, ref} ->
        case stream_loop(ref, cfg, "", false) do
          # the connection had been established: new failure sequence
          {:disconnected, true} -> connect_loop(cfg, 1)
          {:disconnected, false} -> connect_loop(cfg, failures + 1)
        end

      {:error, reason} ->
        Logger.warning("Mendooze.EventPoller: request failed: #{inspect(reason)}")
        connect_loop(cfg, failures + 1)
    end
  end

  defp stream_loop(ref, cfg, buffer, connected) do
    receive do
      {:http, {^ref, :stream_start, _headers}} ->
        Logger.info("Mendooze.EventPoller: event stream connected")
        stream_loop(ref, cfg, buffer, true)

      {:http, {^ref, :stream, chunk}} ->
        {frames, rest} = decode_frames(buffer <> chunk)
        Enum.each(frames, &dispatch_frame(&1, cfg.sink))
        stream_loop(ref, cfg, rest, connected)

      {:http, {^ref, :stream_end, _headers}} ->
        Logger.info("Mendooze.EventPoller: event stream closed by server")
        {:disconnected, connected}

      {:http, {^ref, {:error, reason}}} ->
        Logger.warning("Mendooze.EventPoller: stream error: #{inspect(reason)}")
        {:disconnected, connected}

      # complete non-streamed response, e.g. an HTTP error status
      {:http, {^ref, other}} ->
        Logger.warning("Mendooze.EventPoller: unexpected response: #{inspect(other)}")
        {:disconnected, connected}
    after
      cfg.stall_ms ->
        # no event nor keep-alive for several server cycles: dead connection
        Logger.warning("Mendooze.EventPoller: stream stalled, reconnecting")
        :httpc.cancel_request(ref, @httpc_profile)
        {:disconnected, connected}
    end
  end

  defp dispatch_frame(frame, sink) do
    case decode_event(frame) do
      {:ok, event} ->
        send(sink, {:mendooze_event, event})

      {:error, reason} ->
        Logger.warning("Mendooze.EventPoller: dropping bad event frame: #{inspect(reason)}")
    end
  end

  # ── Pure frame / event decoding (unit-testable) ─────────────────────────────

  @doc """
  Extract complete `<methodResponse>` frames from the stream buffer.

  Returns `{frames, rest}` where `rest` is the incomplete tail to prepend
  to the next chunk. Leading whitespace — including the bare `\\r\\n`
  keep-alives — is discarded.
  """
  @spec decode_frames(binary()) :: {[binary()], binary()}
  def decode_frames(buffer), do: do_decode_frames(buffer, [])

  defp do_decode_frames(buffer, acc) do
    buffer = String.trim_leading(buffer)

    case String.split(buffer, "</methodResponse>", parts: 2) do
      [_incomplete] -> {Enum.reverse(acc), buffer}
      [frame, rest] -> do_decode_frames(rest, [frame <> "</methodResponse>" | acc])
    end
  end

  @doc """
  Decode one XML-RPC frame into an event term.

  The event tuple starts with the `JSR309Event::Events` type code — a wire
  contract shared with the server (`JSR309Event.h`), never renumbered:
  1 PlayerEndOfFile, 2 ExternalFIRRequested, 3 PlayerStarted,
  4 RecorderStarted, 5 RecorderStopped(reason), 6 EndpointDisconnected.
  The video `role` field of events 2 and 6 is not used and dropped.
  """
  @spec decode_event(binary()) :: {:ok, event()} | {:error, term()}
  def decode_event(frame) do
    case XMLRPC.decode(frame) do
      {:ok, %XMLRPC.MethodResponse{param: param}} -> translate_event(param)
      {:ok, other} -> {:error, {:unexpected_frame, other}}
      {:error, reason} -> {:error, {:decode_error, reason}}
    end
  end

  defp translate_event([1, sess, player]) do
    Logger.info([ module: __MODULE__, session: sess, event: :player_end_of_file ])
    {:ok, {:player_end_of_file, sess, player}}
  end

  defp translate_event([2, sess, endpoint_id, media, _role]),
    do: {:ok, {:external_fir, sess, endpoint_id, media_atom(media)}}

  defp translate_event([3, sess, player]) do
    Logger.info([ module: __MODULE__, session: sess, event: :player_started ])
    {:ok, {:player_started, sess, player}}
  end

  defp translate_event([4, sess, recorder]) do
    Logger.info([ module: __MODULE__, session: sess, event: :recorder_started ])
    {:ok, {:recorder_started, sess, recorder}}
  end

  defp translate_event([5, sess, recorder, reason]) do
    Logger.info([ module: __MODULE__, session: sess, event: :recorder_stopped, reason: reason_atom(reason) ])
    {:ok, {:recorder_stopped, sess, recorder, reason_atom(reason)}}
  end

  defp translate_event([6, sess, endpoint_id, media, _role]),
    do: {:ok, {:endpoint_disconnected, sess, endpoint_id, media_atom(media)}}

  defp translate_event(other) do
    Logger.warning("Mendooze.EventPoller: unknown event tuple: #{inspect(other)}")
    {:error, {:unknown_event, other}}
  end

  defp media_atom(0), do: :audio
  defp media_atom(1), do: :video
  defp media_atom(2), do: :text
  defp media_atom(other), do: other

  defp reason_atom(0), do: :caller
  defp reason_atom(1), do: :duration
  defp reason_atom(2), do: :silence
  defp reason_atom(3), do: :dtmf
  defp reason_atom(other), do: other
end
