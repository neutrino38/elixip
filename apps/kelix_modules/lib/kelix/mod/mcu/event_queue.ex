defmodule Kelix.Mod.Mcu.EventQueue do
  @moduledoc """
  The MCU event stream of one media server (design `docs/design/mcu_module.md`
  §3.7): a chunked HTTP long-poll on `GET /events/mcu/<queueId>`, decoded and
  dispatched to the module, which routes each event to the owning participant.

  The server never calls back — events are *fetched*. Each one is a serialized
  XML-RPC `<methodResponse>` whose parameter array starts with the
  `MCU::Events` type code; a bare `\\r\\n` chunk is the keep-alive the server sends
  when nothing happened in its cycle (~30 s).

  Two types exist today:

  | type | payload | meaning |
  |---|---|---|
  | `1` | `(confId, tag, partId)` | the MCU wants a full intra-frame from that participant |
  | `2` | `(confId, tag, partId, status)` | doc-sharing status — **ignored** (§1.2) |

  Types `3` (media timeout) and `4` (media connected) are specified for P7
  (§16.1-16.2) and decoded here already: the wire contract is append-only, so a
  consumer written now needs no change when the server starts emitting them.

  Decoded events reach the sink as `{:mcu_event, mcu_name, event}`. A lost stream
  is retried every `:retry_ms`; after `:max_failures` consecutive failures the sink
  is told `{:mcu_event_stream_down, mcu_name}` — that, not a silent stall, is what
  makes an MCU restart visible (§9.2).
  """
  use GenServer
  require Logger

  alias Kelix.Mod.Mcu.Client

  @default_retry_ms 1_000
  @default_max_failures 5
  # three missed keep-alive cycles: the connection is dead, not quiet
  @default_stall_ms 90_000
  # A dedicated :httpc profile: the long-poll holds its connection for the whole
  # session and would otherwise serialise every control RPC behind it.
  @httpc_profile :kelix_mcu_event_queue

  @type event ::
          {:fpu_requested, conf_id :: integer, tag :: String.t(), part_id :: integer}
          | {:media_timeout, conf_id :: integer, tag :: String.t(), part_id :: integer,
             media :: atom | integer}
          | {:media_connected, conf_id :: integer, tag :: String.t(), part_id :: integer,
             media :: atom | integer}

  # ── API ──────────────────────────────────────────────────────────────────────

  @doc """
  Start the poller. Options: `:name` (MCU entry name), `:base_url`, `:client`
  (the `Kelix.Mod.Mcu.Client` to read the `queueId` from), `:sink`, `:retry_ms`,
  `:max_failures`, `:stall_ms`, `:server_name`.
  """
  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts) do
    case Keyword.get(opts, :server_name) do
      nil -> GenServer.start_link(__MODULE__, opts)
      name -> GenServer.start_link(__MODULE__, opts, name: name)
    end
  end

  # ── GenServer ────────────────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    state = %{
      name: Keyword.get(opts, :name, "mcu"),
      base_url: Keyword.fetch!(opts, :base_url),
      client: Keyword.get(opts, :client),
      sink: Keyword.fetch!(opts, :sink),
      retry_ms: Keyword.get(opts, :retry_ms, @default_retry_ms),
      max_failures: Keyword.get(opts, :max_failures, @default_max_failures),
      stall_ms: Keyword.get(opts, :stall_ms, @default_stall_ms),
      request: nil,
      buffer: "",
      failures: 0,
      connected?: false,
      down_notified?: false,
      # the stale queue id we have already asked the client to replace, so the
      # retry loop asks once per id and not once per second
      renewing: nil,
      timer: nil
    }

    ensure_profile()
    {:ok, state, {:continue, :poll}}
  end

  @impl true
  def handle_continue(:poll, state), do: {:noreply, start_request(state)}

  @impl true
  def handle_info(:poll, state), do: {:noreply, start_request(%{state | timer: nil})}

  def handle_info({:http, {ref, :stream_start, _headers}}, %{request: ref} = state) do
    # Say how long it took when we had gone quiet: the failure lines stop after a
    # few (see log_failure/2), so this is the only place the outage gets a size.
    suffix =
      if state.down_notified?,
        do: " again after #{state.failures} failed attempts",
        else: ""

    Logger.info(module: __MODULE__, message: "mcu #{state.name}: event stream connected#{suffix}")

    {:noreply,
     %{state | connected?: true, failures: 0, down_notified?: false, renewing: nil}}
  end

  def handle_info({:http, {ref, :stream, chunk}}, %{request: ref} = state) do
    {frames, rest} = decode_frames(state.buffer <> chunk)
    Enum.each(frames, &dispatch(&1, state))
    {:noreply, arm_stall(%{state | buffer: rest})}
  end

  def handle_info({:http, {ref, :stream_end, _headers}}, %{request: ref} = state) do
    Logger.info(module: __MODULE__, message: "mcu #{state.name}: event stream closed by server")
    {:noreply, retry(state)}
  end

  def handle_info({:http, {ref, {:error, reason}}}, %{request: ref} = state) do
    state = log_failure(state, "event stream error: #{inspect(reason)}")
    {:noreply, retry(state)}
  end

  # 404: the queue id we hold is unknown to the server. Ids are never reallocated,
  # so this is not transient — the media server restarted and answers control RPCs
  # perfectly well while knowing nothing of our queue. Retrying it is hopeless;
  # ask the client for a fresh one and poll that. Guarded on the stale id so the
  # ~1 Hz retry loop does not stack EventQueueCreate calls while one is in flight.
  def handle_info(
        {:http, {ref, {{_proto, 404, _reason}, _headers, _body}}},
        %{request: ref} = state
      ) do
    stale = queue_id(state)

    state =
      if is_integer(stale) and stale != state.renewing do
        state = log_failure(state, "event queue #{stale} is gone (404); asking for a new one")
        renew_queue(state, stale)
        %{state | renewing: stale}
      else
        state
      end

    {:noreply, retry(state)}
  end

  # any other complete (non-streamed) response: an HTTP error status
  def handle_info({:http, {ref, other}}, %{request: ref} = state) do
    state = log_failure(state, "unexpected event response: #{inspect(other)}")
    {:noreply, retry(state)}
  end

  def handle_info(:stall, state) do
    state = log_failure(state, "event stream stalled")
    cancel(state)
    {:noreply, retry(state)}
  end

  # a stale message from a cancelled request
  def handle_info({:http, _}, state), do: {:noreply, state}
  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    cancel(state)
    :ok
  end

  # ── polling ──────────────────────────────────────────────────────────────────

  defp start_request(state) do
    case queue_id(state) do
      nil ->
        # the MCU is unreachable: the client is retrying the queue creation, so
        # there is nothing to poll yet
        schedule_retry(state)

      queue_id ->
        url = String.to_charlist("#{state.base_url}/events/mcu/#{queue_id}")

        case :httpc.request(:get, {url, []}, [], [sync: false, stream: :self], @httpc_profile) do
          {:ok, ref} ->
            arm_stall(%{state | request: ref, buffer: "", connected?: false})

          {:error, reason} ->
            state = log_failure(state, "event request failed: #{inspect(reason)}")
            retry(state)
        end
    end
  end

  # The retry loop runs at ~1 Hz, so a media server that stays down would write a
  # line a second for ever — and it did. Report the first few attempts, then go
  # silent: retry/1 has the last word with a single error at :max_failures, and
  # nothing more is said until the stream is really back (stream_start clears the
  # flag and reports how many attempts it took).
  defp log_failure(state, message) do
    unless state.down_notified? do
      Logger.warning(module: __MODULE__, message: "mcu #{state.name}: #{message}")
    end

    state
  end

  defp renew_queue(%{client: nil}, _stale_id), do: :ok

  defp renew_queue(%{client: client}, stale_id) do
    Client.renew_queue(client, stale_id)
  catch
    :exit, _ -> :ok
  end

  defp queue_id(%{client: nil}), do: nil

  defp queue_id(%{client: client}) do
    Client.queue_id(client)
  catch
    :exit, _ -> nil
  end

  # A stream that had connected starts a fresh failure sequence: the MCU answered
  # once, so a single drop is not the same evidence as never reaching it.
  defp retry(state) do
    failures = if state.connected?, do: 1, else: state.failures + 1
    state = %{state | request: nil, buffer: "", connected?: false, failures: failures}

    if failures >= state.max_failures and not state.down_notified? do
      Logger.error(
        module: __MODULE__,
        message: "mcu #{state.name}: event stream lost after #{failures} failures"
      )

      send(state.sink, {:mcu_event_stream_down, state.name})
      schedule_retry(%{state | down_notified?: true})
    else
      schedule_retry(state)
    end
  end

  defp schedule_retry(state) do
    state = cancel_stall(state)
    %{state | timer: Process.send_after(self(), :poll, state.retry_ms)}
  end

  defp arm_stall(state) do
    state = cancel_stall(state)
    %{state | timer: Process.send_after(self(), :stall, state.stall_ms)}
  end

  defp cancel_stall(%{timer: nil} = state), do: state

  defp cancel_stall(%{timer: timer} = state) do
    Process.cancel_timer(timer)
    %{state | timer: nil}
  end

  defp cancel(%{request: nil}), do: :ok
  defp cancel(%{request: ref}), do: :httpc.cancel_request(ref, @httpc_profile)

  defp ensure_profile() do
    case :inets.start(:httpc, [{:profile, @httpc_profile}]) do
      {:ok, _pid} ->
        :httpc.set_options([max_sessions: 100, max_keep_alive_length: 0], @httpc_profile)

      {:error, {:already_started, _pid}} ->
        :ok
    end
  end

  defp dispatch(frame, state) do
    case decode_event(frame) do
      {:ok, event} ->
        send(state.sink, {:mcu_event, state.name, event})

      :ignore ->
        :ok

      {:error, reason} ->
        Logger.warning(
          module: __MODULE__,
          message: "mcu #{state.name}: dropping bad event frame: #{inspect(reason)}"
        )
    end
  end

  # ── pure frame / event decoding (unit-testable) ───────────────────────────────

  @doc """
  Extract complete `<methodResponse>` frames from the stream buffer.

  Returns `{frames, rest}`, `rest` being the incomplete tail to prepend to the next
  chunk. Leading whitespace — the bare `\\r\\n` keep-alives included — is discarded.
  """
  @spec decode_frames(binary) :: {[binary], binary}
  def decode_frames(buffer), do: do_decode_frames(buffer, [])

  defp do_decode_frames(buffer, acc) do
    buffer = String.trim_leading(buffer)

    case String.split(buffer, "</methodResponse>", parts: 2) do
      [_incomplete] -> {Enum.reverse(acc), buffer}
      [frame, rest] -> do_decode_frames(rest, [frame <> "</methodResponse>" | acc])
    end
  end

  @doc """
  Decode one XML-RPC frame into an event term, `:ignore` for an event we
  deliberately do not act on (type `2`, doc sharing — §1.2).

  The type code is the `MCU::Events` wire contract, shared with every controller of
  that media server (mcuGold included): codes are appended, never renumbered.
  """
  @spec decode_event(binary) :: {:ok, event} | :ignore | {:error, term}
  def decode_event(frame) do
    case XMLRPC.decode(frame) do
      {:ok, %XMLRPC.MethodResponse{param: param}} -> translate(param)
      {:ok, other} -> {:error, {:unexpected_frame, other}}
      {:error, reason} -> {:error, {:decode_error, reason}}
    end
  end

  # type 1: PlayerRequestFPU — the mixer needs an intra-frame from that leg
  defp translate([1, conf_id, tag, part_id]), do: {:ok, {:fpu_requested, conf_id, tag, part_id}}

  # type 2: document-sharing status — out of scope, dropped without a warning
  defp translate([2 | _rest]), do: :ignore

  # types 3 and 4 land with the server-side work of §16.1-16.2 (P7)
  defp translate([3, conf_id, tag, part_id, media | _role]),
    do: {:ok, {:media_timeout, conf_id, tag, part_id, media_atom(media)}}

  defp translate([4, conf_id, tag, part_id, media | _role]),
    do: {:ok, {:media_connected, conf_id, tag, part_id, media_atom(media)}}

  defp translate(other), do: {:error, {:unknown_event, other}}

  defp media_atom(0), do: :audio
  defp media_atom(1), do: :video
  defp media_atom(2), do: :text
  defp media_atom(other), do: other
end
