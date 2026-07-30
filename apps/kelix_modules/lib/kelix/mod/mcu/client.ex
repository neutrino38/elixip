defmodule Kelix.Mod.Mcu.Client do
  @moduledoc """
  One control channel to one media server (design `docs/design/mcu_module.md`
  §4.1): the XML-RPC connection plus the `queueId` its events arrive on.

  Every RPC of §3.2-3.5 goes through `call/3`, which **serialises** them on this
  process. That is deliberate: the conference registry, the participant setup
  sequences and the health state then observe one ordered stream of commands per
  MCU, which is what makes the "acquire → on error, release what was acquired"
  rule of §9.1 hold. The cost is that a wedged MCU stalls the other legs on the
  *same* MCU until `xmlrpc_timeout_ms` expires — bounded, and the reason the
  facade calls are themselves bounded (`Kelix.Module.safe_call/3`).

  An MCU that is unreachable at boot does **not** prevent the module from
  starting (§4.1): the client comes up `down`, retries the queue creation every
  `@reconnect_ms`, and answers `{:error, :mcu_down}` meanwhile — which the module
  turns into a `503` rather than a hung call.

  `:transport` (a `(method, params -> {:ok, list} | {:error, term})` function)
  replaces the HTTP layer in tests: it is what lets the RPC-order test of §13
  assert the exact sequence with no media server in sight.
  """
  use GenServer
  require Logger

  alias Kelix.Mod.Mcu.XmlRpc

  @reconnect_ms 10_000
  # The GenServer call must outlive the HTTP timeout it wraps (plus whatever is
  # queued ahead of it), else the caller gives up on a request still perfectly in
  # flight. `xmlrpc_timeout_ms` is the real bound; this is only the backstop.
  @call_timeout_ms 30_000

  @type t :: pid | GenServer.server()

  # ── API ──────────────────────────────────────────────────────────────────────

  @doc """
  Start a client. Options: `:name` (MCU entry name, for logs), `:base_url`,
  `:timeout_ms`, `:transport`, `:register` (`{module, name}` notified of health
  transitions), `:reconnect_ms`, and `:server_name` (process registration).
  """
  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts) do
    case Keyword.get(opts, :server_name) do
      nil -> GenServer.start_link(__MODULE__, opts)
      name -> GenServer.start_link(__MODULE__, opts, name: name)
    end
  end

  @doc """
  Run an MCU method. `{:ok, return_val}` / `{:error, reason}`; `{:error, :mcu_down}`
  when the channel has no event queue (unreachable server).
  """
  @spec call(t, String.t(), [term]) :: {:ok, [term]} | {:error, term}
  def call(client, method, params \\ []) do
    GenServer.call(client, {:rpc, method, params}, @call_timeout_ms)
  catch
    # a dead or wedged channel is a down MCU, never a caller crash
    :exit, _ -> {:error, :mcu_down}
  end

  @doc """
  Create an object and return its id (`CreateConference`, `CreateParticipant`):
  `call/3` plus the negative-id check of `XmlRpc.created_id/1`.
  """
  @spec create(t, String.t(), [term]) :: {:ok, non_neg_integer} | {:error, term}
  def create(client, method, params), do: XmlRpc.created_id(call(client, method, params))

  @doc "Channel state: `%{name, base_url, queue_id, status}`."
  @spec info(t) :: map
  def info(client), do: GenServer.call(client, :info)

  @doc "The event-queue id, or `nil` while the MCU is unreachable."
  @spec queue_id(t) :: non_neg_integer | nil
  def queue_id(client), do: info(client).queue_id

  @doc """
  The server's DTLS fingerprint for `hash`, fetched once and cached: it is
  server-wide, not per participant (§2, `GetLocalCryptoDTLSFingerprint`).
  """
  @spec dtls_fingerprint(t, String.t()) :: {:ok, String.t()} | {:error, term}
  def dtls_fingerprint(client, hash \\ "SHA-256") do
    GenServer.call(client, {:dtls_fingerprint, hash}, @call_timeout_ms)
  catch
    :exit, _ -> {:error, :mcu_down}
  end

  # ── GenServer ────────────────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    state = %{
      name: Keyword.get(opts, :name, "mcu"),
      base_url: Keyword.get(opts, :base_url),
      timeout_ms: Keyword.get(opts, :timeout_ms, 10_000),
      transport: Keyword.get(opts, :transport),
      register: Keyword.get(opts, :register),
      reconnect_ms: Keyword.get(opts, :reconnect_ms, @reconnect_ms),
      queue_id: nil,
      status: :down,
      # health transitions are only pushed once the registry knows this channel
      # exists: before that, `announce/1` carries both the pid and the status
      announced?: false,
      fingerprints: %{}
    }

    # The synchronous RPCs run on httpc's default profile: raise its per-host
    # session pool so concurrent legs don't queue behind the default of 2.
    if is_nil(state.transport), do: :httpc.set_options(max_sessions: 100)

    {:ok, connect(state), {:continue, :announce}}
  end

  @impl true
  # Tell the registry who we are, *always* — including when we came up `down`.
  # Health transitions alone would not do: an MCU unreachable at boot never
  # transitions, and the registry would hold no channel to reach it with once it
  # recovers.
  def handle_continue(:announce, state) do
    announce(state)
    {:noreply, %{state | announced?: true}}
  end

  @impl true
  def handle_call(:info, _from, state) do
    {:reply, Map.take(state, [:name, :base_url, :queue_id, :status]), state}
  end

  def handle_call({:rpc, method, params}, _from, state) do
    if state.status == :up do
      {result, state} = rpc(state, method, params)
      {:reply, result, state}
    else
      {:reply, {:error, :mcu_down}, state}
    end
  end

  def handle_call({:dtls_fingerprint, hash}, _from, state) do
    case Map.fetch(state.fingerprints, hash) do
      {:ok, fingerprint} ->
        {:reply, {:ok, fingerprint}, state}

      :error ->
        case rpc(state, "GetLocalCryptoDTLSFingerprint", [hash]) do
          {{:ok, [fingerprint | _]}, state} when is_binary(fingerprint) ->
            {:reply, {:ok, fingerprint},
             %{state | fingerprints: Map.put(state.fingerprints, hash, fingerprint)}}

          {{:ok, other}, state} ->
            {:reply, {:error, {:unexpected_return, other}}, state}

          {{:error, _} = err, state} ->
            {:reply, err, state}
        end
    end
  end

  @impl true
  def handle_info(:reconnect, state) do
    {:noreply, connect(state)}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{status: :up, queue_id: queue_id} = state) when not is_nil(queue_id) do
    # best effort: a server that already went away must not turn a clean stop
    # into a crash
    rpc(state, "EventQueueDelete", [queue_id])
    :ok
  end

  def terminate(_reason, _state), do: :ok

  # ── connection / health ──────────────────────────────────────────────────────

  # The event queue is what makes a channel usable: it is created once here and
  # passed to every CreateConference, so events can be routed back.
  defp connect(state) do
    case rpc(%{state | status: :up}, "EventQueueCreate", []) do
      {{:ok, [queue_id | _]}, state} when is_integer(queue_id) and queue_id >= 0 ->
        Logger.info(
          module: __MODULE__,
          message: "mcu #{state.name} up (#{state.base_url}), event queue #{queue_id}"
        )

        mark(%{state | queue_id: queue_id}, :up)

      {{:ok, other}, state} ->
        Logger.error(
          module: __MODULE__,
          message: "mcu #{state.name}: unexpected EventQueueCreate return #{inspect(other)}"
        )

        schedule_reconnect(mark(%{state | queue_id: nil}, :down))

      {{:error, reason}, state} ->
        Logger.error(
          module: __MODULE__,
          message: "mcu #{state.name} unreachable (#{state.base_url}): #{inspect(reason)}"
        )

        schedule_reconnect(mark(%{state | queue_id: nil}, :down))
    end
  end

  defp schedule_reconnect(state) do
    if state.reconnect_ms > 0, do: Process.send_after(self(), :reconnect, state.reconnect_ms)
    state
  end

  # Health transitions are pushed to the owner (the module) rather than polled:
  # `admit/2` must answer 503 on a down MCU without an RPC round-trip per INVITE.
  defp mark(state, status) do
    if status != state.status and state.announced? do
      notify(state, status)
    end

    %{state | status: status}
  end

  defp notify(%{register: {module, name}} = state, status) do
    send(module, {:mcu_health, name, status, %{queue_id: state.queue_id}})
  end

  defp notify(_state, _status), do: :ok

  defp announce(%{register: {module, name}} = state) do
    send(module, {:mcu_client, name, self(), state.status, %{queue_id: state.queue_id}})
  end

  defp announce(_state), do: :ok

  # ── RPC ──────────────────────────────────────────────────────────────────────

  # A transport error means the channel is gone, so it also flips the health flag;
  # an applicative error ({:mcu_error, _}) does not — the server answered.
  defp rpc(state, method, params) do
    started = System.monotonic_time()

    result =
      case state.transport do
        nil -> XmlRpc.call(state.base_url, method, params, timeout_ms: state.timeout_ms)
        fun when is_function(fun, 2) -> fun.(method, params)
      end

    # §11: how long the media server takes to answer each method, per method. This is
    # the first thing to look at when calls get slow to set up, since every leg's
    # setup is a handful of these in series.
    Kelix.Metrics.Emit.mcu_rpc(method, System.monotonic_time() - started)

    case result do
      {:ok, _} = ok ->
        {ok, state}

      {:error, {:mcu_error, msg}} = err ->
        Logger.warning(module: __MODULE__, message: "mcu #{state.name}: #{method}: #{msg}")
        Kelix.Metrics.Emit.mcu_rpc_error(method, :mcu_error)
        {err, state}

      {:error, reason} = err ->
        Logger.error(
          module: __MODULE__,
          message: "mcu #{state.name}: #{method} failed: #{inspect(reason)}"
        )

        Kelix.Metrics.Emit.mcu_rpc_error(method, error_label(reason))
        {err, transport_lost(state, method)}
    end
  end

  # A **bounded** label: the reason's shape, never the server's message or an
  # `:inet` tuple, either of which would give the metric unbounded cardinality. The
  # detail is one log line above.
  defp error_label(reason) when is_atom(reason), do: reason
  defp error_label({:failed_connect, _}), do: :unreachable

  defp error_label(reason) when is_tuple(reason) and tuple_size(reason) > 0 do
    case elem(reason, 0) do
      atom when is_atom(atom) -> atom
      _ -> :unknown
    end
  end

  defp error_label(_reason), do: :unknown

  # EventQueueCreate failing during connect/1 is handled there (it must not
  # schedule two reconnects), so only in-service failures land here.
  defp transport_lost(state, "EventQueueCreate"), do: state

  defp transport_lost(state, _method),
    do: schedule_reconnect(mark(%{state | queue_id: nil}, :down))
end
