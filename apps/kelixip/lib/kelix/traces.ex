defmodule Kelix.Traces do
  @moduledoc """
  The journals an operator asked for, kept in memory, **unrendered**.

  `kelictl debug <id> on` turns the journal of a live scenario on
  (`Kelix.Control.debug_scenario/2`). It is written when the scenario ends, or
  at once with `kelictl debug <id> off`, and lands here through
  `SIP.FSL.Host.journal_events/2`: `Kelix.Config` names `store/2` as the node's
  `:sequence_output`.

  What is kept is the journal itself — the `FSL.Journal` events, SIP messages
  included, and the run's metadata — never a drawing of it. Each reader draws
  it its own way: `kelictl debug show` as a text ladder or PlantUML, kelescope
  as a popup. This module stores, bounds, expires and tells; it renders and
  interprets nothing.

  **One journal per instance**, filed under the instance id `kelictl monitor`
  prints. FSL starts no journal again in a run after `off`, so an instance
  flushes at most once; `has?/1` lets the control layer refuse a second `on`
  rather than accept one FSL would ignore.

  **Memory only.** A journal is kept `[debug] trace_retention` seconds after it
  was written (3600 by default), `[debug] max_traces` of them at most (100), the
  oldest dropped first, and each is cut at `[debug] max_trace_bytes` of message
  text (1 MiB) with a `:cut` event, as Trix does. A restart loses them all: they
  are an operator's working material, not a record.

  **Pushes.** `subscribe/1` returns the snapshot and then sends
  `{:kelix_traces, {:upsert, summary}}` when a journal is kept and again when
  its instance ends, and `{:kelix_traces, {:remove, id}}` when it expires or is
  evicted.
  """
  use GenServer
  require Logger

  @typedoc "A kept journal, as `summary/1` shows it (no events, no metadata)."
  @type summary :: %{
          id: pos_integer,
          scenario: String.t(),
          domain: String.t() | nil,
          script: String.t() | nil,
          written_at: DateTime.t(),
          expires_at: DateTime.t(),
          running: boolean,
          sip_count: non_neg_integer,
          bytes: non_neg_integer
        }

  # What an event costs besides its message text, in the byte count: small, but
  # a journal of a thousand state changes is not free either.
  @event_overhead 64

  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts \\ []) do
    # `name: nil` starts an unregistered store, which a test drives by pid.
    case Keyword.get(opts, :name, __MODULE__) do
      nil -> GenServer.start_link(__MODULE__, opts)
      name -> GenServer.start_link(__MODULE__, opts, name: name)
    end
  end

  @doc """
  Keep a finished journal — the node's `:sequence_output`, called by
  `SIP.FSL.Host.journal_events/2` in the scenario's own process. Answers what
  `c:FSL.Host.journal_events/2` expects.

  A run the pool did not start has no instance id to be filed under (a child
  machine's slot is `{id, name}`): it is not kept, and the answer says so.
  """
  @spec store([map], map, GenServer.server()) :: {:ok, term} | {:error, term}
  def store(events, meta, server \\ __MODULE__) do
    case Map.get(meta, :slot) do
      id when is_integer(id) -> GenServer.call(server, {:store, id, events, meta, self()})
      _other -> {:error, :no_instance_id}
    end
  catch
    :exit, reason -> {:error, {:trace_store_unavailable, reason}}
  end

  @doc "The kept journals, oldest first, as summaries."
  @spec list(GenServer.server()) :: [summary]
  def list(server \\ __MODULE__), do: GenServer.call(server, :list)

  @doc "The journal of instance `id`: its summary, `meta` and `events`."
  @spec get(pos_integer, GenServer.server()) :: {:ok, map} | {:error, :not_found}
  def get(id, server \\ __MODULE__), do: GenServer.call(server, {:get, id})

  @doc "Is a journal kept for instance `id`?"
  @spec has?(pos_integer, GenServer.server()) :: boolean
  def has?(id, server \\ __MODULE__), do: GenServer.call(server, {:has?, id})

  @doc "The retention (seconds), capacity and per-journal bound this store runs with."
  @spec limits(GenServer.server()) :: map
  def limits(server \\ __MODULE__), do: GenServer.call(server, :limits)

  @doc """
  Subscribe `pid` to the kept journals: returns `%{limits: …, traces: [summary]}`
  and registers `pid` in the same call, so no change falls in between. `pid` is
  monitored and dropped when it dies — a kelescope node that disconnects
  included.
  """
  @spec subscribe(pid, GenServer.server()) :: %{limits: map, traces: [summary]}
  def subscribe(pid, server \\ __MODULE__), do: GenServer.call(server, {:subscribe, pid})

  @doc "Stop a subscription started by `subscribe/1`."
  @spec unsubscribe(pid, GenServer.server()) :: :ok
  def unsubscribe(pid, server \\ __MODULE__), do: GenServer.call(server, {:unsubscribe, pid})

  # ── server ──────────────────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    limits =
      Keyword.get_lazy(opts, :limits, fn ->
        try do
          Kelix.Config.current().debug
        catch
          :exit, _ -> %Kelix.Config{}.debug
        end
      end)

    limits = Map.merge(%Kelix.Config{}.debug, limits)

    {:ok, %{limits: limits, entries: %{}, subscribers: %{}}}
  end

  @impl true
  def handle_call({:store, id, events, meta, from_pid}, _from, state) do
    if Map.has_key?(state.entries, id) do
      Logger.warning(
        module: __MODULE__,
        message: "a second journal for instance #{id}: it replaces the first"
      )
    end

    {events, bytes} = bound(events, state.limits.max_trace_bytes)
    row = instance_row(id)
    now = DateTime.utc_now()

    entry = %{
      id: id,
      scenario: Map.get(meta, :scenario),
      domain: row && row.domain,
      script: row && row.script,
      pid: from_pid,
      monitor: Process.monitor(from_pid),
      written_at: now,
      written_ms: now_ms(),
      expires_at: DateTime.add(now, state.limits.trace_retention, :second),
      sip_count: Enum.count(events, &match?(%{kind: :message}, &1)),
      bytes: bytes,
      meta: meta,
      events: events
    }

    state = drop_monitor(state, Map.get(state.entries, id))

    Process.send_after(
      self(),
      {:expire, id, entry.written_ms},
      state.limits.trace_retention * 1000
    )

    state =
      %{state | entries: Map.put(state.entries, id, entry)}
      |> evict()

    push(state, {:upsert, summary(entry)})

    Logger.info(
      module: __MODULE__,
      message:
        "journal of instance #{id} (#{entry.scenario}) kept in memory: " <>
          "#{entry.sip_count} SIP messages, #{bytes} bytes"
    )

    {:reply, {:ok, {:kelix_trace, id}}, state}
  end

  def handle_call(:list, _from, state), do: {:reply, summaries(state), state}

  def handle_call({:get, id}, _from, state) do
    reply =
      case Map.fetch(state.entries, id) do
        {:ok, entry} ->
          {:ok, Map.merge(summary(entry), %{meta: entry.meta, events: entry.events})}

        :error ->
          {:error, :not_found}
      end

    {:reply, reply, state}
  end

  def handle_call({:has?, id}, _from, state),
    do: {:reply, Map.has_key?(state.entries, id), state}

  def handle_call(:limits, _from, state), do: {:reply, state.limits, state}

  def handle_call({:subscribe, pid}, _from, state) do
    subscribers =
      if Map.has_key?(state.subscribers, pid),
        do: state.subscribers,
        else: Map.put(state.subscribers, pid, Process.monitor(pid))

    state = %{state | subscribers: subscribers}
    {:reply, %{limits: state.limits, traces: summaries(state)}, state}
  end

  def handle_call({:unsubscribe, pid}, _from, state) do
    case Map.pop(state.subscribers, pid) do
      {nil, _} ->
        {:reply, :ok, state}

      {ref, subscribers} ->
        Process.demonitor(ref, [:flush])
        {:reply, :ok, %{state | subscribers: subscribers}}
    end
  end

  @impl true
  # Only the timer of the journal it was armed for: a replaced entry has another.
  def handle_info({:expire, id, written_ms}, state) do
    case Map.get(state.entries, id) do
      %{written_ms: ^written_ms} = entry -> {:noreply, remove(state, entry)}
      _other -> {:noreply, state}
    end
  end

  def handle_info({:DOWN, ref, :process, pid, _reason}, state) do
    case Map.pop(state.subscribers, pid) do
      {^ref, subscribers} ->
        {:noreply, %{state | subscribers: subscribers}}

      _not_a_subscriber ->
        # An instance whose journal is kept has ended: say so once.
        case Enum.find(Map.values(state.entries), &(&1.monitor == ref)) do
          nil ->
            {:noreply, state}

          entry ->
            entry = %{entry | monitor: nil}
            state = %{state | entries: Map.put(state.entries, entry.id, entry)}
            push(state, {:upsert, summary(entry)})
            {:noreply, state}
        end
    end
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ── internals ───────────────────────────────────────────────────────────────

  defp summary(entry) do
    entry
    |> Map.take([:id, :scenario, :domain, :script, :written_at, :expires_at, :sip_count, :bytes])
    |> Map.put(:running, entry.monitor != nil)
  end

  defp summaries(state) do
    state.entries |> Map.values() |> Enum.sort_by(& &1.written_ms) |> Enum.map(&summary/1)
  end

  # The oldest go first, past max_traces.
  defp evict(state) do
    excess = map_size(state.entries) - state.limits.max_traces

    if excess > 0 do
      state.entries
      |> Map.values()
      |> Enum.sort_by(& &1.written_ms)
      |> Enum.take(excess)
      |> Enum.reduce(state, &remove(&2, &1))
    else
      state
    end
  end

  defp remove(state, entry) do
    state = drop_monitor(state, entry)
    state = %{state | entries: Map.delete(state.entries, entry.id)}
    push(state, {:remove, entry.id})
    state
  end

  defp drop_monitor(state, %{monitor: ref}) when is_reference(ref) do
    Process.demonitor(ref, [:flush])
    state
  end

  defp drop_monitor(state, _entry), do: state

  defp push(state, msg) do
    for pid <- Map.keys(state.subscribers), do: send(pid, {:kelix_traces, msg})
    :ok
  end

  # Keep the head of the journal up to `max` bytes of message text, then a :cut.
  defp bound(events, max) do
    {kept, bytes, cut?} =
      Enum.reduce_while(events, {[], 0, false}, fn event, {acc, bytes, _cut} ->
        cost = @event_overhead + body_size(event)

        if bytes + cost > max,
          do: {:halt, {acc, bytes, true}},
          else: {:cont, {[event | acc], bytes + cost, false}}
      end)

    kept =
      if cut? do
        at =
          case kept do
            [%{at: at} | _] -> at
            _ -> Map.get(List.first(events) || %{}, :at, 0)
          end

        [%{kind: :cut, at: at} | kept]
      else
        kept
      end

    {Enum.reverse(kept), bytes}
  end

  defp body_size(%{body: body}) when is_binary(body), do: byte_size(body)
  defp body_size(_event), do: 0

  # Which domain and script the instance serves, while it is still registered —
  # it is: a journal is written from the instance's own process, before it exits.
  defp instance_row(id) do
    Enum.find(Kelix.InstancePool.list(), &(&1.id == id))
  catch
    :exit, _ -> nil
  end

  defp now_ms, do: System.monotonic_time(:millisecond)
end
