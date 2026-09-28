defmodule Kelix.InstancePool do
  @moduledoc """
  Shared instance factory: quota + spawn + monitoring + cooperative-shutdown,
  keyed by `(domain, function)` (design §4.2, §16 #1). Generalizes the machinery
  of `Elixip.ScenarioUAS` to multi-domain, script-per-rule dispatch — the
  `Kelix.Router` callbacks resolve a request then hand it here.

  On `accept/4`: enforce the per-domain `max_calls` then the server `max_calls`
  (503 beyond), check out the script's current version from `Kelix.ScriptRegistry`
  (refcount++), spawn one monitored scenario instance
  (`SIP.Scenario.Runner.spawn_uas_instance/2`) and reply `{:accept, pid}`. When an
  instance ends (`:DOWN`) its slot is freed and the script version checked back in.

  Also the live half of `Kelix.Control.subscribe_monitor/1`: subscribes to
  `FSL.Monitor` once at boot and re-joins its pushes with its own rows
  (`join_row/2`, the same join `Kelix.Control.monitor/0` runs on every read),
  forwarding `{:kelix_monitor, {:upsert, row}}` / `{:remove, id}` to whoever
  called `subscribe_monitor/1`.

  Also the active-calls half of `Kelix.Control.subscribe_domain_counters/1`:
  `per_domain` changes on every `accept/4` and every instance's `:DOWN`, and
  each change is pushed as `{:kelix_domain_counter, domain, :active_calls,
  count}` to whoever called `subscribe_domain_counters/1` — same subscriber
  bookkeeping as the monitor subscription, kept in its own set since a
  subscriber may want one push without the other.
  """
  use GenServer
  require Logger

  alias Kelix.{ScriptRegistry, Config}

  @type route :: %{
          domain: String.t(),
          function: atom,
          script: String.t(),
          max_calls: pos_integer | nil
        }

  # instances:    ref => %{id, pid, dialog_id, domain, function, script, version}
  # per_domain:   domain => active count
  # next_id:      monotonic id handed to each instance (stable handle for `shutdown/1`)
  # monitor_subs: MapSet(pid) subscribed via `subscribe_monitor/1`
  # monitor_mons: monitor_ref => subscriber pid, so a dead/disconnected subscriber
  #               is dropped without an explicit `unsubscribe_monitor/1`
  # counter_subs / counter_mons: same bookkeeping, for `subscribe_domain_counters/1`
  defstruct instances: %{},
            per_domain: %{},
            total_active: 0,
            next_id: 1,
            counters: %{started: 0, succeeded: 0, aborted: 0, failed: 0, rejected_quota: 0},
            monitor_subs: MapSet.new(),
            monitor_mons: %{},
            counter_subs: MapSet.new(),
            counter_mons: %{}

  # The three call-shape columns default to a value, not to a blank — same
  # defaults and rationale as `FSL.Monitor`'s own, for the row it
  # has nothing on (a scenario that only just appeared, or one the monitor lost).
  @empty_fsm %{
    scenario: "",
    state: "",
    event: "",
    command: "",
    account: "",
    medias: "n/a",
    mediaserver: "none",
    outbound: "n/a",
    # the instance's journal is on right now (kelictl debug, kelescope)
    traced: false
  }

  @fsm_keys [
    :scenario,
    :state,
    :event,
    :command,
    :account,
    :medias,
    :mediaserver,
    :outbound,
    :traced
  ]

  # ── API ──────────────────────────────────────────────────────────────────────

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc "Reserve a slot and spawn an instance for `route`. `{:accept, pid}` / `{:reject, code, reason}`."
  @spec accept(route, pid | nil, map, keyword) :: {:accept, pid} | {:reject, integer, String.t()}
  def accept(route, dialog_id, req, overrides \\ []),
    do: GenServer.call(__MODULE__, {:accept, route, dialog_id, req, overrides})

  @doc "Runtime counters (for --monitor / status / tests)."
  def stats(), do: GenServer.call(__MODULE__, :stats)

  @doc "Cooperatively shut down every running instance."
  def shutdown_all(reason \\ :node_shutdown),
    do: GenServer.cast(__MODULE__, {:shutdown_all, reason})

  @doc "Running instances, one row per instance (for `Kelix.Control` / status / CLI)."
  @spec list() :: [
          %{id: pos_integer, pid: pid, domain: String.t(), function: atom, script: String.t()}
        ]
  def list(), do: GenServer.call(__MODULE__, :list)

  @doc "Cooperatively shut down one instance by its `id` (from `list/0`). `:ok` / `{:error, :not_found}`."
  @spec shutdown(pos_integer, term) :: :ok | {:error, :not_found}
  def shutdown(id, reason \\ :operator), do: GenServer.call(__MODULE__, {:shutdown, id, reason})

  @doc """
  Turn the sequence journal of one running instance on (`:on`) or write it out
  now (`:off`) — `{:scenario_ctl, :journal, op}`, which every `on_events` wait
  takes without leaving it. `:ok` / `{:error, :not_found}`.
  """
  @spec journal(pos_integer, :on | :off) :: :ok | {:error, :not_found}
  def journal(id, op) when op in [:on, :off], do: GenServer.call(__MODULE__, {:journal, id, op})

  @doc """
  Subscribe `pid` to live joined rows **and return the snapshot** — the
  sanctioned entry point is `Kelix.Control.subscribe_monitor/1`, which is now
  this one call. `pid` gets `{:kelix_monitor, {:upsert, row}}` (rows in
  `monitor/0`'s shape) as an instance appears or its FSM fields change, and
  `{:kelix_monitor, {:remove, id}}` when it ends. `pid` is monitored, so a dead
  or disconnected subscriber is dropped on its own.

  Registering and snapshotting in one call is what closes the window: a change
  landing between two separate calls would have to arrive as a push *and* in the
  snapshot to be safe, and that only holds for one of the two orders. One call
  has no order to get wrong. `FSL.Monitor.subscribe/1` states the same contract
  one layer down, which is where the FSM half of these rows comes from.
  """
  @spec subscribe_monitor(pid()) :: [map]
  def subscribe_monitor(pid), do: GenServer.call(__MODULE__, {:subscribe_monitor, pid})

  @doc "Stop a subscription started by `subscribe_monitor/1`."
  @spec unsubscribe_monitor(pid()) :: :ok
  def unsubscribe_monitor(pid), do: GenServer.call(__MODULE__, {:unsubscribe_monitor, pid})

  @doc """
  Subscribe `pid` to active-calls-per-domain changes — the sanctioned entry
  point is `Kelix.Control.subscribe_domain_counters/1`. `pid` gets
  `{:kelix_domain_counter, domain, :active_calls, count}` each time a domain's
  active-call count changes; monitored like `subscribe_monitor/1`.
  """
  @spec subscribe_domain_counters(pid()) :: :ok
  def subscribe_domain_counters(pid), do: GenServer.call(__MODULE__, {:subscribe_counters, pid})

  @doc "Stop a subscription started by `subscribe_domain_counters/1`."
  @spec unsubscribe_domain_counters(pid()) :: :ok
  def unsubscribe_domain_counters(pid),
    do: GenServer.call(__MODULE__, {:unsubscribe_counters, pid})

  @doc """
  Join one `list/0` row with its `FSL.Monitor.calls/0` entry (`nil` when
  there is none yet, or a sub-FSM slot the pool does not key on — see
  `Kelix.Control.monitor/0`). Public so this module can run the join live, once
  per pushed change, instead of `Kelix.Control.monitor/0` re-reading everything.
  """
  @spec join_row(map, map | nil) :: map
  def join_row(row, nil), do: Map.merge(row, @empty_fsm)

  def join_row(row, fsm_entry),
    do: Map.merge(row, Map.merge(@empty_fsm, Map.take(fsm_entry, @fsm_keys)))

  # ── GenServer ────────────────────────────────────────────────────────────────

  @impl true
  def init(_opts) do
    FSL.Monitor.subscribe(self())
    {:ok, %__MODULE__{}}
  end

  @impl true
  def handle_call({:accept, route, dialog_id, req, overrides}, _from, state) do
    %{domain: domain, function: function, script: script, max_calls: dmax} = route
    server_max = server_max_calls()

    cond do
      is_integer(server_max) and state.total_active >= server_max ->
        Logger.warning(module: __MODULE__, message: "server max_calls #{server_max} reached; 503")
        {:reply, {:reject, 503, "Service Unavailable"}, bump(state, :rejected_quota)}

      is_integer(dmax) and Map.get(state.per_domain, domain, 0) >= dmax ->
        Logger.warning(
          module: __MODULE__,
          message: "domain #{domain} max_calls #{dmax} reached; 503"
        )

        {:reply, {:reject, 503, "Service Unavailable"}, bump(state, :rejected_quota)}

      true ->
        spawn_instance(state, route, function, domain, script, dialog_id, req, overrides)
    end
  end

  def handle_call(:stats, _from, state), do: {:reply, stats_map(state), state}

  def handle_call(:list, _from, state) do
    rows = for {_ref, i} <- state.instances, do: to_list_row(i)
    {:reply, Enum.sort_by(rows, & &1.id), state}
  end

  def handle_call({:shutdown, id, reason}, _from, state) do
    case Enum.find(Map.values(state.instances), &(&1.id == id)) do
      nil ->
        {:reply, {:error, :not_found}, state}

      inst ->
        send(inst.pid, {:scenario_ctl, :shutdown, reason})
        {:reply, :ok, state}
    end
  end

  def handle_call({:journal, id, op}, _from, state) do
    case find_instance(state, id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      inst ->
        send(inst.pid, {:scenario_ctl, :journal, op})
        {:reply, :ok, state}
    end
  end

  def handle_call({:subscribe_monitor, pid}, _from, state) do
    state =
      if MapSet.member?(state.monitor_subs, pid) do
        state
      else
        ref = Process.monitor(pid)

        %{
          state
          | monitor_subs: MapSet.put(state.monitor_subs, pid),
            monitor_mons: Map.put(state.monitor_mons, ref, pid)
        }
      end

    {:reply, joined_rows(state), state}
  end

  def handle_call({:unsubscribe_monitor, pid}, _from, state) do
    {:reply, :ok, drop_monitor_sub(state, pid)}
  end

  def handle_call({:subscribe_counters, pid}, _from, state) do
    if MapSet.member?(state.counter_subs, pid) do
      {:reply, :ok, state}
    else
      ref = Process.monitor(pid)

      state = %{
        state
        | counter_subs: MapSet.put(state.counter_subs, pid),
          counter_mons: Map.put(state.counter_mons, ref, pid)
      }

      {:reply, :ok, state}
    end
  end

  def handle_call({:unsubscribe_counters, pid}, _from, state) do
    {:reply, :ok, drop_counter_sub(state, pid)}
  end

  @impl true
  def handle_cast({:shutdown_all, reason}, state) do
    broadcast_shutdown(state, reason)
    {:noreply, state}
  end

  @impl true
  # instance terminated: free its slot + check the script version back in
  def handle_info({:DOWN, ref, :process, pid, reason}, state) do
    case Map.pop(state.instances, ref) do
      {nil, _} ->
        {:noreply, state |> drop_monitor_sub_by_ref(ref) |> drop_counter_sub_by_ref(ref)}

      {inst, instances} ->
        ScriptRegistry.checkin(inst.script, inst.version)
        # Free the FSM monitor row (and those of any spawn_fsm children) — otherwise
        # a busy registrar accumulates one row per registration, forever. Also the
        # signal `subscribe_monitor/1`'s subscribers get told this row is gone
        # (`{:fsl_monitor, {:cleared, _}}` below).
        FSL.Monitor.clear(inst.id)

        Logger.debug(
          module: __MODULE__,
          message: "instance #{inspect(pid)} ended (#{inspect(reason)})"
        )

        per_domain = dec(state.per_domain, inst.domain)

        state = %{
          state
          | instances: instances,
            per_domain: per_domain,
            total_active: state.total_active - 1
        }

        broadcast_counter(state, inst.domain, :active_calls, Map.get(per_domain, inst.domain, 0))

        {:noreply, state}
    end
  end

  # `SIP.Scenario.Monitor` pushes (subscribed to at init/1): re-join with our own
  # row and forward to whoever called `subscribe_monitor/1`.
  def handle_info({:fsl_monitor, {:updated, slot, fsm_row}}, state) do
    with true <- is_integer(slot),
         inst when not is_nil(inst) <- find_instance(state, slot) do
      broadcast_monitor(state, {:upsert, join_row(to_list_row(inst), fsm_row)})
    end

    {:noreply, state}
  end

  # A {parent_slot, name} sub-FSM slot is not a row of ours (`monitor/0` does not
  # surface it either) — nothing to remove.
  def handle_info({:fsl_monitor, {:cleared, slot}}, state) do
    if is_integer(slot), do: broadcast_monitor(state, {:remove, slot})
    {:noreply, state}
  end

  # outcome notification from the instance finalizer (slot already freed by :DOWN)
  def handle_info({:child_exit, _name, outcome, _reason}, state) do
    key =
      case outcome do
        :success -> :succeeded
        :aborted -> :aborted
        _ -> :failed
      end

    {:noreply, bump(state, key)}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def terminate(reason, state) do
    broadcast_shutdown(state, reason)
    :ok
  end

  # ── internals ────────────────────────────────────────────────────────────────

  defp spawn_instance(state, _route, function, domain, script, dialog_id, req, overrides) do
    case ScriptRegistry.checkout(script) do
      {:error, reason} ->
        Logger.error(
          module: __MODULE__,
          message: "cannot load script #{inspect(script)}: #{inspect(reason)}"
        )

        {:reply, {:reject, 500, "Server Internal Error"}, state}

      {:ok, module, version} ->
        id = state.next_id

        {pid, ref} =
          SIP.Scenario.Runner.spawn_uas_instance(module,
            dialog_pid: dialog_id,
            parent_pid: self(),
            inbound_request: req,
            config_overrides: overrides,
            # Key the FSM monitor row on OUR id rather than the instance pid, so
            # `Kelix.Control.monitor/0` can join the two views — and so a `spawn_fsm`
            # child sorts right under its parent ({id, name}).
            slot_id: id
          )

        inst = %{
          id: id,
          pid: pid,
          dialog_id: dialog_id,
          domain: domain,
          function: function,
          script: script,
          version: version
        }

        state2 = %{
          state
          | instances: Map.put(state.instances, ref, inst),
            per_domain: Map.update(state.per_domain, domain, 1, &(&1 + 1)),
            total_active: state.total_active + 1,
            next_id: id + 1
        }

        # INFO, not debug, and it names the *module*: the script name comes from the
        # dial plan, the module is what actually runs. Two scripts that declare the
        # same `defmodule` compile to the same versioned BEAM module, so the two
        # differ — and that is the only place it shows.
        Logger.info(
          module: __MODULE__,
          message:
            "instance #{id}: #{function} on #{domain} script #{script} " <>
              "running #{inspect(module)} (v#{version}) → #{inspect(pid)}"
        )

        # A new row can show up before its first FSM report (design doc, "push
        # mechanism"): no fsm entry yet, so it degrades to the empty FSM columns.
        broadcast_monitor(state2, {:upsert, join_row(to_list_row(inst), nil)})
        broadcast_counter(state2, domain, :active_calls, Map.get(state2.per_domain, domain))

        {:reply, {:accept, pid}, bump(state2, :started)}
    end
  end

  # The snapshot `subscribe_monitor/1` answers with: this pool's rows joined with
  # the FSM view. Reading `FSL.Monitor` from inside a call of ours is safe — that
  # registry reads its own state and calls nobody — and subscribing is rare
  # enough that blocking the pool for one read costs nothing a caller will see.
  defp joined_rows(state) do
    fsm =
      case FSL.Monitor.calls() do
        rows when is_list(rows) -> Map.new(rows, &{&1.slot, &1})
        _other -> %{}
      end

    for inst <- Map.values(state.instances) do
      join_row(to_list_row(inst), Map.get(fsm, inst.id))
    end
  end

  defp to_list_row(i),
    do: %{id: i.id, pid: i.pid, domain: i.domain, function: i.function, script: i.script}

  defp find_instance(state, id), do: Enum.find(Map.values(state.instances), &(&1.id == id))

  defp broadcast_monitor(state, msg) do
    for pid <- state.monitor_subs, do: send(pid, {:kelix_monitor, msg})
    :ok
  end

  defp broadcast_counter(state, domain, kind, count) do
    for pid <- state.counter_subs, do: send(pid, {:kelix_domain_counter, domain, kind, count})
    :ok
  end

  defp drop_counter_sub(state, pid) do
    case Enum.find(state.counter_mons, fn {_ref, p} -> p == pid end) do
      nil ->
        state

      {ref, _pid} ->
        Process.demonitor(ref, [:flush])

        %{
          state
          | counter_subs: MapSet.delete(state.counter_subs, pid),
            counter_mons: Map.delete(state.counter_mons, ref)
        }
    end
  end

  defp drop_counter_sub_by_ref(state, ref) do
    case Map.pop(state.counter_mons, ref) do
      {nil, _} ->
        state

      {pid, mons} ->
        %{state | counter_mons: mons, counter_subs: MapSet.delete(state.counter_subs, pid)}
    end
  end

  defp drop_monitor_sub(state, pid) do
    case Enum.find(state.monitor_mons, fn {_ref, p} -> p == pid end) do
      nil ->
        state

      {ref, _pid} ->
        Process.demonitor(ref, [:flush])

        %{
          state
          | monitor_subs: MapSet.delete(state.monitor_subs, pid),
            monitor_mons: Map.delete(state.monitor_mons, ref)
        }
    end
  end

  defp drop_monitor_sub_by_ref(state, ref) do
    case Map.pop(state.monitor_mons, ref) do
      {nil, _} ->
        state

      {pid, mons} ->
        %{state | monitor_mons: mons, monitor_subs: MapSet.delete(state.monitor_subs, pid)}
    end
  end

  defp broadcast_shutdown(state, reason) do
    Enum.each(state.instances, fn {_ref, %{pid: pid}} ->
      send(pid, {:scenario_ctl, :shutdown, reason})
    end)
  end

  defp server_max_calls() do
    case Process.whereis(Config) do
      nil -> nil
      _ -> Config.current().max_calls
    end
  end

  defp bump(state, key), do: %{state | counters: Map.update!(state.counters, key, &(&1 + 1))}
  defp dec(map, domain), do: Map.update(map, domain, 0, &max(&1 - 1, 0))

  defp stats_map(state),
    do: Map.merge(%{active: state.total_active, per_domain: state.per_domain}, state.counters)
end
