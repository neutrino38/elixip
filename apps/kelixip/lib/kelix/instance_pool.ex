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

  # instances: ref => %{id, pid, dialog_id, domain, function, script, version}
  # per_domain: domain => active count
  # next_id:    monotonic id handed to each instance (stable handle for `shutdown/1`)
  defstruct instances: %{},
            per_domain: %{},
            total_active: 0,
            next_id: 1,
            counters: %{started: 0, succeeded: 0, aborted: 0, failed: 0, rejected_quota: 0}

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

  # ── GenServer ────────────────────────────────────────────────────────────────

  @impl true
  def init(_opts), do: {:ok, %__MODULE__{}}

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
    rows =
      for {_ref, i} <- state.instances,
          do: %{id: i.id, pid: i.pid, domain: i.domain, function: i.function, script: i.script}

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
        {:noreply, state}

      {inst, instances} ->
        ScriptRegistry.checkin(inst.script, inst.version)
        # Free the FSM monitor row (and those of any spawn_fsm children) — otherwise
        # a busy registrar accumulates one row per registration, forever.
        SIP.Scenario.Monitor.clear(inst.id)

        Logger.debug(
          module: __MODULE__,
          message: "instance #{inspect(pid)} ended (#{inspect(reason)})"
        )

        {:noreply,
         %{
           state
           | instances: instances,
             per_domain: dec(state.per_domain, inst.domain),
             total_active: state.total_active - 1
         }}
    end
  end

  # outcome notification from the instance finalizer (slot already freed by :DOWN)
  def handle_info({:scenario_exit, _name, outcome, _reason}, state) do
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

        {:reply, {:accept, pid}, bump(state2, :started)}
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
