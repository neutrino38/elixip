defmodule Elixip.RegistrarUAS do
  @moduledoc """
  Registration processing module used by the `elixipp` tool when it runs a
  `:uas_register` scenario. It implements the `SIP.Session.Registrar` behaviour
  and acts as a factory of scenario instances, enforcing a concurrency quota.

  On each inbound REGISTER the dialog layer calls `on_new_registration/3`. This
  module:

    * rejects with `503 Service Unavailable` when `max_instances` concurrent
      scenario instances are already running;
    * otherwise spawns one scenario instance (via
      `SIP.Scenario.Runner.spawn_uas_instance/2`) bound to the new dialog and
      returns `{:accept, instance_pid}`.

  Instances are monitored; their slot is freed when they terminate.
  """
  @behaviour SIP.Session.Registrar
  use GenServer
  require Logger

  defstruct scenario_module: nil,
            max_instances: 1,
            instances: %{},
            total_started: 0,
            total_rejected_quota: 0

  # ── Public API ──────────────────────────────────────────────────────────

  @doc """
  Start the registrar. Required options:
    * `:scenario_module` — the `:uas_register` scenario module to instantiate;
    * `:max_instances`   — maximum concurrent instances (REGISTER rejected with
      503 beyond this).
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Return runtime counters (for the --monitor view and tests)."
  @spec stats() :: %{
          active: non_neg_integer(),
          total_started: non_neg_integer(),
          total_rejected_quota: non_neg_integer()
        }
  def stats, do: GenServer.call(__MODULE__, :stats)

  # ── SIP.Session.Registrar behaviour ──────────────────────────────────────

  @impl SIP.Session.Registrar
  def on_new_registration(dialog_id, registerreq, transaction_id) do
    GenServer.call(__MODULE__, {:new_registration, dialog_id, registerreq, transaction_id})
  end

  @impl SIP.Session.Registrar
  def on_registration_expired(dialog_id, app_pid) do
    GenServer.cast(__MODULE__, {:registration_expired, dialog_id, app_pid})
  end

  # ── GenServer callbacks ───────────────────────────────────────────────────

  @impl GenServer
  def init(opts) do
    state = %__MODULE__{
      scenario_module: Keyword.fetch!(opts, :scenario_module),
      max_instances: Keyword.get(opts, :max_instances, 1)
    }

    {:ok, state}
  end

  @impl GenServer
  def handle_call({:new_registration, dialog_id, registerreq, _transaction_id}, _from, state) do
    if map_size(state.instances) >= state.max_instances do
      Logger.warning(
        "RegistrarUAS: quota reached (#{state.max_instances}), rejecting REGISTER with 503"
      )

      {:reply, {:reject, 503, "Service Unavailable"},
       %{state | total_rejected_quota: state.total_rejected_quota + 1}}
    else
      {pid, ref} =
        SIP.Scenario.Runner.spawn_uas_instance(state.scenario_module,
          dialog_pid: dialog_id,
          parent_pid: self(),
          inbound_request: registerreq
        )

      instances = Map.put(state.instances, ref, %{pid: pid, dialog_id: dialog_id})

      Logger.debug(
        "RegistrarUAS: accepted REGISTER, instance #{inspect(pid)} (#{map_size(instances)} active)"
      )

      {:reply, {:accept, pid},
       %{state | instances: instances, total_started: state.total_started + 1}}
    end
  end

  def handle_call(:stats, _from, state) do
    {:reply,
     %{
       active: map_size(state.instances),
       total_started: state.total_started,
       total_rejected_quota: state.total_rejected_quota
     }, state}
  end

  @impl GenServer
  def handle_cast({:registration_expired, dialog_id, _app_pid}, state) do
    Logger.debug("RegistrarUAS: registration expired for dialog #{inspect(dialog_id)}")
    {:noreply, state}
  end

  @impl GenServer
  # A scenario instance terminated (normally or not): free its slot.
  def handle_info({:DOWN, ref, :process, pid, reason}, state) do
    case Map.pop(state.instances, ref) do
      {nil, _} ->
        {:noreply, state}

      {_info, instances} ->
        Logger.debug(
          "RegistrarUAS: instance #{inspect(pid)} ended (#{inspect(reason)}), #{map_size(instances)} active"
        )

        {:noreply, %{state | instances: instances}}
    end
  end

  # Lifecycle notification from the instance finalizer; the :DOWN message already
  # frees the slot, so this is only logged.
  def handle_info({:scenario_exit, _name, outcome, reason}, state) do
    Logger.debug("RegistrarUAS: scenario_exit #{inspect(outcome)} (#{inspect(reason)})")
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl GenServer
  # When the registrar stops, cooperatively shut down every running instance
  # (same mechanism as the DSL sub-FSM shutdown). Instances handle
  # {:scenario_ctl, :shutdown, _} via the clause auto-injected into on_events.
  def terminate(reason, state) do
    Enum.each(state.instances, fn {_ref, %{pid: pid}} ->
      send(pid, {:scenario_ctl, :shutdown, reason})
    end)

    :ok
  end
end
