defmodule Elixip.ScenarioUAS do
  @moduledoc """
  UAS scenario factory used by the `elixipp` tool when it runs a server scenario
  (`:uas_register` or `:uas_invite`). It is a single GenServer implementing **both**
  the `SIP.Session.Registrar` and the `SIP.Session.Call` behaviours, so the same
  quota / monitoring / stats machinery drives registrar and call servers.

  On each inbound request the dialog layer calls `on_new_registration/3`
  (REGISTER) or `on_new_call/3` (INVITE). This module:

    * for an INVITE, rejects with `604 Does Not Exist Anywhere` when the R-URI
      domain does not match the configured `domains` (`:any` = catch-all);
    * rejects with `503 Service Unavailable` when `max_instances` concurrent
      instances are already running, or `max_run` total runs have been reached;
    * otherwise spawns one scenario instance (via
      `SIP.Scenario.Runner.spawn_uas_instance/2`) bound to the new dialog and
      returns `{:accept, instance_pid}`.

  Instances are monitored; their slot is freed when they terminate.

  `Elixip.RegistrarUAS` is kept as a backward-compatible alias delegating to this
  module (see the bottom of this file).
  """
  @behaviour SIP.Session.Registrar
  @behaviour SIP.Session.Call
  use GenServer
  require Logger

  defstruct scenario_module: nil,
            max_instances: 1,
            max_run: nil,
            scenario_overrides: [],
            domains: :any,
            instances: %{},
            total_started: 0,
            total_succeeded: 0,
            total_aborted: 0,
            total_failed: 0,
            total_rejected_quota: 0,
            total_rejected_domain: 0

  # ── Public API ──────────────────────────────────────────────────────────

  @doc """
  Start the factory. Options:
    * `:scenario_module` — the UAS scenario module to instantiate (required);
    * `:max_instances`   — maximum concurrent instances (requests rejected with
      503 beyond this);
    * `:max_run`         — maximum total instances over the run (503 beyond it);
    * `:scenario_overrides` — keyword list merged on top of the scenario `config`
      block for every spawned instance (e.g. `[password: "secret"]`);
    * `:domains` — served domains for a call server (`:any` or a list of hosts);
      defaults to the scenario's `config[:domains]`, itself defaulting to `:any`.
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

  @doc "Broadcast a cooperative shutdown to all active instances without stopping the factory."
  @spec shutdown_all(term()) :: :ok
  def shutdown_all(reason \\ :elixipp_graceful),
    do: GenServer.cast(__MODULE__, {:shutdown_all, reason})

  # ── SIP.Session.Registrar behaviour ──────────────────────────────────────

  @impl SIP.Session.Registrar
  def on_new_registration(dialog_id, registerreq, transaction_id) do
    GenServer.call(__MODULE__, {:new_registration, dialog_id, registerreq, transaction_id})
  end

  @impl SIP.Session.Registrar
  def on_registration_expired(dialog_id, app_pid) do
    GenServer.cast(__MODULE__, {:instance_ended, dialog_id, app_pid})
  end

  # ── SIP.Session.Call behaviour ────────────────────────────────────────────

  @impl SIP.Session.Call
  def on_new_call(dialog_id, invitereq, transaction_id) do
    GenServer.call(__MODULE__, {:new_call, dialog_id, invitereq, transaction_id})
  end

  @impl SIP.Session.Call
  def on_call_end(dialog_id, app_pid) do
    GenServer.cast(__MODULE__, {:instance_ended, dialog_id, app_pid})
  end

  # ── GenServer callbacks ───────────────────────────────────────────────────

  @impl GenServer
  def init(opts) do
    state = %__MODULE__{
      scenario_module: Keyword.fetch!(opts, :scenario_module),
      max_instances: Keyword.get(opts, :max_instances, 1),
      max_run: Keyword.get(opts, :max_run, nil),
      scenario_overrides: Keyword.get(opts, :scenario_overrides, []),
      domains: resolve_domains(opts)
    }

    {:ok, state}
  end

  @impl GenServer
  def handle_call({:new_registration, dialog_id, req, _transaction_id}, _from, state) do
    accept_or_reject(state, dialog_id, req, "REGISTER")
  end

  # An INVITE additionally goes through the virtual-server domain check first.
  def handle_call({:new_call, dialog_id, req, _transaction_id}, _from, state) do
    if domain_ok?(state.domains, req) do
      accept_or_reject(state, dialog_id, req, "INVITE")
    else
      Logger.warning(
        "ScenarioUAS: INVITE R-URI domain #{inspect(ruri_domain(req))} not served " <>
          "(domains: #{inspect(state.domains)}), rejecting with 604"
      )

      {:reply, {:reject, 604, "Does Not Exist Anywhere"},
       %{state | total_rejected_domain: state.total_rejected_domain + 1}}
    end
  end

  def handle_call(:stats, _from, state) do
    {:reply,
     %{
       active: map_size(state.instances),
       total_started: state.total_started,
       total_succeeded: state.total_succeeded,
       total_aborted: state.total_aborted,
       total_failed: state.total_failed,
       total_rejected_quota: state.total_rejected_quota,
       total_rejected_domain: state.total_rejected_domain
     }, state}
  end

  @impl GenServer
  def handle_cast({:shutdown_all, reason}, state) do
    Enum.each(state.instances, fn {_ref, %{pid: pid}} ->
      send(pid, {:scenario_ctl, :shutdown, reason})
    end)

    {:noreply, state}
  end

  # on_registration_expired/2 and on_call_end/2 both funnel here; the :DOWN
  # message already freed the slot, so this is only logged.
  @impl GenServer
  def handle_cast({:instance_ended, dialog_id, _app_pid}, state) do
    Logger.debug("ScenarioUAS: instance ended for dialog #{inspect(dialog_id)}")
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
          "ScenarioUAS: instance #{inspect(pid)} ended (#{inspect(reason)}), #{map_size(instances)} active"
        )

        {:noreply, %{state | instances: instances}}
    end
  end

  # Lifecycle notification from the instance finalizer; the :DOWN message already
  # frees the slot, so this only updates the outcome counters.
  def handle_info({:scenario_exit, _name, outcome, reason}, state) do
    Logger.debug("ScenarioUAS: scenario_exit #{inspect(outcome)} (#{inspect(reason)})")

    state =
      case outcome do
        :success -> %{state | total_succeeded: state.total_succeeded + 1}
        :aborted -> %{state | total_aborted: state.total_aborted + 1}
        _ -> %{state | total_failed: state.total_failed + 1}
      end

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl GenServer
  # When the factory stops, cooperatively shut down every running instance
  # (same mechanism as the DSL sub-FSM shutdown).
  def terminate(reason, state) do
    Enum.each(state.instances, fn {_ref, %{pid: pid}} ->
      send(pid, {:scenario_ctl, :shutdown, reason})
    end)

    :ok
  end

  # ── Internals ─────────────────────────────────────────────────────────────

  # Shared quota check + instance spawn for REGISTER and INVITE.
  defp accept_or_reject(state, dialog_id, req, kind) do
    max_run_reached = is_integer(state.max_run) and state.total_started >= state.max_run

    cond do
      max_run_reached ->
        Logger.debug("ScenarioUAS: max_run #{state.max_run} reached, rejecting #{kind} with 503")
        {:reply, {:reject, 503, "Service Unavailable"},
         %{state | total_rejected_quota: state.total_rejected_quota + 1}}

      map_size(state.instances) >= state.max_instances ->
        Logger.warning(
          "ScenarioUAS: quota reached (#{state.max_instances}), rejecting #{kind} with 503"
        )

        {:reply, {:reject, 503, "Service Unavailable"},
         %{state | total_rejected_quota: state.total_rejected_quota + 1}}

      true ->
        {pid, ref} =
          SIP.Scenario.Runner.spawn_uas_instance(state.scenario_module,
            dialog_pid: dialog_id,
            parent_pid: self(),
            inbound_request: req,
            config_overrides: state.scenario_overrides
          )

        instances = Map.put(state.instances, ref, %{pid: pid, dialog_id: dialog_id})

        Logger.debug(
          "ScenarioUAS: accepted #{kind}, instance #{inspect(pid)} (#{map_size(instances)} active)"
        )

        {:reply, {:accept, pid},
         %{state | instances: instances, total_started: state.total_started + 1}}
    end
  end

  # Effective served domains: explicit :domains option wins, else the scenario
  # `config[:domains]`, else :any (catch-all). A single host is wrapped in a list.
  defp resolve_domains(opts) do
    raw =
      case Keyword.get(opts, :domains) do
        nil ->
          module = Keyword.fetch!(opts, :scenario_module)

          if function_exported?(module, :__scenario_config__, 0),
            do: Keyword.get(module.__scenario_config__(), :domains, :any),
            else: :any

        d ->
          d
      end

    normalize_domains(raw)
  end

  defp normalize_domains(:any), do: :any
  defp normalize_domains(d) when is_binary(d), do: [String.downcase(d)]
  defp normalize_domains(list) when is_list(list), do: Enum.map(list, &String.downcase/1)

  defp domain_ok?(:any, _req), do: true

  defp domain_ok?(domains, req) when is_list(domains) do
    case ruri_domain(req) do
      d when is_binary(d) -> String.downcase(d) in domains
      _ -> false
    end
  end

  defp ruri_domain(%{ruri: %SIP.Uri{domain: d}}), do: d
  defp ruri_domain(_), do: nil
end

defmodule Elixip.RegistrarUAS do
  @moduledoc """
  Backward-compatible alias for `Elixip.ScenarioUAS` (transition name). New code
  should use `Elixip.ScenarioUAS`. Both the registration processing module and
  this alias resolve to the same GenServer.
  """
  @behaviour SIP.Session.Registrar

  defdelegate start_link(opts), to: Elixip.ScenarioUAS
  defdelegate stats(), to: Elixip.ScenarioUAS
  defdelegate shutdown_all(reason), to: Elixip.ScenarioUAS
  def shutdown_all, do: Elixip.ScenarioUAS.shutdown_all()

  @impl SIP.Session.Registrar
  defdelegate on_new_registration(dialog_id, req, transaction_id), to: Elixip.ScenarioUAS

  @impl SIP.Session.Registrar
  defdelegate on_registration_expired(dialog_id, app_pid), to: Elixip.ScenarioUAS
end
