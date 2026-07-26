defmodule SIP.Scenario.CallDispatcher do
  @moduledoc """
  Minimal call processing module routing inbound INVITEs to UAS scenarios
  spawned as sub-FSMs (`sub_fsm` on a `:uas_invite` scenario).

  `SIP.Scenario.Runner.spawn_child/4` registers each waiting child here and
  installs this module as the call processing module of
  `SIP.Session.ConfigRegistry`. On an inbound INVITE, `on_new_call/3` hands the
  dialog to the first waiting child (`{:accept, pid}`); the dialog layer then
  delivers `{:INVITE, req, transaction_pid, dialog_pid}` to that process —
  exactly what a UAS scenario waits for. One child handles one call: once
  popped, a child is never reused. With no child waiting, the INVITE is
  rejected `486 Busy Here`.

  This keeps the DSL layer self-contained: unlike `Elixip.ScenarioUAS` (the
  elixipp server-mode factory), no new instance is spawned per call — the
  parent scenario controls the lifecycle by re-spawning a `sub_fsm` when it
  wants to accept another call.
  """
  @behaviour SIP.Session.Call
  use GenServer
  require Logger

  # ── Public API ──────────────────────────────────────────────────────────

  @doc """
  Start the dispatcher. Idempotent: an already-running dispatcher is reused
  (same contract as `SIP.Session.ConfigRegistry.start/0`).
  """
  @spec start() :: {:ok, pid()} | {:error, term()}
  def start() do
    case GenServer.start(__MODULE__, nil, name: __MODULE__) do
      {:ok, pid} -> {:ok, pid}
      {:error, {:already_started, pid}} -> {:ok, pid}
      err -> err
    end
  end

  @doc "Register a child FSM waiting for one inbound INVITE."
  @spec register_waiting(pid()) :: :ok
  def register_waiting(pid) when is_pid(pid) do
    GenServer.call(__MODULE__, {:register_waiting, pid})
  end

  # ── SIP.Session.Call behaviour ────────────────────────────────────────────

  @impl SIP.Session.Call
  def on_new_call(_dialog_id, _invitereq, _transaction_id) do
    case GenServer.call(__MODULE__, :pop_waiting) do
      pid when is_pid(pid) ->
        {:accept, pid}

      nil ->
        Logger.info(
          module: __MODULE__,
          message: "Inbound INVITE but no sub-FSM waiting for a call: rejecting with 486"
        )

        {:reject, 486, "Busy Here"}
    end
  end

  @impl SIP.Session.Call
  def on_call_end(dialog_id, _app_pid) do
    Logger.debug(
      module: __MODULE__,
      message: "Call ended for dialog #{inspect(dialog_id)}"
    )
  end

  # ── GenServer callbacks ───────────────────────────────────────────────────
  # State: FIFO of {pid, monitor_ref} for the children waiting for a call.

  @impl GenServer
  def init(nil), do: {:ok, []}

  @impl GenServer
  def handle_call({:register_waiting, pid}, _from, waiting) do
    ref = Process.monitor(pid)
    {:reply, :ok, waiting ++ [{pid, ref}]}
  end

  def handle_call(:pop_waiting, _from, waiting) do
    case waiting do
      [{pid, ref} | rest] ->
        Process.demonitor(ref, [:flush])
        {:reply, pid, rest}

      [] ->
        {:reply, nil, []}
    end
  end

  @impl GenServer
  # A waiting child died (scenario timeout, crash, cooperative shutdown):
  # drop it from the queue so a later INVITE is not accepted by a dead pid.
  def handle_info({:DOWN, ref, :process, _pid, _reason}, waiting) do
    {:noreply, Enum.reject(waiting, fn {_p, r} -> r == ref end)}
  end

  def handle_info(_msg, waiting), do: {:noreply, waiting}
end
