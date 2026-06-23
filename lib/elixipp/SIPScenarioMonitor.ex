defmodule SIP.Scenario.Monitor do
  @moduledoc """
  In-memory registry of the scenario instances ("calls") currently running, used
  by the `elixipp --monitor` live view.

  One entry per call, keyed by the scenario process pid. Each entry holds the
  scenario name, the last command sent (e.g. `send_INVITE`), the current FSM
  state and the event that triggered the last transition.

  Both `SIP.Scenario.Runner` (state transitions) and the `SIP.Session.*` send_*
  macros (commands) report here, but **only when the monitor is started** — the
  reporting helpers are a no-op otherwise, so there is zero overhead when
  monitoring is off.

  Designed to hold several concurrent calls — today a single instance, tomorrow
  the SIPP-like parallel mode.
  """
  use GenServer

  @typedoc "Category of a command, to drive the future sequence diagram."
  @type command_type :: :sip | :media | :http | :db | :scenario | :control | nil

  @type call_info :: %{
          scenario: String.t(),
          command: String.t(),
          command_type: command_type(),
          state: String.t(),
          event: String.t(),
          event_type: command_type()
        }

  @empty %{
    scenario: "",
    account: "",
    command: "",
    command_type: nil,
    state: "",
    event: "",
    event_type: nil
  }

  # ── Public API ──────────────────────────────────────────────────────────────

  @doc "Start the monitor (idempotent — reuses an already-running instance)."
  @spec start() :: {:ok, pid()}
  def start do
    case GenServer.start(__MODULE__, :ok, name: __MODULE__) do
      {:ok, pid} -> {:ok, pid}
      {:error, {:already_started, pid}} -> {:ok, pid}
      err -> err
    end
  end

  @doc """
  Upsert the state of a call. `call_id` is the scenario process pid. `event_type`
  categorizes the triggering event (`:sip`, `:media`, `:timer`, …) — stored for
  the future sequence diagram, mirroring `command_type`.
  """
  @spec report(pid(), String.t(), String.t(), String.t(), String.t(), command_type()) :: :ok
  def report(call_id, scenario, username, state, event, event_type \\ nil) do
    GenServer.cast(__MODULE__, {:report, call_id, scenario, username, state, event, event_type})
  end

  @doc """
  Record the last command issued by the current scenario process, with its
  category (`:sip`, `:media`, `:http`, `:db`, …). Called by the instrumented
  `SIP.Session.*` macros. The category is stored to drive the future sequence
  diagram (knowing whether a command targets the SIP peer, the media server, …).

  No-op if the monitor is not running, so it stays free when `--monitor` is off.
  """
  @spec note_command(command_type(), String.t() | atom()) :: :ok
  def note_command(type, command) when is_atom(type) do
    if Process.whereis(__MODULE__) do
      # Use the stable slot_id set by the CLI duration loop so that successive
      # runs of the same logical slot recycle the same monitor row.
      slot_id = Process.get(:scenario_slot_id, self())
      GenServer.cast(__MODULE__, {:command, slot_id, type, to_string(command)})
    end

    # Feed the PlantUML sequence journal (no-op when not enabled in this process).
    SIP.Scenario.SequenceJournal.record_command(type, command)

    :ok
  end

  @doc "Snapshot of all calls (one map per call), ordered by appearance."
  @spec calls() :: [call_info()]
  def calls do
    GenServer.call(__MODULE__, :calls)
  end

  @doc "Remove a slot entry so its row is recycled by the next call on that slot."
  @spec clear(term()) :: :ok
  def clear(slot_id) do
    if Process.whereis(__MODULE__) do
      GenServer.cast(__MODULE__, {:clear, slot_id})
    end

    :ok
  end

  # ── Server ──────────────────────────────────────────────────────────────────

  @impl true
  def init(:ok), do: {:ok, %{calls: %{}, seq: 0}}

  @impl true
  def handle_cast({:report, call_id, scenario, username, state, event, event_type}, st) do
    update(st, call_id, %{
      scenario: to_string(scenario),
      account: to_string(username),
      state: to_string(state),
      event: to_string(event),
      event_type: event_type
    })
  end

  @impl true
  def handle_cast({:clear, slot_id}, st) do
    {:noreply, %{st | calls: Map.delete(st.calls, slot_id)}}
  end

  @impl true
  def handle_cast({:command, call_id, type, command}, st) do
    update(st, call_id, %{command: command, command_type: type})
  end

  @impl true
  def handle_call(:calls, _from, st) do
    rows =
      st.calls
      |> Map.values()
      |> Enum.sort_by(& &1.idx)
      |> Enum.map(
        &Map.take(&1, [:scenario, :account, :command, :command_type, :state, :event, :event_type])
      )

    {:reply, rows, st}
  end

  # Merge `fields` into the entry for `call_id`, creating it (with a monotonic
  # display index) if it does not exist yet.
  defp update(st, call_id, fields) do
    {base, seq} =
      case Map.fetch(st.calls, call_id) do
        :error ->
          idx = if is_integer(call_id), do: call_id, else: st.seq
          {Map.put(@empty, :idx, idx), st.seq + 1}

        {:ok, existing} ->
          {existing, st.seq}
      end

    entry = Map.merge(base, fields)
    {:noreply, %{st | calls: Map.put(st.calls, call_id, entry), seq: seq}}
  end
end
