defmodule SIP.Scenario.SequenceJournal do
  @moduledoc """
  Per-process, in-memory journal of a scenario instance's run: the commands it
  sent (`send_INVITE`, `media_play`, …), the state transitions it went through,
  its terminal outcome, and — through `SIP.Scenario.SipTrace` — every SIP
  message its dialogs put on or took off the wire. Used to render a PlantUML
  sequence diagram when `--log-sequence` is set on the `elixipp` CLI, or when the
  scenario enables its debug flag (`config debug: true` or `ctx_set(:debug, true)`).

  The journal lives in the **process dictionary of the scenario instance process**
  — the same process where `SIP.Scenario.Runner.run_instance/1`, the `send_*`
  macros (`SIP.Scenario.Monitor.note_command/2`) and the runner `report/5` all
  run. It is therefore naturally isolated per call and adds zero overhead when
  disabled (every recording helper is a no-op when no journal has been started).
  The SIP messages are recorded by other processes and merged in at `flush/0`,
  every event carrying a monotonic timestamp (`:at`, microseconds) for the order.
  """
  require Logger

  @journal_key :scenario_sequence_journal
  @meta_key :scenario_sequence_meta

  @typedoc "A recorded event, in chronological order once read back via `events/0`."
  @type event ::
          %{kind: :command, at: integer(), type: atom(), name: String.t()}
          | %{
              kind: :transition,
              at: integer(),
              to: atom() | String.t(),
              event: String.t(),
              type: atom() | nil
            }
          | %{
              kind: :terminal,
              at: integer(),
              outcome: :succeeded | :failed,
              reason: String.t(),
              type: atom() | nil
            }
          | SIP.Scenario.SipTrace.event()

  @typedoc "`:t0` is the monotonic time the journal started, the diagram's origin."
  @type meta :: %{scenario: String.t(), pid: String.t(), config: keyword(), t0: integer()}

  @doc "Start a journal in the current process with the given metadata."
  @spec start(map()) :: :ok
  def start(meta) when is_map(meta) do
    Process.put(@meta_key, Map.put(meta, :t0, now()))
    Process.put(@journal_key, [])
    SIP.Scenario.SipTrace.watch()
    :ok
  end

  @doc "True when a journal is active in the current process."
  @spec enabled?() :: boolean()
  def enabled?, do: Process.get(@journal_key) != nil

  @doc "Record an outbound command, e.g. `record_command(:sip, \"send_INVITE\")`."
  @spec record_command(atom(), String.t() | atom()) :: :ok
  def record_command(type, name) do
    append(%{kind: :command, at: now(), type: type, name: to_string(name)})
  end

  @doc """
  Record a state report. `state` is the target state name, or `:succeeded` /
  `:failed` for a terminal; `event` is the (already stringified) triggering
  description and `type` its category (`:sip`, `:media`, …).
  """
  @spec record_transition(atom(), String.t(), atom() | nil) :: :ok
  def record_transition(state, event, type) do
    append(transition_event(state, blank_to_string(event), type))
  end

  @doc """
  Record the inbound request a UAS instance was spawned for. It reached the
  transaction layer before this instance existed, so no trace caught it.
  """
  @spec record_inbound_request(map()) :: :ok
  def record_inbound_request(req) when is_map(req) do
    if enabled?() do
      case SIP.Scenario.SipTrace.event(:in, req) do
        nil -> :ok
        event -> append(event)
      end
    end

    :ok
  end

  @doc "Trace the messages of a dialog that existed before this journal started."
  @spec adopt_dialog(pid()) :: :ok
  def adopt_dialog(dialog_pid) when is_pid(dialog_pid) do
    if enabled?(), do: SIP.Scenario.SipTrace.adopt(dialog_pid)
    :ok
  end

  @doc """
  Chronological list of the events recorded in this process (`[]` when
  disabled). The SIP messages recorded by other processes are not in it: they
  join at `flush/0`.
  """
  @spec events() :: [event()]
  def events do
    case Process.get(@journal_key) do
      nil -> []
      list -> Enum.reverse(list)
    end
  end

  @doc "Metadata stored at `start/1` (`nil` when disabled)."
  @spec meta() :: meta() | nil
  def meta, do: Process.get(@meta_key)

  @doc """
  Render the PlantUML file and clear the journal from the process dictionary.

  Returns `{:ok, path}` on success, `:disabled` when no journal is active, or
  `{:error, reason}` if the file could not be written.
  """
  @spec flush() :: {:ok, String.t()} | :disabled | {:error, term()}
  def flush do
    case Process.get(@journal_key) do
      nil ->
        :disabled

      _ ->
        meta = Process.get(@meta_key)
        events = merge(events(), SIP.Scenario.SipTrace.take())
        content = SIP.Scenario.SequenceDiagram.to_plantuml(events, meta)
        path = SIP.Scenario.SequenceDiagram.filename(meta)
        clear()

        case File.write(path, content) do
          :ok -> {:ok, path}
          {:error, reason} -> {:error, reason}
        end
    end
  end

  @doc "Drop the journal from the current process (used by `flush/0` and tests)."
  @spec clear() :: :ok
  def clear do
    Process.delete(@journal_key)
    Process.delete(@meta_key)
    SIP.Scenario.SipTrace.take()
    :ok
  end

  # ── internals ──────────────────────────────────────────────────────────────

  defp now, do: System.monotonic_time(:microsecond)

  defp merge(own, traced) do
    Enum.sort_by(own ++ traced, &Map.get(&1, :at, 0))
  end

  # No-op when disabled, so callers (note_command / report) need no guard.
  defp append(event) do
    case Process.get(@journal_key) do
      nil -> :ok
      list -> Process.put(@journal_key, [event | list])
    end

    :ok
  end

  defp transition_event(state, event, type) when state in [:succeeded, :failed] do
    %{kind: :terminal, at: now(), outcome: state, reason: event, type: type}
  end

  defp transition_event(state, event, type) do
    %{kind: :transition, at: now(), to: state, event: event, type: type}
  end

  defp blank_to_string(nil), do: ""
  defp blank_to_string(value), do: to_string(value)
end
