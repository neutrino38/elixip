defmodule SIP.Scenario.SequenceJournal do
  @moduledoc """
  Per-process, in-memory journal of a scenario instance's run: the commands it
  sent (`send_INVITE`, `media_play`, …), the state transitions it went through and
  its terminal outcome. Used to render a PlantUML sequence diagram when
  `--log-sequence` is set on the `elixipp` CLI, or when the scenario enables its
  debug flag (`ctx_set(:debug, true)`).

  The journal lives in the **process dictionary of the scenario instance process**
  — the same process where `SIP.Scenario.Runner.run_instance/1`, the `send_*`
  macros (`SIP.Scenario.Monitor.note_command/2`) and the runner `report/5` all
  run. It is therefore naturally isolated per call and adds zero overhead when
  disabled (every recording helper is a no-op when no journal has been started).
  """
  require Logger

  @journal_key :scenario_sequence_journal
  @meta_key :scenario_sequence_meta

  @typedoc "A recorded event, in chronological order once read back via `events/0`."
  @type event ::
          %{kind: :command, type: atom(), name: String.t()}
          | %{kind: :transition, to: atom(), event: String.t(), type: atom() | nil}
          | %{kind: :terminal, outcome: :succeeded | :failed, reason: String.t(), type: atom() | nil}

  @type meta :: %{scenario: String.t(), pid: String.t(), config: keyword()}

  @doc "Start a journal in the current process with the given metadata."
  @spec start(meta()) :: :ok
  def start(meta) when is_map(meta) do
    Process.put(@meta_key, meta)
    Process.put(@journal_key, [])
    :ok
  end

  @doc "True when a journal is active in the current process."
  @spec enabled?() :: boolean()
  def enabled?, do: Process.get(@journal_key) != nil

  @doc "Record an outbound command, e.g. `record_command(:sip, \"send_INVITE\")`."
  @spec record_command(atom(), String.t() | atom()) :: :ok
  def record_command(type, name) do
    append(%{kind: :command, type: type, name: to_string(name)})
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

  @doc "Chronological list of recorded events (`[]` when disabled)."
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
        content = SIP.Scenario.SequenceDiagram.to_plantuml(events(), meta)
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
    :ok
  end

  # ── internals ──────────────────────────────────────────────────────────────

  # No-op when disabled, so callers (note_command / report) need no guard.
  defp append(event) do
    case Process.get(@journal_key) do
      nil -> :ok
      list -> Process.put(@journal_key, [event | list])
    end

    :ok
  end

  defp transition_event(state, event, type) when state in [:succeeded, :failed] do
    %{kind: :terminal, outcome: state, reason: event, type: type}
  end

  defp transition_event(state, event, type) do
    %{kind: :transition, to: state, event: event, type: type}
  end

  defp blank_to_string(nil), do: ""
  defp blank_to_string(value), do: to_string(value)
end
