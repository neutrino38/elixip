defmodule Kelix.Mod.Mcu.Push do
  @moduledoc """
  The live-push transport of the module's event vocabulary: a subscriber list and
  `send/2`, the mechanism
  `Kelix.Mod.Registrar` and `Kelix.Control.subscribe_monitor/1` already use.

  Three topics, one per panel a UI opens:

    * the conference **list** — `{:kelix_conferences, {:upsert, conf_row}}` and
      `{:kelix_conferences, {:remove, uid}}`;
    * **one conference** — `{:kelix_conference, uid, {:snapshot, %{conference:,
      participants:}}}` and `{:kelix_conference, uid, :destroyed}`;
    * **one conference's statistics** — `{:kelix_conference_stats, uid, sample}`,
      swept by `Kelix.Mod.Mcu.Stats`.

  `Kelix.Mod.Mcu.Event.emit/3` is the single hook: every observed transition is
  already emitted there exactly once, with the conference uid, so the fan-out is one
  more consumer and not a broadcast call at twenty sites. The event NAME decides what
  goes out (`action/1`), which is what makes `conference.destroyed` safe — it is the
  one emission that runs BEFORE its `:ets.delete`, so re-reading the row there would
  resurrect a destroyed conference in the UI.

  The subscriber table is `:protected` and owned by `Kelix.Mod.Mcu` — unlike the
  registrar's, whose subscribers live in its GenServer state: `emit/3` runs in
  whatever process observed the transition (a scenario, a message sender), so a
  publisher must be able to read the list without a GenServer hop. Writes still go
  through the owner.

  Nothing is rendered for a topic nobody subscribed to: the roster render sits on the
  call path (every ringing, joined and left), so an unwatched conference must cost a
  `:ets.select` and nothing more.
  """
  alias Kelix.Mod.Mcu
  alias Kelix.Mod.Mcu.Conference

  @table :kelix_mcu_push_subs

  @type topic :: :list | {:conf, String.t()} | {:stats, String.t()}

  @doc "Create the subscriber table (called by `Kelix.Mod.Mcu.init/1`, its owner)."
  @spec create_table() :: :ok
  def create_table() do
    :ets.new(@table, [:set, :protected, :named_table, read_concurrency: true])
    :ok
  end

  # ── writes (owner process only) ──────────────────────────────────────────────

  @doc false
  @spec put(topic, pid) :: :ok
  def put(topic, pid) do
    if alive?(), do: :ets.insert(@table, {key(topic, pid), true})
    :ok
  end

  @doc false
  @spec drop(topic, pid) :: :ok
  def drop(topic, pid) do
    if alive?(), do: :ets.delete(@table, key(topic, pid))
    :ok
  end

  # A destroyed conference leaves its subscriptions in place, deliberately: the
  # subscriber has just been told (`:destroyed`) and unsubscribes, and until it does
  # its entry costs nothing — no event will name that uid again, and the statistics
  # sweep finds no row and issues no RPC. Dropping it here instead would desynchronise
  # this table from the monitors `Kelix.Mod.Mcu` holds for the same subscriptions.

  # ── reads ────────────────────────────────────────────────────────────────────

  @doc "The pids subscribed to `topic`."
  @spec subscribers(topic) :: [pid]
  def subscribers(:list), do: select([{{{:list, :"$1"}, :_}, [], [:"$1"]}])
  def subscribers({:conf, uid}), do: select([{{{:conf, uid, :"$1"}, :_}, [], [:"$1"]}])
  def subscribers({:stats, uid}), do: select([{{{:stats, uid, :"$1"}, :_}, [], [:"$1"]}])

  @doc "The conferences at least one pid asked statistics for (what `Stats` sweeps)."
  @spec watched_stats() :: [String.t()]
  def watched_stats() do
    [{{{:stats, :"$1", :_}, :_}, [], [:"$1"]}] |> select() |> Enum.uniq()
  end

  # ── publishing ───────────────────────────────────────────────────────────────

  @doc """
  Relay one emitted event to whoever subscribed. Called by `Event.emit/3`, in the
  process that emitted — a no-op when the module is not running.
  """
  @spec publish(atom, String.t() | nil) :: :ok
  def publish(name, uid) do
    case {alive?(), action(name), uid} do
      {true, :row, uid} when is_binary(uid) -> row(uid)
      {true, :remove, uid} when is_binary(uid) -> removed(uid)
      _ -> :ok
    end
  end

  @doc """
  Push one conference's current rows, whatever emitted (used by `publish/2`, and by
  the statistics sweep when it finds a roster the events had no reason to re-push).
  """
  @spec row(String.t()) :: :ok
  def row(uid) do
    list_subs = subscribers(:list)
    conf_subs = subscribers({:conf, uid})

    if list_subs != [] or conf_subs != [] do
      case Mcu.conference(uid) do
        {:ok, conf} ->
          for pid <- list_subs, do: send(pid, {:kelix_conferences, {:upsert, render(conf)}})
          for pid <- conf_subs, do: send(pid, {:kelix_conference, uid, {:snapshot, detail(conf)}})
          :ok

        :error ->
          # the row went away between the emission and here: a destroy is the only
          # path that does that, and it pushes its own remove
          :ok
      end
    end

    :ok
  end

  @doc "The snapshot `subscribe_conference/2` answers with."
  @spec detail(Conference.t()) :: map
  def detail(%Conference{} = conf) do
    %{conference: render(conf), participants: Enum.map(roster(conf), &render_participant/1)}
  end

  @doc "The conference row every topic carries (what `conference.list` returns)."
  @spec render(Conference.t()) :: map
  def render(%Conference{} = conf), do: Conference.render(conf)

  @doc "One participant row (what `participant.list` returns)."
  @spec render_participant(Conference.participant()) :: map
  def render_participant(part), do: Conference.render_participant(part)

  @doc """
  A conference's participants in **admission order**, which is the order every
  pushed roster and every statistics sample uses: the map they are held in has none,
  and a table whose rows move on their own is unreadable.
  """
  @spec roster(Conference.t()) :: [Conference.participant()]
  def roster(%Conference{} = conf),
    do: conf |> Conference.participants() |> Enum.sort_by(& &1.admitted_at)

  @doc "Send one statistics sample to that conference's watchers."
  @spec stats(String.t(), map) :: :ok
  def stats(uid, sample) do
    for pid <- subscribers({:stats, uid}), do: send(pid, {:kelix_conference_stats, uid, sample})
    :ok
  end

  # ── what each event name publishes ───────────────────────────────────────────

  # The vocabulary is frozen (`Event`), so this is a total function over it, and the
  # events that change no row publish nothing: `participant.message` is the
  # collaboration channel's hot path, and a rejected call has no conference at all.
  defp action(:"conference.destroyed"), do: :remove

  defp action(name) do
    case Atom.to_string(name) do
      "conference." <> _ -> :row
      "participant.message" -> :none
      "participant.rejected" -> :none
      "participant.fpu_requested" -> :none
      "participant." <> _ -> :row
      _ -> :none
    end
  end

  defp removed(uid) do
    for pid <- subscribers(:list), do: send(pid, {:kelix_conferences, {:remove, uid}})
    for pid <- subscribers({:conf, uid}), do: send(pid, {:kelix_conference, uid, :destroyed})
    :ok
  end

  defp key(:list, pid), do: {:list, pid}
  defp key({:conf, uid}, pid), do: {:conf, uid, pid}
  defp key({:stats, uid}, pid), do: {:stats, uid, pid}

  defp select(spec) do
    case :ets.whereis(@table) do
      :undefined -> []
      tid -> :ets.select(tid, spec)
    end
  end

  defp alive?(), do: :ets.whereis(@table) != :undefined
end
