defmodule SIP.Scenario.Monitor do
  @moduledoc """
  In-memory registry of the scenario instances ("calls") currently running, used
  by the `elixipp --monitor` live view.

  One entry per call, keyed by the scenario slot id (an integer for a CLI slot,
  `{parent_slot, name}` for a `spawn_fsm` child, the scenario process pid
  otherwise). Each entry holds the scenario name, the last command sent (e.g.
  `send_INVITE`), the current FSM state and the event that triggered the last
  transition. A sub-FSM gets its own row, displayed right below its parent.

  Both `SIP.Scenario.Runner` (state transitions) and the `SIP.Session.*` send_*
  macros (commands) report here, but **only when the monitor is started** — the
  reporting helpers are a no-op otherwise, so there is zero overhead when
  monitoring is off.

  Designed to hold several concurrent calls — today a single instance, tomorrow
  the SIPP-like parallel mode.

  A pid can also `subscribe/1` to be told of changes as they happen instead of
  polling `calls/0` — `{:sip_scenario_monitor, {:updated, slot, row}}` after
  every reported change, `{:sip_scenario_monitor, {:cleared, slot}}` when a slot
  (and any sub-FSM children) is cleared. On the model of
  `Kelix.Mod.Registrar.subscribe_register_event/2`; `Kelix.InstancePool` is the
  one subscriber today, joining these with its own rows for
  `Kelix.Control.subscribe_monitor/1`.
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
          event_type: command_type(),
          medias: String.t(),
          mediaserver: String.t(),
          outbound: String.t()
        }

  # The three call-shape columns default to a *value*, not to an empty string: a
  # call that negotiated no media, connects to no media server and dials nobody is
  # the ordinary case (a registrar), and "n/a" says so where a blank cell would
  # read as "not measured".
  @empty %{
    scenario: "",
    account: "",
    command: "",
    command_type: nil,
    state: "",
    event: "",
    event_type: nil,
    medias: "n/a",
    mediaserver: "none",
    outbound: "n/a"
  }

  # Display letter of each negotiated media, in the order they are rendered.
  @media_letters [audio: "A", video: "V", text: "T"]

  # ── Public API ──────────────────────────────────────────────────────────────

  @doc """
  Start the monitor **unlinked** (idempotent — reuses an already-running instance).

  This is elixipp's imperative bootstrap, called from the CLI once it knows
  `--monitor` was asked for. A supervised owner wants `start_link/1` instead.
  """
  @spec start() :: {:ok, pid()}
  def start do
    case GenServer.start(__MODULE__, :ok, name: __MODULE__) do
      {:ok, pid} -> {:ok, pid}
      {:error, {:already_started, pid}} -> {:ok, pid}
      err -> err
    end
  end

  @doc """
  Start the monitor under a supervisor — how the kelixip server runs it, so
  `kelictl monitor` has FSM state to report (the `use GenServer` default
  `child_spec/1` calls this).
  """
  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(_opts \\ []), do: GenServer.start_link(__MODULE__, :ok, name: __MODULE__)

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
  Update the account column of the current scenario row. Called when the
  registered identity becomes known (e.g. after auth succeeds in a UAS
  REGISTER scenario). No-op if the monitor is not running.
  """
  @spec note_account(String.t()) :: :ok
  def note_account(username) do
    if Process.whereis(__MODULE__) do
      slot_id = Process.get(:scenario_slot_id, self())
      GenServer.cast(__MODULE__, {:account, slot_id, to_string(username)})
    end

    :ok
  end

  @doc """
  Record the media the call has just negotiated: the `kinds` of the answer the two
  ends settled on, as `SIP.Msg.Ops.media_kinds/1` reads them. Rendered
  `A` / `AV` / `AVT`, and `none` for an answer that carried none of the three.

  Called by the framework wherever an answer is built, received or relayed, so a
  scenario has nothing to say about it. No-op if the monitor is not running.
  """
  @spec note_medias([:audio | :video | :text]) :: :ok
  def note_medias(kinds) when is_list(kinds) do
    put(:medias, media_label(kinds))
  end

  @doc """
  Record the media server this call is connected to, by the name it is declared
  under (`[mediaserver.pool.<name>]`). No-op if the monitor is not running.
  """
  @spec note_mediaserver(String.t()) :: :ok
  def note_mediaserver(name) do
    put(:mediaserver, to_string(name))
  end

  @doc """
  Record the destination of the outbound leg: the target being dialled, and then
  the one that answered — a serial hunt walks several, and the column names the
  one the call is currently about. No-op if the monitor is not running.
  """
  @spec note_outbound(String.t() | %SIP.Uri{}) :: :ok
  def note_outbound(uri) do
    put(:outbound, uri_label(uri))
  end

  defp media_label(kinds) do
    case Enum.map_join(@media_letters, "", fn {kind, letter} ->
           if kind in kinds, do: letter, else: ""
         end) do
      "" -> "none"
      label -> label
    end
  end

  # The destination as an operator dialled it: the URI without its display name,
  # its header parameters or its `method` — `SIP.Uri.serialize_ruri/1` is the one
  # reading of "this URI as a request target" (see the URI-parameters rule in
  # CLAUDE.md).
  defp uri_label(%SIP.Uri{} = uri) do
    {:ok, label} = SIP.Uri.serialize_ruri(uri)
    label
  end

  defp uri_label(uri), do: to_string(uri)

  defp put(key, value) do
    if Process.whereis(__MODULE__) do
      slot_id = Process.get(:scenario_slot_id, self())
      GenServer.cast(__MODULE__, {:put, slot_id, key, value})
    end

    :ok
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

  @doc """
  Snapshot of all calls (one map per call), ordered by appearance.

  Each row carries its `:slot` — the key it was reported under — so a caller that
  owns those slots can join this view with its own (kelixip keys them on the
  instance id, see `Kelix.Control.monitor/0`). Renderers that build from named
  columns simply ignore it.
  """
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

  @doc "Subscribe `pid` to call changes (see the moduledoc for the message shapes)."
  @spec subscribe(pid()) :: :ok
  def subscribe(pid), do: GenServer.call(__MODULE__, {:subscribe, pid})

  @spec unsubscribe(pid()) :: :ok
  def unsubscribe(pid), do: GenServer.call(__MODULE__, {:unsubscribe, pid})

  # ── Server ──────────────────────────────────────────────────────────────────

  @impl true
  def init(:ok), do: {:ok, %{calls: %{}, seq: 0, subs: MapSet.new()}}

  @impl true
  def handle_call({:subscribe, pid}, _from, st),
    do: {:reply, :ok, %{st | subs: MapSet.put(st.subs, pid)}}

  def handle_call({:unsubscribe, pid}, _from, st),
    do: {:reply, :ok, %{st | subs: MapSet.delete(st.subs, pid)}}

  def handle_call(:calls, _from, st) do
    rows = st.calls |> Map.values() |> Enum.sort_by(& &1.idx) |> Enum.map(&row/1)
    {:reply, rows, st}
  end

  @impl true
  def handle_cast({:report, call_id, scenario, username, state, event, event_type}, st) do
    fields = %{
      scenario: to_string(scenario),
      state: to_string(state),
      event: to_string(event),
      event_type: event_type
    }

    # Only overwrite account when the caller provides a non-empty username;
    # otherwise preserve a value set earlier by note_account/1 (e.g. UAS scenarios
    # whose context has no local identity but learned the account after auth).
    fields =
      case to_string(username) do
        "" -> fields
        u -> Map.put(fields, :account, u)
      end

    update(st, call_id, fields)
  end

  @impl true
  # Clearing a slot also removes the rows of its sub-FSMs (keyed
  # {parent_slot, name}, possibly nested), so a recycled slot starts clean.
  def handle_cast({:clear, slot_id}, st) do
    calls =
      st.calls
      |> Enum.reject(fn {call_id, _entry} -> root_slot(call_id) == slot_id end)
      |> Map.new()

    notify(st, {:cleared, slot_id})
    {:noreply, %{st | calls: calls}}
  end

  @impl true
  def handle_cast({:account, call_id, username}, st) do
    update(st, call_id, %{account: username})
  end

  @impl true
  def handle_cast({:put, call_id, key, value}, st) do
    update(st, call_id, %{key => value})
  end

  @impl true
  def handle_cast({:command, call_id, type, command}, st) do
    update(st, call_id, %{command: command, command_type: type})
  end

  # The public shape of one entry (see `calls/0`): the display columns plus
  # `:depth` (tree nesting) and `:slot` (the key it was reported under).
  defp row(entry) do
    entry
    |> Map.take([
      :scenario,
      :account,
      :command,
      :command_type,
      :state,
      :event,
      :event_type,
      :medias,
      :mediaserver,
      :outbound
    ])
    |> Map.put(:depth, length(entry.idx) - 1)
    |> Map.put(:slot, entry.slot)
  end

  # Merge `fields` into the entry for `call_id`, creating it (with a monotonic
  # display index) if it does not exist yet.
  defp update(st, call_id, fields) do
    {base, seq} =
      case Map.fetch(st.calls, call_id) do
        :error ->
          {@empty |> Map.put(:idx, index_for(st, call_id)) |> Map.put(:slot, call_id), st.seq + 1}

        {:ok, existing} ->
          {existing, st.seq}
      end

    entry = Map.merge(base, fields)
    st = %{st | calls: Map.put(st.calls, call_id, entry), seq: seq}
    notify(st, {:updated, call_id, row(entry)})
    {:noreply, st}
  end

  defp notify(st, msg) do
    for pid <- st.subs, do: send(pid, {:sip_scenario_monitor, msg})
    :ok
  end

  # Display index of a new entry, as a path so rows sort in tree order: a CLI
  # slot sorts on its number, a sub-FSM right below its parent, anything else
  # (e.g. a server-mode instance) in order of appearance.
  defp index_for(st, call_id) do
    case call_id do
      slot when is_integer(slot) ->
        [slot]

      {parent_slot, _name} ->
        case Map.fetch(st.calls, parent_slot) do
          {:ok, %{idx: parent_idx}} -> parent_idx ++ [st.seq]
          :error -> [st.seq]
        end

      _pid ->
        [st.seq]
    end
  end

  # Root CLI slot of a call id: {parent_slot, name} chains up to the slot that
  # spawned the whole family.
  defp root_slot({parent_slot, _name}), do: root_slot(parent_slot)
  defp root_slot(call_id), do: call_id
end
