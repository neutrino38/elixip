defmodule Kelix.Mod.McuPresence do
  @moduledoc """
  Conference rooms as presentities (`docs/design/mcu-presence-plan.md`): the link
  between `Kelix.Mod.Mcu` and `Kelix.Mod.Presence`, neither of which depends on
  the other.

  A room's resource is `sip:<did>@<domain>`, package `presence`, and its state is
  what `report/4` states on the MCU's authority:

  | The conference                                   | The state          |
  |--------------------------------------------------|--------------------|
  | live on its media server, not full               | `open`             |
  | live, full (`Conference.full?/1`)                | `open` + RPID busy |
  | `stale` — its media server went away             | `closed`           |
  | does not exist                                   | no state           |

  Full is the quota the admission applies — a ringing leg holds a slot — so a
  room reads busy exactly when the next caller would get the `486`.

  The MCU is read through its live push, `Kelix.Mod.Mcu.subscribe_conferences/1`:
  the snapshot at start, then one row per conference transition. A row is
  reported **only when the state it maps to changed** — a participant joining a
  half-empty room changes no presence, and must not cost every watcher a NOTIFY.

  Both halves are monitored. An MCU restart is a re-subscribe and a resync
  against the new snapshot; a presence restart dropped every state this module
  reported, so it is a full re-report. Until both are up, the module retries.

  No SIP function, no script, no facade: `kelictl mcu_presence list` is its whole
  surface.
  """
  use GenServer
  @behaviour Kelix.Module
  require Logger

  alias Kelix.Mod.{Mcu, Presence}

  @retry_ms 1_000

  # state:
  #   domains   nil (every domain) or a MapSet of downcased domain names
  #   rows      %{uid => conference row} as the MCU last pushed it, every domain
  #   reported  %{uid => {domain, did, doc}} what presence was last told
  #   mcu       monitor ref of the MCU subscription's owner, nil when unsubscribed
  #   presence  monitor ref of the presence module, nil when not running
  defstruct domains: nil,
            rows: %{},
            reported: %{},
            mcu: nil,
            presence: nil,
            retry_ms: @retry_ms,
            retrying: false

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  # ── Kelix.Module behaviour ───────────────────────────────────────────────────

  @impl Kelix.Module
  def child_spec(_name, config),
    do: %{id: __MODULE__, start: {__MODULE__, :start_link, [[domains: domains(config)]]}}

  @config_keys ~w(module domains)

  # The link means nothing without both halves: a node configured with one of them
  # missing fails at start, not on the first SUBSCRIBE to a room.
  @impl Kelix.Module
  def validate_config(config) when is_map(config) do
    with :ok <- reject_unknown_keys(config),
         :ok <- domains_ok(config) do
      case missing_companions(configured_modules()) do
        [] -> :ok
        missing -> {:error, "needs the #{Enum.join(missing, " and ")} module(s) loaded"}
      end
    end
  end

  def validate_config(_), do: {:error, "block must be a table"}

  @impl Kelix.Module
  def reload(_name, config), do: GenServer.call(__MODULE__, {:reload, domains(config)})

  @impl Kelix.Module
  def describe(), do: %{version: "1.0", exports: []}

  @impl Kelix.Module
  def describe_control() do
    [
      %{
        name: "list",
        rest: {:get, "/rooms"},
        rw: :r,
        args: [],
        render: %{kind: :table, columns: ~w(presentity_uri status activity uid)},
        help: "The conference rooms reported to presence, and the state each was given"
      }
    ]
  end

  @impl Kelix.Module
  def handle_control("list", _args), do: {:ok, rooms()}
  def handle_control(command, _args), do: {:error, {:unknown_command, command}}

  @doc "The rooms reported to presence, as rendered rows (`kelictl mcu_presence list`)."
  @spec rooms() :: [map] | {:error, :down | :timeout}
  def rooms(), do: Kelix.Module.safe_call(__MODULE__, :rooms)

  @doc false
  # The names among `mcu` and `presence` that are not configured, or not installed.
  # `configured` is nil when there is no configuration to consult (a unit test).
  @spec missing_companions([String.t()] | nil) :: [String.t()]
  def missing_companions(configured) do
    for {name, module} <- [{"mcu", Mcu}, {"presence", Presence}],
        not ((configured == nil or name in configured) and
               Kelix.ModuleSupervisor.ensure_loaded(module)),
        do: name
  end

  # `mcu` and `presence` are both config.toml blocks (only the registrar's lives in
  # domains.toml).
  defp configured_modules() do
    if Process.whereis(Kelix.Config), do: Map.keys(Kelix.Config.current().modules)
  end

  defp reject_unknown_keys(config) do
    case Map.keys(config) -- @config_keys do
      [] -> :ok
      extra -> {:error, "unknown key(s): #{Enum.join(Enum.sort(extra), ", ")}"}
    end
  end

  defp domains_ok(config) do
    case Map.get(config, "domains") do
      nil -> :ok
      list when is_list(list) -> if Enum.all?(list, &is_binary/1), do: :ok, else: domains_error()
      _ -> domains_error()
    end
  end

  defp domains_error(), do: {:error, "domains must be a list of domain names"}

  defp domains(config) do
    case Map.get(config, "domains") do
      nil -> nil
      list -> MapSet.new(list, &String.downcase/1)
    end
  end

  # ── what a room's presence is ───────────────────────────────────────────────

  @doc """
  The presence document of one conference row, as `subscribe_conferences/1`
  pushes it. Open, busy when full, closed when its media server went away.
  """
  @spec room_doc(map) :: SIP.Presence.Doc.t()
  def room_doc(%{domain: domain, did: did} = row) do
    entity = "sip:#{did}@#{domain}"

    cond do
      row.stale ->
        SIP.Presence.Doc.new(entity, :closed)

      row.participants >= row.max_participants ->
        SIP.Presence.Doc.new(entity, :open, activity: :busy)

      true ->
        SIP.Presence.Doc.new(entity, :open)
    end
  end

  # ── GenServer ────────────────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    state = %__MODULE__{
      domains: Keyword.get(opts, :domains),
      retry_ms: Keyword.get(opts, :retry_ms, @retry_ms)
    }

    {:ok, state, {:continue, :sync}}
  end

  @impl true
  def handle_continue(:sync, state), do: {:noreply, sync(state)}

  @impl true
  def handle_call(:rooms, _from, state) do
    rows =
      for {uid, {domain, did, doc}} <- state.reported do
        %{
          presentity_uri: "sip:#{did}@#{domain}",
          status: to_string(SIP.Presence.Doc.status(doc)),
          activity: doc.activity && to_string(doc.activity),
          uid: uid
        }
      end

    {:reply, Enum.sort_by(rows, & &1.presentity_uri), state}
  end

  def handle_call({:reload, domains}, _from, state) do
    {:reply, :ok, reconcile_all(%{state | domains: domains})}
  end

  @impl true
  def handle_info({:kelix_conferences, {:upsert, row}}, state) do
    state = %{state | rows: Map.put(state.rows, row.uid, row)}
    {:noreply, reconcile(state, row.uid)}
  end

  def handle_info({:kelix_conferences, {:remove, uid}}, state) do
    state = %{state | rows: Map.delete(state.rows, uid)}
    {:noreply, reconcile(state, uid)}
  end

  # The MCU module restarted: its subscriber list went with it. What was reported
  # stays until the new snapshot says otherwise.
  def handle_info({:DOWN, ref, :process, _pid, _reason}, %{mcu: ref} = state) do
    {:noreply, sync(%{state | mcu: nil})}
  end

  # Presence restarted, and dropped every state we reported with the old process.
  def handle_info({:DOWN, ref, :process, _pid, _reason}, %{presence: ref} = state) do
    {:noreply, sync(%{state | presence: nil, reported: %{}})}
  end

  def handle_info(:retry, state), do: {:noreply, sync(%{state | retrying: false})}

  def handle_info(_msg, state), do: {:noreply, state}

  # ── both halves up, and in step ─────────────────────────────────────────────

  defp sync(state) do
    state = state |> ensure_mcu() |> ensure_presence()

    state = if state.presence, do: reconcile_all(state), else: state

    if state.mcu && state.presence, do: state, else: schedule_retry(state)
  end

  defp ensure_mcu(%{mcu: nil} = state) do
    case Mcu.subscribe_conferences(self()) do
      {:ok, %{owner: owner, conferences: rows}} ->
        %{state | mcu: Process.monitor(owner), rows: Map.new(rows, &{&1.uid, &1})}

      {:error, _reason} ->
        state
    end
  end

  defp ensure_mcu(state), do: state

  defp ensure_presence(%{presence: nil} = state) do
    case Process.whereis(Presence) do
      nil -> state
      pid -> %{state | presence: Process.monitor(pid)}
    end
  end

  defp ensure_presence(state), do: state

  defp schedule_retry(%{retrying: true} = state), do: state

  defp schedule_retry(state) do
    Process.send_after(self(), :retry, state.retry_ms)
    %{state | retrying: true}
  end

  # ── what presence is told ───────────────────────────────────────────────────

  defp reconcile_all(state) do
    uids = Enum.uniq(Map.keys(state.rows) ++ Map.keys(state.reported))
    Enum.reduce(uids, state, &reconcile(&2, &1))
  end

  # One room brought in step: nothing when the state it maps to is the one already
  # reported, a withdrawal when it left (destroyed, its DID or domain changed, out
  # of the configured domains), a report when it has a new one.
  defp reconcile(%{presence: nil} = state, _uid), do: state

  defp reconcile(state, uid) do
    wanted = wanted(state, Map.get(state.rows, uid))
    current = Map.get(state.reported, uid)

    cond do
      wanted == current ->
        state

      current != nil and (wanted == nil or key(wanted) != key(current)) ->
        {domain, did, _doc} = current
        state = tell(state, uid, domain, did, nil)

        # the room moved to another resource: report it there — unless the
        # withdrawal failed, which the next transition retries
        if wanted == nil or Map.has_key?(state.reported, uid),
          do: state,
          else: reconcile(state, uid)

      true ->
        {domain, did, doc} = wanted
        tell(state, uid, domain, did, doc)
    end
  end

  defp wanted(_state, nil), do: nil

  defp wanted(_state, %{did: did, domain: domain})
       when not is_binary(did) or not is_binary(domain),
       do: nil

  defp wanted(state, row) do
    if state.domains == nil or MapSet.member?(state.domains, String.downcase(row.domain)),
      do: {row.domain, row.did, room_doc(row)}
  end

  defp key({domain, did, _doc}), do: {String.downcase(domain), did}

  defp tell(state, uid, domain, did, doc) do
    case Presence.report(domain, did, :mcu, doc) do
      :ok ->
        reported =
          if doc == nil,
            do: Map.delete(state.reported, uid),
            else: Map.put(state.reported, uid, {domain, did, doc})

        %{state | reported: reported}

      {:error, reason} ->
        # left as it was: the next transition of this room, or the resync after
        # presence comes back, tries again
        Logger.warning(
          module: __MODULE__,
          message: "presence of room sip:#{did}@#{domain} not reported: #{inspect(reason)}"
        )

        state
    end
  end
end
