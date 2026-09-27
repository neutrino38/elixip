defmodule Kelix.Mod.DialogState do
  @moduledoc """
  The call occupancy of the served AORs (`docs/design/dialog-state-plan.md`): the
  link between the dialogs that cross this node and `Kelix.Mod.Presence`, which
  is what a BLF key, a presence watcher and the ACD read it through.

  A dialog **stamped** with the served AOR its far end is proven to be
  (`SIP.Dialog.Events`) pushes each transition of its call state here. Per AOR,
  two documents are reported to presence, each **only when it changed**:

  | On the package | The document                                              |
  |----------------|-----------------------------------------------------------|
  | `dialog`       | one `<dialog>` per live dialog of the AOR; withdrawn when none |
  | `presence`     | `open` + RPID `on-the-phone` while one dialog is confirmed; withdrawn otherwise |

  A ringing agent is not on the phone: the ACD reads the ringing from the dialog
  row it is pushed (`subscribe_dialogs/2`), on every transition.

  Both halves are monitored. A dialog that crashes emits no `terminated`, so its
  monitor ends it here as `terminated` by `error`. A presence restart dropped
  every state this module reported, so it is a full re-report; while presence
  is down the state is kept and the report retried. A restart of this module
  resyncs from the dialogs still alive (`SIP.Dialog.pids/0`, `SIP.Dialog.info/1`).

  No SIP function, no script, no facade a script imports: `kelictl dialog_state
  list` and the ACD push are its whole surface.
  """
  use GenServer
  @behaviour Kelix.Module
  require Logger

  alias Kelix.Mod.Presence

  @retry_ms 1_000
  @states [:trying, :proceeding, :early, :confirmed, :terminated]

  # state:
  #   domains   nil (every served domain) or a MapSet of downcased domain names
  #   dialogs   %{pid => {key, info}} the live stamped dialogs, `info` as
  #             SIP.Dialog.Events pushes it, `key` = {domain, user} of its AOR
  #   monitors  %{monitor_ref => pid} one per dialog followed
  #   reported  %{key => %{dialog: doc | nil, presence: doc | nil}} what presence
  #             was last told
  #   presence  monitor ref of the presence module, nil when not running
  #   subs      %{domain => MapSet(pid)} the ACD subscribers
  #   sub_mons  %{monitor_ref => {domain, pid}}
  defstruct domains: nil,
            dialogs: %{},
            monitors: %{},
            reported: %{},
            presence: nil,
            subs: %{},
            sub_mons: %{},
            retry_ms: @retry_ms,
            retrying: false

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  # ── Kelix.Module behaviour ───────────────────────────────────────────────────

  @impl Kelix.Module
  def child_spec(_name, config),
    do: %{id: __MODULE__, start: {__MODULE__, :start_link, [[domains: domains(config)]]}}

  @config_keys ~w(module domains)

  # The link means nothing without presence: a node configured without it fails
  # at start, not on the first call.
  @impl Kelix.Module
  def validate_config(config) when is_map(config) do
    with :ok <- reject_unknown_keys(config),
         :ok <- domains_ok(config) do
      if presence_missing?(configured_modules()),
        do: {:error, "needs the presence module loaded"},
        else: :ok
    end
  end

  def validate_config(_), do: {:error, "block must be a table"}

  @impl Kelix.Module
  def reload(_name, config), do: GenServer.call(__MODULE__, {:reload, domains(config)})

  @impl Kelix.Module
  def describe(),
    do: %{version: "1.0", exports: [subscribe_dialogs: 2, unsubscribe_dialogs: 2]}

  @impl Kelix.Module
  def describe_control() do
    [
      %{
        name: "list",
        rest: {:get, "/dialogs"},
        rw: :r,
        args: [%{name: "domain", required: true}],
        render: %{
          kind: :table,
          columns: ~w(aor callid direction state remote since presence)
        },
        help: "The live calls of a domain's users, and the presence each AOR was reported in"
      }
    ]
  end

  @impl Kelix.Module
  def handle_control("list", %{"domain" => domain}), do: {:ok, dialogs(domain)}

  def handle_control(command, args) when is_map(args) do
    case Map.get(args, "domain") do
      nil -> {:error, "domain is required"}
      _ -> {:error, {:unknown_command, command}}
    end
  end

  @doc "The live dialogs of a domain, as rendered rows (`kelictl dialog_state list`)."
  @spec dialogs(String.t()) :: [map] | {:error, :down | :timeout}
  def dialogs(domain) when is_binary(domain),
    do: Kelix.Module.safe_call(__MODULE__, {:dialogs, domain_name(domain)})

  @doc """
  Subscribe `pid` to the live dialogs of `domain`'s users as they change — the
  module half of `Kelix.Control.subscribe_dialogs/2`, the ACD's feed.

  Answers `{:ok, %{owner, dialogs}}`: the rows as they stand, taken in the same
  call that registers `pid` so no transition falls between the two, and the
  process holding the subscription. `pid` then receives `{:kelix_dialogs, domain,
  {:upsert, row}}` on every transition of a dialog — the last one being
  `terminated`, with why — then `{:kelix_dialogs, domain, {:remove, id}}` once
  it is gone. `pid` is monitored, so a dead subscriber is dropped on its own.

  A row is one dialog, read from its AOR's point of view (RFC 4235):

      %{domain, aor, id, direction, state, event, remote, since}

  `aor` is `sip:user@domain`, `id` the Call-ID, `direction` `:initiator` when
  the AOR placed the call and `:recipient` when it received it, `state` one of
  RFC 4235's five, `event` why it ended (`:terminated` only), `remote` the other
  party as the request names it, `since` when the dialog was created — answered
  when confirmed.
  """
  @spec subscribe_dialogs(String.t(), pid) ::
          {:ok, %{owner: pid, dialogs: [map]}} | {:error, :down | :timeout}
  def subscribe_dialogs(domain, pid) when is_binary(domain) and is_pid(pid),
    do: Kelix.Module.safe_call(__MODULE__, {:subscribe, domain_name(domain), pid})

  @doc "Stop a subscription started by `subscribe_dialogs/2`."
  @spec unsubscribe_dialogs(String.t(), pid) :: :ok | {:error, :down | :timeout}
  def unsubscribe_dialogs(domain, pid) when is_binary(domain) and is_pid(pid),
    do: Kelix.Module.safe_call(__MODULE__, {:unsubscribe, domain_name(domain), pid})

  @doc false
  # Whether `presence` is neither configured nor installed. `configured` is nil
  # when there is no configuration to consult (a unit test).
  @spec presence_missing?([String.t()] | nil) :: boolean
  def presence_missing?(configured) do
    not ((configured == nil or "presence" in configured) and
           Kelix.ModuleSupervisor.ensure_loaded(Presence))
  end

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

  # ── GenServer ────────────────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    state = %__MODULE__{
      domains: Keyword.get(opts, :domains),
      retry_ms: Keyword.get(opts, :retry_ms, @retry_ms)
    }

    # Subscribed BEFORE the resync: a transition between the two is then in the
    # mailbox, and `forward?/2` keeps an event older than the snapshot from
    # moving a dialog back.
    :ok = SIP.Dialog.Events.subscribe()
    {:ok, state, {:continue, :sync}}
  end

  @impl true
  def handle_continue(:sync, state), do: {:noreply, state |> resync() |> sync()}

  @impl true
  def handle_call({:dialogs, domain}, _from, state), do: {:reply, rows(state, domain), state}

  def handle_call({:subscribe, domain, pid}, _from, state) do
    subs = Map.get(state.subs, domain, MapSet.new())

    state =
      if MapSet.member?(subs, pid) do
        state
      else
        ref = Process.monitor(pid)

        %{
          state
          | subs: Map.put(state.subs, domain, MapSet.put(subs, pid)),
            sub_mons: Map.put(state.sub_mons, ref, {domain, pid})
        }
      end

    {:reply, {:ok, %{owner: self(), dialogs: acd_rows(state, domain)}}, state}
  end

  def handle_call({:unsubscribe, domain, pid}, _from, state),
    do: {:reply, :ok, drop_sub(state, domain, pid)}

  def handle_call({:reload, domains}, _from, state),
    do: {:reply, :ok, reconcile_all(%{state | domains: domains})}

  @impl true
  def handle_info({:sip_dialog, pid, %{state: :terminated} = info}, state) do
    case Map.get(state.dialogs, pid) do
      nil -> {:noreply, state}
      {key, _seen} -> {:noreply, end_dialog(state, pid, key, info)}
    end
  end

  def handle_info({:sip_dialog, pid, info}, state) do
    case Map.get(state.dialogs, pid) do
      {key, seen} ->
        if forward?(seen, info),
          do: {:noreply, transition(state, pid, key, info)},
          else: {:noreply, state}

      nil ->
        case key_of(info) do
          nil -> {:noreply, state}
          key -> {:noreply, state |> follow(pid) |> transition(pid, key, info)}
        end
    end
  end

  # A dialog that crashed: `terminate/2` never ran, so nothing said it ended.
  def handle_info({:DOWN, ref, :process, pid, _reason}, %{monitors: mons} = state)
      when is_map_key(mons, ref) do
    state = %{state | monitors: Map.delete(mons, ref)}

    case Map.get(state.dialogs, pid) do
      nil ->
        {:noreply, state}

      {key, info} ->
        {:noreply, end_dialog(state, pid, key, %{info | state: :terminated, event: :error})}
    end
  end

  # Presence restarted, and dropped every state we reported with the old process.
  def handle_info({:DOWN, ref, :process, _pid, _reason}, %{presence: ref} = state) do
    {:noreply, sync(%{state | presence: nil, reported: %{}})}
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    case Map.get(state.sub_mons, ref) do
      nil -> {:noreply, state}
      {domain, pid} -> {:noreply, drop_sub(state, domain, pid)}
    end
  end

  def handle_info(:retry, state), do: {:noreply, sync(%{state | retrying: false})}

  def handle_info(_msg, state), do: {:noreply, state}

  # ── the dialogs followed ─────────────────────────────────────────────────────

  # The dialogs alive when this module starts: the ones stamped, still in a call
  # state, on a served domain. A dialog that dies under the read is skipped; its
  # events, if it is still there to send them, admit it later.
  defp resync(state) do
    Enum.reduce(SIP.Dialog.pids(), state, fn pid, st ->
      with %{method: :INVITE, remote_aor: %SIP.Uri{}} = info <- read_info(pid),
           false <- info.state == :terminated,
           key when key != nil <- key_of(info) do
        st |> follow(pid) |> store(pid, key, info)
      else
        _ -> st
      end
    end)
  end

  defp read_info(pid) do
    SIP.Dialog.info(pid)
  catch
    :exit, _ -> nil
  end

  # The AOR's domain as `domains.toml` names it — a stamp carries the nominal
  # name already (the registrar folds it, the digest's realm is it), and one
  # this node does not serve is not this module's to report. With no
  # configuration to consult (a unit test) the name is taken as it is.
  defp key_of(%{remote_aor: %SIP.Uri{userpart: user, domain: domain}})
       when is_binary(user) and is_binary(domain) do
    case served_domain(domain) do
      nil -> nil
      name -> {name, String.downcase(user)}
    end
  end

  defp key_of(_info), do: nil

  # What an operator or a caller names, folded as the dialogs are keyed: an alias
  # is its domain; a name this node does not serve answers nothing either way.
  defp domain_name(domain), do: served_domain(domain) || String.downcase(domain)

  defp served_domain(domain) do
    case Process.whereis(Kelix.Domains) do
      nil ->
        String.downcase(domain)

      _pid ->
        case Kelix.Domains.lookup(Kelix.Domains.current(), domain) do
          %Kelix.Domain{name: name} -> name
          nil -> nil
        end
    end
  end

  defp follow(state, pid) do
    if Enum.any?(state.monitors, fn {_ref, p} -> p == pid end),
      do: state,
      else: %{state | monitors: Map.put(state.monitors, Process.monitor(pid), pid)}
  end

  defp store(state, pid, key, info),
    do: %{state | dialogs: Map.put(state.dialogs, pid, {key, info})}

  # A call state only goes forward (SIP.Dialog.Events): an event queued before
  # the resync read a later state is old news.
  defp forward?(seen, info), do: index(info.state) > index(seen.state)

  defp index(state), do: Enum.find_index(@states, &(&1 == state))

  defp transition(state, pid, {domain, _user} = key, info) do
    state
    |> store(pid, key, info)
    |> push(domain, {:upsert, row(key, info)})
    |> reconcile(key)
  end

  # The last thing the ACD hears of a dialog is why it ended, then that it is gone.
  defp end_dialog(state, pid, {domain, _user} = key, info) do
    state = %{state | dialogs: Map.delete(state.dialogs, pid)}

    state =
      case Enum.find(state.monitors, fn {_ref, p} -> p == pid end) do
        nil ->
          state

        {ref, _pid} ->
          Process.demonitor(ref, [:flush])
          %{state | monitors: Map.delete(state.monitors, ref)}
      end

    state
    |> push(domain, {:upsert, row(key, info)})
    |> push(domain, {:remove, info.callid})
    |> reconcile(key)
  end

  # ── presence, in step ────────────────────────────────────────────────────────

  defp sync(state) do
    state = ensure_presence(state)

    if state.presence,
      do: reconcile_all(state),
      else: schedule_retry(state)
  end

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

  defp reconcile_all(state) do
    keys = for {_pid, {key, _info}} <- state.dialogs, do: key
    Enum.reduce(Enum.uniq(keys ++ Map.keys(state.reported)), state, &reconcile(&2, &1))
  end

  # One AOR brought in step: each of its two documents reported when it is not
  # the one presence already holds — nothing for a transition that changes
  # neither, a withdrawal (`nil`) when the last dialog went or the domain left
  # the configured ones.
  defp reconcile(%{presence: nil} = state, _key), do: state

  defp reconcile(state, key) do
    infos = if in_scope?(state, key), do: live_infos(state, key), else: []
    current = Map.get(state.reported, key, %{dialog: nil, presence: nil})

    state
    |> tell(key, :dialog, dialog_doc(key, infos), current.dialog)
    |> tell(key, :presence, presence_doc(key, infos), current.presence)
  end

  defp tell(state, _key, _package, doc, doc), do: state

  defp tell(state, {domain, user} = key, package, doc, _current) do
    result =
      case package do
        :dialog -> Presence.report(domain, user, :dialog_state, doc, "dialog")
        :presence -> Presence.report(domain, user, :dialog_state, doc)
      end

    case result do
      :ok ->
        put_reported(state, key, package, doc)

      {:error, reason} ->
        # left as it was: the next transition of this AOR, or the resync after
        # presence comes back, tries again
        Logger.warning(
          module: __MODULE__,
          message: "#{package} of sip:#{user}@#{domain} not reported: #{inspect(reason)}"
        )

        state
    end
  end

  defp put_reported(state, key, package, doc) do
    entry =
      state.reported
      |> Map.get(key, %{dialog: nil, presence: nil})
      |> Map.put(package, doc)

    reported =
      if entry == %{dialog: nil, presence: nil},
        do: Map.delete(state.reported, key),
        else: Map.put(state.reported, key, entry)

    %{state | reported: reported}
  end

  defp in_scope?(%{domains: nil}, _key), do: true
  defp in_scope?(%{domains: domains}, {domain, _user}), do: MapSet.member?(domains, domain)

  defp live_infos(state, key) do
    for {_pid, {^key, info}} <- state.dialogs, do: info
  end

  # Sorted, so two snapshots of the same calls are one document.
  defp dialog_doc(_key, []), do: nil

  defp dialog_doc(key, infos) do
    entity = aor_string(key)

    %SIP.DialogInfo.Doc{
      entity: entity,
      dialogs:
        infos
        |> Enum.sort_by(&{DateTime.to_unix(&1.created_at, :microsecond), &1.callid})
        |> Enum.map(&dialog_entry(entity, &1))
    }
  end

  # One `<dialog>`, read from the AOR's side: its tag is the From tag of a call
  # it placed and the To tag of one it received.
  defp dialog_entry(entity, info) do
    {local_tag, remote_tag} =
      case info.direction do
        :inbound -> {info.fromtag, info.totag}
        :outbound -> {info.totag, info.fromtag}
      end

    %SIP.DialogInfo.Dialog{
      id: info.callid,
      call_id: info.callid,
      local_tag: local_tag,
      remote_tag: remote_tag,
      direction: direction(info.direction),
      state: info.state,
      event: info.event,
      local: %SIP.DialogInfo.Party{identity: entity},
      remote: %SIP.DialogInfo.Party{identity: remote_party(info)}
    }
  end

  # On the phone while one call is up. Ringing is not on the phone: the ACD reads
  # it from the dialog row, and a watcher of the presence sees `open` unchanged.
  defp presence_doc(key, infos) do
    if Enum.any?(infos, &(&1.state == :confirmed)),
      do: SIP.Presence.Doc.new(aor_string(key), :open, activity: :on_the_phone)
  end

  # ── the rows ─────────────────────────────────────────────────────────────────

  defp row({domain, _user} = key, info) do
    %{
      domain: domain,
      aor: aor_string(key),
      id: info.callid,
      direction: direction(info.direction),
      state: info.state,
      event: info.event,
      remote: remote_party(info),
      since: since(info)
    }
  end

  # `direction` is the dialog's, from this node's side; the AOR is on the far end.
  defp direction(:inbound), do: :initiator
  defp direction(:outbound), do: :recipient

  # The other party: who the AOR called, or who called it.
  defp remote_party(%{direction: :inbound, to: to}), do: party_string(to)
  defp remote_party(%{direction: :outbound, from: from}), do: party_string(from)

  defp since(%{state: :confirmed, confirmed_at: %DateTime{} = at}), do: at
  defp since(%{created_at: at}), do: at

  defp aor_string({domain, user}), do: "sip:#{user}@#{domain}"

  # `From` and `To` are `%SIP.Uri{}` on a request this node built and the raw
  # header string on one it parsed: read either, keep the address only.
  defp party_string(%SIP.Uri{userpart: nil, domain: domain}), do: "sip:#{domain}"
  defp party_string(%SIP.Uri{userpart: user, domain: domain}), do: "sip:#{user}@#{domain}"

  defp party_string(value) when is_binary(value) do
    case SIP.Uri.parse(value) do
      {:ok, %SIP.Uri{} = uri} -> party_string(uri)
      _ -> value
    end
  end

  defp party_string(_other), do: nil

  defp acd_rows(state, domain) do
    for {key, info} <- domain_dialogs(state, domain), do: row(key, info)
  end

  defp domain_dialogs(state, domain) do
    for {_pid, {{^domain, _user} = key, info}} <- state.dialogs,
        in_scope?(state, key),
        do: {key, info}
  end

  # What `kelictl dialog_state list` shows: one line per live dialog, with the
  # presence its AOR was reported in beside it.
  defp rows(state, domain) do
    state
    |> domain_dialogs(domain)
    |> Enum.map(fn {key, info} ->
      row = row(key, info)

      %{
        aor: row.aor,
        callid: row.id,
        direction: to_string(row.direction),
        state: to_string(row.state),
        remote: row.remote,
        since: row.since && DateTime.to_iso8601(row.since),
        presence: reported_presence(state, key)
      }
    end)
    |> Enum.sort_by(&{&1.aor, &1.since, &1.callid})
  end

  defp reported_presence(state, key) do
    case get_in(state.reported, [key, :presence]) do
      %SIP.Presence.Doc{activity: activity} -> activity && to_string(activity)
      _ -> nil
    end
  end

  # ── the ACD push ─────────────────────────────────────────────────────────────

  defp push(state, domain, msg) do
    case Map.get(state.subs, domain) do
      nil -> :ok
      subs -> for pid <- subs, do: send(pid, {:kelix_dialogs, domain, msg})
    end

    state
  end

  defp drop_sub(state, domain, pid) do
    {refs, mons} = Enum.split_with(state.sub_mons, fn {_ref, key} -> key == {domain, pid} end)
    Enum.each(refs, fn {ref, _key} -> Process.demonitor(ref, [:flush]) end)

    subs =
      state.subs
      |> Map.get(domain, MapSet.new())
      |> MapSet.delete(pid)
      |> then(fn set ->
        if MapSet.size(set) == 0,
          do: Map.delete(state.subs, domain),
          else: Map.put(state.subs, domain, set)
      end)

    %{state | subs: subs, sub_mons: Map.new(mons)}
  end
end
