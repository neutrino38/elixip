defmodule Kelix.Mod.Registrar.Contact do
  @moduledoc "One stored contact binding for an AOR (design §6.1)."

  @type t :: %__MODULE__{
          contact: SIP.Uri.t(),
          received: {String.t() | nil, tuple, non_neg_integer} | nil,
          flow_pid: pid | nil,
          flow_module: module | nil,
          dialog_pid: pid | nil,
          info: term,
          expires_at: DateTime.t()
        }

  # `flow_pid` + `flow_module` are the connection the REGISTER came in on (§6.3):
  # the pid alone is not enough to send over it — `SIP.Transport.Selector` needs to
  # know *which* transport it is (`transport_str`/`is_reliable`), and an inbound
  # request stamps its R-URI with both while the stored Contact URI carries neither.
  defstruct contact: nil,
            received: nil,
            flow_pid: nil,
            flow_module: nil,
            dialog_pid: nil,
            info: nil,
            expires_at: nil
end

defmodule Kelix.Mod.Registrar do
  @moduledoc """
  The usrloc / location service (design §6): stores AORs and their contacts, with
  **strong per-domain separation** — one ETS table per domain plus a
  `%{domain => tid}` index (§6.1, decided 2026-07-26). AOR = the `To` user-part
  (RFC 3261).

  Facade (imported by the registrar script):
    * `save/4`   — register/unregister from a REGISTER; returns the granted
      contacts/expires (it does **not** compose the SIP response — the script
      does, via SIP.Session.Registrar helpers, §11.1);
    * `lookup/1` — rewrite a request to reach the registered UA(s);
    * `subscribe_register_event/2` / `unsubscribe_register_event/2`.

  Delivered as a loadable `Kelix.Module` (P5): `validate_config/1`, `child_spec/2`
  and `describe/0` below; the facades route through `Kelix.Module.safe_call/3` so
  a down store never blocks nor crashes the scenario instance. Hooking the dialogue
  layer for expiry / connected-transport drop is §6.4/P3c; for now expiry is
  time-checked on read.
  """
  use GenServer
  @behaviour Kelix.Module
  require Logger

  alias Kelix.Mod.Registrar.Contact

  @default_expires 3600
  @min_expires 60
  @default_max_contacts 10
  @sweep_ms 30_000

  # state:
  #   tables   %{domain => :ets.tid}          per-domain AOR store (aor => [Contact])
  #   subs     %{"aor@domain" => MapSet(pid)} register-event subscribers
  #   mons     %{monitor_ref => {domain, aor, dialog_pid}}  connected-flow monitors
  defstruct tables: %{},
            subs: %{},
            mons: %{},
            max_contacts: @default_max_contacts,
            min_expires: @min_expires,
            sweep_ms: @sweep_ms

  # ── API ──────────────────────────────────────────────────────────────────────

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  # ── Kelix.Module behaviour ───────────────────────────────────────────────────

  @impl Kelix.Module
  def child_spec(_name, config) do
    opts =
      [max_contacts_per_aor: config["max_contacts_per_aor"], min_expires: config["min_expires"]]
      |> Enum.reject(fn {_k, v} -> is_nil(v) end)

    %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}}
  end

  # Every key a [module.registrar] block may carry. `module` is the generic
  # module-resolution key handled by Kelix.ModuleSupervisor.
  @config_keys ~w(module max_contacts_per_aor min_expires call_timeout_ms)

  @impl Kelix.Module
  def validate_config(config) when is_map(config) do
    with :ok <- reject_unknown_keys(config),
         :ok <- pos_int_ok(config, "max_contacts_per_aor"),
         :ok <- pos_int_ok(config, "min_expires"),
         :ok <- pos_int_ok(config, "call_timeout_ms") do
      :ok
    end
  end

  def validate_config(_), do: {:error, "block must be a table"}

  @impl Kelix.Module
  def describe(),
    do: %{
      version: "1.0",
      exports: [save: 4, lookup: 1, subscribe_register_event: 2, unsubscribe_register_event: 2]
    }

  defp pos_int_ok(config, key) do
    case Map.get(config, key) do
      nil -> :ok
      v when is_integer(v) and v > 0 -> :ok
      _ -> {:error, "#{key} must be a positive integer"}
    end
  end

  # Fail fast on a typo instead of silently running on the default.
  defp reject_unknown_keys(config) do
    case Map.keys(config) -- @config_keys do
      [] -> :ok
      extra -> {:error, "unknown key(s): #{Enum.join(Enum.sort(extra), ", ")}"}
    end
  end

  @doc """
  Register/unregister the contacts of a REGISTER `req` under `domain`. `dialog_pid`
  is the backing dialog (stored per contact, used later for teardown); `info` is
  arbitrary scenario data. Returns `{:ok, granted}` (contacts + expires actually
  granted) or `{:error, {code, reason}}`.
  """
  @spec save(map, String.t(), pid | nil, term) :: {:ok, map} | {:error, {integer, String.t()}}
  def save(req, domain, dialog_pid \\ nil, info \\ nil),
    do: Kelix.Module.safe_call(__MODULE__, {:save, req, domain, dialog_pid, info})

  @doc "Rewrite `req` to reach the AOR's registered contacts. `{:ok, [req]}` / `:notfound` / `{:error, r}`."
  @spec lookup(map) :: {:ok, [map]} | :notfound | {:error, term}
  def lookup(req), do: Kelix.Module.safe_call(__MODULE__, {:lookup, req})

  @doc """
  The shortest registration this store will grant (seconds).

  Exists so the script can put the mandatory `Min-Expires` header on the `423`
  `save/4` returns (RFC 3261 §10.3 step 7) without duplicating the bound: the
  module owns the policy, the script composes the response (§11.1). Falls back to
  the built-in default when the store is down.
  """
  @spec min_expires() :: pos_integer
  def min_expires() do
    case Kelix.Module.safe_call(__MODULE__, :min_expires) do
      n when is_integer(n) and n > 0 -> n
      _ -> @min_expires
    end
  end

  @doc "Raw current contacts for an AOR (expired ones filtered out)."
  @spec bindings(String.t(), String.t()) :: [Contact.t()]
  def bindings(domain, aor), do: Kelix.Module.safe_call(__MODULE__, {:bindings, domain, aor})

  @doc "All live bindings of a domain, as `%{aor => [Contact]}` (for status/CLI)."
  @spec all(String.t()) :: %{optional(String.t()) => [Contact.t()]}
  def all(domain), do: Kelix.Module.safe_call(__MODULE__, {:all, domain})

  @doc "Subscribe `pid` to `{:registrar, event, \"aor@domain\"}` events for `uri` (may be unregistered)."
  @spec subscribe_register_event(SIP.Uri.t(), pid) :: :ok
  def subscribe_register_event(uri, pid),
    do: Kelix.Module.safe_call(__MODULE__, {:subscribe, uri, pid})

  @spec unsubscribe_register_event(SIP.Uri.t(), pid) :: :ok
  def unsubscribe_register_event(uri, pid),
    do: Kelix.Module.safe_call(__MODULE__, {:unsubscribe, uri, pid})

  @doc """
  Administratively remove an AOR's binding(s) (for `kelictl unregister`). `contact`
  is a specific contact-URI string, or `:all` to drop the whole AOR. Returns `:ok`,
  `:notfound`, or a facade error (`{:error, :down | :timeout}`).
  """
  @spec remove(String.t(), String.t(), String.t() | :all) :: :ok | :notfound | {:error, term}
  def remove(domain, aor, contact \\ :all),
    do: Kelix.Module.safe_call(__MODULE__, {:remove, domain, downcase(aor), contact})

  # ── GenServer ────────────────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    sweep_ms = Keyword.get(opts, :sweep_ms, @sweep_ms)
    Process.send_after(self(), :sweep, sweep_ms)

    {:ok,
     %__MODULE__{
       max_contacts: Keyword.get(opts, :max_contacts_per_aor, @default_max_contacts),
       min_expires: Keyword.get(opts, :min_expires, @min_expires),
       sweep_ms: sweep_ms
     }}
  end

  @impl true
  def handle_call({:save, req, domain, dialog_pid, info}, _from, state) do
    case do_save(state, req, domain, dialog_pid, info) do
      {:ok, granted, state2} -> {:reply, {:ok, granted}, state2}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:lookup, req}, _from, state) do
    {:reply, do_lookup(state, req), state}
  end

  def handle_call(:min_expires, _from, state), do: {:reply, state.min_expires, state}

  def handle_call({:bindings, domain, aor}, _from, state) do
    {:reply, live_contacts(state, domain, downcase(aor)), state}
  end

  def handle_call({:all, domain}, _from, state) do
    result =
      case Map.get(state.tables, domain) do
        nil ->
          %{}

        tid ->
          for {aor, _} <- :ets.tab2list(tid),
              into: %{},
              do: {aor, live_contacts(state, domain, aor)}
      end

    {:reply, result, state}
  end

  def handle_call({:subscribe, uri, pid}, _from, state) do
    key = aor_key(uri)
    subs = Map.update(state.subs, key, MapSet.new([pid]), &MapSet.put(&1, pid))
    {:reply, :ok, %{state | subs: subs}}
  end

  def handle_call({:unsubscribe, uri, pid}, _from, state) do
    key = aor_key(uri)
    subs = Map.update(state.subs, key, MapSet.new(), &MapSet.delete(&1, pid))
    {:reply, :ok, %{state | subs: subs}}
  end

  def handle_call({:remove, domain, aor, which}, _from, state) do
    {reply, state2} = do_remove(state, domain, aor, which)
    {:reply, reply, state2}
  end

  # ── save ─────────────────────────────────────────────────────────────────────

  defp do_save(state, req, domain, dialog_pid, info) do
    with {:ok, aor} <- aor_of(req),
         contacts = List.wrap(Map.get(req, :contact)) |> Enum.reject(&is_nil/1),
         {:ok, actions} <- plan_contacts(contacts, Map.get(req, :expires), state.min_expires) do
      apply_actions(state, domain, aor, actions, req, dialog_pid, info)
    end
  end

  # Decide, per contact, whether to add (with granted expires) or remove (expires 0).
  defp plan_contacts([], _header, _min), do: {:error, {400, "No Contact"}}

  # `Contact: *` — remove every binding of the AOR (RFC 3261 §10.2.2). It is only
  # legal alone and with `Expires: 0`; anything else is a malformed request, not a
  # partial wildcard.
  defp plan_contacts(contacts, header_exp, min_exp) when is_list(contacts) do
    if Enum.any?(contacts, &wildcard?/1) do
      cond do
        length(contacts) > 1 ->
          {:error, {400, "Wildcard Contact must be the only one"}}

        header_or_default(header_exp) != 0 ->
          {:error, {400, "Wildcard Contact requires Expires: 0"}}

        true ->
          {:ok, [:remove_all]}
      end
    else
      plan_each_contact(contacts, header_exp, min_exp)
    end
  end

  defp wildcard?(:*), do: true
  defp wildcard?("*"), do: true
  defp wildcard?(_), do: false

  defp plan_each_contact(contacts, header_exp, min_exp) do
    Enum.reduce_while(contacts, {:ok, []}, fn c, {:ok, acc} ->
      exp = requested_expires(c, header_exp)

      cond do
        exp == 0 -> {:cont, {:ok, [{:remove, c} | acc]}}
        exp < min_exp -> {:halt, {:error, {423, "Interval Too Brief"}}}
        true -> {:cont, {:ok, [{:add, c, min(exp, @default_expires)} | acc]}}
      end
    end)
    |> case do
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      err -> err
    end
  end

  defp apply_actions(state, domain, aor, actions, req, dialog_pid, info) do
    # `[:remove_all]` (wildcard) and an all-`{:remove, _}` plan converge on the
    # same outcome: the AOR loses every binding it had.
    unregister? = actions == [:remove_all] or Enum.all?(actions, &match?({:remove, _}, &1))
    tid = table_for(state, domain)
    state = put_table(state, domain, tid)
    existing = live_contacts_from(tid, aor)

    if unregister? do
      :ets.delete(tid, aor)
      state = demonitor_aor(state, domain, aor)
      notify(state, domain, aor, :unregistered)
      {:ok, granted(aor, [], 0), state}
    else
      # apply removes then adds, keyed by contact URI string
      kept = drop_contacts(existing, for({:remove, c} <- actions, do: uri_key(c)))

      added =
        for {:add, c, exp} <- actions do
          %Contact{
            contact: c,
            received: received_of(req),
            flow_pid: flow_of(req),
            flow_module: flow_module_of(req),
            dialog_pid: dialog_pid,
            info: info,
            expires_at: DateTime.add(now(), exp, :second)
          }
        end

      merged = upsert(kept, added)

      if length(merged) > state.max_contacts do
        {:error, {403, "Too many contacts"}}
      else
        :ets.insert(tid, {aor, merged})
        # Monitor the backing dialog so a connected-transport drop invalidates the
        # binding (§6.3, WebRTC-critical).
        state = ensure_monitor(state, domain, aor, dialog_pid)
        notify(state, domain, aor, :registered)
        {:ok, granted(aor, added, granted_expires(actions)), state}
      end
    end
  end

  # ── administrative removal (kelictl unregister) ──────────────────────────────

  defp do_remove(state, domain, aor, which) do
    case Map.get(state.tables, domain) do
      nil -> {:notfound, state}
      tid -> remove_from(state, domain, aor, which, tid, live_contacts_from(tid, aor))
    end
  end

  defp remove_from(state, _domain, _aor, _which, _tid, []), do: {:notfound, state}

  defp remove_from(state, domain, aor, :all, tid, _contacts) do
    :ets.delete(tid, aor)
    state = demonitor_aor(state, domain, aor)
    notify(state, domain, aor, :unregistered)
    {:ok, state}
  end

  defp remove_from(state, domain, aor, contact_str, tid, contacts) do
    kept = Enum.reject(contacts, &(uri_key(&1.contact) == contact_str))

    cond do
      kept == contacts ->
        {:notfound, state}

      kept == [] ->
        :ets.delete(tid, aor)
        state = demonitor_aor(state, domain, aor)
        notify(state, domain, aor, :unregistered)
        {:ok, state}

      true ->
        :ets.insert(tid, {aor, kept})
        notify(state, domain, aor, :registered)
        {:ok, state}
    end
  end

  # ── expiry sweep + connected-flow monitoring ─────────────────────────────────

  @impl true
  def handle_info(:sweep, state) do
    state = Enum.reduce(Map.keys(state.tables), state, &sweep_domain(&2, &1))
    Process.send_after(self(), :sweep, state.sweep_ms)
    {:noreply, state}
  end

  # a monitored dialog/flow died: drop its bindings and emit :disconnected
  def handle_info({:DOWN, ref, :process, dead_pid, _reason}, state) do
    case Map.pop(state.mons, ref) do
      {nil, _} ->
        {:noreply, state}

      {{domain, aor, _pid}, mons} ->
        tid = Map.get(state.tables, domain)

        remaining =
          tid && live_contacts_from(tid, aor) |> Enum.reject(&(&1.dialog_pid == dead_pid))

        store_or_delete(tid, aor, remaining || [])
        notify(state, domain, aor, :disconnected)
        {:noreply, %{state | mons: mons}}
    end
  end

  def handle_info(_msg, state), do: {:noreply, state}

  defp sweep_domain(state, domain) do
    tid = Map.get(state.tables, domain)

    Enum.reduce(:ets.tab2list(tid), state, fn {aor, contacts}, st ->
      {live, expired} = Enum.split_with(contacts, &(not expired?(&1)))

      if expired == [] do
        st
      else
        store_or_delete(tid, aor, live)
        notify(st, domain, aor, :expired)
        if live == [], do: demonitor_aor(st, domain, aor), else: st
      end
    end)
  end

  defp store_or_delete(tid, aor, []), do: :ets.delete(tid, aor)
  defp store_or_delete(tid, aor, contacts), do: :ets.insert(tid, {aor, contacts})

  defp ensure_monitor(state, _domain, _aor, pid) when not is_pid(pid), do: state

  defp ensure_monitor(state, domain, aor, pid) do
    already? = Enum.any?(state.mons, fn {_ref, key} -> key == {domain, aor, pid} end)

    if already? do
      state
    else
      ref = Process.monitor(pid)
      %{state | mons: Map.put(state.mons, ref, {domain, aor, pid})}
    end
  end

  defp demonitor_aor(state, domain, aor) do
    {to_drop, kept} =
      Enum.split_with(state.mons, fn {_ref, {d, a, _pid}} -> d == domain and a == aor end)

    Enum.each(to_drop, fn {ref, _} -> Process.demonitor(ref, [:flush]) end)
    %{state | mons: Map.new(kept)}
  end

  # ── lookup ───────────────────────────────────────────────────────────────────

  defp do_lookup(state, req) do
    with %SIP.Uri{userpart: user, domain: dom} when is_binary(user) <- Map.get(req, :ruri) do
      aor = downcase(user)
      domain = fold_alias(dom)

      case live_contacts(state, domain, aor) do
        [] -> :notfound
        contacts -> {:ok, Enum.map(contacts, &rewrite(req, &1))}
      end
    else
      _ -> {:error, :no_ruri}
    end
  end

  # A copy of req with its R-URI replaced by the stored contact + the resolved
  # destination and flow. Both are what `SIP.Transport.Selector.select_transport/1`
  # short-circuits on (§6.4): a live `tp_pid`+`tp_module` sends straight over the
  # existing connection, and failing that `destip`/`destport` skip DNS.
  defp rewrite(req, %Contact{contact: c} = binding) do
    ruri =
      case binding.received do
        {proto, ip, port} ->
          %SIP.Uri{
            c
            | destip: ip,
              destport: port,
              destproto: proto,
              tp_pid: binding.flow_pid,
              tp_module: binding.flow_module
          }

        _ ->
          %SIP.Uri{c | tp_pid: binding.flow_pid, tp_module: binding.flow_module}
      end

    Map.put(req, :ruri, ruri)
  end

  # ── contact / expires helpers ────────────────────────────────────────────────

  defp requested_expires(contact, header_exp) do
    case SIP.Uri.get_uri_param(contact, "expires") do
      {:ok, v} -> to_int(v, header_or_default(header_exp))
      _ -> header_or_default(header_exp)
    end
  end

  defp header_or_default(exp) when is_integer(exp), do: exp
  defp header_or_default(_), do: @default_expires

  defp to_int(v, default) when is_binary(v) do
    case Integer.parse(v) do
      {n, _} -> n
      :error -> default
    end
  end

  # A valueless URI param (";expires" with no "=") is parsed as `true`.
  defp to_int(_v, default), do: default

  defp granted_expires(actions) do
    case for({:add, _c, exp} <- actions, do: exp) do
      [exp | _] -> exp
      [] -> 0
    end
  end

  defp granted(aor, contacts, expires) do
    %{aor: aor, contacts: Enum.map(contacts, & &1.contact), expires: expires}
  end

  # ── storage helpers ──────────────────────────────────────────────────────────

  defp table_for(state, domain) do
    case Map.get(state.tables, domain) do
      nil -> :ets.new(:"kelix_usrloc_#{domain}", [:set, :private])
      tid -> tid
    end
  end

  defp put_table(state, domain, tid), do: %{state | tables: Map.put(state.tables, domain, tid)}

  defp live_contacts(state, domain, aor) do
    case Map.get(state.tables, domain) do
      nil -> []
      tid -> live_contacts_from(tid, aor)
    end
  end

  defp live_contacts_from(tid, aor) do
    case :ets.lookup(tid, aor) do
      [{^aor, contacts}] -> Enum.filter(contacts, &(not expired?(&1)))
      [] -> []
    end
  end

  defp expired?(%Contact{expires_at: at}), do: DateTime.compare(now(), at) != :lt

  defp drop_contacts(contacts, keys) do
    Enum.reject(contacts, &(uri_key(&1.contact) in keys))
  end

  # replace same-URI existing contacts with the new ones, then append the rest
  defp upsert(existing, added) do
    added_keys = MapSet.new(added, &uri_key(&1.contact))
    Enum.reject(existing, &(uri_key(&1.contact) in added_keys)) ++ added
  end

  # ── events ───────────────────────────────────────────────────────────────────

  defp notify(state, domain, aor, event) do
    key = "#{aor}@#{domain}"

    for pid <- Map.get(state.subs, key, MapSet.new()) do
      send(pid, {:registrar, event, key})
    end

    # observability (§11): registrar lifecycle counter, per domain
    Kelix.Metrics.Emit.registrar_event(domain, event)
    :ok
  end

  # ── request field helpers ────────────────────────────────────────────────────

  # The AOR is the To user-part (§6.1, §16 #9). Beware: `SIPMsg` leaves `:to` as
  # the RAW header string (only `:ruri` and `:contact` are parsed into a
  # `%SIP.Uri{}`), so an inbound REGISTER arrives here with a binary — parse it.
  # A struct is accepted too: that is what a scenario/test hands over directly.
  defp aor_of(req) do
    case to_uri(Map.get(req, :to)) do
      %SIP.Uri{userpart: u} when is_binary(u) and u != "" -> {:ok, downcase(u)}
      _ -> {:error, {400, "Missing To user-part (AOR)"}}
    end
  end

  defp to_uri(%SIP.Uri{} = uri), do: uri

  defp to_uri(header) when is_binary(header) do
    case SIP.Uri.parse(header) do
      {:ok, uri} -> uri
      _ -> nil
    end
  end

  defp to_uri(_), do: nil

  defp received_of(req) do
    case Map.get(req, :ruri) do
      %SIP.Uri{destip: ip, destport: port, destproto: proto} when not is_nil(ip) ->
        {proto, ip, port}

      _ ->
        nil
    end
  end

  defp flow_of(req) do
    case Map.get(req, :ruri) do
      %SIP.Uri{tp_pid: pid} -> pid
      _ -> nil
    end
  end

  defp flow_module_of(req) do
    case Map.get(req, :ruri) do
      %SIP.Uri{tp_module: t_mod} -> t_mod
      _ -> nil
    end
  end

  defp aor_key(%SIP.Uri{userpart: u, domain: d}), do: "#{downcase(u)}@#{fold_alias(d)}"

  # alias → nominal domain name (folds via Domains if running; else identity)
  defp fold_alias(nil), do: nil

  defp fold_alias(host) do
    with pid when not is_nil(pid) <- Process.whereis(Kelix.Domains),
         %Kelix.Domain{name: name} <- Kelix.Domains.lookup(Kelix.Domains.current(), host) do
      name
    else
      _ -> host
    end
  end

  # serialize/1 always succeeds on a %SIP.Uri{}, hence the hard match.
  defp uri_key(%SIP.Uri{} = u) do
    {:ok, s} = SIP.Uri.serialize(u)
    s
  end

  defp downcase(s) when is_binary(s), do: String.downcase(s)
  defp now(), do: DateTime.utc_now()
end
