defmodule Kelix.Mod.Registrar.Contact do
  @moduledoc "One stored contact binding for an AOR (design §6.1)."

  @type t :: %__MODULE__{
          contact: SIP.Uri.t(),
          received: {String.t(), tuple, non_neg_integer} | nil,
          flow_pid: pid | nil,
          dialog_pid: pid | nil,
          info: term,
          expires_at: DateTime.t()
        }

  defstruct contact: nil, received: nil, flow_pid: nil, dialog_pid: nil, info: nil, expires_at: nil
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

  It will be delivered as a loadable `Kelix.Module` (P5) and hook the dialogue
  layer for expiry / connected-transport drop (§6.4, P3c). For now it is a plain
  supervised GenServer; expiry is time-checked on read.
  """
  use GenServer
  require Logger

  alias Kelix.Mod.Registrar.Contact

  @default_expires 3600
  @min_expires 60
  @default_max_contacts 10

  # state:
  #   tables   %{domain => :ets.tid}          per-domain AOR store (aor => [Contact])
  #   subs     %{"aor@domain" => MapSet(pid)} register-event subscribers
  defstruct tables: %{}, subs: %{}, max_contacts: @default_max_contacts

  # ── API ──────────────────────────────────────────────────────────────────────

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc """
  Register/unregister the contacts of a REGISTER `req` under `domain`. `dialog_pid`
  is the backing dialog (stored per contact, used later for teardown); `info` is
  arbitrary scenario data. Returns `{:ok, granted}` (contacts + expires actually
  granted) or `{:error, {code, reason}}`.
  """
  @spec save(map, String.t(), pid | nil, term) :: {:ok, map} | {:error, {integer, String.t()}}
  def save(req, domain, dialog_pid \\ nil, info \\ nil),
    do: GenServer.call(__MODULE__, {:save, req, domain, dialog_pid, info})

  @doc "Rewrite `req` to reach the AOR's registered contacts. `{:ok, [req]}` / `:notfound` / `{:error, r}`."
  @spec lookup(map) :: {:ok, [map]} | :notfound | {:error, term}
  def lookup(req), do: GenServer.call(__MODULE__, {:lookup, req})

  @doc "Raw current contacts for an AOR (expired ones filtered out)."
  @spec bindings(String.t(), String.t()) :: [Contact.t()]
  def bindings(domain, aor), do: GenServer.call(__MODULE__, {:bindings, domain, aor})

  @doc "All live bindings of a domain, as `%{aor => [Contact]}` (for status/CLI)."
  @spec all(String.t()) :: %{optional(String.t()) => [Contact.t()]}
  def all(domain), do: GenServer.call(__MODULE__, {:all, domain})

  @doc "Subscribe `pid` to `{:registrar, event, \"aor@domain\"}` events for `uri` (may be unregistered)."
  @spec subscribe_register_event(SIP.Uri.t(), pid) :: :ok
  def subscribe_register_event(uri, pid), do: GenServer.call(__MODULE__, {:subscribe, uri, pid})

  @spec unsubscribe_register_event(SIP.Uri.t(), pid) :: :ok
  def unsubscribe_register_event(uri, pid), do: GenServer.call(__MODULE__, {:unsubscribe, uri, pid})

  # ── GenServer ────────────────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    {:ok, %__MODULE__{max_contacts: Keyword.get(opts, :max_contacts_per_aor, @default_max_contacts)}}
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

  def handle_call({:bindings, domain, aor}, _from, state) do
    {:reply, live_contacts(state, domain, downcase(aor)), state}
  end

  def handle_call({:all, domain}, _from, state) do
    result =
      case Map.get(state.tables, domain) do
        nil -> %{}
        tid -> for {aor, _} <- :ets.tab2list(tid), into: %{}, do: {aor, live_contacts(state, domain, aor)}
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

  # ── save ─────────────────────────────────────────────────────────────────────

  defp do_save(state, req, domain, dialog_pid, info) do
    with {:ok, aor} <- aor_of(req),
         contacts = List.wrap(Map.get(req, :contact)) |> Enum.reject(&is_nil/1),
         {:ok, actions} <- plan_contacts(contacts, Map.get(req, :expires)) do
      apply_actions(state, domain, aor, actions, req, dialog_pid, info)
    end
  end

  # Decide, per contact, whether to add (with granted expires) or remove (expires 0).
  defp plan_contacts([], _header), do: {:error, {400, "No Contact"}}

  defp plan_contacts(contacts, header_exp) do
    Enum.reduce_while(contacts, {:ok, []}, fn c, {:ok, acc} ->
      exp = requested_expires(c, header_exp)

      cond do
        exp == 0 -> {:cont, {:ok, [{:remove, c} | acc]}}
        exp < @min_expires -> {:halt, {:error, {423, "Interval Too Brief"}}}
        true -> {:cont, {:ok, [{:add, c, min(exp, @default_expires)} | acc]}}
      end
    end)
    |> case do
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      err -> err
    end
  end

  defp apply_actions(state, domain, aor, actions, req, dialog_pid, info) do
    unregister? = Enum.all?(actions, &match?({:remove, _}, &1))
    tid = table_for(state, domain)
    existing = live_contacts_from(tid, aor)

    if unregister? do
      :ets.delete(tid, aor)
      notify(state, domain, aor, :unregistered)
      {:ok, granted(aor, [], 0), put_table(state, domain, tid)}
    else
      # apply removes then adds, keyed by contact URI string
      kept = drop_contacts(existing, for({:remove, c} <- actions, do: uri_key(c)))

      added =
        for {:add, c, exp} <- actions do
          %Contact{
            contact: c,
            received: received_of(req),
            flow_pid: flow_of(req),
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
        notify(state, domain, aor, :registered)
        {:ok, granted(aor, added, granted_expires(actions)), put_table(state, domain, tid)}
      end
    end
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

  # a copy of req with its R-URI replaced by the stored contact + resolved dest/flow
  defp rewrite(req, %Contact{contact: c, received: received, flow_pid: flow}) do
    ruri =
      case received do
        {proto, ip, port} -> %SIP.Uri{c | destip: ip, destport: port, destproto: proto, tp_pid: flow}
        _ -> %SIP.Uri{c | tp_pid: flow}
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

  defp to_int(v, _default) when is_integer(v), do: v
  defp to_int(v, default) when is_binary(v) do
    case Integer.parse(v) do
      {n, _} -> n
      :error -> default
    end
  end

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

    :ok
  end

  # ── request field helpers ────────────────────────────────────────────────────

  defp aor_of(req) do
    case Map.get(req, :to) do
      %SIP.Uri{userpart: u} when is_binary(u) and u != "" -> {:ok, downcase(u)}
      _ -> {:error, {400, "Missing To user-part (AOR)"}}
    end
  end

  defp received_of(req) do
    case Map.get(req, :ruri) do
      %SIP.Uri{destip: ip, destport: port, destproto: proto} when not is_nil(ip) -> {proto, ip, port}
      _ -> nil
    end
  end

  defp flow_of(req) do
    case Map.get(req, :ruri) do
      %SIP.Uri{tp_pid: pid} -> pid
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

  defp uri_key(%SIP.Uri{} = u) do
    case SIP.Uri.serialize(u) do
      {:ok, s} -> s
      _ -> inspect(u)
    end
  end

  defp downcase(s) when is_binary(s), do: String.downcase(s)
  defp now(), do: DateTime.utc_now()
end
