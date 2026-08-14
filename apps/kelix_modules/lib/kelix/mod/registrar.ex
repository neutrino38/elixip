defmodule Kelix.Mod.Registrar.Contact do
  @moduledoc "One stored contact binding for an AOR (design §6.1)."

  @type t :: %__MODULE__{
          contact: SIP.Uri.t(),
          received: {String.t() | nil, tuple, non_neg_integer} | nil,
          flow_pid: pid | nil,
          flow_module: module | nil,
          dialog_pid: pid | nil,
          instance: String.t() | nil,
          reg_id: String.t() | nil,
          methods: String.t() | nil,
          info: term,
          expires_at: DateTime.t()
        }

  # `flow_pid` + `flow_module` are the connection the REGISTER came in on (§6.3):
  # the pid alone is not enough to send over it — `SIP.Transport.Selector` needs to
  # know *which* transport it is (`transport_str`/`is_reliable`), and an inbound
  # request stamps its R-URI with both while the stored Contact URI carries neither.
  # `instance` + `reg_id` are the RFC 5626 (outbound) identity of the registering
  # device, `methods` its RFC 3840 callee capabilities. Kept because they say things
  # the contact URI cannot: which physical device this is (across an address change),
  # and which methods it is willing to receive.
  defstruct contact: nil,
            received: nil,
            flow_pid: nil,
            flow_module: nil,
            dialog_pid: nil,
            instance: nil,
            reg_id: nil,
            methods: nil,
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
    * `save/2`   — register/unregister from a REGISTER; says whether the AOR is left
      `:registered` or `:unregistered` and hands back the granted contacts/expires
      (it does **not** compose the SIP response — the script does, via
      SIP.Session.Registrar helpers, §11.1);
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
            default_expires: @default_expires,
            sweep_ms: @sweep_ms

  # ── API ──────────────────────────────────────────────────────────────────────

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  # ── Kelix.Module behaviour ───────────────────────────────────────────────────

  @impl Kelix.Module
  def child_spec(_name, config) do
    opts =
      [
        max_contacts_per_aor: config["max_contacts_per_aor"],
        min_expires: config["min_expires"],
        default_expires: config["default_expires"]
      ]
      |> Enum.reject(fn {_k, v} -> is_nil(v) end)

    %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}}
  end

  # Every key a [module.registrar] block may carry. `module` is the generic
  # module-resolution key handled by Kelix.ModuleSupervisor.
  @config_keys ~w(module max_contacts_per_aor min_expires default_expires call_timeout_ms)

  @impl Kelix.Module
  def validate_config(config) when is_map(config) do
    with :ok <- reject_unknown_keys(config),
         :ok <- pos_int_ok(config, "max_contacts_per_aor"),
         :ok <- pos_int_ok(config, "min_expires"),
         :ok <- pos_int_ok(config, "default_expires"),
         :ok <- pos_int_ok(config, "call_timeout_ms") do
      :ok
    end
  end

  def validate_config(_), do: {:error, "block must be a table"}

  @impl Kelix.Module
  def describe(),
    do: %{
      version: "1.0",
      exports: [
        save: 2,
        save: 4,
        lookup: 1,
        targets: 2,
        subscribe_register_event: 2,
        unsubscribe_register_event: 2
      ]
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
  Register/unregister the contacts of a REGISTER `req`.

  Two calling forms:

    * `save(sip_ctx, req)` — the scenario form. The served domain and the backing
      dialog are read off the scenario context (`domain`, injected by
      `Kelix.Router`; `dialogpid`, set when the instance was spawned), so a script
      never carries either around: `case save(sip_ctx, req) do …`.
    * `save(req, domain, dialog_pid, info)` — the programmatic form, for callers
      with no scenario context (tests, seeding the store).

  `dialog_pid` is stored per contact and used later for teardown; `info` is
  arbitrary scenario data.

  A binding belongs to one session at a time: re-registering a contact that another
  dialog owns hands it over, and that dialog is terminated
  (`{:dialog_terminated, _, :superseded}` → its instance ends). Nothing for the
  script to do — but it is why saving can end a session other than its own.

  The verdict says **what happened to the AOR**, not merely that the store
  accepted the request, because the two demand different things of the script: a
  registration is answered and then waited on for its refresh, an
  un-registration is answered and the session is over. The script that has to
  re-derive it from `granted.expires == 0` gets it wrong on the request that
  drops one of two bindings — that one still leaves the AOR registered.

    * `{:registered, granted}`   — the AOR has live bindings;
    * `{:unregistered, granted}` — its last binding is gone (`Expires: 0`, or the
      `Contact: *` wildcard); `granted.contacts` is empty and `granted.expires` 0;
    * `{:error, {code, reason}}` — 400 (no Contact / bad wildcard), 423 (too
      brief), 403 (too many contacts);
    * `{:error, :down | :timeout}` — the store could not answer (§8.2).

  `granted` is `%{aor, contacts, expires}`: ALL the AOR's current bindings, each
  stamped with its own remaining lifetime — what `SIP.Session.Registrar.accept_registration/3`
  puts in the 200 OK (RFC 3261 §10.3 step 8). It does not build the response; the
  script does (§11.1).
  """
  @spec save(%SIP.Context{} | map, map | String.t(), pid | nil, term) ::
          {:registered, map}
          | {:unregistered, map}
          | {:error, {integer, String.t()}}
          | {:error, :down | :timeout}
  def save(ctx_or_req, req_or_domain, dialog_pid \\ nil, info \\ nil)

  def save(sip_ctx = %SIP.Context{}, req, _dialog_pid, info) when is_map(req),
    do: save(req, sip_ctx.domain, sip_ctx.dialogpid, info)

  def save(req, domain, dialog_pid, info) when is_map(req) do
    # The store is a module, not the SIP peer: `:db` is the monitor's category for
    # "this instance went and asked something of a backend", which is what makes
    # `kelictl monitor` show a registrar instance doing its work rather than
    # sitting idle between the REGISTER and the 200.
    SIP.Scenario.Monitor.note_command(:db, "registrar_save")
    Kelix.Module.safe_call(__MODULE__, {:save, req, domain, dialog_pid, info})
  end

  @doc "Rewrite `req` to reach the AOR's registered contacts. `{:ok, [req]}` / `:notfound` / `{:error, r}`."
  @spec lookup(map) :: {:ok, [map]} | :notfound | {:error, term}
  def lookup(req), do: Kelix.Module.safe_call(__MODULE__, {:lookup, req})

  @doc """
  Where to call the AOR `req` asks for, as a `%SIP.B2bua.Peer{}` ready to hand to
  `b2bua_forward/3`.

  The B2BUA-shaped counterpart of `lookup/1`. `lookup/1` answers a *proxy*
  question — "rewrite this request, once per binding" — and hands back requests;
  a B2BUA builds its own forwarded request
  (`SIP.Msg.Ops.prepare_forwarded_request/2`) and needs a **peer** (design
  docs/design/b2bua_module.md §3.2):

      case Kelix.Mod.Registrar.targets(ctx_get(:domain), req) do
        {:ok, peer}  -> b2bua_forward(req, peer, false)
        :notfound    -> b2bua_reply(req, 480, "Temporarily Unavailable")
        :no_aor      -> b2bua_reply(req, 400, "Bad Request")
        :unavailable -> b2bua_reply(req, 500, "Location Service Unavailable")
      end

  The peer's URIs are the live contacts, each stamped with its destination and
  registration flow — what `SIP.Transport.Selector` short-circuits on, so the
  call reaches a NATed device over the connection it registered on and skips
  DNS. Hence `use_srv: false` and `ruri: :peer`: a registered contact is reached
  by asking for it by name.

  Ordering is the Contact `q` parameter, highest first (RFC 3261 §20.10; absent
  means no stated preference, taken as the highest, 1.0), equal q keeping
  registration order. `uris` is therefore a list of **groups** — one per q value
  — and `fork: :parallel` rings a group all at once and walks the groups in
  order: kamailio's `lookup("location") + t_relay()`, and what RFC 3261 §16.6
  prescribes. A script wanting another policy edits the struct it gets back
  (`%{peer | fork: :serial}` rings them one at a time, `:none` tries the first
  and stops).

  Returns `{:ok, peer}`, or one of three atoms, each mapping to one SIP answer:
  `:notfound` (no live binding — 480), `:no_aor` (the request carries no usable
  R-URI user part — 400), `:unavailable` (the store or this module could not
  answer — 500; the reason is logged here rather than returned).
  """
  @spec targets(String.t(), map()) ::
          {:ok, %SIP.B2bua.Peer{}} | :notfound | :no_aor | :unavailable
  def targets(domain, req) do
    case Kelix.Module.safe_call(__MODULE__, {:targets, domain, req}) do
      {:ok, _peer} = ok ->
        ok

      atom when atom in [:notfound, :no_aor] ->
        atom

      {:error, reason} ->
        Logger.warning(
          module: __MODULE__,
          message:
            "targets for #{inspect(SIP.Msg.Ops.target_aor(req))}@#{domain} " <>
              "unavailable: #{inspect(reason)}"
        )

        :unavailable
    end
  end

  @doc """
  The shortest registration granted on `domain` (seconds).

  Exists so the script can put the mandatory `Min-Expires` header on the `423`
  `save/4` returns (RFC 3261 §10.3 step 7) without duplicating the bound: the
  module owns the policy, the script composes the response (§11.1). Falls back to
  the built-in default when the store is down.
  """
  @spec min_expires(String.t() | nil) :: pos_integer
  def min_expires(domain \\ nil) do
    case Kelix.Module.safe_call(__MODULE__, {:min_expires, domain}) do
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
  Administratively remove an AOR's binding(s) (`kelictl registration remove`). `contact`
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
       default_expires: Keyword.get(opts, :default_expires, @default_expires),
       sweep_ms: sweep_ms
     }}
  end

  @impl true
  def handle_call({:save, req, domain, dialog_pid, info}, _from, state) do
    case do_save(state, req, domain, dialog_pid, info) do
      {verdict, granted, state2} when verdict in [:registered, :unregistered] ->
        {:reply, {verdict, granted}, state2}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:lookup, req}, _from, state) do
    {:reply, do_lookup(state, req), state}
  end

  def handle_call({:targets, domain, req}, _from, state) do
    {:reply, do_targets(state, domain, req), state}
  end

  def handle_call({:min_expires, domain}, _from, state),
    do: {:reply, bounds(state, domain).min_expires, state}

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
         header_exp = SIP.Msg.Ops.expires_header(req),
         {:ok, actions} <- plan_contacts(contacts, header_exp, bounds(state, domain)) do
      apply_actions(state, domain, aor, actions, req, dialog_pid, info)
    end
  end

  @doc false
  # Expiry policy for a domain: `[domain.registrar]` in domains.toml overrides the
  # store-wide `[module.registrar]` block, which overrides the built-in defaults
  # (design §16 #8 — per-domain bounds live with the domain they serve).
  #
  # `default_expires` is both the value granted when the request asks for nothing
  # AND the ceiling on what is granted; `min_expires` is the floor below which the
  # request is refused with 423.
  def bounds(state, domain) do
    per_domain = domain_registrar_block(domain)

    %{
      min_expires: per_domain[:min_expires] || state.min_expires,
      default_expires: per_domain[:default_expires] || state.default_expires
    }
  end

  # the [domain.registrar] block of `domain`, or %{} (Domains not running, unknown
  # domain, registrar not enabled — every one of them a "no override" case)
  defp domain_registrar_block(domain) when is_binary(domain) do
    with pid when not is_nil(pid) <- Process.whereis(Kelix.Domains),
         %Kelix.Domain{registrar: %{} = block} <-
           Kelix.Domains.lookup(Kelix.Domains.current(), domain) do
      block
    else
      _ -> %{}
    end
  end

  defp domain_registrar_block(_domain), do: %{}

  # Decide, per contact, whether to add (with granted expires) or remove (expires 0).
  defp plan_contacts([], _header, _min), do: {:error, {400, "No Contact"}}

  # `Contact: *` — remove every binding of the AOR (RFC 3261 §10.2.2). It is only
  # legal alone and with `Expires: 0`; anything else is a malformed request, not a
  # partial wildcard.
  defp plan_contacts(contacts, header_exp, bounds) when is_list(contacts) do
    if Enum.any?(contacts, &wildcard?/1) do
      cond do
        length(contacts) > 1 ->
          {:error, {400, "Wildcard Contact must be the only one"}}

        header_or_default(header_exp, bounds) != 0 ->
          {:error, {400, "Wildcard Contact requires Expires: 0"}}

        true ->
          {:ok, [:remove_all]}
      end
    else
      plan_each_contact(contacts, header_exp, bounds)
    end
  end

  defp wildcard?(:*), do: true
  defp wildcard?("*"), do: true
  defp wildcard?(_), do: false

  defp plan_each_contact(contacts, header_exp, bounds) do
    Enum.reduce_while(contacts, {:ok, []}, fn c, {:ok, acc} ->
      exp = requested_expires(c, header_exp, bounds)

      cond do
        exp == 0 -> {:cont, {:ok, [{:remove, c} | acc]}}
        exp < bounds.min_expires -> {:halt, {:error, {423, "Interval Too Brief"}}}
        true -> {:cont, {:ok, [{:add, c, min(exp, bounds.default_expires)} | acc]}}
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
      {:unregistered, granted(aor, [], 0), state}
    else
      # apply removes then adds, keyed by contact URI string
      kept = drop_contacts(existing, for({:remove, c} <- actions, do: binding_key(c)))

      added =
        for {:add, c, exp} <- actions do
          %Contact{
            contact: c,
            received: received_of(req),
            flow_pid: flow_of(req),
            flow_module: flow_module_of(req),
            dialog_pid: dialog_pid,
            instance: contact_param(c, "+sip.instance"),
            reg_id: contact_param(c, "reg-id"),
            methods: contact_param(c, "methods"),
            info: info,
            expires_at: DateTime.add(now(), exp, :second)
          }
        end

      merged = upsert(kept, added)

      if length(merged) > state.max_contacts do
        {:error, {403, "Too many contacts"}}
      else
        :ets.insert(tid, {aor, merged})
        # `merged`, not `added`: RFC 3261 §10.3 step 8 wants the 200 OK to
        # enumerate ALL current bindings, so a UA refreshing one of its two
        # contacts still learns about the other.
        # Monitor the backing dialog so a connected-transport drop invalidates the
        # binding (§6.3, WebRTC-critical).
        state = ensure_monitor(state, domain, aor, dialog_pid, flow_module_of(req))
        state = supersede_owners(state, domain, aor, existing, added, dialog_pid)
        notify(state, domain, aor, :registered)
        {:registered, granted(aor, merged, granted_expires(actions)), state}
      end
    end
  end

  # ── administrative removal (kelictl registration remove) ─────────────────────

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

  # A binding is tied to the dialog that created it **only over a
  # connection-oriented transport** (§6.3, WebRTC-critical): there the UA is
  # reachable over that one connection and nothing else, so losing it makes the
  # contact undialable and the binding a lie.
  #
  # Over a **connectionless** transport the opposite holds, and this is a property
  # of the transport mode, not of UDP specifically: one binding is shared by however
  # many dialogs the UA takes part in, so it cannot belong to any single one of them.
  # It lives its own life, bounded by `expires_at` and reclaimed by the periodic
  # sweep — the usrloc semantics. Monitoring the dialog there made a registration
  # evaporate as soon as that one dialog ended, which is exactly what a real handset
  # triggered on 2026-07-28.
  @connected_transports [SIP.Transport.TCP, SIP.Transport.TLS, SIP.Transport.WSS]

  defp ensure_monitor(state, _domain, _aor, pid, _flow) when not is_pid(pid), do: state

  defp ensure_monitor(state, _domain, _aor, _pid, flow)
       when flow not in @connected_transports,
       do: state

  defp ensure_monitor(state, domain, aor, pid, _flow) do
    already? = Enum.any?(state.mons, fn {_ref, key} -> key == {domain, aor, pid} end)

    if already? do
      state
    else
      ref = Process.monitor(pid)
      %{state | mons: Map.put(state.mons, ref, {domain, aor, pid})}
    end
  end

  # One binding, one session. A binding is re-registered by a dialog other than the
  # one that owns it — a different Call-ID naming the same contact — so the previous
  # dialog owns nothing any more: it is superseded, and its registrar instance must
  # go with it.
  #
  # This is what a client re-enabling its account produces (Linphone, 2026-08-11):
  # it re-registers its previous Call-ID *and* opens a new one within the same
  # second, both naming the same contact and the same `+sip.instance`. `upsert/2`
  # then leaves one binding and two live sessions, the loser's being a session that
  # claims a registration it does not hold — visible in `kelictl monitor`, and about
  # to un-register a binding that is no longer its own.
  #
  # Whatever the transport, unlike the dialog *monitor* above: over UDP the previous
  # dialog is just as stale, and nothing else there would ever notice — no
  # connection drops, so it would sit out a full registration lifetime.
  #
  # Demonitored before it is told to end, so the death we cause does not come back
  # through `handle_info({:DOWN, …})` as a `:disconnected` for an AOR that is still
  # registered.
  defp supersede_owners(state, domain, aor, existing, added, dialog_pid)
       when is_pid(dialog_pid) do
    rebound = MapSet.new(added, &binding_key(&1))

    existing
    |> Enum.filter(fn %Contact{dialog_pid: owner} = c ->
      is_pid(owner) and owner != dialog_pid and MapSet.member?(rebound, binding_key(c))
    end)
    |> Enum.uniq_by(& &1.dialog_pid)
    |> Enum.reduce(state, fn %Contact{dialog_pid: owner}, st ->
      Logger.info(
        module: __MODULE__,
        message:
          "#{aor}@#{domain}: binding re-registered by #{inspect(dialog_pid)}, " <>
            "superseding #{inspect(owner)}"
      )

      st = demonitor_owner(st, domain, aor, owner)
      SIP.Dialog.terminate(owner, :superseded)
      st
    end)
  end

  # No dialog behind this save (the programmatic form: tests, seeding the store) —
  # nothing to hand the registration over to, so nothing is superseded either.
  defp supersede_owners(state, _domain, _aor, _existing, _added, _dialog_pid), do: state

  defp demonitor_owner(state, domain, aor, pid) do
    case Enum.find(state.mons, fn {_ref, key} -> key == {domain, aor, pid} end) do
      nil ->
        state

      {ref, _key} ->
        Process.demonitor(ref, [:flush])
        %{state | mons: Map.delete(state.mons, ref)}
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

  # ── targets (B2BUA-shaped lookup) ────────────────────────────────────────────

  defp do_targets(state, domain, req) when is_binary(domain) do
    case SIP.Msg.Ops.target_aor(req) do
      aor when is_binary(aor) ->
        case live_contacts(state, fold_alias(domain), downcase(aor)) do
          [] ->
            :notfound

          contacts ->
            {:ok,
             %SIP.B2bua.Peer{
               uris: q_groups(contacts),
               use_srv: false,
               ruri: :peer,
               fork: :parallel
             }}
        end

      _no_aor ->
        :no_aor
    end
  end

  defp do_targets(_state, _domain, _req), do: :no_aor

  # The contacts as RFC 3261 §16.6 says to try them: one group per q value,
  # highest first, each group a list to ring **together**. Equal q keeps
  # registration order inside its group, which is what `Enum.group_by/2`
  # preserves and what decides who is dialled first when the group is really a
  # rung of one.
  defp q_groups(contacts) do
    contacts
    |> Enum.group_by(&q_of/1)
    |> Enum.sort_by(fn {q, _} -> q end, :desc)
    |> Enum.map(fn {_q, group} -> Enum.map(group, &target_uri/1) end)
  end

  # The Contact `q` (RFC 3261 §20.10): 0..1, highest preference first. Absent
  # means the device stated no preference, which ranks it top — the single-contact
  # case, i.e. nearly all of them, must not sort below one that asked for 0.3.
  # Junk is read as absent rather than raising: an unparsable q is a reason to
  # ignore the preference, not to fail the call.
  defp q_of(%Contact{contact: uri}) do
    with {:ok, v} <- SIP.Uri.get_header_param(uri, "q"),
         {q, _rest} <- Float.parse(v) do
      q
    else
      _ -> 1.0
    end
  end

  # A copy of req with its R-URI replaced by the stored contact + the resolved
  # destination and flow.
  defp rewrite(req, %Contact{} = binding), do: Map.put(req, :ruri, target_uri(binding))

  # The stored contact stamped with the destination and flow it registered over.
  # Both are what `SIP.Transport.Selector.select_transport/1` short-circuits on
  # (§6.4): a live `tp_pid`+`tp_module` sends straight over the existing
  # connection, and failing that `destip`/`destport` skip DNS.
  #
  # `SIP.Uri.to_request_uri/1` first: what is stored is a Contact *header* value,
  # display name and binding parameters (`q`, `expires`, `+sip.instance`, the RFC
  # 3840 feature tags) included, and none of that may appear on the Request-URI
  # this becomes (RFC 3261 §16.6 item 2). The URI parameters are kept in full —
  # §19.1.5 requires it — which is the whole reason this is one framework call
  # and not a list of parameter names maintained here.
  defp target_uri(%Contact{contact: c} = binding) do
    c = SIP.Uri.to_request_uri(c)
    binding = %Contact{binding | contact: c}

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
  end

  # ── contact / expires helpers ────────────────────────────────────────────────

  # The lifetime one contact asks for. The RFC 3261 §10.2.4 precedence (and its
  # tolerance for a valueless or junk `;expires`) is the framework's, read once in
  # SIP.Msg.Ops — see CLAUDE.md, Message Layer. What is ours is the *policy*: the
  # per-domain `default_expires` used when neither the contact nor the header says.
  defp requested_expires(contact, header_exp, bounds),
    do: SIP.Msg.Ops.contact_expires(contact, header_exp, bounds.default_expires)

  defp header_or_default(exp, _bounds) when is_integer(exp), do: exp
  defp header_or_default(_exp, bounds), do: bounds.default_expires

  defp granted_expires(actions) do
    case for({:add, _c, exp} <- actions, do: exp) do
      [exp | _] -> exp
      [] -> 0
    end
  end

  # Each returned contact carries its OWN remaining lifetime as an `expires`
  # Contact header parameter (`c-p-expires`, RFC 3261 §25.1, hence
  # `set_header_param/3`), so a 200 OK enumerating several bindings is accurate per
  # binding instead of stamping them all with the expiry of the one just refreshed.
  defp granted(aor, contacts, expires) do
    %{aor: aor, contacts: Enum.map(contacts, &contact_with_expires/1), expires: expires}
  end

  defp contact_with_expires(%Contact{contact: uri, expires_at: at}) do
    SIP.Uri.set_header_param(uri, "expires", to_string(remaining_seconds(at)))
  end

  defp remaining_seconds(at), do: max(DateTime.diff(at, now(), :second), 0)

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
    Enum.reject(contacts, &(binding_key(&1) in keys))
  end

  # replace same-identity existing contacts with the new ones, then append the rest
  defp upsert(existing, added) do
    added_keys = MapSet.new(added, &binding_key/1)
    Enum.reject(existing, &(binding_key(&1) in added_keys)) ++ added
  end

  @doc false
  # Identity of a binding.
  #
  # `+sip.instance` (+ `reg-id`) when the UA offers them: that is RFC 5626's whole
  # point — it names the **device**, so the same phone reaching us from a new address
  # REPLACES its binding instead of adding a second one. Keying on the contact URI
  # alone is why a handset has to drop its old contact by hand on every network
  # change, and why a NAT rebind used to leave a stale binding behind.
  #
  # Falling back to the URI keeps RFC 3261 behaviour for UAs that offer no instance.
  def binding_key(%Contact{contact: uri}), do: binding_key(uri)

  def binding_key(%SIP.Uri{} = uri) do
    case contact_param(uri, "+sip.instance") do
      nil -> {:uri, uri_key(uri)}
      # reg-id absent means "one flow", RFC 5626 §4.1 — not the same binding as an
      # explicit reg-id, so it gets its own slot rather than being folded into one.
      instance -> {:instance, instance, contact_param(uri, "reg-id")}
    end
  end

  # Contact HEADER parameters (`+sip.instance`, `reg-id`, `methods` — all of them
  # `contact-params`, hence `get_header_param/2`). They reach us quoted
  # (`+sip.instance="<urn:uuid:…>"`), which a URI parameter could not even be:
  # compare and store the value, not the quoting.
  defp contact_param(%SIP.Uri{} = uri, name) do
    case SIP.Uri.get_header_param(uri, name) do
      {:ok, value} when is_binary(value) -> String.trim(value, "\"")
      _ -> nil
    end
  end

  defp contact_param(_other, _name), do: nil

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

  # Binding identity is the contact **URI**: RFC 3261 §10.2.4 compares bindings by
  # URI, so a refresh that merely changes `expires` has to REPLACE the binding
  # rather than add a second one. Contact *header* parameters are therefore
  # excluded — and `SIP.Uri.serialize_ruri/1` excludes exactly them (plus the
  # display name, which a handset is free to change without becoming a new
  # device), so the list of names this used to maintain by hand is gone.
  #
  # Keeping them in meant a handset that rebinds (old contact with `;expires=0`,
  # new one alongside) never got its old contact dropped — the key differed by that
  # very parameter — so the AOR accumulated stale contacts until
  # `max_contacts_per_aor` started refusing the next registration.
  #
  # `+sip.instance`/`reg-id` would make a *better* binding key than the URI (RFC
  # 5626 outbound), but that is its own feature; until then identity stays the URI,
  # as RFC 3261 has it.
  #
  # serialize_ruri/1 always succeeds on a %SIP.Uri{}, hence the hard match.
  defp uri_key(%SIP.Uri{} = u) do
    {:ok, s} = SIP.Uri.serialize_ruri(u)
    s
  end

  defp downcase(s) when is_binary(s), do: String.downcase(s)
  defp now(), do: DateTime.utc_now()
end
