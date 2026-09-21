defmodule Kelix.Mod.Presence do
  @moduledoc """
  The presence collection (design `docs/design/DESIGN-PRESENCE.md`, *The kelixip
  Presence module*): who watches what, what has been published about it, and the
  fan-out that turns one PUBLISH into N NOTIFYs.

  **Strong per-domain separation**, like the registrar: one ETS table per domain
  for the published states, one for the watchers, and a `%{domain => tid}` index.
  A resource is `{username, domain, event}` — the presentity and the event package
  — which is `presentity`'s key without its entity-tag, and what a watcher
  subscribes to.

  Facade (imported by the presence scripts):

    * `publish/2` — store what a PUBLISH asks for, mint or refuse an entity-tag,
      and push the new state to every watcher of the resource;
    * `watch/2` / `unwatch/1` — register the calling instance as a watcher of the
      subscription it just accepted, and hand back the state as it stands;
    * `state_of/2` — the current document of a resource, for a script that wants
      it without subscribing;
    * `watchers/2`, `presentities/1`, `remove/2` — what `kelictl presence` shows
      and does.

  ## What it does NOT decide

  **Who may watch whom.** The collection stores and pushes; admission is the
  script's, and `presence-subscribe.exs` is where a deployment writes its rule.
  A policy key here would be a second place deciding it, and the real answer —
  RFC 5025 authorization rules carried over XCAP, with `presence.winfo` to feed
  them — is a phase of its own that plugs into this same collection.

  **What a document means.** It holds whatever the event package parsed, opaque,
  so one collection serves `presence`, `dialog` and whatever a third party
  registers. The only thing it reads of a publication is its key and its lifetime.

  ## It holds kamailio's rows

  A published state is a `%SIP.Publication{}` — a `presentity` row — and a watcher
  a `%SIP.Subscription{}` — an `active_watchers` row (plan decision 2). Nothing is
  persisted in v1: nothing can resurrect a dialog, so a restart loses the
  subscriptions whatever is written down, and what is taken from day one is the
  **shape**, so a backend later writes rows it already holds.

  ## Composition is not done here

  Several publishers may hold state for one presentity at the same time (RFC 3903
  §4.1, which is why the entity-tag is part of `presentity`'s key). v1 emits
  **full state from the most recent publication** rather than composing them: the
  composite state is its own phase, and a wrong composition is worse than an
  honest "the last thing said about this resource".
  """
  use GenServer
  @behaviour Kelix.Module
  require Logger

  @sweep_ms 30_000

  # state:
  #   states     %{domain => :ets.tid}  resource => [%SIP.Publication{}], one per etag
  #   watchers   %{domain => :ets.tid}  resource => %{pid => %SIP.Subscription{}}
  #   mons       %{monitor_ref => {domain, resource, pid}}  watcher instances
  defstruct states: %{}, watchers: %{}, mons: %{}, sweep_ms: @sweep_ms

  @type resource :: {String.t() | nil, String.t() | nil, String.t() | nil}

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  # ── Kelix.Module behaviour ───────────────────────────────────────────────────

  @impl Kelix.Module
  def child_spec(_name, _config), do: %{id: __MODULE__, start: {__MODULE__, :start_link, [[]]}}

  # Every key a [module.presence] block may carry. `module` is the generic
  # module-resolution key handled by Kelix.ModuleSupervisor. There is deliberately
  # no expiry key: the bounds of a subscription and of a publication belong to the
  # event package (RFC 6665 §4.4.1), and a second source for them is a copy that
  # drifts.
  @config_keys ~w(module call_timeout_ms)

  @impl Kelix.Module
  def validate_config(config) when is_map(config) do
    with :ok <- reject_unknown_keys(config),
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
        publish: 2,
        watch: 2,
        unwatch: 1,
        state_of: 2,
        presentities: 1,
        watchers: 2,
        remove: 2
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

  # ── control surface (§8.1, §10) ─────────────────────────────────────────────

  # The columns are kamailio's, under kamailio's names — `presentity_uri`, `etag`,
  # `expires`, `event`, `status` — so an operator reading this and an operator
  # reading the table they migrated from are reading one vocabulary.
  @impl Kelix.Module
  def describe_control() do
    [
      %{
        name: "list",
        rest: {:get, "/presentities"},
        rw: :r,
        args: [%{name: "domain", required: true}],
        render: %{
          kind: :table,
          columns: ~w(presentity_uri event etag expires sender content_type)
        },
        help: "The published states of a domain, one row per entity-tag"
      },
      %{
        name: "show",
        rest: {:get, "/presentities/:aor"},
        errors: %{not_found: 404},
        rw: :r,
        args: [%{name: "domain", required: true}, %{name: "aor", required: true}],
        render: %{
          kind: :detail,
          fields: ~w(presentity_uri states watchers),
          nested: %{
            "states" => %{columns: ~w(event etag expires sender content_type)},
            "watchers" => %{columns: ~w(watcher event status expires callid)}
          }
        },
        help: "One presentity: what is published about it, and who watches it"
      },
      %{
        name: "watchers",
        rest: {:get, "/presentities/:aor/watchers"},
        rw: :r,
        args: [%{name: "domain", required: true}, %{name: "aor", required: true}],
        render: %{
          kind: :table,
          columns: ~w(watcher presentity_uri event event_id status expires callid)
        },
        help: "The live subscriptions to one presentity"
      },
      %{
        name: "remove",
        rest: {:delete, "/presentities/:aor"},
        errors: %{not_found: 404},
        rw: :w,
        args: [%{name: "domain", required: true}, %{name: "aor", required: true}],
        help: "Drop everything published about an AOR, and tell its watchers"
      }
    ]
  end

  @doc """
  Run a declared control command.

  `remove` drops the published state, not the subscriptions: a watcher stays
  subscribed and is told there is no state left, which is what it would have seen
  had the publisher removed it. Tearing the dialogs down would look the same in
  this view and quite different on the wire.
  """
  @impl Kelix.Module
  def handle_control("list", %{"domain" => domain}), do: {:ok, presentities(domain)}

  def handle_control("watchers", %{"domain" => domain, "aor" => aor}),
    do: {:ok, watchers(domain, aor)}

  def handle_control("show", %{"domain" => domain, "aor" => aor}) do
    states = Enum.filter(presentities(domain), &(aor_of(&1.presentity_uri) == downcase(aor)))
    watchers = watchers(domain, aor)

    if states == [] and watchers == [] do
      {:error, :not_found}
    else
      {:ok,
       %{presentity_uri: "sip:#{downcase(aor)}@#{domain}", states: states, watchers: watchers}}
    end
  end

  def handle_control("remove", %{"domain" => domain, "aor" => aor}) do
    case remove(domain, aor) do
      :ok -> {:ok, %{removed: aor}}
      :notfound -> {:error, :not_found}
      {:error, reason} -> {:error, reason}
    end
  end

  def handle_control(command, args) when is_map(args) do
    case Map.get(args, "domain") do
      nil -> {:error, "domain is required"}
      _ -> {:error, {:unknown_command, command}}
    end
  end

  defp aor_of(uri) when is_binary(uri) do
    case SIP.Uri.parse(uri) do
      {:ok, %SIP.Uri{userpart: user}} -> downcase(user)
      _ -> nil
    end
  end

  defp aor_of(_uri), do: nil

  # ── facades ─────────────────────────────────────────────────────────────────

  @doc """
  Store what a PUBLISH asks for, and push the result to every watcher.

  `pub` is the `%SIP.Publication{}` `check_publish/1` handed the script — already
  read against the event package, with the operation, the entity-tag presented and
  the lifetime that may be granted. What is left here is the half only the holder
  of the tags can answer:

    * `{:ok, etag, expires}` — a NEW entity-tag (RFC 3903 §4.1 mints one per
      successful publication) and the lifetime granted, which is what the 200 OK
      carries. A removal (`Expires: 0`) answers `{:ok, nil, 0}`: there is no state
      left to name, and a publisher handed a tag there would present it on its
      next refresh and be answered 412 for ever;
    * `{:error, 412}` — a refresh, a modification or a removal presenting a tag
      this collection does not hold (expired, or never issued). RFC 3903 §6: the
      publisher must start over with an initial PUBLISH;
    * `{:error, :down | :timeout}` — the collection could not answer (§8.2).

  The fan-out happens here, not in the script: one PUBLISH becomes N pushes of
  `{:presence, :state, resource, doc}` to the watcher instances, each of which
  sends its own NOTIFY from its own state (plan decision 1). A removal pushes
  `doc = nil` — "nothing is published about this resource any more" — and what to
  notify then is the watcher script's decision.
  """
  @spec publish(%SIP.Context{} | String.t(), SIP.Publication.t()) ::
          {:ok, String.t() | nil, non_neg_integer} | {:error, 412} | {:error, :down | :timeout}
  def publish(ctx_or_domain, pub)

  def publish(%SIP.Context{} = sip_ctx, %SIP.Publication{} = pub),
    do: publish(sip_ctx.domain, pub)

  def publish(domain, %SIP.Publication{} = pub) do
    # The store is a module, not the SIP peer: `:db` is what makes `kelictl
    # monitor` show the instance doing its work rather than idling between the
    # PUBLISH and its 200.
    SIP.Scenario.Monitor.note_command(:db, "presence_publish")
    Kelix.Module.safe_call(__MODULE__, {:publish, served_domain(domain), pub})
  end

  @doc """
  Register the calling instance as a watcher of `sub`, and hand back the state as
  it stands.

  Called by a notifier script right after `accept_subscription/1`: the
  subscription is the framework's (one dialog's point of view), the collection is
  ours (who watches what). Answers `{:ok, doc}` — the document to NOTIFY straight
  away, `nil` when nothing has been published about the resource yet — or
  `{:error, :down | :timeout}`.

  The instance is **monitored**: a watcher that dies with its dialog is dropped
  without anything having to say so. `unwatch/1` is for the scenario that ends its
  subscription and keeps running.

  A subscription granted zero seconds (an un-SUBSCRIBE) is not stored: it is the
  END of a subscription, and the only NOTIFY still owed is the dialog's final one.
  """
  @spec watch(%SIP.Context{} | String.t(), SIP.Subscription.t()) ::
          {:ok, term} | {:error, :down | :timeout}
  def watch(ctx_or_domain, sub)

  def watch(%SIP.Context{} = sip_ctx, %SIP.Subscription{} = sub),
    do: watch(sip_ctx.domain, sub)

  def watch(domain, %SIP.Subscription{} = sub) do
    SIP.Scenario.Monitor.note_command(:db, "presence_watch")
    Kelix.Module.safe_call(__MODULE__, {:watch, served_domain(domain), sub, self()})
  end

  @doc "Stop watching: drop the calling instance from every resource it watches."
  @spec unwatch(%SIP.Context{} | String.t()) :: :ok | {:error, :down | :timeout}
  def unwatch(ctx_or_domain)
  def unwatch(%SIP.Context{} = sip_ctx), do: unwatch(sip_ctx.domain)

  def unwatch(domain),
    do: Kelix.Module.safe_call(__MODULE__, {:unwatch, served_domain(domain), self()})

  @doc """
  The document published about a resource, or `nil`.

  `resource` is `{username, event}` on the domain the context serves, or the full
  `{username, domain, event}` triple.
  """
  @spec state_of(%SIP.Context{} | String.t(), {String.t(), String.t()} | resource) ::
          term | {:error, :down | :timeout}
  def state_of(ctx_or_domain, resource)

  def state_of(%SIP.Context{} = sip_ctx, resource), do: state_of(sip_ctx.domain, resource)

  def state_of(domain, {user, event}), do: state_of(domain, {user, domain, event})

  def state_of(_domain, {user, dom, event}),
    do: Kelix.Module.safe_call(__MODULE__, {:state_of, resource_key({user, dom, event})})

  @doc "Every published state of a domain, as rendered rows (`kelictl presence list`)."
  @spec presentities(String.t()) :: [map] | {:error, :down | :timeout}
  def presentities(domain),
    do: Kelix.Module.safe_call(__MODULE__, {:presentities, served_domain(domain)})

  @doc "The live watchers of an AOR, as rendered rows (`kelictl presence watchers`)."
  @spec watchers(String.t(), String.t()) :: [map] | {:error, :down | :timeout}
  def watchers(domain, aor),
    do: Kelix.Module.safe_call(__MODULE__, {:watchers, served_domain(domain), downcase(aor)})

  @doc """
  Administratively drop everything held about an AOR (`kelictl presence remove`):
  its published states, and the push that tells its watchers there is none left.

  The subscriptions themselves are NOT torn down — a watcher stays subscribed and
  is told the state is gone, which is what it would see if the publisher had
  removed it. `:ok`, or `:notfound` when nothing was held.
  """
  @spec remove(String.t(), String.t()) :: :ok | :notfound | {:error, :down | :timeout}
  def remove(domain, aor),
    do: Kelix.Module.safe_call(__MODULE__, {:remove, served_domain(domain), downcase(aor)})

  # ── GenServer ───────────────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    sweep_ms = Keyword.get(opts, :sweep_ms, @sweep_ms)
    Process.send_after(self(), :sweep, sweep_ms)
    {:ok, %__MODULE__{sweep_ms: sweep_ms}}
  end

  @impl true
  def handle_call({:publish, domain, pub}, _from, state) do
    {reply, state} = do_publish(state, domain, pub)
    {:reply, reply, state}
  end

  def handle_call({:watch, domain, sub, pid}, _from, state) do
    {reply, state} = do_watch(state, domain, sub, pid)
    {:reply, reply, state}
  end

  def handle_call({:unwatch, domain, pid}, _from, state) do
    {:reply, :ok, drop_watcher(state, domain, pid)}
  end

  def handle_call({:state_of, {_user, domain, _event} = resource}, _from, state) do
    {:reply, current_doc(state, domain, resource), state}
  end

  def handle_call({:presentities, domain}, _from, state) do
    rows =
      for {_resource, pubs} <- table_contents(state.states, domain),
          pub <- live_publications(pubs),
          do: render_publication(pub)

    {:reply, rows, state}
  end

  def handle_call({:watchers, domain, aor}, _from, state) do
    rows =
      for {{user, _dom, _event}, subs} <- table_contents(state.watchers, domain),
          user == aor,
          {_pid, sub} <- subs,
          do: render_subscription(sub)

    {:reply, rows, state}
  end

  def handle_call({:remove, domain, aor}, _from, state) do
    {reply, state} = do_remove(state, domain, aor)
    {:reply, reply, state}
  end

  # a watcher instance died with its dialog: it watches nothing any more
  @impl true
  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    case Map.pop(state.mons, ref) do
      {nil, _} ->
        {:noreply, state}

      {{domain, resource, pid}, mons} ->
        {:noreply, forget_watcher(%{state | mons: mons}, domain, resource, pid)}
    end
  end

  def handle_info(:sweep, state) do
    state = Enum.reduce(Map.keys(state.states), state, &sweep_domain(&2, &1))
    Process.send_after(self(), :sweep, state.sweep_ms)
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ── publish ─────────────────────────────────────────────────────────────────

  defp do_publish(state, domain, pub) do
    resource = resource_key(SIP.Publication.resource(pub), domain)
    tid = ensure_table(state.states, domain)
    state = %{state | states: Map.put(state.states, domain, tid)}
    held = live_publications(lookup_list(tid, resource))

    case plan_publication(pub, held) do
      {:error, 412} ->
        # A tag we do not hold: expired under the publisher's feet, or never
        # issued by this node (a restart). RFC 3903 §6 — start over.
        Logger.info(
          module: __MODULE__,
          message:
            "PUBLISH for #{SIP.Publication.presentity_uri(pub)} presents an unknown " <>
              "entity-tag #{inspect(pub.etag)}: 412"
        )

        {{:error, 412}, state}

      {:remove, previous} ->
        store(tid, resource, List.delete(held, previous))
        {{:ok, nil, 0}, fan_out(state, domain, resource, :removed)}

      {:store, previous, stored} ->
        store(tid, resource, List.delete(held, previous) ++ [stored])

        {{:ok, stored.etag, SIP.Publication.remaining(stored)},
         fan_out(state, domain, resource, :published)}
    end
  end

  # What a PUBLISH asks of the collection, RFC 3903 §4.1 read against what is
  # held. The four operations are `check_publish/1`'s reading of the request; what
  # is added here is the only thing it could not know — whether we hold the tag.
  defp plan_publication(%SIP.Publication{operation: :initial} = pub, _held),
    do: {:store, nil, issue(pub)}

  defp plan_publication(%SIP.Publication{} = pub, held) do
    case Enum.find(held, &(&1.etag == pub.etag)) do
      nil -> {:error, 412}
      previous -> replace(pub, previous)
    end
  end

  defp replace(%SIP.Publication{operation: :remove}, previous), do: {:remove, previous}

  # A refresh carries no body: what is published stays, only its lifetime moves.
  # A modification carries one, and it is the new state.
  defp replace(%SIP.Publication{operation: :refresh} = pub, previous),
    do: {:store, previous, issue(%{previous | expires: pub.expires})}

  defp replace(%SIP.Publication{} = pub, previous), do: {:store, previous, issue(pub)}

  # Every successful publication gets a NEW tag (RFC 3903 §4.1): the one the
  # publisher presented is spent, and the next refresh must present this one.
  defp issue(%SIP.Publication{} = pub),
    do: %{pub | etag: SIP.Publication.new_etag(), received_time: SIP.Publication.now()}

  # ── watch ───────────────────────────────────────────────────────────────────

  defp do_watch(state, domain, sub, pid) do
    resource = subscription_resource(sub, domain)

    # An un-SUBSCRIBE is accepted as a lifetime of zero and is the END of a
    # subscription: storing it would leave a watcher nothing will ever reach.
    if SIP.Subscription.status(sub) == :terminated do
      {{:ok, current_doc(state, domain, resource)}, state}
    else
      tid = ensure_table(state.watchers, domain)
      state = %{state | watchers: Map.put(state.watchers, domain, tid)}
      subs = lookup_map(tid, resource)
      :ets.insert(tid, {resource, Map.put(subs, pid, sub)})

      {{:ok, current_doc(state, domain, resource)}, monitor_watcher(state, domain, resource, pid)}
    end
  end

  defp monitor_watcher(state, domain, resource, pid) do
    if Enum.any?(state.mons, fn {_ref, key} -> key == {domain, resource, pid} end) do
      state
    else
      ref = Process.monitor(pid)
      %{state | mons: Map.put(state.mons, ref, {domain, resource, pid})}
    end
  end

  defp drop_watcher(state, domain, pid) do
    case Map.get(state.watchers, domain) do
      nil ->
        state

      tid ->
        state =
          Enum.reduce(:ets.tab2list(tid), state, fn {resource, subs}, st ->
            if Map.has_key?(subs, pid), do: forget_watcher(st, domain, resource, pid), else: st
          end)

        demonitor_watcher(state, domain, pid)
    end
  end

  defp forget_watcher(state, domain, resource, pid) do
    case Map.get(state.watchers, domain) do
      nil ->
        state

      tid ->
        case Map.delete(lookup_map(tid, resource), pid) do
          empty when map_size(empty) == 0 -> :ets.delete(tid, resource)
          subs -> :ets.insert(tid, {resource, subs})
        end

        state
    end
  end

  defp demonitor_watcher(state, domain, pid) do
    {dropped, kept} =
      Enum.split_with(state.mons, fn {_ref, {d, _resource, p}} -> d == domain and p == pid end)

    Enum.each(dropped, fn {ref, _} -> Process.demonitor(ref, [:flush]) end)
    %{state | mons: Map.new(kept)}
  end

  # ── the fan-out ─────────────────────────────────────────────────────────────

  # One PUBLISH, N pushes. The message reaches the watcher's SCENARIO INSTANCE,
  # which sends the NOTIFY from its own state (plan decision 1): a NOTIFY sent
  # from here would be invisible to `kelictl monitor` and to the sequence diagram,
  # and a scenario parked in a state would no longer describe what the node does.
  defp fan_out(state, domain, resource, event) do
    doc = current_doc(state, domain, resource)

    for {pid, _sub} <- watchers_of(state, domain, resource) do
      send(pid, {:presence, :state, resource, doc})
    end

    Kelix.Metrics.Emit.presence_event(domain, event)
    state
  end

  defp watchers_of(state, domain, resource) do
    case Map.get(state.watchers, domain) do
      nil -> %{}
      tid -> lookup_map(tid, resource)
    end
  end

  # The state of a resource: the most recent live publication's document (see the
  # moduledoc — composition is its own phase), `nil` when nothing is published.
  defp current_doc(state, domain, resource) do
    case Map.get(state.states, domain) do
      nil ->
        nil

      tid ->
        case live_publications(lookup_list(tid, resource)) do
          [] -> nil
          pubs -> pubs |> Enum.max_by(& &1.received_time) |> Map.get(:doc)
        end
    end
  end

  # ── administrative removal, and the expiry sweep ────────────────────────────

  defp do_remove(state, domain, aor) do
    case Map.get(state.states, domain) do
      nil ->
        {:notfound, state}

      tid ->
        case for({{user, _d, _e} = r, _pubs} <- :ets.tab2list(tid), user == aor, do: r) do
          [] ->
            {:notfound, state}

          resources ->
            state =
              Enum.reduce(resources, state, fn resource, st ->
                :ets.delete(tid, resource)
                fan_out(st, domain, resource, :removed)
              end)

            {:ok, state}
        end
    end
  end

  # A publication whose lifetime has lapsed is gone, and its watchers are told so
  # — kamailio sweeps `expires < now()` on a timer, and a watcher left believing
  # in a state nobody refreshed is the failure this exists to prevent.
  defp sweep_domain(state, domain) do
    tid = Map.get(state.states, domain)

    Enum.reduce(:ets.tab2list(tid), state, fn {resource, pubs}, st ->
      case live_publications(pubs) do
        ^pubs ->
          st

        live ->
          store(tid, resource, live)
          fan_out(st, domain, resource, :expired)
      end
    end)
  end

  # ── rendering (what both control frontals show) ─────────────────────────────

  # kamailio's column names, deliberately: an operator reading this and an
  # operator reading the table they migrated from are reading one vocabulary
  # (DESIGN-PRESENCE.md, *The data model is kamailio's*).
  defp render_publication(%SIP.Publication{} = pub) do
    %{
      presentity_uri: SIP.Publication.presentity_uri(pub),
      event: pub.event,
      etag: pub.etag,
      expires: SIP.Publication.remaining(pub),
      sender: pub.sender,
      content_type: pub.content_type
    }
  end

  defp render_subscription(%SIP.Subscription{} = sub) do
    %{
      presentity_uri: sub.presentity_uri,
      watcher: watcher_uri(sub),
      event: sub.event,
      event_id: sub.event_id,
      status: to_string(SIP.Subscription.status(sub)),
      expires: SIP.Subscription.remaining(sub),
      callid: sub.callid
    }
  end

  defp watcher_uri(%SIP.Subscription{watcher_username: nil}), do: nil
  defp watcher_uri(%SIP.Subscription{watcher_username: u, watcher_domain: d}), do: "sip:#{u}@#{d}"

  # ── keys and storage ────────────────────────────────────────────────────────

  # `{username, domain, event}`: `presentity`'s key without its entity-tag — what
  # a watcher subscribes to, and therefore what the fan-out notifies on. The user
  # part is folded (an AOR is case-insensitive) and so is the package name (RFC
  # 6665 §8.2.1); the domain served is the one the router resolved, so an alias
  # and its nominal name are one resource.
  @doc false
  @spec resource_key(resource, String.t() | nil) :: resource
  def resource_key(resource, domain \\ nil)

  def resource_key({user, dom, event}, domain),
    do: {downcase(user), served_domain(dom || domain), downcase(event)}

  defp subscription_resource(%SIP.Subscription{} = sub, domain) do
    case SIP.Uri.parse(to_string(sub.presentity_uri)) do
      {:ok, %SIP.Uri{userpart: user}} -> resource_key({user, domain, sub.event})
      _ -> resource_key({sub.to_user, domain, sub.event})
    end
  end

  # alias → nominal domain name (folds via Domains when it is running; else
  # identity), so a watcher reaching us on `example.fr` and a publisher on
  # `example.com` share one resource.
  defp served_domain(nil), do: nil

  defp served_domain(domain) when is_binary(domain) do
    with pid when not is_nil(pid) <- Process.whereis(Kelix.Domains),
         %Kelix.Domain{name: name} <- Kelix.Domains.lookup(Kelix.Domains.current(), domain) do
      name
    else
      _ -> domain
    end
  end

  defp ensure_table(tables, domain) do
    case Map.get(tables, domain) do
      nil -> :ets.new(:"kelix_presence_#{domain}", [:set, :private])
      tid -> tid
    end
  end

  defp table_contents(tables, domain) do
    case Map.get(tables, domain) do
      nil -> []
      tid -> :ets.tab2list(tid)
    end
  end

  defp lookup_list(tid, key) do
    case :ets.lookup(tid, key) do
      [{^key, list}] -> list
      [] -> []
    end
  end

  defp lookup_map(tid, key) do
    case :ets.lookup(tid, key) do
      [{^key, map}] -> map
      [] -> %{}
    end
  end

  defp store(tid, key, []), do: :ets.delete(tid, key)
  defp store(tid, key, list), do: :ets.insert(tid, {key, list})

  defp live_publications(pubs),
    do: Enum.filter(pubs, &(SIP.Publication.remaining(&1) > 0))

  defp downcase(nil), do: nil
  defp downcase(value) when is_binary(value), do: String.downcase(value)
  defp downcase(value), do: value
end
