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
    * `watch/2` / `watch_many/3` / `unwatch/1` — register the calling instance as
      a watcher of the subscription it just accepted — of one resource, or of the
      N a list subscription names — and hand back the state as it stands;
    * `state_of/2` — the current document of a resource, for a script that wants
      it without subscribing;
    * `report/5` — another module stating the state of a resource, on one event
      package, on its own authority (see *Reported states*); `report/4` is the
      `presence` case;
    * `exists?/2` — whether a presentity exists at all, the question a notifier
      script asks before it accepts a subscription;
    * `watchers/2`, `presentities/1`, `remove/2` — what `kelictl presence` shows
      and does;
    * `subscribe_presentities/2` / `unsubscribe_presentities/2` — one domain's
      presentities pushed as they change (kelescope's live presence panel), on
      the model of `Kelix.Mod.Registrar.subscribe_registrations/2`.

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

  ## A resource nobody publishes

  A presence state is first what its presentity PUBLISHed. When nothing live is
  published, it is the state another module **reported** for it (see *Reported
  states*); failing that, **open** while the presentity is registered — which the
  registrar script says, through `registration_changed/1` and
  `registration_ended/1` — and, on a domain that has a registrar, **closed** for a
  subscriber `Kelix.Mod.AuthDb` knows. Anywhere else — a domain with no
  registrar, a domain this node does not serve, a user nobody provisioned — there
  is no state, `nil`, which a notifier reports as `noresource`.

  On the `dialog` package (RFC 4235) nothing is published and the registration
  says nothing: the state is what a module **reported** — the calls of the AOR —
  and, for a subscriber `Kelix.Mod.AuthDb` knows, an **empty** document when
  nothing is: an idle phone has no dialog, which is what its BLF key displays,
  and `noresource` would end the subscription of every idle phone at subscribe
  time (docs/design/dialog-state-plan.md, decision 7). Any other package has no
  state.

  A registration that opens or closes a watched resource nobody publishes is
  pushed like a publication. The collection never follows the registrar on its
  own: a domain whose registrar script does not report (`registrar.exs`) shows its
  subscribers closed.

  ## Reported states

  A module other than this one may state the presence of a resource on its own
  authority — `Kelix.Mod.McuPresence` says a conference room is open, busy or
  closed, a reporter on the `dialog` package which calls an AOR is on — through
  `report/5`. A reported state is held per `{resource, source}`, the package
  included,
  ranks below a live publication and above the registration, and goes when its
  source withdraws it (`nil`) or when the process that reported it dies: the
  reporter is monitored, and a module that restarts reports again.

  Watchers are pushed when the **resolved** state of the resource changes, and
  only then: a source repeating what it said costs nobody a NOTIFY.

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
  #   registered MapSet of `presence` resources whose presentity holds a binding,
  #              as the registrar script reported it
  #   reported   %{resource => %{source => %{doc, pid, seq, known?}}}, the states
  #              `report/5` stated; `known?` is whether the subscriber base knows
  #              the presentity, asked in the reporter's process at report time
  #   reporters  %{pid => monitor_ref} of the processes that reported a state
  #   panel_subs %{domain => MapSet(pid)} subscribed via `subscribe_presentities/2`
  #   panel_mons %{monitor_ref => {domain, pid}}, dropped on death without an
  #              explicit `unsubscribe_presentities/2`
  defstruct states: %{},
            watchers: %{},
            mons: %{},
            registered: MapSet.new(),
            reported: %{},
            reporters: %{},
            panel_subs: %{},
            panel_mons: %{},
            sweep_ms: @sweep_ms

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
        watch_many: 3,
        unwatch: 1,
        state_of: 2,
        report: 4,
        report: 5,
        exists?: 2,
        own_state?: 1,
        registration_changed: 1,
        registration_changed: 2,
        registration_ended: 1,
        presentities: 1,
        watchers: 2,
        remove: 2,
        subscribe_presentities: 2,
        unsubscribe_presentities: 2
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
          columns: ~w(presentity_uri event source status etag expires sender content_type)
        },
        help: "The states held for a domain: one row per entity-tag, one per registration"
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
            "states" => %{columns: ~w(event source status etag expires sender content_type)},
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
  away, the registrar's reading when nothing live is published (see *A resource
  nobody publishes*), `nil` when there is none either — or
  `{:error, :down | :timeout}`.

  The domain passed is a **fallback**, used only when the subscription's
  presentity URI carries none: the resource belongs to the domain its own URI
  names, never to the one that routed the SUBSCRIBE. The two differ as soon as a
  watcher subscribes through a list URI — `sip:rls@sip.linphone.org` routes to
  this node and names no presentity at all.

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
    domain = served_domain(domain)

    case Kelix.Module.safe_call(__MODULE__, {:watch, domain, sub, self()}) do
      {:ok, nil} -> {:ok, unpublished_state(subscription_resource(sub, domain))}
      other -> other
    end
  end

  @doc """
  The same, for the N resources of one subscription (RFC 4662: one SUBSCRIBE to a
  list, one state per entry).

  `uris` are the entries as the watcher wrote them, and the answer is keyed on
  those very strings — the script composes its RLMI out of the URIs it was given,
  not out of whatever this collection folded them to. Their value is the document
  held for each, the registrar's reading when nothing live is published, `nil`
  when there is none either.

  Each entry is watched on **its own domain**, which is why a list is not N calls
  to `watch/2` with one context: the three entries of one buddy list routinely sit
  on three different domains, and only one of them can be the routed one.

  The instance is monitored per resource, as `watch/2` monitors it: it is dropped
  from every resource it watches when it dies, whatever domain each of them lives
  on.
  """
  @spec watch_many(%SIP.Context{} | String.t(), SIP.Subscription.t(), [String.t()]) ::
          {:ok, %{String.t() => term}} | {:error, :down | :timeout}
  def watch_many(ctx_or_domain, sub, uris)

  def watch_many(%SIP.Context{} = sip_ctx, %SIP.Subscription{} = sub, uris),
    do: watch_many(sip_ctx.domain, sub, uris)

  def watch_many(domain, %SIP.Subscription{} = sub, uris) when is_list(uris) do
    SIP.Scenario.Monitor.note_command(:db, "presence_watch_many")
    domain = served_domain(domain)

    case Kelix.Module.safe_call(__MODULE__, {:watch_many, domain, sub, uris, self()}) do
      {:ok, docs} when is_map(docs) ->
        {:ok,
         Map.new(docs, fn
           {uri, nil} -> {uri, unpublished_state(uri_resource(uri, domain, sub.event))}
           held -> held
         end)}

      other ->
        other
    end
  end

  @doc """
  Stop watching: drop the calling instance from every resource it watches.

  Every resource, on every domain — an instance serving a list subscription is
  registered on as many domains as its list spans, and the domain it was routed
  through says nothing about them. The argument is kept for the scripts that pass
  their context, and is not read.
  """
  @spec unwatch(%SIP.Context{} | String.t()) :: :ok | {:error, :down | :timeout}
  def unwatch(ctx_or_domain)
  def unwatch(%SIP.Context{} = sip_ctx), do: unwatch(sip_ctx.domain)

  def unwatch(_domain),
    do: Kelix.Module.safe_call(__MODULE__, {:unwatch, self()})

  @doc """
  Report that a REGISTER was saved — whatever its outcome — so the presentity it
  names is open or closed from now on.

  Called by the registrar script after `Kelix.Mod.Registrar.save/2`. The status is
  not the script's to give: it is read off the registrar here, all the AOR's
  devices included, so an un-REGISTER from one handset leaves the subscriber open
  while another holds a binding. Watchers of the resource are pushed when the
  status changes and nothing live is published; a refreshing REGISTER pushes
  nothing.
  """
  @spec registration_changed(%SIP.Context{}) :: :ok | {:error, :down | :timeout}
  def registration_changed(%SIP.Context{} = sip_ctx), do: report_registration(sip_ctx, nil)

  @doc """
  The same, for a change no registrar script saw: a binding removed by hand
  (`kelictl registration remove`, `DELETE /domains/<domain>/registrations/<aor>`).
  `domain` is the served domain's name, `aor` the user part.
  """
  @spec registration_changed(String.t(), String.t()) :: :ok | {:error, :down | :timeout}
  def registration_changed(domain, aor) when is_binary(domain) and is_binary(aor) do
    resource = resource_key({aor, domain, "presence"})
    Kelix.Module.safe_call(__MODULE__, {:registration, resource, nil})
  end

  @doc """
  Report that the registration of this instance's dialog ended — its connection
  dropped, or it was not refreshed in time.

  The bindings of the ending dialog no longer count, even if the registrar has not
  dropped them yet; the presentity stays open while another device holds one.
  """
  @spec registration_ended(%SIP.Context{}) :: :ok | {:error, :down | :timeout}
  def registration_ended(%SIP.Context{} = sip_ctx),
    do: report_registration(sip_ctx, sip_ctx.dialogpid)

  # The AOR is the REGISTER's To, on the domain the router resolved — the key the
  # registrar stored the bindings under.
  defp report_registration(sip_ctx, ending_dialog) do
    SIP.Scenario.Monitor.note_command(:db, "presence_registration")

    # To is the raw header string on a parsed request: read it through the
    # framework, never by matching a `%SIP.Uri{}` only a hand-built request has.
    with %{} = req <- SIP.Session.CallUAS.stored_req(sip_ctx),
         user when is_binary(user) <- SIP.Msg.Ops.to_username(req) do
      resource = resource_key({user, sip_ctx.domain, "presence"})
      Kelix.Module.safe_call(__MODULE__, {:registration, resource, ending_dialog})
    else
      _no_register -> :ok
    end
  end

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

  @doc """
  State the presence of a resource on the calling module's own authority, on the
  `presence` package: `report/5` with `"presence"`.
  """
  @spec report(String.t(), String.t(), atom, SIP.Presence.Doc.t() | nil) ::
          :ok | {:error, :down | :timeout}
  def report(domain, user, source, doc), do: report(domain, user, source, doc, "presence")

  @doc """
  State a resource's state on one event package, on the calling module's own
  authority.

  `user` is the user part of the presentity on `domain`, `package` the event
  package the statement is about (`"presence"`, `"dialog"`), `source` names who
  says so (`:mcu`, `:dialog_state`), and `doc` is the document its watchers are to
  be told — what the package models: a `%SIP.Presence.Doc{}`, a
  `%SIP.DialogInfo.Doc{}`; `nil` withdraws what `source` said. The state ranks
  below a live publication and above what the collection tells for a resource
  nobody reports (see *Reported states* and *A resource nobody publishes*), and
  the watchers are pushed when the resolved state changes, and only then.

  The calling process is monitored: when it dies, every state it reported is
  withdrawn and the watchers told what follows. A reporter that restarts reports
  again.
  """
  @spec report(String.t(), String.t(), atom, term | nil, String.t()) ::
          :ok | {:error, :down | :timeout}
  def report(domain, user, source, doc, package)
      when is_binary(domain) and is_binary(user) and is_atom(source) and is_binary(package) do
    resource = resource_key({user, domain, package})

    # The existence question is a query on the subscriber base: asked HERE, in the
    # reporter's process, and kept with the report, so that withdrawing it later —
    # the reporter's death included — can tell a subscriber (closed, or idle) from
    # a resource that only existed through the report (no state).
    known? = doc != nil and provisioned?(resource)

    Kelix.Module.safe_call(__MODULE__, {:report, resource, source, doc, known?})
  end

  @doc """
  Whether the presentity `aor` exists on the context's domain: a subscriber
  `Kelix.Mod.AuthDb` knows, or a resource some source reports a state for (see
  *Reported states*). What a notifier script asks before accepting a SUBSCRIBE —
  a presentity that does not exist is a `404`, not a state a watcher would wait
  on.

  `aor` is the user part. A collection that cannot answer answers `false`.
  """
  @spec exists?(%SIP.Context{} | String.t(), String.t() | nil) :: boolean
  def exists?(ctx_or_domain, aor)
  def exists?(%SIP.Context{} = sip_ctx, aor), do: exists?(sip_ctx.domain, aor)

  def exists?(domain, aor) when is_binary(domain) and is_binary(aor) do
    {user, rdomain, _event} = resource = resource_key({aor, domain, "presence"})

    # the collection first: a call on an in-memory map, where the subscriber base
    # is a query
    Kelix.Module.safe_call(__MODULE__, {:reported?, resource}) == true or
      subscriber?(user, rdomain)
  end

  def exists?(_domain, _aor), do: false

  @doc """
  Whether the PUBLISH this instance serves is about the very user its digest
  proved — the question a compositor script asks before it lets anyone state a
  presence. The presentity is the Request-URI's user part (RFC 3903 §4.1, as
  `check_publish/1` reads it); the publisher is the identity the authentication
  recorded (`assert_identity/1`). Case-insensitive, as an AOR is.

  The domains are not compared: the digest was checked against the realm of the
  served domain, which is the domain the Request-URI routed to. `false` when
  nothing was authenticated or the request names no user.
  """
  @spec own_state?(%SIP.Context{}) :: boolean
  def own_state?(%SIP.Context{asserted_identity: %SIP.Uri{userpart: me}} = sip_ctx)
      when is_binary(me) do
    with %{} = req <- SIP.Session.CallUAS.stored_req(sip_ctx),
         user when is_binary(user) <- SIP.Msg.Ops.target_aor(req) do
      String.downcase(user) == String.downcase(me)
    else
      _ -> false
    end
  end

  def own_state?(_sip_ctx), do: false

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

  @doc """
  Subscribe `pid` to `domain`'s presentities as they change — the module half of
  `Kelix.Control.subscribe_presence/2`.

  Answers `{:ok, rows}`, the domain's presentities as they stand, taken in the
  same call that registers `pid` so no change falls between the two. `pid` then
  receives `{:kelix_presence, domain, {:upsert, row}}` each time a presentity's
  publications, watchers or status change, and `{:kelix_presence, domain,
  {:remove, aor}}` when nothing is published about it and nobody watches it any
  more. `pid` is monitored, so a dead or disconnected subscriber is dropped on its
  own.

  A row is one presentity — an AOR the domain holds a publication or a watcher
  for:

      %{domain, aor, presentity_uri, status, activity, note, states, watchers}

  `status` is `"open"` / `"closed"` as a watcher of its `presence` package would
  be told (see *A resource nobody publishes*), `nil` when there is no such state;
  `activity` and `note` are the RPID person facet of that same document. `states`
  and `watchers` are the rows `kelictl presence list` and `kelictl presence
  watchers` render.
  """
  @spec subscribe_presentities(String.t(), pid) :: {:ok, [map]} | {:error, :down | :timeout}
  def subscribe_presentities(domain, pid),
    do: Kelix.Module.safe_call(__MODULE__, {:subscribe_panel, served_domain(domain), pid})

  @doc "Stop a subscription started by `subscribe_presentities/2`."
  @spec unsubscribe_presentities(String.t(), pid) :: :ok | {:error, :down | :timeout}
  def unsubscribe_presentities(domain, pid),
    do: Kelix.Module.safe_call(__MODULE__, {:unsubscribe_panel, served_domain(domain), pid})

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

  def handle_call({:watch_many, domain, sub, uris, pid}, _from, state) do
    {reply, state} = do_watch_many(state, domain, sub, uris, pid)
    {:reply, reply, state}
  end

  def handle_call({:unwatch, pid}, _from, state) do
    {:reply, :ok, drop_watcher(state, pid)}
  end

  def handle_call({:state_of, resource}, _from, state) do
    {:reply, current_doc(state, resource), state}
  end

  def handle_call({:presentities, domain}, _from, state) do
    rows =
      for(
        {_resource, pubs} <- table_contents(state.states, domain),
        pub <- live_publications(pubs),
        do: render_publication(pub)
      ) ++ reported_rows(state, domain, :_) ++ registration_rows(state, domain, :_)

    {:reply, Enum.sort_by(rows, & &1.presentity_uri), state}
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

  def handle_call({:subscribe_panel, domain, pid}, _from, state) do
    subs = Map.get(state.panel_subs, domain, MapSet.new())

    state =
      if MapSet.member?(subs, pid) do
        state
      else
        ref = Process.monitor(pid)

        %{
          state
          | panel_subs: Map.put(state.panel_subs, domain, MapSet.put(subs, pid)),
            panel_mons: Map.put(state.panel_mons, ref, {domain, pid})
        }
      end

    {:reply, {:ok, panel_rows(state, domain)}, state}
  end

  def handle_call({:unsubscribe_panel, domain, pid}, _from, state) do
    {:reply, :ok, drop_panel_sub(state, domain, pid)}
  end

  def handle_call({:report, resource, source, doc, known?}, {pid, _tag}, state) do
    {:reply, :ok, do_report(state, resource, source, doc, known?, pid)}
  end

  def handle_call({:reported?, resource}, _from, state) do
    {:reply, reported_doc(state, resource) != nil, state}
  end

  # The registrar is asked HERE rather than in the reporting instance: two devices
  # of one AOR reporting at once are then answered in turn, each reading the store
  # as the other left it, and the last push is the true one.
  def handle_call({:registration, {user, domain, _event} = resource, ending_dialog}, _from, state) do
    open? =
      Code.ensure_loaded?(Kelix.Mod.Registrar) and
        Kelix.Mod.Registrar.registered?(domain, user, ending_dialog)

    {:reply, :ok, set_registered(state, resource, open?)}
  end

  # a watcher instance died with its dialog: it watches nothing any more — or a
  # panel subscriber went away
  @impl true
  def handle_info({:DOWN, ref, :process, pid, _reason}, state) do
    case Map.get(state.reporters, pid) do
      ^ref -> {:noreply, withdraw_reporter(state, pid)}
      _ -> {:noreply, watcher_down(state, ref)}
    end
  end

  def handle_info(:sweep, state) do
    state = Enum.reduce(Map.keys(state.states), state, &sweep_domain(&2, &1))
    Process.send_after(self(), :sweep, state.sweep_ms)
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  defp watcher_down(state, ref) do
    case Map.pop(state.mons, ref) do
      {nil, _} ->
        case Map.get(state.panel_mons, ref) do
          nil -> state
          {domain, pid} -> drop_panel_sub(state, domain, pid)
        end

      {{domain, resource, pid}, mons} ->
        forget_watcher(%{state | mons: mons}, domain, resource, pid)
    end
  end

  # ── publish ─────────────────────────────────────────────────────────────────

  defp do_publish(state, domain, pub) do
    {_user, rdomain, _event} = resource = resource_key(SIP.Publication.resource(pub), domain)
    tid = ensure_table(state.states, rdomain)
    state = %{state | states: Map.put(state.states, rdomain, tid)}
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
        {{:ok, nil, 0}, fan_out(state, resource, :removed)}

      {:store, previous, stored} ->
        store(tid, resource, List.delete(held, previous) ++ [stored])

        {{:ok, stored.etag, SIP.Publication.remaining(stored)},
         fan_out(state, resource, :published)}
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
      {{:ok, held_state(state, resource)}, state}
    else
      state = register_watcher(state, resource, sub, pid)
      {{:ok, held_state(state, resource)}, state}
    end
  end

  defp do_watch_many(state, domain, sub, uris, pid) do
    terminated? = SIP.Subscription.status(sub) == :terminated

    {docs, state} =
      Enum.reduce(uris, {%{}, state}, fn uri, {docs, st} ->
        {_user, rdomain, _event} = resource = uri_resource(uri, domain, sub.event)

        st =
          if terminated? or not served?(rdomain),
            do: st,
            else: register_watcher(st, resource, %{sub | presentity_uri: uri}, pid)

        {Map.put(docs, uri, held_state(st, resource)), st}
      end)

    {{:ok, docs}, state}
  end

  # A buddy list names whatever the client put in it, `sip:someone@some.example`
  # included. Registering a watcher on a domain this node does not serve costs a
  # table and a monitor for a resource nobody will ever publish — and the list is
  # the client's, so the count would be the client's too. Such an entry answers
  # `nil` instead, which the notifier reports as `noresource`.
  defp served?(domain) when is_binary(domain), do: domain_entry(domain) != :unknown
  defp served?(_no_domain), do: false

  # The table a resource lives in is the one of ITS domain, never the one that
  # routed the request that named it. They are the same for a plain SUBSCRIBE and
  # differ for every list subscription, so deriving it from the resource is what
  # makes a PUBLISH on `weshwesh.eu` reach a watcher admitted through another
  # domain.
  defp register_watcher(state, {_user, rdomain, _event} = resource, sub, pid) do
    tid = ensure_table(state.watchers, rdomain)
    state = %{state | watchers: Map.put(state.watchers, rdomain, tid)}
    subs = lookup_map(tid, resource)
    :ets.insert(tid, {resource, Map.put(subs, pid, sub)})

    state = monitor_watcher(state, rdomain, resource, pid)
    broadcast_panel(state, resource)
    state
  end

  defp monitor_watcher(state, domain, resource, pid) do
    if Enum.any?(state.mons, fn {_ref, key} -> key == {domain, resource, pid} end) do
      state
    else
      ref = Process.monitor(pid)
      %{state | mons: Map.put(state.mons, ref, {domain, resource, pid})}
    end
  end

  # What this instance watches is read off the monitors rather than off one
  # domain's table: a list subscription is registered on as many domains as its
  # list spans, and sweeping only the domain it was routed through would leave
  # every other entry pushing to a dead process.
  defp drop_watcher(state, pid) do
    state.mons
    |> Enum.filter(fn {_ref, {_domain, _resource, p}} -> p == pid end)
    |> Enum.reduce(state, fn {ref, {domain, resource, _p}}, st ->
      Process.demonitor(ref, [:flush])

      %{st | mons: Map.delete(st.mons, ref)}
      |> forget_watcher(domain, resource, pid)
    end)
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

        broadcast_panel(state, resource)
        state
    end
  end

  # ── the fan-out ─────────────────────────────────────────────────────────────

  # One PUBLISH, N pushes. The message reaches the watcher's SCENARIO INSTANCE,
  # which sends the NOTIFY from its own state (plan decision 1): a NOTIFY sent
  # from here would be invisible to `kelictl monitor` and to the sequence diagram,
  # and a scenario parked in a state would no longer describe what the node does.
  defp fan_out(state, {_user, rdomain, _event} = resource, event) do
    watchers = watchers_of(state, resource)

    # Nothing to compute for nobody. When the last publication goes, the
    # presentity published, so it exists — the subscriber base is not asked.
    if map_size(watchers) > 0, do: push(watchers, resource, known_state(state, resource))

    broadcast_panel(state, resource)
    Kelix.Metrics.Emit.presence_event(rdomain, event)
    state
  end

  defp push(watchers, resource, doc) do
    for {pid, _sub} <- watchers, do: send(pid, {:presence, :state, resource, doc})
    :ok
  end

  # A registration moved. It is news only when the status actually changed — the
  # registrar script reports every refreshing REGISTER — and only for a resource
  # nobody publishes nor reports: both win over the registration.
  defp set_registered(state, resource, open?) do
    if MapSet.member?(state.registered, resource) == open? do
      state
    else
      registered =
        if open?,
          do: MapSet.put(state.registered, resource),
          else: MapSet.delete(state.registered, resource)

      state = %{state | registered: registered}
      watchers = watchers_of(state, resource)

      if map_size(watchers) > 0 and current_doc(state, resource) == nil and
           reported_doc(state, resource) == nil,
         do: push(watchers, resource, known_state(state, resource))

      broadcast_panel(state, resource)
      state
    end
  end

  # ── reported states ─────────────────────────────────────────────────────────

  # One source's statement about one resource. The watchers see the RESOLVED
  # state, so they are pushed only when that moves: a report under a live
  # publication, or one repeating what its source already said, is news to nobody.
  defp do_report(state, resource, source, doc, known?, pid) do
    # one reading of existence for both sides of the comparison: withdrawing the
    # last report must not change it
    known? = known? or reported_known?(state, resource)
    before = resolved_state(state, resource, known?)

    sources = Map.get(state.reported, resource, %{})

    sources =
      case doc do
        nil ->
          Map.delete(sources, source)

        doc ->
          entry = %{doc: doc, pid: pid, seq: System.unique_integer([:monotonic]), known?: known?}
          Map.put(sources, source, entry)
      end

    state = if doc == nil, do: state, else: monitor_reporter(state, pid)

    state = put_reported(state, resource, sources)
    reported_changed(state, resource, before, resolved_state(state, resource, known?))
  end

  # Everything a dead reporter said goes with it, each resource pushed as it
  # resolves without it.
  defp withdraw_reporter(state, pid) do
    state = %{state | reporters: Map.delete(state.reporters, pid)}

    Enum.reduce(state.reported, state, fn {resource, sources}, st ->
      {gone, kept} = Enum.split_with(sources, fn {_source, entry} -> entry.pid == pid end)

      if gone == [] do
        st
      else
        known? = Enum.any?(sources, fn {_source, entry} -> entry.known? end)
        before = resolved_state(st, resource, known?)
        st = put_reported(st, resource, Map.new(kept))
        reported_changed(st, resource, before, resolved_state(st, resource, known?))
      end
    end)
  end

  defp reported_changed(state, resource, before, after_) do
    if before != after_ do
      watchers = watchers_of(state, resource)
      if map_size(watchers) > 0, do: push(watchers, resource, after_)
    end

    broadcast_panel(state, resource)
    state
  end

  defp put_reported(state, resource, sources) when map_size(sources) == 0,
    do: %{state | reported: Map.delete(state.reported, resource)}

  defp put_reported(state, resource, sources),
    do: %{state | reported: Map.put(state.reported, resource, sources)}

  defp monitor_reporter(state, pid) do
    if Map.has_key?(state.reporters, pid),
      do: state,
      else: %{state | reporters: Map.put(state.reporters, pid, Process.monitor(pid))}
  end

  # The most recent source's document wins, as the most recent publication does:
  # composing two sources is no more this collection's job than composing two
  # publishers.
  defp reported_doc(state, resource) do
    case Map.get(state.reported, resource) do
      nil -> nil
      sources -> sources |> Map.values() |> Enum.max_by(& &1.seq) |> Map.get(:doc)
    end
  end

  defp reported_known?(state, resource) do
    state.reported
    |> Map.get(resource, %{})
    |> Enum.any?(fn {_source, entry} -> entry.known? end)
  end

  # ── a resource nobody publishes ─────────────────────────────────────────────

  # The state of a resource, in order: its live publication, a reported state,
  # then what its package tells for a presentity known to exist — `known?`, which
  # the caller answers — else nil. On `presence`: open for a registered
  # presentity, closed on a domain with a registrar. On `dialog`: no call.
  defp resolved_state(state, resource, known?) do
    current_doc(state, resource) || reported_doc(state, resource) ||
      status_doc(resource, implied_status(state, resource, known?))
  end

  # The state as the collection alone can tell it, for a resource known to exist
  # since it published or registered.
  defp known_state(state, resource), do: resolved_state(state, resource, true)

  # What the collection answers a watcher: the publication, else a reported
  # state, else open for a registered presentity, else nil — which the facade
  # completes in the caller's process with `unpublished_state/1`.
  defp held_state(state, resource) do
    current_doc(state, resource) || reported_doc(state, resource) ||
      if MapSet.member?(state.registered, resource), do: status_doc(resource, :open)
  end

  # The same, for a watcher that just subscribed: a presentity that neither
  # publishes nor is registered may be one nobody provisioned. The existence
  # question is a query on the subscriber base, so it runs in the CALLER's process
  # (the facades call this on a `nil` the collection answered) — never in the
  # collection's, where every other watcher and publisher would wait on it.
  defp unpublished_state(resource),
    do: status_doc(resource, implied_status(nil, resource, false))

  # What the package says of a presentity nobody publishes nor reports. On
  # `presence`: `:open` / `:closed`, or nil on a domain with no registrar (or not
  # served), or for a user the subscriber base does not know. On `dialog`: `:idle`
  # for a subscriber the base knows — the registration says nothing about a call
  # — else nil. Any other package: nil.
  defp implied_status(state, {user, domain, "presence"} = resource, known?)
       when is_binary(user) and is_binary(domain) do
    cond do
      state != nil and MapSet.member?(state.registered, resource) -> :open
      registrar_domain?(domain) and (known? or subscriber?(user, domain)) -> :closed
      true -> nil
    end
  end

  defp implied_status(_state, {user, domain, "dialog"} = resource, known?)
       when is_binary(user) and is_binary(domain) do
    if known? or provisioned?(resource), do: :idle, else: nil
  end

  defp implied_status(_state, _resource, _known?), do: nil

  defp status_doc(_resource, nil), do: nil

  defp status_doc({user, domain, "dialog"}, :idle),
    do: %SIP.DialogInfo.Doc{entity: "sip:#{user}@#{domain}"}

  defp status_doc({user, domain, _event}, status),
    do: SIP.Presence.Doc.new("sip:#{user}@#{domain}", status)

  # Whether the subscriber base provisions the presentity, as far as the package
  # can use the answer: on `presence` it takes a registrar to say "closed", on
  # `dialog` a known AOR is idle whatever registers it.
  defp provisioned?({user, domain, "presence"}),
    do: registrar_domain?(domain) and subscriber?(user, domain)

  defp provisioned?({user, domain, "dialog"}), do: subscriber?(user, domain)
  defp provisioned?(_resource), do: false

  defp registrar_domain?(domain) do
    match?(%Kelix.Domain{registrar: registrar} when registrar != nil, domain_entry(domain))
  end

  # The modules are installed separately: a node may run this one without the
  # subscriber base, and the existence question then has no answer.
  defp subscriber?(user, domain),
    do: Code.ensure_loaded?(Kelix.Mod.AuthDb) and Kelix.Mod.AuthDb.subscriber?(user, domain)

  defp watchers_of(state, {_user, rdomain, _event} = resource) do
    case Map.get(state.watchers, rdomain) do
      nil -> %{}
      tid -> lookup_map(tid, resource)
    end
  end

  # The state of a resource: the most recent live publication's document (see the
  # moduledoc — composition is its own phase), `nil` when nothing is published.
  defp current_doc(state, {_user, rdomain, _event} = resource) do
    case Map.get(state.states, rdomain) do
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
                fan_out(st, resource, :removed)
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
          fan_out(st, resource, :expired)
      end
    end)
  end

  # ── the live panel (kelescope) ──────────────────────────────────────────────

  defp drop_panel_sub(state, domain, pid) do
    {refs, mons} =
      Enum.split_with(state.panel_mons, fn {_ref, key} -> key == {domain, pid} end)

    Enum.each(refs, fn {ref, _key} -> Process.demonitor(ref, [:flush]) end)

    subs =
      state.panel_subs
      |> Map.get(domain, MapSet.new())
      |> MapSet.delete(pid)
      |> then(fn set ->
        if MapSet.size(set) == 0,
          do: Map.delete(state.panel_subs, domain),
          else: Map.put(state.panel_subs, domain, set)
      end)

    %{state | panel_subs: subs, panel_mons: Map.new(mons)}
  end

  # Skips the render entirely when nobody watches the domain's panel: every
  # PUBLISH and every SUBSCRIBE comes through here, and a domain nobody displays
  # must cost nothing.
  defp broadcast_panel(state, {user, rdomain, _event}) do
    case Map.get(state.panel_subs, rdomain) do
      nil ->
        :ok

      subs ->
        msg =
          case panel_row(state, rdomain, user) do
            nil -> {:remove, user}
            row -> {:upsert, row}
          end

        for pid <- subs, do: send(pid, {:kelix_presence, rdomain, msg})
        :ok
    end
  end

  # Sorted: the tables are ETS sets, whose enumeration order is arbitrary and
  # would reshuffle the panel between two otherwise identical snapshots.
  defp panel_rows(state, domain) do
    held =
      for tables <- [state.states, state.watchers],
          {{user, _dom, _event}, _held} <- table_contents(tables, domain),
          do: user

    registered = for {user, ^domain, _event} <- state.registered, do: user
    reported = for {{user, ^domain, _event}, _sources} <- state.reported, do: user
    users = Enum.uniq(held ++ registered ++ reported)

    users
    |> Enum.sort()
    |> Enum.map(&panel_row(state, domain, &1))
    |> Enum.reject(&is_nil/1)
  end

  # One presentity, every package it is published or watched on, and its reported
  # registration. `nil` when there is none of the three — the row is gone.
  defp panel_row(state, domain, user) do
    states =
      for(
        {_resource, pubs} <- match_user(state.states, domain, user),
        pub <- live_publications(pubs),
        do: render_publication(pub)
      ) ++ reported_rows(state, domain, user) ++ registration_rows(state, domain, user)

    watchers =
      for {_resource, subs} <- match_user(state.watchers, domain, user),
          {_pid, sub} <- subs,
          do: render_subscription(sub)

    if states == [] and watchers == [] do
      nil
    else
      doc = known_state(state, {user, domain, "presence"})

      %{
        domain: domain,
        aor: user,
        presentity_uri: "sip:#{user}@#{domain}",
        status: doc_field(doc, :status),
        activity: doc_field(doc, :activity),
        note: doc_field(doc, :note),
        states: states,
        watchers: watchers
      }
    end
  end

  defp match_user(tables, domain, user) do
    case Map.get(tables, domain) do
      nil -> []
      tid -> :ets.match_object(tid, {{user, :_, :_}, :_})
    end
  end

  # The document is opaque to the collection; only a PIDF one has these fields,
  # and a dialog-info one is shown by what it lists.
  defp doc_field(%SIP.Presence.Doc{} = doc, :status),
    do: doc |> SIP.Presence.Doc.status() |> to_string()

  defp doc_field(%SIP.DialogInfo.Doc{dialogs: [_one]}, :status), do: "1 dialog"
  defp doc_field(%SIP.DialogInfo.Doc{dialogs: dialogs}, :status), do: "#{length(dialogs)} dialogs"

  defp doc_field(%SIP.Presence.Doc{activity: nil}, :activity), do: nil
  defp doc_field(%SIP.Presence.Doc{activity: a}, :activity), do: to_string(a)
  defp doc_field(%SIP.Presence.Doc{note: note}, :note), do: note
  defp doc_field(_doc, _field), do: nil

  # ── rendering (what both control frontals show) ─────────────────────────────

  # kamailio's column names, deliberately: an operator reading this and an
  # operator reading the table they migrated from are reading one vocabulary
  # (DESIGN-PRESENCE.md, *The data model is kamailio's*).
  defp render_publication(%SIP.Publication{} = pub) do
    %{
      presentity_uri: SIP.Publication.presentity_uri(pub),
      event: pub.event,
      source: "publish",
      status: doc_field(pub.doc, :status),
      etag: pub.etag,
      expires: SIP.Publication.remaining(pub),
      sender: pub.sender,
      content_type: pub.content_type
    }
  end

  # A presentity the registrar script reported registered holds a state nobody
  # published: open, which is what its watchers are told while nothing live is
  # published. Listed beside the publications so `list` shows every state the
  # collection holds, not only kamailio's `presentity` rows. `user` is `:_` for
  # the whole domain.
  defp registration_rows(state, domain, user) do
    for {u, ^domain, event} <- state.registered, user == :_ or u == user do
      %{
        presentity_uri: "sip:#{u}@#{domain}",
        event: event,
        source: "registrar",
        status: "open",
        etag: nil,
        expires: nil,
        sender: nil,
        content_type: nil
      }
    end
  end

  # A state another module reported, one row per source — `source` names it
  # (`mcu`), as `registrar` names the registration's.
  defp reported_rows(state, domain, user) do
    for {{u, ^domain, event}, sources} <- state.reported,
        user == :_ or u == user,
        {source, entry} <- Enum.sort(sources) do
      %{
        presentity_uri: "sip:#{u}@#{domain}",
        event: event,
        source: to_string(source),
        status: doc_field(entry.doc, :status),
        etag: nil,
        expires: nil,
        sender: nil,
        content_type: nil
      }
    end
  end

  defp render_subscription(%SIP.Subscription{} = sub) do
    %{
      presentity_uri: sub.presentity_uri,
      watcher: SIP.Subscription.watcher_uri(sub),
      event: sub.event,
      event_id: sub.event_id,
      status: to_string(SIP.Subscription.status(sub)),
      expires: SIP.Subscription.remaining(sub),
      callid: sub.callid
    }
  end

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
      {:ok, %SIP.Uri{userpart: user, domain: dom}} ->
        resource_key({user, dom || domain, sub.event})

      _ ->
        resource_key({sub.to_user, sub.to_domain || domain, sub.event})
    end
  end

  # One entry of a resource list, as the watcher wrote it. Same rule: the domain
  # comes from the URI, and the caller's is only what an entry without one falls
  # back on.
  defp uri_resource(uri, domain, event) do
    case SIP.Uri.parse(to_string(uri)) do
      {:ok, %SIP.Uri{userpart: user, domain: dom}} -> resource_key({user, dom || domain, event})
      _ -> resource_key({uri, domain, event})
    end
  end

  # alias → nominal domain name (folds via Domains when it is running; else
  # identity), so a watcher reaching us on `example.fr` and a publisher on
  # `example.com` share one resource.
  defp served_domain(nil), do: nil

  defp served_domain(domain) when is_binary(domain) do
    case domain_entry(domain) do
      %Kelix.Domain{name: name} -> name
      _unknown_or_no_registry -> domain
    end
  end

  # The domain as `domains.toml` holds it, `:unknown` when it holds no such
  # domain, and `:no_registry` when there is no configuration to consult at all
  # — a unit test, an elixipp run. The last two are deliberately different
  # answers: with no registry there is no policy, and refusing everything would
  # be one.
  defp domain_entry(domain) do
    case Process.whereis(Kelix.Domains) do
      nil -> :no_registry
      _pid -> Kelix.Domains.lookup(Kelix.Domains.current(), domain) || :unknown
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
