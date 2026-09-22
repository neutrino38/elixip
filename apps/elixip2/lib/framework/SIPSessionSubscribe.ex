# The subscription layer (RFC 6665): one subscription, seen from the dialog that
# carries it. See docs/design/DESIGN-PRESENCE.md, "The subscription layer
# (framework)", and docs/design/presence-basic-plan.md, phase P3.
#
# Three modules, in the order they are read:
#
#   * `SIP.Subscription` — what one subscription IS. A kamailio `active_watchers`
#     row, under that row's names.
#   * `SIP.Session.Notifier` — the server half: the negotiation and its refusals,
#     the 2xx, the NOTIFYs.
#   * `SIP.Session.SubscribeUAC` — the watcher half: the SUBSCRIBE, its refresh,
#     and what a NOTIFY off the wire means.
#
# What is NOT here, on purpose: the timers and the final NOTIFY, which live in
# the dialog (`SIP.DialogImpl`, design decision 1 — no process per subscription,
# and the dialog already carries `expirationtimer`), and the collection of who
# watches what, which is a kelixip module's.

defmodule SIP.Subscription do
  @moduledoc """
  One subscription: an event package, a dialog, a lifetime and a state.

  ## It is a kamailio row

  Every field below but the last four is a column of kamailio 6.1's
  `active_watchers` table, carrying that column's value under that column's name
  (docs/design/DESIGN-PRESENCE.md, *The data model is kamailio's*). That is
  decided now and not when a database backend is written, because a struct
  designed freely today is a migration tomorrow, and the migration is what never
  gets written. Three consequences worth stating out loud:

    * **`expires` is an absolute epoch second**, not a remaining lifetime.
      kamailio writes `expires + time(NULL)` and reads back `expires -
      time(NULL)`; so do we, and nothing converts in between — a conversion in
      the middle is where the sign error lives. `remaining/1` is the one place
      that subtracts.
    * **`status` is kamailio's integer**, not an atom: 1 active, 2 pending (the
      column's default), 3 terminated, 4 waiting, 5 polite-block. `status/1`
      reads it as an atom for a `case`; the integer is what is stored.
    * **`event` is the package name as a string**, with `event_id` beside it —
      exactly the `{package, id}` pair `SIP.Msg.Ops.event_package/1` returns.

  `updated`, `updated_winfo`, `flags` and `priority` are kamailio's own cluster
  bookkeeping. They are filled with the defaults the schema states and treated as
  opaque: we use the format, we do not claim to use the base the way kamailio
  does.

  ## The key

  RFC 6665 keys a subscription on Call-ID + both tags + the event type + `id`,
  and several subscriptions may share one dialog. Real clients do not — Linphone
  opens one dialog per subscription — and **v1 refuses a second package on an
  existing dialog** (489). The key is complete from day one all the same, because
  widening it later is a breaking change to everything that stores one. It is
  also `active_watchers`'s own key: `UNIQUE (callid, to_tag, from_tag)` plus
  `event` and `event_id`.

  `to_tag` is the notifier's tag and `from_tag` the watcher's, on both sides of
  the wire: the row describes the subscription, not the point of view. Which of
  the two is *local* follows from the dialog's direction, and the dialog is what
  fills them (`SIP.Dialog.set_subscription/2`).
  """

  @typedoc "kamailio's `status` enum (presence/subscribe.h)."
  @type status :: 1..5

  defstruct [
    # ── the key ──────────────────────────────────────────────────────────────
    callid: nil,
    to_tag: nil,
    from_tag: nil,
    event: nil,
    event_id: nil,
    # ── who watches what ─────────────────────────────────────────────────────
    presentity_uri: nil,
    watcher_username: nil,
    watcher_domain: nil,
    to_user: nil,
    to_domain: nil,
    from_user: nil,
    from_domain: nil,
    # ── the dialog carrying it ───────────────────────────────────────────────
    local_cseq: 0,
    remote_cseq: 0,
    contact: nil,
    local_contact: nil,
    record_route: nil,
    socket_info: nil,
    user_agent: nil,
    # ── its lifetime and its state ───────────────────────────────────────────
    # ABSOLUTE epoch second, like kamailio's column. Never a remaining lifetime.
    expires: 0,
    # 2 = pending, the column's default.
    status: 2,
    reason: nil,
    version: 0,
    # ── kamailio's own bookkeeping, filled with the schema's defaults ────────
    updated: 0,
    updated_winfo: 0,
    flags: 0,
    # ── not columns: the handles the framework works with ────────────────────
    # What `{:subscription_terminated, ref, reason}` names. A row has no column
    # for it because a row does not have to be told when it ends.
    ref: nil,
    # The `SIP.EventPackage` implementation, and the content type negotiated out
    # of its `content_types/0` against the SUBSCRIBE's `Accept`.
    package: nil,
    content_type: nil
  ]

  @type t :: %__MODULE__{}

  @statuses %{1 => :active, 2 => :pending, 3 => :terminated, 4 => :waiting, 5 => :polite_block}
  @status_ints Map.new(@statuses, fn {int, atom} -> {atom, int} end)

  @doc """
  The RFC 6665 subscription key: `{callid, to_tag, from_tag, event, event_id}`.

  Complete from day one — see the moduledoc — and identical on both sides of the
  wire, so a watcher and a notifier name the same subscription the same way.
  """
  @spec key(t()) ::
          {binary() | nil, binary() | nil, binary() | nil, binary() | nil, binary() | nil}
  def key(%__MODULE__{} = sub),
    do: {sub.callid, sub.to_tag, sub.from_tag, sub.event, sub.event_id}

  @doc "kamailio's `status` integer, read as an atom. An unknown value reads `:terminated`."
  @spec status(t() | non_neg_integer()) ::
          :active | :pending | :terminated | :waiting | :polite_block
  def status(%__MODULE__{status: value}), do: status(value)
  def status(value) when is_integer(value), do: Map.get(@statuses, value, :terminated)

  @doc "The same, the other way round, for a caller holding an atom."
  @spec status_int(atom()) :: status()
  def status_int(atom) when is_atom(atom), do: Map.get(@status_ints, atom, 3)

  @doc "Set `status` from an atom, keeping the column an integer."
  @spec put_status(t(), atom()) :: t()
  def put_status(%__MODULE__{} = sub, atom), do: %{sub | status: status_int(atom)}

  @doc """
  How many seconds this subscription still has, now — `expires` being absolute.

  Never negative: a lapsed subscription has 0 seconds left, which is what goes
  into the `Subscription-State` of the NOTIFY that announces its end.
  """
  @spec remaining(t()) :: non_neg_integer()
  def remaining(%__MODULE__{expires: expires}), do: max(expires - now(), 0)

  @doc "Set the absolute `expires` from a lifetime in seconds."
  @spec grant(t(), non_neg_integer()) :: t()
  def grant(%__MODULE__{} = sub, seconds) when is_integer(seconds) and seconds >= 0,
    do: %{sub | expires: now() + seconds, updated: now()}

  @doc "The epoch second, the way kamailio counts it (`time(NULL)`)."
  @spec now() :: integer()
  def now, do: System.os_time(:second)
end

defmodule SIP.Session.Notifier do
  @moduledoc """
  The notifier half of RFC 6665: what a server scenario calls when a SUBSCRIBE
  lands on it.

      state authorize do
        case accept_subscription(expires: :negotiated) do
          {:ok, _sub} -> notify(state_doc()); goto(subscribed, "200 + NOTIFY")
          # the verb has already answered 423 / 406 / 489
          {:error, code} -> goto(wait_subscribe, "\#{code}")
        end
      end

  ## What the verb decides, so the script does not

  `accept_subscription/0,1` negotiates before it accepts, and answers the refusal
  itself when the negotiation fails — there is nothing for a script to check:

  | Read | Against | Refusal |
  |---|---|---|
  | `Require` | the extensions this layer implements | **420 Bad Extension**, with `Unsupported` |
  | `Event` | `SIP.EventPackage.lookup/1` | **489 Bad Event** |
  | `Accept` | the package's `content_types/0` | **406 Not Acceptable** |
  | `Expires` | the package's `min_expires/0` | **423 Interval Too Brief**, with `Min-Expires` |

  Above `max_expires/0` nothing is refused: the notifier grants its maximum, which
  is what RFC 6665 §4.2.1 asks for. `Expires: 0` is not a refusal either — it is
  how a watcher un-subscribes, and it is accepted as a lifetime of zero, which the
  dialog turns into the final NOTIFY straight away.

  Each reading goes through `SIP.Msg.Ops` (CLAUDE.md, *Message Layer*); none of
  them is re-derived here.

  ## What the framework does after the 2xx

  `SIP.Dialog.set_subscription/2` hands the dialog the subscription, and from
  that moment the **dialog** owns its end: it arms the granted lifetime, and when
  that lifetime lapses it sends the final NOTIFY
  (`Subscription-State: terminated;reason=timeout`) and hands the scenario its one
  `{:subscription_terminated, ref, reason}`. Left to the script that NOTIFY would
  be forgotten in three scripts out of four, and the subscription would leak on the
  watcher's side (design decision 4).
  """

  require Logger

  @doc false
  defmacro __using__(_opts) do
    quote do
      use SIP.Context

      @doc """
      Accept the SUBSCRIBE this instance is serving, after negotiating it.

      Answers `{:ok, %SIP.Subscription{}}`, or `{:error, code}` — in which case
      the refusal has already gone out on the wire. Options:

        * `:expires` — `:negotiated` (the default: what the watcher asked for,
          bounded by the package) or an integer ceiling of the scenario's own;
        * `:package` — the package name this scenario serves. A SUBSCRIBE for any
          other one is answered **489** without the scenario having to look;
        * `:allow_events` — the package names the *domain* enables, written out
          as `Allow-Events` on the 2xx. A property of the domain, never of the
          node (plan decision 3), so the caller passes it.
      """
      defmacro accept_subscription(opts \\ []) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "accept_subscription")

          {var!(sip_ctx), unquote(Macro.var(:__sub_rc__, __MODULE__))} =
            SIP.Session.Notifier.do_accept_subscription(var!(sip_ctx), unquote(opts))

          unquote(Macro.var(:__sub_rc__, __MODULE__))
        end
      end

      @doc """
      Refuse the SUBSCRIBE this instance is serving with `code`.

      For the policy refusals only — a watcher who may not watch (**403**), a
      resource that does not exist (**404**). The protocol refusals (489, 406,
      423) are `accept_subscription/1`'s and have already gone out by the time it
      answers `{:error, code}`.
      """
      defmacro reject_subscription(code, reason \\ nil) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "reject_subscription #{unquote(code)}")

          var!(sip_ctx) =
            SIP.Session.Notifier.do_reject_subscription(
              var!(sip_ctx),
              unquote(code),
              unquote(reason)
            )
        end
      end

      @doc """
      Send the current state to the watcher as a NOTIFY — the whole document, since
      v1 emits full state only.

      `doc` is whatever this subscription's event package models; it is handed to
      its `serialize/2` with the content type negotiated at acceptance. A binary
      is passed through packages that model their document as text.
      """
      defmacro notify(doc) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "notify")
          var!(sip_ctx) = SIP.Session.Notifier.do_notify(var!(sip_ctx), unquote(doc))
        end
      end

      @doc """
      End this subscription now, stating why — one of RFC 6665 §4.1.3's reasons
      (`:noresource`, `:rejected`, `:deactivated`, `:probation`, `:giveup`,
      `:invariant`, `:timeout`).

      The final NOTIFY goes out and the scenario is handed its one
      `{:subscription_terminated, ref, reason}`; both come from the dialog, which
      is the single place that guarantees exactly one of each.
      """
      defmacro terminate_subscription(reason \\ :noresource) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "terminate_subscription")

          var!(sip_ctx) =
            SIP.Session.Notifier.do_terminate_subscription(var!(sip_ctx), unquote(reason))
        end
      end

      @doc "The subscription this instance is serving, or nil before it accepted one."
      defmacro last_subscription() do
        quote do
          SIP.Context.appdata_get(var!(sip_ctx), :subscription)
        end
      end
    end
  end

  # ── The negotiation ─────────────────────────────────────────────────────────

  @doc """
  Read a SUBSCRIBE against the packages this node knows, and say what may be
  granted.

  Answers `{:ok, package_module, content_type, granted_expires}`, or
  `{:error, code, reason, fields}` — `fields` being what the refusal must carry
  (the `Min-Expires` of a 423, RFC 6665 §4.2.1 making it as mandatory there as
  RFC 3261 §10.3 does for a REGISTER: without it the watcher has no way to know
  what to ask for and simply gives up).

  Public because the Router asks the same question before any script runs, and
  asking it twice is how two answers to one question start.
  """
  @spec negotiate(map(), keyword()) ::
          {:ok, module(), binary(), non_neg_integer()} | {:error, 400..699, binary(), list()}
  def negotiate(req, opts \\ []) when is_map(req) do
    with :ok <- check_required_extensions(req),
         {:ok, name, id} <- read_event(req, opts),
         {:ok, package} <- lookup_package(name),
         {:ok, content_type} <- pick_content_type(req, package),
         {:ok, granted} <- bound_expires(req, package, opts) do
      _ = id
      {:ok, package, content_type, granted}
    end
  end

  # The extensions the subscription layer implements. Empty is a complete answer:
  # what it means is "this layer implements no SIP extension a watcher may demand",
  # and a watcher demanding one is told so rather than served something else.
  @supported_extensions []

  # RFC 3261 §8.2.2.3. The 420 names the extensions in `Unsupported`, so a watcher
  # that can do without them asks again; a refusal that says only "no" leaves it
  # retrying the same request.
  #
  # Checked here, in the subscription layer, and NOT on every inbound request: a
  # blanket check would start refusing the `Require: timer` and `Require: 100rel`
  # of INVITEs this node serves today, which is a regression, not a fix.
  defp check_required_extensions(req) do
    case SIP.Msg.Ops.required_extensions(req) -- @supported_extensions do
      [] ->
        :ok

      unsupported ->
        Logger.info(
          "Subscription refused: unsupported extension(s) #{Enum.join(unsupported, ", ")} (420)"
        )

        {:error, 420, "Bad Extension", [{"Unsupported", Enum.join(unsupported, ", ")}]}
    end
  end

  # No Event header at all is a SUBSCRIBE nobody can serve (RFC 6665 §8.2.1): the
  # package is what says which state is being asked for, so its absence is the
  # same answer as a package we do not know.
  defp read_event(req, opts) do
    case SIP.Msg.Ops.event_package(req) do
      nil ->
        {:error, 489, "Bad Event", []}

      {name, id} ->
        case Keyword.get(opts, :package) do
          nil -> {:ok, name, id}
          served when is_binary(served) -> match_served_package(name, id, served)
        end
    end
  end

  defp match_served_package(name, id, served) do
    if name == String.downcase(served) do
      {:ok, name, id}
    else
      # A scenario serving one package must never have to check that the inbound
      # SUBSCRIBE concerns it (plan §1, "489 before any script").
      {:error, 489, "Bad Event", []}
    end
  end

  defp lookup_package(name) do
    case SIP.EventPackage.lookup(name) do
      {:ok, package} ->
        {:ok, package}

      :error ->
        # Not a boot refusal and not a crash: a domain may name a package whose
        # module has not started yet, and start order stays out of the contract
        # (design, *Who registers a package*, rule 2).
        Logger.info("Subscription refused: no event package '#{name}' on this node (489)")
        {:error, 489, "Bad Event", []}
    end
  end

  # The package's own preference order decides, not the watcher's `q` — which is
  # why `accepted_content_types/1` drops it. An absent Accept means "the default
  # type of the package" (RFC 6665 §4.4.5), never "nothing is acceptable".
  defp pick_content_type(req, package) do
    offered = package.content_types()

    case SIP.Msg.Ops.accepted_content_types(req) do
      [] ->
        case offered do
          [first | _] -> {:ok, first}
          [] -> {:error, 406, "Not Acceptable", []}
        end

      accepted ->
        case Enum.find(offered, &(String.downcase(&1) in accepted)) do
          nil -> {:error, 406, "Not Acceptable", []}
          content_type -> {:ok, content_type}
        end
    end
  end

  defp bound_expires(req, package, opts) do
    requested = SIP.Msg.Ops.subscription_expires(req, package.default_expires())
    ceiling = ceiling_of(opts, package)

    cond do
      # An un-subscribe, not a lifetime that is "too brief" (RFC 6665 §4.4.4).
      # The same distinction the registrar had to learn the hard way for a
      # rebinding REGISTER carrying `;expires=0`.
      requested == 0 -> {:ok, 0}
      requested < package.min_expires() -> too_brief(package)
      true -> {:ok, min(requested, ceiling)}
    end
  end

  # `nil` reads as `:negotiated`, so a caller passing a value it read from its own
  # configuration does not have to strip the absence first.
  defp ceiling_of(opts, package) do
    case Keyword.get(opts, :expires) do
      seconds when is_integer(seconds) -> min(seconds, package.max_expires())
      _negotiated -> package.max_expires()
    end
  end

  defp too_brief(package) do
    {:error, 423, "Interval Too Brief", [{"Min-Expires", to_string(package.min_expires())}]}
  end

  # ── The verbs ───────────────────────────────────────────────────────────────

  @doc false
  @spec do_accept_subscription(%SIP.Context{}, keyword()) ::
          {%SIP.Context{}, {:ok, SIP.Subscription.t()} | {:error, 400..699}}
  def do_accept_subscription(sip_ctx = %SIP.Context{}, opts) when is_list(opts) do
    req = stored_subscribe!(sip_ctx)

    case negotiate(req, opts) do
      {:ok, package, content_type, granted} ->
        accept(sip_ctx, req, package, content_type, granted, opts)

      {:error, code, reason, fields} ->
        sip_ctx = reply(sip_ctx, req, code, reason, fields, "reject_subscribe #{code}")
        {sip_ctx, {:error, code}}
    end
  end

  defp accept(sip_ctx, req, package, content_type, granted, opts) do
    # The watcher is the From of the SUBSCRIBE, and `active_watchers` keeps it
    # under three pairs of columns: the two addresses as sent, and the watcher
    # itself. Read once, in the message layer, like every other header.
    {from_user, from_domain} = SIP.Msg.Ops.header_aor(req, :from)
    {to_user, to_domain} = SIP.Msg.Ops.header_aor(req, :to)

    sub =
      %SIP.Subscription{
        event: package.name(),
        event_id: elem(SIP.Msg.Ops.event_package(req) || {nil, nil}, 1),
        package: package,
        content_type: content_type,
        presentity_uri: presentity_uri(req),
        watcher_username: from_user,
        watcher_domain: from_domain,
        from_user: from_user,
        from_domain: from_domain,
        to_user: to_user,
        to_domain: to_domain,
        user_agent: Map.get(req, :useragent),
        ref: make_ref()
      }
      # An un-SUBSCRIBE is accepted like any other (RFC 6665 §4.4.4 makes it a
      # lifetime of zero, not a refusal), and what it accepts is the END of the
      # subscription: kamailio's `terminated`, not an `active` row with nothing
      # left to run.
      |> SIP.Subscription.put_status(if granted > 0, do: :active, else: :terminated)
      |> SIP.Subscription.grant(granted)

    fields =
      [expires: granted]
      |> put_allow_events(opts)

    sip_ctx = reply(sip_ctx, req, 200, "OK", fields, "accept_subscription")

    # From here the dialog owns the lifetime, the final NOTIFY and the one
    # termination event. It also fills the columns only it knows — both tags,
    # the CSeqs, the route set and the contacts.
    case SIP.Dialog.set_subscription(sip_ctx.dialogpid, sub) do
      {:ok, sub} ->
        {SIP.Context.appdata_set(sip_ctx, :subscription, sub), {:ok, sub}}

      {:error, reason} ->
        Logger.warning("Subscription accepted but the dialog refused it: #{inspect(reason)}")
        {SIP.Context.appdata_set(sip_ctx, :subscription, sub), {:ok, sub}}
    end
  end

  defp put_allow_events(fields, opts) do
    case Keyword.get(opts, :allow_events) do
      nil -> fields
      names -> fields ++ [allowevents: SIP.Msg.Ops.allow_events(List.wrap(names))]
    end
  end

  @doc false
  @spec do_reject_subscription(%SIP.Context{}, 400..699, binary() | nil) :: %SIP.Context{}
  def do_reject_subscription(sip_ctx = %SIP.Context{}, code, reason) when is_integer(code) do
    reply(sip_ctx, stored_subscribe!(sip_ctx), code, reason, [], "reject_subscribe #{code}")
  end

  @doc false
  @spec do_notify(%SIP.Context{}, term()) :: %SIP.Context{}
  def do_notify(sip_ctx = %SIP.Context{}, doc) do
    case SIP.Context.appdata_get(sip_ctx, :subscription) do
      nil ->
        Logger.error("notify/1 called before a subscription was accepted; nothing sent")
        SIP.Context.set(sip_ctx, :lasterr, {:error, :no_subscription})

      %SIP.Subscription{} = sub ->
        if SIP.Subscription.status(sub) == :terminated do
          # The subscription is over — an un-SUBSCRIBE, or a lifetime that has
          # lapsed — and the only NOTIFY still owed is the final one, which is
          # the dialog's (design decision 4). A state sent here would reach the
          # watcher as `active;expires=0` one second before the termination it
          # contradicts, and every notifier script would have to know not to send
          # it.
          Logger.debug("notify/1 on a subscription that has ended; nothing sent")
          SIP.Context.set(sip_ctx, :lasterr, :ok)
        else
          send_notify(sip_ctx, sub, doc)
        end
    end
  end

  defp send_notify(sip_ctx, sub, doc) do
    case sub.package.serialize(sub.content_type, doc) do
      {:ok, body} ->
        rc = SIP.Dialog.send_notify(sip_ctx.dialogpid, body, sub.content_type)

        sip_ctx
        |> SIP.Context.appdata_set(:subscription, %{sub | version: sub.version + 1})
        |> SIP.Context.set(:lasterr, rc)

      {:error, reason} ->
        # The document the application handed us is not one this package can
        # write. Saying so beats sending a NOTIFY with an empty body, which a
        # watcher reads as "no state at all".
        Logger.error(
          "notify/1: #{inspect(sub.package)} cannot serialize this document as " <>
            "#{sub.content_type}: #{inspect(reason)}"
        )

        SIP.Context.set(sip_ctx, :lasterr, {:error, reason})
    end
  end

  @doc false
  @spec do_terminate_subscription(%SIP.Context{}, atom()) :: %SIP.Context{}
  def do_terminate_subscription(sip_ctx = %SIP.Context{}, reason) when is_atom(reason) do
    rc = SIP.Dialog.end_subscription(sip_ctx.dialogpid, reason)
    SIP.Context.set(sip_ctx, :lasterr, rc)
  end

  # ── Helpers ─────────────────────────────────────────────────────────────────

  # The SUBSCRIBE this instance is serving. `auto_store/2` puts every inbound one
  # there — the initial request AND every refresh — which is the whole reason a
  # script does not carry it from state to state by hand.
  defp stored_subscribe!(sip_ctx) do
    case SIP.Context.appdata_get(sip_ctx, :last_uas_req) ||
           SIP.Context.appdata_get(sip_ctx, :inbound_request) do
      %{method: :SUBSCRIBE} = req ->
        req

      other ->
        raise "No inbound SUBSCRIBE to answer (last stored request: #{inspect(other && other.method)})"
    end
  end

  # The resource being watched, as `active_watchers.presentity_uri` holds it: the
  # Request-URI with no parameter of the transaction that carried it.
  defp presentity_uri(req) do
    case Map.get(req, :ruri) do
      %SIP.Uri{} = uri ->
        case uri |> SIP.Uri.delete_param("unittest") |> SIP.Uri.serialize_ruri() do
          {:ok, str} -> str
          _ -> nil
        end

      other when is_binary(other) ->
        other

      _ ->
        nil
    end
  end

  defp reply(sip_ctx, req, code, reason, fields, label) do
    rc = SIP.Session.reply(sip_ctx.dialogpid, req, code, reason, fields, label)
    SIP.Context.set(sip_ctx, :lasterr, normalize(rc))
  end

  defp normalize(:ignore), do: :ok
  defp normalize(rc), do: rc
end

defmodule SIP.Session.SubscribeUAC do
  @moduledoc """
  The watcher half of RFC 6665: sending a SUBSCRIBE and living with what comes
  back.

      state subscribing do
        send_SUBSCRIBE("sip:bob@ives.fr", "presence", expires: 600)
        goto(wait_200)
      end

  ## What the framework does, and what is left to the script

  Three things are the framework's, and a watcher scenario writes none of them:

    * **the 200 to every inbound NOTIFY.** It goes out from the dialog, before the
      scenario is even handed the request. A NOTIFY answered late — or not at all,
      because the scenario was in a state with no clause for it — makes the
      notifier tear the subscription down.
    * **the refresh.** The dialog re-SUBSCRIBEs at half the granted lifetime, with
      the package, the `id` and the lifetime already negotiated. The response
      surfaces like any other, so a refresh challenged 401 is the scenario's to
      re-authenticate (`send_auth_SUBSCRIBE/4`) and a refresh answered 481 is the
      restart every design note warns will look like a regression. `app_drives_refresh: true`
      hands the schedule back: the dialog then delivers `:subscription_refresh`
      and sends nothing itself.
    * **exactly one `{:subscription_terminated, ref, reason}`**, with the RFC 6665
      §4.1.3 reason, whichever way the subscription ended.

  `deactivated` and `probation` mean *subscribe again*. They are surfaced like
  the other five in this phase rather than acted on under the scenario's feet:
  re-subscribing opens a NEW dialog (the old one is terminated by definition), and
  the only process that can open one is the scenario itself. The verb it needs is
  `send_SUBSCRIBE/3` — it recreates the dialog on its own, standalone method that
  SUBSCRIBE is.
  """

  require Logger

  @doc false
  defmacro __using__(_opts) do
    quote do
      use SIP.Context

      @doc """
      Send a SUBSCRIBE to `ruri` for `package`, creating the dialog.

      Options: `:expires` (what to ask for — the package's own default when
      absent), `:id` (the RFC 6665 `id` parameter), `:accept` (the content types
      to advertise — the package's `content_types/0` when absent).
      """
      defmacro send_SUBSCRIBE(ruri, package, opts \\ []) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "send_SUBSCRIBE")

          var!(sip_ctx) =
            SIP.Session.SubscribeUAC.client_subscribe(
              var!(sip_ctx),
              unquote(ruri),
              unquote(package),
              unquote(opts)
            )
        end
      end

      @doc "The same, answering the digest challenge carried by `resp_401`."
      defmacro send_auth_SUBSCRIBE(resp_401, ruri, package, opts \\ []) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "send_auth_SUBSCRIBE")

          var!(sip_ctx) =
            SIP.Session.SubscribeUAC.auth_subscribe(
              var!(sip_ctx),
              unquote(resp_401),
              unquote(ruri),
              unquote(package),
              unquote(opts)
            )
        end
      end

      @doc """
      Un-subscribe: the same SUBSCRIBE with `Expires: 0` (RFC 6665 §4.4.4).

      The notifier answers 200 and sends one last NOTIFY carrying
      `Subscription-State: terminated;reason=timeout`, which is what ends the
      subscription — so the scenario waits for its
      `{:subscription_terminated, …}` rather than assuming the 200 was the end.
      """
      defmacro send_unSUBSCRIBE() do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "send_unSUBSCRIBE")
          var!(sip_ctx) = SIP.Session.SubscribeUAC.unsubscribe(var!(sip_ctx))
        end
      end

      @doc """
      Process a reply to a SUBSCRIBE: on a 2xx, record the subscription and the
      lifetime the notifier granted, and let the dialog arm the refresh. Usually
      reached through `process_sip_reply/2`.
      """
      defmacro process_subscribe_reply(resp, transaction_id) do
        quote do
          var!(sip_ctx) =
            SIP.Session.SubscribeUAC.process_subscribe_reply(
              var!(sip_ctx),
              unquote(resp),
              unquote(transaction_id)
            )
        end
      end

      @doc "The subscription this watcher holds, or nil before the 2xx came back."
      defmacro current_subscription() do
        quote do
          SIP.Context.appdata_get(var!(sip_ctx), :subscription)
        end
      end

      @doc """
      The state a NOTIFY carries, read by the event package that carries it.

      Answers `{:ok, document}` — a `%SIP.Presence.Doc{}` for `presence`,
      whatever the package models for anything else — or `{:error, reason}`,
      `:no_body` being the final NOTIFY, which states a termination and carries
      nothing.

      A watcher that reads the body itself re-derives the content type, the
      package and the parsing in every scenario that displays a state
      ([CLAUDE.md](../../CLAUDE.md), *Writing a scenario*); this is the one
      reading, and it is the same one the notifier wrote with.
      """
      defmacro notified_document(notify) do
        quote do
          SIP.Session.SubscribeUAC.document_of(var!(sip_ctx), unquote(notify))
        end
      end
    end
  end

  # ── Building the request ────────────────────────────────────────────────────

  @doc false
  @spec subscribe_msg(%SIP.Context{}, binary() | SIP.Uri.t(), binary(), keyword()) :: map()
  def subscribe_msg(sip_ctx = %SIP.Context{}, ruri, package, opts) when is_list(opts) do
    package_name = String.downcase(package)
    expires = Keyword.get(opts, :expires) || default_expires(package_name)

    %{
      "Max-Forwards" => "70",
      method: :SUBSCRIBE,
      ruri: to_uri(ruri),
      from: SIP.Context.from(sip_ctx),
      to: to_uri(ruri) |> SIP.Uri.delete_param("unittest"),
      event: event_header(package_name, Keyword.get(opts, :id)),
      accept: accept_header(package_name, Keyword.get(opts, :accept)),
      expires: expires,
      useragent: Application.get_env(:elixip2, :useragent, "Elixipp/0.1"),
      callid: nil,
      contentlength: 0
    }
  end

  # The lifetime to ask for when the scenario names none: the package's, never a
  # number of the framework's own (RFC 6665 §4.4.1, and design decision 2 — the
  # default belongs to the package). An unknown package still yields a usable
  # request: the notifier is the one that answers 489, and it needs the SUBSCRIBE
  # to do it.
  defp default_expires(name) do
    case SIP.EventPackage.lookup(name) do
      {:ok, package} -> package.default_expires()
      :error -> 3600
    end
  end

  defp accept_header(_name, accept) when is_binary(accept), do: accept

  defp accept_header(_name, accept) when is_list(accept) and accept != [],
    do: Enum.join(accept, ", ")

  defp accept_header(name, _none) do
    case SIP.EventPackage.lookup(name) do
      {:ok, package} -> Enum.join(package.content_types(), ", ")
      # Say nothing rather than guess: an absent Accept means "the default type of
      # the package", which is exactly what we want when we cannot name it.
      :error -> nil
    end
  end

  defp event_header(name, nil), do: name
  defp event_header(name, id), do: name <> ";id=" <> to_string(id)

  defp to_uri(%SIP.Uri{} = uri), do: uri

  defp to_uri(str) when is_binary(str) do
    {:ok, uri} = SIP.Uri.parse(str)
    uri
  end

  # ── Sending ─────────────────────────────────────────────────────────────────

  @doc false
  @spec client_subscribe(%SIP.Context{}, binary() | SIP.Uri.t(), binary(), keyword()) ::
          %SIP.Context{}
  def client_subscribe(sip_ctx = %SIP.Context{}, ruri, package, opts \\ []) do
    req = subscribe_msg(sip_ctx, ruri, package, opts)

    sip_ctx
    |> SIP.Context.appdata_set(:subscribe_target, {ruri, package, opts})
    |> SIP.Session.send_sip_request(req, req.expires)
  end

  @doc false
  @spec auth_subscribe(%SIP.Context{}, map(), binary() | SIP.Uri.t(), binary(), keyword()) ::
          %SIP.Context{}
  def auth_subscribe(sip_ctx = %SIP.Context{}, rsp, ruri, package, opts \\ [])
      when is_map(rsp) and is_integer(rsp.response) do
    if rsp.response not in [401, 407] do
      raise "send_auth_SUBSCRIBE expects the 401/407 that challenged the SUBSCRIBE"
    end

    {header, kind} =
      if rsp.response == 401,
        do: {:wwwauthenticate, :wwwauthenticate},
        else: {:proxyauthenticate, :proxyauthenticate}

    case Map.get(rsp, header) do
      nil ->
        Logger.error("SUBSCRIBE challenged #{rsp.response} with no #{header} header")
        SIP.Context.set(sip_ctx, :lasterr, {:error, :no_challenge})

      authparams ->
        req =
          subscribe_msg(sip_ctx, ruri, package, opts)
          |> SIP.Msg.Ops.add_authorization_to_req(
            authparams,
            kind,
            sip_ctx.authusername,
            sip_ctx.ha1,
            :ha1
          )

        SIP.Session.send_sip_request(sip_ctx, req, req.expires)
    end
  end

  @doc false
  @spec unsubscribe(%SIP.Context{}) :: %SIP.Context{}
  def unsubscribe(sip_ctx = %SIP.Context{}) do
    case SIP.Context.appdata_get(sip_ctx, :subscribe_target) do
      {ruri, package, opts} ->
        client_subscribe(sip_ctx, ruri, package, Keyword.put(opts, :expires, 0))

      _ ->
        Logger.error("send_unSUBSCRIBE called before any SUBSCRIBE was sent")
        SIP.Context.set(sip_ctx, :lasterr, {:error, :no_subscription})
    end
  end

  # ── Reading a NOTIFY ────────────────────────────────────────────────────────

  @doc """
  The document a NOTIFY carries, parsed by the event package of the subscription
  it belongs to.

  The package comes from the subscription this watcher holds; a NOTIFY arriving
  before its own 200 (the race RFC 6665 §4.2.1.2 forbids and UDP produces anyway)
  has none yet, so the `Event` header of the NOTIFY itself is the fallback — it is
  mandatory there (§8.2.1), and the registry answers what it names.
  """
  @spec document_of(%SIP.Context{}, map()) :: {:ok, term()} | {:error, term()}
  def document_of(sip_ctx = %SIP.Context{}, notify) when is_map(notify) do
    with {:ok, package} <- package_for(sip_ctx, notify),
         body when is_binary(body) <- SIP.Msg.Ops.body_string(notify) do
      package.parse(content_type_of(notify, package), body)
    else
      {:error, reason} -> {:error, reason}
      # A NOTIFY with no body at all: the final one says why the subscription
      # ended in its Subscription-State, and there is no state left to carry.
      nil -> {:error, :no_body}
    end
  end

  defp package_for(sip_ctx, notify) do
    case SIP.Context.appdata_get(sip_ctx, :subscription) do
      %SIP.Subscription{package: package} when not is_nil(package) ->
        {:ok, package}

      _not_subscribed_yet ->
        case SIP.Msg.Ops.event_package(notify) do
          {name, _id} -> lookup_package(name)
          nil -> {:error, :no_event_package}
        end
    end
  end

  defp lookup_package(name) do
    case SIP.EventPackage.lookup(name) do
      {:ok, package} -> {:ok, package}
      :error -> {:error, {:unknown_event_package, name}}
    end
  end

  # An absent Content-Type means the package's default type (RFC 6665 §4.4.5),
  # the same reading the notifier applies to an absent Accept.
  defp content_type_of(notify, package) do
    SIP.Msg.Ops.body_content_type(notify) || List.first(package.content_types())
  end

  # ── Reading the answer ──────────────────────────────────────────────────────

  @doc """
  Process a reply to a SUBSCRIBE.

  On a 2xx the subscription is recorded with the lifetime the notifier **granted**
  — which may be shorter than the one asked for — and handed to the dialog, which
  arms the refresh and takes over the NOTIFYs. A 2xx granting 0 is the answer to an
  un-subscribe: nothing is armed, and the final NOTIFY that follows is what ends
  the subscription.

  Every other reply is left alone. A 423 carries the `Min-Expires` the notifier
  will accept and a 489 says it does not serve this package; both are the
  scenario's to react to, since only it knows whether asking again is worth it.
  """
  @spec process_subscribe_reply(%SIP.Context{}, map(), pid() | reference()) :: %SIP.Context{}
  def process_subscribe_reply(sip_ctx = %SIP.Context{}, resp, _transaction_id)
      when is_map(resp) and resp.response in 200..299 do
    {name, id} = requested_event(sip_ctx, resp)
    granted = SIP.Msg.Ops.expires_header(resp) || requested_expires(sip_ctx)

    sub =
      %SIP.Subscription{
        event: name,
        event_id: id,
        package: package_of(name),
        content_type: nil,
        presentity_uri: to_string(Map.get(resp, :to) || ""),
        ref: make_ref()
      }
      |> SIP.Subscription.put_status(if(granted > 0, do: :pending, else: :terminated))
      |> SIP.Subscription.grant(granted)

    case SIP.Dialog.set_subscription(sip_ctx.dialogpid, sub) do
      {:ok, sub} -> SIP.Context.appdata_set(sip_ctx, :subscription, sub)
      _ -> SIP.Context.appdata_set(sip_ctx, :subscription, sub)
    end
  end

  def process_subscribe_reply(sip_ctx = %SIP.Context{}, _resp, _transaction_id), do: sip_ctx

  # What we asked for, read back from what we sent rather than from the answer: a
  # 2xx to a SUBSCRIBE need not echo the Event header (RFC 6665 §8.2.1 asks for it
  # on the request), and a notifier that leaves it out would otherwise give us a
  # subscription with no package at all.
  defp requested_event(sip_ctx, resp) do
    case SIP.Msg.Ops.event_package(resp) do
      {name, id} ->
        {name, id}

      nil ->
        case SIP.Context.appdata_get(sip_ctx, :subscribe_target) do
          {_ruri, package, opts} -> {String.downcase(package), Keyword.get(opts, :id)}
          _ -> {nil, nil}
        end
    end
  end

  defp requested_expires(sip_ctx) do
    case SIP.Context.appdata_get(sip_ctx, :subscribe_target) do
      {_ruri, package, opts} ->
        Keyword.get(opts, :expires) || default_expires(String.downcase(package))

      _ ->
        3600
    end
  end

  defp package_of(nil), do: nil

  defp package_of(name) do
    case SIP.EventPackage.lookup(name) do
      {:ok, package} -> package
      :error -> nil
    end
  end
end
