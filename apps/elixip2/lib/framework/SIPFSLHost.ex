defmodule SIP.FSL.Host do
  @moduledoc """
  What SIP adds to the state machine.

  `FSL.Host` is the list of questions the language refuses to answer for itself;
  this module is SIP's answers, and the reason it exists is as much readability
  as decoupling. "What does SIP add to FSL?" used to be spread across three files
  and two macro expansions — three `use` lines at the top of `SIP.Scenario`,
  three calls injected into every `on_events` clause, one on state entry, a media
  clause, an inference table, and four more couplings inside the runner's
  `finalize/4`. Read here, top to bottom, it is one module.

  A scenario names this host by `use`-ing `SIP.Scenario`, which records it; the
  runner reads it back. Nothing is configured globally, so a SIP machine and a
  machine of some other binding run side by side in one VM.
  """
  @behaviour FSL.Host

  require Logger

  # is_req/1: only an inbound *request* names an identity (see initial_account/1)
  import SIP.Msg.Ops, only: [is_req: 1]

  # ── Bootstrap ───────────────────────────────────────────────────────────────

  @doc """
  Start the SIP layers: transactions, the transport selector, the dialog layer,
  the session config registry, and the node's auth secret.

  Idempotent — each layer treats an already-started layer as success — so it is
  safe to call once per run, or once for a hundred.
  """
  @impl true
  def bootstrap do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _config_pid} = SIP.Session.ConfigRegistry.start()
    # One server secret for the node's lifetime, keying every digest nonce
    # (SIP.Auth.Nonce). kelixip supervises it instead; here it belongs to the run.
    :ok = SIP.Auth.Secret.start()
    # The event packages this library provides, so a SUBSCRIBE for one of them is
    # not answered 489 by a run that never named a package (SIP.EventPackage).
    :ok = SIP.EventPackage.register_builtins()
    :ok
  end

  # ── The context ─────────────────────────────────────────────────────────────

  @doc """
  Build a `%SIP.Context{}` from the scenario's `config` block.

  Three destinations, and a key goes to exactly one of them:

    * a **native property** of the SIP context — `:username`, `:domain`,
      `:authusername`, `:displayname`, `:algorithm`, `:debug` — becomes a struct
      field;
    * a **global key** — `:proxyuri`, `:proxyusesrv`, `:optionkeepaliveperiod`,
      `:mediaserver` — is not per-session and goes to the `:elixip2` application
      env, where `SIP.Resolver`, `SIP.Session.Register` and the media selection
      read it. This is the single place that applies them, whether they come from
      the `config` block or from an external JSON header, so a scenario no longer
      has to `Application.put_env` by hand in its `initial_state`;
    * anything else goes to `appdata`, so a scenario can read it back.

  `:passwd` is applied last, because computing `:ha1` needs `:authusername`,
  `:domain` and `:algorithm` to be set first — which is why it cannot simply be a
  fourth clause in the fold.
  """
  @impl true
  def build_context(config) when is_list(config) do
    {passwd, rest} = Keyword.pop(config, :passwd)

    ctx =
      Enum.reduce(rest, %SIP.Context{}, fn {key, value}, acc -> put_config(acc, key, value) end)

    if is_nil(passwd), do: ctx, else: SIP.Context.set(ctx, :passwd, passwd)
  end

  @context_string_props [:username, :authusername, :displayname, :domain, :algorithm]

  @global_keys [:proxyuri, :proxyusesrv, :optionkeepaliveperiod, :mediaserver]

  defp put_config(ctx, key, value) when key in @global_keys do
    apply_global_key(key, value)
    ctx
  end

  defp put_config(ctx, :debug, value) when is_boolean(value), do: Map.put(ctx, :debug, value)

  defp put_config(ctx, key, value) when key in @context_string_props and is_binary(value),
    do: SIP.Context.set(ctx, key, value)

  # Unknown / non-native keys (e.g. :proxy) are stored in appdata.
  defp put_config(ctx, key, value), do: FSL.Context.appdata_set(ctx, key, value)

  # `:proxyuri` accepts either an already-parsed %SIP.Uri{} (from the JSON
  # loader) or a string "sip:host:port" (from a scenario `config` block), parsing
  # the latter so both paths converge.
  defp apply_global_key(:proxyuri, %SIP.Uri{} = uri),
    do: Application.put_env(:elixip2, :proxyuri, uri)

  defp apply_global_key(:proxyuri, value) when is_binary(value) do
    case SIP.Uri.parse(value) do
      {:ok, uri} -> Application.put_env(:elixip2, :proxyuri, uri)
      {err, _} -> raise "invalid proxyuri #{inspect(value)}: #{inspect(err)}"
    end
  end

  # :mediaserver selects the media adapter used by media_connect/0:
  # [module: :mockup | :mendooze | Module, url: "..."] (map accepted too).
  defp apply_global_key(:mediaserver, value) when is_list(value) or is_map(value),
    do: Application.put_env(:elixip2, :mediaserver, value)

  defp apply_global_key(:mediaserver, value),
    do: raise("invalid mediaserver config #{inspect(value)}: expected [module: ..., url: ...]")

  defp apply_global_key(key, value), do: Application.put_env(:elixip2, key, value)

  # ── Who a row is about ──────────────────────────────────────────────────────

  @doc """
  The account the monitor's row shows: the `:initial` report of a run, and every
  `:subsequent` one.

  It is the one piece of the reporting path that reads a protocol message, and
  the distinction it draws between the two phases is policy — which is why both
  are the host's and neither is the runner's.
  """
  @impl true
  def account(ctx, :initial), do: initial_account(ctx)
  def account(ctx, :subsequent), do: report_account(ctx)

  # What the monitor's `account` column shows until the scenario says better.
  #
  # A UAS instance serves whoever called it, so it shows the identity the inbound
  # request asserts — digest username, else P-Asserted-Identity, else From, the
  # framework's single reading of that question (SIP.Msg.Ops.asserted_username/1).
  # Its own `config` username, if it even has one, is the same string on every row
  # and answers nothing. A UAC keeps showing its own account, untouched.
  #
  # "Is this a UAS instance" is decided on the **inbound request**, not on the
  # `uas` annotation: that annotation is what tells `elixipp` to open listeners,
  # and a kelixip script does not carry it — the server knows a script serves
  # inbound traffic from `domains.toml`. A UAS instance is precisely one spawned
  # with the request that created it (`spawn_uas_instance/2` — the only paths that
  # pass `:inbound_request` are Kelix.InstancePool and Elixip.ScenarioUAS), and a
  # UAC instance has none by construction, so it never reaches the request branch.
  #
  # A script that knows a better name (the AOR it registered, the conference it
  # joined) overwrites it with `SIP.Scenario.Monitor.note_account/1` — see
  # report_account/1 for why the transitions that follow keep quiet about it.
  defp initial_account(ctx) do
    case inbound_request(ctx) do
      nil -> own_username(ctx)
      req -> SIP.Msg.Ops.asserted_username(req) || own_username(ctx)
    end
  end

  # What every report AFTER the first one says about the account.
  #
  # For a UAS instance: nothing. Its identity was resolved once, from the request
  # that spawned it, and from then on only the script speaks. An empty username is
  # how the monitor is told "keep what you have" — re-pushing the resolved identity
  # on every transition would clobber the AOR the registrar noted or the conference
  # DID an MCU call joined, which are the whole point of `note_account/1`.
  #
  # A UAC keeps reporting its own account, which a scenario may legitimately rebind
  # mid-run.
  defp report_account(ctx) do
    case inbound_request(ctx) do
      nil -> own_username(ctx)
      _uas_instance -> ""
    end
  end

  # The request that spawned this instance — set by `spawn_uas_instance/2` and by
  # nothing else, so its presence IS "this is a UAS instance". Deliberately not the
  # `uas` annotation: that one tells `elixipp` to open listeners, and the kelixip
  # scripts carry none — the server knows they serve inbound traffic from
  # `domains.toml`. Only a request names a sender, hence the `is_req` guard.
  defp inbound_request(ctx) do
    case FSL.Context.appdata_get(ctx, :inbound_request) do
      req when is_req(req) -> req
      _none -> nil
    end
  end

  defp own_username(ctx) do
    case ctx.username do
      username when is_binary(username) -> username
      _ -> ""
    end
  end

  # ── Spawning a child ────────────────────────────────────────────────────────

  @doc """
  Prepare a freshly spawned child FSM of the given kind.

  The kind is whatever `uas/1` wrote on the child's module — SIP's own
  vocabulary, which the language passes through without reading.
  """
  @impl true
  def spawn_child(type, pid), do: setup_uas_child(type, pid)

  # A `:uas_invite` child does not act on its own: it waits for an inbound
  # INVITE. Route the next one to it by registering it with the call
  # dispatcher, installed as the call processing module unless the app
  # already configured one (e.g. Elixip.ScenarioUAS in elixipp server mode
  # — never silently overridden).
  defp setup_uas_child(:uas_invite, pid) do
    {:ok, _} = SIP.Scenario.CallDispatcher.start()
    :ok = SIP.Scenario.CallDispatcher.register_waiting(pid)

    case SIP.Session.ConfigRegistry.get_call_processing_module() do
      nil ->
        SIP.Session.ConfigRegistry.set_call_processing_module(SIP.Scenario.CallDispatcher)

      SIP.Scenario.CallDispatcher ->
        :ok

      other ->
        Logger.warning(
          "spawn_fsm: call processing module #{inspect(other)} already configured; " <>
            "the :uas_invite child will not receive inbound INVITEs through the dispatcher"
        )
    end

    :ok
  end

  # A `:uas_register`, `:uas_presence` or `:uas_message` child is reached
  # through a factory registered as the processing module for its method
  # (`Elixip.ScenarioUAS`, the kelixip Router), not through a per-child
  # dispatcher like the call one above: there is nothing to register a waiting
  # pid with, so a sub-FSM of any of these kinds would wait for a request that
  # is routed elsewhere.
  defp setup_uas_child(type, _pid) when type in [:uas_register, :uas_presence, :uas_message] do
    Logger.warning("spawn_fsm: scenario type #{inspect(type)} is not supported as a sub-FSM yet")
  end

  defp setup_uas_child(_type, _pid), do: :ok

  # ── Teardown ────────────────────────────────────────────────────────────────

  @doc """
  Release what a SIP session holds, in the one order that is correct: the B2BUA
  legs, then the media.

  A leg left behind holds the call up at the far end, and it is the leg that
  carries the media the server is about to stop serving — releasing the media
  first would leave the far end with a live call and nothing on it, which is
  worse than a call that ends. The two are one rule, which is why they are one
  callback and not two.
  """
  @impl true
  def finalize(sip_ctx), do: sip_ctx |> release_b2bua_legs() |> release_media()

  # No-op for a scenario that created no leg (SIP.Session.B2bua.release_legs/1
  # returns the context untouched).
  defp release_b2bua_legs(sip_ctx), do: SIP.Session.B2bua.release_legs(sip_ctx)

  # If a media server is in use, wait (max 5 s) for the dialog to terminate
  # before releasing media resources, as specified in the README.
  defp release_media(sip_ctx) do
    if is_pid(sip_ctx.mediaserverpid) and not is_nil(sip_ctx.mediaservermodule) do
      receive do
        {:dialog_terminated, _dialog_pid, _reason} -> :ok
        # The same event from a tagged leg (a B2BUA outbound leg): it says just
        # as much about the call being over, and ignoring it would stall here
        # for the full timeout.
        {_tag, {:dialog_terminated, _dialog_pid, _reason}} -> :ok
      after
        5_000 -> :ok
      end

      SIP.Session.Media.media_cleanup_ressources(sip_ctx)
    else
      sip_ctx
    end
  end

  # ── Run options ─────────────────────────────────────────────────────────────

  @doc """
  The two `run_instance/2` options that mean something to SIP and nothing to the
  language.

  A UAS scenario does not create its dialog: the inbound request did, before the
  instance existed. So the registrar hands the instance that dialog pid — which
  is what the reply macros target — and, optionally, the request itself, which is
  also delivered as a `{:REGISTER, …}` message. Its presence is what makes this a
  server instance as far as `account/2` is concerned.
  """
  @impl true
  def apply_run_opts(sip_ctx, opts) do
    sip_ctx =
      case Keyword.get(opts, :dialog_pid) do
        nil -> sip_ctx
        pid -> SIP.Context.set(sip_ctx, :dialogpid, pid)
      end

    case Keyword.get(opts, :inbound_request) do
      nil -> sip_ctx
      req -> FSL.Context.appdata_set(sip_ctx, :inbound_request, req)
    end
  end

  # ── Every event ─────────────────────────────────────────────────────────────

  @doc """
  What SIP does with an event the machine has just received, before the
  scenario's own clause runs — and the order is the reason this is one function.

    1. **which leg, which transaction.** Recorded first, because it is what the
       `b2bua_*` verbs read to know where to act: a clause replying to the event
       it just matched is not asked for a direction.
    2. **what a leg that has just died owes.** A dialog dying is not news the
       scenario has to translate: whatever it decides next, the requests that leg
       was going to answer never will be, and someone is waiting for each of
       them. They are answered here, at once, on the leg they came from — so the
       caller hears about its callee going away now rather than at the teardown
       (`docs/design/DESIGN-SIPSTACK.md#57-resilience`, R6).
    3. **the inbound request, stashed last**, along with the dialog pid, in the
       slot `reply_invite*` and `last_uas_req/0` serve.

  Spread over three calls injected into every `on_events` clause, that order
  lived in the expansion of a macro. Here it can be read.
  """
  @impl true
  def on_event(sip_ctx, event) do
    SIP.Session.B2bua.note_event(event)

    sip_ctx
    |> SIP.Session.B2bua.note_leg_event(event)
    |> SIP.Session.CallUAS.auto_store(event)
  end

  @doc """
  Forget the leg and the transaction of the matched event, because a state has
  just been entered.

  An `after` body acts on the inbound leg, not on whatever the previous state
  happened to match.
  """
  @impl true
  def on_state_enter(sip_ctx) do
    SIP.Session.B2bua.forget_event()
    sip_ctx
  end

  # ── Categorizing an event ───────────────────────────────────────────────────

  @doc """
  `:media` for a media-server event, `:sip` for everything else — a method atom,
  a status code, or a bound variable standing for either.

  The fallback is the point, and it is why this is SIP's answer and not the
  language's: an unrecognised leading atom is read as coming *from the peer*, and
  drawn that way in the sequence diagram. That sentence only means something
  where there is a peer.

  `element` is quoted AST: `{name, meta, context}` is a bound variable in the
  scenario's pattern.
  """
  @impl true
  def event_type(:ms_event), do: :media
  def event_type(element) when is_atom(element), do: :sip
  def event_type(element) when is_integer(element), do: :sip

  def event_type({name, _meta, ctx_arg}) when is_atom(name) and is_atom(ctx_arg), do: :sip

  def event_type(_element), do: nil

  # ── The clause every wait carries ───────────────────────────────────────────

  @doc """
  One clause, prepended to every `on_events`: the media server going away.

  `:server_disconnected` is delivered to every sink and acted upon by nothing, so
  a scenario without a clause for it leaves the event in its mailbox and goes on
  waiting for media that cannot come, until its own `after` fires — if it has
  one. Six reference scenarios closed that by hand; the seventh was always going
  to forget (`docs/design/DESIGN-FRAMEWORK.md#67-the-media-server-as-a-failure-domain`, R8).

  The reaction is the cooperative shutdown a controller would have asked for, so
  `on_shutdown` runs if declared (`:aborted` otherwise), the legs and the media
  are released, and the caller is answered. R6's rule applied to the media plane:
  a dead resource ends the call it was serving, promptly, instead of being
  discovered at teardown.

  Idempotent by construction, because it leaves the state: a second
  `:server_disconnected` — the MCU case relays the fact AND passes it through —
  finds no `on_events` to match against.
  """
  @impl true
  def injected_clauses(ctx), do: [{:media_down, media_down_clause(ctx)}]

  defp media_down_clause(ctx) do
    [clause] =
      quote do
        {:ms_event, _ref, :server_disconnected} ->
          {:goto, :__shutdown__, "media server down", :media, unquote(ctx)}
      end

    clause
  end

  @doc """
  Would one of this scenario's own clauses catch a media server going away?

  **Deliberately generous.** A clause matching `{:ms_event, _, :server_disconnected}`
  obviously does, but so does one matching every media event
  (`{:ms_event, _, evt}` and then deciding), and so does a catch-all. Being
  generous errs toward leaving the scenario in charge, which is the safe
  direction — the default exists for scenarios that never considered the case,
  not to overrule those that did.
  """
  @impl true
  def clause_covers?(:media_down, pattern), do: pattern_handles_media_down?(pattern)
  def clause_covers?(_name, _pattern), do: false

  # `{:ms_event, ref, evt}` is a 3-tuple, i.e. `{:{}, _, elems}` in quoted form.
  defp pattern_handles_media_down?({:{}, _meta, [:ms_event, _ref, event]}),
    do: event == :server_disconnected or variable?(event)

  # A bare variable or `_`: a catch-all, which catches this too.
  defp pattern_handles_media_down?(pattern), do: variable?(pattern)

  defp variable?({name, _meta, ctx_arg}) when is_atom(name) and is_atom(ctx_arg), do: true
  defp variable?(_), do: false

  # ── The sequence journal ────────────────────────────────────────────────────

  @doc """
  The journal of this instance has just started: trace its SIP messages.

  The messages go through the dialog and transaction processes, never through
  this one, so `SIP.Scenario.SipTrace` records them there for whoever watches.
  Watching is this process declaring itself; its dialogs bind to it as they
  learn their application. Two things predate the journal and are caught up
  here: the dialogs already open — the one in the context (a UAS instance's, or
  a UAC's when `debug` was set mid-run) and a B2BUA's outbound legs, each with
  its leg tag — adopted; and the request a UAS instance was spawned for, which
  crossed its transaction before anybody traced, recorded directly.
  """
  @impl true
  def journal_started(sip_ctx) do
    :ok = SIP.Scenario.SipTrace.watch()
    # The monitor row says so, for kelictl and kelescope (`traced`).
    FSL.Monitor.note(:traced, true)

    if is_pid(Map.get(sip_ctx, :dialogpid)),
      do: SIP.Scenario.SipTrace.adopt(sip_ctx.dialogpid)

    for {tag, pid} <- SIP.Session.B2bua.leg_dialogs(sip_ctx),
        do: SIP.Scenario.SipTrace.adopt(pid, tag)

    with %{} = req <- inbound_request(sip_ctx),
         %{} = event <- SIP.Scenario.SipTrace.event(:in, req) do
      SIP.Scenario.SequenceJournal.record(event)
    end

    :ok
  end

  @doc "The SIP messages traced for this instance, handed to the journal and forgotten."
  @impl true
  def journal_collect, do: SIP.Scenario.SipTrace.take()

  @doc """
  Where a finished journal goes: to the `{module, function}` named by the
  `:elixip2, :sequence_output` application env, called with the events and the
  journal's metadata, **unrendered** — kelixip keeps them in memory for its
  operator (`Kelix.Traces`), and each reader draws them its own way. Without
  one, `:default`: FSL renders the diagram to a file in the working directory,
  as `elixipp --log-sequence` has always written.

  Either way the instance's journal is over, and its monitor row says so.
  """
  @impl true
  def journal_events(events, meta) do
    FSL.Monitor.note(:traced, false)

    case Application.get_env(:elixip2, :sequence_output) do
      {module, fun} -> apply(module, fun, [events, meta])
      nil -> :default
    end
  end

  # ── The monitor's columns ───────────────────────────────────────────────────

  @doc """
  The columns a SIP call adds to the live monitor's row, with the defaults that
  say what an empty one means.

  Declared here, once, and passed to the monitor by whoever starts it —
  `elixipp`'s `--monitor` bootstrap and `Kelix.Application`'s supervision tree.
  The registry itself never learns which keys are which; it merges these onto
  every new row and lets `note/2` write them (extraction plan §4.7).

  The defaults are values and not blanks on purpose: a call that negotiated no
  media, connects to no media server and dials nobody is the ordinary case — a
  registrar session — and `"n/a"` says so, where an empty cell would read as
  "nobody measured".
  """
  @spec monitor_columns() :: keyword()
  def monitor_columns,
    do: [medias: "n/a", mediaserver: "none", outbound: "n/a", traced: false]
end
