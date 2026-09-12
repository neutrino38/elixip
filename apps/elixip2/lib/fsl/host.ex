defmodule FSL.Host do
  @moduledoc """
  What an **embedding** of FSL provides, and the only thing the language asks of
  one.

  FSL runs state machines. It knows states, transitions, `on_events` and its
  selective-receive semantics, `stay`, `goto back`, sub-FSMs and cooperative
  shutdown, service building blocks, the journal. It knows nothing about a
  dialog, a transaction, a media plane or a call — and the test of whether a seam
  is cut in the right place is not "does the SIP binding still work" (it will,
  whatever we do, because the code was shaped around it) but whether a **second**
  binding could be written without touching FSL. XMPP, Matrix and the frameworks
  behind chatbots are the candidates named for this; none of them has a dialog or
  a transaction, and two of them have no notion of a call at all.

  So everything FSL must not know is a callback here. A scenario names its host
  at `use` time, the module records it, and the runner reads it back through the
  generated `__fsl_host__/0` — no application env, no global configuration, so
  two hosts coexist in one VM. That is what makes the language testable with a
  trivial host of its own (`FSL.Host.Default`), and what a package needs.

  Every callback is optional: `FSL.Host.Default` answers each of them with the
  least the machine needs, so a state machine with no protocol at all runs with
  no host written.

  ## The callbacks, and what SIP puts in each

  | Callback | SIP's implementation |
  |---|---|
  | `c:bootstrap/0` | start the transaction layer, the transport selector, the dialog layer, the config registry and the node's auth secret |
  | `c:build_context/1` | turn the `config` block into a `%SIP.Context{}`: the native properties, `:passwd` -> `:ha1`, the global keys routed to the application env, the rest into appdata |
  | `c:account/2` | who a UAS instance serves: the identity the inbound request asserts, once, then silence so the script can speak |
  | `c:apply_run_opts/2` | the dialog an inbound request already created, and the request itself |
  | `c:spawn_child/2` | register a `:uas_invite` child with the call dispatcher, so the next inbound INVITE reaches it |
  | `c:finalize/1` | wind down the B2BUA legs, then the media, waiting first for the dialog to end |
  | `c:on_event/2` | which leg and transaction the event came from, what a dead leg owes, then stash the request |
  | `c:on_state_enter/1` | forget the matched event's leg and transaction |
  | `c:event_type/1` | `:ms_event` is media, anything else it is shown is SIP |
  | `c:injected_clauses/1` | the media server going away |
  | `c:clause_covers?/2` | whether the scenario already handles that itself |
  | `c:diagram_renderer/0` | not implemented: the PlantUML renderer FSL ships is the right one |

  That is the whole list.
  """

  @doc """
  Start whatever the binding's verbs need before any machine runs. Idempotent:
  it is called once per run, and several runs share one process tree.

  Returns `:ok`. A binding with nothing to start says so by not implementing it.
  """
  @callback bootstrap() :: :ok

  @doc """
  Build the initial context from the scenario's `config` block.

  The keyword list is the `config` of the scenario module, with any run-time
  overrides already merged on top. What a binding does with a key is entirely
  its business — a native property of its own context struct, a value routed
  somewhere else entirely, or `appdata`, which is where the default host puts
  everything.
  """
  @callback build_context(config :: keyword()) :: FSL.Context.t()

  @doc """
  The label a run is reported under — the monitor's `account` column.

  Called with the context and `:initial` for the first row of a run, then
  `:subsequent` for every one after it. The distinction is the binding's to make:
  SIP answers the identity the inbound request asserts for the first row of a UAS
  instance and then keeps quiet, so the script can name the AOR it registered or
  the conference it joined without every transition clobbering it.

  A host that has nothing to say about accounts leaves the column empty by not
  implementing this.
  """
  @callback account(ctx :: FSL.Context.t(), phase :: :initial | :subsequent) :: String.t()

  @doc """
  Prepare a child FSM that `spawn_fsm` has just started, given the kind its
  module declared and its pid.

  The kind is an **opaque term** as far as FSL is concerned — whatever the
  binding's own annotation wrote there. SIP writes `:uac`, `:uas_register`,
  `:uas_invite`, and a `:uas_invite` child is one that does nothing until an
  INVITE is routed to it, so the SIP host registers it with the call dispatcher.
  A language that knew those atoms would be a language that knows about server
  roles in a protocol.
  """
  @callback spawn_child(kind :: term(), pid :: pid()) :: :ok

  @doc """
  Release what the binding holds for this run, and return the context.

  One callback rather than one per resource, because the order between them is
  the binding's rule and has to stay in one place: SIP releases its B2BUA legs
  before its media, and waits (bounded) for the dialog to end first. Where this
  step sits among the others — after the children, before `cleanup/1` and before
  the parent is told — is the FSM's, and stays in the runner.
  """
  @callback finalize(ctx :: FSL.Context.t()) :: FSL.Context.t()

  @doc """
  Apply the `run_instance/2` options the FSM has no reading of.

  FSL owns `:parent_pid`, `:self_name`, `:appdata`, `:slot_id` and
  `:config_overrides`, and applies those itself; everything else names something
  only the binding understands and arrives here. SIP reads two: the dialog an
  inbound request already created (so the reply macros have a target) and the
  request itself, which is also what tells the host this is a server instance.

  A host with no options of its own returns the context untouched by not
  implementing this.
  """
  @callback apply_run_opts(ctx :: FSL.Context.t(), opts :: keyword()) :: FSL.Context.t()

  @doc """
  Act on an event the machine has just received, before the scenario's own
  clause runs.

  Called for **every** matched event, including the ones FSL injects itself, so a
  binding sees the whole stream. SIP does three things here, and their order is
  the reason this is one callback rather than three: it records which leg and
  which transaction the event came from (so a clause replying to it needs no
  direction argument), then answers what a leg that has just died owes — at once,
  so the caller hears about its callee going away now rather than at the teardown
  — and only then stashes an inbound request in the slot the reply macros serve.
  Written as one function, that order is readable; spread over three injected
  calls, it lived in the expansion of a macro.
  """
  @callback on_event(ctx :: FSL.Context.t(), event :: term()) :: FSL.Context.t()

  @doc """
  Forget whatever the last event left behind, because a state has just been
  entered.

  The mirror of `c:on_event/2`. FSL clears its own per-event bookkeeping either
  way; this is for the binding's. SIP forgets the leg and the transaction of the
  matched event, so an `after` body acts on the inbound leg rather than on
  whatever the previous state happened to match.
  """
  @callback on_state_enter(ctx :: FSL.Context.t()) :: FSL.Context.t()

  @doc """
  Categorize an event from the **first element of the pattern** that matches it,
  at macro-expansion time.

  FSL classifies what it owns: its own inter-FSM messages (`:parent_msg`,
  `:child_msg`, `:child_exit`) and the service-block namespaces a scenario has
  learned are `:scenario`, its control protocol (`:scenario_ctl`) is `:control`.
  Everything else is the binding's, and the binding's answer is not decoration:
  the type decides which lane an arrow is drawn from in the sequence diagram, so
  `:sip` means "from the peer", which is only meaningful when there is a peer.

  SIP answers `:media` for `:ms_event` and `:sip` for anything else it is shown —
  a method atom, a status code, a bound variable. That *fallback* is exactly why
  this is a host decision: an unrecognised leading atom drawing an arrow from a
  peer is a sentence about SIP, not about state machines.

  `element` is quoted AST, not a value: a bound variable in the pattern arrives
  as `{name, meta, context}`. Answer `nil` for anything with nothing to say.
  """
  @callback event_type(element :: Macro.t()) :: atom() | nil

  @doc """
  Clauses the binding wants prepended to **every** `on_events` wait, as
  `{name, quoted_clause}`.

  `ctx` is the context variable of the scenario being compiled, already quoted,
  so a clause can hand the context back: a binding writes
  `{:goto, :__shutdown__, "…", :media, unquote(ctx)}` and does not have to know
  what this particular scenario calls it.

  SIP injects one: a media server going away. `:server_disconnected` is delivered
  to every sink and acted upon by nothing, so a scenario without a clause for it
  would sit waiting for media that cannot come until its own `after` fires — if
  it has one. FSL injects its own cooperative-shutdown clause, and a service
  block's deadline, and neither is a host's business.

  Run at expansion time. Every injected clause must **leave the state** by
  construction, which is what lets them be instrumented without the `stay`
  rewrite and produce no dead branch.
  """
  @callback injected_clauses(ctx :: Macro.t()) :: [{atom(), Macro.t()}]

  @doc """
  Does a clause the scenario wrote itself already cover the injected clause
  called `name`? If so, the injection is dropped and the scenario keeps control.

  `pattern` is the quoted pattern of one of the scenario's own clauses, `when`
  guard stripped. Answered clause by clause, and SIP's answer is **deliberately
  generous**: a clause matching `{:ms_event, _, :server_disconnected}` obviously
  covers the media clause, but so does one matching every media event, and so
  does a catch-all. Erring that way leaves the scenario in charge, which is the
  safe direction — the default exists for scenarios that never considered the
  case, not to overrule those that did.

  Note that FSL's own shutdown clause is **not** governed by this, and the
  asymmetry is the point: only an explicit `:scenario_ctl` clause opts out of
  being stoppable. A scenario that merely writes `event -> …` has not thereby
  declined to be stopped, and one that could not be stopped would be a node that
  cannot drain.
  """
  @callback clause_covers?(name :: atom(), pattern :: Macro.t()) :: boolean()

  @doc """
  The module that turns this run's journal into a diagram.

  A binding may want its own; the default is the one FSL ships,
  `FSL.Diagram.PlantUML` (PlantUML), which after §4.8 needs no protocol
  vocabulary — its lane rule is by exclusion, so a type it has never heard of is
  still drawn as coming from the peer.

  The module must export `to_plantuml/2` and `filename/1`.
  """
  @callback diagram_renderer() :: module()

  @optional_callbacks bootstrap: 0,
                      diagram_renderer: 0,
                      apply_run_opts: 2,
                      build_context: 1,
                      account: 2,
                      spawn_child: 2,
                      finalize: 1,
                      on_event: 2,
                      on_state_enter: 1,
                      event_type: 1,
                      injected_clauses: 1,
                      clause_covers?: 2

  @doc """
  The host a scenario module declared, or `FSL.Host.Default` when it declared
  none.

  Read off the module rather than out of a configuration key, so two bindings
  can run side by side in one VM — which is what lets FSL's own suite run
  against a host that is not SIP's.
  """
  @spec of(module()) :: module()
  def of(module) do
    with true <- function_exported?(module, :__fsl_host__, 0),
         host when is_atom(host) and not is_nil(host) <- module.__fsl_host__() do
      host
    else
      _none -> FSL.Host.Default
    end
  end

  @doc """
  Call `fun` on a module's host, or answer `default` when it does not implement
  it.

  On the path of every transition — `c:account/2` is asked once per report — so
  `function_exported?/3` is tried first, on its own: it is a lookup in the
  already-loaded module. `Code.ensure_loaded?/1` is the fallback and not the
  first test, because a host is only *not* loaded once (a binding shipped in a
  kelixip `module_dir` is loaded on first use), and paying for the code server on
  every transition to cover that once is how a hook becomes a cost.
  """
  @spec call(module(), atom(), [term()], term()) :: term()
  def call(module, fun, args, default), do: hook(of(module), fun, args, default)

  @doc """
  Same, on a host that is already known — which is the case inside a macro, where
  the scenario's host was read off the module at expansion time.

  `Code.ensure_compiled/1` and not `ensure_loaded/1` in the fallback: some of
  these hooks are asked *while the compiler is running*, and a host being
  compiled in the same pass has to be waited for rather than declared absent.
  That is what `ensure_compiled/1` does, and it is the whole reason a
  compile-time hook can be trusted.
  """
  @spec hook(module(), atom(), [term()], term()) :: term()
  def hook(host, fun, args, default) do
    arity = length(args)

    cond do
      function_exported?(host, fun, arity) ->
        apply(host, fun, args)

      match?({:module, _}, Code.ensure_compiled(host)) and function_exported?(host, fun, arity) ->
        apply(host, fun, args)

      true ->
        default
    end
  end
end

defmodule FSL.Host.Default do
  @moduledoc """
  The host of a state machine that embeds no protocol: a plain `%FSL.Context{}`,
  nothing to start, no hooks.

  It is not a placeholder. It is what `use FSL.Machine` gets when it names no
  host, what FSL's own test suite runs against, and the worked example the
  documentation needs — so it is written once and used three times.
  """
  @behaviour FSL.Host

  @impl true
  def bootstrap, do: :ok

  @doc """
  Everything the `config` block carries goes into `appdata`.

  A machine with no protocol has no native properties to speak of, and guessing
  which keys deserve a field of their own is the binding's job, not the
  language's.
  """
  @impl true
  def build_context(config) do
    Enum.reduce(config, %FSL.Context{}, fn {key, value}, ctx ->
      FSL.Context.appdata_set(ctx, key, value)
    end)
  end
end
