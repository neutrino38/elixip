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

  More arrive as the remaining seams of the extraction are cut: `c:on_event/2`,
  `c:on_state_enter/1`, `c:event_type/1`, `c:injected_clauses/0`,
  `c:clause_covers?/2`, `c:diagram_renderer/0`.
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

  @optional_callbacks bootstrap: 0,
                      apply_run_opts: 2,
                      build_context: 1,
                      account: 2,
                      spawn_child: 2,
                      finalize: 1

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
  def call(module, fun, args, default) do
    host = of(module)
    arity = length(args)

    cond do
      function_exported?(host, fun, arity) -> apply(host, fun, args)
      Code.ensure_loaded?(host) and function_exported?(host, fun, arity) -> apply(host, fun, args)
      true -> default
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
