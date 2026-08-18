defmodule SIP.Scenario do
  @moduledoc """
  The Finite State Language (FSL): describes SIP / call scenarios as finite state
  machines, à la ExUnit.

  A scenario is a plain Elixir module saved as an `.exs` file that does
  `use SIP.Scenario`. This pulls in FSL together with
  `SIP.Session.CallUAC` and `SIP.Session.Media`, so the call and media helper
  macros are available inside the states.

      defmodule UAC.Invite do
        use SIP.Scenario

        config username: "toto", domain: "mydomain.com", passwd: "xxxx"

        state initial_state do
          media_connect(MediaServer.Mockup, "sip:localhost:8080")
          goto next
        end

        state calling do
          send_INVITE("sip:bob@mydomain.com", :mediaserver, timeout: 30, webrtc: :no)
          goto wait_answer
        end

        state wait_answer do
          receive do
            {200, rsp, trans, _dlg} ->
              process_invite_reply(rsp, trans)
              scenario_success("answered")
          after
            30_000 -> scenario_failure("no answer")
          end
        end
      end

  ## Entry points

    * `MyScenario.run(true)`  — start the SIP stack, then run one instance.
    * `MyScenario.run(false)` — run one instance, assuming the stack is up.
    * `SIP.Scenario.start_stack/0` — start the stack once, so several instances
      can later be spawned in parallel, each calling `run(false)`.

  ## How a state compiles

  Each `state name do ... end` becomes a function `__state_name/1` taking the
  implicit `sip_ctx`. Its body must end with a transition macro — `goto`,
  `scenario_success` or `scenario_failure` — which returns a transition
  descriptor consumed by `SIP.Scenario.Runner`. See that module for the loop.

  `goto next` moves to the next declared state, `goto loop` re-enters the
  current one, `goto back` returns to the state entered before this one, and
  `goto some_state` jumps to a named state. Before transitioning, `goto` checks
  `sip_ctx.lasterr`: any value other than `:ok` aborts the scenario as a failure.

  Inside an `on_events` clause, `stay` consumes the event and keeps waiting on
  the same `on_events` without re-running the state body.
  """

  @doc """
  Start the SIP stack (transactions, transport selector, dialog and config
  registry) once. Idempotent. Use it before spawning several scenario instances
  that each call `run(false)`.
  """
  @spec start_stack() :: :ok
  defdelegate start_stack(), to: SIP.Scenario.Runner, as: :bootstrap_stack

  defmacro __using__(_opts) do
    quote do
      use SIP.Session.CallUAC
      use SIP.Session.Media
      use SIP.Session.B2bua

      import SIP.Scenario,
        only: [
          config: 1,
          uas: 1,
          state: 2,
          on_events: 1,
          on_shutdown: 1,
          sub_fsm: 1,
          sub_fsm: 2,
          notify: 2,
          notify_parent: 1,
          goto: 1,
          goto: 2,
          goto: 3,
          stay: 0,
          stay: 1,
          stay: 2,
          scenario_success: 0,
          scenario_success: 1,
          scenario_failure: 0,
          scenario_failure: 1,
          scenario_aborted: 0,
          scenario_aborted: 1
        ]

      Module.register_attribute(__MODULE__, :scenario_states, accumulate: true)
      @scenario_config []
      # Default scenario kind. A server scenario overrides this with `uas :register`.
      # Read back through __scenario_type__/0.
      @scenario_type :uac
      @before_compile SIP.Scenario
    end
  end

  defmacro __before_compile__(env) do
    states = env.module |> Module.get_attribute(:scenario_states) |> Enum.reverse()

    quote do
      @doc false
      def __scenario_states__, do: unquote(states)

      @doc false
      def __scenario_config__, do: @scenario_config

      @doc false
      def __scenario_type__, do: @scenario_type

      @doc """
      Run one instance of this scenario. `start_stack?` is `true` to start the
      SIP stack first (one-shot mode) or `false` to reuse an already-started
      stack. Returns `:ok` on success or `{:error, reason}` on failure.
      """
      @spec run(boolean()) :: :ok | {:aborted, term()} | {:error, term()}
      def run(start_stack?) when is_boolean(start_stack?) do
        SIP.Scenario.Runner.run(__MODULE__, start_stack?)
      end
    end
  end

  @doc """
  Declare the SIP identity / parameters of the scenario. Builds the initial
  `%SIP.Context{}` (computing `:ha1` from `:passwd`). Keys that are not native
  context properties (e.g. `:proxy`) are kept in the context appdata.
  """
  defmacro config(opts) do
    quote do
      @scenario_config unquote(opts)
    end
  end

  @doc """
  Declare that this scenario is a server (UAS) scenario of a given kind, e.g.
  `uas :register`. This sets `__scenario_type__/0` to `:uas_<kind>` so the
  loader and `elixipp` can tell server scenarios apart from the default `:uac`
  client scenarios. The scenario itself implements the request handling (e.g.
  replying to a REGISTER), since that is application responsibility.
  """
  defmacro uas(kind) when is_atom(kind) do
    type = :"uas_#{kind}"

    quote do
      @scenario_type unquote(type)
    end
  end

  @doc """
  Declare a state of the finite state machine. The body must end with a
  transition macro (`goto` / `scenario_success` / `scenario_failure`).
  """
  defmacro state(name_ast, do: body) do
    name = state_atom(name_ast)
    fname = :"__state_#{name}"
    check_stay_placement!(body, "state #{name}")

    quote do
      require Logger
      @scenario_states unquote(name)
      def unquote(fname)(var!(sip_ctx)) do
        # Touch sip_ctx so a state whose body rebinds it before reading does not
        # trigger an "unused variable" warning.
        _ = var!(sip_ctx)
        # Clear the event type inferred by on_events, so a `goto` in this state
        # that is not inside a on_events clause stays untyped. Same for the
        # B2BUA leg/transaction of the matched event: an `after` clause acts on
        # the inbound leg, not on whatever the previous state matched.
        Process.delete(:scenario_event_type)
        SIP.Session.B2bua.forget_event()

        try do
          unquote(body)
        rescue
          e ->
            Logger.error("Exception in scenario state #{unquote(name)}")
            Logger.error(Exception.format(:error, e, __STACKTRACE__))
            scenario_failure("exception!")
        catch
          # An exit, not an exception — and until now nothing caught it, so it
          # killed the scenario process outright and `Runner.finalize/4` never
          # ran: no B2BUA leg was torn down, no media released, and the caller of
          # a relayed INVITE waited for a final response nobody would ever send
          # (design §14.4, R2).
          #
          # It reaches us through a `GenServer.call` — every SIP primitive here is
          # one — toward a dialog or transport that died between the check and the
          # call. R3 and R6 keep the ordinary cases from getting this far; this is
          # the net under them, so that whatever happens the scenario ENDS, which
          # is what runs the teardown that answers the caller.
          :exit, reason ->
            Logger.error("Exit in scenario state #{unquote(name)}: #{inspect(reason)}")

            scenario_failure("exit!")
        end
      end
    end
  end

  @doc """
  Transition to another state. `target` may be a state name, `next` (the next
  declared state), `loop` (re-enter the current state) or `back` (return to the
  state the FSM was in before entering this one). `desc` is an optional
  short description of the triggering event, used for logging and shown in the
  monitor. `type` optionally categorizes that event (`:sip`, `:media`, `:timer`,
  `:http`, `:db`, …) — recorded by the monitor to drive the future sequence
  diagram, mirroring the command typing of the `SIP.Session.*` macros.

  When `type` is omitted and the `goto` runs inside a `on_events` clause, the
  type is inferred from the matched event (`:media` for `{:ms_event, …}`, `:sip`
  for the other SIP tuples). An explicit `type` always wins.

      goto call_answered, "200 OK", :sip
      goto start_play, "media connected", :media

  `back` reads `sip_ctx.laststate`, a single slot the runner writes on every
  transition that actually changes state — `goto loop` and `stay` leave it
  alone. It is one slot, not a stack: two consecutive `goto back` toggle between
  two states. Using it with no previous state (from `initial_state`) aborts the
  scenario as a failure.

  Aborts the scenario as a failure if `sip_ctx.lasterr` is not `:ok`.
  """
  defmacro goto(target_ast, desc \\ nil, type \\ nil) do
    target = target_ast |> state_atom() |> pseudo_target()

    quote do
      if var!(sip_ctx).lasterr == :ok do
        # An explicit type wins; otherwise fall back to the type inferred by the
        # enclosing on_events clause (nil when not in one).
        event_type = unquote(type) || Process.get(:scenario_event_type)
        {:goto, unquote(target), unquote(desc), event_type, var!(sip_ctx)}
      else
        # lasterr aborts the scenario as a failure. Keep the same 5-tuple shape
        # (with the inferred event type) the runner expects for terminals.
        {:terminal, :failure, var!(sip_ctx).lasterr, Process.get(:scenario_event_type),
         var!(sip_ctx)}
      end
    end
  end

  @doc """
  Consume the matched event and keep waiting on the **same** `on_events`, without
  re-entering the state: the state body is not re-executed, so its side effects
  (sending a request, arming a timer, allocating media) are not replayed. This is
  what `goto loop` cannot do.

      state call_established do
        on_events do
          {:MESSAGE, req, trans, _dlg} ->
            reply_request(req, trans, 200, "OK")
            stay "in-dialog MESSAGE"

          {:BYE, _req, _trans, _dlg} ->
            goto hangup, "BYE"
        end
      end

  `desc` and `type` behave as in `goto/3`: the transition is logged as
  `(state) -> (state)` and reported to `SIP.Scenario.Monitor`, so a scenario whose
  whole activity is `stay` never looks frozen in the live view. Like `goto`, it
  aborts the scenario as a failure when `sip_ctx.lasterr` is not `:ok`.

  The enclosing `after` timeout is **not** re-armed: it is the deadline of the
  state, computed once when the `on_events` is entered, and a `stay` re-enters
  the wait with the time that is left. `stay` is only meaningful inside an
  `on_events` clause; anywhere else the scenario stops as a failure.
  """
  defmacro stay(desc \\ nil, type \\ nil) do
    quote do
      if var!(sip_ctx).lasterr == :ok do
        event_type = unquote(type) || Process.get(:scenario_event_type)
        {:stay, unquote(desc), event_type, var!(sip_ctx)}
      else
        {:terminal, :failure, var!(sip_ctx).lasterr, Process.get(:scenario_event_type),
         var!(sip_ctx)}
      end
    end
  end

  @doc """
  Like Elixir's `receive`, but each clause records the *type* of the matched
  event so the trailing `goto` is automatically categorized (no need to pass the
  type explicitly). The type is inferred from the clause pattern: `{:ms_event,
  …}` → `:media`, any other SIP tuple (`{100, …}`, `{:BYE, …}`, `{code, …}`) →
  `:sip`.

      on_events do
        {200, rsp, trans, _dlg} -> process_invite_reply(rsp, trans); goto answered, "200 OK"
        {:ms_event, _c, :ice_connected} -> goto play, "media connected"
      after
        30_000 -> scenario_failure("timeout")
      end

  A clause ending with `stay/2` re-enters this same wait instead of leaving the
  state. The `after` clause is therefore the deadline of the whole wait, not of
  one event: its expression is evaluated once, when the block is entered, and a
  `stay` comes back with the time that is left.
  """
  defmacro on_events(blocks) do
    do_clauses = Keyword.fetch!(blocks, :do)

    # Make every on_events cooperatively shutdown-aware: prepend a clause matching
    # the control message, unless the scenario already handles :scenario_ctl
    # itself. Prepending keeps it ahead of a possible catch-all `_ ->` clause.
    ctl_clauses = if Enum.any?(do_clauses, &ctl_clause?/1), do: [], else: [shutdown_clause()]

    # …and media-server-death-aware, the same way and for the same reason
    # (design docs/design/b2bua_module.md §14.6, R8). `:server_disconnected` is
    # delivered to every sink and acted upon by nothing: a scenario without a
    # clause for it leaves the event in its mailbox and goes on waiting for media
    # that will never come, until its own `after` fires — if it has one.
    #
    # Injected only when the scenario handles no media death itself, so a policy
    # that wants control keeps it — the rule `on_events` clauses already follow.
    media_clauses =
      if Enum.any?(do_clauses, &handles_media_down?/1), do: [], else: [media_down_clause()]

    # `stay` re-enters the wait, so the receive lives inside a closure that calls
    # itself. Hygienic unique vars: a state body may hold several on_events, and
    # nested ones must not capture each other's closure or deadline.
    wait = Macro.unique_var(:fsl_wait, __MODULE__)
    deadline = Macro.unique_var(:fsl_deadline, __MODULE__)

    # The injected clauses leave the state by construction, so they get no
    # stay-dispatch wrapper — one whose `{:stay, …}` branch the compiler would
    # rightly report as unreachable, once per scenario state.
    instrumented =
      Enum.map(media_clauses ++ ctl_clauses, &instrument_receive_clause(&1, nil, nil)) ++
        Enum.map(do_clauses, &instrument_receive_clause(&1, wait, deadline))

    {timeout_ast, new_blocks} =
      case Keyword.fetch(blocks, :after) do
        {:ok, [{:->, meta, [[timeout], after_body]}]} ->
          # The timeout is a deadline for the state, not for each event: it is
          # turned into an absolute one on entry and re-armed with what remains,
          # so a stream of consumed events cannot keep the wait alive forever.
          remaining = quote(do: SIP.Scenario.remaining_timeout(unquote(deadline)))
          {timeout, [do: instrumented, after: [{:->, meta, [[remaining], after_body]}]]}

        {:ok, after_clauses} ->
          {:infinity, [do: instrumented, after: after_clauses]}

        :error ->
          {:infinity, [do: instrumented]}
      end

    receive_ast = {:receive, [], [new_blocks]}

    quote do
      unquote(wait) = fn unquote(wait), var!(sip_ctx), unquote(deadline) ->
        _ = var!(sip_ctx)
        unquote(receive_ast)
      end

      unquote(wait).(
        unquote(wait),
        var!(sip_ctx),
        SIP.Scenario.deadline(unquote(timeout_ast))
      )
    end
  end

  @doc false
  # Absolute deadline for an `on_events` wait, so `stay` can re-enter it without
  # granting a fresh timeout.
  def deadline(:infinity), do: :infinity
  def deadline(ms) when is_integer(ms), do: System.monotonic_time(:millisecond) + ms

  @doc false
  def remaining_timeout(:infinity), do: :infinity

  def remaining_timeout(deadline),
    do: max(deadline - System.monotonic_time(:millisecond), 0)

  # Does this receive clause already match a {:scenario_ctl, ...} control message?
  defp ctl_clause?({:->, _meta, [head, _body]}), do: clause_event_type(head) == :control
  defp ctl_clause?(_), do: false

  # The auto-injected cooperative-shutdown clause: jump to the reserved
  # :__shutdown__ state, which the runner resolves to `on_shutdown` (if declared)
  # or to the default :aborted termination.
  defp shutdown_clause do
    [clause] =
      quote do
        {:scenario_ctl, :shutdown, _reason} ->
          {:goto, :__shutdown__, "shutdown", :control, var!(sip_ctx)}
      end

    clause
  end

  # Would any of this scenario's own clauses catch a media server going away?
  #
  # Deliberately generous: a clause matching `{:ms_event, _, :server_disconnected}`
  # obviously does, but so does one matching every media event
  # (`{:ms_event, _, evt}` and then deciding), and so does a catch-all. Being
  # generous errs toward leaving the scenario in charge, which is the safe
  # direction — the default exists for scenarios that never considered the case,
  # not to overrule those that did.
  defp handles_media_down?({:->, _meta, [head, _body]}), do: head_handles_media_down?(head)
  defp handles_media_down?(_), do: false

  defp head_handles_media_down?([{:when, _meta, [pattern | _guards]}]),
    do: pattern_handles_media_down?(pattern)

  defp head_handles_media_down?([pattern]), do: pattern_handles_media_down?(pattern)
  defp head_handles_media_down?(_), do: false

  # `{:ms_event, ref, evt}` is a 3-tuple, i.e. `{:{}, _, elems}` in quoted form.
  defp pattern_handles_media_down?({:{}, _meta, [:ms_event, _ref, event]}),
    do: event == :server_disconnected or variable?(event)

  # A bare variable or `_`: a catch-all, which catches this too.
  defp pattern_handles_media_down?(pattern), do: variable?(pattern)

  defp variable?({name, _meta, ctx}) when is_atom(name) and is_atom(ctx), do: true
  defp variable?(_), do: false

  # The default reaction: the cooperative shutdown a controller would ask for, so
  # `on_shutdown` runs if declared (and `:aborted` otherwise), `finalize` releases
  # the legs and the media, and the caller is answered. R6's rule applied to the
  # media plane — a dead resource ends the call it was serving, promptly, instead
  # of being discovered at teardown.
  #
  # Idempotent by construction: it leaves the state, so a second
  # `:server_disconnected` (the MCU case relays the fact AND passes it through)
  # finds no `on_events` to match against.
  defp media_down_clause do
    [clause] =
      quote do
        {:ms_event, _ref, :server_disconnected} ->
          {:goto, :__shutdown__, "media server down", :media, var!(sip_ctx)}
      end

    clause
  end

  @doc "Terminate the scenario successfully, transitioning to the success state."
  defmacro scenario_success(reason \\ "", type \\ nil) do
    quote do
      event_type = unquote(type) || Process.get(:scenario_event_type)
      {:terminal, :success, unquote(reason), event_type, var!(sip_ctx)}
    end
  end

  @spec scenario_failure() :: {:__block__, [], [{:=, [...], [...]} | {:{}, [...], [...]}, ...]}
  @doc "Terminate the scenario as a failure, storing `reason` in the context."
  defmacro scenario_failure(reason \\ "", type \\ nil) do
    quote do
      event_type = unquote(type) || Process.get(:scenario_event_type)
      var!(sip_ctx) = SIP.Context.set(var!(sip_ctx), :errorreason, to_string(unquote(reason)))
      {:terminal, :failure, unquote(reason), event_type, var!(sip_ctx)}
    end
  end

  @doc """
  Terminate the scenario as *aborted* — a controller-driven wind-down (e.g. a
  cooperative shutdown), distinct from a failure so it is not counted as one.
  Typically used as the last statement of an `on_shutdown` block.
  """
  defmacro scenario_aborted(reason \\ "", type \\ nil) do
    quote do
      event_type = unquote(type) || Process.get(:scenario_event_type)
      {:terminal, :aborted, unquote(reason), event_type, var!(sip_ctx)}
    end
  end

  @doc """
  Spawn another scenario as a *sub finite-state machine* (a separate process,
  required because each FSM owns its own SIP/media mailbox). Hands the child our
  PID and a local name so the two can exchange messages with `notify/2` /
  `notify_parent/1`.

  `target` is either a compiled scenario module or a path to a `.exs` scenario
  file. Options:

    * `as:`   — **required** local name (atom) used to address the child and to
      tag the messages it sends back.
    * `args:` — optional map merged into the child context appdata.

  The child handle is stored in `sip_ctx.appdata[:__children__]`, so it survives
  across states; the macro rebinds `sip_ctx` like `ctx_set`.

      state initial_state do
        sub_fsm UAS.AutoAnswer, as: :callee, args: %{play: "ring.wav"}
        goto calling
      end
  """
  defmacro sub_fsm(target, opts \\ []) do
    # A relative sub-scenario path is resolved against the directory of the file that
    # declares it — `include` semantics, like PHP's, not "relative to wherever the
    # tester happened to run from". `__CALLER__.file` is that file, known here at
    # expansion time; expanding it now pins the directory the same way `__DIR__` does.
    #
    # Resolving against the cwd is what broke uac_register_and_uas_invite.exs, whose
    # `sub_fsm "scenarios/uas_invite.exs"` died with a bare "exception!" for anyone
    # not standing in apps/elixip2.
    base_dir = Path.expand(Path.dirname(__CALLER__.file))

    quote do
      var!(sip_ctx) =
        SIP.Scenario.Runner.spawn_child(
          var!(sip_ctx),
          unquote(target),
          unquote(opts),
          self(),
          unquote(base_dir)
        )
    end
  end

  @doc """
  Send an application message to a named child sub-FSM. The child receives it as
  `{:scenario_msg, :parent, payload}`. Unknown name → logged and ignored.
  """
  defmacro notify(child_name, payload) do
    quote do
      SIP.Scenario.Runner.notify_child(var!(sip_ctx), unquote(child_name), unquote(payload))
    end
  end

  @doc """
  Send an application message to the parent FSM. The parent receives it as
  `{:scenario_msg, <our name>, payload}`. No-op when this scenario has no parent
  (so the same scenario also runs standalone).
  """
  defmacro notify_parent(payload) do
    quote do
      SIP.Scenario.Runner.notify_parent(var!(sip_ctx), unquote(payload))
    end
  end

  @doc """
  Declare an optional handler run when a cooperative shutdown is requested
  (`{:scenario_ctl, :shutdown, _}` received inside an `on_events`). Compiles to
  the reserved `:__shutdown__` state; its body must end with a transition macro
  (`scenario_aborted/1` recommended). When omitted, the runner terminates the
  scenario with the `:aborted` outcome by default.

      on_shutdown do
        # release app resources, send a BYE, ...
        scenario_aborted("controller asked to stop")
      end
  """
  defmacro on_shutdown(do: body) do
    check_stay_placement!(body, "on_shutdown block")

    quote do
      require Logger

      def __state___shutdown__(var!(sip_ctx)) do
        _ = var!(sip_ctx)
        Process.delete(:scenario_event_type)

        try do
          unquote(body)
        rescue
          e ->
            Logger.error("Exception in scenario on_shutdown handler")
            Logger.error(Exception.format(:error, e, __STACKTRACE__))
            scenario_failure("exception!")
        end
      end
    end
  end

  # Extract a state name (atom) from the macro argument, which is either a bare
  # identifier (`initial_state`, `next`, `loop`) parsed as a variable AST node,
  # or a literal atom.
  defp state_atom({name, _meta, context}) when is_atom(name) and is_atom(context), do: name
  defp state_atom(name) when is_atom(name), do: name

  # `back` is a pseudo-target like `next` and `loop`, resolved by the runner from
  # `sip_ctx.laststate`. Renamed so it cannot collide with a state actually named
  # `back` — `next` and `loop` reserve their name the same way.
  defp pseudo_target(:back), do: :__back__
  defp pseudo_target(other), do: other

  # ── on_events event-type inference (compile time) ─────────────────────────

  # Instrument a receive clause with two compile-time additions:
  #   1. store the inferred event type in the process dict, so the trailing
  #      `goto` picks it up (event-type inference);
  #   2. auto-store the matched event: bind it to a hygienic variable via an
  #      as-pattern (`pattern = evt`) and prepend a call to
  #      `SIP.Session.CallUAS.auto_store/2`, which stashes an inbound
  #      INVITE/UPDATE (and its transaction pid) in the context so `reply_invite*`
  #      can reply without re-passing the request. auto_store is a fully-qualified
  #      runtime call (not an import): it works in every scenario — including a
  #      UAC receiving a re-INVITE — and is a no-op for non-offer events.
  #   3. wrap the clause result: a `{:stay, …}` descriptor re-enters the wait
  #      closure with the context the clause produced, so appdata mutations
  #      survive; anything else is a transition and propagates to the runner.
  defp instrument_receive_clause({:->, meta, [head, body]}, wait, deadline) do
    # Compute the type from the ORIGINAL head, before the as-pattern rewrite.
    type = clause_event_type(head)
    evt = Macro.unique_var(:evt, __MODULE__)

    new_body =
      quote do
        Process.put(:scenario_event_type, unquote(type))
        # Which B2BUA leg this event came from and which transaction it carries,
        # so the b2bua_* macros need no direction argument. Runtime, not
        # compile-time: a catch-all clause ({tag, evt}) has no literal tag to
        # read off the pattern.
        SIP.Session.B2bua.note_event(unquote(evt))
        # A leg that has just died owes answers it will never send. They are
        # given here, before the scenario's clause runs, so the caller is
        # answered the moment its callee goes rather than at the teardown
        # (design docs/design/b2bua_module.md §14.4, R6).
        var!(sip_ctx) = SIP.Session.B2bua.note_leg_event(var!(sip_ctx), unquote(evt))
        var!(sip_ctx) = SIP.Session.CallUAS.auto_store(var!(sip_ctx), unquote(evt))
        unquote(rewrite_stay(body, wait, deadline))
      end

    {:->, meta, [bind_event_var(head, evt), new_body]}
  end

  # Turn every `stay` written in this clause into a call back into the wait
  # closure. Done on the AST rather than on the clause *result* (a `case` telling
  # a `{:stay, …}` descriptor from a `{:goto, …}` one): the compiler knows the
  # exact type each clause returns, so in the — normal — case where no clause
  # stays, that `case` carries a branch it can prove dead, and it says so once per
  # state of every scenario.
  #
  # Recursion stops at a nested `on_events` / `receive`: a `stay` in there belongs
  # to that wait, not to this one. The `after` body is never walked, for the same
  # reason in reverse — the deadline has expired, there is nothing to go back to.

  # No closure to go back to (auto-injected clause): the body IS the transition.
  defp rewrite_stay(body, nil, nil), do: body

  defp rewrite_stay({:on_events, _meta, _args} = node, _wait, _deadline), do: node
  defp rewrite_stay({:receive, _meta, _args} = node, _wait, _deadline), do: node

  defp rewrite_stay({:stay, _meta, args}, wait, deadline) when is_list(args),
    do: stay_ast(args, wait, deadline)

  # `stay` alone on a line parses as a variable, not as a zero-arity call.
  defp rewrite_stay({:stay, _meta, ctx}, wait, deadline) when is_atom(ctx),
    do: stay_ast([], wait, deadline)

  defp rewrite_stay({fun, meta, args}, wait, deadline),
    do: {rewrite_stay(fun, wait, deadline), meta, rewrite_stay(args, wait, deadline)}

  defp rewrite_stay({left, right}, wait, deadline),
    do: {rewrite_stay(left, wait, deadline), rewrite_stay(right, wait, deadline)}

  defp rewrite_stay(list, wait, deadline) when is_list(list),
    do: Enum.map(list, &rewrite_stay(&1, wait, deadline))

  defp rewrite_stay(other, _wait, _deadline), do: other

  # `stay` re-enters an `on_events` wait, so outside one there is nothing to
  # re-enter. Refuse it at compile time, where the scenario writer can still see
  # which state is at fault — the runner would otherwise only fail the run.
  # Everything an `on_events` owns is pruned, its `after` body included: it is
  # that macro's business, and a `stay` left there fails at runtime.
  defp check_stay_placement!(body, where) do
    if stay?(body) do
      raise CompileError,
        description:
          "stay is only allowed in an on_events clause, and #{where} uses it outside one. " <>
            "Use goto loop to re-enter the state."
    end
  end

  defp stay?({:on_events, _meta, _args}), do: false
  defp stay?({:stay, _meta, args}) when is_list(args), do: true
  defp stay?({:stay, _meta, ctx}) when is_atom(ctx), do: true
  defp stay?({fun, _meta, args}), do: stay?(fun) or stay?(args)
  defp stay?({left, right}), do: stay?(left) or stay?(right)
  defp stay?(list) when is_list(list), do: Enum.any?(list, &stay?/1)
  defp stay?(_other), do: false

  defp stay_ast(args, wait, deadline) do
    desc = Enum.at(args, 0)
    type = Enum.at(args, 1)

    quote do
      if var!(sip_ctx).lasterr == :ok do
        unquote(wait).(
          unquote(wait),
          SIP.Scenario.Runner.note_stay(
            __MODULE__,
            var!(sip_ctx),
            unquote(desc),
            unquote(type) || Process.get(:scenario_event_type)
          ),
          unquote(deadline)
        )
      else
        {:terminal, :failure, var!(sip_ctx).lasterr, Process.get(:scenario_event_type),
         var!(sip_ctx)}
      end
    end
  end

  # Wrap the clause pattern in an as-pattern binding it to `evt`, keeping any
  # `when` guard (which may reference variables bound by the pattern). Leaves
  # anything unexpected untouched.
  defp bind_event_var([{:when, m, [pattern | guards]}], evt),
    do: [{:when, m, [{:=, [], [pattern, evt]} | guards]}]

  defp bind_event_var([pattern], evt), do: [{:=, [], [pattern, evt]}]
  defp bind_event_var(other, _evt), do: other

  # The clause head is a one-element list holding the pattern, optionally wrapped
  # in a `when` guard.
  defp clause_event_type([{:when, _meta, [pattern | _guards]}]), do: pattern_event_type(pattern)
  defp clause_event_type([pattern]), do: pattern_event_type(pattern)
  defp clause_event_type(_), do: nil

  # Tuples with 0, 1 or 3+ elements are `{:{}, _, elems}`; 2-tuples are literal.
  defp pattern_event_type({:{}, _meta, [first | _rest]}), do: first_element_type(first)
  defp pattern_event_type({first, _second}), do: first_element_type(first)
  defp pattern_event_type(_), do: nil

  # Media events are `{:ms_event, ...}`; inter-FSM messages are `{:scenario_msg,
  # ...}` / `{:scenario_exit, ...}`; control messages are `{:scenario_ctl, ...}`;
  # SIP requests/responses are tuples whose first element is a method atom, a
  # status code integer, or a bound variable.
  defp first_element_type(:ms_event), do: :media
  defp first_element_type(:scenario_msg), do: :scenario
  defp first_element_type(:scenario_exit), do: :scenario
  defp first_element_type(:scenario_ctl), do: :control
  defp first_element_type(first) when is_atom(first), do: :sip
  defp first_element_type(first) when is_integer(first), do: :sip
  defp first_element_type({name, _meta, ctx}) when is_atom(name) and is_atom(ctx), do: :sip
  defp first_element_type(_), do: nil
end
