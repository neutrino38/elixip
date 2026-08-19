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

  defmacro __using__(opts) do
    # `use SIP.SBB` funnels here with kind: :sbb. A service building block is the
    # same language — same states, same on_events, same session mixins — read by
    # `sbb_loop/4` instead of `loop/4`, so it shares this whole expansion rather
    # than growing a parallel one. See docs/design/DESIGN-SBB.md.
    kind = Keyword.get(opts, :kind, :scenario)

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
          spawn_fsm: 1,
          spawn_fsm: 2,
          sub_fsm: 1,
          sub_fsm: 2,
          sbb_fsm: 1,
          sbb_fsm: 2,
          sbb_return: 1,
          sbb_cleanup: 1,
          sbb_data_get: 1,
          sbb_data_set: 2,
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
      # :scenario or :sbb — read at compile time by `on_events` (which injects the
      # deadline clause only into an SBB) and by `__before_compile__`.
      @scenario_kind unquote(kind)
      @before_compile SIP.Scenario
    end
  end

  defmacro __before_compile__(env) do
    states = env.module |> Module.get_attribute(:scenario_states) |> Enum.reverse()
    sbb? = Module.get_attribute(env.module, :scenario_kind) == :sbb

    common =
      quote do
        @doc false
        def __scenario_states__, do: unquote(states)

        @doc false
        def __scenario_config__, do: @scenario_config

        @doc false
        def __scenario_type__, do: @scenario_type
      end

    kind_specific =
      if sbb? do
        quote do
          @doc false
          def __sbb__, do: true

          @doc false
          # Completion deadline (ms) for one run of this block, overridable per
          # call site with `sbb_fsm(mod, timeout: …)`. 32 s is timer B — the
          # bound a silent callee leaves (design §6.3).
          def __sbb_timeout__, do: @sbb_timeout

          @doc false
          # The block's namespace: the first element of everything it returns.
          def __sbb_namespace__, do: @sbb_namespace

          @doc false
          # outcome -> description. `:timeout` is added when the block is bounded,
          # because the host can receive it whether or not the author listed it.
          def __sbb_returns__ do
            if @sbb_timeout == :infinity do
              @sbb_returns
            else
              Keyword.put_new(
                @sbb_returns,
                :timeout,
                "the block's own deadline expired before it concluded"
              )
            end
          end

          @doc false
          # What the block returns when that deadline expires, so the host has one
          # arm to write and no special case. Follows the return contract like any
          # other outcome, which is why it has a default rather than a convention.
          def __sbb_timeout_event__ do
            @sbb_timeout_event || {@sbb_namespace, :timeout, %{block: __MODULE__}}
          end

        end
      else
        # An SBB deliberately does NOT define run/1: `SIP.Scenario.Loader` picks the
        # first module in a compiled .exs exporting run/1 and __scenario_states__/0,
        # so an SBB declared above the scenario in the same file would otherwise be
        # loaded and run AS the scenario (design §6.1).
        quote do
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

    [common, kind_specific]
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

    # The 1.4 inter-FSM event shapes are gone from the wire (§4.6 of
    # docs/design/DESIGN-SBB.md: one name per concept across the two
    # FSL dialects). A message cannot carry a deprecated alias the way a macro
    # can, and a scenario still matching the old tuple would simply never be
    # woken — it would wait on its `after`, silently. So the mismatch is reported
    # here, where the pattern is still visible, instead of in production.
    Enum.each(do_clauses, &warn_deprecated_event(&1, __CALLER__))
    Enum.each(do_clauses, &check_no_sbb_call!(&1, __CALLER__))

    # What this module has learned about the blocks it calls (see
    # register_sbb_namespace/2): read once, here, because the clauses below are
    # rewritten by pure functions that have no caller to consult.
    namespaces = Module.get_attribute(__CALLER__.module, :sbb_namespaces) || []

    # A service building block carries a completion deadline (S7), armed by
    # `run_sbb/3` as a timer message. Only a clause can wake a blocked `receive`,
    # so every on_events of an SBB gets one — prepended, like the two below, so a
    # catch-all cannot swallow it first. Scenarios get none: they are nobody's
    # subroutine, and the message would be stale.
    sbb_clauses =
      if Module.get_attribute(__CALLER__.module, :scenario_kind) == :sbb,
        do: [sbb_deadline_clause()],
        else: []

    # Make every on_events cooperatively shutdown-aware: prepend a clause matching
    # the control message, unless the scenario already handles :scenario_ctl
    # itself. Prepending keeps it ahead of a possible catch-all `_ ->` clause.
    ctl_clauses =
      if Enum.any?(do_clauses, &ctl_clause?(&1, namespaces)), do: [], else: [shutdown_clause()]

    # …and media-server-death-aware, the same way and for the same reason
    # (design docs/design/DESIGN-FRAMEWORK.md#67-the-media-server-as-a-failure-domain, R8). `:server_disconnected` is
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
      Enum.map(
        sbb_clauses ++ media_clauses ++ ctl_clauses,
        &instrument_receive_clause(&1, nil, nil, namespaces)
      ) ++
        Enum.map(do_clauses, &instrument_receive_clause(&1, wait, deadline, namespaces))

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

  # The injected deadline clause of an SBB state. It throws rather than returning
  # a descriptor, because the block that armed the timer may be several frames up:
  # a nested block lets a parent's ref pass through, and `run_sbb/3` catches only
  # its own. `sip_ctx` travels with it so the host keeps what the block learned.
  defp sbb_deadline_clause do
    quote do
      {:sbb_deadline, sbb_deadline_ref} ->
        throw({:sbb_deadline_hit, sbb_deadline_ref, var!(sip_ctx)})
    end
    |> hd()
  end

  # `sbb_fsm` is only valid in a state body. An `on_events` deadline is absolute
  # (SIP.Scenario.deadline/1), so a block called from a clause would burn the
  # host's remaining timeout while it runs — a 30 s block under a 30 s host
  # deadline would return into an `after` that fires at once. From a state body
  # the suspension S7 asks for is free, because the deadline does not exist yet.
  defp check_no_sbb_call!({:->, meta, [_head, body]}, caller) do
    if calls_sbb_fsm?(body) do
      raise CompileError,
        file: caller.file,
        line: Keyword.get(meta, :line, caller.line),
        description:
          "sbb_fsm is only allowed in a state body, not in an on_events clause. " <>
            "Give the block its own state and call it there."
    end
  end

  defp check_no_sbb_call!(_clause, _caller), do: :ok

  defp calls_sbb_fsm?({:sbb_fsm, _meta, args}) when is_list(args), do: true
  defp calls_sbb_fsm?({fun, _meta, args}), do: calls_sbb_fsm?(fun) or calls_sbb_fsm?(args)
  defp calls_sbb_fsm?({left, right}), do: calls_sbb_fsm?(left) or calls_sbb_fsm?(right)
  defp calls_sbb_fsm?(list) when is_list(list), do: Enum.any?(list, &calls_sbb_fsm?/1)
  defp calls_sbb_fsm?(_other), do: false

  # Does this receive clause already match a {:scenario_ctl, ...} control message?
  defp ctl_clause?({:->, _meta, [head, _body]}, namespaces),
    do: clause_event_type(head, namespaces) == :control

  defp ctl_clause?(_clause, _namespaces), do: false

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

  Named after `fx.spawn` of the TypeScript FSL, which spawns a child machine on
  the same contract (`finite-state-language`, spec §8.1) — the two dialects keep
  one name per concept.

  `target` is either a compiled scenario module or a path to a `.exs` scenario
  file. Options:

    * `as:`   — **required** local name (atom) used to address the child and to
      tag the messages it sends back.
    * `args:` — optional map merged into the child context appdata.

  The child handle is stored in `sip_ctx.appdata[:__children__]`, so it survives
  across states; the macro rebinds `sip_ctx` like `ctx_set`.

      state initial_state do
        spawn_fsm UAS.AutoAnswer, as: :callee, args: %{play: "ring.wav"}
        goto calling
      end
  """
  defmacro spawn_fsm(target, opts \\ []) do
    spawn_fsm_ast(target, opts, __CALLER__.file)
  end

  @doc """
  Deprecated spelling of `spawn_fsm/2`, kept so scenarios written before 1.5.0
  keep loading. Same semantics, including the path resolution.
  """
  @deprecated "Use spawn_fsm/2 instead"
  defmacro sub_fsm(target, opts \\ []) do
    spawn_fsm_ast(target, opts, __CALLER__.file)
  end

  # A relative sub-scenario path is resolved against the directory of the file that
  # declares it — `include` semantics, like PHP's, not "relative to wherever the
  # tester happened to run from". `caller_file` is that file, known here at
  # expansion time; expanding it now pins the directory the same way `__DIR__` does.
  #
  # Resolving against the cwd is what broke uac_register_and_uas_invite.exs, whose
  # `spawn_fsm "scenarios/uas_invite.exs"` died with a bare "exception!" for anyone
  # not standing in apps/elixip2.
  defp spawn_fsm_ast(target, opts, caller_file) do
    base_dir = Path.expand(Path.dirname(caller_file))

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
  Enter a **service building block**: the current process runs `module`'s FSM
  until it hands control back, then execution continues on the next line of this
  state body. Not a spawn — no second process, no second set of legs. The block
  sees this scenario's context, dialogs and mailbox, because it *is* this
  process (design `docs/design/DESIGN-SBB.md`).

  Options:

    * `timeout:` — completion deadline in ms, overriding the block's own
      `@sbb_timeout`. On expiry the block returns its `@sbb_timeout_event`
      exactly as if it had returned it itself.
    * `args:`    — map seeding the block's private sandbox, read inside it with
      `sbb_data_get/1`.
    * `resume:`  — `true` keeps the sandbox from a previous run of the same
      block instead of clearing it. For a block designed to be re-entered after
      an interruption; the default is a clean slate, so a serial hunt calling a
      block target after target does not inherit the previous attempt.

  The block talks back through **events**, matched in the `on_events` that
  follows:

      state place_call do
        sbb_fsm SBB.Call, args: %{dest: dest}, timeout: 60_000

        on_events do
          {:call, :connected, uri} -> goto talking, "answered by \#{uri}"
          {:call, :rejected, code, _reason} -> goto failed, "callee said \#{code}"
        end
      end

  Only valid in a **state body**, never inside an `on_events` clause: that
  clause's deadline is absolute, so a block called from one would burn the
  host's remaining timeout while it runs. Give the block its own state.
  """
  defmacro sbb_fsm(module, opts \\ []) do
    register_sbb_namespace(module, __CALLER__)

    quote do
      var!(sip_ctx) =
        SIP.Scenario.Runner.run_sbb(var!(sip_ctx), unquote(module), unquote(opts))
    end
  end

  @doc false
  # Called by a face module's `__using__` so that `use SBB.Call` teaches the
  # scenario the namespaces of the blocks it is about to call, for the whole
  # module rather than from this state on.
  #
  # Read-modify-write on a plain attribute rather than `accumulate: true`,
  # deliberately: this list is written and read during macro EXPANSION, while a
  # `Module.register_attribute` call sitting in `__using__`'s quote is executed
  # later, when the module body is evaluated — and it would clear, at that point,
  # everything expansion had gathered. The list stays a list because nothing else
  # ever touches this attribute.
  def register_namespace(caller_module, namespace) when is_atom(namespace) do
    known = Module.get_attribute(caller_module, :sbb_namespaces) || []

    unless namespace in known do
      Module.put_attribute(caller_module, :sbb_namespaces, [namespace | known])
    end
  end

  # A block's return starts with the namespace its author chose, so no table in
  # the framework can list them: they are learned from the blocks this module
  # actually calls. `sbb_fsm` expands before the `on_events` that handles its
  # return — in the same state, or in a later one — so the namespace is known by
  # the time the clause is classified. When it is not (a computed module, a block
  # not compiled yet, a host handling the return in an EARLIER state), the clause
  # falls back to the old reading and nothing breaks but a colour.
  defp register_sbb_namespace(module_ast, caller) do
    with {:ok, module} <- expand_module(module_ast, caller),
         true <- Code.ensure_loaded?(module),
         true <- function_exported?(module, :__sbb_namespace__, 0) do
      register_namespace(caller.module, module.__sbb_namespace__())
    end

    :ok
  end

  defp expand_module({:__aliases__, _meta, _parts} = alias_ast, caller) do
    case Macro.expand(alias_ast, caller) do
      module when is_atom(module) -> {:ok, module}
      _other -> :error
    end
  end

  defp expand_module(module, _caller) when is_atom(module), do: {:ok, module}
  defp expand_module(_other, _caller), do: :error

  @doc """
  End this service building block, posting `event` to the process and handing
  control back to the state that called it. The host matches `event` in its own
  `on_events`, like any other event — and **behind** anything this block left
  unconsumed, since it goes to the back of the mailbox.

  This, not `scenario_success`, is how a block returns. The three terminals keep
  their ordinary meaning inside a block: they tear down the whole stack, host
  included.

  Every branch of an SBB ends on `sbb_return` or on a terminal; a branch that
  falls through leaves the host waiting for an event nobody will send.
  """
  defmacro sbb_return(event) do
    check_sbb_return!(event, __CALLER__)

    quote do
      {:sbb_return, unquote(event), var!(sip_ctx)}
    end
  end

  # The return contract (DESIGN-SBB.md#21-the-shape-of-a-return),
  # checked wherever a literal makes it checkable: a block returns
  # `{namespace, outcome, data}`, the namespace is its own, and the outcome is
  # one it declares in `@sbb_returns`.
  #
  # Worth a compile error rather than a runtime one because of how this fails
  # otherwise: a mistyped outcome is not a crash, it is a host sitting on its
  # `after` waiting for an event nobody will ever send — a thirty-second silence
  # with nothing in the log. A computed event is left alone; the check is on what
  # can be read.
  defp check_sbb_return!(event, caller) do
    if Module.get_attribute(caller.module, :scenario_kind) == :sbb do
      namespace = Module.get_attribute(caller.module, :sbb_namespace)
      check_sbb_return_shape!(event, namespace, declared_outcomes(caller.module), caller)
    end
  end

  # An empty list means the block declared no vocabulary, and outcomes go
  # unchecked: declaring is opt-in, enforcement follows the declaration.
  # `:timeout` belongs to a bounded block's vocabulary whether or not its author
  # listed it — `__sbb_returns__/0` folds it in the same way — so a block
  # returning it on a timeout of its own, as a ring timeout is, is not
  # undeclared.
  defp declared_outcomes(module) do
    case Module.get_attribute(module, :sbb_returns) || [] do
      [] ->
        []

      declared ->
        if Module.get_attribute(module, :sbb_timeout) == :infinity,
          do: Keyword.keys(declared),
          else: Keyword.keys(declared) ++ [:timeout]
    end
  end

  # A three-element tuple is `{:{}, meta, elements}` in AST; a two-element one is
  # a plain tuple. Everything else — a variable, a call, a case — is computed.
  defp check_sbb_return_shape!({:{}, meta, [ns, outcome, _data]}, namespace, declared, caller)
       when is_atom(ns) do
    if ns != namespace do
      sbb_return_error!(
        meta,
        caller,
        "sbb_return: this block's namespace is #{inspect(namespace)}, not #{inspect(ns)}. " <>
          "Every event a block returns starts with its own namespace, so a host can tell " <>
          "two blocks apart; set @sbb_namespace if #{inspect(ns)} is the intended one."
      )
    end

    if is_atom(outcome) and declared != [] and outcome not in declared do
      sbb_return_error!(
        meta,
        caller,
        "sbb_return: #{inspect(outcome)} is not one of this block's declared outcomes " <>
          "(#{Enum.map_join(declared, ", ", &inspect/1)}). Add it to @sbb_returns, with a " <>
          "line saying what it means and what its data map carries."
      )
    end
  end

  defp check_sbb_return_shape!({ns, outcome}, _namespace, _declared, caller) when is_atom(ns) do
    sbb_return_error!(
      [],
      caller,
      "sbb_return: a block returns {namespace, outcome, data} — three elements, the last a " <>
        "map. Write {#{inspect(ns)}, #{Macro.to_string(outcome)}, %{}}: a fixed shape is what " <>
        "lets a block report one more thing later without breaking the scenarios that match it."
    )
  end

  defp check_sbb_return_shape!(event, _namespace, _declared, caller) when is_atom(event) do
    sbb_return_error!(
      [],
      caller,
      "sbb_return: a block returns {namespace, outcome, data}, not a bare #{inspect(event)}."
    )
  end

  defp check_sbb_return_shape!(_event, _namespace, _declared, _caller), do: :ok

  defp sbb_return_error!(meta, caller, description) do
    raise CompileError,
      file: caller.file,
      line: Keyword.get(meta, :line, caller.line),
      description: description
  end

  @doc """
  Read a key from this block's private sandbox — `appdata` is shared with the
  host (that is the point), but a block's scratch space is its own, so it cannot
  collide with a host key of the same name.
  """
  defmacro sbb_data_get(key) do
    quote do
      SIP.Scenario.Runner.sbb_data_get(var!(sip_ctx), __MODULE__, unquote(key))
    end
  end

  @doc """
  Write a key into this block's private sandbox. Anything the block wants to
  *hand over* goes in the event it returns, or under a documented key of the
  shared `appdata` — not here.
  """
  defmacro sbb_data_set(key, value) do
    quote do
      var!(sip_ctx) =
        SIP.Scenario.Runner.sbb_data_set(var!(sip_ctx), __MODULE__, unquote(key), unquote(value))
    end
  end

  @doc """
  Send an application message to a named child sub-FSM. The child receives it as
  `{:parent_msg, payload}`. Unknown name → logged and ignored.
  """
  defmacro notify(child_name, payload) do
    quote do
      SIP.Scenario.Runner.notify_child(var!(sip_ctx), unquote(child_name), unquote(payload))
    end
  end

  @doc """
  Send an application message to the parent FSM. The parent receives it as
  `{:child_msg, <our name>, payload}` — the name the parent assigned with `as:`,
  so it matches a stable literal in every state. No-op when this scenario has no
  parent (so the same scenario also runs standalone).
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

  @doc """
  Declare what a **service building block** releases when it is left without
  returning — by a terminal, by a cooperative shutdown, or by an enclosing
  block's deadline.

  It does **not** run on `sbb_return/1`: an ordinary ending is a branch the
  block wrote itself, and whatever it had to release it released there. What
  this block covers is the other way out, the one no branch of the block chose:

      defmodule SBB.Announce do
        use SIP.SBB

        @sbb_namespace :announce
        @sbb_returns [played: "the file reached its end — %{}"]

        sbb_cleanup do
          # the host is going away and this block reserved a player
          media_stop_playback()
          sip_ctx
        end

        # ...
      end

  The body sees `sip_ctx` and must return a `%SIP.Context{}` — the one the
  unwinding carries on with, so a cleanup may annotate the context the terminal
  is about to finalize. Anything else is ignored and the context passes through
  unchanged, and an exception is logged rather than restarting the unwinding
  that is already in progress.

  Blocks unwind innermost first, so a nested block releases what it reserved
  before the block that called it does. This is the counterpart of `cleanup` in
  the TypeScript dialect (`finite-state-language`, spec §8.4).
  """
  defmacro sbb_cleanup(do: body) do
    quote do
      require Logger

      @doc false
      def __sbb_cleanup__(var!(sip_ctx)) do
        _ = var!(sip_ctx)
        unquote(body)
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
  defp instrument_receive_clause({:->, meta, [head, body]}, wait, deadline, namespaces) do
    # Compute the type from the ORIGINAL head, before the as-pattern rewrite.
    type = clause_event_type(head, namespaces)
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
        # (design docs/design/DESIGN-SIPSTACK.md#57-resilience, R6).
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

  # Compile-time check for the 1.4 spellings of the inter-FSM messages, renamed in
  # 1.5.0. `{:scenario_msg, :parent, p}` -> `{:parent_msg, p}` (one element
  # shorter: the sender was always `:parent`), `{:scenario_msg, name, p}` ->
  # `{:child_msg, name, p}`, `{:scenario_exit, …}` -> `{:child_exit, …}`.
  defp warn_deprecated_event({:->, meta, [head, _body]}, caller) do
    case head |> clause_pattern() |> pattern_first_element() do
      :scenario_msg ->
        deprecation_warning(
          "{:scenario_msg, …} is no longer sent. Match {:parent_msg, payload} for a " <>
            "message from the parent, {:child_msg, name, payload} for one from a child",
          meta,
          caller
        )

      :scenario_exit ->
        deprecation_warning(
          "{:scenario_exit, …} is no longer sent. Match " <>
            "{:child_exit, name, outcome, reason}",
          meta,
          caller
        )

      _ ->
        :ok
    end
  end

  defp warn_deprecated_event(_clause, _caller), do: :ok

  defp deprecation_warning(message, meta, caller) do
    IO.warn(message, file: caller.file, line: Keyword.get(meta, :line, caller.line))
  end

  defp clause_pattern([{:when, _meta, [pattern | _guards]}]), do: pattern
  defp clause_pattern([pattern]), do: pattern
  defp clause_pattern(_), do: nil

  defp pattern_first_element({:{}, _meta, [first | _rest]}), do: first
  defp pattern_first_element({first, _second}), do: first
  defp pattern_first_element(_), do: nil

  # The clause head is a one-element list holding the pattern, optionally wrapped
  # in a `when` guard.
  defp clause_event_type([{:when, _meta, [pattern | _guards]}], ns),
    do: pattern_event_type(pattern, ns)

  defp clause_event_type([pattern], ns), do: pattern_event_type(pattern, ns)
  defp clause_event_type(_, _ns), do: nil

  # Tuples with 0, 1 or 3+ elements are `{:{}, _, elems}`; 2-tuples are literal.
  #
  # A service building block returns `{namespace, outcome, data}`, and the
  # namespace is the block author's word — hence `namespaces`, learned from the
  # blocks this module calls rather than listed here. It matters beyond the
  # colour in the monitor: a `:sip` event is drawn in the sequence diagram as an
  # arrow FROM THE PEER, and a block's return came from nobody.
  defp pattern_event_type({:{}, _meta, [first, _outcome, _data]}, namespaces)
       when is_atom(first) do
    if first in namespaces, do: :scenario, else: first_element_type(first)
  end

  defp pattern_event_type({:{}, _meta, [first | _rest]}, _ns), do: first_element_type(first)
  defp pattern_event_type({first, _second}, _ns), do: first_element_type(first)
  defp pattern_event_type(_, _ns), do: nil

  # Media events are `{:ms_event, ...}`; inter-FSM messages are `{:parent_msg,
  # ...}` / `{:child_msg, ...}` / `{:child_exit, ...}`; control messages are
  # `{:scenario_ctl, ...}`; SIP requests/responses are tuples whose first element
  # is a method atom, a status code integer, or a bound variable.
  defp first_element_type(:ms_event), do: :media
  defp first_element_type(:parent_msg), do: :scenario
  defp first_element_type(:child_msg), do: :scenario
  defp first_element_type(:child_exit), do: :scenario
  # The 1.4 spellings. Nothing sends them any more; they are still typed here so
  # that a scenario matching one is classified — and warned about — rather than
  # read as a SIP method (see deprecated_event_tag/1).
  defp first_element_type(:scenario_msg), do: :scenario
  defp first_element_type(:scenario_exit), do: :scenario
  defp first_element_type(:scenario_ctl), do: :control
  defp first_element_type(first) when is_atom(first), do: :sip
  defp first_element_type(first) when is_integer(first), do: :sip
  defp first_element_type({name, _meta, ctx}) when is_atom(name) and is_atom(ctx), do: :sip
  defp first_element_type(_), do: nil
end
