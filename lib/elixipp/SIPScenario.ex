defmodule SIP.Scenario do
  @moduledoc """
  DSL to describe SIP / call scenarios as finite state machines, à la ExUnit.

  A scenario is a plain Elixir module saved as an `.exs` file that does
  `use SIP.Scenario`. This pulls in the state-machine DSL together with
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
  current one, and `goto some_state` jumps to a named state. Before
  transitioning, `goto` checks `sip_ctx.lasterr`: any value other than `:ok`
  aborts the scenario as a failure.
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

      import SIP.Scenario,
        only: [
          config: 1,
          state: 2,
          on_events: 1,
          goto: 1,
          goto: 2,
          goto: 3,
          scenario_success: 0,
          scenario_success: 1,
          scenario_failure: 0,
          scenario_failure: 1
        ]

      Module.register_attribute(__MODULE__, :scenario_states, accumulate: true)
      @scenario_config []
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

      @doc """
      Run one instance of this scenario. `start_stack?` is `true` to start the
      SIP stack first (one-shot mode) or `false` to reuse an already-started
      stack. Returns `:ok` on success or `{:error, reason}` on failure.
      """
      @spec run(boolean()) :: :ok | {:error, term()}
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
  Declare a state of the finite state machine. The body must end with a
  transition macro (`goto` / `scenario_success` / `scenario_failure`).
  """
  defmacro state(name_ast, do: body) do
    name = state_atom(name_ast)
    fname = :"__state_#{name}"

    quote do
      require Logger
      @scenario_states unquote(name)
      def unquote(fname)(var!(sip_ctx)) do
        # Touch sip_ctx so a state whose body rebinds it before reading does not
        # trigger an "unused variable" warning.
        _ = var!(sip_ctx)
        # Clear the event type inferred by on_events, so a `goto` in this state
        # that is not inside a on_events clause stays untyped.
        Process.delete(:scenario_event_type)
        try do
          unquote(body)
        rescue
          e ->
            Logger.error("Exception in scenario state #{unquote(name)}")
            Logger.error(Exception.format(:error, e, __STACKTRACE__))
            scenario_failure("exception!")
        end
      end
    end
  end

  @doc """
  Transition to another state. `target` may be a state name, `next` (the next
  declared state) or `loop` (re-enter the current state). `desc` is an optional
  short description of the triggering event, used for logging and shown in the
  monitor. `type` optionally categorizes that event (`:sip`, `:media`, `:timer`,
  `:http`, `:db`, …) — recorded by the monitor to drive the future sequence
  diagram, mirroring the command typing of the `SIP.Session.*` macros.

  When `type` is omitted and the `goto` runs inside a `on_events` clause, the
  type is inferred from the matched event (`:media` for `{:ms_event, …}`, `:sip`
  for the other SIP tuples). An explicit `type` always wins.

      goto call_answered, "200 OK", :sip
      goto start_play, "media connected", :media

  Aborts the scenario as a failure if `sip_ctx.lasterr` is not `:ok`.
  """
  defmacro goto(target_ast, desc \\ nil, type \\ nil) do
    target = state_atom(target_ast)

    quote do
      if var!(sip_ctx).lasterr == :ok do
        # An explicit type wins; otherwise fall back to the type inferred by the
        # enclosing on_events clause (nil when not in one).
        event_type = unquote(type) || Process.get(:scenario_event_type)
        {:goto, unquote(target), unquote(desc), event_type, var!(sip_ctx)}
      else
        # lasterr aborts the scenario as a failure. Keep the same 5-tuple shape
        # (with the inferred event type) the runner expects for terminals.
        {:terminal, :failure, var!(sip_ctx).lasterr, Process.get(:scenario_event_type), var!(sip_ctx)}
      end
    end
  end

  @doc """
  Like Elixir's `receive`, but each clause records the *type* of the matched
  event so the trailing `goto` is automatically categorized (no need to pass the
  type explicitly). The type is inferred from the clause pattern: `{:ms_event,
  …}` → `:media`, any other SIP tuple (`{100, …}`, `{:BYE, …}`, `{code, …}`) →
  `:sip`. The optional `after` clause is left untouched.

      on_events do
        {200, rsp, trans, _dlg} -> process_invite_reply(rsp, trans); goto answered, "200 OK"
        {:ms_event, _c, :ice_connected} -> goto play, "media connected"
      after
        30_000 -> scenario_failure("timeout")
      end
  """
  defmacro on_events(blocks) do
    do_clauses = Keyword.fetch!(blocks, :do)
    instrumented = Enum.map(do_clauses, &instrument_receive_clause/1)

    new_blocks =
      case Keyword.fetch(blocks, :after) do
        {:ok, after_clauses} -> [do: instrumented, after: after_clauses]
        :error -> [do: instrumented]
      end

    {:receive, [], [new_blocks]}
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

  # Extract a state name (atom) from the macro argument, which is either a bare
  # identifier (`initial_state`, `next`, `loop`) parsed as a variable AST node,
  # or a literal atom.
  defp state_atom({name, _meta, context}) when is_atom(name) and is_atom(context), do: name
  defp state_atom(name) when is_atom(name), do: name

  # ── on_events event-type inference (compile time) ─────────────────────────

  # Prepend the inferred event type (stored in the process dict) to a receive
  # clause body, so the trailing `goto` picks it up.
  defp instrument_receive_clause({:->, meta, [head, body]}) do
    type = clause_event_type(head)

    new_body =
      quote do
        Process.put(:scenario_event_type, unquote(type))
        unquote(body)
      end

    {:->, meta, [head, new_body]}
  end

  # The clause head is a one-element list holding the pattern, optionally wrapped
  # in a `when` guard.
  defp clause_event_type([{:when, _meta, [pattern | _guards]}]), do: pattern_event_type(pattern)
  defp clause_event_type([pattern]), do: pattern_event_type(pattern)
  defp clause_event_type(_), do: nil

  # Tuples with 0, 1 or 3+ elements are `{:{}, _, elems}`; 2-tuples are literal.
  defp pattern_event_type({:{}, _meta, [first | _rest]}), do: first_element_type(first)
  defp pattern_event_type({first, _second}), do: first_element_type(first)
  defp pattern_event_type(_), do: nil

  # Media events are `{:ms_event, ...}`; SIP requests/responses are tuples whose
  # first element is a method atom, a status code integer, or a bound variable.
  defp first_element_type(:ms_event), do: :media
  defp first_element_type(first) when is_atom(first), do: :sip
  defp first_element_type(first) when is_integer(first), do: :sip
  defp first_element_type({name, _meta, ctx}) when is_atom(name) and is_atom(ctx), do: :sip
  defp first_element_type(_), do: nil
end
