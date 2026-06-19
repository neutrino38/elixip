defmodule SIP.Scenario.Runner do
  @moduledoc """
  Execution engine for `SIP.Scenario` finite state machines.

  A scenario module (one that does `use SIP.Scenario`) compiles each `state`
  block into a function `__state_<name>/1` that takes the `%SIP.Context{}` and
  returns a *transition descriptor*:

    * `{:goto, target, desc, ctx}`     — move to another state
    * `{:terminal, :success, r, ctx}`  — scenario completed successfully
    * `{:terminal, :failure, r, ctx}`  — scenario failed

  `target` is either an explicit state name, the atom `:next` (the next state
  declared in the module) or `:loop` (re-enter the current state). The runner
  resolves those, logs the transition and calls the next state function — this
  is the "handled by the runner, not a direct recursive call" contract from the
  README, which keeps the call stack flat across an arbitrary number of
  transitions.

  ## Entry points

    * `bootstrap_stack/0` — start the SIP layers (idempotent). Call it once,
      either through `run/2` with `start_stack = true` or explicitly via
      `SIP.Scenario.start_stack/0` before running several instances.
    * `run_instance/1` — run a single scenario instance in the **calling
      process** (the dialog layer binds SIP/media events to `self()`, so the
      whole FSM must run where `run_instance/1` is called).
    * `run/2` — convenience used by the generated `run/1`: optionally bootstrap
      the stack, then run one instance.
  """
  require Logger

  @doc """
  Run a single scenario instance, optionally starting the SIP stack first.

  `start_stack = true` is the one-shot mode used by `mix scenario` / `elixipp`.
  `start_stack = false` assumes the stack is already up (started once via
  `SIP.Scenario.start_stack/0`) and is the basis for running many instances in
  parallel later on.
  """
  @spec run(module(), boolean()) :: :ok | {:error, term()}
  def run(module, true) do
    bootstrap_stack()
    run_instance(module)
  end

  def run(module, false), do: run_instance(module)

  @doc """
  Start the SIP layers (transactions, transport selector, dialog, config
  registry). Idempotent: each underlying layer treats an already-started layer
  as success, so this is safe to call repeatedly.
  """
  @spec bootstrap_stack() :: :ok
  def bootstrap_stack do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _config_pid} = SIP.Session.ConfigRegistry.start()
    :ok
  end

  @doc """
  Build the initial context from the scenario `config` block and run the FSM
  from `initial_state` until a terminal state is reached. Returns `:ok` on
  success or `{:error, reason}` on failure.
  """
  @spec run_instance(module()) :: :ok | {:error, term()}
  def run_instance(module) do
    states = module.__scenario_states__()

    unless :initial_state in states do
      raise "Scenario #{inspect(module)} must declare an initial_state"
    end

    ctx =
      module.__scenario_config__()
      |> build_context()
      |> SIP.Context.set(:currentstate, :initial_state)

    report(module, :initial_state, "start", nil)
    loop(module, :initial_state, ctx, states)
  end

  # ── Context bootstrap ─────────────────────────────────────────────────────

  @doc false
  # Build a %SIP.Context{} from the config keyword list. `:passwd` is applied
  # last because computing :ha1 requires :authusername / :domain / :algorithm to
  # be set first. Keys that are not native context properties (e.g. :proxy) are
  # kept in the appdata map so scenarios can read them back.
  @spec build_context(keyword()) :: %SIP.Context{}
  def build_context(config) when is_list(config) do
    {passwd, rest} = Keyword.pop(config, :passwd)

    ctx = Enum.reduce(rest, %SIP.Context{}, fn {key, value}, acc -> put_config(acc, key, value) end)

    if is_nil(passwd), do: ctx, else: SIP.Context.set(ctx, :passwd, passwd)
  end

  @context_string_props [:username, :authusername, :displayname, :domain, :algorithm]

  defp put_config(ctx, :debug, value) when is_boolean(value), do: Map.put(ctx, :debug, value)

  defp put_config(ctx, key, value) when key in @context_string_props and is_binary(value),
    do: SIP.Context.set(ctx, key, value)

  # Unknown / non-native keys (e.g. :proxy) are stored in appdata.
  defp put_config(ctx, key, value), do: SIP.Context.appdata_set(ctx, key, value)

  # ── FSM loop ──────────────────────────────────────────────────────────────

  defp loop(module, state_name, ctx, states) do
    fun = :"__state_#{state_name}"

    case apply(module, fun, [ctx]) do
      {:goto, :next, desc, type, ctx2} ->
        next = next_state(state_name, states)
        log_transition(state_name, next, desc)
        report(module, next, desc, type)
        loop(module, next, SIP.Context.set(ctx2, :currentstate, next), states)

      {:goto, :loop, desc, type, ctx2} ->
        log_transition(state_name, state_name, desc)
        report(module, state_name, desc, type)
        loop(module, state_name, ctx2, states)

      {:goto, target, desc, type, ctx2} when is_atom(target) ->
        unless target in states do
          raise "Scenario #{inspect(module)}: goto unknown state #{inspect(target)}"
        end

        log_transition(state_name, target, desc)
        report(module, target, desc, type)
        loop(module, target, SIP.Context.set(ctx2, :currentstate, target), states)

      {:terminal, :success, reason, type, ctx2} ->
        report(module, :succeeded, reason, type)
        finalize(module, ctx2, :success, reason)

      {:terminal, :failure, reason, type, ctx2} ->
        report(module, :failed, reason, type)
        finalize(module, ctx2, :failure, reason)

      other ->
        raise "State #{state_name} of #{inspect(module)} must end with goto / " <>
                "scenario_success / scenario_failure, got: #{inspect(other)}"
    end
  end

  # Resolve `goto next`: the state declared right after `state_name`.
  defp next_state(state_name, states) do
    case Enum.drop_while(states, &(&1 != state_name)) do
      [^state_name, next | _] -> next
      _ -> raise "No state declared after #{inspect(state_name)} (goto next)"
    end
  end

  defp log_transition(from, to, desc) do
    suffix = if desc in [nil, ""], do: "", else: ": #{desc}"
    Logger.debug("RCV event: (#{from}) -> (#{to})#{suffix}")
  end

  # Report the current state of this call to the live monitor, if it is running.
  # `event_type` categorizes the triggering event (`:sip`, `:media`, …) for the
  # future sequence diagram. No-op (and no dependency on the monitor) when
  # monitoring is off.
  defp report(module, state, event, event_type) do
    if Process.whereis(SIP.Scenario.Monitor) do
      SIP.Scenario.Monitor.report(self(), scenario_label(module), state, event_label(event), event_type)
    end

    :ok
  end

  defp scenario_label(module), do: module |> Module.split() |> Enum.join(".")

  # The event/reason may be any term (e.g. a `{:error, _}` lasterr tuple used as
  # a failure reason), so stringify safely rather than assuming String.Chars.
  defp event_label(event) do
    if String.Chars.impl_for(event), do: to_string(event), else: inspect(event)
  end

  # ── Termination ──────────────────────────────────────────────────────────

  defp finalize(module, ctx, outcome, reason) do
    ctx
    |> release_media()
    |> run_cleanup_callback(module)

    case outcome do
      :success ->
        Logger.info("Scenario #{inspect(module)} succeeded (state #{ctx.currentstate}): #{inspect(reason)}")
        :ok

      :failure ->
        Logger.error("Scenario #{inspect(module)} failed (state #{ctx.currentstate}): #{inspect(reason)}")
        {:error, reason}
    end
  end

  # If a media server is in use, wait (max 5 s) for the dialog to terminate
  # before releasing media resources, as specified in the README.
  defp release_media(ctx) do
    if is_pid(ctx.mediaserverpid) and not is_nil(ctx.mediaservermodule) do
      receive do
        {:dialog_terminated, _dialog_pid, _reason} -> :ok
      after
        5_000 -> :ok
      end

      SIP.Session.Media.media_cleanup_ressources(ctx)
    else
      ctx
    end
  end

  defp run_cleanup_callback(ctx, module) do
    if function_exported?(module, :cleanup, 1) do
      module.cleanup(ctx)
    end

    ctx
  end
end
