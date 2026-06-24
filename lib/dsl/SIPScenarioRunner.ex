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
  @spec run_instance(module(), keyword()) :: :ok | {:aborted, term()} | {:error, term()}
  def run_instance(module, opts \\ []) do
    states = module.__scenario_states__()

    unless :initial_state in states do
      raise "Scenario #{inspect(module)} must declare an initial_state"
    end

    if slot_id = Keyword.get(opts, :slot_id), do: Process.put(:scenario_slot_id, slot_id)

    # External-config / programmatic overrides (highest precedence) are merged on
    # top of the scenario `config` block before building the context. Empty by
    # default, so a run without overrides behaves exactly as before.
    config = Keyword.merge(module.__scenario_config__(), Keyword.get(opts, :config_overrides, []))

    ctx =
      config
      |> build_context()
      |> apply_run_opts(opts)
      |> SIP.Context.set(:currentstate, :initial_state)

    maybe_start_sequence_journal(module, ctx)

    report(module, ctx.username || "", :initial_state, "start", nil)
    loop(module, :initial_state, ctx, states)
  end

  # Seed the context from run_instance/2 options: the parent PID (struct field),
  # the name the parent assigned this instance (appdata :__self_name__), and any
  # `args` map passed at spawn time (merged into appdata). All are optional, so a
  # scenario started without a parent (mix scenario, single elixipp run) is left
  # untouched.
  defp apply_run_opts(ctx, opts) do
    ctx =
      case Keyword.get(opts, :parent_pid) do
        nil -> ctx
        pid -> SIP.Context.set(ctx, :parent_pid, pid)
      end

    ctx =
      case Keyword.get(opts, :self_name) do
        nil -> ctx
        name -> SIP.Context.appdata_set(ctx, :__self_name__, name)
      end

    # UAS scenarios: the dialog is created by the inbound request, so the
    # registrar hands us the dialog pid (so reply macros target it) and,
    # optionally, the request itself (also delivered as a {:REGISTER, …} message).
    ctx =
      case Keyword.get(opts, :dialog_pid) do
        nil -> ctx
        pid -> SIP.Context.set(ctx, :dialogpid, pid)
      end

    ctx =
      case Keyword.get(opts, :inbound_request) do
        nil -> ctx
        req -> SIP.Context.appdata_set(ctx, :inbound_request, req)
      end

    case Keyword.get(opts, :appdata) do
      map when is_map(map) ->
        Enum.reduce(map, ctx, fn {k, v}, acc -> SIP.Context.appdata_set(acc, k, v) end)

      _ ->
        ctx
    end
  end

  # ── Sub-FSM (sub_fsm) support ─────────────────────────────────────────────
  # These functions back the `sub_fsm` / `notify` / `notify_parent` macros of
  # SIP.Scenario. They run in the parent (resp. child) FSM process, the one that
  # owns the SIP/media mailbox, so the spawn_monitor link and the message sends
  # all originate from the right process.

  @doc false
  # Spawn `target` (a scenario module or a path to a .exs scenario file) as a
  # monitored child FSM, hand it our PID and the local name `as:`, and record the
  # resulting handle in the parent context appdata. Returns the updated context.
  @spec spawn_child(%SIP.Context{}, module() | Path.t(), keyword(), pid()) :: %SIP.Context{}
  def spawn_child(ctx, target, opts, parent_pid) do
    name = Keyword.fetch!(opts, :as)
    args = Keyword.get(opts, :args, %{})
    module = resolve_target(target)

    {pid, ref} =
      spawn_monitor(fn ->
        run_instance(module, parent_pid: parent_pid, self_name: name, appdata: args)
      end)

    child = %SIP.Scenario.Child{name: name, pid: pid, ref: ref, module: module}
    children = ctx.appdata |> Map.get(:__children__, %{}) |> Map.put(name, child)
    SIP.Context.appdata_set(ctx, :__children__, children)
  end

  defp resolve_target(target) when is_atom(target), do: target
  defp resolve_target(target) when is_binary(target), do: SIP.Scenario.Loader.load_file!(target)

  @doc """
  Spawn a UAS scenario instance to handle one inbound dialog (e.g. a REGISTER).
  Used by a registration processing module (`Elixip.RegistrarUAS`) from inside
  `on_new_registration/3`: it returns `{pid, ref}` where `pid` is the bound app
  process to return as `{:accept, pid}` and `ref` is a monitor reference the
  caller can use to free its instance slot when the scenario ends.

  `opts` are forwarded to `run_instance/2`; `:dialog_pid`, `:inbound_request`
  and `:parent_pid` are the relevant ones for a server scenario.
  """
  @spec spawn_uas_instance(module() | Path.t(), keyword()) :: {pid(), reference()}
  def spawn_uas_instance(target, opts \\ []) do
    module = resolve_target(target)
    spawn_monitor(fn -> run_instance(module, opts) end)
  end

  @doc false
  # Send an application message to a named child. Unknown name → log + no-op so a
  # typo does not crash the parent FSM.
  @spec notify_child(%SIP.Context{}, atom(), term()) :: :ok
  def notify_child(ctx, name, payload) do
    case ctx.appdata |> Map.get(:__children__, %{}) |> Map.get(name) do
      %SIP.Scenario.Child{pid: pid} -> send(pid, {:scenario_msg, :parent, payload})
      nil -> Logger.warning("notify/2: unknown child #{inspect(name)}")
    end

    :ok
  end

  @doc false
  # Send an application message to the parent FSM, tagged with the name the parent
  # assigned us (so the parent can match on a stable literal). No-op when there is
  # no parent (standalone run).
  @spec notify_parent(%SIP.Context{}, term()) :: :ok
  def notify_parent(ctx, payload) do
    case ctx.parent_pid do
      nil -> :ok
      pid -> send(pid, {:scenario_msg, Map.get(ctx.appdata, :__self_name__), payload})
    end

    :ok
  end

  # Start the per-instance PlantUML sequence journal when --log-sequence is set on
  # the CLI (Application env) or when the scenario enabled its debug flag. No-op
  # otherwise — the journal recording helpers are then free.
  defp maybe_start_sequence_journal(module, ctx) do
    if Application.get_env(:elixip2, :log_sequence, false) or ctx.debug do
      SIP.Scenario.SequenceJournal.start(%{
        scenario: scenario_label(module),
        pid: inspect(self()),
        config: module.__scenario_config__()
      })
    end

    :ok
  end

  # ── Context bootstrap ─────────────────────────────────────────────────────

  @doc false
  # Build a %SIP.Context{} from the config keyword list. `:passwd` is applied
  # last because computing :ha1 requires :authusername / :domain / :algorithm to
  # be set first. Global keys (:proxyuri / :proxyusesrv / :optionkeepaliveperiod)
  # are routed to the :elixip2 application env. Remaining non-native keys (e.g.
  # :proxy) are kept in the appdata map so scenarios can read them back.
  @spec build_context(keyword()) :: %SIP.Context{}
  def build_context(config) when is_list(config) do
    {passwd, rest} = Keyword.pop(config, :passwd)

    ctx =
      Enum.reduce(rest, %SIP.Context{}, fn {key, value}, acc -> put_config(acc, key, value) end)

    if is_nil(passwd), do: ctx, else: SIP.Context.set(ctx, :passwd, passwd)
  end

  @context_string_props [:username, :authusername, :displayname, :domain, :algorithm]

  # Global keys are not per-session: they are routed to the :elixip2 application
  # env (read by SIP.Resolver, SIP.Session.Register, …) instead of the context.
  # This is the single place that applies them, whether they come from the
  # scenario `config` block or from an external JSON header — so scenarios no
  # longer need to `Application.put_env` by hand in their initial_state.
  @global_keys [:proxyuri, :proxyusesrv, :optionkeepaliveperiod]

  defp put_config(ctx, key, value) when key in @global_keys do
    apply_global_key(key, value)
    ctx
  end

  defp put_config(ctx, :debug, value) when is_boolean(value), do: Map.put(ctx, :debug, value)

  defp put_config(ctx, key, value) when key in @context_string_props and is_binary(value),
    do: SIP.Context.set(ctx, key, value)

  # Unknown / non-native keys (e.g. :proxy) are stored in appdata.
  defp put_config(ctx, key, value), do: SIP.Context.appdata_set(ctx, key, value)

  # Apply a global key to the application env. `:proxyuri` accepts either an
  # already-parsed %SIP.Uri{} (from the JSON loader) or a string "sip:host:port"
  # (from a scenario `config` block), parsing the latter so both paths converge.
  defp apply_global_key(:proxyuri, %SIP.Uri{} = uri),
    do: Application.put_env(:elixip2, :proxyuri, uri)

  defp apply_global_key(:proxyuri, value) when is_binary(value) do
    case SIP.Uri.parse(value) do
      {:ok, uri} -> Application.put_env(:elixip2, :proxyuri, uri)
      {err, _} -> raise "invalid proxyuri #{inspect(value)}: #{inspect(err)}"
    end
  end

  defp apply_global_key(key, value), do: Application.put_env(:elixip2, key, value)

  # ── FSM loop ──────────────────────────────────────────────────────────────

  defp loop(module, state_name, ctx, states) do
    fun = :"__state_#{state_name}"

    case apply(module, fun, [ctx]) do
      {:goto, :next, desc, type, ctx2} ->
        next = next_state(state_name, states)
        log_transition(state_name, next, desc)
        report(module, ctx2.username, next, desc, type)
        loop(module, next, SIP.Context.set(ctx2, :currentstate, next), states)

      {:goto, :loop, desc, type, ctx2} ->
        log_transition(state_name, state_name, desc)
        report(module, ctx2.username, state_name, desc, type)
        loop(module, state_name, ctx2, states)

      # Cooperative shutdown: the auto-injected on_events clause (or an explicit
      # one) jumped to the reserved :__shutdown__ state. If the scenario declared
      # an `on_shutdown` block, run it; otherwise terminate with the :aborted
      # outcome (a controller-driven stop, not a failure).
      {:goto, :__shutdown__, desc, type, ctx2} ->
        if function_exported?(module, :__state___shutdown__, 1) do
          log_transition(state_name, :__shutdown__, desc)
          report(module, ctx2.username, :__shutdown__, desc, type)
          loop(module, :__shutdown__, SIP.Context.set(ctx2, :currentstate, :__shutdown__), states)
        else
          report(module, ctx2.username, :aborted, desc, type)
          finalize(module, ctx2, :aborted, "shutdown")
        end

      {:goto, target, desc, type, ctx2} when is_atom(target) ->
        if target in states do
          log_transition(state_name, target, desc)
          report(module, ctx2.username, target, desc, type)
          loop(module, target, SIP.Context.set(ctx2, :currentstate, target), states)
        else
          reason = "jumped from state #{inspect(state_name)} to unknown state #{inspect(target)}"
          Logger.error("Scenario #{inspect(module)} #{reason}.")
          report(module, ctx2.username, :failed, "unknown state #{target}", type)
          finalize(module, ctx2, :failure, {:unknown_state, target})
        end

      {:terminal, :success, reason, type, ctx2} ->
        report(module, ctx2.username, :succeeded, reason, type)
        finalize(module, ctx2, :success, reason)

      {:terminal, :failure, reason, type, ctx2} ->
        report(module, ctx2.username, :failed, reason, type)
        finalize(module, ctx2, :failure, reason)

      {:terminal, :aborted, reason, type, ctx2} ->
        report(module, ctx2.username, :aborted, reason, type)
        finalize(module, ctx2, :aborted, reason)

      # A state must end with goto / scenario_success / scenario_failure. Anything
      # else is a malformed transition: stop the scenario cleanly as a failure
      # rather than crashing the running process with a raw exception.
      other ->
        Logger.error(
          "Invalid transition in state #{state_name}: a state must end with goto / " <>
            "scenario_success / scenario_failure, got: #{inspect(other)}"
        )

        report(module, ctx.username, :failed, "invalid transition", nil)
        finalize(module, ctx, :failure, {:invalid_transition, state_name})
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
  defp report(module, username, state, event, event_type) do
    if Process.whereis(SIP.Scenario.Monitor) do
      call_id = Process.get(:scenario_slot_id, self())

      SIP.Scenario.Monitor.report(
        call_id,
        scenario_label(module),
        username,
        state,
        event_label(event),
        event_type
      )
    end

    # Feed the PlantUML sequence journal (no-op when not enabled in this process).
    SIP.Scenario.SequenceJournal.record_transition(state, event_label(event), event_type)

    :ok
  end

  defp scenario_label(module), do: module |> Module.split() |> Enum.join(".")

  # The event/reason may be any term (e.g. a `{:error, _}` lasterr tuple used as
  # a failure reason), so stringify safely rather than assuming String.Chars.
  defp event_label(event) do
    if String.Chars.impl_for(event), do: to_string(event), else: inspect(event)
  end

  # ── Termination ──────────────────────────────────────────────────────────

  # Grace period (ms) given to children to wind down after a cooperative shutdown
  # request before they are hard-killed.
  @child_shutdown_grace_ms 5_000

  defp finalize(module, ctx, outcome, reason) do
    # Tear down any sub-FSMs first so they release their own resources before we
    # release ours and report up to our parent.
    shutdown_children(ctx)

    ctx
    |> release_media()
    |> run_cleanup_callback(module)

    notify_parent_exit(ctx, outcome, reason)

    case SIP.Scenario.SequenceJournal.flush() do
      {:ok, path} -> Logger.info("Sequence diagram written to #{path}")
      {:error, reason} -> Logger.warning("Could not write sequence diagram: #{inspect(reason)}")
      :disabled -> :ok
    end

    case outcome do
      :success ->
        Logger.info(
          "Scenario #{inspect(module)} succeeded (state #{ctx.currentstate}): #{inspect(reason)}"
        )

        :ok

      :aborted ->
        Logger.info(
          "Scenario #{inspect(module)} aborted (state #{ctx.currentstate}): #{inspect(reason)}"
        )

        {:aborted, reason}

      :failure ->
        Logger.error(
          "Scenario #{inspect(module)} failed (state #{ctx.currentstate}): #{inspect(reason)}"
        )

        {:error, reason}
    end
  end

  # Ask every live child to shut down cooperatively, then wait (bounded) for each
  # to go down, hard-killing any straggler past the grace period. No-op when this
  # scenario spawned no children.
  defp shutdown_children(ctx) do
    children = ctx.appdata |> Map.get(:__children__, %{}) |> Map.values()

    if children == [] do
      :ok
    else
      Enum.each(children, fn %SIP.Scenario.Child{pid: pid} ->
        send(pid, {:scenario_ctl, :shutdown, :parent_terminated})
      end)

      remaining = Map.new(children, fn c -> {c.ref, c} end)

      timer =
        Process.send_after(self(), :__children_shutdown_deadline__, @child_shutdown_grace_ms)

      wait_children_down(remaining, timer)
    end
  end

  defp wait_children_down(remaining, timer) when map_size(remaining) == 0 do
    Process.cancel_timer(timer)
    :ok
  end

  defp wait_children_down(remaining, timer) do
    receive do
      {:DOWN, ref, :process, _pid, _down_reason} ->
        wait_children_down(Map.delete(remaining, ref), timer)

      :__children_shutdown_deadline__ ->
        Enum.each(remaining, fn {_ref, %SIP.Scenario.Child{pid: pid}} ->
          Process.exit(pid, :kill)
        end)

        :timeout
    end
  end

  # Tell our parent (if any) how we terminated, so it can match {:scenario_exit,
  # name, outcome, reason} in its on_events.
  defp notify_parent_exit(ctx, outcome, reason) do
    case ctx.parent_pid do
      nil -> :ok
      pid -> send(pid, {:scenario_exit, Map.get(ctx.appdata, :__self_name__), outcome, reason})
    end

    :ok
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
