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
  declared in the module), `:loop` (re-enter the current state) or `:__back__`
  (the state entered before this one, read from `ctx.laststate`). The runner
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
  # is_req/1: only an inbound *request* names an identity (see initial_account/1)
  import SIP.Msg.Ops, only: [is_req: 1]

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
    # One server secret for the node's lifetime, keying every digest nonce
    # (SIP.Auth.Nonce). kelixip supervises it instead; here it belongs to the run.
    :ok = SIP.Auth.Secret.start()
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

    # The scenario a service building block reports under: a block's states show
    # on this row, qualified, never under the block's own name (§4 of the design).
    Process.put(:scenario_module, module)

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

    report(module, initial_account(ctx), :initial_state, "start", nil)
    loop(module, :initial_state, ctx, states)
  end

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
    case SIP.Context.appdata_get(ctx, :inbound_request) do
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

  # ── Sub-FSM (spawn_fsm) support ─────────────────────────────────────────────
  # These functions back the `spawn_fsm` / `notify` / `notify_parent` macros of
  # SIP.Scenario. They run in the parent (resp. child) FSM process, the one that
  # owns the SIP/media mailbox, so the spawn_monitor link and the message sends
  # all originate from the right process.

  @doc false
  # Spawn `target` (a scenario module or a path to a .exs scenario file) as a
  # monitored child FSM, hand it our PID and the local name `as:`, and record the
  # resulting handle in the parent context appdata. Returns the updated context.
  @spec spawn_child(%SIP.Context{}, module() | Path.t(), keyword(), pid(), Path.t() | nil) ::
          %SIP.Context{}
  def spawn_child(ctx, target, opts, parent_pid, base_dir \\ nil) do
    name = Keyword.fetch!(opts, :as)
    args = Keyword.get(opts, :args, %{})
    module = resolve_target(target, base_dir)

    # Key the child's monitor row under its parent ({parent_slot, name}) so the
    # live table shows it on its own line right below the parent, and so
    # clearing the parent slot recycles the child rows too.
    parent_slot = Process.get(:scenario_slot_id, parent_pid)

    {pid, ref} =
      spawn_monitor(fn ->
        Process.put(:scenario_slot_id, {parent_slot, name})
        run_instance(module, parent_pid: parent_pid, self_name: name, appdata: args)
      end)

    setup_uas_child(SIP.Scenario.Loader.scenario_type(module), pid)

    child = %SIP.Scenario.Child{name: name, pid: pid, ref: ref, module: module}
    children = ctx.appdata |> Map.get(:__children__, %{}) |> Map.put(name, child)
    SIP.Context.appdata_set(ctx, :__children__, children)
  end

  defp resolve_target(target, _base_dir) when is_atom(target), do: target

  defp resolve_target(target, base_dir) when is_binary(target) do
    target
    |> sibling_path(base_dir)
    |> SIP.Scenario.Loader.load_file!()
  end

  # `spawn_fsm "child.exs"` names a file next to the scenario that declares it (the
  # `include` rule, see the spawn_fsm macro). The path as given is still honoured when
  # it resolves — a scenario referring to a file elsewhere keeps working — and which
  # one was used is logged, so a run never silently loads a file the reader did not
  # expect.
  defp sibling_path(target, base_dir) do
    sibling = if base_dir, do: Path.join(base_dir, target), else: target

    cond do
      Path.type(target) == :absolute ->
        target

      File.regular?(sibling) ->
        if Path.expand(sibling) != Path.expand(target) do
          Logger.info("spawn_fsm #{inspect(target)} resolved next to its parent: #{sibling}")
        end

        sibling

      File.regular?(target) ->
        Logger.info("spawn_fsm #{inspect(target)} not found next to its parent, using #{target}")
        target

      true ->
        raise "sub-scenario not found: #{inspect(target)} (looked for #{sibling} " <>
                "next to the declaring scenario, then #{Path.expand(target)})"
    end
  end

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

  defp setup_uas_child(type, _pid) when type in [:uas_register] do
    Logger.warning("spawn_fsm: scenario type #{inspect(type)} is not supported as a sub-FSM yet")
  end

  defp setup_uas_child(_type, _pid), do: :ok

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
    # No declaring scenario here: the target comes from the operator (elixipp's
    # command line), so it is taken as given — cwd-relative, like any path a user
    # types. Only `spawn_fsm` resolves relative to the file that declares it.
    module = resolve_target(target, nil)
    spawn_monitor(fn -> run_instance(module, opts) end)
  end

  @doc false
  # Send an application message to a named child. Unknown name → log + no-op so a
  # typo does not crash the parent FSM.
  @spec notify_child(%SIP.Context{}, atom(), term()) :: :ok
  def notify_child(ctx, name, payload) do
    case ctx.appdata |> Map.get(:__children__, %{}) |> Map.get(name) do
      %SIP.Scenario.Child{pid: pid} -> send(pid, {:parent_msg, payload})
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
      pid -> send(pid, {:child_msg, Map.get(ctx.appdata, :__self_name__), payload})
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
  @global_keys [:proxyuri, :proxyusesrv, :optionkeepaliveperiod, :mediaserver]

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

  # :mediaserver selects the media adapter used by media_connect/0:
  # [module: :mockup | :mendooze | Module, url: "..."] (map accepted too).
  defp apply_global_key(:mediaserver, value) when is_list(value) or is_map(value),
    do: Application.put_env(:elixip2, :mediaserver, value)

  defp apply_global_key(:mediaserver, value),
    do: raise("invalid mediaserver config #{inspect(value)}: expected [module: ..., url: ...]")

  defp apply_global_key(key, value), do: Application.put_env(:elixip2, key, value)

  # ── FSM loop ──────────────────────────────────────────────────────────────

  defp loop(module, state_name, ctx, states) do
    fun = :"__state_#{state_name}"

    # A terminal written inside a service building block unwinds every nested
    # sbb_loop/4 frame as a throw — the only non-local exit that crosses them,
    # and one the per-state try/catch is transparent to (it catches :exit and
    # exceptions, never :throw). Caught here, at the root, it is re-applied as if
    # this state had written it: same report, same finalize, same verdict.
    case run_state(module, fun, ctx) do
      {:goto, :next, desc, type, ctx2} ->
        next = next_state(state_name, states)
        log_transition(state_name, next, desc)
        report(module, report_account(ctx2), next, desc, type)
        loop(module, next, enter(ctx2, state_name, next), states)

      {:goto, :loop, desc, type, ctx2} ->
        log_transition(state_name, state_name, desc)
        report(module, report_account(ctx2), state_name, desc, type)
        loop(module, state_name, ctx2, states)

      # `goto back`: return to whatever state we came from. One slot, no stack —
      # so two consecutive `goto back` toggle between two states.
      {:goto, :__back__, desc, type, ctx2} ->
        case ctx2.laststate do
          nil ->
            reason = "goto back with no previous state"

            Logger.error(
              "Scenario #{inspect(module)} in state #{inspect(state_name)}: #{reason}."
            )

            report(module, report_account(ctx2), :failed, reason, type)
            finalize(module, ctx2, :failure, reason)

          previous ->
            log_transition(state_name, previous, desc)
            report(module, report_account(ctx2), previous, desc, type)
            loop(module, previous, enter(ctx2, state_name, previous), states)
        end

      # Cooperative shutdown: the auto-injected on_events clause (or an explicit
      # one) jumped to the reserved :__shutdown__ state. If the scenario declared
      # an `on_shutdown` block, run it; otherwise terminate with the :aborted
      # outcome (a controller-driven stop, not a failure).
      {:goto, :__shutdown__, desc, type, ctx2} ->
        if function_exported?(module, :__state___shutdown__, 1) do
          log_transition(state_name, :__shutdown__, desc)
          report(module, report_account(ctx2), :__shutdown__, desc, type)
          loop(module, :__shutdown__, enter(ctx2, state_name, :__shutdown__), states)
        else
          report(module, report_account(ctx2), :aborted, desc, type)
          finalize(module, ctx2, :aborted, "shutdown")
        end

      {:goto, target, desc, type, ctx2} when is_atom(target) ->
        if target in states do
          log_transition(state_name, target, desc)
          report(module, report_account(ctx2), target, desc, type)
          loop(module, target, enter(ctx2, state_name, target), states)
        else
          reason = "jumped from state #{inspect(state_name)} to unknown state #{inspect(target)}"
          Logger.error("Scenario #{inspect(module)} #{reason}.")
          report(module, report_account(ctx2), :failed, "unknown state #{target}", type)
          finalize(module, ctx2, :failure, {:unknown_state, target})
        end

      # `sbb_return` outside a block: there is nothing to return to. Same class of
      # error as the `stay` below, and reported the same way rather than falling
      # into the "invalid transition" catch-all, which would say nothing useful.
      {:sbb_return, _event, ctx2} ->
        reason = "sbb_return used outside a service building block"
        Logger.error("Scenario #{inspect(module)} in state #{inspect(state_name)}: #{reason}.")
        report(module, report_account(ctx2), :failed, reason, nil)
        finalize(module, ctx2, :failure, {:sbb_return_outside_sbb, state_name})

      # A `stay` that reached the runner was written outside an `on_events` clause
      # (a plain `receive`, an `after` body, a bare state body): there is no wait
      # to go back to, so it is a scenario error, not a transition.
      {:stay, _desc, type, ctx2} ->
        reason = "stay used outside an on_events clause"
        Logger.error("Scenario #{inspect(module)} in state #{inspect(state_name)}: #{reason}.")
        report(module, report_account(ctx2), :failed, reason, type)
        finalize(module, ctx2, :failure, {:stay_outside_on_events, state_name})

      {:terminal, :success, reason, type, ctx2} ->
        report(module, report_account(ctx2), :succeeded, reason, type)
        finalize(module, ctx2, :success, reason)

      {:terminal, :failure, reason, type, ctx2} ->
        report(module, report_account(ctx2), :failed, reason, type)
        finalize(module, ctx2, :failure, reason)

      {:terminal, :aborted, reason, type, ctx2} ->
        report(module, report_account(ctx2), :aborted, reason, type)
        finalize(module, ctx2, :aborted, reason)

      # A state must end with goto / scenario_success / scenario_failure. Anything
      # else is a malformed transition: stop the scenario cleanly as a failure
      # rather than crashing the running process with a raw exception.
      other ->
        Logger.error(
          "Invalid transition in state #{state_name}: a state must end with goto / " <>
            "scenario_success / scenario_failure, got: #{inspect(other)}"
        )

        report(module, report_account(ctx), :failed, "invalid transition", nil)
        finalize(module, ctx, :failure, {:invalid_transition, state_name})
    end
  end

  # Run one state function, converting a terminal thrown from inside a service
  # building block into the descriptor this state would have produced. Used by
  # loop/4 only: sbb_loop/4 deliberately does NOT catch, so a terminal thrown
  # three blocks deep still unwinds to the root.
  defp run_state(module, fun, ctx) do
    try do
      apply(module, fun, [ctx])
    catch
      {:sbb_terminal, outcome, reason, type, ctx2} ->
        {:terminal, outcome, reason, type, ctx2}

      # A cooperative shutdown that reached a block and found no on_shutdown
      # there: it belongs to the scenario, so it is re-applied as the transition
      # the host state would have made, on_shutdown and all.
      {:sbb_shutdown, desc, type, ctx2} ->
        {:goto, :__shutdown__, desc, type, ctx2}
    end
  end

  # ── Service building blocks (sbb_fsm) ─────────────────────────────────────
  #
  # A block is a scenario FSM run by THIS process on THIS scenario's context: a
  # subroutine call, not a spawn. Design:
  # docs/design/DESIGN-SBB.md.

  @doc false
  # Back the `sbb_fsm` macro. Runs `module`'s FSM to completion and returns the
  # context to rebind in the calling state.
  @spec run_sbb(%SIP.Context{}, module(), keyword()) :: %SIP.Context{}
  def run_sbb(ctx, module, opts \\ []) do
    unless function_exported?(module, :__sbb__, 0) do
      raise ArgumentError,
            "#{inspect(module)} is not a service building block (it must `use SIP.SBB`)"
    end

    states = module.__scenario_states__()

    unless :initial_state in states do
      raise "Service building block #{inspect(module)} must declare an initial_state"
    end

    # The host's position is restored on return: the block moves through states of
    # its own, and `goto back` inside it must not be able to land in a host state.
    host_state = ctx.currentstate
    host_laststate = ctx.laststate

    entry_ctx =
      ctx
      |> seed_sbb_sandbox(module, opts)
      |> SIP.Context.set(:currentstate, :initial_state)
      |> SIP.Context.set(:laststate, nil)

    timeout = Keyword.get(opts, :timeout, module.__sbb_timeout__())
    ref = make_ref()
    timer = arm_sbb_deadline(ref, timeout)

    # Pushed before the first state runs and popped whatever happens to it, so a
    # terminal or a deadline unwinding through here leaves the stack — and the
    # reporting that reads it — as it found it.
    push_sbb_frame(module)
    report(module, report_account(entry_ctx), :initial_state, "enter", :scenario)

    {event, ctx2} =
      try do
        sbb_loop(module, :initial_state, entry_ctx, states, ref)
      catch
        # Our own deadline fired. A deeper block lets the throw pass, so it is
        # always the right frame that answers. This is an ordinary ending — the
        # block returns its timeout event — so `sbb_cleanup` does not run.
        {:sbb_deadline_hit, ^ref, ctx2} ->
          {module.__sbb_timeout_event__(), ctx2}

        # Every other non-local exit leaves this block *without* returning from
        # it: a terminal, a cooperative shutdown, or an enclosing block's
        # deadline. The block releases what it reserved before the throw carries
        # on unwinding, which is what makes nested blocks release innermost
        # first (design §4.4).
        thrown ->
          throw(sbb_unwind_cleanup(module, thrown))
      after
        pop_sbb_frame()
        disarm_sbb_deadline(timer, ref)
      end

    send(self(), event)

    host_ctx =
      ctx2
      |> SIP.Context.set(:currentstate, host_state)
      |> SIP.Context.set(:laststate, host_laststate)

    # Back to the caller's vocabulary. Without this the row would sit on the
    # block's last state while the host waits on the event we just posted — a
    # state the scenario never wrote, shown as where the call is.
    report(module, report_account(host_ctx), host_state, event, :scenario)

    host_ctx
  end

  # Run a block's `sbb_cleanup` on the context the throw is carrying, and hand
  # the term back so it can go on unwinding. Only the shapes the DSL throws
  # carry a context; anything else passes through untouched.
  defp sbb_unwind_cleanup(module, {:sbb_terminal, outcome, reason, type, ctx}),
    do: {:sbb_terminal, outcome, reason, type, sbb_cleanup(module, ctx)}

  defp sbb_unwind_cleanup(module, {:sbb_shutdown, desc, type, ctx}),
    do: {:sbb_shutdown, desc, type, sbb_cleanup(module, ctx)}

  defp sbb_unwind_cleanup(module, {:sbb_deadline_hit, other_ref, ctx}),
    do: {:sbb_deadline_hit, other_ref, sbb_cleanup(module, ctx)}

  defp sbb_unwind_cleanup(_module, thrown), do: thrown

  defp sbb_cleanup(module, ctx) do
    if function_exported?(module, :__sbb_cleanup__, 1) do
      try do
        case module.__sbb_cleanup__(ctx) do
          %SIP.Context{} = ctx2 -> ctx2
          _other -> ctx
        end
      rescue
        e ->
          # We are already unwinding: a throwing cleanup must not restart it.
          Logger.error("Exception in sbb_cleanup of #{inspect(module)}")
          Logger.error(Exception.format(:error, e, __STACKTRACE__))
          ctx
      end
    else
      ctx
    end
  end

  defp push_sbb_frame(module),
    do: Process.put(:sbb_stack, [module | Process.get(:sbb_stack, [])])

  defp pop_sbb_frame do
    case Process.get(:sbb_stack, []) do
      [_ | rest] -> Process.put(:sbb_stack, rest)
      [] -> :ok
    end
  end

  # The block's FSM loop. Same dispatch as loop/4 with two differences, and only
  # two: it never calls finalize/4 (the host's legs, media and children are not
  # the block's to release) and it never reports an outcome to a parent FSM —
  # its caller is a state, not a process. It does report every transition, on the
  # host's row: report_label/2 qualifies the state with the block it belongs to.
  defp sbb_loop(module, state_name, ctx, states, ref) do
    fun = :"__state_#{state_name}"

    case apply(module, fun, [ctx]) do
      {:sbb_return, event, ctx2} ->
        {event, ctx2}

      # A terminal inside a block kills the host too (S8). It has N nested frames
      # to cross, so it goes out as a throw and only loop/4 catches it.
      {:terminal, outcome, reason, type, ctx2} ->
        throw({:sbb_terminal, outcome, reason, type, ctx2})

      {:goto, :next, desc, type, ctx2} ->
        next = next_state(state_name, states)
        log_transition(state_name, next, desc)
        report(module, report_account(ctx2), next, desc, type)
        sbb_loop(module, next, enter(ctx2, state_name, next), states, ref)

      {:goto, :loop, desc, type, ctx2} ->
        log_transition(state_name, state_name, desc)
        report(module, report_account(ctx2), state_name, desc, type)
        sbb_loop(module, state_name, ctx2, states, ref)

      {:goto, :__back__, desc, type, ctx2} ->
        case ctx2.laststate do
          nil ->
            throw({:sbb_terminal, :failure, "goto back with no previous state", nil, ctx2})

          previous ->
            log_transition(state_name, previous, desc)
            report(module, report_account(ctx2), previous, desc, type)
            sbb_loop(module, previous, enter(ctx2, state_name, previous), states, ref)
        end

      # A cooperative shutdown reached the block through the clause injected into
      # every on_events. The block's own on_shutdown runs if it has one — it may
      # owe the far end a response. Otherwise the wind-down CONTINUES INTO THE
      # HOST, because the request was addressed to the scenario, not to us: it
      # goes out as a throw of its own, which loop/4 turns back into the `goto
      # :__shutdown__` the host state would have produced.
      #
      # Ending the scenario here instead would skip the host's on_shutdown, and
      # that block is where a script frees what the call reserved — the media
      # endpoints of a B2BUA among them. A graceful stop during a call that is
      # ringing inside call() would leak them.
      #
      # An ENCLOSING block's own on_shutdown is skipped by that throw. Left that
      # way deliberately: no block has one today, and the machinery to run each
      # frame's wind-down on the way out would have to answer what a frame
      # returning from it means.
      {:goto, :__shutdown__, desc, type, ctx2} ->
        if function_exported?(module, :__state___shutdown__, 1) do
          log_transition(state_name, :__shutdown__, desc)
          report(module, report_account(ctx2), :__shutdown__, desc, type)
          sbb_loop(module, :__shutdown__, enter(ctx2, state_name, :__shutdown__), states, ref)
        else
          throw({:sbb_shutdown, desc, type, ctx2})
        end

      {:goto, target, desc, type, ctx2} when is_atom(target) ->
        if target in states do
          log_transition(state_name, target, desc)
          report(module, report_account(ctx2), target, desc, type)
          sbb_loop(module, target, enter(ctx2, state_name, target), states, ref)
        else
          reason =
            "block #{inspect(module)} jumped from #{inspect(state_name)} to unknown state " <>
              "#{inspect(target)}"

          throw({:sbb_terminal, :failure, reason, nil, ctx2})
        end

      {:stay, _desc, _type, ctx2} ->
        throw({:sbb_terminal, :failure, "stay used outside an on_events clause", nil, ctx2})

      other ->
        reason =
          "block #{inspect(module)}, state #{state_name}: a state must end with goto / " <>
            "sbb_return / scenario_success, got: #{inspect(other)}"

        Logger.error(reason)
        throw({:sbb_terminal, :failure, reason, nil, ctx})
    end
  end

  # The sandbox is cleared on every call, so a block entered twice starts twice
  # from nothing — a serial hunt must not inherit the previous attempt's scratch.
  # `resume: true` is the exception, for a block designed to be re-entered.
  defp seed_sbb_sandbox(ctx, module, opts) do
    args = Keyword.get(opts, :args, %{})

    sandbox =
      if Keyword.get(opts, :resume, false),
        do: Map.merge(sbb_sandbox(ctx, module), args),
        else: args

    SIP.Context.appdata_set(ctx, {:sbb, module}, sandbox)
  end

  defp sbb_sandbox(ctx, module) do
    case SIP.Context.appdata_get(ctx, {:sbb, module}) do
      map when is_map(map) -> map
      _none -> %{}
    end
  end

  @doc false
  def sbb_data_get(ctx, module, key), do: ctx |> sbb_sandbox(module) |> Map.get(key)

  @doc false
  def sbb_data_set(ctx, module, key, value) do
    SIP.Context.appdata_set(
      ctx,
      {:sbb, module},
      ctx |> sbb_sandbox(module) |> Map.put(key, value)
    )
  end

  # A block's completion bound (S7). The timer message is matched by the clause
  # `on_events` injects into every SBB state, which throws it back here — a
  # nested block lets a parent's ref pass, so the frame that armed it answers.
  defp arm_sbb_deadline(_ref, :infinity), do: nil

  defp arm_sbb_deadline(ref, ms) when is_integer(ms),
    do: Process.send_after(self(), {:sbb_deadline, ref}, ms)

  defp disarm_sbb_deadline(nil, _ref), do: :ok

  defp disarm_sbb_deadline(timer, ref) do
    Process.cancel_timer(timer)
    # Cancelling loses a race with a timer that already fired: flush the message
    # so it cannot wake a later on_events of the host.
    receive do
      {:sbb_deadline, ^ref} -> :ok
    after
      0 -> :ok
    end
  end

  # Enter `target`, coming from `from`. The `laststate` slot `goto back` reads is
  # only written when the state actually changes: re-entering a state (`goto
  # loop`, an explicit self-goto, `stay`) is not "coming from" it.
  defp enter(ctx, from, target) do
    ctx = SIP.Context.set(ctx, :currentstate, target)
    if target == from, do: ctx, else: SIP.Context.set(ctx, :laststate, from)
  end

  @doc false
  # Log and report a `stay`: the FSM did not move, but it did act on an event, so
  # the live view must show it rather than a scenario that looks frozen. Called
  # by the `on_events` expansion, which then re-enters its own wait.
  def note_stay(module, ctx, desc, type) do
    log_transition(ctx.currentstate, ctx.currentstate, desc)
    report(module, report_account(ctx), ctx.currentstate, desc, type)
    ctx
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
    {label, state} = report_label(module, state)

    if Process.whereis(SIP.Scenario.Monitor) do
      call_id = Process.get(:scenario_slot_id, self())

      SIP.Scenario.Monitor.report(
        call_id,
        label,
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

  # Who a report is about, and under which state name. Outside a service building
  # block: the scenario, its own state. Inside one: still the scenario — one call,
  # one row — but the state is qualified with the block it belongs to, so the
  # operator reads `SBB.Call/waiting_answer` instead of a state their scenario
  # does not declare. Nesting shows the innermost block, which is where the call
  # actually is.
  defp report_label(module, state) do
    # The row always names the scenario this process runs, never a block: the
    # block module is the one reporting, and on the way back out of run_sbb it is
    # not even on the stack any more. `module` is a fallback for a block driven
    # without run_instance/2 (a test calling run_sbb/3 directly).
    scenario = scenario_label(Process.get(:scenario_module, module))

    case Process.get(:sbb_stack, []) do
      [] -> {scenario, state}
      [block | _] -> {scenario, "#{scenario_label(block)}/#{state}"}
    end
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
    |> release_b2bua_legs()
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

  # Tell our parent (if any) how we terminated, so it can match {:child_exit,
  # name, outcome, reason} in its on_events.
  defp notify_parent_exit(ctx, outcome, reason) do
    case ctx.parent_pid do
      nil -> :ok
      pid -> send(pid, {:child_exit, Map.get(ctx.appdata, :__self_name__), outcome, reason})
    end

    :ok
  end

  # Wind down the B2BUA legs this scenario created, before the media: a leg left
  # behind holds a call up at the far end. No-op for a scenario that created none
  # (SIP.Session.B2bua.release_legs/1 returns the context untouched).
  defp release_b2bua_legs(ctx), do: SIP.Session.B2bua.release_legs(ctx)

  # If a media server is in use, wait (max 5 s) for the dialog to terminate
  # before releasing media resources, as specified in the README.
  defp release_media(ctx) do
    if is_pid(ctx.mediaserverpid) and not is_nil(ctx.mediaservermodule) do
      receive do
        {:dialog_terminated, _dialog_pid, _reason} -> :ok
        # The same event from a tagged leg (a B2BUA outbound leg): it says just
        # as much about the call being over, and ignoring it would stall here
        # for the full timeout.
        {_tag, {:dialog_terminated, _dialog_pid, _reason}} -> :ok
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
