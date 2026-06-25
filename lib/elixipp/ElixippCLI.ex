defmodule Elixipp.CLI do
  @moduledoc """
  Entry point of the standalone `elixipp` executable (built with `mix escript.build`).

      elixipp scenarios/my_call.exs
      elixipp UAC.Invite                       # built-in scenario, no file needed
      elixipp --monitor -l 5 scenarios/my_call.exs
      elixipp --monitor -l 5 --max-run 100 scenarios/my_call.exs

  ## Scenarios

  The argument is either a path to a scenario `.exs` file or the name of a
  **built-in** scenario module bundled into the escript: `UAC.Invite` and
  `UAC.Register`. Built-ins need no file on the host, so the standalone tool can
  run them anywhere.

  ## Options

    * `--monitor` / `-m`   — live table of calls in progress
    * `--limit N` / `-l N` — run N calls simultaneously (implies --monitor)
    * `--max-run N`        — stop after N total executions (default: unlimited)
    * `--rate N`           — calls started per second (default: 10, max: 100)
    * `--config FILE` / `-c` — JSON file parameterizing the scenario (header +
      N accounts). Overrides the scenario `config` block; accounts are picked
      round-robin across runs.

  ## Keys (interactive/live mode)

    * `q`       — graceful shutdown: no new calls, wait for active ones
    * `Ctrl+D`  — immediate stop (prints the summary, then halts)
    * `↑ / ↓`   — scroll the call table when it exceeds the terminal height

  ## Logging

    * `--log-file PATH`   — log file path (default `elixipp.log`)
    * `--log-level LEVEL` — file log level: `debug` | `info` | `warning` | `error`
    * `--log-sequence`    — write a PlantUML sequence diagram (`<scenario>_<pid>.puml`)
      per scenario instance. Single-call only (rejected with `--limit > 1`).
  """
  require Logger

  @default_log_file "elixipp.log"
  @default_log_level :info

  # Call creation rate (calls per second) and its hard ceiling.
  @default_rate 2

  @max_rate 100

  # Grace period (ms) after a graceful stop before still-running calls that did
  # not honour the cooperative shutdown request are hard-killed.
  @shutdown_grace_ms 5_000

  # Table columns: {header, monitor_key, fixed_cell_width}
  @columns [
    {"Scénario", :scenario, 16},
    {"Compte", :account, 16},
    {"Commande", :command, 16},
    {"État", :state, 18},
    {"Événement", :event, 28}
  ]

  # Rows to reserve for the counter line, border, and status bar.
  @ui_overhead 6

  @spec main([String.t()]) :: no_return()
  def main(argv) do
    {opts, rest, _} =
      OptionParser.parse(argv,
        strict: [
          monitor: :boolean,
          limit: :integer,
          max_run: :integer,
          rate: :float,
          config: :string,
          log_file: :string,
          log_level: :string,
          log_sequence: :boolean,
          listen: :keep,
          local_port: :integer,
          local_addr: :string,
          help: :boolean
        ],
        aliases: [m: :monitor, l: :limit, c: :config, h: :help]
      )

    setup_logging(opts[:log_file], opts[:log_level])

    if opts[:help], do: print_help()

    arg =
      case rest do
        [a | _] ->
          a

        [] ->
          abort(
            "usage: elixipp [--monitor] [-l N] [--max-run N] [--rate N] [--log-file PATH] [--log-level LEVEL] <scenario.exs | ModuleName>",
            2
          )
      end

    module = resolve_module(arg)
    ext_config = load_config(opts[:config])
    limit = opts[:limit] || 1

    # Optional local UDP bind overrides (so a UAC can run on a host that already
    # has a UAS bound to 5060 — see the two-process REGISTER recipe in the README).
    apply_local_udp_opts(opts)

    # A server (UAS) scenario is driven by inbound requests, not by an outbound
    # spawn loop: switch to server mode and never return.
    case SIP.Scenario.Loader.scenario_type(module) do
      :uac -> :ok
      type -> run_server_mode(module, type, opts, limit)
    end

    # When neither --limit nor --max-run is given, default to a single one-shot
    # run (--limit 1 --max-run 1). As soon as either is set, --max-run stays
    # unlimited unless explicitly provided.
    max_run =
      case {opts[:limit], opts[:max_run]} do
        {nil, nil} -> 1
        {_, max} -> max
      end

    if limit < 1, do: abort("--limit must be >= 1", 2)
    if max_run != nil and max_run < 0, do: abort("--max-run must be >= 0", 2)

    # --log-sequence produces one PlantUML file per scenario instance, so it only
    # makes sense for a single simultaneous call. Reject it for parallel runs.
    case validate_log_sequence(opts, limit) do
      :ok ->
        if Keyword.get(opts, :log_sequence, false),
          do: Application.put_env(:elixip2, :log_sequence, true)

      {:error, msg} ->
        abort(msg, 2)
    end

    rate = resolve_rate(opts[:rate])
    spawn_interval_ms = round(1000 / rate)

    # The live/snapshot call table is shown only when --monitor is explicitly
    # requested. Parallel execution (-l N or a multi-run --max-run) still works
    # without it — it just runs silently and prints the final summary.
    monitor? = opts[:monitor] || false
    parallel? = monitor? or limit > 1 or max_run == nil or max_run > 1

    if parallel? do
      run_parallel(module, limit, max_run, spawn_interval_ms, rate, monitor?, ext_config)
    else
      # Single one-shot run: bootstrap the stack ourselves so we can inject the
      # external-config overrides for the first account (index 0).
      SIP.Scenario.Runner.bootstrap_stack()
      overrides = SIP.Scenario.ExternalConfig.overrides_for(ext_config, 0)

      case SIP.Scenario.Runner.run_instance(module, config_overrides: overrides) do
        :ok ->
          IO.puts("Scenario #{inspect(module)} succeeded.")
          System.halt(0)

        {:aborted, reason} ->
          IO.puts("Scenario #{inspect(module)} aborted: #{inspect(reason)}")
          System.halt(0)

        {:error, reason} ->
          IO.puts(:stderr, "Scenario #{inspect(module)} failed: #{inspect(reason)}")
          System.halt(1)
      end
    end
  end

  # ── Server (UAS) mode ─────────────────────────────────────────────────────

  @default_listen {:udp, :all, 5060}

  # Run elixipp as a SIP server: bring up the stack and the configured listeners,
  # register the scenario as the registration processing module, then block until
  # the operator stops the tool. `limit` caps the number of concurrent scenario
  # instances (REGISTER beyond it are rejected with 503). Never returns.
  @spec run_server_mode(module(), atom(), keyword(), pos_integer()) :: no_return()
  defp run_server_mode(module, :uas_register, opts, limit) do
    listeners = parse_listeners(opts)

    # Bind the UDP socket to the first UDP listener's address/port (one socket per
    # host for now — see phase 7). Done before bootstrap so the transport binds it.
    case Enum.find(listeners, fn {proto, _a, _p} -> proto == :udp end) do
      {:udp, addr, port} ->
        Application.put_env(:elixip2, :udp_local_port, port)
        if addr != :all, do: Application.put_env(:elixip2, :udp_local_addr, addr)

      _ ->
        :ok
    end

    SIP.Scenario.Runner.bootstrap_stack()

    {:ok, _pid} =
      Elixip.RegistrarUAS.start_link(scenario_module: module, max_instances: limit)

    :ok = SIP.Session.ConfigRegistry.set_registration_processing_module(Elixip.RegistrarUAS)

    started = start_listeners(listeners)

    # --monitor wires the same live call table as the UAC parallel mode. Without
    # it (or on a non-interactive stdin) we fall back to the plain text loop.
    if opts[:monitor] do
      run_server_monitored(module, limit, started)
    else
      print_server_header(module, limit, started)
      server_loop(module)
    end
  end

  defp run_server_mode(_module, type, _opts, _limit) do
    abort("Type de scénario serveur non supporté : #{inspect(type)}", 2)
  end

  defp print_server_header(module, limit, started) do
    IO.puts("elixipp — mode serveur UAS Register (#{inspect(module)})")
    IO.puts("  instances max : #{limit}")
    IO.puts("  listeners     : #{format_listeners(started)}")
    IO.puts("  (tapez 'q' puis Entrée pour arrêter)")
  end

  # Live monitored server loop: bring up Owl + the monitor, render the call table
  # in a live block and react to the keyboard (q / Ctrl+D / arrows). On a
  # non-interactive stdin the live table is impossible, so we degrade to the plain
  # text server loop. Never returns.
  @spec run_server_monitored(module(), pos_integer(), list()) :: no_return()
  defp run_server_monitored(module, limit, started) do
    {:ok, _} = Application.ensure_all_started(:owl)
    {:ok, _} = SIP.Scenario.Monitor.start()

    if match?({:ok, _}, :io.rows()) do
      raw? = setup_raw_terminal(true)

      Owl.LiveScreen.add_block(:display,
        state: {0, :none},
        render: fn {scroll, shutdown} -> render_server_block(scroll, shutdown, module, limit, started) end
      )

      start_input_reader(self())
      server_monitor_loop(%{scroll_offset: 0, raw?: raw?, shutdown: :none, module: module})
    else
      print_server_header(module, limit, started)
      server_loop(module)
    end
  end

  @spec server_monitor_loop(map()) :: no_return()
  defp server_monitor_loop(state) do
    receive do
      :graceful_stop when state.shutdown == :none ->
        Elixip.RegistrarUAS.shutdown_all(:elixipp_graceful)
        state = %{state | shutdown: :graceful}
        Owl.LiveScreen.update(:display, {state.scroll_offset, state.shutdown})
        # If no instance was active, exit right away.
        if Elixip.RegistrarUAS.stats().active == 0 do
          server_monitor_halt(state)
        else
          server_monitor_loop(state)
        end

      :graceful_stop ->
        # Already draining — ignore.
        server_monitor_loop(state)

      :force_quit ->
        server_monitor_halt(state)

      :arrow_up ->
        state = %{state | scroll_offset: max(0, state.scroll_offset - 1)}
        Owl.LiveScreen.update(:display, {state.scroll_offset, state.shutdown})
        server_monitor_loop(state)

      :arrow_down ->
        total = length(SIP.Scenario.Monitor.calls())
        max_scroll = max(0, total - visible_rows())
        state = %{state | scroll_offset: min(max_scroll, state.scroll_offset + 1)}
        Owl.LiveScreen.update(:display, {state.scroll_offset, state.shutdown})
        server_monitor_loop(state)

      _ ->
        server_monitor_loop(state)
    after
      500 ->
        Owl.LiveScreen.update(:display, {state.scroll_offset, state.shutdown})

        if state.shutdown == :graceful and Elixip.RegistrarUAS.stats().active == 0 do
          server_monitor_halt(state)
        else
          server_monitor_loop(state)
        end
    end
  end

  defp server_monitor_halt(state) do
    Owl.LiveScreen.update(:display, {state.scroll_offset, state.shutdown})
    Owl.LiveScreen.flush()
    restore_terminal(state.raw?)
    IO.puts("\r\nServeur arrêté.")
    print_uas_summary(state.module)
    System.halt(0)
  end

  defp drain_uas_instances do
    if Elixip.RegistrarUAS.stats().active > 0 do
      Process.sleep(200)
      drain_uas_instances()
    end
  end

  defp print_uas_summary(module) do
    %{
      total_started: total,
      total_succeeded: succ,
      total_aborted: aborted,
      total_failed: failed
    } = Elixip.RegistrarUAS.stats()

    IO.puts("══ Résumé ══════════════════")
    IO.puts("  Scénario    : #{inspect(module)}")
    IO.puts("  Total       : #{total}")
    IO.puts("  Succès      : #{succ}")
    IO.puts("  Interrompus : #{aborted}")
    IO.puts("  Échecs      : #{failed}")
    IO.puts("════════════════════════════")
  end

  defp render_server_block(scroll, shutdown, module, limit, started) do
    [
      render_server_counters(shutdown, module, limit, started),
      "\n",
      render_table(scroll, true)
    ]
  end

  defp render_server_counters(shutdown, module, limit, started) do
    active = length(SIP.Scenario.Monitor.calls())

    hint =
      case shutdown do
        :none -> "  [q+Entrée: arrêt propre | Ctrl+D: immédiat | ↑↓: défile]"
        :graceful -> "  [arrêt en cours… | Ctrl+D: forcer]"
      end

    line =
      "  Serveur UAS #{inspect(module)}" <>
        "  |  Instances: #{active}/#{limit}" <>
        "  |  Listeners: #{format_listeners(started)}" <>
        hint

    Owl.Data.tag(line, :cyan)
  end

  # Parse repeated --listen options ("proto:port") into {proto, :all, port}
  # triplets. Falls back to the default UDP:5060 listener when none is given.
  @spec parse_listeners(keyword()) :: [{atom(), :all | tuple(), pos_integer()}]
  defp parse_listeners(opts) do
    case Keyword.get_values(opts, :listen) do
      [] -> [@default_listen]
      specs -> Enum.map(specs, &parse_listen_spec/1)
    end
  end

  defp parse_listen_spec(spec) do
    case String.split(spec, ":") do
      [proto, port] ->
        {parse_proto(proto), :all, parse_port(port)}

      [proto, addr, port] ->
        {parse_proto(proto), parse_addr(addr), parse_port(port)}

      _ ->
        abort("--listen invalide : #{inspect(spec)} (attendu proto:port ou proto:addr:port)", 2)
    end
  end

  defp parse_addr(addr) do
    case SIP.NetUtils.parse_address(addr) do
      {:ok, ip} -> ip
      _ -> abort("--listen : adresse IP invalide #{inspect(addr)}", 2)
    end
  end

  # Apply --local-port / --local-addr to the application env (read by the UDP
  # transport when it binds its socket).
  defp apply_local_udp_opts(opts) do
    if port = opts[:local_port], do: Application.put_env(:elixip2, :udp_local_port, port)

    case opts[:local_addr] do
      nil -> :ok
      addr -> Application.put_env(:elixip2, :udp_local_addr, parse_addr(addr))
    end
  end

  defp parse_proto(proto) do
    case String.downcase(proto) do
      p when p in ["udp", "tcp", "tls", "wss"] -> String.to_atom(p)
      _ -> abort("--listen : protocole inconnu #{inspect(proto)} (udp|tcp|tls|wss)", 2)
    end
  end

  defp parse_port(port) do
    case Integer.parse(port) do
      {n, ""} when n > 0 and n <= 65535 -> n
      _ -> abort("--listen : port invalide #{inspect(port)}", 2)
    end
  end

  # Start the configured listeners. Only UDP is wired in this MVP (it reuses the
  # bidirectional SIP.Transport.UDP instance); connected transports (TCP/TLS/WSS)
  # are not implemented yet and are reported as skipped.
  defp start_listeners(listeners) do
    Enum.map(listeners, fn
      {:udp, addr, port} = l ->
        case GenServer.start(SIP.Transport.UDP, {addr, port}) do
          {:ok, _pid} -> {l, :ok}
          {:error, reason} -> {l, {:error, reason}}
        end

      {proto, _addr, _port} = l when proto in [:tcp, :tls, :wss] ->
        {l, :not_implemented}
    end)
  end

  defp format_listeners(started) do
    started
    |> Enum.map(fn {{proto, addr, port}, status} ->
      a = if addr == :all, do: "*", else: inspect(addr)
      "#{proto}:#{a}:#{port} (#{inspect(status)})"
    end)
    |> Enum.join(", ")
  end

  # Block the main process until the operator types 'q' (or stdin reaches EOF on a
  # non-interactive run, in which case we simply park forever).
  @spec server_loop(module()) :: no_return()
  defp server_loop(module) do
    case IO.gets("") do
      :eof ->
        Process.sleep(:infinity)

      {:error, _} ->
        Process.sleep(:infinity)

      line when is_binary(line) ->
        if String.trim(line) == "q" do
          IO.puts("Arrêt propre en cours — attente des instances actives…")
          Elixip.RegistrarUAS.shutdown_all(:elixipp_graceful)
          drain_uas_instances()
          IO.puts("Serveur arrêté.")
          print_uas_summary(module)
          System.halt(0)
        else
          server_loop(module)
        end
    end
  end

  # Load and validate the external JSON config, aborting with a clear message on
  # any error. Returns nil when no --config was given.
  defp load_config(nil), do: nil

  defp load_config(path) do
    SIP.Scenario.ExternalConfig.load!(path)
  rescue
    e -> abort(Exception.message(e), 2)
  end

  # ── Parallel / monitored execution ──────────────────────────────────────────

  # Resolve the call creation rate (calls/s). Values <= 0 or above @max_rate
  # are ignored and fall back to the default rate.
  @doc false
  # --log-sequence requires a single simultaneous call (--limit 1): one PlantUML
  # file is written per instance, which would interleave/clobber across parallel
  # calls. Returns :ok or {:error, message}.
  @spec validate_log_sequence(keyword(), integer()) :: :ok | {:error, String.t()}
  def validate_log_sequence(opts, limit) do
    if Keyword.get(opts, :log_sequence, false) and limit > 1 do
      {:error, "--log-sequence n'est utilisable qu'avec un seul appel simultané (--limit 1)"}
    else
      :ok
    end
  end

  defp resolve_rate(nil), do: @default_rate

  defp resolve_rate(rate) when rate > 0 and rate <= @max_rate, do: rate

  defp resolve_rate(rate) do
    IO.puts(
      :stderr,
      "--rate #{rate} ignoré (autorisé : 0 < rate <= #{@max_rate}), utilisation de #{@default_rate}"
    )

    @default_rate
  end

  defp run_parallel(module, limit, max_run, spawn_interval_ms, rate, monitor?, ext_config) do
    {:ok, _} = Application.ensure_all_started(:owl)
    {:ok, _} = SIP.Scenario.Monitor.start()
    SIP.Scenario.Runner.bootstrap_stack()

    # Keyboard control (q / Ctrl+D) needs an interactive terminal; the live table
    # additionally needs --monitor. On a piped/non-tty stdin we read nothing, so
    # an immediate EOF can't be mistaken for Ctrl+D.
    interactive? = match?({:ok, _}, :io.rows())
    live? = monitor? and interactive?
    raw? = setup_raw_terminal(live?)

    if live? do
      Owl.LiveScreen.add_block(:display,
        state: initial_block_state(),
        render: fn bs -> render_block(bs, limit, max_run) end
      )
    end

    state = %{
      module: module,
      ext_config: ext_config,
      limit: limit,
      max_run: max_run,
      rate: rate,
      spawn_interval_ms: spawn_interval_ms,
      # monotonic ms of the last spawn, nil before the first
      last_spawn: nil,
      monitor?: monitor?,
      live?: live?,
      raw?: raw?,
      # slot_id => {pid, mon_ref}
      slots: %{},
      total_started: 0,
      total_succeeded: 0,
      total_aborted: 0,
      total_failed: 0,
      scroll_offset: 0,
      # :none | :graceful
      shutdown: :none
    }

    if interactive?, do: start_input_reader(self())

    state =
      Enum.reduce(1..limit, state, fn slot_id, acc ->
        if can_start?(acc), do: spawn_slot(acc, slot_id), else: acc
      end)

    state = parallel_loop(state)

    cond do
      live? ->
        # The live block already holds the final table; flushing leaves one copy
        # on screen. Printing render_table_plain on top would duplicate it.
        Owl.LiveScreen.update(:display, block_state(state))
        Owl.LiveScreen.flush()
        restore_terminal(raw?)

      monitor? ->
        # --monitor without an interactive terminal (piped / CI): final snapshot.
        restore_terminal(raw?)
        IO.puts("")
        IO.puts(render_table_plain(state))

      true ->
        # No --monitor: run silently, no table at all.
        restore_terminal(raw?)
    end

    print_summary(state)
    System.halt(if state.total_failed > 0, do: 1, else: 0)
  end

  # ── Slot lifecycle ───────────────────────────────────────────────────────────

  defp spawn_slot(state, slot_id) do
    state = throttle(state)
    SIP.Scenario.Monitor.clear(slot_id)
    parent = self()

    # Pick the account on the monotonic spawn counter (not slot_id, which is
    # recycled): accounts cycle round-robin across successive runs. [] when no
    # --config, so run_instance behaves exactly as before.
    overrides = SIP.Scenario.ExternalConfig.overrides_for(state.ext_config, state.total_started)

    {pid, mon_ref} =
      spawn_monitor(fn ->
        Process.put(:scenario_slot_id, slot_id)
        result = SIP.Scenario.Runner.run_instance(state.module, config_overrides: overrides)
        send(parent, {:slot_done, slot_id, result})
      end)

    %{
      state
      | slots: Map.put(state.slots, slot_id, {pid, mon_ref}),
        total_started: state.total_started + 1
    }
  end

  # Enforce the minimum delay between two call creations (1000 / rate ms).
  # Sleeps only for the remaining time so an idle gap doesn't add latency.
  defp throttle(%{last_spawn: nil} = state) do
    %{state | last_spawn: System.monotonic_time(:millisecond)}
  end

  defp throttle(%{last_spawn: last, spawn_interval_ms: interval} = state) do
    wait = interval - (System.monotonic_time(:millisecond) - last)
    if wait > 0, do: Process.sleep(wait)
    %{state | last_spawn: System.monotonic_time(:millisecond)}
  end

  defp can_start?(state) do
    state.shutdown == :none and
      (state.max_run == nil or state.total_started < state.max_run)
  end

  defp maybe_spawn_next(state, freed_slot_id) do
    if can_start?(state), do: spawn_slot(state, freed_slot_id), else: state
  end

  # ── Main receive loop ────────────────────────────────────────────────────────

  defp parallel_loop(state) do
    if done?(state) do
      state
    else
      receive do
        {:slot_done, slot_id, result} ->
          state = handle_slot_done(state, slot_id, result)
          push_display(state)
          parallel_loop(state)

        {:DOWN, mon_ref, :process, _pid, reason} when reason != :normal ->
          state = handle_slot_crash(state, mon_ref, reason)
          push_display(state)
          parallel_loop(state)

        # Normal exit: already handled by :slot_done — ignore the :DOWN.
        {:DOWN, _mon_ref, :process, _pid, :normal} ->
          parallel_loop(state)

        :graceful_stop ->
          handle_graceful_stop(state)

        :force_quit ->
          handle_force_quit(state)

        :shutdown_deadline ->
          # Grace period elapsed after a graceful stop: hard-kill any leftover.
          Enum.each(state.slots, fn {_sid, {pid, _ref}} -> Process.exit(pid, :kill) end)
          parallel_loop(state)

        :arrow_up ->
          state = %{state | scroll_offset: max(0, state.scroll_offset - 1)}
          push_display(state)
          parallel_loop(state)

        :arrow_down ->
          state = scroll_down(state)
          push_display(state)
          parallel_loop(state)
      after
        200 ->
          push_display(state)
          parallel_loop(state)
      end
    end
  end

  # Done when all slots are empty AND we will never start new ones.
  defp done?(%{slots: slots} = state) do
    slots == %{} and (state.shutdown != :none or not can_start?(state))
  end

  defp handle_slot_done(state, slot_id, result) do
    state = %{state | slots: Map.delete(state.slots, slot_id)}

    state =
      case result do
        :ok -> %{state | total_succeeded: state.total_succeeded + 1}
        {:aborted, _} -> %{state | total_aborted: state.total_aborted + 1}
        {:error, _} -> %{state | total_failed: state.total_failed + 1}
      end

    maybe_spawn_next(state, slot_id)
  end

  defp handle_slot_crash(state, mon_ref, reason) do
    case Enum.find(state.slots, fn {_sid, {_pid, mref}} -> mref == mon_ref end) do
      {slot_id, _} ->
        Logger.warning("Slot #{slot_id} crashed: #{inspect(reason)}")

        state = %{
          state
          | slots: Map.delete(state.slots, slot_id),
            total_failed: state.total_failed + 1
        }

        maybe_spawn_next(state, slot_id)

      nil ->
        state
    end
  end

  # 'q' requests a graceful shutdown: stop starting new calls and wait for the
  # active ones. Immediate stop is Ctrl+D — SIGINT (Ctrl+C) cannot be trapped by
  # the Erlang runtime, so it is not used here.
  defp handle_graceful_stop(state) do
    case state.shutdown do
      :none ->
        IO.write(
          "\r\n[q] Arrêt propre — plus de nouveaux appels, demande d'arrêt aux actifs (Ctrl+D pour forcer).\r\n"
        )

        # Ask every active call to wind down cooperatively, and arm a deadline to
        # hard-kill any that ignores the request (e.g. stuck outside on_events).
        Enum.each(state.slots, fn {_sid, {pid, _ref}} ->
          send(pid, {:scenario_ctl, :shutdown, :elixipp_graceful})
        end)

        Process.send_after(self(), :shutdown_deadline, @shutdown_grace_ms)
        state = %{state | shutdown: :graceful}
        push_display(state)
        if done?(state), do: state, else: parallel_loop(state)

      _ ->
        # Already shutting down gracefully — nothing more to do.
        if done?(state), do: state, else: parallel_loop(state)
    end
  end

  # Ctrl+D (or EOF / Ctrl+C in raw mode): stop everything right now, whatever is
  # still in flight, and print the summary before halting.
  defp handle_force_quit(state) do
    IO.write("\r\n[Ctrl+D] Arrêt immédiat.\r\n")
    restore_terminal(state.raw?)
    print_summary(state)
    System.halt(1)
  end

  defp scroll_down(state) do
    max_scroll = max(0, state.limit - visible_rows())
    %{state | scroll_offset: min(max_scroll, state.scroll_offset + 1)}
  end

  # ── Display ──────────────────────────────────────────────────────────────────

  defp push_display(%{live?: true} = state) do
    Owl.LiveScreen.update(:display, block_state(state))
  end

  defp push_display(_state), do: :ok

  defp initial_block_state, do: {0, 0, 0, 0, 0, 0, :none}

  defp block_state(state) do
    {state.scroll_offset, map_size(state.slots), state.total_started, state.total_succeeded,
     state.total_aborted, state.total_failed, state.shutdown}
  end

  defp render_block({scroll, active, total, succ, aborted, fail, shutdown}, limit, max_run) do
    [
      render_counters(active, total, succ, aborted, fail, limit, max_run, shutdown),
      "\n",
      render_table(scroll, true)
    ]
  end

  defp render_table_plain(_state) do
    case SIP.Scenario.Monitor.calls() do
      [] ->
        "(aucun appel)"

      calls ->
        calls
        |> Enum.map(&display_row(&1, false))
        |> Owl.Table.new(border_style: :solid_rounded, sort_columns: &column_order/2)
        |> Owl.Data.to_chardata()
        |> IO.chardata_to_string()
    end
  end

  defp render_table(scroll, colorize?) do
    max_vis = visible_rows()
    calls = SIP.Scenario.Monitor.calls()
    total = length(calls)
    visible = Enum.slice(calls, scroll, max_vis)

    case visible do
      [] ->
        "(aucun appel actif)"

      rows ->
        table =
          rows
          |> Enum.map(&display_row(&1, colorize?))
          |> Owl.Table.new(border_style: :solid_rounded, sort_columns: &column_order/2)

        if total > max_vis do
          [table, "\n  ↑↓  lignes #{scroll + 1}–#{min(scroll + max_vis, total)}/#{total}"]
        else
          table
        end
    end
  end

  defp render_counters(active, total, succ, aborted, fail, limit, max_run, shutdown) do
    max_str = if max_run, do: "/#{max_run}", else: ""

    shutdown_hint =
      case shutdown do
        :none -> "  [q: arrêt propre | Ctrl+D: immédiat]"
        _ -> "  [Ctrl+D: arrêt immédiat]"
      end

    line =
      "  Actifs: #{active}/#{limit}" <>
        "  |  Succès: #{succ}" <>
        "  |  Interrompus: #{aborted}" <>
        "  |  Échecs: #{fail}" <>
        "  |  Total: #{total}#{max_str}" <>
        shutdown_hint

    Owl.Data.tag(line, :cyan)
  end

  defp print_summary(state) do
    IO.puts("══ Résumé ══════════════════")
    IO.puts("  Scénario : #{inspect(state.module)}")
    IO.puts("  Rate     : #{state.rate} appels/s")
    IO.puts("  Total    : #{state.total_started}")
    IO.puts("  Succès   : #{state.total_succeeded}")
    IO.puts("  Interrompus : #{state.total_aborted}")
    IO.puts("  Échecs   : #{state.total_failed}")
    IO.puts("════════════════════════════")
  end

  defp visible_rows do
    case :io.rows() do
      {:ok, rows} -> max(5, rows - @ui_overhead)
      _ -> 20
    end
  end

  # ── Input reader (q = graceful, Ctrl+D = immediate, arrow keys) ───────────────

  defp start_input_reader(parent) do
    spawn(fn -> input_loop(parent, :standard_io) end)
  end

  defp input_loop(parent, io) do
    case read_byte(io) do
      :eof ->
        # Ctrl+D (EOF in cooked mode) or a closed stdin → immediate stop. No loop:
        # we force-quit, and looping would spin on a persistently-closed stream.
        send(parent, :force_quit)

      <<4>> ->
        # Ctrl+D (EOT) in raw mode → immediate stop.
        send(parent, :force_quit)

      <<3>> ->
        # Ctrl+C in raw mode → immediate stop.
        send(parent, :force_quit)

      <<c>> when c in [?q, ?Q] ->
        # 'q' → graceful shutdown (no new calls, wait for the active ones).
        send(parent, :graceful_stop)
        input_loop(parent, io)

      <<27>> ->
        # ESC prefix: read the rest of the ANSI sequence
        case {read_byte(io), read_byte(io)} do
          {<<"[">>, <<"A">>} -> send(parent, :arrow_up)
          {<<"[">>, <<"B">>} -> send(parent, :arrow_down)
          _ -> :ok
        end

        input_loop(parent, io)

      _ ->
        input_loop(parent, io)
    end
  end

  defp read_byte(io) do
    case :file.read(io, 1) do
      {:ok, byte} -> byte
      :eof -> :eof
      {:error, _} -> :eof
    end
  end

  # ── Raw terminal setup / teardown ────────────────────────────────────────────

  # Redirect from /dev/tty: System.cmd gives the spawned stty its own stdin pipe,
  # not our terminal, so a bare `stty raw` is a no-op and Ctrl+D keeps arriving
  # as EOF instead of byte 4. `</dev/tty` makes stty act on the real terminal.
  defp setup_raw_terminal(true) do
    case System.cmd("sh", ["-c", "stty raw -echo </dev/tty"], stderr_to_stdout: true) do
      {_, 0} -> true
      _ -> false
    end
  end

  defp setup_raw_terminal(false), do: false

  defp restore_terminal(true),
    do: System.cmd("sh", ["-c", "stty sane </dev/tty"], stderr_to_stdout: true)

  defp restore_terminal(false), do: :ok

  # ── Row rendering ─────────────────────────────────────────────────────────────

  defp display_row(call, colorize?) do
    Map.new(@columns, fn {header, key, width} ->
      {header, cell(call, key, width, colorize?)}
    end)
  end

  defp cell(call, :command, width, true),
    do: Owl.Data.tag(fit(call[:command], width), color_for(call[:command_type]))

  defp cell(call, :event, width, true),
    do: Owl.Data.tag(fit(call[:event], width), color_for(call[:event_type]))

  defp cell(call, :state, width, true) do
    case state_color(call[:state]) do
      nil -> fit(call[:state], width)
      color -> Owl.Data.tag(fit(call[:state], width), color)
    end
  end

  defp cell(call, key, width, _colorize?), do: fit(Map.get(call, key, ""), width)

  defp state_color("succeeded"), do: :green
  defp state_color("failed"), do: :red
  defp state_color(_), do: nil

  defp color_for(:sip), do: :light_green
  defp color_for(:media), do: IO.ANSI.color(214)
  defp color_for(_), do: :light_blue

  defp fit(value, width) do
    s = to_string(value)

    if String.length(s) > width do
      String.slice(s, 0, width - 1) <> "…"
    else
      String.pad_trailing(s, width)
    end
  end

  defp column_order(a, b), do: column_rank(a) <= column_rank(b)

  defp column_rank(header) do
    Enum.find_index(@columns, fn {h, _key, _width} -> h == header end) || length(@columns)
  end

  # ── Module resolution ─────────────────────────────────────────────────────────

  defp resolve_module(arg) do
    if String.ends_with?(arg, ".exs") do
      unless File.exists?(arg), do: abort("Scenario file not found: #{arg}", 2)
      SIP.Scenario.Loader.load_file!(arg)
    else
      SIP.Scenario.Loader.load_module!(arg)
    end
  end

  # ── Logging setup ─────────────────────────────────────────────────────────────

  defp setup_logging(log_file, log_level) do
    _ = Application.ensure_all_started(:logger)
    _ = Application.ensure_all_started(:logger_file_backend)

    log_file = log_file || @default_log_file
    file_level = parse_level(log_level)

    Logger.configure(level: file_level)

    backend = {LoggerFileBackend, :elixipp_log}
    Logger.add_backend(backend)

    Logger.configure_backend(backend,
      path: log_file,
      level: file_level,
      format: "$time [$level] $message\n",
      metadata: [:module, :pid]
    )

    quiet_console()
    :ok
  end

  defp quiet_console do
    try do
      Logger.configure_backend(:console, level: :warning)
    catch
      _, _ -> :ok
    end

    try do
      :logger.set_handler_config(:default, :level, :warning)
    catch
      _, _ -> :ok
    end

    :ok
  end

  defp parse_level(nil), do: @default_log_level

  defp parse_level(value) do
    case String.downcase(value) do
      "debug" ->
        :debug

      "info" ->
        :info

      "warn" ->
        :warning

      "warning" ->
        :warning

      "error" ->
        :error

      other ->
        IO.puts(:stderr, "Unknown --log-level #{inspect(other)}, using #{@default_log_level}")
        @default_log_level
    end
  end

  defp abort(message, code) do
    IO.puts(:stderr, message)
    System.halt(code)
  end

  defp print_help do
    IO.puts("""
    elixipp — outil de test de scénarios SIP

    USAGE
      elixipp [OPTIONS] <scenario.exs | NomDeModule>

    EXEMPLES
      elixipp scenarios/uac_invite.exs            # depuis un fichier
      elixipp UAC.Invite                          # scénario intégré (sans fichier)
      elixipp UAC.Register                        # scénario intégré (sans fichier)
      elixipp -m scenarios/uac_invite.exs         # affichage live d'un appel
      elixipp -l 5 scenarios/uac_invite.exs       # 5 appels en continu
      elixipp -l 5 --max-run 100 scenarios/uac_invite.exs   # 5 simultanés, 100 au total
      elixipp -l 5 --rate 20 scenarios/uac_invite.exs       # 5 simultanés, 20 appels/s max
      elixipp -c ives.json scenarios/uac_register.exs       # paramétré par un fichier JSON
      elixipp -c accounts.json --max-run 0 scenarios/uac_register.exs  # balaye tous les comptes
      elixipp --listen udp:5060 scenarios/uas_register.exs  # serveur registrar UAS (UDP)
      elixipp -l 50 --listen udp:5060 scenarios/uas_register.exs  # serveur, 50 enregistrements max

    OPTIONS
      -m, --monitor      Affiche un tableau live des appels en cours.
      -l, --limit N      Lance N appels simultanés.
                         Sans --max-run, les slots sont recyclés indéfiniment.
      --max-run N        Arrête après N exécutions au total.
      -c, --config FILE  Fichier JSON paramétrant le scénario : entête (domain,
                         proxyuri, proxyusesrv, optionkeepaliveperiod) + N comptes
                         {username, password, domain}. Surcharge le bloc config du
                         scénario. Les comptes sont tirés en round-robin sur les
                         exécutions (avec --limit 1, utilisez --max-run pour tous
                         les parcourir).
      --rate N           Nombre d'appels créés par seconde (défaut : 10, max : 100).
                         Espace la création de chaque nouvel appel de 1000/N ms.
                         Les valeurs > 100 sont ignorées (retour au défaut).
      --listen PROTO:PORT  (mode serveur) Écoute les requêtes entrantes sur ce
      --listen PROTO:ADDR:PORT  protocole/port (ADDR optionnel pour fixer l'IP
                         locale annoncée). Répétable. Protocoles : udp (tcp|tls|wss
                         à venir). Défaut si absent : udp:5060.
      --local-port PORT  (mode client) Port UDP local à utiliser pour émettre
                         (défaut 5060). Permet de lancer un UAC sur une machine qui
                         héberge déjà un UAS sur 5060 (test deux-process en local).
      --local-addr ADDR  (mode client) IP locale annoncée dans Via/Contact.
      --log-file PATH    Chemin du fichier de log (défaut : elixipp.log).
      --log-level LEVEL  Niveau : debug | info | warning | error (défaut : debug).
      --log-sequence     Écrit un diagramme de séquence PlantUML par instance de
                         scénario (<scenario>_<pid>.puml). Réservé à un seul appel
                         simultané (refusé avec --limit > 1). Équivaut à activer le
                         flag debug du scénario (ctx_set(:debug, true)).
      -h, --help         Affiche cette aide.

    Sans --limit ni --max-run, comportement équivalent à --limit 1 --max-run 1
    (un seul appel, une seule exécution).

    SCÉNARIOS
      L'argument est soit un chemin vers un fichier .exs, soit le nom d'un
      scénario intégré (compilé dans l'exécutable) : UAC.Invite, UAC.Register.
      Les scénarios intégrés ne nécessitent aucun fichier sur la machine.

    TOUCHES (mode live)
      q                  Arrêt propre : plus de nouveaux appels, attend les actifs.
      Ctrl+D             Arrêt immédiat (affiche le résumé puis quitte).
      ↑ / ↓              Défile le tableau quand il dépasse la hauteur du terminal.

    Code de sortie : 0 si aucun échec, 1 sinon.
    """)

    System.halt(0)
  end
end
