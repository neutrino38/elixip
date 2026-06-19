defmodule Elixipp.CLI do
  @moduledoc """
  Entry point of the standalone `elixipp` executable (built with `mix escript.build`).

      elixipp scenarios/my_call.exs
      elixipp --monitor -l 5 scenarios/my_call.exs
      elixipp --monitor -l 5 --max-run 100 scenarios/my_call.exs

  ## Options

    * `--monitor` / `-m`   — live table of calls in progress
    * `--limit N` / `-l N` — run N calls simultaneously (implies --monitor)
    * `--max-run N`        — stop after N total executions (default: unlimited)
    * `--rate N`           — calls started per second (default: 10, max: 100)

  ## Keys (interactive/live mode)

    * `q`       — graceful shutdown: no new calls, wait for active ones
    * `Ctrl+D`  — immediate stop (prints the summary, then halts)
    * `↑ / ↓`   — scroll the call table when it exceeds the terminal height

  ## Logging

    * `--log-file PATH`   — log file path (default `elixipp.log`)
    * `--log-level LEVEL` — file log level: `debug` | `info` | `warning` | `error`
  """
  require Logger

  @default_log_file "elixipp.log"
  @default_log_level :info

  # Call creation rate (calls per second) and its hard ceiling.
  @default_rate 2

  @max_rate 100

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
          log_file: :string,
          log_level: :string,
          help: :boolean
        ],
        aliases: [m: :monitor, l: :limit, h: :help]
      )

    setup_logging(opts[:log_file], opts[:log_level])

    if opts[:help], do: print_help()

    arg =
      case rest do
        [a | _] -> a
        [] -> abort("usage: elixipp [--monitor] [-l N] [--max-run N] [--rate N] [--log-file PATH] [--log-level LEVEL] <scenario.exs | ModuleName>", 2)
      end

    module = resolve_module(arg)
    limit = opts[:limit] || 1

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

    rate = resolve_rate(opts[:rate])
    spawn_interval_ms = round(1000 / rate)

    # The live/snapshot call table is shown only when --monitor is explicitly
    # requested. Parallel execution (-l N or a multi-run --max-run) still works
    # without it — it just runs silently and prints the final summary.
    monitor? = opts[:monitor] || false
    parallel? = monitor? or limit > 1 or max_run == nil or max_run > 1

    if parallel? do
      run_parallel(module, limit, max_run, spawn_interval_ms, rate, monitor?)
    else
      case module.run(true) do
        :ok ->
          IO.puts("Scenario #{inspect(module)} succeeded.")
          System.halt(0)

        {:error, reason} ->
          IO.puts(:stderr, "Scenario #{inspect(module)} failed: #{inspect(reason)}")
          System.halt(1)
      end
    end
  end

  # ── Parallel / monitored execution ──────────────────────────────────────────

  # Resolve the call creation rate (calls/s). Values <= 0 or above @max_rate
  # are ignored and fall back to the default rate.
  defp resolve_rate(nil), do: @default_rate

  defp resolve_rate(rate) when rate > 0 and rate <= @max_rate, do: rate

  defp resolve_rate(rate) do
    IO.puts(:stderr, "--rate #{rate} ignoré (autorisé : 0 < rate <= #{@max_rate}), utilisation de #{@default_rate}")
    @default_rate
  end

  defp run_parallel(module, limit, max_run, spawn_interval_ms, rate, monitor?) do
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
      limit: limit,
      max_run: max_run,
      rate: rate,
      spawn_interval_ms: spawn_interval_ms,
      last_spawn: nil,       # monotonic ms of the last spawn, nil before the first
      monitor?: monitor?,
      live?: live?,
      raw?: raw?,
      slots: %{},            # slot_id => mon_ref
      total_started: 0,
      total_succeeded: 0,
      total_failed: 0,
      scroll_offset: 0,
      shutdown: :none        # :none | :graceful
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

    {_pid, mon_ref} =
      spawn_monitor(fn ->
        Process.put(:scenario_slot_id, slot_id)
        result = SIP.Scenario.Runner.run_instance(state.module)
        send(parent, {:slot_done, slot_id, result})
      end)

    %{state |
      slots: Map.put(state.slots, slot_id, mon_ref),
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
        {:error, _} -> %{state | total_failed: state.total_failed + 1}
      end
    maybe_spawn_next(state, slot_id)
  end

  defp handle_slot_crash(state, mon_ref, reason) do
    case Enum.find(state.slots, fn {_sid, mref} -> mref == mon_ref end) do
      {slot_id, _} ->
        Logger.warning("Slot #{slot_id} crashed: #{inspect(reason)}")
        state = %{state |
          slots: Map.delete(state.slots, slot_id),
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
        IO.write("\r\n[q] Arrêt propre — plus de nouveaux appels (Ctrl+D pour forcer).\r\n")
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

  defp initial_block_state, do: {0, 0, 0, 0, 0, :none}

  defp block_state(state) do
    {state.scroll_offset, map_size(state.slots),
     state.total_started, state.total_succeeded, state.total_failed, state.shutdown}
  end

  defp render_block({scroll, active, total, succ, fail, shutdown}, limit, max_run) do
    [render_counters(active, total, succ, fail, limit, max_run, shutdown), "\n",
     render_table(scroll, true)]
  end

  defp render_table_plain(_state) do
    case SIP.Scenario.Monitor.calls() do
      [] -> "(aucun appel)"
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

  defp render_counters(active, total, succ, fail, limit, max_run, shutdown) do
    max_str = if max_run, do: "/#{max_run}", else: ""

    shutdown_hint =
      case shutdown do
        :none -> "  [q: arrêt propre | Ctrl+D: immédiat]"
        _ -> "  [Ctrl+D: arrêt immédiat]"
      end

    line =
      "  Actifs: #{active}/#{limit}" <>
      "  |  Succès: #{succ}" <>
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
    spawn(fn -> input_loop(parent) end)
  end

  defp input_loop(parent) do
    case read_byte() do
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
        input_loop(parent)

      <<27>> ->
        # ESC prefix: read the rest of the ANSI sequence
        case {read_byte(), read_byte()} do
          {<<"[">>, <<"A">>} -> send(parent, :arrow_up)
          {<<"[">>, <<"B">>} -> send(parent, :arrow_down)
          _ -> :ok
        end
        input_loop(parent)

      _ ->
        input_loop(parent)
    end
  end

  defp read_byte do
    case :file.read(:standard_io, 1) do
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
      "debug" -> :debug
      "info" -> :info
      "warn" -> :warning
      "warning" -> :warning
      "error" -> :error
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
      elixipp scenarios/uac_invite.exs            # un seul appel
      elixipp UAC.Invite                          # par nom de module
      elixipp -m scenarios/uac_invite.exs         # affichage live d'un appel
      elixipp -l 5 scenarios/uac_invite.exs       # 5 appels en continu
      elixipp -l 5 --max-run 100 scenarios/uac_invite.exs   # 5 simultanés, 100 au total
      elixipp -l 5 --rate 20 scenarios/uac_invite.exs       # 5 simultanés, 20 appels/s max

    OPTIONS
      -m, --monitor      Affiche un tableau live des appels en cours.
      -l, --limit N      Lance N appels simultanés.
                         Sans --max-run, les slots sont recyclés indéfiniment.
      --max-run N        Arrête après N exécutions au total.
      --rate N           Nombre d'appels créés par seconde (défaut : 10, max : 100).
                         Espace la création de chaque nouvel appel de 1000/N ms.
                         Les valeurs > 100 sont ignorées (retour au défaut).
      --log-file PATH    Chemin du fichier de log (défaut : elixipp.log).
      --log-level LEVEL  Niveau : debug | info | warning | error (défaut : debug).
      -h, --help         Affiche cette aide.

    Sans --limit ni --max-run, comportement équivalent à --limit 1 --max-run 1
    (un seul appel, une seule exécution).

    TOUCHES (mode live)
      q                  Arrêt propre : plus de nouveaux appels, attend les actifs.
      Ctrl+D             Arrêt immédiat (affiche le résumé puis quitte).
      ↑ / ↓              Défile le tableau quand il dépasse la hauteur du terminal.

    Code de sortie : 0 si aucun échec, 1 sinon.
    """)

    System.halt(0)
  end
end
