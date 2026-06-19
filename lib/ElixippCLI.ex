defmodule Elixipp.CLI do
  @moduledoc """
  Entry point of the standalone `elixipp` executable (built with
  `mix escript.build`).

      elixipp scenarios/my_call_scenario.exs       # by file path
      elixipp MyCallScenario                        # by module name (if bundled)
      elixipp --monitor scenarios/my_call.exs       # live table of calls in progress

  Like `mix scenario`, it exits with `0` on success and `1` on failure.

  ## --monitor / -m

  Displays a live table (one row per running call) with the scenario name, the
  current FSM state and the event that triggered the last transition. Rendered
  with Owl (pure Elixir, bundles into the escript). The scenario runs in a
  separate process while the main process refreshes the table.

  ## Logging

  `elixipp` sets up its own logging at startup, overriding the configuration
  baked into the escript (`config/config.exs`). Driven by environment variables:

    * `ELIXIPP_LOG_FILE`  — log file path (default `elixipp.log`)
    * `ELIXIPP_LOG_LEVEL` — file log level: `debug` | `info` | `warning` |
      `error` (default `debug`)

  The console is kept quiet (warnings and above) since the tool prints its own
  outcome line.
  """
  require Logger

  @default_log_file "elixipp.log"
  @default_log_level :debug

  # Monitor table columns, in display order: {header, monitor key, fixed width}.
  @columns [
    {"Scénario", :scenario, 16},
    {"Commande", :command, 16},
    {"État", :state, 18},
    {"Événement", :event, 28}
  ]

  @spec main([String.t()]) :: no_return()
  def main(argv) do
    setup_logging()

    {opts, rest, _invalid} =
      OptionParser.parse(argv, strict: [monitor: :boolean], aliases: [m: :monitor])

    arg =
      case rest do
        [arg | _] -> arg
        [] -> abort("usage: elixipp [--monitor] <scenario.exs | ModuleName>", 2)
      end

    module = resolve_module(arg)

    result =
      if opts[:monitor] do
        run_monitored(module)
      else
        module.run(true)
      end

    report_result(module, result)
  end

  defp resolve_module(arg) do
    if String.ends_with?(arg, ".exs") do
      unless File.exists?(arg), do: abort("Scenario file not found: #{arg}", 2)
      SIP.Scenario.Loader.load_file!(arg)
    else
      SIP.Scenario.Loader.load_module!(arg)
    end
  end

  defp report_result(module, :ok) do
    IO.puts("Scenario #{inspect(module)} succeeded.")
    System.halt(0)
  end

  defp report_result(module, {:error, reason}) do
    IO.puts(:stderr, "Scenario #{inspect(module)} failed: #{inspect(reason)}")
    System.halt(1)
  end

  # ── Live monitor view ─────────────────────────────────────────────────────

  defp run_monitored(module) do
    {:ok, _} = Application.ensure_all_started(:owl)
    {:ok, _} = SIP.Scenario.Monitor.start()

    # Owl.LiveScreen only runs on a real terminal; on a pipe / non-interactive
    # device (CI, redirected output) it stays absent. Detect it and degrade
    # gracefully: live in-place table on a TTY, single final snapshot otherwise.
    live? = is_pid(Process.whereis(Owl.LiveScreen))

    if live? do
      # The render function ignores its block state and reads the monitor live,
      # so every refresh shows the current snapshot.
      Owl.LiveScreen.add_block(:calls, state: :tick, render: fn _ -> render_table(true) end)
    end

    parent = self()
    ref = make_ref()
    {_pid, mon_ref} = spawn_monitor(fn -> send(parent, {ref, module.run(true)}) end)

    result = render_loop(ref, mon_ref, live?)

    if live? do
      # Final paint, then make the table permanent in the scrollback.
      Owl.LiveScreen.update(:calls, :final)
      Owl.LiveScreen.flush()
    else
      # Non-interactive: print the final snapshot once (Owl.IO renders the tags
      # and strips colors when the device is not a terminal).
      Owl.IO.puts(render_table(false))
    end

    result
  end

  # Refresh the table every 150 ms until the scenario process reports its result
  # (or dies). spawn_monitor sends the result before the process exits, so the
  # result branch always wins the race against the :DOWN message.
  defp render_loop(ref, mon_ref, live?) do
    receive do
      {^ref, result} ->
        result

      {:DOWN, ^mon_ref, :process, _pid, :normal} ->
        # Result already delivered above; nothing left to wait for.
        {:error, :scenario_exited}

      {:DOWN, ^mon_ref, :process, _pid, reason} ->
        {:error, {:scenario_crashed, reason}}
    after
      150 ->
        if live?, do: Owl.LiveScreen.update(:calls, :tick)
        render_loop(ref, mon_ref, live?)
    end
  end

  # Returns Owl.Data, rendered by Owl.LiveScreen / Owl.IO. `colorize?` is true
  # only on a real terminal (live mode); the non-interactive snapshot stays plain
  # so no ANSI leaks into pipes / CI logs.
  defp render_table(colorize?) do
    case SIP.Scenario.Monitor.calls() do
      [] ->
        "(no active calls)"

      calls ->
        calls
        |> Enum.map(&display_row(&1, colorize?))
        |> Owl.Table.new(border_style: :solid_rounded, sort_columns: &column_order/2)
    end
  end

  # Build a fixed-width display row from a monitor call map. The command and
  # event cells are colored by their type; Owl computes column widths from the
  # underlying text, ignoring the ANSI sequences.
  defp display_row(call, colorize?) do
    Map.new(@columns, fn {header, key, width} -> {header, cell(call, key, width, colorize?)} end)
  end

  defp cell(call, :command, width, true),
    do: Owl.Data.tag(fit(call[:command], width), color_for(call[:command_type]))

  defp cell(call, :event, width, true),
    do: Owl.Data.tag(fit(call[:event], width), color_for(call[:event_type]))

  # Terminal states get a green (success) / red (failure) state cell.
  defp cell(call, :state, width, true) do
    case state_color(call[:state]) do
      nil -> fit(call[:state], width)
      color -> Owl.Data.tag(fit(call[:state], width), color)
    end
  end

  defp cell(call, key, width, _colorize?), do: fit(Map.get(call, key, ""), width)

  # The runner reports terminal states as "succeeded" / "failed".
  defp state_color("succeeded"), do: :green
  defp state_color("failed"), do: :red
  defp state_color(_other), do: nil

  # Color by command/event type: light green for SIP, light orange for media,
  # light blue for everything else. Owl accepts named foreground atoms and
  # 256-color foreground sequences (`\e[38;5;Nm`); 214 is orange.
  defp color_for(:sip), do: :light_green
  defp color_for(:media), do: IO.ANSI.color(214)
  defp color_for(_other), do: :light_blue

  # Truncate (with an ellipsis) or right-pad a cell to a fixed width, so every
  # column keeps a constant width regardless of content. Header labels are
  # shorter than their column width, so the cells drive the final width.
  defp fit(value, width) do
    s = to_string(value)

    if String.length(s) > width do
      String.slice(s, 0, width - 1) <> "…"
    else
      String.pad_trailing(s, width)
    end
  end

  # Keep the columns in @columns order rather than the default alphabetical sort.
  defp column_order(a, b), do: column_rank(a) <= column_rank(b)

  defp column_rank(header) do
    Enum.find_index(@columns, fn {h, _key, _width} -> h == header end) || length(@columns)
  end

  # ── Logging setup ───────────────────────────────────────────────────────────

  # Configure logging for the elixipp run, overriding whatever was baked into
  # the escript. Driven by ELIXIPP_LOG_FILE / ELIXIPP_LOG_LEVEL.
  defp setup_logging do
    _ = Application.ensure_all_started(:logger)
    _ = Application.ensure_all_started(:logger_file_backend)

    log_file = System.get_env("ELIXIPP_LOG_FILE", @default_log_file)
    file_level = parse_level(System.get_env("ELIXIPP_LOG_LEVEL"))

    # The primary Logger level gates every backend, so it must be at least as
    # verbose as the file level or messages would be dropped before reaching it.
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

  # Keep the terminal quiet (warnings and above). Best-effort: tolerate either
  # the legacy Elixir console backend or the Erlang default handler being absent.
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
        IO.puts(:stderr, "Unknown ELIXIPP_LOG_LEVEL #{inspect(other)}, using #{@default_log_level}")
        @default_log_level
    end
  end

  defp abort(message, code) do
    IO.puts(:stderr, message)
    System.halt(code)
  end
end
