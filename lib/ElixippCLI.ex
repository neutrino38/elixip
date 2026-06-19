defmodule Elixipp.CLI do
  @moduledoc """
  Entry point of the standalone `elixipp` executable (built with
  `mix escript.build`).

      elixipp scenarios/my_call_scenario.exs   # by file path
      elixipp MyCallScenario                    # by module name (if bundled)

  Like `mix scenario`, it exits with `0` on success and `1` on failure.

  ## Logging

  `elixipp` sets up its own logging at startup, overriding the configuration
  baked into the escript (`config/config.exs`). An escript does not reliably
  apply the project Logger config, so the policy is configured programmatically
  here and tuned through environment variables:

    * `ELIXIPP_LOG_FILE`  — log file path (default `elixipp.log`)
    * `ELIXIPP_LOG_LEVEL` — file log level: `debug` | `info` | `warning` |
      `error` (default `debug`)

  The console is kept quiet (warnings and above) since the tool prints its own
  outcome line.
  """
  require Logger

  @default_log_file "elixipp.log"
  @default_log_level :debug

  @spec main([String.t()]) :: no_return()
  def main(argv) do
    setup_logging()

    case argv do
      [arg | _] -> run(arg)
      [] -> abort("usage: elixipp <scenario.exs | ModuleName>", 2)
    end
  end

  defp run(arg) do
    module =
      if String.ends_with?(arg, ".exs") do
        unless File.exists?(arg), do: abort("Scenario file not found: #{arg}", 2)
        SIP.Scenario.Loader.load_file!(arg)
      else
        SIP.Scenario.Loader.load_module!(arg)
      end

    case module.run(true) do
      :ok ->
        IO.puts("Scenario #{inspect(module)} succeeded.")
        System.halt(0)

      {:error, reason} ->
        IO.puts(:stderr, "Scenario #{inspect(module)} failed: #{inspect(reason)}")
        System.halt(1)
    end
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
