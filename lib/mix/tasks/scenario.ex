defmodule Mix.Tasks.Scenario do
  @shortdoc "Run an elixip SIP scenario (.exs file)"
  @moduledoc """
  Compile the project, load a scenario `.exs` file, run it and exit with status
  `0` on success or `1` on failure (so it can be used in CI).

      mix scenario scenarios/my_call_scenario.exs

  The scenario module is located automatically (the module that defines `run/1`
  through `use SIP.Scenario`) and run with the stack started (`run(true)`).
  """
  use Mix.Task

  @impl true
  def run(args) do
    # Start the application (and its deps), not just compile: this applies the
    # project config — in particular the Logger backends (console + file) — so
    # scenario logs land in the configured log file instead of the console with
    # default settings.
    Mix.Task.run("app.start")

    path =
      case args do
        [path | _] -> path
        [] -> Mix.raise("usage: mix scenario <scenario.exs>")
      end

    unless File.exists?(path), do: Mix.raise("Scenario file not found: #{path}")

    module = SIP.Scenario.Loader.load_file!(path)

    case module.run(true) do
      :ok ->
        Mix.shell().info("Scenario #{inspect(module)} succeeded.")
        :ok

      {:error, reason} ->
        Mix.shell().error("Scenario #{inspect(module)} failed: #{inspect(reason)}")
        exit({:shutdown, 1})
    end
  end
end
