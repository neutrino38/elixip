defmodule Mix.Tasks.Scenario do
  @shortdoc "Run an elixip SIP scenario (.exs file)"
  @moduledoc """
  Compile the project, load a scenario `.exs` file, run it and exit with status
  `0` on success or `1` on failure (so it can be used in CI).

      mix scenario scenarios/my_call_scenario.exs
      mix scenario UAC.Register                          # built-in scenario, no file
      mix scenario --config ives.json UAC.Register

  The argument is either a path to a scenario `.exs` file or the name of a
  built-in scenario module (e.g. `UAC.Invite`, `UAC.Register`). The scenario
  module is located automatically (the one that defines `run/1` through
  `use SIP.Scenario`) and run with the stack started.

  `--config FILE` parameterizes the scenario from an external JSON file (header +
  N accounts); it overrides the scenario `config` block. The first account
  (index 0) is used, since `mix scenario` runs a single instance.
  """
  use Mix.Task

  @impl true
  def run(args) do
    # Start the application (and its deps), not just compile: this applies the
    # project config — in particular the Logger backends (console + file) — so
    # scenario logs land in the configured log file instead of the console with
    # default settings.
    Mix.Task.run("app.start")

    {opts, rest, _} =
      OptionParser.parse(args, strict: [config: :string], aliases: [c: :config])

    arg =
      case rest do
        [arg | _] -> arg
        [] -> Mix.raise("usage: mix scenario [--config FILE] <scenario.exs | ModuleName>")
      end

    # A built-in scenario is given by module name (e.g. UAC.Register); otherwise
    # the argument is a path to a .exs file to compile and load.
    module =
      if String.ends_with?(arg, ".exs") do
        unless File.exists?(arg), do: Mix.raise("Scenario file not found: #{arg}")
        SIP.Scenario.Loader.load_file!(arg)
      else
        SIP.Scenario.Loader.load_module!(arg)
      end

    ext_config = if opts[:config], do: SIP.Scenario.ExternalConfig.load!(opts[:config])
    overrides = SIP.Scenario.ExternalConfig.overrides_for(ext_config, 0)

    SIP.Scenario.Runner.bootstrap_stack()

    case SIP.Scenario.Runner.run_instance(module, config_overrides: overrides) do
      :ok ->
        Mix.shell().info("Scenario #{inspect(module)} succeeded.")
        :ok

      {:aborted, reason} ->
        Mix.shell().info("Scenario #{inspect(module)} aborted: #{inspect(reason)}")
        :ok

      {:error, reason} ->
        Mix.shell().error("Scenario #{inspect(module)} failed: #{inspect(reason)}")
        exit({:shutdown, 1})
    end
  end
end
