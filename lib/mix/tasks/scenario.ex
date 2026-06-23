defmodule Mix.Tasks.Scenario do
  @shortdoc "Run an elixip SIP scenario (.exs file)"
  @moduledoc """
  Compile the project, load a scenario `.exs` file, run it and exit with status
  `0` on success or `1` on failure (so it can be used in CI).

      mix scenario scenarios/my_call_scenario.exs
      mix scenario --config ives.json scenarios/uac_register.exs

  The scenario module is located automatically (the module that defines `run/1`
  through `use SIP.Scenario`) and run with the stack started.

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

    path =
      case rest do
        [path | _] -> path
        [] -> Mix.raise("usage: mix scenario [--config FILE] <scenario.exs>")
      end

    unless File.exists?(path), do: Mix.raise("Scenario file not found: #{path}")

    module = SIP.Scenario.Loader.load_file!(path)

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
