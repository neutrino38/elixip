defmodule SIP.Scenario.Loader do
  @moduledoc """
  Locate and load scenario modules, for the `mix scenario` task and the
  `elixipp` escript.
  """

  @doc """
  Compile a scenario `.exs` file and return the scenario module it defines
  (the one created by `use SIP.Scenario`). Raises if none is found.
  """
  @spec load_file!(Path.t()) :: module()
  def load_file!(path) do
    path
    |> Code.compile_file()
    |> Enum.map(&elem(&1, 0))
    |> Enum.find(&scenario_module?/1)
    |> case do
      nil -> raise "No scenario module (use SIP.Scenario) found in #{path}"
      module -> module
    end
  end

  @doc """
  Resolve a scenario module from its name (e.g. `"UAC.Invite"`), assuming it is
  already compiled / bundled. Raises if it is not a scenario module.
  """
  @spec load_module!(String.t()) :: module()
  def load_module!(name) do
    module = Module.concat([name])

    cond do
      not Code.ensure_loaded?(module) -> raise "Module #{name} is not available"
      not scenario_module?(module) -> raise "Module #{name} is not a SIP.Scenario"
      true -> module
    end
  end

  defp scenario_module?(module) do
    Code.ensure_loaded?(module) and
      function_exported?(module, :run, 1) and
      function_exported?(module, :__scenario_states__, 0)
  end
end
