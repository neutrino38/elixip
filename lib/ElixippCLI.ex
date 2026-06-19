defmodule Elixipp.CLI do
  @moduledoc """
  Entry point of the standalone `elixipp` executable (built with
  `mix escript.build`).

      elixipp scenarios/my_call_scenario.exs   # by file path
      elixipp MyCallScenario                    # by module name (if bundled)

  Like `mix scenario`, it exits with `0` on success and `1` on failure.
  """

  @spec main([String.t()]) :: no_return()
  def main(argv) do
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

  defp abort(message, code) do
    IO.puts(:stderr, message)
    System.halt(code)
  end
end
