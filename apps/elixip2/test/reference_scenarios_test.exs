defmodule SIP.Test.ReferenceScenarios do
  use ExUnit.Case, async: true

  @moduledoc """
  Every scenario shipped in `scenarios/` still loads.

  The reference scenarios are documentation that runs — FSL.md and B2BUA.md quote
  them, and a reader copies them. A macro that changes shape breaks all of them at
  once, and the suites that drive one scenario each would only catch the ones they
  drive. This catches the rest, at the only moment where the cost is a compile.
  """

  @scenarios Path.expand("../scenarios", __DIR__)

  # `load_file!/1` evaluates the file, so a scenario that names a module :elixip2
  # does not depend on (a kelixip loadable module) cannot be loaded here — those
  # ship under apps/kelixip/scripts and are covered by that app's registry test.
  for path <- Path.wildcard(Path.join(@scenarios, "*.exs")) do
    @path path
    test "#{Path.basename(path)} loads" do
      module = SIP.Scenario.Loader.load_file!(@path)

      assert is_atom(module)
      assert function_exported?(module, :__scenario_states__, 0)
      assert :initial_state in module.__scenario_states__()
    end
  end
end
