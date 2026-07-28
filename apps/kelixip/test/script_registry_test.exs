defmodule Kelix.ScriptRegistryUsesModulesTest do
  # async: false — reads the global Kelix.ModuleRegistry.
  use ExUnit.Case, async: false

  @moduledoc """
  The load-time check on a script's declared `uses_modules` (design §16 #14).
  Before it, the dependency script → modules was written nowhere: a domain enabling
  `registrar` with no module installed was only a boot *warning*, and the first
  REGISTER died inside the instance.
  """

  alias Kelix.ScriptRegistry

  defmodule DeclaresTwo do
    def __scenario_config__, do: [domain: "example.com", uses_modules: [:registrar, :auth_db]]
  end

  defmodule DeclaresNothing do
    def __scenario_config__, do: [domain: "example.com"]
  end

  defmodule NoConfigAtAll do
  end

  # Kelix.ModuleRegistry is an application singleton other tests write to, so make
  # the starting point explicit rather than assumed.
  setup do
    clear = fn ->
      Kelix.ModuleRegistry.unregister("registrar")
      Kelix.ModuleRegistry.unregister("auth_db")
    end

    clear.()
    on_exit(clear)
    :ok
  end

  test "a script whose declared modules are all loaded passes" do
    Kelix.ModuleRegistry.register("registrar", Some.Registrar, %{})
    Kelix.ModuleRegistry.register("auth_db", Some.AuthDb, %{})
    assert ScriptRegistry.check_declared_modules(DeclaresTwo, "registrar.exs") == :ok
  end

  test "a missing module names itself, and what is loaded" do
    Kelix.ModuleRegistry.register("registrar", Some.Registrar, %{})

    assert {:error, reason} = ScriptRegistry.check_declared_modules(DeclaresTwo, "registrar.exs")
    assert reason =~ "auth_db"
    assert reason =~ "registrar.exs"
    # the operator is told what IS loaded, so the fix is obvious. Matched loosely:
    # the registry is shared, other tests may have left entries in it.
    assert reason =~ ~r/loaded:.*"registrar"/
  end

  test "declaring nothing stays loadable — the declaration is opt-in" do
    assert ScriptRegistry.check_declared_modules(DeclaresNothing, "x.exs") == :ok
    assert ScriptRegistry.check_declared_modules(NoConfigAtAll, "x.exs") == :ok
  end
end

defmodule Kelix.ScriptRegistryTest do
  use ExUnit.Case, async: false

  alias Kelix.ScriptRegistry

  @scripts Path.join(__DIR__, "support/scripts")

  describe "compile_checked/2 — load-time contract (§5.3)" do
    test "a valid registrar script compiles to a version-suffixed module" do
      assert {:ok, mod} =
               ScriptRegistry.compile_checked(Path.join(@scripts, "valid_registrar.exs"), 7)

      assert mod == KelixTest.ValidRegistrar.V7
      assert function_exported?(mod, :__scenario_type__, 0)
      assert mod.__scenario_type__() == :uas_register
      assert function_exported?(mod, :__state___shutdown__, 1)
    end

    test "a scenario without on_shutdown is refused" do
      assert {:error, msg} =
               ScriptRegistry.compile_checked(Path.join(@scripts, "no_shutdown.exs"), 1)

      assert msg =~ "cooperative shutdown"
      assert msg =~ "on_shutdown"
    end

    test "a non-scenario module is refused" do
      assert {:error, msg} =
               ScriptRegistry.compile_checked(Path.join(@scripts, "not_a_scenario.exs"), 1)

      assert msg =~ "no scenario module"
    end

    test "a missing file is refused cleanly" do
      assert {:error, msg} = ScriptRegistry.compile_checked(Path.join(@scripts, "nope.exs"), 1)
      assert msg =~ "cannot read"
    end

    test "a syntax error is reported, not raised" do
      path = Path.join(System.tmp_dir!(), "bad_#{System.unique_integer([:positive])}.exs")
      File.write!(path, "defmodule Bad do\n  state :x do\n")
      on_exit(fn -> File.rm(path) end)
      assert {:error, msg} = ScriptRegistry.compile_checked(path, 1)
      assert msg =~ "syntax error" or msg =~ "compile error"
    end
  end

  # These use the Kelix.ScriptRegistry singleton started by the :kelixip app.
  # Each test writes a UNIQUE fixture (unique path + unique module name) so it is
  # isolated on the shared registry and never redefines another test's module.
  describe "GenServer — current / reload / checkout (app singleton)" do
    test "current loads+caches, reload bumps to a distinct module, checkout/checkin" do
      path = unique_valid_script()

      assert {:ok, m1} = ScriptRegistry.current(path)
      assert {:ok, ^m1} = ScriptRegistry.current(path)

      assert :ok = ScriptRegistry.reload(path)
      assert {:ok, m2} = ScriptRegistry.current(path)
      refute m1 == m2
      assert to_string(m2) =~ ".V"

      assert {:ok, mod, ver} = ScriptRegistry.checkout(path)
      assert is_atom(mod) and is_integer(ver)
      assert :ok = ScriptRegistry.checkin(path, ver)
    end

    test "current refuses an invalid script" do
      assert {:error, msg} = ScriptRegistry.current(Path.join(@scripts, "no_shutdown.exs"))
      assert msg =~ "cooperative shutdown"
    end
  end

  # a minimal valid registrar with a UNIQUE module name, written to a temp file
  defp unique_valid_script do
    mod = "KelixTest.Reg#{System.unique_integer([:positive])}"

    src = """
    defmodule #{mod} do
      use SIP.Scenario
      uas :register
      state initial_state do
        scenario_success("ok")
      end
      on_shutdown do
        scenario_aborted("shutdown")
      end
    end
    """

    path = Path.join(System.tmp_dir!(), "reg_#{System.unique_integer([:positive])}.exs")
    File.write!(path, src)
    on_exit(fn -> File.rm(path) end)
    path
  end
end
