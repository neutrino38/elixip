defmodule Kelix.ScriptRegistryTest do
  use ExUnit.Case, async: false

  alias Kelix.ScriptRegistry

  @scripts Path.join(__DIR__, "support/scripts")

  describe "compile_checked/2 — load-time contract (§5.3)" do
    test "a valid registrar script compiles to a version-suffixed module" do
      assert {:ok, mod} = ScriptRegistry.compile_checked(Path.join(@scripts, "valid_registrar.exs"), 7)
      assert mod == KelixTest.ValidRegistrar.V7
      assert function_exported?(mod, :__scenario_type__, 0)
      assert mod.__scenario_type__() == :uas_register
      assert function_exported?(mod, :__state___shutdown__, 1)
    end

    test "a scenario without on_shutdown is refused" do
      assert {:error, msg} = ScriptRegistry.compile_checked(Path.join(@scripts, "no_shutdown.exs"), 1)
      assert msg =~ "cooperative shutdown"
      assert msg =~ "on_shutdown"
    end

    test "a non-scenario module is refused" do
      assert {:error, msg} = ScriptRegistry.compile_checked(Path.join(@scripts, "not_a_scenario.exs"), 1)
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

  describe "GenServer — current / reload / versioning" do
    setup do
      pid = start_supervised!({ScriptRegistry, script_dir: @scripts})
      %{pid: pid}
    end

    test "current/1 loads on demand and caches the same module" do
      assert {:ok, mod} = ScriptRegistry.current("valid_registrar.exs")
      assert {:ok, ^mod} = ScriptRegistry.current("valid_registrar.exs")
    end

    test "current/1 refuses an invalid script" do
      assert {:error, msg} = ScriptRegistry.current("no_shutdown.exs")
      assert msg =~ "cooperative shutdown"
    end

    test "reload bumps the version to a distinct module" do
      assert {:ok, v1} = ScriptRegistry.current("valid_registrar.exs")
      assert :ok = ScriptRegistry.reload("valid_registrar.exs")
      assert {:ok, v2} = ScriptRegistry.current("valid_registrar.exs")
      refute v1 == v2
      assert v2 == KelixTest.ValidRegistrar.V2
    end

    test "checkout increments refcount and returns the current module + version" do
      assert {:ok, mod, ver} = ScriptRegistry.checkout("valid_registrar.exs")
      assert is_atom(mod) and is_integer(ver)
      assert :ok = ScriptRegistry.checkin("valid_registrar.exs", ver)
    end
  end
end
