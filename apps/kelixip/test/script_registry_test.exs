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

    # Regression: the suffixing means a script that names itself in full
    # (`Kelix.Mcu.Call.media_error/1`) compiles fine and then dies at runtime, because
    # the module is `Kelix.Mcu.Call.V<n>` and the unsuffixed one never exists. The
    # loader in :elixip2 does NOT suffix, so the scenario tests cannot catch this —
    # only a compile through this module can. The verdict is irrelevant here (the
    # scripts declare `uses_modules`, which no module satisfies in this app); the
    # warnings the compiler emits are what is being asserted on.
    #
    # Which is why `Kelix.Mod.*` has to be excluded, and why this test had been red
    # since the day it was written (2026-08-02, dde2f60): it refuted EVERY "is
    # undefined" warning, and registrar.exs legitimately calls Kelix.Mod.AuthDb and
    # Kelix.Mod.Registrar — the loadable modules that :kelixip deliberately does not
    # depend on, so that the core ships no SIP function. Those warnings are the
    # design working, not a dangling reference. Everything else still fails, which is
    # what catches the bug the test is named after; mcu.exs and mcu_adhoc.exs emit
    # nothing at all.
    @loadable_module ~r/\(module Kelix\.Mod\.\w+ is not available/

    test "the shipped reference scripts have no dangling self-reference" do
      for script <- [
            "registrar.exs",
            "mcu.exs",
            "mcu_adhoc.exs",
            "direct-call.exs",
            "direct-call-with-auth.exs",
            "direct-call-with-auth-and-media.exs"
          ] do
        path = Path.expand("../scripts/#{script}", __DIR__)

        warnings =
          ExUnit.CaptureIO.capture_io(:stderr, fn ->
            ScriptRegistry.compile_checked(path, 8_000 + System.unique_integer([:positive]))
          end)

        dangling =
          warnings
          |> String.split("\n")
          |> Enum.filter(&(&1 =~ "is undefined"))
          |> Enum.reject(&(&1 =~ @loadable_module))

        assert dangling == [],
               "#{script} references a module it does not define: #{Enum.join(dangling, "\n")}"
      end
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

  # What `kelictl domain reload-all` leans on: the contract is checked when the
  # config is loaded, not when the first call is routed to it.
  describe "validate/1 — the batch check the domains reload runs (§3.2)" do
    test "valid scripts pass, and are loaded (so the first call needs no compile)" do
      path = unique_valid_script()

      assert :ok = ScriptRegistry.validate([path, path])
      assert {:ok, mod} = ScriptRegistry.current(path)
      assert to_string(mod) =~ ".V"
    end

    test "every offender is reported, not just the first" do
      good = unique_valid_script()
      missing = Path.join(@scripts, "nope.exs")
      no_shutdown = Path.join(@scripts, "no_shutdown.exs")

      assert {:error, failures} = ScriptRegistry.validate([good, missing, no_shutdown])
      assert length(failures) == 2
      assert {^missing, missing_reason} = List.keyfind(failures, missing, 0)
      assert missing_reason =~ "cannot read"
      assert {^no_shutdown, shutdown_reason} = List.keyfind(failures, no_shutdown, 0)
      assert shutdown_reason =~ "cooperative shutdown"
    end

    test "a script edited on disk is recompiled; an untouched one is not" do
      path = unique_valid_script()
      assert :ok = ScriptRegistry.validate([path])
      assert {:ok, v1} = ScriptRegistry.current(path)

      # untouched: same version, no new module
      assert :ok = ScriptRegistry.validate([path])
      assert {:ok, ^v1} = ScriptRegistry.current(path)

      # edited: the stamp changed, so the edit is what gets checked and served
      File.write!(path, File.read!(path) |> String.replace(~s("ok"), ~s("edited")))
      assert :ok = ScriptRegistry.validate([path])
      assert {:ok, v2} = ScriptRegistry.current(path)
      refute v1 == v2
    end

    test "an edit that breaks the contract is caught, not served" do
      path = unique_valid_script()
      assert :ok = ScriptRegistry.validate([path])
      assert {:ok, v1} = ScriptRegistry.current(path)

      # drop the on_shutdown block: the file no longer satisfies §5.3
      File.write!(
        path,
        File.read!(path) |> String.replace(~r/\n  on_shutdown do.*?\n  end\n/s, "\n")
      )

      assert {:error, [{^path, reason}]} = ScriptRegistry.validate([path])
      assert reason =~ "cooperative shutdown"
      # the rejected version is not published: instances keep getting the good one
      assert {:ok, ^v1} = ScriptRegistry.current(path)
    end
  end

  # Two scripts declaring the same `defmodule` compile to the same versioned module,
  # so the second load silently overwrites the first and both dial-plan entries run
  # one body. Found in production: 900031111 → record.exs answered with play.exs's
  # Player, because both files still said `defmodule UAS.InviteExample`.
  describe "module ownership — two scripts cannot share a module name" do
    test "the second script is refused, naming the module and the owner" do
      mod = "KelixTest.Twin#{System.unique_integer([:positive])}"
      first = script_named(mod)
      second = script_named(mod)

      assert :ok = ScriptRegistry.validate([first])
      assert {:ok, m1} = ScriptRegistry.current(first)

      assert {:error, [{^second, reason}]} = ScriptRegistry.validate([second])
      assert reason =~ mod
      assert reason =~ first
      assert reason =~ "rename the module"

      # and the first script is untouched — refused BEFORE the compile that would
      # have overwritten its module, so it still serves its own body.
      assert {:ok, ^m1} = ScriptRegistry.current(first)
      assert function_exported?(m1, :run, 1)
    end

    test "a script reloading keeps its own modules (it is not its own squatter)" do
      path = unique_valid_script()
      assert :ok = ScriptRegistry.validate([path])
      assert :ok = ScriptRegistry.reload(path)
      assert {:ok, mod} = ScriptRegistry.current(path)
      assert to_string(mod) =~ ".V2"
    end

    test "a name freed by a rename can be taken over" do
      mod = "KelixTest.Freed#{System.unique_integer([:positive])}"
      squatted = script_named(mod)
      other = script_named(mod <> "Other")

      assert :ok = ScriptRegistry.validate([squatted, other])
      # `other` renames itself onto a name nobody owns any more
      File.write!(squatted, File.read!(squatted) |> String.replace(mod, mod <> "Renamed"))
      assert :ok = ScriptRegistry.validate([squatted])
      File.write!(other, File.read!(other) |> String.replace(mod <> "Other", mod))
      assert :ok = ScriptRegistry.validate([other])
    end
  end

  # "is what runs still what I edited?" — the operator's other question, answered
  # without reloading anything.
  describe "loaded/0 — module, version and disk freshness" do
    test "a freshly loaded script is not stale, and names its module" do
      path = unique_valid_script()
      assert {:ok, mod} = ScriptRegistry.current(path)

      assert %{^path => entry} = ScriptRegistry.loaded()
      assert entry.module == mod
      assert entry.version == 1
      assert entry.path == path
      assert entry.stale == false
    end

    test "an edit on disk shows as :changed until it is reloaded" do
      path = unique_valid_script()
      assert {:ok, _} = ScriptRegistry.current(path)

      File.write!(path, File.read!(path) |> String.replace(~s("ok"), ~s("edited")))
      assert ScriptRegistry.loaded()[path].stale == :changed

      assert :ok = ScriptRegistry.reload(path)
      assert ScriptRegistry.loaded()[path].stale == false
    end

    test "a deleted file shows as :missing, and the loaded version keeps serving" do
      path = unique_valid_script()
      assert {:ok, mod} = ScriptRegistry.current(path)

      File.rm!(path)
      assert ScriptRegistry.loaded()[path].stale == :missing
      assert {:ok, ^mod} = ScriptRegistry.current(path)
    end
  end

  # `check_module_ownership/3` on its own, with no registry state involved
  describe "check_module_ownership/3" do
    test "an unclaimed module passes" do
      assert ScriptRegistry.check_module_ownership([A.B], %{C.D => "x.exs"}, "y.exs") == :ok
      assert ScriptRegistry.check_module_ownership([], %{}, "y.exs") == :ok
    end

    test "every clashing module is listed, not just the first" do
      owned = %{A.B => "x.exs", C.D => "z.exs"}
      assert {:error, msg} = ScriptRegistry.check_module_ownership([A.B, C.D], owned, "y.exs")
      assert msg =~ "A.B"
      assert msg =~ "x.exs"
      assert msg =~ "C.D"
      assert msg =~ "z.exs"
    end
  end

  # a minimal valid registrar with a UNIQUE module name, written to a temp file
  defp unique_valid_script do
    script_named("KelixTest.Reg#{System.unique_integer([:positive])}")
  end

  defp script_named(mod) do
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
