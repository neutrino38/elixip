defmodule Kelix.ModuleDirTest do
  @moduledoc """
  Dynamic loading of a module's `.beam` from `server.module_dir` (design §8.3,
  §12.1) — the mechanism that lets the core release ship **no** SIP function and a
  deployment install only the modules it uses (§16.12).

  The test writes a real `.beam` into a temporary directory, removes the module
  from memory, and checks the supervisor loads it from there — and refuses it when
  the directory is not the one configured.
  """
  use ExUnit.Case, async: false

  alias Kelix.{ModuleRegistry, ModuleSupervisor}

  # A minimal Kelix.Module, compiled at runtime so it exists only as a .beam file
  # in the directory we choose (never on the build path).
  @source ~S"""
  defmodule Kelix.Mod.Dropped do
    @behaviour Kelix.Module
    use Agent

    def start_link(config), do: Agent.start_link(fn -> config end, name: __MODULE__)

    @impl Kelix.Module
    def child_spec(_name, config),
      do: %{id: __MODULE__, start: {__MODULE__, :start_link, [config]}}

    @impl Kelix.Module
    def validate_config(_config), do: :ok

    @impl Kelix.Module
    def describe(), do: %{version: "9.9", exports: [{:answer, 0}]}

    def answer(), do: 42
  end
  """

  @module Kelix.Mod.Dropped

  setup do
    dir = Path.join(System.tmp_dir!(), "kelix_moddir_#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)

    # Compile to a .beam in `dir`, then wipe the module from the VM so the only way
    # to reach it is through that directory.
    [{@module, bytecode}] = Code.compile_string(@source)
    File.write!(Path.join(dir, "#{@module}.beam"), bytecode)
    unload()

    on_exit(fn ->
      unload()
      :code.del_path(String.to_charlist(dir))
      ModuleRegistry.unregister("dropped")
      File.rm_rf(dir)
    end)

    %{dir: dir}
  end

  defp unload() do
    :code.purge(@module)
    :code.delete(@module)
    :code.purge(@module)
  end

  defp start_sup(opts) do
    start_supervised!(
      {ModuleSupervisor,
       [name: :"modsup_dir_#{System.unique_integer([:positive])}", modules: %{"dropped" => %{}}] ++
         opts}
    )
  end

  test "a module dropped in module_dir is loaded, registered and started", %{dir: dir} do
    refute Code.ensure_loaded?(@module), "the module must not be reachable before the test"

    start_sup(module_dir: dir)

    assert Code.ensure_loaded?(@module)
    assert %{module: @module} = ModuleRegistry.lookup("dropped")
    assert Process.whereis(@module)
    # the loaded code is really the one we compiled into the directory (called
    # through apply/3: the module does not exist at compile time, by design)
    assert apply(@module, :answer, []) == 42
    assert apply(@module, :describe, []).version == "9.9"
  end

  test "without that directory the block is skipped, and the boot survives it", %{dir: _dir} do
    start_sup(module_dir: Path.join(System.tmp_dir!(), "kelix_no_such_dir"))

    refute Code.ensure_loaded?(@module)
    assert ModuleRegistry.lookup("dropped") == nil
  end

  test "a domain enabling a function whose module is missing is flagged at boot" do
    # The trap the extraction introduces: enable `registrar` but install no
    # registrar module, and the script raises on its first facade call — the request
    # goes unanswered. Boot must at least say so out loud.
    dir = Path.join(System.tmp_dir!(), "kelix_warn_#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    path = Path.join(dir, "domains.toml")
    empty = Path.join(dir, "empty.toml")
    File.write!(empty, "")

    File.write!(path, """
    [[domain]]
    name = "warn.example.com"

      [domain.registrar]
      script = "registrar.exs"
    """)

    :ok = Kelix.Domains.reload(path)
    on_exit(fn -> Kelix.Domains.reload(empty) && File.rm_rf(dir) end)

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        ModuleSupervisor.warn_missing_function_modules()
      end)

    assert log =~ "warn.example.com"
    assert log =~ "registrar"
  end

  test "add_module_dir/1 tolerates nil and a missing directory" do
    assert ModuleSupervisor.add_module_dir(nil) == :ok
    assert ModuleSupervisor.add_module_dir("/nope/does/not/exist") == :ok
  end

  test "reload/1 refuses a module absent from the config, leaving the running one alone",
       %{dir: dir} do
    start_sup(module_dir: dir)
    pid = Process.whereis(@module)

    # this module is in no config file: nothing to re-read, nothing to touch —
    # validate-before-act (§8.1), so the running service must be left intact
    assert ModuleSupervisor.reload("dropped") == {:error, :not_configured}
    assert Process.whereis(@module) == pid
    assert apply(@module, :answer, []) == 42
  end
end
