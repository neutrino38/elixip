defmodule Kelix.ModuleSupervisorTest do
  # Kelix.ModuleSupervisor: resolve → validate → register → start one child per
  # [module.<name>] block, and the config-source split (registrar from
  # domains.toml, the rest from config.toml) — design §8.1, §6.1.
  #
  # The :kelixip app is already running under `mix test`, so ModuleRegistry /
  # Control.Registry are live singletons (empty — the app boots no modules). We
  # reuse them and clear entries per test, and start a *separately named*
  # ModuleSupervisor so we don't clash with the app's own instance.
  use ExUnit.Case, async: false

  alias Kelix.{ModuleRegistry, ModuleSupervisor}
  alias Kelix.Control.Registry, as: ControlRegistry

  # A minimal in-test Kelix.Module: an Agent service + a control command. Its
  # config decides validity so we can exercise the skip path.
  defmodule Fake do
    @behaviour Kelix.Module
    use Agent

    def start_link(config), do: Agent.start_link(fn -> config end, name: __MODULE__)

    @impl Kelix.Module
    def child_spec(_name, config),
      do: %{id: __MODULE__, start: {__MODULE__, :start_link, [config]}}

    @impl Kelix.Module
    def validate_config(%{"ok" => false}), do: {:error, "rejected by test"}
    def validate_config(_config), do: :ok

    @impl Kelix.Module
    def describe(), do: %{version: "0.1", exports: []}

    @impl Kelix.Module
    def describe_control(),
      do: [%{name: "ping", args: [], rest: {:get, "/ping"}, rw: :r, help: "test ping"}]

    @impl Kelix.Module
    def handle_control("ping", _args), do: {:ok, :pong}
  end

  # Same, minus the optional control callbacks: a module that contributes no
  # REST/CLI command. (It used to be Kelix.Mod.Registrar, which is no longer
  # compiled into the core — §16.12 — so the core's tests must not reach for it.)
  defmodule Plain do
    @behaviour Kelix.Module
    use Agent

    def start_link(config), do: Agent.start_link(fn -> config end, name: __MODULE__)

    @impl Kelix.Module
    def child_spec(_name, config),
      do: %{id: __MODULE__, start: {__MODULE__, :start_link, [config]}}

    @impl Kelix.Module
    def validate_config(_config), do: :ok

    @impl Kelix.Module
    def describe(), do: %{version: "0.1", exports: []}
  end

  @fake "Kelix.ModuleSupervisorTest.Fake"
  @plain "Kelix.ModuleSupervisorTest.Plain"

  setup do
    # start from a clean slate in the shared registries
    for name <- Map.keys(ModuleRegistry.all()), do: ModuleRegistry.unregister(name)
    for name <- Map.keys(ControlRegistry.all()), do: ControlRegistry.deregister(name)
    :ok
  end

  # start a test-owned supervisor (distinct name) with an explicit block map
  defp start_sup(modules) do
    start_supervised!(
      {ModuleSupervisor, name: :"modsup_#{System.unique_integer([:positive])}", modules: modules}
    )
  end

  describe "starting modules from an explicit block map" do
    test "resolves an explicit module, starts it, and registers metadata + control surface" do
      start_sup(%{"fake" => %{"module" => @fake, "n" => 1}})

      assert Process.whereis(Fake)
      assert %{module: Fake, config: %{"n" => 1}} = ModuleRegistry.lookup("fake")
      assert [%{name: "ping"}] = ControlRegistry.commands_for("fake")
    end

    test "an invalid config is skipped — the module is not started, the supervisor still boots" do
      start_sup(%{"fake" => %{"module" => @fake, "ok" => false}})

      refute Process.whereis(Fake)
      assert ModuleRegistry.lookup("fake") == nil
      assert ControlRegistry.commands_for("fake") == []
    end

    test "an unresolvable module name is skipped, not fatal" do
      start_sup(%{"ghost" => %{}})
      assert ModuleRegistry.lookup("ghost") == nil
    end

    test "a module without describe_control registers no commands" do
      start_sup(%{"plain" => %{"module" => @plain, "max_contacts_per_aor" => 2}})

      assert Process.whereis(Plain)
      assert ModuleRegistry.lookup("plain").config["max_contacts_per_aor"] == 2
      assert ControlRegistry.commands_for("plain") == []
    end
  end

  describe "block_sources/2 — config-source split" do
    test "registrar comes from domains.toml; a config.toml registrar is ignored" do
      config_modules = %{
        "auth_db" => %{"database" => "x"},
        "registrar" => %{"max_contacts_per_aor" => 99}
      }

      domain_modules = %{"registrar" => %{"max_contacts_per_aor" => 3}}

      merged = ModuleSupervisor.block_sources(config_modules, domain_modules)

      assert merged["registrar"] == %{"max_contacts_per_aor" => 3}
      assert merged["auth_db"] == %{"database" => "x"}
    end

    test "no registrar anywhere → just the config.toml modules" do
      assert ModuleSupervisor.block_sources(%{"auth_db" => %{}}, %{}) == %{"auth_db" => %{}}
    end
  end
end
