defmodule Kelix.ModuleReloadTest do
  @moduledoc """
  `kelictl module reload registrar` end to end, against the real module (design
  §8.1): re-read the block from `domains.toml`, validate it, re-read the module's
  code, then reconfigure or restart the service.

  Complements `Kelix.ModuleDirTest` in the core app, which covers the loading
  mechanism with a synthetic `.beam`; here the module is the real one, so what is
  under test is the whole resolve → validate → reload chain, including the config
  source split (`registrar` comes from `domains.toml`, not `config.toml`).

  It drives the **application's** `Kelix.ModuleSupervisor` — the one `reload/1`
  acts on — and cleans its child up afterwards.
  """
  use ExUnit.Case, async: false

  alias Kelix.{ModuleRegistry, ModuleSupervisor}

  @registrar Kelix.Mod.Registrar

  setup do
    %{dir: dir} = Kelix.Test.Fixtures.domains_dir()

    on_exit(fn ->
      _ = Supervisor.terminate_child(ModuleSupervisor, @registrar)
      _ = Supervisor.delete_child(ModuleSupervisor, @registrar)
      ModuleRegistry.unregister("registrar")
    end)

    %{dir: dir}
  end

  # a domains.toml serving example.com with a [module.registrar] block
  defp write_domains!(dir, max_contacts) do
    path = Path.join(dir, "domains_#{max_contacts}.toml")

    File.write!(path, """
    [[domain]]
    name = "example.com"

      [domain.registrar]
      script = "registrar.exs"

    [module.registrar]
    max_contacts_per_aor = #{max_contacts}
    """)

    :ok = Kelix.Domains.reload(path)
  end

  test "reload picks up the new [module.registrar] block from domains.toml", %{dir: dir} do
    write_domains!(dir, 2)

    assert ModuleSupervisor.reload("registrar") == :ok

    assert %{module: @registrar, config: %{"max_contacts_per_aor" => 2}} =
             ModuleRegistry.lookup("registrar")

    assert is_pid(Process.whereis(@registrar))

    # the operator edits domains.toml, reloads the domains, then the module
    write_domains!(dir, 7)
    assert ModuleSupervisor.reload("registrar") == :ok

    assert %{config: %{"max_contacts_per_aor" => 7}} = ModuleRegistry.lookup("registrar")
    assert is_pid(Process.whereis(@registrar))
  end

  test "an unconfigured module is refused without touching anything", %{dir: dir} do
    write_domains!(dir, 2)
    assert ModuleSupervisor.reload("registrar") == :ok
    pid = Process.whereis(@registrar)

    assert ModuleSupervisor.reload("auth_db") == {:error, :not_configured}
    assert ModuleSupervisor.reload("ghost") == {:error, :not_configured}

    # the registrar is untouched by a failed reload of something else
    assert Process.whereis(@registrar) == pid
    assert %{config: %{"max_contacts_per_aor" => 2}} = ModuleRegistry.lookup("registrar")
  end

  test "an invalid block is rejected, the running service untouched", %{dir: dir} do
    write_domains!(dir, 2)
    assert ModuleSupervisor.reload("registrar") == :ok
    pid = Process.whereis(@registrar)

    bad = Path.join(dir, "bad.toml")

    File.write!(bad, """
    [[domain]]
    name = "example.com"

      [domain.registrar]
      script = "registrar.exs"

    [module.registrar]
    max_contacts_per_aor = "many"
    """)

    case Kelix.Domains.reload(bad) do
      :ok ->
        # domains.toml accepted it (module blocks are the module's business), so
        # validate_config/1 is what must refuse it
        assert {:error, _reason} = ModuleSupervisor.reload("registrar")

      {:error, _reason} ->
        # domains.toml refused it outright: the snapshot is kept, so the module
        # still reloads to its previous, valid block
        assert ModuleSupervisor.reload("registrar") == :ok
    end

    assert Process.whereis(@registrar) == pid
    assert %{config: %{"max_contacts_per_aor" => 2}} = ModuleRegistry.lookup("registrar")
  end
end
