defmodule Kelix.Test.Fixtures do
  @moduledoc """
  The two arrange steps that every test touching served domains or a loadable
  module had been copy-pasting: put a `domains.toml` in front of the server, and
  put a fake module in the registry — each undone on exit.

  Both were open-coded in eight files (control_test, control_api_test,
  control_cli_test, module_dir_test, registrar_test, mcu_test,
  module_reload_test, control_registrations_test), thirteen sites in all, in two
  spellings: a lone TOML in `tmp_dir`, or a directory holding `domains.toml`
  next to an `empty.toml`. The empty file is not incidental — `Kelix.Domains`
  goes back to "nothing served" by reloading a path, so the teardown needs an
  empty TOML to point at. Unifying on the directory form covers both, and gives
  the tests that also write a script somewhere a place to put it.
  """

  @doc """
  Serves `toml` as the domain configuration for the duration of the test.

  Returns `%{dir: dir, path: path}` — `path` for the tests that reload or edit
  the file again, `dir` for those that drop a script next to it.

  The teardown is registered *before* the reload, so a TOML that fails to load
  still restores "nothing served" instead of leaking into the next test — which
  the open-coded version, registering `on_exit` after its `assert :ok`, did not.
  """
  def serve_domains(toml) do
    %{dir: dir, path: path} = write_domains(toml)
    :ok = Kelix.Domains.reload(path)
    %{dir: dir, path: path}
  end

  @doc """
  Like `serve_domains/1` but leaves the reload to the caller, for the tests whose
  subject *is* the reload's outcome (an unservable config, a rejected script).
  """
  def write_domains(toml) do
    %{dir: dir} = domains_dir()
    path = Path.join(dir, "domains.toml")
    File.write!(path, toml)
    %{dir: dir, path: path}
  end

  @doc """
  Claims a scratch directory and arranges for "nothing served" on exit, without
  writing any config.

  For the tests that reload several TOMLs of their own over the course of one
  test (module_reload_test walks a `[module.registrar]` block through successive
  values) and only need somewhere to put them.
  """
  def domains_dir do
    dir = Path.join(System.tmp_dir!(), "kelix_test_#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    empty = Path.join(dir, "empty.toml")
    File.write!(empty, "")

    ExUnit.Callbacks.on_exit(fn ->
      Kelix.Domains.reload(empty)
      File.rm_rf(dir)
    end)

    %{dir: dir, empty: empty}
  end

  @doc """
  Registers `module` as the loadable module named `name`, unregistered on exit.

  The core names no module, so a fake exporting only the functions under test is
  the whole contract — see the `FakeRegistrar`s in control_test / control_cli_test.
  """
  def with_module(name, module, config \\ %{}) do
    Kelix.ModuleRegistry.register(name, module, config)
    ExUnit.Callbacks.on_exit(fn -> Kelix.ModuleRegistry.unregister(name) end)
    :ok
  end
end
