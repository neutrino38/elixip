defmodule Kelix.ScriptPreflightTest do
  # async: false — drives the Kelix.Domains singleton.
  use ExUnit.Case, async: false

  @moduledoc """
  The boot half of the §5.3 contract: a `domains.toml` whose scripts cannot run must
  stop the boot, not produce a server that answers `500` to every call routed to
  that domain — the way it was found, one call at a time.
  """

  alias Kelix.{Domains, ScriptPreflight}

  @scripts Path.join(__DIR__, "support/scripts")

  setup do
    empty = write_tmp("")
    on_exit(fn -> Domains.reload(empty) end)
    :ok
  end

  test "nothing to check (no domain, no script) is a silent :ignore" do
    assert :ignore = ScriptPreflight.run()
  end

  test "a servable config passes" do
    :ok = Domains.reload(write_tmp(domain_using("valid_registrar.exs")))
    assert :ignore = ScriptPreflight.run()
  end

  test "a script that is not shutdown-aware fails the child's start, i.e. the boot" do
    # reloaded WITHOUT the script check, exactly as init/1 loads it at boot
    :ok = Domains.reload(write_tmp(domain_using("no_shutdown.exs")))

    stderr =
      ExUnit.CaptureIO.capture_io(:stderr, fn ->
        assert {:error, {:invalid_scripts, message}} = ScriptPreflight.run()
        assert message =~ "domain preflight.example.com [domain.registrar]"
        assert message =~ "cooperative shutdown"
      end)

    # a release dying at boot flushes no Logger output: journald must still see why
    assert stderr =~ "unservable domains.toml"
  end

  test "a missing script fails the same way" do
    :ok = Domains.reload(write_tmp(domain_using("nope.exs")))

    ExUnit.CaptureIO.capture_io(:stderr, fn ->
      assert {:error, {:invalid_scripts, message}} = ScriptPreflight.run()
      assert message =~ "cannot read"
    end)
  end

  defp domain_using(script) do
    """
    [[domain]]
    name = "preflight.example.com"

    [domain.registrar]
    script = "#{Path.join(@scripts, script)}"
    """
  end

  defp write_tmp(content) do
    path = Path.join(System.tmp_dir!(), "preflight_#{System.unique_integer([:positive])}.toml")
    File.write!(path, content)
    on_exit(fn -> File.rm(path) end)
    path
  end
end
