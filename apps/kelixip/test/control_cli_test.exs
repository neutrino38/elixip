defmodule Kelix.Control.CLITest do
  # kelictl arg parsing + rendering (design §10.2). run/2 targets node() so it
  # dispatches locally (apply Kelix.Control) — no distribution needed in tests.
  use ExUnit.Case, async: false

  alias Kelix.Control.CLI

  defp run(argv), do: CLI.run(argv, node())

  test "status renders key lines, exit 0" do
    {0, out} = run(["status"])
    assert out =~ "node:"
    assert out =~ "active calls:"
    assert out =~ "media pool:"
  end

  test "regs on an empty registrar" do
    {0, out} = run(["regs"])
    assert out == "no registrations"
  end

  test "an unknown command prints usage, exit 2" do
    {2, out} = run(["frobnicate"])
    assert out =~ "usage: kelictl"
  end

  test "stop with a non-integer id → error, exit 2" do
    {2, out} = run(["stop", "abc"])
    assert out =~ "must be an integer"
  end

  test "stop with an unknown id → error, exit 1" do
    {1, out} = run(["stop", "999999"])
    assert out =~ "error:"
  end

  test "mcu toggle on an unknown MCU → error, exit 1" do
    {1, out} = run(["mcu", "ghost", "off"])
    assert out =~ "error:"
  end

  test "log-level valid → ok" do
    prev = Logger.level()
    on_exit(fn -> Logger.configure(level: prev) end)
    assert {0, "ok"} = run(["log-level", "info"])
  end

  test "reload-script with no name → usage error, exit 2" do
    {2, out} = run(["reload-script"])
    assert out =~ "at least one script name"
  end

  test "reload-script reports per-name results" do
    {code, out} = run(["reload-script", "nope"])
    assert code == 1
    assert out =~ "nope:"
  end

  test "a module command on an unknown module → error, exit 1" do
    {1, out} = run(["mymod", "docmd", "arg"])
    assert out =~ "error:"
  end
end
