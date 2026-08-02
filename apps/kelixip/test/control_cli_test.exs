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

  describe "domain list / domain show" do
    @domains_toml """
    [[domain]]
    name = "cli.example.com"
    aliases = ["cli.example.fr"]
    max_calls = 500

    [domain.registrar]
    script = "registrar-example.exs"
    default_expires = 3600

    [[domain.call]]
    pattern = "0[1-9]XXXXXXXX"
    script = "user2pstn.exs"

    [[domain.call]]
    default = true
    script = "catchall.exs"
    """

    setup do
      path =
        Path.join(System.tmp_dir!(), "cli_domains_#{System.unique_integer([:positive])}.toml")

      File.write!(path, @domains_toml)
      assert :ok = Kelix.Domains.reload(path)

      on_exit(fn ->
        empty = path <> ".empty"
        File.write!(empty, "")
        Kelix.Domains.reload(empty)
        File.rm(path)
        File.rm(empty)
      end)

      :ok
    end

    test "domain list renders one row per domain" do
      {0, out} = run(["domain", "list"])

      assert out =~ ~r/domain\s+aliases\s+functions\s+calls\s+regs\s+max/
      assert out =~ ~r/cli\.example\.com\s+cli\.example\.fr\s+registrar, calls\s+0\s+0\s+500/
    end

    test "domain show renders the properties and the numbered dial-plan" do
      {0, out} = run(["domain", "show", "cli.example.com"])

      assert out =~ "domain:        cli.example.com"
      assert out =~ "aliases:       cli.example.fr"
      assert out =~ "max calls:     500"
      assert out =~ "registrar:     default_expires=3600 script=registrar-example.exs"
      assert out =~ "presence:      (disabled)"
      # first-match-wins, so the position is part of the answer
      assert out =~ "1. 0[1-9]XXXXXXXX -> user2pstn.exs"
      assert out =~ "2. (default)      -> catchall.exs"
    end

    test "domain show accepts an alias" do
      {0, out} = run(["domain", "show", "cli.example.fr"])
      assert out =~ "domain:        cli.example.com"
    end

    test "domain show on an unknown domain → exit 1" do
      assert {1, "no such domain"} = run(["domain", "show", "ghost.example.org"])
    end

    test "a mistyped domain sub-command gets the domain usage, not `unknown module`" do
      {2, out} = run(["domain", "shwo", "x"])
      assert out =~ "usage: kelictl domain list | domain show <domain>"
    end
  end

  # The Kelix.Domains singleton is shared with the rest of the suite, so empty it
  # here rather than assuming the boot state survived the files before this one.
  test "domain list with no domain served" do
    path =
      Path.join(System.tmp_dir!(), "cli_domains_empty_#{System.unique_integer([:positive])}.toml")

    File.write!(path, "")
    on_exit(fn -> File.rm(path) end)
    assert :ok = Kelix.Domains.reload(path)

    assert {0, "no domain served"} = run(["domain", "list"])
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
