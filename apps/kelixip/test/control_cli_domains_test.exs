defmodule Kelix.Control.CLIDomainsTest do
  # async: false — Kelix.Domains, the pool and the script registry are singletons.
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog

  alias Kelix.Control.CLI

  @initial """
  [[domain]]
  name = "first.example"
  aliases = ["alias.example"]
  """

  setup do
    %{dir: dir, path: path} = Kelix.Test.Fixtures.serve_domains(@initial)
    Kelix.Test.Fixtures.with_script_dir(Path.join(__DIR__, "support/scripts"))

    prev = Application.get_env(:kelixip, :domains_path)
    Application.put_env(:kelixip, :domains_path, path)

    on_exit(fn ->
      File.chmod(dir, 0o755)
      File.chmod(path, 0o644)

      if prev,
        do: Application.put_env(:kelixip, :domains_path, prev),
        else: Application.delete_env(:kelixip, :domains_path)
    end)

    %{dir: dir, path: path}
  end

  defp run(argv), do: CLI.run(argv, node())

  describe "domain delete" do
    test "says how many scenarios it stopped and what each purge did" do
      log =
        capture_log(fn ->
          assert {0, out} = run(["domain", "delete", "first.example", "--admin", "alice"])

          assert out ==
                   "domain first.example deleted (v#{Kelix.Domains.current().version}): " <>
                     "0 scenario(s) asked to stop\n" <>
                     "  presence: not loaded, nothing held\n" <>
                     "  registrar: not loaded, nothing held"
        end)

      assert log =~ "domain delete first.example by admin=alice"
    end

    test "an alias or an unknown name is exit 3" do
      assert run(["domain", "delete", "alias.example"]) == {3, "no such domain"}
      assert {2, "usage: kelictl domain" <> _} = run(["domain", "delete"])
    end

    test "a stale --version and a hand edit are conflicts, exit 4", %{path: path} do
      v = Kelix.Domains.current().version
      assert {4, msg} = run(["domain", "delete", "first.example", "--version", "#{v - 1}"])
      assert msg =~ "changed since the version given"

      File.write!(path, File.read!(path) <> "# by hand\n")
      assert {4, msg} = run(["domain", "delete", "first.example"])
      assert msg =~ "kelictl domain reload-all"
    end

    test "a file the node cannot write is exit 5, naming the path and the user",
         %{dir: dir, path: path} do
      File.chmod!(path, 0o444)
      File.chmod!(dir, 0o555)

      assert {5, msg} = run(["domain", "delete", "first.example"])
      assert msg =~ path
      assert msg =~ "permission denied, eacces"
      assert msg =~ "running as "
      assert msg =~ "Nothing was applied."
    end

    test "a bad option is a usage error" do
      assert {2, "domain: bad option" <> _} =
               run(["domain", "delete", "first.example", "--version", "x"])
    end
  end

  @s "script=domain_waiter.exs"

  # Each write is its own command, as an operator types them; the log is not the
  # subject here.
  defp edit(argv), do: elem(with_log(fn -> run(argv) end), 0)

  defp show(), do: elem(run(["domain", "show", "new.example"]), 1)

  describe "editing a domain one element at a time" do
    test "create, then functions and rules, read back by domain show" do
      assert {0, "domain new.example created (v" <> _} =
               edit(["domain", "create", "new.example", "aliases=n2.example", "max_calls=5"])

      assert {0, "ok (v" <> _} = edit(["domain", "new.example", "registrar", "set", @s])

      assert {0, "rule 1 added" <> _} =
               edit(["domain", "new.example", "call", "add", "default", @s])

      assert {0, "rule 1 added" <> _} = edit(["domain", "new.example", "call", "add", "1XXX", @s])
      assert {0, "rule 2 added" <> _} = edit(["domain", "new.example", "call", "add", "2XXX", @s])

      assert {0, _} =
               edit(["domain", "new.example", "chat", "add", "default", @s, "idle_timeout=60"])

      assert {0, _} = edit(["domain", "new.example", "options", "keepalive", "set", @s])
      assert {0, _} = edit(["domain", "new.example", "options", "add", "conf-.", @s])

      assert {0, _} =
               edit([
                 "domain",
                 "new.example",
                 "presence",
                 "add",
                 "presence",
                 "subscribe=domain_waiter.exs"
               ])

      assert {0, "rule 1 added" <> _} =
               edit([
                 "domain",
                 "new.example",
                 "presence",
                 "presence",
                 "subscribe",
                 "add",
                 "rls",
                 @s
               ])

      out = show()
      assert out =~ "aliases:       n2.example"
      assert out =~ "max calls:     5"
      assert out =~ "version:       #{Kelix.Domains.current().version}"
      assert out =~ ~r/  1\. 1XXX\s+-> domain_waiter.exs/
      assert out =~ ~r/  3\. \(default\) -> domain_waiter.exs/
      assert out =~ "idle 60s"
      assert out =~ ~r/options:\n  keepalive -> domain_waiter.exs.*\n  1\. conf-\./
      assert out =~ "presence SUBSCRIBE 1. rls"
      assert out =~ "presence SUBSCRIBE 2. (default)"
    end

    test "update, move, remove a rule; set and alias" do
      edit(["domain", "create", "new.example"])
      edit(["domain", "new.example", "call", "add", "1XXX", @s])
      edit(["domain", "new.example", "call", "add", "2XXX", @s])

      assert {0, _} = edit(["domain", "new.example", "call", "update", "2", "pattern=3XXX"])
      assert {0, _} = edit(["domain", "new.example", "call", "move", "2", "to=1"])
      assert show() =~ ~r/1\. 3XXX.*\n  2\. 1XXX/
      assert {0, _} = edit(["domain", "new.example", "call", "remove", "1"])
      refute show() =~ "3XXX"

      assert {0, _} = edit(["domain", "new.example", "set", "max_calls=9"])
      assert show() =~ "max calls:     9"
      assert {0, _} = edit(["domain", "new.example", "set", "max_calls=none"])
      assert show() =~ "max calls:     unlimited"

      assert {0, _} = edit(["domain", "new.example", "alias", "add", "n3.example"])
      assert {0, _} = edit(["domain", "new.example", "alias", "remove", "n3.example"])
    end

    test "--admin and the command reach the node's log" do
      edit(["domain", "create", "new.example"])

      log =
        capture_log(fn ->
          run(["domain", "new.example", "call", "add", "1XXX", @s, "--admin", "alice"])
        end)

      assert log =~ "domain call add 1XXX new.example by admin=alice"
    end

    test "refusals: not found 3, exists and conflict 4, invalid 1, usage 2" do
      assert {3, _} = edit(["domain", "nowhere.example", "set", "max_calls=1"])
      assert {3, _} = edit(["domain", "first.example", "call", "remove", "1"])
      assert {4, "it already exists"} = edit(["domain", "create", "alias.example"])

      v = Kelix.Domains.current().version
      edit(["domain", "first.example", "call", "add", "1XXX", @s])

      assert {4, _} =
               edit(["domain", "first.example", "call", "remove", "1", "--version", "#{v}"])

      assert {1, "invalid domain: unknown argument(s): bogus"} =
               edit(["domain", "first.example", "set", "bogus=1"])

      assert {2, "domain: \"1XXX\" is not name=value"} =
               edit(["domain", "first.example", "call", "update", "1", "1XXX"])

      assert {2, "usage: kelictl domain" <> _} =
               edit(["domain", "first.example", "call", "move", "1"])

      assert {2, "usage: kelictl domain" <> _} =
               edit(["domain", "first.example", "alias", "add", "x.example", "a=b"])
    end
  end

  describe "status" do
    test "says whether the node can write its domains.toml", %{dir: dir, path: path} do
      assert {0, out} = run(["status"])
      assert out =~ "domains file:    #{path}, writable"

      File.chmod!(path, 0o444)
      File.chmod!(dir, 0o555)
      assert {0, out} = run(["status"])
      assert out =~ "domains file:    #{path}, NOT writable (eacces, node runs as "
    end

    test "says when the file was edited by hand, until it is reloaded", %{path: path} do
      File.write!(path, File.read!(path) <> "# by hand\n")
      assert {0, out} = run(["status"])

      assert out =~
               "domains file:    #{path}, writable; EDITED BY HAND and not reloaded: " <>
                 "domain edits are refused until `kelictl domain reload-all`"

      assert {0, "ok"} = elem(with_log(fn -> run(["domain", "reload-all"]) end), 0)
      assert {0, out} = run(["status"])
      assert out =~ ~r/domains file:    #{path}, writable\n/
    end
  end

  test "help and completion know the domain commands" do
    assert {0, help} = run(["domain", "help"])
    assert help =~ "[DELETE /domains/<domain>]"

    assert {0, words} = run(["complete", "domain", ""])
    assert "delete" in String.split(words, "\n")

    assert {0, words} = run(["complete", "domain", "delete", ""])
    assert "first.example" in String.split(words, "\n")

    assert {0, words} = run(["complete", "domain", ""])
    assert ["create", "first.example"] -- String.split(words, "\n") == []

    assert {0, words} = run(["complete", "domain", "first.example", ""])
    assert String.split(words, "\n") == ~w(alias call chat options presence registrar set)

    assert {0, "add\nmove\nremove\nupdate"} =
             run(["complete", "domain", "first.example", "call", ""])

    assert {0, help} = run(["domain", "help"])
    assert help =~ "domain <domain> call|chat|options move <n> to=<m>"
  end
end
