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

  describe "status" do
    test "says whether the node can write its domains.toml", %{dir: dir, path: path} do
      assert {0, out} = run(["status"])
      assert out =~ "domains file:    #{path}, writable"

      File.chmod!(path, 0o444)
      File.chmod!(dir, 0o555)
      assert {0, out} = run(["status"])
      assert out =~ "domains file:    #{path}, NOT writable (eacces, node runs as "
    end
  end

  test "help and completion know `domain delete`" do
    assert {0, help} = run(["domain", "help"])
    assert help =~ "[DELETE /domains/<domain>]"

    assert {0, words} = run(["complete", "domain", ""])
    assert "delete" in String.split(words, "\n")

    assert {0, words} = run(["complete", "domain", "delete", ""])
    assert "first.example" in String.split(words, "\n")
  end
end
