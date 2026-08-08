defmodule Kelix.DomainsTest do
  use ExUnit.Case, async: true

  alias Kelix.{Domains, Domain, DialRule}

  @valid """
  [[domain]]
  name = "example.com"
  aliases = ["example.fr", "example.ca"]
  max_calls = 500

  [domain.registrar]
  script = "registrar-example.exs"
  default_expires = 3600
  min_expires = 60

  [domain.presence]
  script = "presence-example.exs"

  [[domain]]
  name = "mydomain.de"

  [domain.registrar]
  script = "registrar-common.exs"

  [[domain.call]]
  pattern = "XXXX"
  script = "user2user.exs"

  [[domain.call]]
  pattern = "0[1-9]XXXXXXXX"
  script = "user2pstn.exs"

  [[domain.call]]
  default = true
  script = "catchall.exs"
  """

  describe "parse/1 — valid config" do
    setup do
      {:ok, snap} = Domains.parse(@valid)
      %{snap: snap}
    end

    test "parses both domains in order", %{snap: snap} do
      assert [%Domain{name: "example.com"}, %Domain{name: "mydomain.de"}] = snap.domains
    end

    test "domain fields", %{snap: snap} do
      [ex, my] = snap.domains
      assert ex.aliases == ["example.fr", "example.ca"]
      assert ex.max_calls == 500

      assert ex.registrar == %{
               script: "registrar-example.exs",
               default_expires: 3600,
               min_expires: 60
             }

      assert ex.presence == %{script: "presence-example.exs"}
      assert ex.dial_plan == []
      assert my.max_calls == nil
      assert my.presence == nil
    end

    test "index resolves name + aliases, case-insensitive", %{snap: snap} do
      assert %Domain{name: "example.com"} = Domains.lookup(snap, "example.com")
      assert %Domain{name: "example.com"} = Domains.lookup(snap, "EXAMPLE.FR")
      assert %Domain{name: "example.com"} = Domains.lookup(snap, "example.ca")
      assert %Domain{name: "mydomain.de"} = Domains.lookup(snap, "mydomain.de")
      assert Domains.lookup(snap, "unknown.net") == nil
    end

    test "dial-plan is ordered with the catch-all last and matchers work", %{snap: snap} do
      my = Enum.find(snap.domains, &(&1.name == "mydomain.de"))
      assert [r1, r2, r3] = my.dial_plan
      assert r1.raw == "XXXX" and r1.script == "user2user.exs"
      assert r3.default? and r3.script == "catchall.exs"
      assert DialRule.matches?(r1, "1234")
      refute DialRule.matches?(r1, "12345")
      assert DialRule.matches?(r2, "0612345678")
      assert DialRule.matches?(r3, "anything")
    end
  end

  describe "parse/1 — validation errors" do
    test "missing domain name" do
      assert {:error, msg} = Domains.parse(~s([[domain]]\naliases = ["x"]))
      assert msg =~ "missing required `name`"
    end

    test "unknown top-level key" do
      assert {:error, msg} = Domains.parse(~s(foo = 1\n[[domain]]\nname = "a"))
      assert msg =~ "unknown top-level key"
    end

    test "unknown domain key" do
      assert {:error, msg} = Domains.parse(~s([[domain]]\nname = "a"\nbogus = 1))
      assert msg =~ "unknown key"
    end

    test "unknown registrar key" do
      toml = ~s([[domain]]\nname = "a"\n[domain.registrar]\nscript = "s"\nbogus = 1)
      assert {:error, msg} = Domains.parse(toml)
      assert msg =~ "unknown key"
    end

    test "registrar block requires script" do
      toml = ~s([[domain]]\nname = "a"\n[domain.registrar]\ndefault_expires = 3600)
      assert {:error, msg} = Domains.parse(toml)
      assert msg =~ "missing required `script`"
    end

    test "bad dial-plan pattern" do
      toml = ~s([[domain]]\nname = "a"\n[[domain.call]]\npattern = "[1-9"\nscript = "s")
      assert {:error, msg} = Domains.parse(toml)
      assert msg =~ "bad pattern"
    end

    test "catch-all must be last" do
      toml =
        ~s([[domain]]\nname = "a"\n[[domain.call]]\ndefault = true\nscript = "c"\n[[domain.call]]\npattern = "X"\nscript = "s")

      assert {:error, msg} = Domains.parse(toml)
      assert msg =~ "must be the last call rule"
    end

    test "duplicate name/alias across domains" do
      toml = ~s([[domain]]\nname = "a.com"\naliases = ["dup.com"]\n[[domain]]\nname = "dup.com")
      assert {:error, msg} = Domains.parse(toml)
      assert msg =~ "used by more than one domain"
    end

    test "max_calls must be a positive integer" do
      assert {:error, msg} = Domains.parse(~s([[domain]]\nname = "a"\nmax_calls = -1))
      assert msg =~ "positive integer"
    end
  end

  # Uses the Kelix.Domains singleton started by the :kelixip application (booted
  # for these tests). One sequential test so it is independent of test order:
  # assertions are relative to the version captured at the start.
  test "reload is atomic — swap on success, keep current on any failure" do
    before = Domains.current()

    # valid file -> version bumped, domains + index loaded
    good = write_tmp(@valid)
    assert :ok = Domains.reload(good)
    v1 = Domains.current()
    assert v1.version == before.version + 1
    assert length(v1.domains) == 2
    assert %Domain{} = Domains.lookup(v1, "example.fr")

    # invalid content -> rejected, current version untouched
    bad = write_tmp(~s([[domain]]\nname = "a"\nbogus = 1))
    assert {:error, msg} = Domains.reload(bad)
    assert msg =~ "unknown key"
    assert Domains.current().version == v1.version
    assert length(Domains.current().domains) == 2

    # missing file -> rejected cleanly, current untouched
    assert {:error, msg2} = Domains.reload("/no/such/domains.toml")
    assert msg2 =~ "cannot read"
    assert Domains.current().version == v1.version
  end

  describe "script_refs/1 — every script the config names" do
    test "registrar, presence and each call rule, with the context that names them" do
      {:ok, snap} = Domains.parse(@valid)

      assert Domains.script_refs(snap) == [
               {"registrar-example.exs", "domain example.com [domain.registrar]"},
               {"presence-example.exs", "domain example.com [domain.presence]"},
               {"registrar-common.exs", "domain mydomain.de [domain.registrar]"},
               {"user2user.exs", ~s(domain mydomain.de call rule "XXXX")},
               {"user2pstn.exs", ~s(domain mydomain.de call rule "0[1-9]XXXXXXXX")},
               {"catchall.exs", "domain mydomain.de call rule default = true"}
             ]
    end

    test "a script reused by two rules is listed once" do
      {:ok, snap} =
        Domains.parse("""
        [[domain]]
        name = "a"
        [[domain.call]]
        pattern = "X"
        script = "same.exs"
        [[domain.call]]
        default = true
        script = "same.exs"
        """)

      assert [{"same.exs", _}] = Domains.script_refs(snap)
    end

    test "a domain enabling nothing refers to no script" do
      {:ok, snap} = Domains.parse(~s([[domain]]\nname = "a"))
      assert Domains.script_refs(snap) == []
    end
  end

  # The regression this whole check exists for: `kelictl domain reload-all` used to
  # answer :ok on a config whose scripts were missing / uncompilable / not
  # shutdown-aware, and the operator only found out on the first call routed there.
  # Asserts on what was swapped in rather than on version numbers: the singleton is
  # shared with the rest of the suite, which reloads it too.
  test "reload(check_scripts: true) rejects a config whose scripts are not servable" do
    scripts = Path.join(__DIR__, "support/scripts")
    empty = write_tmp("")
    on_exit(fn -> Domains.reload(empty) end)

    missing = write_tmp(domain_using(Path.join(scripts, "nope.exs")))
    assert {:error, msg} = Domains.reload(missing, check_scripts: true)
    assert msg =~ "1 script(s) rejected"
    assert msg =~ "domain check.example.com [domain.registrar]"
    assert msg =~ "cannot read"
    refute Domains.lookup(Domains.current(), "check.example.com")

    no_shutdown = write_tmp(domain_using(Path.join(scripts, "no_shutdown.exs")))
    assert {:error, msg2} = Domains.reload(no_shutdown, check_scripts: true)
    assert msg2 =~ "cooperative shutdown"
    refute Domains.lookup(Domains.current(), "check.example.com")

    # …and accepts the very same config once the script it names is servable
    good = write_tmp(domain_using(Path.join(scripts, "valid_registrar.exs")))
    assert :ok = Domains.reload(good, check_scripts: true)

    assert %Domain{name: "check.example.com"} =
             Domains.lookup(Domains.current(), "check.example.com")
  end

  defp domain_using(script) do
    """
    [[domain]]
    name = "check.example.com"

    [domain.registrar]
    script = "#{script}"
    """
  end

  defp write_tmp(content) do
    path = Path.join(System.tmp_dir!(), "domains_#{System.unique_integer([:positive])}.toml")
    File.write!(path, content)
    on_exit(fn -> File.rm(path) end)
    path
  end
end
