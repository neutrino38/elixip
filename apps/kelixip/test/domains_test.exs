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
      assert ex.registrar == %{script: "registrar-example.exs", default_expires: 3600, min_expires: 60}
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

  describe "GenServer — atomic reload" do
    setup do
      pid = start_supervised!(Domains)
      %{pid: pid}
    end

    test "starts empty (version 0, no domains)" do
      snap = Domains.current()
      assert snap.version == 0
      assert snap.domains == []
    end

    test "reload swaps in a new version" do
      path = write_tmp(@valid)
      assert :ok = Domains.reload(path)
      snap = Domains.current()
      assert snap.version == 1
      assert length(snap.domains) == 2
      assert %Domain{} = Domains.lookup(snap, "example.fr")
    end

    test "an invalid reload is rejected and keeps the current version" do
      good = write_tmp(@valid)
      assert :ok = Domains.reload(good)
      assert Domains.current().version == 1

      bad = write_tmp(~s([[domain]]\nname = "a"\nbogus = 1))
      assert {:error, msg} = Domains.reload(bad)
      assert msg =~ "unknown key"
      # current config untouched
      assert Domains.current().version == 1
      assert length(Domains.current().domains) == 2
    end

    test "reload of a missing file is rejected cleanly" do
      assert {:error, msg} = Domains.reload("/no/such/domains.toml")
      assert msg =~ "cannot read"
      assert Domains.current().version == 0
    end
  end

  defp write_tmp(content) do
    path = Path.join(System.tmp_dir!(), "domains_#{System.unique_integer([:positive])}.toml")
    File.write!(path, content)
    on_exit(fn -> File.rm(path) end)
    path
  end
end
