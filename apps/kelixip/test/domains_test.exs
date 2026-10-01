defmodule Kelix.DomainsTest do
  use ExUnit.Case, async: true

  alias Kelix.{Domains, Domain, DialRule, PresenceBlock}

  @valid """
  [[domain]]
  name = "example.com"
  aliases = ["example.fr", "example.ca"]
  max_calls = 500

  [domain.registrar]
  script = "registrar-example.exs"
  default_expires = 3600
  min_expires = 60

  [[domain.presence]]
  event-package = "presence"
  subscribe = "presence-subscribe.exs"
  publish = "presence-publish.exs"

  [[domain.presence]]
  event-package = "dialog"
  subscribe = "dialog-subscribe.exs"

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

      # One block per event package, in declaration order. `publish` absent means
      # the package is subscribed to and published by nobody (405), not that the
      # subscribe script serves both.
      assert ex.presence == [
               %PresenceBlock{
                 event_package: "presence",
                 subscribe: [%Kelix.DialRule{default?: true, script: "presence-subscribe.exs"}],
                 publish: "presence-publish.exs"
               },
               %PresenceBlock{
                 event_package: "dialog",
                 subscribe: [%Kelix.DialRule{default?: true, script: "dialog-subscribe.exs"}],
                 publish: nil
               }
             ]

      assert ex.dial_plan == []
      assert my.max_calls == nil
      assert my.presence == []
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

  describe "parse/1 — wildcard aliases" do
    @wildcard """
    [[domain]]
    name = "a.gw.out"

    [[domain]]
    name = "gw.out"
    aliases = ["*.gw.out", "passerelle.example.fr"]

    [[domain]]
    name = "deep"
    aliases = ["*.dc.gw.out"]
    """

    setup do
      {:ok, snap} = Domains.parse(@wildcard)
      %{snap: snap}
    end

    test "matches any depth below the suffix", %{snap: snap} do
      assert %Domain{name: "gw.out"} = Domains.lookup(snap, "b.gw.out")
      assert %Domain{name: "gw.out"} = Domains.lookup(snap, "x.y.z.gw.out")
      assert %Domain{name: "gw.out"} = Domains.lookup(snap, "B.GW.OUT")
    end

    test "the bare suffix resolves through `name`, not through the wildcard", %{snap: snap} do
      assert %Domain{name: "gw.out"} = Domains.lookup(snap, "gw.out")
      # the leading dot is part of the suffix: this is not a subdomain of gw.out
      assert Domains.lookup(snap, "notgw.out") == nil
    end

    test "a literal name wins over a wildcard covering it", %{snap: snap} do
      assert %Domain{name: "a.gw.out"} = Domains.lookup(snap, "a.gw.out")
    end

    test "the longest suffix wins", %{snap: snap} do
      assert %Domain{name: "deep"} = Domains.lookup(snap, "srv.dc.gw.out")
      assert %Domain{name: "gw.out"} = Domains.lookup(snap, "srv.other.gw.out")
    end

    test "literal aliases still work alongside a wildcard", %{snap: snap} do
      assert %Domain{name: "gw.out"} = Domains.lookup(snap, "passerelle.example.fr")
    end

    test "aliases are reported as written", %{snap: snap} do
      gw = Enum.find(snap.domains, &(&1.name == "gw.out"))
      assert gw.aliases == ["*.gw.out", "passerelle.example.fr"]
    end

    test "two domains claiming the same suffix are rejected" do
      toml =
        ~s([[domain]]\nname = "a"\naliases = ["*.gw.out"]\n[[domain]]\nname = "b"\naliases = ["*.GW.OUT"])

      assert {:error, msg} = Domains.parse(toml)
      assert msg =~ "used by more than one domain"
    end

    test "a `*` anywhere but in front is rejected" do
      for bad <- ~w(* *. a.*.b *gw.out gw.*) do
        toml = ~s([[domain]]\nname = "a"\naliases = ["#{bad}"])
        assert {:error, msg} = Domains.parse(toml), "accepted #{inspect(bad)}"
        assert msg =~ "a wildcard alias is written"
      end
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

    test "chat rules: the dial plan's rules, and its refusals under their own name" do
      toml =
        ~s([[domain]]\nname = "a"\n[[domain.chat]]\ndefault = true\nscript = "c"\n[[domain.chat]]\npattern = "X"\nscript = "s")

      assert {:error, msg} = Domains.parse(toml)
      assert msg =~ "must be the last chat rule"

      assert {:error, msg} =
               Domains.parse(~s([[domain]]\nname = "a"\n[[domain.chat]]\nscript = "s"))

      assert msg =~ "each [[domain.chat]] needs"

      assert {:error, msg} =
               Domains.parse(~s([[domain]]\nname = "a"\n[domain.chat]\nscript = "s"))

      assert msg =~ "`chat` must be an array of tables"
    end

    test "chat rules parsed in order, with a working matcher" do
      toml = """
      [[domain]]
      name = "a"

      [[domain.chat]]
      pattern = "room-."
      script = "chatroom.exs"

      [[domain.chat]]
      default = true
      script = "p2p-chat.exs"
      """

      assert {:ok, snap} = Domains.parse(toml)
      %Kelix.Domain{chat: [room, default], dial_plan: []} = Domains.lookup(snap, "a")
      assert room.script == "chatroom.exs" and Kelix.DialRule.matches?(room, "room-42")
      refute Kelix.DialRule.matches?(room, "room-")
      assert default.default? and default.script == "p2p-chat.exs"

      assert Domains.script_refs(snap) == [
               {"chatroom.exs", ~s(domain a chat rule "room-.")},
               {"p2p-chat.exs", "domain a chat rule default = true"}
             ]
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

    # Two blocks claiming one package: which of them serves a SUBSCRIBE would be
    # decided by declaration order, and the second would be unreachable.
    test "two presence blocks claiming the same event package" do
      toml = """
      [[domain]]
      name = "a"
      [[domain.presence]]
      event-package = "presence"
      subscribe = "one.exs"
      [[domain.presence]]
      event-package = "PRESENCE"
      subscribe = "two.exs"
      """

      assert {:error, msg} = Domains.parse(toml)
      assert msg =~ "served by more than one"
      assert msg =~ "presence"
    end

    test "a presence block needs an event package and a subscribe script" do
      no_package = ~s([[domain]]\nname = "a"\n[[domain.presence]]\nsubscribe = "s.exs")
      assert {:error, msg} = Domains.parse(no_package)
      assert msg =~ "missing required `event-package`"

      no_script = ~s([[domain]]\nname = "a"\n[[domain.presence]]\nevent-package = "presence")
      assert {:error, msg2} = Domains.parse(no_script)
      assert msg2 =~ "`subscribe` is required"
    end

    test "an unknown key in a presence block" do
      toml =
        ~s([[domain]]\nname = "a"\n[[domain.presence]]\nevent-package = "presence"\nsubscribe = "s.exs"\nnotify = "n.exs")

      assert {:error, msg} = Domains.parse(toml)
      assert msg =~ "unknown key(s): notify"
    end

    # SUBSCRIBE is routed like a call: rules on the R-URI user part, first match
    # wins, the catch-all last. `subscribe = "s.exs"` is the one-rule shorthand.
    test "SUBSCRIBE rules are read like the dial-plan" do
      toml = ~s"""
      [[domain]]
      name = "a"
      [[domain.presence]]
      event-package = "presence"
        [[domain.presence.subscribe]]
        pattern = "rls"
        script = "l.exs"
        [[domain.presence.subscribe]]
        default = true
        script = "s.exs"
      """

      assert {:ok, snap} = Domains.parse(toml)
      assert [%{subscribe: [list, catch_all]}] = Domains.lookup(snap, "a").presence
      assert %Kelix.DialRule{raw: "rls", script: "l.exs", default?: false} = list
      assert %Kelix.DialRule{default?: true, script: "s.exs"} = catch_all
    end

    test "a script string is a single catch-all rule" do
      toml =
        ~s([[domain]]\nname = "a"\n[[domain.presence]]\nevent-package = "presence"\nsubscribe = "s.exs")

      assert {:ok, snap} = Domains.parse(toml)

      assert [%{subscribe: [%Kelix.DialRule{default?: true, script: "s.exs"}]}] =
               Domains.lookup(snap, "a").presence
    end

    test "SUBSCRIBE rules are checked as the dial-plan's are" do
      head = ~s([[domain]]\nname = "a"\n[[domain.presence]]\nevent-package = "presence"\n)

      catch_all_first =
        head <>
          ~s([[domain.presence.subscribe]]\ndefault = true\nscript = "s.exs"\n) <>
          ~s([[domain.presence.subscribe]]\npattern = "rls"\nscript = "l.exs"\n)

      assert {:error, msg} = Domains.parse(catch_all_first)
      assert msg =~ "must be the last presence.subscribe rule"

      no_pattern = head <> ~s([[domain.presence.subscribe]]\nscript = "s.exs"\n)
      assert {:error, msg} = Domains.parse(no_pattern)
      assert msg =~ "[[domain.presence.subscribe]] needs `pattern"
    end

    # `lists` / `list-subscribe` were the way to route a resource list before
    # SUBSCRIBE had rules; a file still carrying them is told what replaces them.
    test "lists and list-subscribe are refused with their replacement" do
      base =
        ~s([[domain]]\nname = "a"\n[[domain.presence]]\nevent-package = "presence"\nsubscribe = "s.exs"\n)

      for extra <- [~s(lists = ["rls"]\nlist-subscribe = "l.exs"), ~s(lists = ["rls"])] do
        assert {:error, msg} = Domains.parse(base <> extra)
        assert msg =~ "[[domain.presence.subscribe]] pattern = \"rls\""
      end
    end

    # The shape this key had before it carried the event package. An operator
    # upgrading a node has the old form under their eyes, so the message names the
    # new one rather than "must be an array of tables".
    test "the pre-P7 single [domain.presence] table names the new form" do
      toml = ~s([[domain]]\nname = "a"\n[domain.presence]\nscript = "presence.exs")
      assert {:error, msg} = Domains.parse(toml)
      assert msg =~ "array of tables"
      assert msg =~ "event-package"
    end
  end

  # Uses the Kelix.Domains singleton started by the :kelixip application (booted
  # for these tests). One sequential test so it is independent of test order:
  # assertions are relative to the version captured at the start.
  test "reload is atomic — swap on success, keep current on any failure" do
    before = Domains.current()
    empty = write_tmp("")
    on_exit(fn -> Domains.reload(empty) end)

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
               {"presence-subscribe.exs",
                "domain example.com [[domain.presence]] subscribe rule default = true (event-package presence)"},
               {"presence-publish.exs",
                "domain example.com [[domain.presence]] publish (event-package presence)"},
               {"dialog-subscribe.exs",
                "domain example.com [[domain.presence]] subscribe rule default = true (event-package dialog)"},
               {"registrar-common.exs", "domain mydomain.de [domain.registrar]"},
               {"user2user.exs", ~s(domain mydomain.de call rule "XXXX")},
               {"user2pstn.exs", ~s(domain mydomain.de call rule "0[1-9]XXXXXXXX")},
               {"catchall.exs", "domain mydomain.de call rule default = true"}
             ]
    end

    test "every SUBSCRIBE rule's script is a reference of its block" do
      {:ok, snap} =
        Domains.parse("""
        [[domain]]
        name = "a"
        [[domain.presence]]
        event-package = "presence"
        publish = "p.exs"
          [[domain.presence.subscribe]]
          pattern = "rls"
          script = "l.exs"
          [[domain.presence.subscribe]]
          default = true
          script = "s.exs"
        """)

      assert Domains.script_refs(snap) == [
               {"l.exs",
                ~s{domain a [[domain.presence]] subscribe rule "rls" (event-package presence)}},
               {"s.exs",
                "domain a [[domain.presence]] subscribe rule default = true (event-package presence)"},
               {"p.exs", "domain a [[domain.presence]] publish (event-package presence)"}
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
