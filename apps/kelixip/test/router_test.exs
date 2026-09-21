defmodule Kelix.RouterTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias Kelix.{Router, Domains}

  # example.com: registrar + presence (no calls)
  # mydomain.de: registrar + calls (dial-plan)
  @domains_toml """
  [[domain]]
  name = "example.com"
  aliases = ["example.fr"]

  [domain.registrar]
  script = "registrar-example.exs"

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
  script  = "user2user.exs"

  [[domain.call]]
  pattern = "0[1-9]XXXXXXXX"
  script  = "user2pstn.exs"

  [[domain.call]]
  default = true
  script  = "catchall.exs"
  """

  setup_all do
    {:ok, snap} = Domains.parse(@domains_toml)
    %{snap: snap}
  end

  defp req(method, user, host) do
    %{method: method, ruri: %SIP.Uri{userpart: user, domain: host}}
  end

  # A SUBSCRIBE / PUBLISH as it arrives: the event package is a header, and it is
  # what step 3 routes on.
  defp event_req(method, user, host, package) do
    Map.put(req(method, user, host), :event, package)
  end

  describe "step 1 — domain" do
    test "unknown domain → 404", %{snap: snap} do
      assert {:reject, 404, _} = Router.resolve(snap, req(:REGISTER, "alice", "nope.net"))
    end

    test "alias resolves to its domain", %{snap: snap} do
      assert {:route, %{domain: %{name: "example.com"}}} =
               Router.resolve(snap, req(:REGISTER, "alice", "example.fr"))
    end

    test "falls back to the To host when the R-URI has none", %{snap: snap} do
      r = %{
        method: :REGISTER,
        ruri: %SIP.Uri{userpart: "a", domain: nil},
        to: %SIP.Uri{domain: "example.com"}
      }

      assert {:route, %{function: :registrar}} = Router.resolve(snap, r)
    end

    test "a wildcard alias routes a subdomain to its domain and its script" do
      toml = """
      [[domain]]
      name = "gw.out"
      aliases = ["*.gw.out"]

      [[domain.call]]
      default = true
      script  = "gateway.exs"
      """

      {:ok, snap} = Domains.parse(toml)

      assert {:route, %{domain: %{name: "gw.out"}, script: "gateway.exs"}} =
               Router.resolve(snap, req(:INVITE, "0612345678", "sbc.eu.gw.out"))

      assert {:reject, 404, _} = Router.resolve(snap, req(:INVITE, "0612345678", "notgw.out"))
    end
  end

  describe "step 2 — function (method → enabled function)" do
    test "REGISTER → registrar", %{snap: snap} do
      assert {:route, %{function: :registrar, script: "registrar-example.exs"}} =
               Router.resolve(snap, req(:REGISTER, "alice", "example.com"))
    end

    test "SUBSCRIBE → presence when enabled", %{snap: snap} do
      assert {:route, %{function: :presence, script: "presence-subscribe.exs"}} =
               Router.resolve(snap, event_req(:SUBSCRIBE, "alice", "example.com", "presence"))
    end

    test "INVITE on a domain without calls → 405", %{snap: snap} do
      assert {:reject, 405, _} = Router.resolve(snap, req(:INVITE, "1234", "example.com"))
    end

    test "SUBSCRIBE on a domain without presence → 405", %{snap: snap} do
      assert {:reject, 405, _} =
               Router.resolve(snap, event_req(:SUBSCRIBE, "alice", "mydomain.de", "presence"))
    end

    test "an unmapped method (BYE out-of-dialog) → 405", %{snap: snap} do
      assert {:reject, 405, _} = Router.resolve(snap, req(:BYE, "x", "example.com"))
    end

    # Page-mode chat is a function of its own with its own blocks (DESIGN-CHAT.md);
    # a MESSAGE carries no Event, so it can name none of the presence blocks.
    test "an out-of-dialog MESSAGE is not routed to presence", %{snap: snap} do
      assert {:reject, 405, _} = Router.resolve(snap, req(:MESSAGE, "alice", "example.com"))
    end
  end

  # The step the event package added: one domain serves as many packages as it
  # declares blocks, and which of them a request is about is written in its Event
  # header. The 489 is raised HERE, before any script runs.
  describe "step 3 — script (presence: the event package picks the block)" do
    test "each package gets its own script, and the method picks which", %{snap: snap} do
      assert {:route, %{script: "presence-subscribe.exs", function: :presence}} =
               Router.resolve(snap, event_req(:SUBSCRIBE, "bob", "example.com", "presence"))

      assert {:route, %{script: "presence-publish.exs"}} =
               Router.resolve(snap, event_req(:PUBLISH, "bob", "example.com", "presence"))

      assert {:route, %{script: "dialog-subscribe.exs"}} =
               Router.resolve(snap, event_req(:SUBSCRIBE, "bob", "example.com", "dialog"))
    end

    test "the package name is matched case-insensitively", %{snap: snap} do
      assert {:route, %{script: "presence-subscribe.exs"}} =
               Router.resolve(snap, event_req(:SUBSCRIBE, "bob", "example.com", "PRESENCE"))
    end

    # RFC 6665 §4.4.1: the `id` parameter names one subscription among several on
    # a dialog; it is not part of the package name and must not defeat the match.
    test "an Event id does not defeat the match", %{snap: snap} do
      assert {:route, %{script: "presence-subscribe.exs"}} =
               Router.resolve(snap, event_req(:SUBSCRIBE, "bob", "example.com", "presence;id=42"))
    end

    test "a package this domain does not serve → 489 carrying Allow-Events", %{snap: snap} do
      assert {:reject, 489, "Bad Event", fields} =
               Router.resolve(
                 snap,
                 event_req(:SUBSCRIBE, "bob", "example.com", "message-summary")
               )

      # What the watcher could have asked for instead — without it the refusal is
      # one the client can only retry identically (RFC 6665 §4.4.7).
      assert {"Allow-Events", "presence, dialog"} = List.keyfind(fields, "Allow-Events", 0)
    end

    # No Event header at all: the package is what says which state is being asked
    # for, so its absence is the same answer as a package we do not serve.
    test "a SUBSCRIBE with no Event header → 489", %{snap: snap} do
      assert {:reject, 489, "Bad Event", _fields} =
               Router.resolve(snap, req(:SUBSCRIBE, "bob", "example.com"))
    end

    # The `dialog` block declares no publish script: the package is served, that
    # method on it is not.
    test "PUBLISH on a package whose block declares no publish script → 405", %{snap: snap} do
      assert {:reject, 405, _} =
               Router.resolve(snap, event_req(:PUBLISH, "bob", "example.com", "dialog"))
    end

    test "allow_events/1 is composed from the domain's blocks, in order", %{snap: snap} do
      assert Router.allow_events(Domains.lookup(snap, "example.com")) == "presence, dialog"
      assert Router.allow_events(Domains.lookup(snap, "mydomain.de")) == ""
    end
  end

  describe "step 3 — script (calls dial-plan first-match)" do
    test "4-digit → user2user", %{snap: snap} do
      assert {:route, %{function: :calls, script: "user2user.exs"}} =
               Router.resolve(snap, req(:INVITE, "1234", "mydomain.de"))
    end

    test "national number → user2pstn", %{snap: snap} do
      assert {:route, %{script: "user2pstn.exs"}} =
               Router.resolve(snap, req(:INVITE, "0612345678", "mydomain.de"))
    end

    test "no specific match → catch-all", %{snap: snap} do
      assert {:route, %{script: "catchall.exs"}} =
               Router.resolve(snap, req(:INVITE, "abc", "mydomain.de"))
    end
  end

  describe "helpers" do
    test "enabled_methods reflects the domain's functions", %{snap: snap} do
      example = Domains.lookup(snap, "example.com")
      my = Domains.lookup(snap, "mydomain.de")
      assert Enum.sort(Router.enabled_methods(example)) == [:PUBLISH, :REGISTER, :SUBSCRIBE]
      assert Enum.sort(Router.enabled_methods(my)) == [:INVITE, :REGISTER]
    end
  end

  # The media override handed to every spawned instance. Three outcomes, and the
  # middle one used to be indistinguishable from the third — which is the whole
  # defect of 2026-08-13: a pool with nothing serviceable returned `nil`, the
  # instance fell back to the global `:mediaserver` config, and its default is the
  # TEST MOCKUP. Real traffic went to a stub; the call signalled perfectly, carried
  # no media, and was logged as a success.
  describe "media override (what the pool says reaches the instance)" do
    test "no pool at all → nil, so the global :mediaserver config applies" do
      # A name nothing is registered under: that is a pool-less deployment, and the
      # standalone elixipp tool. Both legitimately name their media server in
      # configuration, so the fallback stays for them — only a pool that ANSWERED
      # "nothing" suppresses it.
      refute Process.whereis(:router_mp_absent)
      assert Router.media_override(:router_mp_absent) == nil
    end

    test "a pool with nothing serviceable → :unavailable, never a silent fallback" do
      # A pool whose only entry fails its probe. `checkout/1` then says :no_mcu.
      mp =
        start_pool(
          [%{name: "mcu1", module: :mendooze, url: "http://mcu.test:9090", enabled: true}],
          fn _ -> false end
        )

      :ok = Kelix.MediaPool.check_health(mp)
      assert {:error, :no_mcu} = Kelix.MediaPool.checkout(mp)

      # And the router must turn that into a refusal, not into nil — which is what
      # sent real traffic to the mockup.
      assert Router.media_override(mp) == [module: :unavailable]
    end

    # `name:` rides along with the module and the url: it is what `kelictl monitor`
    # shows in its `mediaserver` column, and an operator reading it next to
    # `kelictl mediaserver list` needs the same word on both sides.
    test "a healthy pool → that MCU's name, module and url, for this call only" do
      mp =
        start_pool(
          [%{name: "mcu1", module: :mendooze, url: "http://mcu.test:9090", enabled: true}],
          fn _ -> true end
        )

      :ok = Kelix.MediaPool.check_health(mp)

      assert Router.media_override(mp) == [
               name: "mcu1",
               module: :mendooze,
               url: "http://mcu.test:9090"
             ]
    end
  end

  # start a test-owned pool with an injected probe; periodic check pushed far out
  defp start_pool(pool, probe) do
    name = :"router_mp_#{System.unique_integer([:positive])}"

    start_supervised!(
      {Kelix.MediaPool, name: name, pool: pool, probe: probe, first_check_ms: 60_000}
    )

    name
  end

  # a domain with calls but no dial-plan match + no catch-all → 404
  test "calls with no matching rule and no catch-all → 404" do
    toml = ~s([[domain]]\nname = "d.com"\n[[domain.call]]\npattern = "9XX"\nscript = "s.exs")
    {:ok, snap} = Domains.parse(toml)
    assert {:reject, 404, _} = Router.resolve(snap, req(:INVITE, "1234", "d.com"))
    assert {:route, %{script: "s.exs"}} = Router.resolve(snap, req(:INVITE, "911", "d.com"))
  end

  # Why a request was refused, for whoever reads the node's log rather than a
  # capture. Each line must name the request AND the domains.toml block that is
  # missing: a bare "404" sends the operator back to reading the TOML by hand.
  describe "reject logs" do
    test "unknown domain names the domain and the file", %{snap: snap} do
      log = capture_log(fn -> Router.resolve(snap, req(:INVITE, "bob", "nope.net")) end)

      assert log =~ "INVITE sip:bob@nope.net rejected"
      assert log =~ "domain nope.net not declared in domains.toml"
    end

    test "REGISTER on a domain with no registrar block" do
      toml = ~s([[domain]]\nname = "d.com"\n[[domain.call]]\npattern = "9XX"\nscript = "s.exs")
      {:ok, no_reg} = Domains.parse(toml)

      log = capture_log(fn -> Router.resolve(no_reg, req(:REGISTER, "alice", "d.com")) end)

      assert log =~ "REGISTER sip:alice@d.com rejected"
      assert log =~ "registrar not configured in domains.toml for domain d.com"
    end

    test "INVITE on a domain with no call rule at all", %{snap: snap} do
      log = capture_log(fn -> Router.resolve(snap, req(:INVITE, "1234", "example.com")) end)

      assert log =~ "INVITE sip:1234@example.com rejected"
      assert log =~ "no call rule declared in domains.toml for domain example.com"
    end

    test "INVITE matching no dial-plan rule names the destination and the domain" do
      toml = ~s([[domain]]\nname = "d.com"\n[[domain.call]]\npattern = "9XX"\nscript = "s.exs")
      {:ok, snap} = Domains.parse(toml)

      log = capture_log(fn -> Router.resolve(snap, req(:INVITE, "1234", "d.com")) end)

      assert log =~
               "destination sip:1234@d.com does not match any call rule declared in domain d.com"
    end
  end
end
