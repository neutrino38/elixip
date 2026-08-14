defmodule Kelix.RouterTest do
  use ExUnit.Case, async: true

  alias Kelix.{Router, Domains}

  # example.com: registrar + presence (no calls)
  # mydomain.de: registrar + calls (dial-plan)
  @domains_toml """
  [[domain]]
  name = "example.com"
  aliases = ["example.fr"]

  [domain.registrar]
  script = "registrar-example.exs"

  [domain.presence]
  script = "presence-example.exs"

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

  describe "step 1 — domain" do
    test "unknown domain → 404", %{snap: snap} do
      assert {:reject, 404, _} = Router.resolve(snap, req(:REGISTER, "alice", "nope.net"))
    end

    test "alias resolves to its domain", %{snap: snap} do
      assert {:route, %{domain: %{name: "example.com"}}} =
               Router.resolve(snap, req(:REGISTER, "alice", "example.fr"))
    end

    test "falls back to the To host when the R-URI has none", %{snap: snap} do
      r = %{method: :REGISTER, ruri: %SIP.Uri{userpart: "a", domain: nil}, to: %SIP.Uri{domain: "example.com"}}
      assert {:route, %{function: :registrar}} = Router.resolve(snap, r)
    end
  end

  describe "step 2 — function (method → enabled function)" do
    test "REGISTER → registrar", %{snap: snap} do
      assert {:route, %{function: :registrar, script: "registrar-example.exs"}} =
               Router.resolve(snap, req(:REGISTER, "alice", "example.com"))
    end

    test "SUBSCRIBE → presence when enabled", %{snap: snap} do
      assert {:route, %{function: :presence, script: "presence-example.exs"}} =
               Router.resolve(snap, req(:SUBSCRIBE, "alice", "example.com"))
    end

    test "INVITE on a domain without calls → 405", %{snap: snap} do
      assert {:reject, 405, _} = Router.resolve(snap, req(:INVITE, "1234", "example.com"))
    end

    test "SUBSCRIBE on a domain without presence → 405", %{snap: snap} do
      assert {:reject, 405, _} = Router.resolve(snap, req(:SUBSCRIBE, "alice", "mydomain.de"))
    end

    test "an unmapped method (BYE out-of-dialog) → 405", %{snap: snap} do
      assert {:reject, 405, _} = Router.resolve(snap, req(:BYE, "x", "example.com"))
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
      assert Enum.sort(Router.enabled_methods(example)) == [:MESSAGE, :PUBLISH, :REGISTER, :SUBSCRIBE]
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
      mp = start_pool([%{name: "mcu1", module: :mendooze, url: "http://mcu.test:9090", enabled: true}], fn _ -> false end)
      :ok = Kelix.MediaPool.check_health(mp)
      assert {:error, :no_mcu} = Kelix.MediaPool.checkout(mp)

      # And the router must turn that into a refusal, not into nil — which is what
      # sent real traffic to the mockup.
      assert Router.media_override(mp) == [module: :unavailable]
    end

    test "a healthy pool → that MCU's module and url, for this call only" do
      mp = start_pool([%{name: "mcu1", module: :mendooze, url: "http://mcu.test:9090", enabled: true}], fn _ -> true end)
      :ok = Kelix.MediaPool.check_health(mp)

      assert Router.media_override(mp) == [module: :mendooze, url: "http://mcu.test:9090"]
    end
  end

  # start a test-owned pool with an injected probe; periodic check pushed far out
  defp start_pool(pool, probe) do
    name = :"router_mp_#{System.unique_integer([:positive])}"
    start_supervised!({Kelix.MediaPool, name: name, pool: pool, probe: probe, first_check_ms: 60_000})
    name
  end

  # a domain with calls but no dial-plan match + no catch-all → 404
  test "calls with no matching rule and no catch-all → 404" do
    toml = ~s([[domain]]\nname = "d.com"\n[[domain.call]]\npattern = "9XX"\nscript = "s.exs")
    {:ok, snap} = Domains.parse(toml)
    assert {:reject, 404, _} = Router.resolve(snap, req(:INVITE, "1234", "d.com"))
    assert {:route, %{script: "s.exs"}} = Router.resolve(snap, req(:INVITE, "911", "d.com"))
  end
end
