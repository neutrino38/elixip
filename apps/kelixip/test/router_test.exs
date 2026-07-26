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

  # a domain with calls but no dial-plan match + no catch-all → 404
  test "calls with no matching rule and no catch-all → 404" do
    toml = ~s([[domain]]\nname = "d.com"\n[[domain.call]]\npattern = "9XX"\nscript = "s.exs")
    {:ok, snap} = Domains.parse(toml)
    assert {:reject, 404, _} = Router.resolve(snap, req(:INVITE, "1234", "d.com"))
    assert {:route, %{script: "s.exs"}} = Router.resolve(snap, req(:INVITE, "911", "d.com"))
  end
end
