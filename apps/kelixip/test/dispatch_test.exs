defmodule Kelix.DispatchTest do
  # Exercises the full P2c chain: Router.resolve → InstancePool quota/checkout →
  # spawn. Uses the app-started Kelix.ScriptRegistry / Kelix.InstancePool
  # singletons; unique domain names isolate per-domain quota across tests.
  use ExUnit.Case, async: false

  alias Kelix.{Router, InstancePool, Domains}

  @waiter Path.join(__DIR__, "support/scripts/waiter.exs")
  @no_shutdown Path.join(__DIR__, "support/scripts/no_shutdown.exs")

  defp reg_req(user, host), do: %{method: :REGISTER, ruri: %SIP.Uri{userpart: user, domain: host}}
  defp uniq(prefix), do: "#{prefix}#{System.unique_integer([:positive])}.test"

  defp cleanup(pids),
    do: on_exit(fn -> Enum.each(pids, &send(&1, {:scenario_ctl, :shutdown, :test_cleanup})) end)

  describe "InstancePool.accept" do
    test "spawns an instance and enforces the per-domain quota (503)" do
      dom = uniq("pool")
      route = %{domain: dom, function: :registrar, script: @waiter, max_calls: 1}

      assert {:accept, pid1} = InstancePool.accept(route, self(), reg_req("a", dom), [])
      assert is_pid(pid1) and Process.alive?(pid1)

      # a second call on the same domain hits max_calls: 1 → 503
      assert {:reject, 503, _} = InstancePool.accept(route, self(), reg_req("b", dom), [])

      cleanup([pid1])
    end

    test "a script failing the load-time contract → 500" do
      route = %{domain: uniq("bad"), function: :registrar, script: @no_shutdown, max_calls: nil}
      assert {:reject, 500, _} = InstancePool.accept(route, self(), reg_req("a", "bad.test"), [])
    end
  end

  describe "Router.dispatch (resolve → spawn) over a snapshot" do
    setup do
      dom = uniq("disp")

      {:ok, snap} =
        Domains.parse(~s([[domain]]\nname = "#{dom}"\n[domain.registrar]\nscript = "#{@waiter}"))

      %{snap: snap, dom: dom}
    end

    test "REGISTER to a served domain → accept + running instance", %{snap: snap, dom: dom} do
      assert {:accept, pid} = Router.dispatch(self(), reg_req("alice", dom), snap)
      assert Process.alive?(pid)
      cleanup([pid])
    end

    test "unknown domain → 404", %{snap: snap} do
      assert {:reject, 404, _} = Router.dispatch(self(), reg_req("alice", "nope.test"), snap)
    end

    test "INVITE on a registrar-only domain (calls not enabled) → 405", %{snap: snap, dom: dom} do
      invite = %{method: :INVITE, ruri: %SIP.Uri{userpart: "1234", domain: dom}}
      assert {:reject, 405, _} = Router.dispatch(self(), invite, snap)
    end
  end

  describe "the calls path (SIP.Session.Call)" do
    setup do
      dom = uniq("calls")

      {:ok, snap} =
        Domains.parse(
          ~s([[domain]]\nname = "#{dom}"\n[[domain.call]]\npattern = "8XXX"\nscript = "#{@waiter}")
        )

      %{snap: snap, dom: dom}
    end

    test "an INVITE matching a dial rule spawns the rule's script", %{snap: snap, dom: dom} do
      invite = %{method: :INVITE, ruri: %SIP.Uri{userpart: "8001", domain: dom}}
      assert {:accept, pid} = Router.dispatch(self(), invite, snap)
      assert Process.alive?(pid)
      cleanup([pid])
    end

    test "an INVITE matching no dial rule → 404", %{snap: snap, dom: dom} do
      invite = %{method: :INVITE, ruri: %SIP.Uri{userpart: "1234", domain: dom}}
      assert {:reject, 404, _} = Router.dispatch(self(), invite, snap)
    end

    # Without this registration the framework answers an INVITE 500 ("no call server
    # defined") however complete the dial plan is — the calls half of the router was
    # unreachable until it was wired.
    test "the router is registered as the call processing module" do
      assert SIP.Session.ConfigRegistry.get_call_processing_module() == Router
      assert function_exported?(Router, :on_new_call, 3)
      assert function_exported?(Router, :on_call_end, 2)
    end
  end
end
