defmodule Kelix.ControlRegistrationsTest do
  @moduledoc """
  Functional test of the **core ↔ module** pair: `Kelix.Control.registrations/0,1`,
  `registration/2` and `unregister/3` driven through the real `Kelix.Mod.Registrar`.

  It lives with the module, not with the core, precisely because the core no
  longer carries it (§16.12): `Kelix.Control` reaches the registrar by its
  configured name through `Kelix.ModuleRegistry.facade/4`, and that indirection is
  what this test exercises end to end.
  """
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Kelix.Control

  describe "registrations + unregister" do
    setup do
      # inject a domain into the app's Domains singleton, restore to empty after
      Kelix.Test.Fixtures.serve_domains("""
      [[domain]]
      name = "example.com"

        [domain.registrar]
        script = "uas_register"
      """)

      # Start the registrar the way production does — through the ModuleSupervisor,
      # which resolves, validates, **registers it under its configured name** and
      # starts it. That registration is what `Kelix.Control` resolves through now
      # that no module is compiled into the core: starting the process alone would
      # leave the control layer unable to find it.
      start_supervised!(
        {Kelix.ModuleSupervisor,
         name: :"modsup_ctl_#{System.unique_integer([:positive])}", modules: %{"registrar" => %{}}}
      )

      assert %{module: Kelix.Mod.Registrar} = Kelix.ModuleRegistry.lookup("registrar")

      on_exit(fn -> Kelix.ModuleRegistry.unregister("registrar") end)

      :ok
    end

    test "lists a registration, shows it, then removes it" do
      assert {:registered, _} = Kelix.Mod.Registrar.save(register("alice"), "example.com")

      # the cross-domain view: one entry per served domain
      assert Enum.any?(Control.registrations(), fn entry ->
               entry.domain == "example.com" and
                 Enum.any?(entry.registrations, &(&1.aor == "alice"))
             end)

      # …the domain's own list, and the AOR in detail — with what the registrar
      # actually stored: the REGISTER above came from 1.2.3.4:5060 over UDP
      assert {:ok, %{domain: "example.com", registrations: [row]}} =
               Control.registrations("example.com")

      assert {:ok, ^row} = Control.registration("example.com", "alice")
      assert [%{uri: "sip:alice@10.0.0.9", source: "UDP 1.2.3.4:5060"}] = row.contacts
      assert hd(row.contacts).expires_in in 3599..3600

      assert Control.unregister("example.com", "alice") == :ok
      assert {:ok, %{registrations: []}} = Control.registrations("example.com")
      assert Control.registration("example.com", "alice") == {:error, :not_found}
    end

    test "removal is per-domain: an unserved domain removes nothing" do
      assert {:registered, _} = Kelix.Mod.Registrar.save(register("bob"), "example.com")

      assert Control.unregister("ghost.example.org", "bob") == :notfound
      # …and the binding is still there
      assert {:ok, _} = Control.registration("example.com", "bob")

      assert Control.unregister("example.com", "bob") == :ok
      assert Control.unregister("example.com", "bob") == :notfound
    end

    # kelescope confirms this action and requires an admin name before sending it
    # — traced here, not merely returned.
    test "unregister/4 traces the admin name in this node's own logs" do
      assert {:registered, _} = Kelix.Mod.Registrar.save(register("alice"), "example.com")

      log =
        capture_log(fn ->
          assert Control.unregister("example.com", "alice", :all, "jdoe") == :ok
        end)

      assert log =~ "unregister example.com/alice"
      assert log =~ "by admin=jdoe"
      assert log =~ ":ok"
    end

    test "unregister/4 traces even a removal that finds nothing" do
      log =
        capture_log(fn ->
          assert Control.unregister("example.com", "ghost", :all, "jdoe") == :notfound
        end)

      assert log =~ "by admin=jdoe"
      assert log =~ ":notfound"
    end
  end

  describe "subscribe_registrations/2" do
    setup do
      Kelix.Test.Fixtures.serve_domains("""
      [[domain]]
      name = "example.com"
      aliases = ["example.org"]

        [domain.registrar]
        script = "uas_register"
      """)

      start_supervised!(
        {Kelix.ModuleSupervisor,
         name: :"modsup_sub_#{System.unique_integer([:positive])}", modules: %{"registrar" => %{}}}
      )

      on_exit(fn -> Kelix.ModuleRegistry.unregister("registrar") end)
      :ok
    end

    # kelescope's live registrations panel:
    # opening a domain's panel gets the current detail, then a push per change,
    # with no polling.
    test "returns the current detail, matched by name or alias, then pushes changes" do
      assert {:registered, _} = Kelix.Mod.Registrar.save(register("alice"), "example.com")

      assert {:ok, %{domain: "example.com", registrations: [%{aor: "alice"}]}} =
               Control.subscribe_registrations(self(), "example.org")

      assert {:registered, _} = Kelix.Mod.Registrar.save(register("bob"), "example.com")
      assert_receive {:kelix_registrations, "example.com", {:upsert, %{aor: "bob"}}}, 500

      assert Control.unregister("example.com", "alice") == :ok
      assert_receive {:kelix_registrations, "example.com", {:remove, "alice"}}, 500
    end

    test "an unserved domain answers :not_found" do
      assert Control.subscribe_registrations(self(), "ghost.example.org") ==
               {:error, :not_found}
    end

    test "unsubscribe_registrations/2 stops the pushes" do
      Control.subscribe_registrations(self(), "example.com")
      assert Control.unsubscribe_registrations(self(), "example.com") == :ok

      Kelix.Mod.Registrar.save(register("carol"), "example.com")
      refute_receive {:kelix_registrations, _, _}, 100
    end
  end

  defp register(user) do
    %{
      method: :REGISTER,
      to: %SIP.Uri{userpart: user, domain: "example.com"},
      ruri: %SIP.Uri{
        userpart: user,
        domain: "example.com",
        destip: {1, 2, 3, 4},
        destport: 5060,
        destproto: "UDP",
        tp_pid: self()
      },
      contact: %SIP.Uri{userpart: user, domain: "10.0.0.9", port: 5060},
      expires: 3600,
      callid: "call-1"
    }
  end
end
