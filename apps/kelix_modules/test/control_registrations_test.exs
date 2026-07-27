defmodule Kelix.ControlRegistrationsTest do
  @moduledoc """
  Functional test of the **core ↔ module** pair: `Kelix.Control.registrations/1`
  and `unregister/2` driven through the real `Kelix.Mod.Registrar`.

  It lives with the module, not with the core, precisely because the core no
  longer carries it (§16.12): `Kelix.Control` reaches the registrar by its
  configured name through `Kelix.ModuleRegistry.facade/4`, and that indirection is
  what this test exercises end to end.
  """
  use ExUnit.Case, async: false

  alias Kelix.Control

  describe "registrations + unregister" do
    setup do
      # inject a domain into the app's Domains singleton, restore to empty after
      dir = Path.join(System.tmp_dir!(), "kelix_ctl_#{System.unique_integer([:positive])}")
      File.mkdir_p!(dir)
      path = Path.join(dir, "domains.toml")
      empty = Path.join(dir, "empty.toml")

      File.write!(path, """
      [[domain]]
      name = "example.com"

        [domain.registrar]
        script = "uas_register"
      """)

      File.write!(empty, "")

      :ok = Kelix.Domains.reload(path)

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

      on_exit(fn ->
        Kelix.ModuleRegistry.unregister("registrar")
        Kelix.Domains.reload(empty) && File.rm_rf(dir)
      end)

      :ok
    end

    test "lists a registration then removes it" do
      assert {:ok, _} = Kelix.Mod.Registrar.save(register("alice"), "example.com")

      rows = Control.registrations()
      assert Enum.any?(rows, &(&1.domain == "example.com" and &1.aor == "alice"))

      assert Control.unregister("alice@example.com") == :ok
      assert Control.registrations("alice") == []
    end

    test "unregister across all domains when no domain given" do
      assert {:ok, _} = Kelix.Mod.Registrar.save(register("bob"), "example.com")
      assert Control.unregister("bob") == :ok
      assert Control.unregister("bob") == :notfound
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
