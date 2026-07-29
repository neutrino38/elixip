defmodule SIP.Test.ScenarioLoader do
  use ExUnit.Case

  alias SIP.Scenario.Loader

  describe "built-in scenarios" do
    test "load_module! resolves the bundled UAC.Invite and UAC.Register" do
      assert Loader.load_module!("UAC.Invite") == UAC.Invite
      assert Loader.load_module!("UAC.Register") == UAC.Register
    end

    test "built-ins are real scenario modules (run/1 + __scenario_states__/0)" do
      for mod <- [UAC.Invite, UAC.Register] do
        # function_exported?/3 only sees loaded modules; force the load first so
        # the assertion does not depend on a prior test having referenced it
        # (ExUnit randomizes test order within the module).
        Code.ensure_loaded!(mod)
        assert function_exported?(mod, :run, 1)
        assert :initial_state in mod.__scenario_states__()
      end
    end

    test "global keys from the built-in config block reach the app env" do
      # build_context routes proxyuri/proxyusesrv to the :elixip2 app env.
      saved = Enum.map([:proxyuri, :proxyusesrv], &{&1, Application.get_env(:elixip2, &1)})

      on_exit(fn ->
        Enum.each(saved, fn
          {k, nil} -> Application.delete_env(:elixip2, k)
          {k, v} -> Application.put_env(:elixip2, k, v)
        end)
      end)

      ctx = SIP.Scenario.Runner.build_context(UAC.Register.__scenario_config__())
      assert ctx.username == "1000"
      assert ctx.domain == "example.com"

      assert %SIP.Uri{domain: "sip.example.com", port: 5060} =
               Application.get_env(:elixip2, :proxyuri)

      assert Application.get_env(:elixip2, :proxyusesrv) == false
    end
  end

  describe "errors" do
    test "load_module! raises for an unknown module" do
      assert_raise RuntimeError, ~r/not available/, fn ->
        Loader.load_module!("UAC.DoesNotExist")
      end
    end

    test "load_module! raises for a module that is not a scenario" do
      assert_raise RuntimeError, ~r/not a SIP.Scenario/, fn ->
        Loader.load_module!("SIP.Uri")
      end
    end
  end
end
