defmodule SIP.Test.ScenarioLoader do
  @moduledoc """
  What loading a scenario means **for SIP**: the built-ins Elixip compiles into
  the escript, and the `:uac` default of a module that declared no role.

  The loader itself is `FSL.Loader` and its generic half — resolving a name,
  refusing a module that is not a machine, compiling an `.exs` and picking the
  right module out of it — is tested in the package (`test/loader_test.exs`).
  What is here is what the language has no opinion about.
  """
  use ExUnit.Case

  alias SIP.Scenario.Loader

  describe "built-in scenarios" do
    test "load_module! resolves the bundled scenarios" do
      assert Loader.load_module!("UAC.Invite") == UAC.Invite
      assert Loader.load_module!("UAC.Register") == UAC.Register
      assert Loader.load_module!("UAC.Page") == UAC.Page
      assert Loader.load_module!("UAS.Page") == UAS.Page
    end

    test "UAS.Page is a page-mode server, UAC.Page a client" do
      assert Loader.scenario_type(UAS.Page) == :uas_message
      assert Loader.scenario_type(UAC.Page) == :uac
    end

    test "the editable copies load by path, under their own names" do
      dir = Path.expand("../scenarios", __DIR__)
      assert Loader.load_file!(Path.join(dir, "uac_page.exs")) == UAC.PageExample
      assert Loader.load_file!(Path.join(dir, "uas_page.exs")) == UAS.PageExample
    end

    test "built-ins are real scenario modules (run/1 + __scenario_states__/0)" do
      for mod <- [UAC.Invite, UAC.Register, UAC.Page, UAS.Page] do
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

  describe "the role a scenario declared" do
    # `:uac` is a SIP role name, so the language keeps the slot opaque and has no
    # opinion about what "declared nothing" means. The default is applied here,
    # on SIP's side of the facade — including for a module compiled before the
    # `uas` annotation existed, which has no `__scenario_type__/0` at all.
    test "defaults to :uac, which FSL.Loader does not" do
      defmodule PlainUAC do
        use SIP.Scenario

        state initial_state do
          scenario_success("x")
        end
      end

      assert Loader.scenario_type(PlainUAC) == :uac
      assert FSL.Loader.scenario_type(PlainUAC) == :uac

      defmodule NotAMachine do
        def hello, do: :world
      end

      # The language answers `nil` for a module that declared nothing at all;
      # SIP reads that as `:uac`.
      assert FSL.Loader.scenario_type(NotAMachine) == nil
      assert Loader.scenario_type(NotAMachine) == :uac
    end

    test "a server scenario declares its own, and both agree" do
      defmodule Registrar do
        use SIP.Scenario
        uas(:register)

        state initial_state do
          scenario_success("x")
        end
      end

      assert Loader.scenario_type(Registrar) == :uas_register
      assert FSL.Loader.scenario_type(Registrar) == :uas_register
    end
  end
end
