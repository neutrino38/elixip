defmodule SIP.Test.FSL.BuildContext do
  @moduledoc """
  `SIP.Scenario.Runner.build_context/1` as a **routing** function: one `config`
  keyword list, three destinations.

  | Kind of key | Destination |
  |---|---|
  | a native context property (`:username`, `:domain`, `:debug`, …) | a struct field |
  | a global key (`:proxyuri`, `:proxyusesrv`, `:optionkeepaliveperiod`, `:mediaserver`) | the `:elixip2` application env |
  | anything else | `appdata` |

  `scenario_engine_test` covers the happy path of the first and the third; the
  global-key path is only covered indirectly, through `scenario_loader_test`.
  This pins all three *as one routing decision*, which is what
  `c:build_context/1` becomes when the context migrates
  (finite-state-language/elixir/docs/extraction-plan.md §4.1): Elixip's host
  keeps this routing, and `FSL.Host.Default` puts everything in `appdata`.
  """
  use ExUnit.Case

  alias SIP.Scenario.Runner

  # Every key this function writes outside the context. Restored on exit, so the
  # module is invisible to whatever runs next (see SIP.Test.AppEnv).
  setup_all do
    SIP.Test.AppEnv.preserve([:proxyuri, :proxyusesrv, :optionkeepaliveperiod, :mediaserver])
    :ok
  end

  test "one config block, three destinations" do
    ctx =
      Runner.build_context(
        # native properties → struct fields
        username: "alice",
        domain: "example.com",
        # a global key → the :elixip2 application env
        proxyuri: "sip:proxy.example.com:5080",
        # unknown / non-native → appdata
        favourite_colour: "blue"
      )

    assert ctx.username == "alice"
    assert ctx.domain == "example.com"

    assert %SIP.Uri{domain: "proxy.example.com", port: 5080} =
             Application.get_env(:elixip2, :proxyuri)

    assert SIP.Context.appdata_get(ctx, :favourite_colour) == "blue"

    # …and each key went to ONE place. A global key that also landed in appdata
    # would be read back by a scenario that should be reading the app env.
    assert SIP.Context.appdata_get(ctx, :proxyuri) == nil
    assert SIP.Context.appdata_get(ctx, :username) == nil
  end

  test "the global keys are exactly those four" do
    Application.delete_env(:elixip2, :proxyusesrv)
    Application.delete_env(:elixip2, :optionkeepaliveperiod)

    ctx =
      Runner.build_context(
        proxyusesrv: true,
        optionkeepaliveperiod: 42,
        mediaserver: [module: :mockup, url: "sip:localhost:8080"]
      )

    assert Application.get_env(:elixip2, :proxyusesrv) == true
    assert Application.get_env(:elixip2, :optionkeepaliveperiod) == 42

    assert Application.get_env(:elixip2, :mediaserver) == [
             module: :mockup,
             url: "sip:localhost:8080"
           ]

    # None of them is a context property, and none of them is appdata.
    assert Map.from_struct(ctx) == Map.from_struct(%SIP.Context{})
  end

  test ":proxyuri accepts a parsed URI as well as a string, and both converge" do
    {:ok, uri} = SIP.Uri.parse("sip:proxy2.example.com:5090")
    Runner.build_context(proxyuri: uri)
    assert Application.get_env(:elixip2, :proxyuri) == uri

    Runner.build_context(proxyuri: "sip:proxy2.example.com:5090")

    assert %SIP.Uri{domain: "proxy2.example.com", port: 5090} =
             Application.get_env(:elixip2, :proxyuri)
  end

  test "an invalid :proxyuri raises rather than being stored" do
    assert_raise RuntimeError, ~r/invalid proxyuri/, fn ->
      Runner.build_context(proxyuri: "not a uri at all")
    end
  end

  test "an invalid :mediaserver raises rather than being stored" do
    assert_raise RuntimeError, ~r/invalid mediaserver config/, fn ->
      Runner.build_context(mediaserver: "http://localhost:8080")
    end
  end

  # :passwd is applied LAST, because computing :ha1 needs :authusername,
  # :domain and :algorithm to be set first. Written in the other order in the
  # config block, which is what a scenario is free to do.
  test ":passwd becomes :ha1, whatever order the config block is written in" do
    ctx =
      Runner.build_context(
        passwd: "secret",
        username: "bob",
        authusername: "bob",
        domain: "example.com"
      )

    assert ctx.ha1 == SIP.Auth.compute_ha1("MD5", "bob", "example.com", "secret")
    # The cleartext password is not kept anywhere in the context.
    refute :passwd in Map.keys(Map.from_struct(ctx))
    assert SIP.Context.appdata_get(ctx, :passwd) == nil
  end

  test ":debug is a native boolean property, not appdata" do
    assert Runner.build_context(debug: true).debug == true
    assert SIP.Context.appdata_get(Runner.build_context(debug: true), :debug) == nil
  end

  test "an empty config block builds the default context" do
    assert Runner.build_context([]) == %SIP.Context{}
  end
end
