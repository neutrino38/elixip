defmodule SIP.Test.ExternalConfig do
  use ExUnit.Case

  alias SIP.Scenario.ExternalConfig

  # ── parse! : header ────────────────────────────────────────────────────────

  test "parses the header keys and routes proxyuri through SIP.Uri" do
    %ExternalConfig{header: header} =
      ExternalConfig.parse!(%{
        "domain" => "example.com",
        "proxyuri" => "sip:proxy.example.com:5060",
        "proxyusesrv" => false,
        "optionkeepaliveperiod" => 5,
        "accounts" => [%{"username" => "1000", "password" => "pw"}]
      })

    assert header[:domain] == "example.com"
    assert header[:proxyusesrv] == false
    assert header[:optionkeepaliveperiod] == 5
    assert %SIP.Uri{domain: "proxy.example.com", port: 5060} = header[:proxyuri]
  end

  test "header is optional (only accounts required)" do
    %ExternalConfig{header: header, accounts: [acct]} =
      ExternalConfig.parse!(%{
        "accounts" => [%{"username" => "1000", "password" => "pw", "domain" => "d.com"}]
      })

    assert header == []
    assert acct[:domain] == "d.com"
  end

  # ── parse! : accounts ────────────────────────────────────────────────────────

  test "maps password to :passwd and defaults authusername to username" do
    %ExternalConfig{accounts: [acct]} =
      ExternalConfig.parse!(%{
        "domain" => "ex.com",
        "accounts" => [%{"username" => "1000", "password" => "secret"}]
      })

    assert acct[:username] == "1000"
    assert acct[:passwd] == "secret"
    assert acct[:authusername] == "1000"
    assert acct[:domain] == "ex.com"
    refute Keyword.has_key?(acct, :displayname)
  end

  test "account domain overrides the header domain; authusername/displayname kept" do
    %ExternalConfig{accounts: [acct]} =
      ExternalConfig.parse!(%{
        "domain" => "header.com",
        "accounts" => [
          %{
            "username" => "1000",
            "password" => "pw",
            "authusername" => "auth1000",
            "displayname" => "Bob",
            "domain" => "account.com"
          }
        ]
      })

    assert acct[:domain] == "account.com"
    assert acct[:authusername] == "auth1000"
    assert acct[:displayname] == "Bob"
  end

  # ── overrides_for : round-robin selection ────────────────────────────────────

  test "overrides_for merges header with the round-robin account and is nil-safe" do
    config =
      ExternalConfig.parse!(%{
        "domain" => "ex.com",
        "proxyusesrv" => true,
        "accounts" => [
          %{"username" => "a", "password" => "pa"},
          %{"username" => "b", "password" => "pb"}
        ]
      })

    o0 = ExternalConfig.overrides_for(config, 0)
    o1 = ExternalConfig.overrides_for(config, 1)
    o2 = ExternalConfig.overrides_for(config, 2)

    assert o0[:username] == "a"
    assert o1[:username] == "b"
    # cycles back to the first account
    assert o2[:username] == "a"
    # header keys are merged in
    assert o0[:proxyusesrv] == true
    assert o0[:domain] == "ex.com"

    # nil config -> empty overrides (no --config behaves as before)
    assert ExternalConfig.overrides_for(nil, 0) == []
    assert ExternalConfig.account_count(nil) == 0
    assert ExternalConfig.account_count(config) == 2
  end

  # ── Strict validation : every error raises ───────────────────────────────────

  test "unknown header key raises" do
    assert_raise ArgumentError, ~r/inconnue/, fn ->
      ExternalConfig.parse!(%{
        "proxyusrv" => false,
        "accounts" => [%{"username" => "a", "password" => "p", "domain" => "d"}]
      })
    end
  end

  test "unknown account key raises" do
    assert_raise ArgumentError, ~r/compte inconnue/, fn ->
      ExternalConfig.parse!(%{
        "domain" => "d",
        "accounts" => [%{"username" => "a", "password" => "p", "expire" => 60}]
      })
    end
  end

  test "missing username or password raises" do
    assert_raise ArgumentError, ~r/requis manquant/, fn ->
      ExternalConfig.parse!(%{"domain" => "d", "accounts" => [%{"password" => "p"}]})
    end

    assert_raise ArgumentError, ~r/requis manquant/, fn ->
      ExternalConfig.parse!(%{"domain" => "d", "accounts" => [%{"username" => "a"}]})
    end
  end

  test "domain absent from both account and header raises" do
    assert_raise ArgumentError, ~r/domaine/, fn ->
      ExternalConfig.parse!(%{"accounts" => [%{"username" => "a", "password" => "p"}]})
    end
  end

  test "bad header types raise" do
    assert_raise ArgumentError, fn ->
      ExternalConfig.parse!(%{
        "proxyusesrv" => "no",
        "accounts" => [%{"username" => "a", "password" => "p", "domain" => "d"}]
      })
    end

    assert_raise ArgumentError, fn ->
      ExternalConfig.parse!(%{
        "optionkeepaliveperiod" => "5",
        "accounts" => [%{"username" => "a", "password" => "p", "domain" => "d"}]
      })
    end
  end

  test "invalid proxyuri raises" do
    assert_raise ArgumentError, ~r/proxyuri invalide/, fn ->
      ExternalConfig.parse!(%{
        "proxyuri" => "not a uri",
        "accounts" => [%{"username" => "a", "password" => "p", "domain" => "d"}]
      })
    end
  end

  test "empty or missing accounts raises" do
    assert_raise ArgumentError, ~r/accounts/, fn ->
      ExternalConfig.parse!(%{"domain" => "d", "accounts" => []})
    end

    assert_raise ArgumentError, ~r/accounts/, fn ->
      ExternalConfig.parse!(%{"domain" => "d"})
    end
  end

  # ── load! : file I/O ─────────────────────────────────────────────────────────

  test "load! reads, parses and validates a JSON file" do
    path = Path.join(System.tmp_dir!(), "elixip_cfg_#{System.unique_integer([:positive])}.json")

    File.write!(path, ~s({"domain":"ex.com","accounts":[{"username":"1000","password":"pw"}]}))
    on_exit(fn -> File.rm(path) end)

    %ExternalConfig{accounts: [acct]} = ExternalConfig.load!(path)
    assert acct[:username] == "1000"
  end

  test "load! raises on a missing file" do
    assert_raise ArgumentError, ~r/introuvable/, fn ->
      ExternalConfig.load!("/nonexistent/elixip/does-not-exist.json")
    end
  end

  test "load! raises on invalid JSON" do
    path = Path.join(System.tmp_dir!(), "elixip_bad_#{System.unique_integer([:positive])}.json")
    File.write!(path, "{ not json")
    on_exit(fn -> File.rm(path) end)

    assert_raise ArgumentError, ~r/JSON invalide/, fn -> ExternalConfig.load!(path) end
  end

  # ── Runner integration : overrides + global-key routing ──────────────────────

  defmodule Identity do
    use SIP.Scenario
    config(username: "default", domain: "default.com", proxyusesrv: true)

    state initial_state do
      scenario_success("ok")
    end
  end

  test "config_overrides win over the scenario config block and route globals to app env" do
    # Routing mutates the shared :elixip2 app env — snapshot and restore so this
    # test does not leak into the others.
    saved =
      Enum.map(
        [:proxyuri, :proxyusesrv, :optionkeepaliveperiod],
        &{&1, Application.get_env(:elixip2, &1)}
      )

    on_exit(fn ->
      Enum.each(saved, fn
        {k, nil} -> Application.delete_env(:elixip2, k)
        {k, v} -> Application.put_env(:elixip2, k, v)
      end)
    end)

    config =
      ExternalConfig.parse!(%{
        "domain" => "json.com",
        "proxyuri" => "sip:p.json.com:5060",
        "proxyusesrv" => false,
        "optionkeepaliveperiod" => 7,
        "accounts" => [%{"username" => "json-user", "password" => "pw"}]
      })

    overrides = ExternalConfig.overrides_for(config, 0)

    # build_context applies the per-session keys and routes the global keys.
    ctx =
      SIP.Scenario.Runner.build_context(
        Keyword.merge([username: "default", domain: "default.com", proxyusesrv: true], overrides)
      )

    assert ctx.username == "json-user"
    assert ctx.domain == "json.com"
    # global keys are NOT stored on the context...
    refute Map.has_key?(ctx.appdata, :proxyuri)
    # ...they land in the application env
    assert Application.get_env(:elixip2, :proxyusesrv) == false
    assert Application.get_env(:elixip2, :optionkeepaliveperiod) == 7
    assert %SIP.Uri{domain: "p.json.com"} = Application.get_env(:elixip2, :proxyuri)
  end
end
