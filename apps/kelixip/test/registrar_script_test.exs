defmodule Kelix.RegistrarScriptTest do
  # Drives the full authenticated flow through a spawned instance of the
  # reference registrar script, with a mock dialog capturing the SIP replies:
  #   REGISTER (no auth) → 401 challenge → digest re-REGISTER → 200 + binding.
  # The HA1 "DB" is injected via app env; nonce/secret run for real.
  use ExUnit.Case, async: false

  alias Kelix.Mod.Registrar

  @domain "example.com"
  @user "alice"
  @pass "secret"
  @uri "sip:example.com"
  @ha1 SIP.Auth.compute_ha1("MD5", @user, @domain, @pass)

  defmodule MockDialog do
    use GenServer
    def start_link(test), do: GenServer.start_link(__MODULE__, test)
    def init(test), do: {:ok, test}

    def handle_call({:replyreq, req, code, reason, fields}, _from, test) do
      send(test, {:replied, code, reason, fields, req})
      {:reply, :ok, test}
    end

    def handle_call(_msg, _from, test), do: {:reply, :ok, test}
    def handle_info(_msg, test), do: {:noreply, test}
  end

  setup_all do
    %{scenario: SIP.Scenario.Loader.load_file!(Path.expand("../scripts/registrar.exs", __DIR__))}
  end

  setup do
    # SIP.Auth.Secret + Kelix.NonceCache come from the application tree (§2.1).
    start_supervised!(Registrar)
    # the "subscriber DB": alice@example.com resolves to the known HA1
    Application.put_env(:kelixip, :authdb_ha1_lookup, fn @user, @domain -> {:ok, @ha1} end)
    on_exit(fn -> Application.delete_env(:kelixip, :authdb_ha1_lookup) end)
    :ok
  end

  defp register(opts \\ []) do
    base = %{
      method: :REGISTER,
      to: %SIP.Uri{userpart: @user, domain: @domain},
      ruri: %SIP.Uri{userpart: @user, domain: @domain, destip: {1, 2, 3, 4}, destport: 5060, destproto: "UDP"},
      contact: %SIP.Uri{userpart: @user, domain: "10.0.0.9", port: 5060},
      expires: Keyword.get(opts, :expires, 3600),
      callid: "call-1"
    }

    case Keyword.get(opts, :authorization) do
      nil -> base
      auth -> Map.put(base, :authorization, auth)
    end
  end

  # a qop=auth Authorization computed as a real client would, from the challenge nonce
  defp digest_auth(nonce, nc \\ "00000001") do
    cnonce = "0a4f113b"

    response =
      SIP.Auth.compute_auth_response_from_ha1("MD5", nonce, @ha1, "REGISTER", @uri, %{
        "nc" => nc,
        "cnonce" => cnonce,
        "qop" => "auth"
      })

    %{
      "username" => @user,
      "realm" => @domain,
      "nonce" => nonce,
      "uri" => @uri,
      "response" => response,
      "algorithm" => "MD5",
      "qop" => "auth",
      "nc" => nc,
      "cnonce" => cnonce
    }
  end

  defp spawn_registrar(module, dialog) do
    {pid, _ref} =
      SIP.Scenario.Runner.spawn_uas_instance(module,
        dialog_pid: dialog,
        inbound_request: register(),
        config_overrides: [domain: @domain]
      )

    on_exit(fn -> send(pid, {:scenario_ctl, :shutdown, :test}) end)
    pid
  end

  test "REGISTER → 401 challenge → digest re-REGISTER → 200 + binding", %{scenario: module} do
    {:ok, dialog} = MockDialog.start_link(self())
    pid = spawn_registrar(module, dialog)

    # 1) unauthenticated REGISTER → 401 with a stateless-nonce challenge
    send(pid, {:REGISTER, register(), nil, dialog})
    assert_receive {:replied, 401, "Unauthorized", fields, _}, 1000
    params = fields[:wwwauthenticate]
    assert params["qop"] == "auth" and params["algorithm"] == "MD5"
    nonce = params["nonce"]
    assert Registrar.bindings(@domain, @user) == []

    # 2) the client replays with a digest response → 200 + stored binding
    send(pid, {:REGISTER, register(authorization: digest_auth(nonce)), nil, dialog})
    assert_receive {:replied, 200, "OK", _fields, _}, 1000
    assert [_binding] = Registrar.bindings(@domain, @user)
  end

  test "a wrong password is rejected with 403", %{scenario: module} do
    {:ok, dialog} = MockDialog.start_link(self())
    pid = spawn_registrar(module, dialog)

    send(pid, {:REGISTER, register(), nil, dialog})
    assert_receive {:replied, 401, _, fields, _}, 1000
    nonce = fields[:wwwauthenticate]["nonce"]

    # a response computed with the wrong HA1
    bad = %{digest_auth(nonce) | "response" => "ffffffffffffffffffffffffffffffff"}
    send(pid, {:REGISTER, register(authorization: bad), nil, dialog})
    assert_receive {:replied, 403, _, _, _}, 1000
    assert Registrar.bindings(@domain, @user) == []
  end
end
