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
    %{
      scenario:
        SIP.Scenario.Loader.load_file!(
          Path.expand("../../kelixip/scripts/registrar.exs", __DIR__)
        )
    }
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
      ruri: %SIP.Uri{
        userpart: @user,
        domain: @domain,
        destip: {1, 2, 3, 4},
        destport: 5060,
        destproto: "UDP"
      },
      contact:
        Keyword.get(opts, :contact, %SIP.Uri{userpart: @user, domain: "10.0.0.9", port: 5060}),
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

  # Authenticate once and return the nonce-bearing digest for the next request.
  defp authenticate(pid, dialog, req) do
    send(pid, {:REGISTER, req, nil, dialog})
    assert_receive {:replied, 401, _, fields, _}, 1000
    digest_auth(fields[:wwwauthenticate]["nonce"])
  end

  test "a 423 carries the mandatory Min-Expires header", %{scenario: module} do
    {:ok, dialog} = MockDialog.start_link(self())
    pid = spawn_registrar(module, dialog)

    short = register(expires: 10)
    auth = authenticate(pid, dialog, short)

    send(pid, {:REGISTER, Map.put(short, :authorization, auth), nil, dialog})
    assert_receive {:replied, 423, "Interval Too Brief", fields, _}, 1000

    # RFC 3261 §10.3-7: without it the client cannot know what to renegotiate.
    assert {"Min-Expires", value} = List.keyfind(fields, "Min-Expires", 0)
    assert String.to_integer(value) == Registrar.min_expires()
  end

  test "a wildcard Contact with Expires: 0 drops every binding", %{scenario: module} do
    {:ok, dialog} = MockDialog.start_link(self())
    pid = spawn_registrar(module, dialog)

    # register two contacts first
    send(
      pid,
      {:REGISTER, register(authorization: authenticate(pid, dialog, register())), nil, dialog}
    )

    assert_receive {:replied, 200, _, _, _}, 1000

    second = register(contact: %SIP.Uri{userpart: @user, domain: "10.0.0.42", port: 5060})

    send(
      pid,
      {:REGISTER, Map.put(second, :authorization, authenticate(pid, dialog, second)), nil, dialog}
    )

    assert_receive {:replied, 200, _, _, _}, 1000
    assert length(Registrar.bindings(@domain, @user)) == 2

    # "Contact: *" + "Expires: 0" — the UA-shutdown unregister-all (RFC 3261 §10.2.2)
    wildcard = register(contact: :*, expires: 0)

    send(
      pid,
      {:REGISTER, Map.put(wildcard, :authorization, authenticate(pid, dialog, wildcard)), nil,
       dialog}
    )

    assert_receive {:replied, 200, "OK", fields, _}, 1000
    # nothing is left to enumerate, so the 200 carries no Contact
    assert fields[:contact] == nil
    assert Registrar.bindings(@domain, @user) == []
  end

  test "a wildcard Contact without Expires: 0 is a 400, not an unregister", %{scenario: module} do
    {:ok, dialog} = MockDialog.start_link(self())
    pid = spawn_registrar(module, dialog)

    send(
      pid,
      {:REGISTER, register(authorization: authenticate(pid, dialog, register())), nil, dialog}
    )

    assert_receive {:replied, 200, _, _, _}, 1000

    bad = register(contact: :*, expires: 3600)

    send(
      pid,
      {:REGISTER, Map.put(bad, :authorization, authenticate(pid, dialog, bad)), nil, dialog}
    )

    assert_receive {:replied, 400, _, _, _}, 1000
    # the existing binding survives a malformed wildcard
    assert length(Registrar.bindings(@domain, @user)) == 1
  end

  test "a store that is down answers 503 — never silence", %{scenario: module} do
    {:ok, dialog} = MockDialog.start_link(self())
    pid = spawn_registrar(module, dialog)
    auth = authenticate(pid, dialog, register())

    # Kelix.Module.safe_call/3 degrades to {:error, :down}; the script must map
    # that onto a response, because an unanswered REGISTER is the worst outcome.
    stop_supervised!(Registrar)

    send(pid, {:REGISTER, register(authorization: auth), nil, dialog})
    assert_receive {:replied, 503, _, _, _}, 1000
  end
end
