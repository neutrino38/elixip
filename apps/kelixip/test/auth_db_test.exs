defmodule Kelix.Mod.AuthDbTest do
  # Tests the auth VERDICT logic with an injected HA1 lookup (no DB). The DB
  # query (lookup_ha1/2) is covered by a separate, credential-gated live test.
  use ExUnit.Case, async: false

  alias Kelix.Mod.AuthDb

  @domain "example.com"
  @user "alice"
  @pass "secret"
  @uri "sip:example.com"
  @now 1_000_000

  @ha1 SIP.Auth.compute_ha1("MD5", @user, @domain, @pass)

  # SIP.Auth.Secret + Kelix.NonceCache are supervised by the application (§2.1), so
  # they are already up here — nothing to start.

  # inject the "DB": a valid user resolves to the known HA1
  defp lookup do
    [ha1_lookup: fn @user, @domain -> {:ok, @ha1} end]
  end

  defp nonce(now \\ @now), do: SIP.Auth.Nonce.generate(@domain, now: now)

  # a plain (no-qop) Authorization with a correct response
  defp auth(nonce, opts \\ []) do
    response =
      case Keyword.get(opts, :response) do
        nil -> SIP.Auth.compute_auth_response_from_ha1("MD5", nonce, @ha1, "REGISTER", @uri)
        r -> r
      end

    %{
      "username" => @user,
      "realm" => Keyword.get(opts, :realm, @domain),
      "nonce" => nonce,
      "uri" => @uri,
      "response" => response,
      "algorithm" => "MD5"
    }
  end

  defp reg(auth), do: %{method: :REGISTER, authorization: auth}

  test "no Authorization → challenge (not stale)" do
    assert AuthDb.do_registration_auth(%{method: :REGISTER}, @domain, lookup()) == {:requireauth, false}
  end

  test "a valid digest → :ok" do
    assert AuthDb.do_registration_auth(reg(auth(nonce())), @domain, [now: @now] ++ lookup()) == :ok
  end

  test "a wrong password (bad response) → 403" do
    a = auth(nonce(), response: "00000000000000000000000000000000")
    assert AuthDb.do_registration_auth(reg(a), @domain, [now: @now] ++ lookup()) == {:reject, 403, "Forbidden"}
  end

  test "an unknown user (:notfound) → 403" do
    lookup = [ha1_lookup: fn _u, _r -> :notfound end]
    assert AuthDb.do_registration_auth(reg(auth(nonce())), @domain, [now: @now] ++ lookup) == {:reject, 403, "Forbidden"}
  end

  test "a realm mismatch → 403" do
    a = auth(nonce(), realm: "evil.com")
    assert AuthDb.do_registration_auth(reg(a), @domain, [now: @now] ++ lookup()) == {:reject, 403, "Forbidden"}
  end

  test "a forged nonce → fresh challenge" do
    a = auth("not-a-real-nonce")
    assert AuthDb.do_registration_auth(reg(a), @domain, [now: @now] ++ lookup()) == {:requireauth, false}
  end

  test "an expired nonce → stale challenge" do
    a = auth(nonce(@now))
    # validate 100 s later with a 60 s window → stale
    opts = [now: @now + 100, max_age: 60] ++ lookup()
    assert AuthDb.do_registration_auth(reg(a), @domain, opts) == {:requireauth, true}
  end

  test "a DB error → 500" do
    lookup = [ha1_lookup: fn _u, _r -> {:error, :db_down} end]
    assert AuthDb.do_registration_auth(reg(auth(nonce())), @domain, [now: @now] ++ lookup) == {:reject, 500, "Server Internal Error"}
  end

  describe "qop=auth + nc anti-replay" do
    defp qop_auth(nonce, nc) do
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

    test "a valid qop=auth response → :ok, and replaying the same nc → stale challenge" do
      n = nonce()
      assert AuthDb.do_registration_auth(reg(qop_auth(n, "00000001")), @domain, [now: @now] ++ lookup()) == :ok
      # same nonce + same nc = replay
      assert AuthDb.do_registration_auth(reg(qop_auth(n, "00000001")), @domain, [now: @now] ++ lookup()) == {:requireauth, true}
      # advancing nc is accepted
      assert AuthDb.do_registration_auth(reg(qop_auth(n, "00000002")), @domain, [now: @now] ++ lookup()) == :ok
    end
  end
end
