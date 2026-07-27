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
    assert AuthDb.do_registration_auth(%{method: :REGISTER}, @domain, lookup()) ==
             {:requireauth, false}
  end

  test "a valid digest → :ok" do
    assert AuthDb.do_registration_auth(reg(auth(nonce())), @domain, [now: @now] ++ lookup()) ==
             :ok
  end

  test "a wrong password (bad response) → 403" do
    a = auth(nonce(), response: "00000000000000000000000000000000")

    assert AuthDb.do_registration_auth(reg(a), @domain, [now: @now] ++ lookup()) ==
             {:reject, 403, "Forbidden"}
  end

  test "an unknown user (:notfound) → 403" do
    lookup = [ha1_lookup: fn _u, _r -> :notfound end]

    assert AuthDb.do_registration_auth(reg(auth(nonce())), @domain, [now: @now] ++ lookup) ==
             {:reject, 403, "Forbidden"}
  end

  test "a realm mismatch → 403" do
    a = auth(nonce(), realm: "evil.com")

    assert AuthDb.do_registration_auth(reg(a), @domain, [now: @now] ++ lookup()) ==
             {:reject, 403, "Forbidden"}
  end

  test "a forged nonce → fresh challenge" do
    a = auth("not-a-real-nonce")

    assert AuthDb.do_registration_auth(reg(a), @domain, [now: @now] ++ lookup()) ==
             {:requireauth, false}
  end

  test "an expired nonce → stale challenge" do
    a = auth(nonce(@now))
    # validate 100 s later with a 60 s window → stale
    opts = [now: @now + 100, max_age: 60] ++ lookup()
    assert AuthDb.do_registration_auth(reg(a), @domain, opts) == {:requireauth, true}
  end

  test "a DB error → 500" do
    lookup = [ha1_lookup: fn _u, _r -> {:error, :db_down} end]

    assert AuthDb.do_registration_auth(reg(auth(nonce())), @domain, [now: @now] ++ lookup) ==
             {:reject, 500, "Server Internal Error"}
  end

  describe "unsupported digest algorithm" do
    # SIP.Auth.algo2atom/1 raises on anything it does not know. Reaching it means
    # the scenario instance dies and the REGISTER is never answered — the worst
    # possible outcome, and remotely triggerable without credentials.
    for algo <- ["SHA-256", "SHA-512-256", "MD5-sess", "garbage"] do
      test "#{algo} → re-challenge, never a raise" do
        a = Map.put(auth(nonce()), "algorithm", unquote(algo))

        assert AuthDb.do_registration_auth(reg(a), @domain, [now: @now] ++ lookup()) ==
                 {:requireauth, false}
      end
    end

    test "the algorithm is matched case-insensitively" do
      a = Map.put(auth(nonce()), "algorithm", "md5")
      assert AuthDb.do_registration_auth(reg(a), @domain, [now: @now] ++ lookup()) == :ok
    end

    test "a lookup that raises → 500, not a dead instance" do
      lookup = [ha1_lookup: fn _u, _r -> raise "boom" end]

      assert AuthDb.do_registration_auth(reg(auth(nonce())), @domain, [now: @now] ++ lookup) ==
               {:reject, 500, "Server Internal Error"}
    end
  end

  describe "password_hash drives the algorithm" do
    # The stored HA1 was salted with exactly one hash. Letting the client pick the
    # algorithm made `password_hash` dead config and pushed unknown values into
    # the raising SIP.Auth.algo2atom/1.
    setup do
      previous = Application.get_env(:kelixip, AuthDb)

      on_exit(fn ->
        if previous,
          do: Application.put_env(:kelixip, AuthDb, previous),
          else: Application.delete_env(:kelixip, AuthDb)
      end)

      :ok
    end

    defp configure_hash(hash) do
      AuthDb.configure(%{"database" => "d", "username" => "u", "password_hash" => hash})
    end

    test "the challenge advertises MD5 by default" do
      assert AuthDb.challenge_algorithm() == "MD5"
    end

    test "the challenge advertises SHA-256 when the base stores sha256 HA1s" do
      configure_hash("sha256")
      assert AuthDb.challenge_algorithm() == "SHA-256"
    end

    test "a sha256 base verifies a SHA-256 credential" do
      configure_hash("sha256")
      ha1 = SIP.Auth.compute_ha1("SHA256", @user, @domain, @pass)
      lookup = [ha1_lookup: fn @user, @domain -> {:ok, ha1} end]
      n = nonce()

      a = %{
        auth(n)
        | "algorithm" => "SHA-256",
          "response" =>
            SIP.Auth.compute_auth_response_from_ha1("SHA256", n, ha1, "REGISTER", @uri)
      }

      assert AuthDb.do_registration_auth(reg(a), @domain, [now: @now] ++ lookup) == :ok
    end

    test "a sha256 base re-challenges an MD5 credential instead of failing obscurely" do
      configure_hash("sha256")

      assert AuthDb.do_registration_auth(reg(auth(nonce())), @domain, [now: @now] ++ lookup()) ==
               {:requireauth, false}
    end
  end

  describe "subscriber lookup key (ha1 vs ha1b conventions)" do
    test "a bare username is the row key as-is" do
      assert AuthDb.subscriber_of("alice") == "alice"
    end

    test "user@domain is stripped to the bare user — ha1b rows are keyed on it" do
      assert AuthDb.subscriber_of("alice@example.com") == "alice"
    end

    test "an ha1b deployment authenticates a user@domain credential" do
      # ha1b = H(user@domain:realm:password): the client authenticates as
      # `alice@example.com`, but the subscriber row is still keyed on `alice`.
      ha1b = SIP.Auth.compute_ha1("MD5", "#{@user}@#{@domain}", @domain, @pass)
      lookup = [ha1_lookup: fn @user, @domain -> {:ok, ha1b} end]
      n = nonce()

      a = %{
        auth(n)
        | "username" => "#{@user}@#{@domain}",
          "response" => SIP.Auth.compute_auth_response_from_ha1("MD5", n, ha1b, "REGISTER", @uri)
      }

      assert AuthDb.do_registration_auth(reg(a), @domain, [now: @now] ++ lookup) == :ok
    end

    test "an upper-case HA1 in the base still verifies" do
      lookup = [ha1_lookup: fn @user, @domain -> {:ok, String.upcase(@ha1)} end]

      assert AuthDb.do_registration_auth(reg(auth(nonce())), @domain, [now: @now] ++ lookup) ==
               :ok
    end
  end

  describe "validate_config/1" do
    @valid %{"database" => "kamailio", "username" => "kamailio"}

    test "accepts a full block" do
      assert AuthDb.validate_config(Map.merge(@valid, %{"ha1_column" => "ha1b", "port" => 3306})) ==
               :ok
    end

    test "rejects an unknown key rather than silently ignoring it" do
      assert {:error, reason} = AuthDb.validate_config(Map.put(@valid, "ha1_colum", "ha1b"))
      assert reason =~ "ha1_colum"
    end

    test "rejects a column name that is not a plain SQL identifier" do
      assert {:error, _} = AuthDb.validate_config(Map.put(@valid, "ha1_column", "ha1; DROP"))
    end

    test "accepts the pool and TLS knobs" do
      config =
        Map.merge(@valid, %{
          "pool_size" => 8,
          "connect_timeout_ms" => 2_000,
          "ssl" => true,
          "ssl_ca_cert_file" => "/etc/pki/ca.pem"
        })

      assert AuthDb.validate_config(config) == :ok
    end

    test "rejects a non-integer pool_size and a non-boolean ssl" do
      assert {:error, _} = AuthDb.validate_config(Map.put(@valid, "pool_size", "many"))
      assert {:error, _} = AuthDb.validate_config(Map.put(@valid, "ssl", "yes"))
    end
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

      assert AuthDb.do_registration_auth(
               reg(qop_auth(n, "00000001")),
               @domain,
               [now: @now] ++ lookup()
             ) == :ok

      # same nonce + same nc = replay
      assert AuthDb.do_registration_auth(
               reg(qop_auth(n, "00000001")),
               @domain,
               [now: @now] ++ lookup()
             ) == {:requireauth, true}

      # advancing nc is accepted
      assert AuthDb.do_registration_auth(
               reg(qop_auth(n, "00000002")),
               @domain,
               [now: @now] ++ lookup()
             ) == :ok
    end
  end
end
