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

  # ── authenticating something other than a REGISTER ──────────────────────────

  describe "challengeable?/1" do
    test "an initial INVITE is challenged" do
      assert AuthDb.challengeable?(%{method: :INVITE, to: "<sip:bob@#{@domain}>"})
    end

    test "ACK and CANCEL never are — neither can carry the answer to a challenge" do
      refute AuthDb.challengeable?(%{method: :ACK, to: "<sip:bob@#{@domain}>"})
      refute AuthDb.challengeable?(%{method: :CANCEL, to: "<sip:bob@#{@domain}>"})
    end

    test "OPTIONS never is — challenging a liveness probe makes this node look down" do
      refute AuthDb.challengeable?(%{method: :OPTIONS, to: "<sip:bob@#{@domain}>"})
    end

    test "an in-dialog request is not, the dialog was authenticated when created" do
      in_dialog = %{method: :INVITE, to: "<sip:bob@#{@domain}>;tag=abc123"}
      refute AuthDb.challengeable?(in_dialog)
    end

    test "it reads the To tag off a %SIP.Uri{} too, not only the raw header" do
      uri = %SIP.Uri{userpart: "bob", domain: @domain, params: %{"tag" => "abc"}}
      refute AuthDb.challengeable?(%{method: :INVITE, to: uri})
      assert AuthDb.challengeable?(%{method: :INVITE, to: %SIP.Uri{uri | params: %{}}})
    end
  end

  describe "authenticate/3 on an INVITE" do
    # The digest covers the METHOD, so a credential is not transferable between
    # requests: this is what makes authenticating a call different from replaying
    # the registration's Authorization header.
    defp invite_auth(nonce, opts) do
      method = Keyword.get(opts, :method, "INVITE")

      %{
        "username" => Keyword.get(opts, :username, @user),
        "realm" => @domain,
        "nonce" => nonce,
        "uri" => @uri,
        "response" => SIP.Auth.compute_auth_response_from_ha1("MD5", nonce, @ha1, method, @uri),
        "algorithm" => "MD5"
      }
    end

    defp invite(auth, opts \\ []) do
      %{
        method: :INVITE,
        from: %SIP.Uri{userpart: Keyword.get(opts, :from, @user), domain: @domain},
        to: "<sip:bob@#{@domain}>",
        ruri: %SIP.Uri{userpart: "bob", domain: @domain},
        authorization: auth
      }
    end

    test "a valid digest → {:ok, identity}" do
      req = invite(invite_auth(nonce(), []))

      assert {:ok, %{user: @user, realm: @domain}} =
               AuthDb.authenticate(req, @domain, [now: @now] ++ lookup())
    end

    test "no credentials → challenge, as for a REGISTER" do
      assert AuthDb.authenticate(invite(nil) |> Map.delete(:authorization), @domain, lookup()) ==
               {:requireauth, false}
    end

    test "a REGISTER's Authorization replayed on an INVITE is refused" do
      # same nonce, same user, same everything — but hashed over REGISTER
      req = invite(invite_auth(nonce(), method: "REGISTER"))

      assert AuthDb.authenticate(req, @domain, [now: @now] ++ lookup()) ==
               {:reject, 403, "Forbidden"}
    end

    test "Proxy-Authorization is read like Authorization (a 407 challenge)" do
      req =
        invite(nil)
        |> Map.delete(:authorization)
        |> Map.put(:proxyauthorization, invite_auth(nonce(), []))

      assert {:ok, _} = AuthDb.authenticate(req, @domain, [now: @now] ++ lookup())
    end
  end

  describe "identity check (the From is not proof of anything)" do
    # A valid digest proves who holds the password, not that the From is theirs.
    defp spoofed(opts) do
      %{
        method: :INVITE,
        from: %SIP.Uri{userpart: "bob", domain: @domain},
        to: "<sip:carol@#{@domain}>",
        authorization: %{
          "username" => @user,
          "realm" => @domain,
          "nonce" => Keyword.fetch!(opts, :nonce),
          "uri" => @uri,
          "response" =>
            SIP.Auth.compute_auth_response_from_ha1(
              "MD5",
              Keyword.fetch!(opts, :nonce),
              @ha1,
              "INVITE",
              @uri
            ),
          "algorithm" => "MD5"
        }
      }
    end

    test ":strict refuses alice authenticating a call From: bob" do
      opts = [now: @now, identity_check: :strict] ++ lookup()

      assert AuthDb.authenticate(spoofed(nonce: nonce()), @domain, opts) ==
               {:reject, 403, "Forbidden"}
    end

    test ":warn lets it through (and says so), which is the shipped default" do
      opts = [now: @now, identity_check: :warn] ++ lookup()
      assert {:ok, %{user: @user}} = AuthDb.authenticate(spoofed(nonce: nonce()), @domain, opts)
    end

    test ":off does not even look" do
      opts = [now: @now, identity_check: :off] ++ lookup()
      assert {:ok, %{user: @user}} = AuthDb.authenticate(spoofed(nonce: nonce()), @domain, opts)
    end

    test "a matching From passes under :strict" do
      req = %{spoofed(nonce: nonce()) | from: %SIP.Uri{userpart: @user, domain: @domain}}
      opts = [now: @now, identity_check: :strict] ++ lookup()
      assert {:ok, %{user: @user}} = AuthDb.authenticate(req, @domain, opts)
    end

    test "a REGISTER is held against its To (the AOR), not its From" do
      req = %{
        method: :REGISTER,
        # the From claims someone else; only the To matters for a REGISTER
        from: %SIP.Uri{userpart: "someone-else", domain: @domain},
        to: "<sip:#{@user}@#{@domain}>",
        authorization: auth(nonce())
      }

      opts = [now: @now, identity_check: :strict] ++ lookup()
      assert AuthDb.do_registration_auth(req, @domain, opts) == :ok
    end

    test "a REGISTER binding an AOR that is not the authenticated user is refused" do
      req = %{
        method: :REGISTER,
        to: "<sip:victim@#{@domain}>",
        authorization: auth(nonce())
      }

      opts = [now: @now, identity_check: :strict] ++ lookup()
      assert AuthDb.do_registration_auth(req, @domain, opts) == {:reject, 403, "Forbidden"}
    end
  end

  describe "fetch_credential/3" do
    test "returns the secret tagged with the algorithm it was salted with" do
      assert AuthDb.fetch_credential(@user, @domain, lookup()) == {:ok, {:ha1, "MD5", @ha1}}
    end

    test "an unknown subscriber is :notfound, not an error" do
      assert AuthDb.fetch_credential("ghost", @domain, ha1_lookup: fn _u, _r -> :notfound end) ==
               :notfound
    end

    test "the hex is normalised — a base holding upper case still verifies" do
      upper = [ha1_lookup: fn _u, _r -> {:ok, String.upcase(@ha1)} end]
      assert {:ok, {:ha1, "MD5", hex}} = AuthDb.fetch_credential(@user, @domain, upper)
      assert hex == @ha1
    end
  end
end
