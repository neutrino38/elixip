defmodule Kelix.Mod.AuthDbLiveTest do
  # Live counterpart to auth_db_test.exs: exercises the REAL MyXQL query
  # (lookup_ha1/2) and the full verdict chain against an actual Kamailio-style
  # `subscriber` table.
  #
  # Credentials are NEVER committed: they live in an external JSON file pointed
  # to by KELIX_AUTHDB_CONFIG. Absent that env var (or file), the whole module
  # is skipped, so `mix test` stays green without a database (same spirit as the
  # MENDOOZE_URL gate for the Mendooze E2E).
  #
  # Run with:
  #
  #   KELIX_AUTHDB_CONFIG=./authdb.json \
  #     mix test apps/kelixip/test/auth_db_live_test.exs
  #
  # See test/fixtures/authdb.json.example for the file shape. The test reads the
  # stored HA1 (Kamailio: ha1 = md5(user:realm:password)) and forges a valid
  # digest from it — so no cleartext password is needed and the whole
  # DB → verdict path is covered.
  use ExUnit.Case, async: false

  alias Kelix.Mod.AuthDb

  @cfg_path System.get_env("KELIX_AUTHDB_CONFIG")

  @skip_reason (cond do
                  is_nil(@cfg_path) -> "KELIX_AUTHDB_CONFIG not set"
                  not File.exists?(@cfg_path) -> "KELIX_AUTHDB_CONFIG file not found: #{@cfg_path}"
                  true -> false
                end)

  # test_helper does `exclude: [:skip]`, a bare-atom filter that excludes on the
  # mere PRESENCE of the :skip tag — so only set it when we actually skip.
  if @skip_reason, do: @moduletag(skip: @skip_reason)

  @uri "sip:kelix"

  # External JSON: DB connection keys (consumed by AuthDb.child_spec/configure)
  # plus two test parameters — "realm" (the domain/auth realm) and "testuser"
  # (a subscriber known to exist in that realm).
  defp load_config do
    @cfg_path |> File.read!() |> Jason.decode!()
  end

  setup do
    file = load_config()

    realm = file["realm"] || raise ~s(missing "realm" in #{@cfg_path})
    user = file["testuser"] || raise ~s(missing "testuser" in #{@cfg_path})

    # everything except the two test params is DB/facade config
    cfg = Map.drop(file, ["realm", "testuser"])

    # facade config (table/columns/hash) → app env; the real DB connection as a
    # supervised child; nonce infra for the end-to-end verdict path.
    AuthDb.configure(cfg)
    start_supervised!(AuthDb.child_spec(cfg))
    start_supervised!(Kelix.Secret)
    start_supervised!(Kelix.NonceCache)

    %{realm: realm, user: user}
  end

  test "lookup_ha1/2 returns the stored HA1 for a known subscriber", %{realm: realm, user: user} do
    assert {:ok, ha1} = AuthDb.lookup_ha1(user, realm)
    assert is_binary(ha1)
    # Kamailio ha1 is an MD5 hex digest
    assert ha1 =~ ~r/\A[0-9a-f]{32}\z/
  end

  test "lookup_ha1/2 returns :notfound for an unknown user", %{realm: realm} do
    unknown = "no-such-user-#{System.unique_integer([:positive])}"
    assert AuthDb.lookup_ha1(unknown, realm) == :notfound
  end

  test "do_registration_auth: a digest forged from the DB HA1 → :ok", %{realm: realm, user: user} do
    {:ok, ha1} = AuthDb.lookup_ha1(user, realm)
    nonce = Kelix.Nonce.generate(realm)

    response = SIP.Auth.compute_auth_response_from_ha1("MD5", nonce, ha1, "REGISTER", @uri)

    auth = %{
      "username" => user,
      "realm" => realm,
      "nonce" => nonce,
      "uri" => @uri,
      "response" => response,
      "algorithm" => "MD5"
    }

    req = %{method: :REGISTER, authorization: auth}
    # no :ha1_lookup opt → goes through the real DB
    assert AuthDb.do_registration_auth(req, realm) == :ok
  end

  test "do_registration_auth: a wrong response → 403", %{realm: realm, user: user} do
    nonce = Kelix.Nonce.generate(realm)

    auth = %{
      "username" => user,
      "realm" => realm,
      "nonce" => nonce,
      "uri" => @uri,
      "response" => "00000000000000000000000000000000",
      "algorithm" => "MD5"
    }

    req = %{method: :REGISTER, authorization: auth}
    assert AuthDb.do_registration_auth(req, realm) == {:reject, 403, "Forbidden"}
  end

  test "do_registration_auth: no Authorization → fresh challenge", %{realm: realm} do
    assert AuthDb.do_registration_auth(%{method: :REGISTER}, realm) == {:requireauth, false}
  end
end
