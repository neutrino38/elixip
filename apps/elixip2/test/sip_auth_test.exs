defmodule SIP.Test.Auth do
  use ExUnit.Case, async: true

  @ha1 SIP.Auth.compute_ha1("MD5", "alice", "example.com", "secret")
  @method "REGISTER"
  @uri "sip:example.com"
  @nonce "deadbeef"

  defp md5_hex(s), do: :crypto.hash(:md5, s) |> Base.encode16(case: :lower)

  test "RFC 2069 response (no qop) matches H(HA1:nonce:HA2)" do
    ha2 = md5_hex("#{@method}:#{@uri}")
    expected = md5_hex("#{@ha1}:#{@nonce}:#{ha2}")
    assert SIP.Auth.compute_auth_response_from_ha1("MD5", @nonce, @ha1, @method, @uri) == expected
  end

  test "qop=auth response matches H(HA1:nonce:nc:cnonce:qop:HA2)" do
    nc = "00000001"
    cnonce = "0a4f113b"
    ha2 = md5_hex("#{@method}:#{@uri}")
    expected = md5_hex("#{@ha1}:#{@nonce}:#{nc}:#{cnonce}:auth:#{ha2}")

    got =
      SIP.Auth.compute_auth_response_from_ha1("MD5", @nonce, @ha1, @method, @uri, %{
        "nc" => nc,
        "cnonce" => cnonce,
        "qop" => "auth"
      })

    assert got == expected
    # the qop form differs from the RFC 2069 form
    refute got == SIP.Auth.compute_auth_response_from_ha1("MD5", @nonce, @ha1, @method, @uri)
  end

  describe "expected_response_from_ha1/4 dispatch" do
    test "uses the qop form when the client sent qop/nc/cnonce" do
      params = %{"nonce" => @nonce, "uri" => @uri, "qop" => "auth", "nc" => "00000001", "cnonce" => "abcd"}

      assert SIP.Auth.expected_response_from_ha1("MD5", @ha1, @method, params) ==
               SIP.Auth.compute_auth_response_from_ha1("MD5", @nonce, @ha1, @method, @uri, %{
                 "nc" => "00000001",
                 "cnonce" => "abcd",
                 "qop" => "auth"
               })
    end

    test "falls back to RFC 2069 when there is no qop" do
      params = %{"nonce" => @nonce, "uri" => @uri}

      assert SIP.Auth.expected_response_from_ha1("MD5", @ha1, @method, params) ==
               SIP.Auth.compute_auth_response_from_ha1("MD5", @nonce, @ha1, @method, @uri)
    end
  end
end
