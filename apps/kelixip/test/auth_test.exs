defmodule Kelix.AuthTest do
  use ExUnit.Case, async: true

  @secret :binary.copy(<<0x5C>>, 32)

  test "builds a digest challenge with a valid stateless nonce + qop" do
    params = Kelix.Auth.challenge_params("example.com", secret: @secret)

    assert params["realm"] == "example.com"
    assert params["qop"] == "auth"
    assert params["algorithm"] == "MD5"
    assert params[:authproc] == "Digest"
    refute Map.has_key?(params, "stale")
    # the embedded nonce is a real SIP.Auth.Nonce for this realm
    assert SIP.Auth.Nonce.validate(params["nonce"], "example.com", secret: @secret) == :ok
  end

  test "stale: true adds stale=true to the challenge" do
    params = Kelix.Auth.challenge_params("d.com", secret: @secret, stale: true)
    assert params["stale"] == "true"
  end

  # The params say nothing about which header carries them; the code does, and that
  # mapping has one home (401 → WWW-Authenticate for a UAS, 407 → Proxy-Authenticate
  # for the server routing a call).
  test "the challenge header follows the response code" do
    assert SIP.Msg.Ops.challenge_header(401) == :wwwauthenticate
    assert SIP.Msg.Ops.challenge_header(407) == :proxyauthenticate
  end
end
