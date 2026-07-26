defmodule Kelix.AuthTest do
  use ExUnit.Case, async: true

  @secret :binary.copy(<<0x5C>>, 32)

  test "builds a WWW-Authenticate challenge with a valid stateless nonce + qop" do
    params = Kelix.Auth.challenge_www_authenticate("example.com", secret: @secret)

    assert params["realm"] == "example.com"
    assert params["qop"] == "auth"
    assert params["algorithm"] == "MD5"
    assert params[:authproc] == "Digest"
    refute Map.has_key?(params, "stale")
    # the embedded nonce is a real Kelix.Nonce for this realm
    assert Kelix.Nonce.validate(params["nonce"], "example.com", secret: @secret) == :ok
  end

  test "stale: true adds stale=true to the challenge" do
    params = Kelix.Auth.challenge_www_authenticate("d.com", secret: @secret, stale: true)
    assert params["stale"] == "true"
  end
end
