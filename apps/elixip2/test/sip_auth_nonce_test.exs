defmodule SIP.Test.AuthNonce do
  use ExUnit.Case, async: true

  alias SIP.Auth.Nonce

  @secret :binary.copy(<<0xA7>>, 32)
  @realm "example.com"

  # deterministic opts (fixed secret + clock)
  defp gen(realm, now), do: Nonce.generate(realm, secret: @secret, now: now)
  defp val(nonce, realm, now, max_age \\ 60), do: Nonce.validate(nonce, realm, secret: @secret, now: now, max_age: max_age)

  test "a fresh nonce validates :ok" do
    n = gen(@realm, 1_000_000)
    assert val(n, @realm, 1_000_000) == :ok
    assert val(n, @realm, 1_000_030) == :ok
  end

  test "is base64url (no +/ or padding)" do
    n = gen(@realm, 1_000_000)
    refute n =~ "+"
    refute n =~ "/"
    refute n =~ "="
  end

  test "each nonce is unique (random component)" do
    refute gen(@realm, 1_000_000) == gen(@realm, 1_000_000)
  end

  test "beyond max_age it is :stale (authentic but old)" do
    n = gen(@realm, 1_000_000)
    assert val(n, @realm, 1_000_061) == :stale
    assert val(n, @realm, 1_000_060) == :ok
  end

  test "the realm is bound: a nonce for one domain is :invalid on another" do
    n = gen("a.com", 1_000_000)
    assert Nonce.validate(n, "b.com", secret: @secret, now: 1_000_000) == :invalid
  end

  test "a different secret rejects the nonce" do
    n = gen(@realm, 1_000_000)
    other = :binary.copy(<<0x11>>, 32)
    assert Nonce.validate(n, @realm, secret: other, now: 1_000_000) == :invalid
  end

  test "a tampered nonce is :invalid" do
    n = gen(@realm, 1_000_000)
    # flip a byte in the decoded payload and re-encode
    {:ok, raw} = Base.url_decode64(n, padding: false)
    <<first, rest::binary>> = raw
    tampered = Base.url_encode64(<<Bitwise.bxor(first, 1), rest::binary>>, padding: false)
    assert val(tampered, @realm, 1_000_000) == :invalid
  end

  test "garbage / wrong-length input is :invalid" do
    assert val("not-a-nonce", @realm, 1_000_000) == :invalid
    assert val("", @realm, 1_000_000) == :invalid
    assert val(Base.url_encode64("short", padding: false), @realm, 1_000_000) == :invalid
  end

  test "timestamp/1 extracts the embedded time" do
    n = gen(@realm, 1_234_567)
    assert {:ok, 1_234_567} = Nonce.timestamp(n)
    assert :error = Nonce.timestamp("garbage")
  end

  test "with no :secret opt it uses the node secret, which round-trips" do
    # SIP.Auth.Secret is started by bootstrap_stack/0 in the server and the tool;
    # in a bare test it self-starts, and the same secret must validate the nonce.
    n = Nonce.generate(@realm)
    assert Nonce.validate(n, @realm) == :ok
    assert Nonce.validate(n, "other.com") == :invalid
  end

  test "a non-binary nonce is :invalid, not a crash" do
    assert Nonce.validate(nil, @realm) == :invalid
  end
end
