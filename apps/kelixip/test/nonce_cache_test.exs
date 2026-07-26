defmodule Kelix.NonceCacheTest do
  use ExUnit.Case, async: false

  alias Kelix.NonceCache

  setup do
    start_supervised!(NonceCache)
    :ok
  end

  test "nc must strictly advance per nonce" do
    assert NonceCache.check_nc("n1", 1) == :ok
    assert NonceCache.check_nc("n1", 1) == :replay
    assert NonceCache.check_nc("n1", 2) == :ok
    assert NonceCache.check_nc("n1", 2) == :replay
    # a lower nc than the max seen is a replay
    assert NonceCache.check_nc("n1", 1) == :replay
  end

  test "different nonces are independent" do
    assert NonceCache.check_nc("a", 5) == :ok
    assert NonceCache.check_nc("b", 1) == :ok
    assert NonceCache.check_nc("b", 6) == :ok
  end

  test "the sweep drops entries past the TTL" do
    stop_supervised!(NonceCache)
    start_supervised!({NonceCache, ttl_ms: 100})

    assert NonceCache.check_nc("x", 3) == :ok
    assert NonceCache.check_nc("x", 3) == :replay
    # after the TTL the nonce is forgotten, so the same nc is accepted again
    Process.sleep(260)
    assert NonceCache.check_nc("x", 3) == :ok
  end
end
