defmodule Kelix.NonceCacheTest do
  use ExUnit.Case, async: false

  alias Kelix.NonceCache

  # The default cache is supervised by the application (§2.1), so these tests run
  # against their own named instance: no shared state with the auth tests, and a
  # short TTL for the sweep test.
  setup do
    start_supervised!({NonceCache, name: :nc_test})
    :ok
  end

  test "nc must strictly advance per nonce" do
    assert NonceCache.check_nc("n1", 1, :nc_test) == :ok
    assert NonceCache.check_nc("n1", 1, :nc_test) == :replay
    assert NonceCache.check_nc("n1", 2, :nc_test) == :ok
    assert NonceCache.check_nc("n1", 2, :nc_test) == :replay
    # a lower nc than the max seen is a replay
    assert NonceCache.check_nc("n1", 1, :nc_test) == :replay
  end

  test "different nonces are independent" do
    assert NonceCache.check_nc("a", 5, :nc_test) == :ok
    assert NonceCache.check_nc("b", 1, :nc_test) == :ok
    assert NonceCache.check_nc("b", 6, :nc_test) == :ok
  end

  test "the sweep drops entries past the TTL" do
    start_supervised!({NonceCache, name: :nc_ttl_test, ttl_ms: 100})

    assert NonceCache.check_nc("x", 3, :nc_ttl_test) == :ok
    assert NonceCache.check_nc("x", 3, :nc_ttl_test) == :replay
    # after the TTL the nonce is forgotten, so the same nc is accepted again
    Process.sleep(260)
    assert NonceCache.check_nc("x", 3, :nc_ttl_test) == :ok
  end

  test "the application supervises the default cache" do
    assert is_pid(Process.whereis(NonceCache))
    assert NonceCache.check_nc("nc-default-instance", 1) == :ok
  end
end
