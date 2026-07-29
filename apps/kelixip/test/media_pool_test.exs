defmodule Kelix.MediaPoolTest do
  # Kelix.MediaPool: round-robin selection, health/failover, runtime toggle,
  # entry validation (design §9). The :kelixip app already runs a Kelix.MediaPool
  # singleton (empty), so we start test-owned instances under distinct names.
  use ExUnit.Case, async: false

  alias Kelix.MediaPool

  @pool %{
    "mcu1" => %{"module" => "mockup", "url" => "http://10.0.0.1:8080", "enabled" => true},
    "mcu2" => %{"module" => "mendooze", "url" => "http://10.0.0.2:8080", "enabled" => true}
  }

  # start a test-owned pool with an injected probe; periodic check pushed far out
  defp start_pool(pool, probe \\ fn _ -> true end) do
    name = :"mp_#{System.unique_integer([:positive])}"
    start_supervised!({MediaPool, name: name, pool: pool, probe: probe, first_check_ms: 60_000})
    name
  end

  describe "checkout/1 round-robin" do
    test "cycles through enabled + healthy MCUs in name order" do
      mp = start_pool(@pool)
      assert {:ok, %{name: "mcu1", module: :mockup}} = MediaPool.checkout(mp)
      assert {:ok, %{name: "mcu2", module: :mendooze}} = MediaPool.checkout(mp)
      assert {:ok, %{name: "mcu1"}} = MediaPool.checkout(mp)
    end

    test "an empty pool has nothing to hand out" do
      mp = start_pool(%{})
      assert MediaPool.checkout(mp) == {:error, :no_mcu}
    end
  end

  describe "toggle/3" do
    test "a disabled MCU is skipped; re-enabling brings it back" do
      mp = start_pool(@pool)
      assert :ok = MediaPool.toggle("mcu1", false, mp)
      assert {:ok, %{name: "mcu2"}} = MediaPool.checkout(mp)
      assert {:ok, %{name: "mcu2"}} = MediaPool.checkout(mp)

      assert :ok = MediaPool.toggle("mcu1", true, mp)
      assert Enum.any?(1..3, fn _ -> match?({:ok, %{name: "mcu1"}}, MediaPool.checkout(mp)) end)
    end

    test "all disabled → no MCU" do
      mp = start_pool(@pool)
      MediaPool.toggle("mcu1", false, mp)
      MediaPool.toggle("mcu2", false, mp)
      assert MediaPool.checkout(mp) == {:error, :no_mcu}
    end

    test "toggling an unknown entry is an error" do
      mp = start_pool(@pool)
      assert MediaPool.toggle("ghost", false, mp) == {:error, :unknown}
    end
  end

  describe "health-check + failover" do
    test "an unhealthy MCU is skipped after a probe" do
      # mcu1 fails its probe, mcu2 passes
      mp = start_pool(@pool, fn e -> e.name == "mcu2" end)
      assert :ok = MediaPool.check_health(mp)

      assert {:ok, %{name: "mcu2"}} = MediaPool.checkout(mp)
      assert {:ok, %{name: "mcu2"}} = MediaPool.checkout(mp)
    end

    test "all unhealthy → no MCU" do
      mp = start_pool(@pool, fn _ -> false end)
      assert :ok = MediaPool.check_health(mp)
      assert MediaPool.checkout(mp) == {:error, :no_mcu}
    end
  end

  describe "entry validation" do
    test "a malformed entry (no url) is skipped, the rest load" do
      pool = Map.put(@pool, "bad", %{"module" => "mockup"})
      mp = start_pool(pool)
      names = mp |> MediaPool.status() |> Enum.map(& &1.name)
      assert "bad" not in names
      assert "mcu1" in names and "mcu2" in names
    end
  end
end
