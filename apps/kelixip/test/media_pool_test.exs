defmodule Kelix.MediaPoolTest do
  # Kelix.MediaPool: round-robin selection, health/failover, runtime toggle,
  # entry validation (design §9). The :kelixip app already runs a Kelix.MediaPool
  # singleton (empty), so we start test-owned instances under distinct names.
  use ExUnit.Case, async: false
  import SIP.Test.Wait

  alias Kelix.MediaPool

  # Entries as Kelix.Config decodes them (see ConfigTest for the decoding itself):
  # the pool consumes them, it no longer parses TOML attributes.
  @pool [
    %{name: "mcu1", module: :mockup, url: "http://10.0.0.1:8080", enabled: true},
    %{name: "mcu2", module: :mendooze, url: "http://10.0.0.2:8080", enabled: true}
  ]

  # Adapters spying on how the *default* probe calls them (the tests below inject
  # their own probe instead, so these are the only two that exercise it).
  defmodule SpyAdapter do
    def connect(url, opts) do
      send(:media_pool_probe_spy, {:spy_connect, url, opts})
      {:ok, self()}
    end

    def disconnect(_pid, opts) do
      send(:media_pool_probe_spy, {:spy_disconnect, opts})
      :ok
    end
  end

  defmodule LegacyAdapter do
    def connect(url) do
      send(:media_pool_probe_spy, {:legacy_connect, url})
      {:ok, self()}
    end

    def disconnect(_pid, _opts), do: :ok
  end

  # start a test-owned pool with an injected probe; periodic check pushed far out
  defp start_pool(pool, probe \\ fn _ -> true end, opts \\ []) do
    name = :"mp_#{System.unique_integer([:positive])}"

    defaults = [name: name, pool: pool, probe: probe, first_check_ms: 60_000]
    start_supervised!({MediaPool, Keyword.merge(defaults, opts)})
    name
  end

  defp healthy?(mp, name),
    do: Enum.find(MediaPool.status(mp), &(&1.name == name)).healthy

  # A probe that reports itself to the test and waits for permission to answer, so the
  # window between "a holder said down" and "the probe came back" is testable.
  defp gated_probe(test) do
    fn e ->
      send(test, {:probing, e.name, self()})

      receive do
        {:answer, verdict} -> verdict
      after
        2_000 -> false
      end
    end
  end

  # same, but keeping the real probe: one entry on the given adapter module
  defp start_pool_with_default_probe(module, url) do
    name = :"mp_#{System.unique_integer([:positive])}"
    entry = %{name: "spy", module: module, url: url, enabled: true}
    start_supervised!({MediaPool, name: name, pool: [entry], first_check_ms: 60_000})
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
      mp = start_pool([])
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

    # The default probe opens a real connection every cycle. Adapters that accept
    # options are told it is only a keepalive, so they log that churn at :debug.
    test "the default probe announces itself as a keepalive to the adapter" do
      # the name goes away with the test process
      Process.register(self(), :media_pool_probe_spy)

      mp = start_pool_with_default_probe(SpyAdapter, "http://spy:8080")
      assert :ok = MediaPool.check_health(mp)

      assert_received {:spy_connect, "http://spy:8080", [purpose: :health_check]}
      assert_received {:spy_disconnect, [force: true]}
    end

    test "an adapter that only implements connect/1 is still probed" do
      # the name goes away with the test process
      Process.register(self(), :media_pool_probe_spy)

      mp = start_pool_with_default_probe(LegacyAdapter, "http://legacy:8080")
      assert :ok = MediaPool.check_health(mp)

      assert_received {:legacy_connect, "http://legacy:8080"}
      assert [%{healthy: true}] = MediaPool.status(mp)
    end
  end

  describe "recheck/3" do
    test "a :down hint marks the entry unhealthy before any probe answers" do
      mp = start_pool(@pool, gated_probe(self()))

      MediaPool.recheck("mcu1", :down, mp)

      assert_receive {:probing, "mcu1", task}
      # the probe has not answered yet, and the entry is already out of the rotation
      refute healthy?(mp, "mcu1")
      assert {:ok, %{name: "mcu2"}} = MediaPool.checkout(mp)

      send(task, {:answer, true})
      assert until(fn -> healthy?(mp, "mcu1") end)
    end

    test "an :up hint does not make an entry healthy — only the probe does" do
      mp = start_pool(@pool, fn _ -> false end)
      :ok = MediaPool.check_health(mp)
      refute healthy?(mp, "mcu1")

      MediaPool.recheck("mcu1", :up, mp)

      # the probe still says no, so the hint changed nothing
      refute until(fn -> healthy?(mp, "mcu1") end, 200)
    end

    test "a probe already in flight when the hint lands cannot resurrect the entry" do
      mp = start_pool(@pool, gated_probe(self()))

      # a probe starts while the server still answers…
      MediaPool.recheck("mcu1", :unknown, mp)
      assert_receive {:probing, "mcu1", task}

      # …the server dies and a holder says so before that probe returns
      MediaPool.recheck("mcu1", :down, mp)
      refute healthy?(mp, "mcu1")

      # the in-flight probe now answers "up" — a stale reading, and it is dropped
      send(task, {:answer, true})
      refute until(fn -> healthy?(mp, "mcu1") end, 200)
    end

    test "a second hint inside the debounce window does not re-probe" do
      test = self()
      mp = start_pool(@pool, fn e -> send(test, {:probed, e.name}) && true end)

      MediaPool.recheck("mcu1", :down, mp)
      assert_receive {:probed, "mcu1"}

      MediaPool.recheck("mcu1", :down, mp)
      refute_receive {:probed, "mcu1"}, 200
    end

    test "a hint for an entry the pool does not know is ignored" do
      mp = start_pool(@pool, fn _ -> raise "must not probe" end)

      assert :ok = MediaPool.recheck("ghost", :down, mp)
      assert [%{healthy: true}, %{healthy: true}] = MediaPool.status(mp)
    end

    test "recheck on a pool that is not running does not raise" do
      assert :ok = MediaPool.recheck("mcu1", :down, :mp_nobody_home)
    end
  end

  describe "periodic probing" do
    test "an entry believed down is re-probed at the short interval, an up one is not" do
      test = self()
      probe = fn e -> send(test, {:probed, e.name}) && e.name == "mcu2" end

      # mcu1 fails its probe, mcu2 passes; the tick is the down interval
      start_pool(@pool, probe,
        first_check_ms: 10,
        down_interval_ms: 50,
        health_interval_ms: 10_000
      )

      # first cycle probes both — nothing has been measured yet
      assert_receive {:probed, "mcu1"}
      assert_receive {:probed, "mcu2"}

      # mcu1 is down: it comes back every 50 ms. mcu2 is up: not for another 10 s.
      assert_receive {:probed, "mcu1"}, 500
      refute_receive {:probed, "mcu2"}, 300
    end
  end

  describe "entries" do
    test "are taken in the order given, with health optimistic until the first probe" do
      mp = start_pool(@pool)

      assert [
               %{name: "mcu1", module: :mockup, enabled: true, healthy: true},
               %{name: "mcu2", module: :mendooze, enabled: true, healthy: true}
             ] = MediaPool.status(mp)
    end

    # Validation moved to Kelix.Config: a malformed entry aborts the boot instead of
    # being skipped here, so there is nothing for the pool to reject any more.
    test "status/1 exposes what a caller needs to reach the server" do
      mp = start_pool(@pool)
      assert Enum.all?(MediaPool.status(mp), &match?(%{url: "http://10.0.0." <> _}, &1))
    end
  end
  describe "what each media server carries, asked rather than configured" do
    test "the probe brings the profiles back, and status/0 shows them" do
      profiles = %{
        "publicv4" => %{available: true, announced: "203.0.113.9", bind: "", default: true},
        "publicv6" => %{available: true, announced: "2001:db8::12", bind: "", default: false}
      }

      {:ok, mp} =
        MediaPool.start_link(
          name: :mp_profiles,
          pool: [%{name: "mcu1", module: :mockup, url: "u", enabled: true}],
          probe: fn _e -> {true, profiles} end,
          first_check_ms: 10_000
        )

      # Nothing has asked yet.
      assert [%{profiles: :unknown}] = MediaPool.status(mp)

      :ok = MediaPool.check_health(mp)
      assert [%{name: "mcu1", healthy: true, profiles: ^profiles}] = MediaPool.status(mp)
    end

    test "a probe that could not ask does not erase what the last one learnt" do
      profiles = %{"publicv6" => %{available: true, announced: "2001:db8::12"}}
      answer = :counters.new(1, [])

      probe = fn _e ->
        if :counters.get(answer, 1) == 0, do: {true, profiles}, else: false
      end

      {:ok, mp} =
        MediaPool.start_link(
          name: :mp_profiles_keep,
          pool: [%{name: "mcu1", module: :mockup, url: "u", enabled: true}],
          probe: probe,
          first_check_ms: 10_000
        )

      :ok = MediaPool.check_health(mp)
      assert [%{healthy: true, profiles: ^profiles}] = MediaPool.status(mp)

      # The server goes away: unhealthy, but not suddenly address-less.
      :counters.add(answer, 1, 1)
      :ok = MediaPool.check_health(mp)
      assert [%{healthy: false, profiles: ^profiles}] = MediaPool.status(mp)
    end

    test "a probe that only says up/down keeps working" do
      {:ok, mp} =
        MediaPool.start_link(
          name: :mp_profiles_bool,
          pool: [%{name: "mcu1", module: :mockup, url: "u", enabled: true}],
          probe: fn _e -> true end,
          first_check_ms: 10_000
        )

      :ok = MediaPool.check_health(mp)
      assert [%{healthy: true, profiles: :unknown}] = MediaPool.status(mp)
    end
  end
end
