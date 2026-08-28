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
      assert [%{healthy: true, profiles: :unknown, server_status: :unknown}] = MediaPool.status(mp)
    end

    test "the probe brings the server's self-description back too" do
      status = %{
        "server" => %{"version" => "1.14.0", "uptimeSecs" => 42},
        "capabilities" => %{"video" => %{"decode" => ["H264", "VP6"], "encode" => ["H264"]}}
      }

      {:ok, mp} =
        MediaPool.start_link(
          name: :mp_status,
          pool: [%{name: "mcu1", module: :mockup, url: "u", enabled: true}],
          probe: fn _e -> {true, :unknown, status} end,
          first_check_ms: 10_000
        )

      # Nothing has asked yet — and the pool must not pretend it knows a version.
      assert [%{server_status: :unknown}] = MediaPool.status(mp)

      :ok = MediaPool.check_health(mp)
      assert [%{name: "mcu1", healthy: true, server_status: ^status}] = MediaPool.status(mp)
    end

    test "an unreachable server keeps its last self-description, like its profiles" do
      status = %{"server" => %{"version" => "1.14.0"}}
      answer = :counters.new(1, [])

      probe = fn _e ->
        if :counters.get(answer, 1) == 0, do: {true, :unknown, status}, else: false
      end

      {:ok, mp} =
        MediaPool.start_link(
          name: :mp_status_keep,
          pool: [%{name: "mcu1", module: :mockup, url: "u", enabled: true}],
          probe: probe,
          first_check_ms: 10_000
        )

      :ok = MediaPool.check_health(mp)
      assert [%{healthy: true, server_status: ^status}] = MediaPool.status(mp)

      :counters.add(answer, 1, 1)
      :ok = MediaPool.check_health(mp)
      assert [%{healthy: false, server_status: ^status}] = MediaPool.status(mp)
    end
  end

  # Regression guard. The periodic path used to store the probe's RAW return
  # straight into `healthy`, while only the synchronous refresh normalized it. With
  # the default probe — which answers a tuple — a DEAD media server was recorded as
  # `{false, :unknown}`, which is truthy: it stayed in the rotation and `list`
  # showed it up. `interval_for/2`, which matches on `healthy: true` / `false`, had
  # no clause for a tuple at all.
  describe "the periodic probe records the same facts as the synchronous one" do
    defp tuple_probe_pool(name, verdict) do
      {:ok, mp} =
        MediaPool.start_link(
          name: name,
          pool: [%{name: "mcu1", module: :mockup, url: "u", enabled: true}],
          # The shape the DEFAULT probe answers.
          probe: fn _e -> verdict end,
          first_check_ms: 20,
          health_interval_ms: 20,
          down_interval_ms: 20
        )

      mp
    end

    test "a tuple-answering probe on the periodic path yields a boolean health" do
      mp = tuple_probe_pool(:mp_periodic_down, {false, :unknown, :unknown})

      assert until(fn -> match?([%{healthy: false}], MediaPool.status(mp)) end)

      assert [%{healthy: false}] = MediaPool.status(mp)
      # And the entry really is out of the rotation, which is the whole point.
      assert MediaPool.checkout(mp) == {:error, :no_mcu}
    end

    test "the periodic path also refreshes profiles and the self-description" do
      profiles = %{"publicv4" => %{available: true, announced: "203.0.113.9"}}
      status = %{"server" => %{"version" => "1.14.0"}}

      mp = tuple_probe_pool(:mp_periodic_facts, {true, profiles, status})

      assert until(fn -> match?([%{profiles: ^profiles}], MediaPool.status(mp)) end)

      assert [%{healthy: true, profiles: ^profiles, server_status: ^status}] =
               MediaPool.status(mp)
    end

    test "the pool survives the tick that follows a tuple-answering probe" do
      # interval_for/2 reads `healthy` on the NEXT tick to pick its interval: a
      # tuple there crashed the GenServer, taking every media server with it.
      mp = tuple_probe_pool(:mp_periodic_survives, {true, :unknown, :unknown})

      assert until(fn -> match?([%{healthy: true}], MediaPool.status(mp)) end)
      Process.sleep(120)

      assert Process.alive?(Process.whereis(:mp_periodic_survives))
      assert [%{healthy: true}] = MediaPool.status(mp)
    end
  end
  describe "checkout with a profile constraint" do
    defp pool_with(profiles_by_name) do
      entries =
        for {name, _} <- profiles_by_name,
            do: %{name: name, module: :mockup, url: "u-#{name}", enabled: true}

      {:ok, mp} =
        MediaPool.start_link(
          name: :"mp_constraint_#{:erlang.unique_integer([:positive])}",
          pool: entries,
          probe: fn e -> {true, Map.fetch!(Map.new(profiles_by_name), e.name)} end,
          first_check_ms: 10_000
        )

      :ok = MediaPool.check_health(mp)
      mp
    end

    defp carries(names) do
      Map.new(names, fn n -> {n, %{available: true, announced: "x", bind: "", default: false}} end)
    end

    test "no constraint keeps the round-robin it always had" do
      mp = pool_with([{"a", carries(["publicv4"])}, {"b", carries(["publicv6"])}])

      assert {:ok, %{name: "a"}} = MediaPool.checkout(mp)
      assert {:ok, %{name: "b"}} = MediaPool.checkout(mp)
    end

    test "only a server carrying the profile is returned" do
      mp = pool_with([{"a", carries(["publicv4"])}, {"b", carries(["publicv6"])}])

      assert {:ok, %{name: "b"}} = MediaPool.checkout(mp, [{:ipv6, :public}])
      assert {:ok, %{name: "b"}} = MediaPool.checkout(mp, [{:ipv6, :public}])
      assert {:ok, %{name: "a"}} = MediaPool.checkout(mp, [{:ipv4, :public}])
    end

    test "two profiles need ONE server carrying both" do
      # A media session lives on one server, so an IPv4↔IPv6 call needs a server
      # that announces both — not one of each.
      mp =
        pool_with([
          {"v4only", carries(["publicv4"])},
          {"both", carries(["publicv4", "publicv6"])}
        ])

      assert {:ok, %{name: "both"}} =
               MediaPool.checkout(mp, [{:ipv4, :public}, {:ipv6, :public}])
    end

    test "no server carrying it fails the call rather than picking another" do
      # A fallback would put the media on the wrong interface with nothing to say
      # so, and the caller could not retry elsewhere.
      mp = pool_with([{"a", carries(["publicv4"])}])

      assert MediaPool.checkout(mp, [{:ipv6, :public}]) == {:error, :no_mcu}
      assert MediaPool.checkout(mp, [{:ipv4, :internal}]) == {:error, :no_mcu}
    end

    test "an entry whose profiles are unknown satisfies no constraint" do
      {:ok, mp} =
        MediaPool.start_link(
          name: :mp_constraint_unknown,
          pool: [%{name: "old", module: :mockup, url: "u", enabled: true}],
          probe: fn _e -> true end,
          first_check_ms: 10_000
        )

      :ok = MediaPool.check_health(mp)

      # Still serves the calls that ask for nothing — every call on a node never
      # told it has two sides.
      assert {:ok, %{name: "old"}} = MediaPool.checkout(mp)
      assert MediaPool.checkout(mp, [{:ipv4, :public}]) == {:error, :no_mcu}
    end

    test "an unhealthy server carrying the profile is still out" do
      mp = pool_with([{"a", carries(["publicv4"])}])
      :ok = MediaPool.toggle("a", false, mp)

      assert MediaPool.checkout(mp, [{:ipv4, :public}]) == {:error, :no_mcu}
    end
  end
end
