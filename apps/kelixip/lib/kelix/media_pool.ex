defmodule Kelix.MediaPool do
  @moduledoc """
  Round-robin pool of media servers (MCUs) over the `[mediaserver.pool.*]` entries
  (design §9). A supervised GenServer that, for each new call, hands out an
  `enabled` **and** healthy MCU; a periodic health-check marks each MCU up/down so
  failover skips the ones that are down; entries can be enabled/disabled at runtime.

  Each entry wraps a `MediaServer.Behaviour` adapter (`:mockup` / `:mendooze` /
  a module) by its config URL — the pool itself holds no connection, it only
  **selects**. `Kelix.Router` injects the selected `%{module, url}` into the spawned
  instance as a per-instance `:mediaserver_instance` override, so FSL
  `media_connect/0` connects to a pool-chosen server transparently.

  Entries come from `Kelix.Config.current().mediaserver_pool`, already **decoded and
  validated** there (`Kelix.Config.pool_entry`): a malformed entry aborts the boot
  rather than being skipped here, and the mcu module reads that same list to open its
  control channels — one declaration of a media server, one reading of it. Tests
  bypass the config with `start_link(pool: [entry…], probe: fn entry -> bool end)`.

  ## How an entry's health is decided

  The periodic probe alone is too slow to be the only detector: whoever holds a live
  channel to a media server (the mcu module's control channel, an adapter's event
  stream) sees it die in the second, while the next cycle may be 30 s away. Those
  holders call `recheck/3` to say "measure this one now", and the pool re-probes out
  of cycle.

  What they do **not** do is push a verdict. `healthy` stays what this pool measured
  on its own channel — a module's channel is a different one to the same server and
  can disagree (see `Kelix.Control.mediaserver/1`). One asymmetry makes that safe:

  > only the pool's own probe may declare an entry **up**; any holder may declare it
  > **suspect**.

  So a `:down` hint marks the entry unhealthy at once — the cost of a wrong "down" is
  one skipped MCU, the cost of a wrong "up" is a call routed into a hole — while an
  `:up` hint only earns a probe.
  """
  use GenServer
  require Logger

  # The probe is a real connection (event queue + event poller) opened and closed
  # again on every cycle, so keep it rare on a server that answers: 30 s.
  @health_interval_ms 30_000

  # An entry believed down is re-probed far more often. Nothing pushes an "up" for an
  # adapter no module drives, so for those this interval *is* the return-to-service
  # latency — and probing a server that is already down costs a refused connection.
  @down_interval_ms 5_000

  # A recheck/3 landing less than this after that entry's last probe *started* skips
  # the probe: a flapping server must not become a queue-create storm on the MCU. The
  # hint itself still applies — only the measurement is dropped, and the next tick
  # picks it up.
  @recheck_min_interval_ms 2_000

  @type entry :: %{
          name: String.t(),
          module: atom,
          url: String.t(),
          enabled: boolean,
          healthy: boolean,
          profiles: %{String.t() => map} | :unknown
        }
  @type choice :: %{name: String.t(), module: atom, url: String.t()}

  # ── API ──────────────────────────────────────────────────────────────────────

  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts \\ []),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  @doc """
  Pick the next enabled + healthy MCU (round-robin).
  `{:ok, choice}` / `{:error, :no_mcu}`.

  `profiles` narrows it to servers carrying **every** addressing profile the call
  needs, as `{family, side}` pairs — one per leg, so often two, and a media
  session lives on one server. No eligible entry fails the call rather than
  falling back on another profile: a fallback would put the media on the wrong
  interface with nothing to say so.

  An entry whose profiles are unknown satisfies no constraint. It stays eligible
  to the calls that ask for none, which is every call on a node that was never
  told it has two sides.
  """
  @spec checkout(GenServer.server(), [{:ipv4 | :ipv6, :internal | :public}]) ::
          {:ok, choice} | {:error, :no_mcu}
  def checkout(server \\ __MODULE__, profiles \\ []),
    do: GenServer.call(server, {:checkout, profiles})

  @doc "Enable/disable a pool entry at runtime (no restart). `:ok` / `{:error, :unknown}`."
  @spec toggle(String.t(), boolean, GenServer.server()) :: :ok | {:error, :unknown}
  def toggle(name, on?, server \\ __MODULE__) when is_boolean(on?),
    do: GenServer.call(server, {:toggle, name, on?})

  @doc "Pool state for status/CLI: one map per entry (name/module/url/enabled/healthy)."
  @spec status(GenServer.server()) :: [entry]
  def status(server \\ __MODULE__), do: GenServer.call(server, :status)

  @doc "Probe every entry now, synchronously, and update health. Returns `:ok`."
  @spec check_health(GenServer.server()) :: :ok
  def check_health(server \\ __MODULE__), do: GenServer.call(server, :check_health)

  @doc """
  Tell the pool that a holder of a channel to `name` observed something — re-probe
  that entry now, out of cycle (see the module doc).

  `hint` is what the caller saw on **its own** channel:

  - `:down` — marks the entry unhealthy immediately, then probes
  - `:up` — probes; the entry only becomes healthy if that probe says so
  - `:unknown` — probes, no opinion

  Asynchronous and never raises: a caller reporting a media server it cannot reach
  must not block, nor care whether the pool is running (an unknown `name` is
  ignored — the pool is the node's only declaration of a media server, §9).
  """
  @spec recheck(String.t(), :up | :down | :unknown, GenServer.server()) :: :ok
  def recheck(name, hint, server \\ __MODULE__) when hint in [:up, :down, :unknown],
    do: GenServer.cast(server, {:recheck, name, hint})

  # ── GenServer ────────────────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    entries = health_fields(Keyword.get(opts, :pool) || pool_from_config())
    interval = Keyword.get(opts, :health_interval_ms, @health_interval_ms)
    down_interval = Keyword.get(opts, :down_interval_ms, @down_interval_ms)
    tick = min(interval, down_interval)

    # Optimistic (healthy: true) until the first probe lands, so a boot cannot start
    # by refusing every call — but that window is one tick, not one full cycle: an
    # MCU already dead when kelixip starts must not collect calls for 30 s.
    if entries != [],
      do: Process.send_after(self(), :health_check, Keyword.get(opts, :first_check_ms, tick))

    {:ok,
     %{
       entries: entries,
       cursor: 0,
       probe: Keyword.get(opts, :probe, &default_probe/1),
       interval: interval,
       down_interval: down_interval,
       tick: tick,
       # name => monotonic ms at which that entry's last probe *started*. Stamping
       # the start (not the end) is what keeps a probe that hangs from wedging the
       # entry: the stamp ages either way, so the next cycle probes again.
       probed_at: %{},
       # Ordering of hints against in-flight probes (see the health_results cast).
       # A counter, not a timestamp: a hint and the probe it triggers land in the
       # same millisecond, and "same millisecond" must not read as "after".
       seq: 0,
       hinted_seq: %{}
     }}
  end

  @impl true
  def handle_call({:checkout, profiles}, _from, %{entries: entries} = state) do
    n = length(entries)
    required = Enum.map(profiles, fn {family, side} -> MediaServer.profile_name(family, side) end)

    with true <- n > 0,
         idx when is_integer(idx) <- next_index(entries, state.cursor, n, required) do
      e = Enum.at(entries, idx)

      {:reply, {:ok, %{name: e.name, module: e.module, url: e.url}},
       %{state | cursor: rem(idx + 1, n)}}
    else
      _ ->
        if required != [] do
          Logger.warning(
            module: __MODULE__,
            message:
              "no media server carries #{Enum.join(required, " + ")}: this call needs " <>
                "an interface none of them announces"
          )
        end

        {:reply, {:error, :no_mcu}, state}
    end
  end

  def handle_call({:toggle, name, on?}, _from, state) do
    case Enum.any?(state.entries, &(&1.name == name)) do
      false -> {:reply, {:error, :unknown}, state}
      true -> {:reply, :ok, %{state | entries: set_enabled(state.entries, name, on?)}}
    end
  end

  def handle_call(:status, _from, state), do: {:reply, state.entries, state}

  def handle_call(:check_health, _from, state) do
    state = stamp(state, state.entries)
    {:reply, :ok, %{state | entries: probe_all(state.entries, state.probe)}}
  end

  @impl true
  # Periodic health-check. The tick is the *shortest* of the two intervals; which
  # entries it actually probes depends on what the pool currently believes of each
  # (`due?/3`), so a down entry comes back into service quickly without making an up
  # one churn. Probing runs OFF the GenServer — a slow MCU must not stall checkouts.
  def handle_info(:health_check, state) do
    now = now_ms()
    state = start_probe(state, Enum.filter(state.entries, &due?(&1, state, now)))

    Process.send_after(self(), :health_check, state.tick)
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def handle_cast({:recheck, name, hint}, state) do
    case Enum.find(state.entries, &(&1.name == name)) do
      nil -> {:noreply, state}
      entry -> {:noreply, state |> apply_hint(entry, hint) |> maybe_probe(name)}
    end
  end

  # `seq` is the hint counter as it stood when this batch's probes began. A result is
  # dropped when a hint for that entry landed after that: without this, a full-cycle
  # probe that read the server as up a second before it died lands *after* the "down"
  # notification and puts the entry back in the rotation — the exact stale "up" this
  # whole path exists to prevent.
  def handle_cast({:health_results, seq, results}, state) do
    entries =
      Enum.map(state.entries, fn e ->
        if Map.get(state.hinted_seq, e.name, 0) <= seq,
          do: %{e | healthy: Map.get(results, e.name, e.healthy)},
          else: e
      end)

    {:noreply, %{state | entries: entries}}
  end

  # ── selection ────────────────────────────────────────────────────────────────

  # first serviceable (enabled + healthy) index scanning from the cursor, or nil
  defp next_index(entries, cursor, n, required) do
    Enum.find(for(i <- 0..(n - 1), do: rem(cursor + i, n)), fn i ->
      e = Enum.at(entries, i)
      e.enabled and e.healthy and carries?(e, required)
    end)
  end

  # Every required profile, available on that server. An entry whose profiles are
  # unknown carries nothing as far as anyone can tell — so it satisfies no
  # constraint, and asking it for one would fail at the leg's first
  # StartReceiving instead of here.
  defp carries?(_entry, []), do: true

  defp carries?(%{profiles: profiles}, required) when is_map(profiles),
    do: Enum.all?(required, &(get_in(profiles, [&1, :available]) == true))

  defp carries?(_entry, _required), do: false

  defp set_enabled(entries, name, on?),
    do: Enum.map(entries, fn e -> if e.name == name, do: %{e | enabled: on?}, else: e end)

  defp set_healthy(entries, name, ok?),
    do: Enum.map(entries, fn e -> if e.name == name, do: %{e | healthy: ok?}, else: e end)

  # ── out-of-cycle recheck ─────────────────────────────────────────────────────

  # Only the pool's own probe may declare an entry up (see the module doc), so an
  # `:up` hint changes nothing by itself — it is the probe below that decides. Every
  # hint bumps the counter, whatever its verdict: what it orders is "this entry was
  # spoken about", which is what invalidates a reading taken before.
  defp apply_hint(state, entry, hint) do
    seq = state.seq + 1
    state = %{state | seq: seq, hinted_seq: Map.put(state.hinted_seq, entry.name, seq)}

    if hint == :down,
      do: %{state | entries: set_healthy(state.entries, entry.name, false)},
      else: state
  end

  defp maybe_probe(state, name) do
    entry = Enum.find(state.entries, &(&1.name == name))

    if elapsed_since_probe(state, name) >= @recheck_min_interval_ms,
      do: start_probe(state, [entry]),
      else: state
  end

  # ── health probing ───────────────────────────────────────────────────────────

  # An entry is due when its own interval has elapsed since its last probe started:
  # `down_interval` for one the pool believes down, `interval` for one it believes up.
  defp due?(entry, state, now) do
    case Map.fetch(state.probed_at, entry.name) do
      :error -> true
      {:ok, at} -> now - at >= interval_for(entry, state)
    end
  end

  defp interval_for(%{healthy: true}, state), do: state.interval
  defp interval_for(%{healthy: false}, state), do: state.down_interval

  defp start_probe(state, []), do: state

  defp start_probe(state, entries) do
    parent = self()
    probe = state.probe
    seq = state.seq

    Task.start(fn ->
      GenServer.cast(parent, {:health_results, seq, health_map(entries, probe)})
    end)

    stamp(state, entries)
  end

  defp stamp(state, entries) do
    now = now_ms()
    %{state | probed_at: Enum.reduce(entries, state.probed_at, &Map.put(&2, &1.name, now))}
  end

  defp elapsed_since_probe(state, name) do
    case Map.fetch(state.probed_at, name) do
      :error -> @recheck_min_interval_ms
      {:ok, at} -> now_ms() - at
    end
  end

  defp now_ms(), do: System.monotonic_time(:millisecond)

  defp probe_all(entries, probe) do
    Enum.map(entries, fn e ->
      {healthy, profiles} = probe_result(probe.(e))
      %{e | healthy: healthy, profiles: keep_known(profiles, e.profiles)}
    end)
  end

  defp health_map(entries, probe),
    do: Map.new(entries, fn e -> {e.name, probe.(e)} end)

  # A probe answers health. The default one also brings back what the server said
  # about ITSELF while it had the connection open, since it opens one anyway; an
  # injected probe (the tests, and anything that only means up/down) keeps
  # answering a plain boolean.
  defp probe_result(healthy) when is_boolean(healthy), do: {healthy, :unknown}
  defp probe_result({healthy, profiles}) when is_boolean(healthy), do: {healthy, profiles}

  # A probe that could not ask does not erase what the last one learnt: an
  # unreachable media server is unhealthy, not suddenly address-less.
  defp keep_known(:unknown, previous), do: previous
  defp keep_known(profiles, _previous), do: profiles

  # default probe: connect then immediately disconnect (design §9 — reuse connect/1).
  #
  # The addressing profiles come back with it, so the pool re-reads them every
  # cycle: a media server restarted with other addresses (a new `--internal-ip`, an
  # added v6) describes itself, and nothing on this side has to be told
  # (docs/design/multi-interface.md, step 5).
  defp default_probe(%{module: module, url: url}) do
    mod = resolve_module_atom(module)

    case probe_connect(mod, url) do
      {:ok, pid} ->
        profiles = read_profiles(mod, pid)
        try_disconnect(mod, pid)
        {true, profiles}

      _ ->
        {false, :unknown}
    end
  rescue
    _ -> {false, :unknown}
  catch
    _, _ -> {false, :unknown}
  end

  # Only an adapter that knows the call answers it; the mockup and any older one
  # simply have nothing to say.
  defp read_profiles(mod, pid) do
    if Code.ensure_loaded?(mod) and function_exported?(mod, :network_profiles, 1),
      do: apply(mod, :network_profiles, [pid]),
      else: :unknown
  rescue
    _ -> :unknown
  catch
    _, _ -> :unknown
  end

  # Tell the adapter this connection is only a keepalive probe, so it can log its
  # connection churn at :debug instead of drowning the log every cycle. The
  # behaviour only requires `connect/1`: adapters that don't take options keep it.
  defp probe_connect(mod, url) do
    if Code.ensure_loaded?(mod) and function_exported?(mod, :connect, 2),
      do: apply(mod, :connect, [url, [purpose: :health_check]]),
      else: apply(mod, :connect, [url])
  end

  defp try_disconnect(mod, pid) do
    apply(mod, :disconnect, [pid, [force: true]])
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  # ── config → entries ─────────────────────────────────────────────────────────

  defp pool_from_config() do
    if Process.whereis(Kelix.Config), do: Kelix.Config.current().mediaserver_pool, else: []
  end

  # The decoded entries carry no health: add it here, optimistic until the first
  # probe lands, so a boot cannot start by refusing every call. Profiles start
  # `:unknown` for the same reason — nothing has asked yet.
  defp health_fields(entries) when is_list(entries),
    do: Enum.map(entries, &(&1 |> Map.put(:healthy, true) |> Map.put(:profiles, :unknown)))

  defp health_fields(_), do: []

  defp resolve_module_atom(:mockup), do: MediaServer.Mockup
  defp resolve_module_atom(:mendooze), do: MediaServer.Mendooze
  defp resolve_module_atom(module) when is_atom(module), do: module
end
