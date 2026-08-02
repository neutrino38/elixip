defmodule Kelix.MediaPool do
  @moduledoc """
  Round-robin pool of media servers (MCUs) over the `[mediaserver.pool.*]` entries
  (design §9). A supervised GenServer that, for each new call, hands out an
  `enabled` **and** healthy MCU; a periodic health-check marks each MCU up/down so
  failover skips the ones that are down; entries can be enabled/disabled at runtime.

  Each entry wraps a `MediaServer.Behaviour` adapter (`:mockup` / `:mendooze` /
  a module) by its config URL — the pool itself holds no connection, it only
  **selects**. `Kelix.Router` injects the selected `%{module, url}` into the spawned
  instance as a per-instance `:mediaserver_instance` override, so the DSL
  `media_connect/0` connects to a pool-chosen server transparently.

  Entries come from `Kelix.Config.current().mediaserver_pool`, already **decoded and
  validated** there (`Kelix.Config.pool_entry`): a malformed entry aborts the boot
  rather than being skipped here, and the mcu module reads that same list to open its
  control channels — one declaration of a media server, one reading of it. Tests
  bypass the config with `start_link(pool: [entry…], probe: fn entry -> bool end)`.
  """
  use GenServer

  # The probe is a real connection (event queue + event poller) opened and closed
  # again on every cycle, so keep it rare: 30 s still fails a dead MCU out of the
  # rotation well before an operator notices, at a third of the server-side churn.
  @health_interval_ms 30_000

  @type entry :: %{
          name: String.t(),
          module: atom,
          url: String.t(),
          enabled: boolean,
          healthy: boolean
        }
  @type choice :: %{name: String.t(), module: atom, url: String.t()}

  # ── API ──────────────────────────────────────────────────────────────────────

  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts \\ []),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  @doc "Pick the next enabled + healthy MCU (round-robin). `{:ok, choice}` / `{:error, :no_mcu}`."
  @spec checkout(GenServer.server()) :: {:ok, choice} | {:error, :no_mcu}
  def checkout(server \\ __MODULE__), do: GenServer.call(server, :checkout)

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

  # ── GenServer ────────────────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    entries = health_fields(Keyword.get(opts, :pool) || pool_from_config())
    interval = Keyword.get(opts, :health_interval_ms, @health_interval_ms)

    # optimistic (healthy: true) until the first probe lands; schedule that probe
    if entries != [],
      do: Process.send_after(self(), :health_check, Keyword.get(opts, :first_check_ms, interval))

    {:ok,
     %{
       entries: entries,
       cursor: 0,
       probe: Keyword.get(opts, :probe, &default_probe/1),
       interval: interval
     }}
  end

  @impl true
  def handle_call(:checkout, _from, %{entries: entries} = state) do
    n = length(entries)

    with true <- n > 0,
         idx when is_integer(idx) <- next_index(entries, state.cursor, n) do
      e = Enum.at(entries, idx)

      {:reply, {:ok, %{name: e.name, module: e.module, url: e.url}},
       %{state | cursor: rem(idx + 1, n)}}
    else
      _ -> {:reply, {:error, :no_mcu}, state}
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
    {:reply, :ok, %{state | entries: probe_all(state.entries, state.probe)}}
  end

  @impl true
  # periodic health-check: probe OFF the GenServer (a slow MCU must not stall
  # checkouts), then fold the results back in via a cast.
  def handle_info(:health_check, state) do
    parent = self()
    entries = state.entries
    probe = state.probe

    Task.start(fn -> GenServer.cast(parent, {:health_results, health_map(entries, probe)}) end)

    Process.send_after(self(), :health_check, state.interval)
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def handle_cast({:health_results, results}, state) do
    entries =
      Enum.map(state.entries, fn e -> %{e | healthy: Map.get(results, e.name, e.healthy)} end)

    {:noreply, %{state | entries: entries}}
  end

  # ── selection ────────────────────────────────────────────────────────────────

  # first serviceable (enabled + healthy) index scanning from the cursor, or nil
  defp next_index(entries, cursor, n) do
    Enum.find(for(i <- 0..(n - 1), do: rem(cursor + i, n)), fn i ->
      e = Enum.at(entries, i)
      e.enabled and e.healthy
    end)
  end

  defp set_enabled(entries, name, on?),
    do: Enum.map(entries, fn e -> if e.name == name, do: %{e | enabled: on?}, else: e end)

  # ── health probing ───────────────────────────────────────────────────────────

  defp probe_all(entries, probe),
    do: Enum.map(entries, fn e -> %{e | healthy: probe.(e)} end)

  defp health_map(entries, probe),
    do: Map.new(entries, fn e -> {e.name, probe.(e)} end)

  # default probe: connect then immediately disconnect (design §9 — reuse connect/1).
  defp default_probe(%{module: module, url: url}) do
    mod = resolve_module_atom(module)

    case probe_connect(mod, url) do
      {:ok, pid} ->
        try_disconnect(mod, pid)
        true

      _ ->
        false
    end
  rescue
    _ -> false
  catch
    _, _ -> false
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
  # probe lands, so a boot cannot start by refusing every call.
  defp health_fields(entries) when is_list(entries),
    do: Enum.map(entries, &Map.put(&1, :healthy, true))

  defp health_fields(_), do: []

  defp resolve_module_atom(:mockup), do: MediaServer.Mockup
  defp resolve_module_atom(:mendooze), do: MediaServer.Mendooze
  defp resolve_module_atom(module) when is_atom(module), do: module
end
