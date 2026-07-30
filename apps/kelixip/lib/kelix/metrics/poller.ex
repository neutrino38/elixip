defmodule Kelix.Metrics.Poller do
  @moduledoc """
  Periodically samples the runtime and emits the **gauge** telemetry events the
  Prometheus `last_value` metrics consume (design §11): active instances per
  domain (and total), active AOR registrations per domain, and each media
  server's serviceable state.

  Counters/distributions are emitted at their seams (`Kelix.Metrics.Emit`); only
  the point-in-time gauges need this poll. Every read is guarded so a surface
  being down never crashes the poller — it just skips that sample this tick.
  """
  use GenServer
  require Logger

  @default_interval_ms 15_000

  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(opts) do
    interval = Keyword.get(opts, :interval_ms, @default_interval_ms)
    # emit an initial sample immediately, then on every tick
    send(self(), :sample)
    schedule(interval)
    {:ok, %{interval: interval}}
  end

  @impl true
  def handle_info(:sample, state) do
    sample()
    {:noreply, state}
  end

  def handle_info(:tick, state) do
    sample()
    schedule(state.interval)
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @doc "Take one sample and emit its gauge events (exposed for tests)."
  @spec sample() :: :ok
  def sample() do
    sample_calls()
    sample_registrations()
    sample_mediaservers()
    sample_modules()
    :ok
  end

  defp schedule(interval), do: Process.send_after(self(), :tick, interval)

  # active instances: total + per-domain
  defp sample_calls() do
    safe(fn ->
      stats = Kelix.InstancePool.stats()

      :telemetry.execute(
        [:kelix, :poll, :calls_total],
        %{active: Map.get(stats, :active, 0)},
        %{}
      )

      for {domain, count} <- Map.get(stats, :per_domain, %{}) do
        :telemetry.execute([:kelix, :poll, :calls], %{active: count}, %{domain: domain})
      end
    end)
  end

  # active AOR registrations per domain (count of rows from the control surface)
  defp sample_registrations() do
    safe(fn ->
      Kelix.Control.registrations()
      |> Enum.frequencies_by(& &1.domain)
      |> Enum.each(fn {domain, count} ->
        :telemetry.execute([:kelix, :poll, :registrations], %{count: count}, %{domain: domain})
      end)
    end)
  end

  # each pool MCU: up = enabled AND healthy
  defp sample_mediaservers() do
    safe(fn ->
      for e <- Kelix.MediaPool.status() do
        up = if e.enabled and e.healthy, do: 1, else: 0
        :telemetry.execute([:kelix, :poll, :mcu], %{up: up}, %{mcu: e.name})
      end
    end)
  end

  # Loadable modules with point-in-time state of their own (conferences and their
  # participants, for the `mcu` module) emit it here rather than each running a timer:
  # a module that exports `poll_metrics/0` is sampled on our tick, one that does not
  # is skipped. Generic on purpose — the core names no module.
  defp sample_modules() do
    safe(fn ->
      for {name, _entry} <- Kelix.ModuleRegistry.all() do
        Kelix.ModuleRegistry.facade(name, :poll_metrics, [], :ok)
      end
    end)
  end

  defp safe(fun) do
    fun.()
    :ok
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end
end
