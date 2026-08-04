defmodule Kelix.Metrics do
  @moduledoc """
  Observability (design §11, spec §8.2): `:telemetry` events emitted at the
  framework seams, aggregated by `TelemetryMetricsPrometheus.Core` and exposed as
  Prometheus `/metrics` + a `/health` liveness/readiness probe on the `[metrics]`
  port (separate from the control API, loopback by default).

  This module is a **supervisor** gated on `[metrics].enabled` (returns `:ignore`
  when disabled/unconfigured, like `Kelix.ControlAPI.Endpoint`). When enabled it
  starts three children:

    * the Prometheus **Core** reporter (ETS aggregation over `metrics/0`),
    * `Kelix.Metrics.Poller` — periodically emits the gauge events (active calls /
      registrations per domain, MCU up/down),
    * `Kelix.Metrics.Endpoint` — Bandit serving `Kelix.Metrics.Router`.

  The counter/distribution events are emitted directly at the seams via
  `Kelix.Metrics.Emit`; emitting is a no-op when no reporter is attached, so the
  instrumentation never depends on this supervisor being up.

  All key metrics carry a **`domain` label** (spec §8.2).
  """
  import Telemetry.Metrics

  @reporter_name :kelix_prometheus

  # ── supervisor (gated on [metrics].enabled) ──────────────────────────────────

  @spec child_spec(term) :: Supervisor.child_spec()
  def child_spec(_opts) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, []}, type: :supervisor}
  end

  @spec start_link() :: Supervisor.on_start() | :ignore
  def start_link() do
    case Application.get_env(:kelixip, :metrics, %{}) do
      %{enabled: true} = cfg -> start_children(cfg)
      _ -> :ignore
    end
  end

  defp start_children(cfg) do
    children = [
      {TelemetryMetricsPrometheus.Core, metrics: metrics(), name: @reporter_name},
      Kelix.Metrics.Poller,
      {Kelix.Metrics.Endpoint, cfg}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: __MODULE__)
  end

  @doc "Render the current metrics in Prometheus text format (`\"\"` if no reporter)."
  @spec scrape() :: String.t()
  def scrape() do
    TelemetryMetricsPrometheus.Core.scrape(@reporter_name)
  rescue
    _ -> ""
  catch
    _, _ -> ""
  end

  # ── metric definitions ───────────────────────────────────────────────────────

  @doc "The Telemetry.Metrics definitions exported to Prometheus (spec §8.2)."
  @spec metrics() :: [Telemetry.Metrics.t()]
  def metrics() do
    [
      # Calls / routing — every dispatch decision, split accepted vs rejected.
      counter("kelix.dispatch.accepted.count",
        event_name: [:kelix, :dispatch, :accepted],
        measurement: :count,
        tags: [:domain, :function],
        description: "Out-of-dialog requests accepted (a slot reserved + instance spawned)"
      ),
      counter("kelix.dispatch.rejected.count",
        event_name: [:kelix, :dispatch, :rejected],
        measurement: :count,
        tags: [:domain, :function, :code],
        # the Prometheus exporter needs string label values; `code` is an integer
        tag_values: fn m -> %{m | code: Integer.to_string(m.code)} end,
        description: "Out-of-dialog requests rejected (404/405 routing, 503 quota, 500 load)"
      ),

      # Registrations — the location-service lifecycle, per domain.
      counter("kelix.registrar.event.count",
        event_name: [:kelix, :registrar, :event],
        measurement: :count,
        tags: [:domain, :event],
        description: "Registrar events (registered / unregistered / expired / disconnected)"
      ),

      # Gauges (emitted by the poller).
      last_value("kelix.calls.active",
        event_name: [:kelix, :poll, :calls],
        measurement: :active,
        tags: [:domain],
        description: "Active scenario instances per domain"
      ),
      last_value("kelix.calls.active.total",
        event_name: [:kelix, :poll, :calls_total],
        measurement: :active,
        description: "Active scenario instances (all domains)"
      ),
      last_value("kelix.registrations.active",
        event_name: [:kelix, :poll, :registrations],
        measurement: :count,
        tags: [:domain],
        description: "Active AOR registrations per domain"
      ),
      last_value("kelix.mediaserver.up",
        event_name: [:kelix, :poll, :mcu],
        measurement: :up,
        tags: [:mcu],
        description: "Media server serviceable (enabled + healthy) — 1/0"
      )
    ] ++ mcu_metrics()
  end

  # Conferencing (the `mcu` module, docs/design/mcu_module.md §11). Defined here
  # rather than in the module for the same reason the registrar's are: a loadable
  # module cannot carry half of an event-name contract, and the reporter needs every
  # definition at start — long before a module is loaded.
  defp mcu_metrics() do
    [
      counter("kelix.mcu.call.count",
        event_name: [:kelix, :mcu, :call],
        measurement: :count,
        tags: [:result],
        description: "Inbound conference calls by outcome (joined / 404 / 486 / 488 / 503 / 500)"
      ),
      distribution("kelix.mcu.rpc.duration.seconds",
        event_name: [:kelix, :mcu, :rpc],
        measurement: :duration,
        tags: [:method],
        unit: {:native, :second},
        reporter_options: [buckets: [0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]],
        description: "MCU control RPC duration by method"
      ),
      counter("kelix.mcu.rpc.errors.count",
        event_name: [:kelix, :mcu, :rpc_error],
        measurement: :count,
        tags: [:method, :reason],
        description: "Failed MCU control RPCs by method and reason"
      ),
      last_value("kelix.mcu.conferences",
        event_name: [:kelix, :poll, :mcu_conferences],
        measurement: :count,
        tags: [:mcu],
        description: "Conferences held per media server"
      ),
      last_value("kelix.mcu.participants",
        event_name: [:kelix, :poll, :mcu_participants],
        measurement: :count,
        tags: [:mcu, :conference],
        description: "Participants per conference"
      ),
      last_value("kelix.mcu.mediaserver.up",
        event_name: [:kelix, :poll, :mcu_up],
        measurement: :up,
        tags: [:mcu],
        description: "MCU control channel up (as the conferencing module sees it) — 1/0"
      )
    ]
  end
end
