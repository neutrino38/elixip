defmodule Kelixip.MixProject do
  use Mix.Project

  # The kelixip server application (design docs/kelixip_basic_design.md).
  # Built on the shared :elixip2 SIP stack. Delivered as an OTP release
  # (`mix release kelixip`); the `kelictl` control CLI ships inside that release.
  def project do
    [
      app: :kelixip,
      version: "1.1.0",
      elixir: "~> 1.15",
      # Umbrella: share the root _build / config / deps / lockfile
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      releases: releases()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto],
      mod: {Kelix.Application, []}
    ]
  end

  defp deps do
    [
      # The shared SIP stack + DSL + media.
      {:elixip2, in_umbrella: true},
      # Declarative config parser (config.toml / domains.toml). Pure Elixir,
      # no NIF, release-safe (design §13).
      {:toml, "~> 0.7"},
      # MariaDB/MySQL driver for the auth_db module (subscriber table HA1 lookup).
      {:myxql, "~> 0.7"},
      # REST control API (design §10.3): a Plug.Router served by Bandit. Pure
      # Elixir, release-safe. Kept out of the elixipp escript (server-only).
      {:plug, "~> 1.16"},
      {:bandit, "~> 1.5"},
      # Observability (design §11): :telemetry events → Prometheus. The `_core`
      # exporter aggregates in ETS and exposes `scrape/1`; we serve /metrics +
      # /health ourselves over the existing Bandit, no second HTTP stack.
      {:telemetry, "~> 1.2"},
      {:telemetry_metrics, "~> 1.0"},
      {:telemetry_metrics_prometheus_core, "~> 1.1"}
    ]
  end

  # `mix release kelixip` -> _build/prod/rel/kelixip with embedded ERTS.
  defp releases do
    [
      kelixip: [
        version: "1.1.0",
        applications: [kelixip: :permanent],
        include_executables_for: [:unix]
      ]
    ]
  end
end
