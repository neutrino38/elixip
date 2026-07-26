defmodule Kelixip.MixProject do
  use Mix.Project

  # The kelixip server application (design docs/kelixip_basic_design.md).
  # Built on the shared :elixip2 SIP stack. Delivered as an OTP release
  # (`mix release kelixip`); the `kelictl` control CLI ships inside that release.
  def project do
    [
      app: :kelixip,
      version: "0.2.0",
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
      {:toml, "~> 0.7"}
      # Other server-only deps (bandit, plug, telemetry_*, myxql) are added in
      # later phases, so they never reach the elixipp escript.
    ]
  end

  # `mix release kelixip` -> _build/prod/rel/kelixip with embedded ERTS.
  defp releases do
    [
      kelixip: [
        version: "0.2.0",
        applications: [kelixip: :permanent],
        include_executables_for: [:unix]
      ]
    ]
  end
end
