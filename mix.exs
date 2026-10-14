defmodule Elixip.Umbrella.MixProject do
  use Mix.Project

  # Umbrella root: aggregates the apps under apps/.
  #   apps/elixip2 — shared SIP stack + FSL + media + the elixipp escript
  #   apps/kelixip — the kelixip server (OTP release + kelictl)   (added in P0)
  # Each app declares its own deps and points its build/config/deps/lock at the
  # root (see each apps/*/mix.exs).
  def project do
    [
      apps_path: "apps",
      version: "1.6.0",
      start_permanent: Mix.env() == :prod,
      package: package(),
      deps: deps()
    ]
  end

  # Not published on Hex; declared so the generated SBoM carries the license of
  # every component we ship. BUSL-1.1 is the SPDX id of the Business Source
  # License 1.1 (LICENSE.md); the Change License is GPL-3.0-or-later.
  defp package do
    [licenses: ["BUSL-1.1"]]
  end

  # Umbrella-wide dependencies. Only tooling that must run across every app
  # belongs here; the apps declare their own runtime deps.
  defp deps do
    [
      # CycloneDX SBoM generation (EEF Security WG). Dev-only tooling: it must
      # never end up in the escript or the kelixip release.
      {:sbom, "~> 0.10.0", only: :dev, runtime: false},
      # sbom 0.10 pins protobuf ~> 0.16, which carries CVE-2026-104635; sbom 0.11
      # fixes the pin but needs OTP 27 through purl 0.5. Forced until the OTP bump.
      {:protobuf, "~> 0.17.1", only: :dev, runtime: false, override: true}
    ]
  end
end
