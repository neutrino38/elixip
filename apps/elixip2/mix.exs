defmodule SIPParser.MixProject do
  use Mix.Project

  def project do
    [
      app: :elixip2,
      version: "1.6.0",
      elixir: "~> 1.15",
      # Umbrella: share the root _build / config / deps / lockfile
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      start_permanent: Mix.env() == :prod,
      # SPDX id of the Business Source License 1.1 (see LICENSE.md). Read by
      # `mix sbom.cyclonedx` to license this component in the SBoM.
      package: [licenses: ["BUSL-1.1"]],
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps()
    ]
  end

  # test/support holds the test-only SIP transport mockup and its peers
  # (SIP.Test.*). Keeping them out of :dev/:prod keeps them out of the
  # library and of the kelixip release.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :inets, :crypto]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # The Finite State Language: the engine every scenario and every kelixip
      # script runs on. It lives in its own repository and ships as the hex
      # package `finite_state_language` (OTP app `:fsl`, Apache-2.0).
      {:fsl, "~> 0.2.1", hex: :finite_state_language},
      {:logger_file_backend, "~> 0.0.12"},
      {:jason, "~> 1.4"},
      {:req, "~> 0.6"},
      # Our fork, on a tag. It carries what upstream lacks and we depend on: active
      # mode for WebSocket, IPv6 improvments and mTLS support
      {:socket2, github: "neutrino38/elixir-socket", tag: "2.2.1"},
      # 1.2 parses the m= fmt list as payload types for every RTP profile and
      # accepts the a=fingerprint hash-func token case-insensitively 
      {:ex_sdp, "~> 1.2"},
      # XML-RPC encode/decode for the Mendooze JSR309 control interface.
      {:xmlrpc, "~> 1.5"},
      # The XML parser, for PIDF (SIP.Presence.Pidf).
      {:erlsom, "~> 1.5"}
    ]
  end
end
