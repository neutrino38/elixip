defmodule Elixipp.MixProject do
  use Mix.Project

  # The elixipp test tool (a sipp-like SIP scenario runner). Standalone escript
  # built on the shared :elixip2 SIP stack. Kept as a distinct umbrella app so
  # the escript carries only its own deps (owl) and never the kelixip server
  # deps (design docs/design/kelixip_basic_design.md §12.0).
  def project do
    [
      app: :elixipp,
      version: "1.2.1",
      elixir: "~> 1.15",
      # Umbrella: share the root _build / config / deps / lockfile
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      start_permanent: Mix.env() == :prod,
      escript: escript(),
      deps: deps()
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  # `mix escript.build` (from this app dir) produces ./elixipp
  defp escript do
    [main_module: Elixipp.CLI, name: "elixipp"]
  end

  defp deps do
    [
      # The shared SIP stack + DSL + media.
      {:elixip2, in_umbrella: true},
      # Pure-Elixir terminal UI for the --monitor live table (escript-only).
      {:owl, "~> 0.12"}
    ]
  end
end
