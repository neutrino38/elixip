defmodule Elixip.Umbrella.MixProject do
  use Mix.Project

  # Umbrella root: aggregates the apps under apps/.
  #   apps/elixip2 — shared SIP stack + DSL + media + the elixipp escript
  #   apps/kelixip — the kelixip server (OTP release + kelictl)   (added in P0)
  # Each app declares its own deps and points its build/config/deps/lock at the
  # root (see each apps/*/mix.exs).
  def project do
    [
      apps_path: "apps",
      version: "1.1.0",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Umbrella-wide dependencies (none for now; apps declare their own).
  defp deps do
    []
  end
end
