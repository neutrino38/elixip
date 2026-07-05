defmodule SIPParser.MixProject do
  use Mix.Project

  def project do
    [
      app: :elixip2,
      version: "0.2.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      escript: escript(),
      deps: deps()
    ]
  end

  # Standalone executable: `mix escript.build` produces ./elixipp
  defp escript do
    [main_module: Elixipp.CLI, name: "elixipp"]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :inets]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:logger_file_backend, "~> 0.0.12"},
      {:jason, "~> 1.4"},
      # Fork adding active mode for WebSocket (delivers {:web, socket, data} to the owner)
      {:socket2, github: "neutrino38/elixir-socket", branch: "feat/active-ws"},
      {:ex_sdp, "~> 1.1.1"},
      # XML-RPC encode/decode for the Mendooze JSR309 control interface
      {:xmlrpc, "~> 1.4"},
      # Pure-Elixir terminal UI (tables + live screen) for the elixipp --monitor view.
      # No C NIF (its only dep, ucwidth, is optional), so it bundles cleanly in the escript.
      {:owl, "~> 0.12"}
    ]
  end
end
