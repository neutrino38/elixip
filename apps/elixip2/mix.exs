defmodule SIPParser.MixProject do
  use Mix.Project

  def project do
    [
      app: :elixip2,
      version: "1.2.0",
      elixir: "~> 1.15",
      # Umbrella: share the root _build / config / deps / lockfile
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      start_permanent: Mix.env() == :prod,
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
      {:logger_file_backend, "~> 0.0.12"},
      {:jason, "~> 1.4"},
      # HTTP client for the HTTP.Session scenario mixin (http_GET). Req 0.6 is
      # the current line; it brings Finch/NimblePool for connection pooling.
      {:req, "~> 0.6"},
      # Fork adding active mode for WebSocket (delivers {:web, socket, data} to the owner)
      {:socket2, github: "neutrino38/elixir-socket", branch: "feat/active-ws"},
      {:ex_sdp, "~> 1.1.1"},
      # XML-RPC encode/decode for the Mendooze JSR309 control interface.
      # 1.5 is the first release accepting decimal ~> 3.0, which is required to
      # get away from the vulnerable decimal 2.x (EEF-CVE-2026-32686).
      {:xmlrpc, "~> 1.5"}
      # NB: owl (terminal UI) moved to apps/elixipp — it is only used by the
      # elixipp escript's --monitor view, not by the shared stack.
    ]
  end
end
