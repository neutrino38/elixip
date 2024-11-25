defmodule SIPParser.MixProject do
  use Mix.Project

  def project do
    [
      app: :elixip2,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:logger_file_backend, "~> 0.0.12"},
      {:jason, "~> 1.4"},
      {:socket2, "== 2.1.1"}
    ]
  end
end
