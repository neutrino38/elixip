defmodule KelixModules.MixProject do
  use Mix.Project

  # The **provided modules** of kelixip (`registrar`, `auth_db` — design §8.3).
  #
  # They live in their own app *on purpose*: the core release must NOT carry them
  # (§16.12). `apps/kelixip` does not depend on this app, so `mix release kelixip`
  # cannot pull it in; the modules ship as separate rpm/deb subpackages that drop
  # their `.beam` into `module_dir`, and `Kelix.ModuleSupervisor` loads them from
  # there per config. A kelixip-based product (an MCU, say) installs none of them.
  #
  # This app therefore produces **no OTP application to start** — no `mod:`, no
  # supervision tree. Its modules are started by `Kelix.ModuleSupervisor` inside a
  # running kelixip node. It depends on `:kelixip` for the `Kelix.Module`
  # behaviour + the surfaces the modules use (ModuleRegistry, NonceCache, Domains);
  # the dependency never points the other way.
  def project do
    [
      app: :kelix_modules,
      version: "1.3.0",
      elixir: "~> 1.15",
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto]]
  end

  defp deps do
    [{:kelixip, in_umbrella: true}]
  end
end
