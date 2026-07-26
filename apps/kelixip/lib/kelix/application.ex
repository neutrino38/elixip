defmodule Kelix.Application do
  @moduledoc """
  OTP entry point of the kelixip server (design `docs/kelixip_basic_design.md` §2).

  P0 skeleton: it boots the root supervision tree and supervises the shared SIP
  stack registries + the `ConfigRegistry` — which the standalone stack otherwise
  starts imperatively via `SIP.Scenario.Runner.bootstrap_stack/0`. The remaining
  children (Config, Domains, Router, ModuleSupervisor, MediaPool, listeners,
  ControlAPI, Metrics …) are added in later phases; today it boots with an empty
  configuration.
  """
  use Application
  require Logger

  @impl true
  def start(_type, _args) do
    Logger.info(module: __MODULE__, message: "kelixip starting (P0 skeleton)")

    # Config file paths: wired later from an env var / systemd (design §12);
    # for now they default to nil, so both start with an empty config.
    config_path = Application.get_env(:kelixip, :config_path)
    domains_path = Application.get_env(:kelixip, :domains_path)

    children = [
      # Infra config (config.toml): parsed once, pushes infra keys into the
      # :elixip2 app env. Started first (§3.1).
      {Kelix.Config, path: config_path},
      # SIP stack registries — today started ad-hoc by bootstrap_stack/0, here
      # supervised as first-class children (design §2.1).
      {Registry, keys: :unique, name: Registry.SIP.Transac},
      {Registry, keys: :unique, name: Registry.SIPTransport},
      {Registry, keys: :unique, name: Registry.SIPDialog},
      # ConfigRegistry: the low-level primitive the future Kelix.Router configures
      # (§4). Supervised Agent holding the SIP.Session.ConfigRegistry struct.
      Supervisor.child_spec(
        %{
          id: SIP.Session.ConfigRegistry,
          start:
            {Agent, :start_link,
             [fn -> %SIP.Session.ConfigRegistry{} end, [name: SIP.Session.ConfigRegistry]]}
        },
        []
      ),
      # Domains + dial-plan (domains.toml): hot-reloadable snapshot with atomic
      # swap (§3.2). Started empty; reloaded via Kelix.Domains.reload/1.
      {Kelix.Domains, path: domains_path},
      # Script loading/versioning (§5) and the shared instance factory (§4.2).
      Kelix.ScriptRegistry,
      Kelix.InstancePool
    ]

    opts = [strategy: :one_for_one, name: Kelix.Supervisor]

    case Supervisor.start_link(children, opts) do
      {:ok, sup} ->
        # Route inbound REGISTER through Kelix.Router (design §4.1). calls/presence
        # processing modules are wired when those functions land (roadmap).
        SIP.Session.ConfigRegistry.set_registration_processing_module(Kelix.Router)
        {:ok, sup}

      other ->
        other
    end
  end
end
