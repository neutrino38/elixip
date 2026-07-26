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

    children = [
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
      )
    ]

    opts = [strategy: :one_for_one, name: Kelix.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
