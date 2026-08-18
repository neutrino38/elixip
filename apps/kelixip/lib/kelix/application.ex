defmodule Kelix.Application do
  @moduledoc """
  OTP entry point of the kelixip server (design `docs/design/kelixip_basic_design.md` §2).

  It boots the root supervision tree in the order §2.1 prescribes: infra config,
  then the shared SIP stack registries + the `ConfigRegistry` — which the
  standalone stack otherwise starts imperatively via
  `SIP.Scenario.Runner.bootstrap_stack/0` — then the stores, the modules, the
  frontals, and the **listeners last** (a listener must not accept before the
  router is ready).

  The TOML paths come from the `:kelixip` app env, populated by
  `config/runtime.exs` from `KELIXIP_CONFIG` / `KELIXIP_DOMAINS` (set by the
  systemd unit, design §2.1/§12.1). With no path — `elixipp`, tests, a bare
  release — every store boots empty and no port is bound.
  """
  use Application
  require Logger

  @impl true
  def start(_type, _args) do
    Logger.info(module: __MODULE__, message: "kelixip starting")

    config_path = Application.get_env(:kelixip, :config_path)
    domains_path = Application.get_env(:kelixip, :domains_path)

    resolve_default_dns()

    children = [
      # Syslog sink (§3.1 `[log].target`). Before Kelix.Config, which decides in its
      # own init whether to enable it — so it must already be there to be asked.
      # Inert until enabled: no socket, no handler, nothing on the wire.
      Kelix.Log.Syslog,
      # Infra config (config.toml): parsed once, pushes infra keys into the
      # :elixip2 app env. Started right after (§3.1).
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
      # Stateless-nonce material (§7): the boot-random server secret keying the
      # HMAC nonce (the holder lives in the framework — elixipp needs it too, §16.13),
      # and the intra-window `nc` anti-replay cache. Ordered before the modules —
      # Kelix.Mod.AuthDb calls into both on every challenge.
      SIP.Auth.Secret,
      Kelix.NonceCache,
      # FSM observability: the store the FSL runner reports every state transition
      # to, and the `SIP.Session.*` / `SIP.Dialog.reply` instrumentation its
      # commands. It backs `kelictl monitor` — without it the runner's reporting
      # helpers are no-ops and the whole FSM formalism is invisible from outside.
      # Ordered before the InstancePool, which keys its rows on the instance id.
      SIP.Scenario.Monitor,
      # Script loading/versioning (§5) and the shared instance factory (§4.2).
      Kelix.ScriptRegistry,
      Kelix.InstancePool,
      # Module system (§8): the loaded-module catalogue + the module-contributed
      # control-surface registry, then the supervisor that starts one child per
      # [module.<name>] block (registrar from domains.toml, the rest from
      # config.toml). Ordered after Config + Domains, which it reads.
      Kelix.ModuleRegistry,
      Kelix.Control.Registry,
      Kelix.ModuleSupervisor,
      # Load-time contract check on every script domains.toml refers to (§3.2/§5.3).
      # Here and not earlier: a script's `uses_modules` needs the modules above
      # loaded, and those blocks come from domains.toml itself. Starts no process; a
      # missing / uncompilable / not-shutdown-aware script aborts the boot rather
      # than 500-ing the first call routed to that domain.
      Kelix.ScriptPreflight,
      # Media server pool (§9): round-robin selection over the [mediaserver.pool.*]
      # entries, health-checked; the Router injects the chosen MCU per call. Reads
      # Kelix.Config, so ordered after it; boots empty when no pool is configured.
      Kelix.MediaPool,
      # REST control frontal (§10.3): Bandit + Kelix.ControlAPI, gated on
      # [control_api].enabled. Reads the app env populated by Kelix.Config, so
      # ordered after it; returns :ignore (no server) when disabled/unconfigured.
      Kelix.ControlAPI.Endpoint,
      # Observability (§11): telemetry → Prometheus /metrics + /health, gated on
      # [metrics].enabled. Supervises the Core reporter, the gauge poller and its
      # Bandit endpoint; :ignore when disabled.
      Kelix.Metrics,
      # Dispatch (§4.1): registers the router as the processing module of every
      # implemented SIP function. Stateless — starts no process (:ignore) — but
      # sits here so the wiring precedes the listeners.
      Kelix.Router,
      # Inbound SIP listeners (§2.1): one child per [[listen]] entry. Last, so no
      # request can arrive before the whole stack above is up. No [[listen]]
      # entry ⇒ no child ⇒ no port bound.
      Kelix.Listener.Supervisor
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: Kelix.Supervisor)
  end

  # DNS defaults for SIP.Resolver — normally done by SIP.Transport.Selector.start/0,
  # which the server never calls since the registries are supervised here (§2.1).
  # A host with no usable /etc/resolv.conf must not prevent boot: IP-only routing
  # (and every already-resolved flow) keeps working without a nameserver.
  defp resolve_default_dns() do
    SIP.Resolver.get_dns_default_dns_server()
    :ok
  rescue
    e ->
      Logger.warning(
        module: __MODULE__,
        message: "no default DNS server configured: #{Exception.message(e)}"
      )

      :ok
  end
end
