import Config

# Runtime (release-boot) configuration. Mix evaluates this file at every boot of
# the assembled release — this is where the kelixip server learns where its TOML
# files are (design §2.1: "Application.start/2 reads the TOML path from an env var
# set by the boot script / systemd unit").
#
#   KELIXIP_CONFIG   → config.toml   (infra: listeners, media pool, modules, API)
#   KELIXIP_DOMAINS  → domains.toml  (domains + dial-plan, hot-reloadable)
#
# Both default to the FHS location the package installs (§12.1). A missing or
# invalid file aborts the boot with a clear message (fail fast, so systemd reports
# a failed start) — point the variables elsewhere to run from a checkout.
#
# Guarded on :prod so `mix test`, `mix scenario` and the elixipp escript keep
# booting with an empty config (no file, no listener), as they always have.
if config_env() == :prod do
  config :kelixip,
    config_path: System.get_env("KELIXIP_CONFIG", "/etc/kelixip/config.toml"),
    domains_path: System.get_env("KELIXIP_DOMAINS", "/etc/kelixip/domains.toml")
end
