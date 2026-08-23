import Config

# Runtime (release-boot) configuration. Mix evaluates this file at every boot of
# the assembled release — this is where the kelixip server learns where its TOML
# files are (design §2.1: "Application.start/2 reads the TOML path from an env var
# set by the boot script / systemd unit").
#
#   KELIXIP_CONFIG   → config.toml   (infra: listeners, media pool, modules, API)
#   KELIXIP_DOMAINS  → domains.toml  (domains + dial-plan, hot-reloadable)
#
# In **:prod** both default to the FHS location the package installs (§12.1). A
# missing or invalid file aborts the boot with a clear message (fail fast, so systemd
# reports a failed start).
#
# In every **other** environment the variables are honoured too, but there is no
# default: unset means no path, so `mix test`, `mix scenario` and the elixipp escript
# keep booting with an empty config — no file, no listener — exactly as they always
# have. What this buys is running a real server from a checkout in one command line
# (see BUILD.md, "Running the mcu module from a checkout"), instead of setting the app
# env by hand before starting the application.
default = fn fhs -> if config_env() == :prod, do: fhs, else: nil end

config :kelixip,
  config_path: System.get_env("KELIXIP_CONFIG", default.("/etc/kelixip/config.toml")),
  domains_path: System.get_env("KELIXIP_DOMAINS", default.("/etc/kelixip/domains.toml"))

# The release's log sinks are the ones `[log] target` names: stdout, which systemd
# captures, plus syslog on demand. The umbrella config also adds a file backend for
# the elixipp tool, whose path is *relative* (`elixip.log`, next to wherever the tool
# was run from) — and the service's working directory is `/`, which it may not write.
# In the release that sink could only ever fail to open, so it is not installed;
# `[log] level` reaches the console sink either way (`Kelix.Config.set_level/1`).
if config_env() == :prod do
  config :logger, backends: [:console]
end
