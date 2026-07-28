# Running kelixip

> **Status:** the server boots, binds its `[[listen]]` ports and answers REGISTER
> (P0b). Only the **systemd/packaging** specifics are still pending (**P10**) —
> until then, start the release by hand as shown below.

> kelixip is configured by two TOML files, `config.toml` (infrastructure,
> restart-only) and `domains.toml` (domains + dial-plan, hot-reloadable).
> **Every key of both is documented in
> [installation.md § Configuration](installation.md#configuration)** — this page
> covers only how to point the server at them and run it.

## Where kelixip looks for its config

The release reads two environment variables at every boot (set by the systemd
unit; `rel/env.sh` defaults them to the FHS paths):

| Variable | Default |
|---|---|
| `KELIXIP_CONFIG` | `/etc/kelixip/config.toml` |
| `KELIXIP_DOMAINS` | `/etc/kelixip/domains.toml` |

Override them to run from a checkout:

```bash
KELIXIP_CONFIG=./config.toml KELIXIP_DOMAINS=./domains.toml \
  _build/prod/rel/kelixip/bin/kelixip start      # or `daemon`
```

An unreadable or invalid file **aborts the boot** and prints the reason on
stderr (journald records it), so a failed start always says why.

## Running from a checkout, without packaging

Until the packages exist (**P10**), this is how to run the real server from the
repo. It is what the pre-packaging tests were done with.

**Install the scripts and modules first.** The release carries neither: scripts are
read from `script_dir`, modules loaded from `module_dir`.

```bash
sudo mkdir -p /usr/share/kelixip /usr/lib/kelixip/modules
sudo cp apps/kelixip/scripts/registrar.exs /usr/share/kelixip/
cd apps/kelix_modules && MIX_ENV=prod mix compile
sudo cp ../../_build/prod/lib/kelix_modules/ebin/Elixir.Kelix.Mod.*.beam /usr/lib/kelixip/modules/
```

> **`kelix_modules` is not a dependency of `kelixip`** — deliberately, so the
> release cannot pull the modules in (§16.12). The consequence bites in
> development: **nothing recompiles it for you**. Change a module and the server
> keeps running the `.beam` you installed last time, silently. Redo the compile +
> copy above after every module change. `elixip2`, being a real dependency, *is*
> rebuilt by the command below.

**Start it.** `MIX_ENV=prod` matters: `config/runtime.exs` only reads
`KELIXIP_CONFIG`/`KELIXIP_DOMAINS` in prod, so a dev run ignores your TOML
entirely. The node name must be the one `kelictl` targets (`server.node_name`,
default `kelixip@127.0.0.1`).

```bash
cd apps/kelixip
MIX_ENV=prod elixir --name kelixip@127.0.0.1 --cookie kelixip-dev -S mix run --no-halt
```

It runs in the foreground and logs there. Point it elsewhere with
`KELIXIP_CONFIG=… KELIXIP_DOMAINS=…` on the same line.

**Drive it with `kelictl`.** The `bin/kelictl` wrapper only exists inside the
release; from a checkout, this shell function is the same thing (the cookie must
match):

```bash
cd apps/kelixip
kelictl() { MIX_ENV=prod elixir --name kelictl@127.0.0.1 --cookie kelixip-dev \
    -S mix run --no-start -e 'Kelix.Control.CLI.main(System.argv())' -- "$@"; }

kelictl status
kelictl regs
kelictl monitor
```

> Pick a `[[listen]]` port nothing else holds. 5060/5061/5066/5067/443 are often
> taken by a local kamailio or softswitch; a bind failure **aborts the boot** and
> says so on stderr. The test suite binds `5070` by default too — override with
> `ELIXIP_TEST_UDP_PORT` if you run `mix test --include live` against a live server.

## Start / stop

```bash
# TODO (P10): systemctl start|stop|restart kelixip
kelictl graceful-shutdown        # drain in-progress scenarios first
```

`graceful-shutdown` is the clean way and what the systemd unit will use: it sends
`{:scenario_ctl, :shutdown, …}` to every live instance (each script runs its
`on_shutdown` block), waits a grace period, then stops the VM through the OTP
shutdown sequence — listeners first, sockets closed, stores last. `Ctrl+C Ctrl+C`
kills the VM outright: no `on_shutdown`, no orderly teardown. Fine in development,
not with calls in progress.

## First boot

1. Validate config — an invalid file aborts boot with a clear message (fail fast;
   systemd sees a failed start).
2. Modules from `config.toml` (+ `registrar` from `domains.toml`) start, then the
   listeners bind — last, so nothing is accepted before the dispatch is ready.
3. Check what came up: `kelictl status` lists the bound listeners and the loaded
   modules.
4. Send a test `REGISTER` to a configured domain: an unauthenticated one must be
   answered `401` with a `WWW-Authenticate` challenge.

## Logs

Logs go where `config.toml`'s `[log]` says (keys in
[installation.md](installation.md#log)). Two things worth knowing:

**stdout is always live.** `target = "syslog"` *adds* a sink, it does not replace
one — under systemd, journald captures stdout anyway, and a startup failure has to
be visible there. So with `syslog` you get both.

```toml
[log]
target   = "syslog"
facility = "local2"
level    = "info"
```

Lines then go to the local `/dev/log` socket as RFC 3164 datagrams, which journald
and rsyslog both read:

```bash
journalctl -t kelixip -f          # journald
tail -f /var/log/messages         # rsyslog, per its own routing rules
```

If you only want syslog *files* without changing kelixip's config, journald can
forward what it already captures — `ForwardToSyslog=yes` in
`/etc/systemd/journald.conf`.

**The level reaches every sink.** `[log].level` is applied to the console, the file
backend and the syslog sink, not just to the logger's own threshold — a `debug`
there really does produce the SIP trace. Change it without a restart with
`kelictl log-level <lvl>` (see [administration.md](administration.md)).

Next: [administration.md](administration.md).
