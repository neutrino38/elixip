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

## Start / stop

```bash
# TODO (P10): systemctl start|stop|restart kelixip
kelictl graceful-shutdown        # drain in-progress scenarios first
```

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

Logs go where `config.toml`'s `[log]` says. The level is the one setting worth
changing without a restart: `kelictl log-level <lvl>` (see
[administration.md](administration.md)).

Next: [administration.md](administration.md).
