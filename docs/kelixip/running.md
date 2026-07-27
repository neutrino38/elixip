# Running kelixip

> **Status:** the server boots, binds its `[[listen]]` ports and answers REGISTER
> (P0b). Only the **systemd/packaging** specifics are still pending (**P10**) —
> until then, start the release by hand as shown below.

## The two configuration files

kelixip is configured by two TOML files with distinct lifecycles:

| File | Holds | Reload |
|---|---|---|
| `config.toml` | Infrastructure: `server`, `log`, listeners, media pool, most `[module.*]` blocks, control API, metrics | **Restart only** — a change means a server restart |
| `domains.toml` | Domains, dial-plan, and the `[module.registrar]` block | **Hot** — `kelictl reload-domains` (atomic swap) |

**Every key of both files is documented in
[installation.md § Configuration](installation.md#configuration)**; this page
covers only how to point the server at them and start it. See
[modules/README.md](modules/README.md) for the `[module.<name>]` blocks and each
module page for its parameters.

## Minimal config

```toml
# /etc/kelixip/config.toml
[server]
node_name  = "kelixip@127.0.0.1"
script_dir = "/usr/share/kelixip"
module_dir = "/usr/lib/kelixip/modules"

[[listen]]
proto = "udp"
addr  = "0.0.0.0"
port  = 5060
```

```toml
# /etc/kelixip/domains.toml
[[domain]]
name = "example.com"

  [domain.registrar]
  script = "registrar.exs"          # resolved under script_dir; keep the extension

[module.registrar]
max_contacts_per_aor = 5
```

## Where kelixip looks for those files

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

> A `[[listen]]` UDP entry binds **one socket per node** (the framework's single
> bidirectional UDP transport): `addr` only sets the IP advertised in Via/Contact,
> the socket itself listens on every interface. Extra `udp` entries are ignored
> with a warning.

## Logs

`config.toml`'s `[log]` selects target (`stdout` | `syslog`), facility and level.
Change the level at runtime with `kelictl log-level <lvl>` (see
[administration.md](administration.md)).

Next: [administration.md](administration.md).
