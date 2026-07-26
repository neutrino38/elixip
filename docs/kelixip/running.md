# Running kelixip

> **Status: skeleton.** The systemd/CLI specifics are finalized with **P7**
> (control layer) and **P10** (packaging). The configuration model below is
> current.

## The two configuration files

kelixip is configured by two TOML files with distinct lifecycles:

| File | Holds | Reload |
|---|---|---|
| `config.toml` | Infrastructure: `server`, `log`, listeners, media pool, most `[module.*]` blocks, control API, metrics | **Restart only** — a change means a server restart |
| `domains.toml` | Domains, dial-plan, and the `[module.registrar]` block | **Hot** — `kelictl reload-domains` (atomic swap) |

See [modules/README.md](modules/README.md) for the `[module.<name>]` blocks and
each module page for its parameters.

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
  script = "uas_register"
```

## Start / stop

```bash
# TODO (P10): systemctl start|stop|restart kelixip
# TODO (P7):  kelictl graceful-shutdown        # drain in-progress scenarios first
```

## First boot

1. Validate config — an invalid file aborts boot with a clear message (fail fast;
   systemd sees a failed start).
2. Listeners bind; modules from `config.toml` (+ `registrar` from `domains.toml`)
   start.
3. Send a test `REGISTER` to a configured domain.

## Logs

`config.toml`'s `[log]` selects target (`stdout` | `syslog`), facility and level.
Change the level at runtime with `kelictl log-level <lvl>` (see
[administration.md](administration.md)).

Next: [administration.md](administration.md).
