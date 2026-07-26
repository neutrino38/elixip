# Administration with `kelictl`

> **Status: skeleton.** `kelictl` and the control layer land in **P7**. The
> command surface below is the locked design (§10.1); each entry is fleshed out
> with real output when implemented.

`kelictl` is a command shipped **inside** the kelixip release, installed as
`/usr/sbin/kelictl`. It is a local client of the running node over Erlang
distribution / RPC: it reads `server.node_name` + the cookie and calls the node's
control layer. It runs no SIP stack, and its credential is the distribution
**cookie** (no token).

## Core commands

| Command | R/W | Does |
|---|---|---|
| `kelictl status` | R | Uptime, counters, media pool, node state |
| `kelictl monitor` | R | Scenarios in progress (reuses the `--monitor` view) |
| `kelictl regs [aor]` | R | Current registrations (all, or one AOR) |
| `kelictl unregister <aor> [contact]` | W | Drop a registration |
| `kelictl stop <id>` | W | Cooperatively shut down one scenario |
| `kelictl reload-script [--notify] <name…>` | W | Reload scenario script(s) |
| `kelictl reload-domains` | W | Hot-reload `domains.toml` (atomic) |
| `kelictl module reload <name>` | W | Reload a module's config |
| `kelictl mcu <name> on\|off` | W | Enable/disable a media server in the pool |
| `kelictl log-level <lvl>` | W | Change the log level at runtime |
| `kelictl graceful-shutdown` | W | Drain scenarios, then shut the node down |

```bash
# TODO (P7): worked examples + real output per command
```

## Module commands

Modules may contribute their own sub-commands, discovered from each module's
declaration:

```
kelictl <module> <command> [args…]
```

These share the same cookie boundary as the core commands. Today neither
[registrar](modules/registrar.md) nor [auth_db](modules/auth_db.md) contributes
one; the mechanism is documented in
[modules/README.md](modules/README.md#control-surface-kelictl--rest).

## Parity with REST

Every `kelictl` command has a matching REST endpoint — same operation, two
frontals. See [rest-api.md](rest-api.md).
