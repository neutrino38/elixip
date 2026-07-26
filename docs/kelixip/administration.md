# Administration with `kelictl`

`kelictl` is a command shipped **inside** the kelixip release, installed as
`/usr/sbin/kelictl`. It runs no SIP stack: it reaches the live node over Erlang
distribution and delegates to the control layer (`Kelix.Control`), then renders
the result as text.

**How it reaches the node.** The `bin/kelictl` overlay runs the CLI *inside* the
running release via `kelixip rpc`, so it shares the node's Erlang **cookie**
(`releases/COOKIE`) — the credential is the cookie, not a token. The target node
name comes from **`RELEASE_NODE`** (set in the release's `rel/env.sh.eex`, default
`kelixip@127.0.0.1`).

> **Note.** `RELEASE_NODE` and `config.toml`'s `server.node_name` are **not yet
> auto-synced**: if you change `server.node_name`, set the matching `RELEASE_NODE`
> in `env.sh` too. Wiring the VM node name from `server.node_name` at boot is a
> packaging follow-up (P10).

## Core commands

| Command | R/W | Does |
|---|---|---|
| `kelictl status` | R | Uptime, counters, media pool, node state |
| `kelictl monitor` | R | Scenarios in progress (reuses the `--monitor` view) |
| `kelictl regs [aor]` | R | Current registrations (all, or one AOR) |
| `kelictl unregister <aor> [contact]` | W | Drop a registration |
| `kelictl stop <id>` | W | Cooperatively shut down one scenario (id from `monitor`) |
| `kelictl reload-script [--notify] <name…>` | W | Reload scenario script(s) |
| `kelictl reload-domains` | W | Hot-reload `domains.toml` (atomic) |
| `kelictl module reload <name>` | W | Reload a module's config |
| `kelictl mcu <name> on\|off` | W | Enable/disable a media server in the pool |
| `kelictl log-level <lvl>` | W | Change the log level at runtime (`debug\|info\|warning\|error`) |
| `kelictl graceful-shutdown` | W | Drain scenarios, then shut the node down |

### Examples

```console
$ kelictl status
node:            kelixip@127.0.0.1
uptime:          0h0m1s
active calls:    0
domains version: 0
modules:
media pool:      (empty)

$ kelictl regs
no registrations

$ kelictl regs alice
alice@example.com -> sip:alice@10.0.0.9:5060

$ kelictl unregister alice@example.com
ok

$ kelictl mcu mcu1 off
ok

$ kelictl mcu ghost off
error: :unknown

$ kelictl reload-domains
ok
```

`unregister <aor>` accepts `user@domain` (that domain) or `user` (every domain);
an optional `contact` removes just that binding. `reload-script` reports one line
per script (`<name>: ok` / `<name>: error: …`).

### Exit codes

`kelictl` classifies results as `0` (ok), `1` (command error, e.g. unknown MCU),
or `2` (usage / bad arguments). **Caveat:** because the overlay dispatches through
`kelixip rpc`, the numeric exit code is **not currently propagated to the shell**
(it always returns `0`); scripts should match on the printed output, not `$?`.
This propagation is a roadmap refinement.

> `reload-script --notify` is **accepted but not yet active** — notifying
> in-progress instances of a reload is a roadmap refinement; today the flag is a
> no-op and the reload swaps the script version as usual.

## Module commands

Modules may contribute their own sub-commands, discovered from each module's
declaration (`describe_control/0`):

```
kelictl <module> <command> [args…]
```

The positional `args…` are handed to the module's `handle_control/2` as
`%{"args" => [ ... ]}`. These share the same cookie boundary as the core commands.
Today neither [registrar](modules/registrar.md) nor [auth_db](modules/auth_db.md)
contributes one; the mechanism is documented in
[modules/README.md](modules/README.md#control-surface-kelictl--rest).

## Parity with REST

Every `kelictl` command maps to a `Kelix.Control` function, and the REST frontal
(P8) exposes the same functions — same operation, two frontals. See
[rest-api.md](rest-api.md).
