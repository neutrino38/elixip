# Administration with `kelictl`

`kelictl` is a command shipped **inside** the kelixip release, installed as
`/usr/sbin/kelictl`. It runs no SIP stack: it reaches the live node over Erlang
distribution and delegates to the control layer (`Kelix.Control`), then renders
the result as text.

**How it reaches the node.** The `bin/kelictl` overlay runs the CLI *inside* the
running release via `kelixip rpc`, so it shares the node's Erlang **cookie** — the
credential is the cookie, not a token. On a packaged install the cookie is the
per-host secret the post-install script generated in `releases/COOKIE`, and the target
node name comes from **`RELEASE_NODE`** in the environment file (default
`kelixip@127.0.0.1`) — `/etc/sysconfig/kelixip` on Alma Linux, `/etc/default/kelixip`
on Ubuntu/Debian, the same file the systemd unit reads.

> **Note.** `RELEASE_NODE` and `config.toml`'s `server.node_name` are **not
> auto-synced**: if you change `server.node_name`, set the matching `RELEASE_NODE`
> in the environment file too. There is now a single place to do it (the service
> and the CLI both read that file), but nothing yet derives the VM node name from
> the TOML at boot.

## Core commands

| Command | R/W | Does |
|---|---|---|
| `kelictl status` | R | Uptime, counters, listeners, media pool, node state |
| `kelictl monitor` | R | Scenarios in progress (reuses the `--monitor` view) |
| `kelictl registration list [domain]` | R | Registrations, one list per domain (all domains, or one) |
| `kelictl registration show <domain> <aor>` | R | One AOR and its bindings, in detail |
| `kelictl registration remove <domain> <aor> [contact]` | W | Drop a registration |
| `kelictl domain list` | R | Served domains, their functions and live counters |
| `kelictl domain show <domain>` | R | One domain in detail (name **or** alias) |
| `kelictl domain reload-all` | W | Hot-reload `domains.toml` (atomic) |
| `kelictl mediaserver list` | R | The media-server pool: adapter, URL, switch, health |
| `kelictl mediaserver show <name>` | R | One media server in detail |
| `kelictl mediaserver enable\|disable <name>` | W | Take a media server in/out of the pool |
| `kelictl stop <id>` | W | Cooperatively shut down one scenario (id from `monitor`) |
| `kelictl reload-script [--notify] <name…>` | W | Reload scenario script(s) |
| `kelictl module list` | R | Loaded modules: version, implementation, how many commands and facades each contributes |
| `kelictl module reload <name>` | W | Reload a module's config |
| `kelictl log-level <lvl>` | W | Change the log level at runtime (`debug\|info\|warning\|error`) |
| `kelictl graceful-shutdown` | W | Drain scenarios, then shut the node down |

### Examples

```console
$ kelictl status
node:            kelixip@127.0.0.1
uptime:          0h0m1s
active calls:    0
listeners:       udp:0.0.0.0:5060, tcp:0.0.0.0:5060
domains version: 0
modules:
media pool:      (empty)

$ kelictl registration list
example.com
  aor    contacts  expires  bindings
  alice  2         4m58s    sip:alice@10.0.0.9:5060, sip:alice@10.0.0.9:5062
  bob    1         9m12s    sip:bob@10.0.0.22:5060

lab.example.net
  (no registration)

$ kelictl registration list lab.example.net
lab.example.net
  (no registration)

$ kelictl registration show example.com alice
aor:          alice@example.com
contacts:     2
  1. sip:alice@10.0.0.9:5060
     expires:   in 4m58s (2026-08-02T12:34:56Z)
     source:    udp 203.0.113.7:45112
     transport: udp
     instance:  <urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6>
     reg-id:    1
  2. sip:alice@10.0.0.9:5062
     expires:   in 9m40s (2026-08-02T12:39:38Z)
     source:    tls 203.0.113.7:51044
     transport: tls

$ kelictl registration remove example.com alice
ok

$ kelictl domain list
domain           aliases     functions         calls  regs  max
example.com      example.fr  registrar, calls  0      0     500
lab.example.net  -           registrar         0      0     -

$ kelictl domain show example.com
domain:        example.com
aliases:       example.fr
max calls:     500
active calls:  0
registrations: 0
registrar:     default_expires=3600 script=registrar.exs
presence:      (disabled)
dial-plan:
  1. 0[1-9]XXXXXXXX -> user2pstn.exs
  2. (default)      -> catchall.exs

$ kelictl domain show ghost.example.org
no such domain

$ kelictl mediaserver list
server  adapter   url                  enabled  health  modules
mcu1    mendooze  http://10.0.0.1:8080  on       up      mcu=up
mcu2    mendooze  http://10.0.0.2:8080  on       down    mcu=down

$ kelictl mediaserver show mcu1
media server: mcu1
adapter:      mendooze
url:          http://10.0.0.1:8080
enabled:      on
health:       up (pool probe)
mcu:          name mcu1, queue_id q-42, status up, url http://10.0.0.1:8080

$ kelictl mediaserver disable mcu1
ok

$ kelictl mediaserver disable ghost
error: :unknown

$ kelictl domain reload-all
ok
```

An AOR is only unique **within a domain**, so the domain is part of the address
rather than a filter on it: `show` and `remove` take `<domain> <aor>`, and `list`
groups its answer per domain. With no argument, `list` prints one section per
**served** domain — including the ones nobody is registered in, because
"served, empty" and "not served at all" are what an operator is usually trying to
tell apart. `<domain>` is resolved the way inbound traffic is (name **or** alias,
case-insensitively), so the host seen on the wire is a valid argument; an unserved
one is `no such domain`, not an empty list.

`<aor>` is the user-part (`alice`), or the full `alice@example.com` copied out of a
log — in which case its domain part must be that same domain, rather than being
silently ignored. `remove` takes an optional `contact` to drop just that binding
instead of the whole AOR; there is deliberately no form that removes an AOR from
every domain at once. `reload-script` reports one line per script (`<name>: ok` /
`<name>: error: …`).

`show` prints what the registrar stored, not just the URI: `expires` both ways
(the remaining time is the question, the instant is what a log line carries),
`source` — where the REGISTER actually came from, which behind a NAT is **not**
what the contact URI says, and the usual reason a call to a registered phone
never arrives — the transport it is reachable over, and the identity the handset
sent (`instance`, `reg-id`, `methods`, RFC 5626/3840). A field the handset did
not send gets no line rather than a dash.

`domain list` / `domain show` read the **live** `domains.toml` snapshot — what the
router is using right now, which after a rejected `domain reload-all` is *not* what
is on disk (the version is in `kelictl status`). `show` resolves its argument the
way inbound traffic is resolved, against the name **and** the aliases,
case-insensitively, so the host seen on the wire is a valid argument. The
dial-plan is listed in file order and numbered, because it is first-match-wins:
rule *n* is only tried if rules *1…n-1* did not match. `functions` lists what the
domain actually serves (a function block present in the TOML = enabled), so an
empty column means every request to that domain is answered `404`.

`mediaserver list` / `mediaserver show` list the `[mediaserver.pool.*]` entries —
the node's only declaration of a media server — in config order, which is the
round-robin order. Two things that read alike are kept apart there:

* **`enabled`** is the operator switch, flipped by `mediaserver enable|disable`
  and by nothing else. Disabling stops **new** calls and conferences landing on
  that server; what is already running stays until it ends.
* **`health`** is the pool's own probe (a connect/disconnect on the
  point-to-point adapter's channel, every 30 s), and the `modules` column is what
  each module driving that server says about it — the `mcu` module holds a
  *different* control channel to the same box. `up` on one side and `down` on the
  other is a real state, not a contradiction: a server whose JSR-309 side is
  unreachable can serve conferences perfectly, and vice versa.

A server the pool does not declare is `error: :unknown` on `enable`/`disable` and
`no such media server` on `show`.

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

Modules may contribute their own sub-commands, declared once per module
(`describe_control/0`):

```
kelictl <module> <command> [args…]
```

The positional `args…` are handed to the module's `handle_control/2` as
`%{"args" => [ ... ]}`; the convention is `name=value` tokens (`true`/`false` is a
boolean, digits an integer, a leading `{`/`[` is JSON). These share the same
cookie boundary as the core commands.

**Ask the node what it serves** rather than reading the module's source — both
listings are rendered from the declaration itself, so they cannot drift:

```console
$ kelictl module list
module  version  implementation  commands  exports
mcu     1.0      Kelix.Mod.Mcu   9         16

kelictl <module> help lists what a module contributes

$ kelictl mcu help
mcu 1.0 (Kelix.Mod.Mcu)

commands:
  conference.create   [POST /modules/mcu/conferences]
      args: domain* name did mcu vad rate audio_codecs video_codecs text_codecs video layout max_participants destroy_when_empty
      Create a conference (allocates a DID when none is given)
  conference.list     [GET /modules/mcu/conferences]
      args: domain did
      List the conferences, optionally filtered by domain and/or DID
  …

facades (import Kelix.Mod.Mcu):
  create_conference/2, ensure_conference/3, …
```

`*` marks a required argument; the bracketed route is the same command over REST
(`GET /modules` and `GET /modules/<name>` serve the same declarations as JSON).
`help` is therefore reserved on a module namespace.

A module's whole namespace is its own: `kelictl mcu <cmd>` is the `mcu` module's
(`kelictl mcu conference.list`), and enabling or disabling a media server is
`kelictl mediaserver enable|disable <name>` — it acts on a `[mediaserver.pool.*]`
entry, of which the `mcu` module is only one consumer. `domain`, `mediaserver`
and `module` are core nouns and never reach a module, so a mistyped sub-command
prints their usage rather than "unknown module".

Of the shipped modules, only [mcu](modules/mcu.md) contributes commands today —
[registrar](modules/registrar.md) and [auth_db](modules/auth_db.md) contribute
none. The mechanism is documented in
[modules/README.md](modules/README.md#control-surface-kelictl--rest).

## Parity with REST

Every `kelictl` command maps to a `Kelix.Control` function, and the REST frontal
(`Kelix.ControlAPI`) exposes the same functions — same operation, two frontals.
See [rest-api.md](rest-api.md).
