# Running kelixip

> kelixip is configured by two TOML files, `config.toml` (infrastructure,
> restart-only) and `domains.toml` (domains + dial-plan, hot-reloadable).
> **Every key of both is documented in
> [installation.md § Configuration](installation.md#configuration)** — this page
> covers only how to point the server at them and run it.

## Where kelixip looks for its config

The release reads two environment variables at every boot:

| Variable | Default |
|---|---|
| `KELIXIP_CONFIG` | `/etc/kelixip/config.toml` |
| `KELIXIP_DOMAINS` | `/etc/kelixip/domains.toml` |

On a packaged install they come from the **environment file**
(`/etc/sysconfig/kelixip` on Alma Linux, `/etc/default/kelixip` on Ubuntu/Debian),
which both the systemd unit and the release's own `rel/env.sh` read — so `kelictl` and
the service always agree on the node, the cookie and the config paths. Set them in the
environment to override a single invocation; `rel/env.sh` lets the environment win
over the file.

Override them to run from a checkout:

```bash
KELIXIP_CONFIG=./config.toml KELIXIP_DOMAINS=./domains.toml \
  _build/prod/rel/kelixip/bin/kelixip start      # or `daemon`
```

An unreadable or invalid file **aborts the boot** and prints the reason on
stderr (journald records it), so a failed start always says why.

## Running from a checkout, without packaging

This is how to run the real server from the repo — for development, when you do not
want to rebuild a package for every change. On a real host, install the packages
([installation.md](installation.md)) and use `systemctl` instead.

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
kelictl registration list
kelictl monitor
```

> Pick a `[[listen]]` port nothing else holds. A bind failure **aborts the boot** and
> says so on stderr. The test suite binds `5070` by default too — override with
> `ELIXIP_TEST_UDP_PORT` if you run `mix test --include live` against a live server.

## Start / stop / reload

```bash
systemctl start kelixip
systemctl reload kelixip          # = kelictl reload-all (atomic, no restart)
systemctl stop kelixip            # drains first, see below
systemctl restart kelixip         # the only way to apply a config.toml change
kelictl graceful-shutdown         # same drain, without systemd
```

`graceful-shutdown` is the clean way and what the unit's `ExecStop` runs: it sends
`{:scenario_ctl, :shutdown, …}` to every live instance (each script runs its
`on_shutdown` block), waits a grace period, then stops the VM through the OTP
shutdown sequence — listeners first, sockets closed, stores last. `Ctrl+C Ctrl+C`
kills the VM outright: no `on_shutdown`, no orderly teardown. Fine in development,
not with calls in progress.

> The call **returns as soon as the drain is broadcast** — it schedules the VM stop
> and hands control back, so `kelictl` does not hang. systemd kills whatever
> survives `ExecStop`, which would cut the drain short, so the unit follows it with
> a wait on the main PID, bounded by `TimeoutStopSec=90`. A `systemctl stop` on an
> idle node takes a handful of seconds; with calls in progress it takes the drain.

`systemctl reload` applies **`domains.toml`** (domains, dial-plan, registrar block),
re-reads the **scenario scripts** that changed on disk, and applies the module blocks
that can be changed live. It is all-or-nothing: a `domains.toml` that does not
validate, or that names a script the node cannot serve, is **refused** — the running
configuration is untouched, the reason goes to the journal, and the `systemctl reload`
command itself fails. The same check runs at boot, where it aborts the start instead of
serving calls that would fail one by one. Details and the report format:
[administration.md](administration.md#reloading-a-running-node).

`config.toml` (listeners, ports, media pool, control API) is restart-only by design,
and so is a module whose configuration changed but whose restart would drop live state
— `reload` says so instead of doing it behind your back.

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
[installation.md](installation.md#log)). Three things worth knowing.

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

**Security incidents have a file of their own.** A refused credential, a request
for a domain the node does not serve, a packet that is not SIP, a failed TLS
handshake, a control-API call without a valid token: each is one line, written
twice. To the journal as a warning, with everything else — so `[log] level =
"error"` filters that copy out. And to the file `[security] log_file` names
([installation.md](installation.md#security)), which the package sets to
`/var/log/kelixip/security.log` and rotates weekly through
`/etc/logrotate.d/kelixip`:

```
2026-10-07T12:34:56Z kelixip: auth-failure src=192.0.2.5 port=5060 proto=UDP method=REGISTER realm=example.com user="alice" reason=bad_password
2026-10-07T12:35:02Z kelixip: invalid-domain src=203.0.113.7 port=5060 proto=TCP method=INVITE reason=unknown_domain
2026-10-07T12:35:09Z kelixip: invalid-packet src=198.51.100.2 port=40000 proto=UDP reason=unparsable
```

The `kelixip: ` prefix, the key order and `src=` second are a contract: the
fail2ban filters below read them. `user` is the only free text and is quoted and
escaped, so a username cannot forge a second `src=`. A successful authentication
is not an incident and is not written. An install upgraded from an earlier version
keeps its `config.toml`, so it has no `[security]` block: the journal copy is
there regardless, and the file appears once you add

```toml
[security]
log_file = "/var/log/kelixip/security.log"
```

## fail2ban

The package ships four filters and a jail example under
`/usr/share/kelixip/fail2ban/`. Link the filters in, copy the jails, reload:

```bash
ln -s /usr/share/kelixip/fail2ban/filter.d/kelixip-*.conf /etc/fail2ban/filter.d/
cp /usr/share/kelixip/fail2ban/jail.d/kelixip.conf /etc/fail2ban/jail.d/
fail2ban-client reload
fail2ban-client status kelixip-scan
```

| Jail | Counts | `maxretry` |
|---|---|---|
| `kelixip-auth` | `auth-failure … reason=bad_password` | 5 |
| `kelixip-scan` | `auth-failure` with `unknown_user` or `bad_realm`; `invalid-domain` | 2 |
| `kelixip-api` | `api-auth` (missing or wrong token, no client certificate) | 3 |
| `kelixip-packet` | `invalid-packet`; `transport-error` (TLS handshake, WebSocket upgrade) | 20 |

Each jail can read either copy. The example reads the file (`logpath =
/var/log/kelixip/security.log`); to read the journal instead, replace `logpath`
with `backend = systemd` and `journalmatch = _SYSTEMD_UNIT=kelixip.service`. Check
a filter against what the node actually wrote with
`fail2ban-regex /var/log/kelixip/security.log kelixip-auth`.

Four caveats, none of which the jails solve:

- **UDP source addresses are spoofable.** Whoever forges a customer's address can
  get it banned. Put your own peers and trunks in `ignoreip`.
- **Over IPv6, ban a /64**, not one address: a host has more addresses than
  `maxretry` will ever see. fail2ban bans the exact address unless its action is
  told otherwise.
- **A NATed office is one address.** Keep `maxretry` generous on `kelixip-auth` and
  strict on `kelixip-scan`.
- **Never behind a reverse proxy or a load balancer** that terminates the
  connection: every source the node sees is the proxy's own address, and the first
  ban cuts off every user at once. kelixip does not read `X-Forwarded-For` or the
  PROXY protocol.

A UA whose messages trip a parser case kelixip does not foresee is counted by
`kelixip-packet`. The node-side switch is `[security] ignore = ["invalid-packet"]`:
that type is no longer written, the other three jails keep working.

Next: [administration.md](administration.md).
