# Installation

## Prerequisites

- Alma Linux 9 (x86_64 or aarch64). The release embeds its own ERTS — no system
  Erlang/Elixir required.
- A database only if you load [`auth_db`](modules/auth_db.md) (MariaDB/MySQL).

## Packages

kelixip is shipped as a **core** release plus **one package per module**, so a
deployment installs only what it uses — the core itself implements no SIP function.

| Package | Contents |
|---|---|
| `kelixip` | the server + `kelictl` + the systemd unit + `/etc/kelixip` |
| `kelixip-mod-registrar` | the [registrar](modules/registrar.md) / user-location module |
| `kelixip-mod-auth_db` | the [database authentication](modules/auth_db.md) module |

```bash
dnf install kelixip kelixip-mod-registrar kelixip-mod-auth_db
# or, from the built files:
rpm -ivh kelixip-*.rpm
```

A domain that enables a function whose module is not installed is a **config error
caught at load time** — it is not a runtime surprise. Installing a module later is a
package install plus `kelictl module reload <name>`; no restart.

Building the packages yourself: [`packaging/README.md`](../../packaging/README.md).

## Filesystem layout (FHS, §12)

| Path | Contents |
|---|---|
| `/etc/kelixip/config.toml` | Infrastructure config (`%config(noreplace)`, 0640 `root:kelixip`) |
| `/etc/kelixip/domains.toml` | Domains + dial-plan + registrar block (`%config(noreplace)`) |
| `/etc/kelixip/tls/` | Listener certificates (0750 `root:kelixip`) |
| `/etc/sysconfig/kelixip` | Node name, cookie and the two TOML paths (`%config(noreplace)`) |
| `/usr/share/kelixip/` | Scenario scripts (`script_dir`) |
| `/usr/lib/kelixip/` | The release itself (embedded ERTS) |
| `/usr/lib/kelixip/modules/` | Loadable modules (`module_dir`, **root-owned**) |
| `/usr/sbin/kelictl` | Admin CLI (a command inside the release) |
| `/usr/sbin/kelixip` | The release's own control script (`start`, `rpc`, …) |
| `/var/lib/kelixip/`, `/var/log/kelixip/` | Mutable state; logs when stdout is redirected |

`module_dir` is root-owned and **not writable by the service** on purpose: loading
a `.beam` is executing code.

## System user & service

The package creates an unprivileged `kelixip` system user and a systemd unit; the
service runs as that user, with `CAP_NET_BIND_SERVICE` as its only privilege (so a
`[[listen]]` entry may ask for port 443).

```bash
systemctl enable --now kelixip
systemctl status kelixip
```

Everything an admin needs to override lives in **`/etc/sysconfig/kelixip`** — never
in the unit, which the package replaces on upgrade:

| Variable | Default | Meaning |
|---|---|---|
| `RELEASE_NODE` | `kelixip@127.0.0.1` | Erlang node name. **Must match `server.node_name`** in config.toml |
| `KELIXIP_CONFIG` / `KELIXIP_DOMAINS` | the two FHS paths | Where the TOML files are read from |
| `RELEASE_COOKIE` | *(unset)* | Only to share one cookie across a cluster — see below |

`kelictl` reads the same file, so it targets the node the service actually runs;
changing `RELEASE_NODE` in one place is enough.

> **The distribution cookie is generated per installation.** It is the credential
> `kelictl` authenticates with, so no fixed cookie ships in the package: `%post`
> generates `/usr/lib/kelixip/releases/COOKIE` from `/dev/urandom` (0640
> `root:kelixip`), keeps it across upgrades and removes it on erase.

### Upgrades

`config.toml` and `domains.toml` are `%config(noreplace)`: your files are kept and
the packaged version lands next to them as `*.rpmnew` — worth diffing after an
upgrade, since new keys show up there first. The unit is restarted by the upgrade.

## Configuration

kelixip reads **two TOML files**, deliberately split by lifecycle:

| File | Holds | Reload |
|---|---|---|
| `config.toml` | Infrastructure: `[server]`, `[log]`, listeners, media pool, most `[module.*]` blocks, control API, metrics | **Restart only** |
| `domains.toml` | The served domains, their dial-plan and the `[module.registrar]` block | **Hot** — `kelictl reload-domains` (atomic: one bad value and the whole reload is rejected, the running config untouched) |

Their paths come from `KELIXIP_CONFIG` / `KELIXIP_DOMAINS` (see
[running.md](running.md)). Both files are validated at boot: **any error aborts
the start** with the reason on stderr, rather than running half-configured.
Unknown keys are rejected too — a typo must not silently fall back to a default.

### config.toml

#### `[server]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `node_name` | string | `kelixip@127.0.0.1` | Erlang node name (`kelictl` reaches the node with it) |
| `script_dir` | string | `/usr/share/kelixip` | Where scenario scripts are resolved from |
| `module_dir` | string | `/usr/lib/kelixip/modules` | Where module `.beam` files are loaded from |
| `user_agent` | string | `kelixip/1.0` | `User-Agent` / `Server` header value |
| `max_calls` | int > 0 | *unlimited* | Node-wide concurrent-instance cap; beyond it, new requests get `503` |

#### `[log]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `target` | `stdout` \| `syslog` | `stdout` | `syslog` adds an RFC 3164 sink over the local `/dev/log` socket (journald and rsyslog both listen there). It **adds** a sink: stdout stays live, since systemd captures it |
| `facility` | `kern`, `user`, `daemon`, `local0`…`local7`, … | `local0` | Syslog facility. Validated against the RFC 3164 list; unused while `target = "stdout"` |
| `level` | `debug` \| `info` \| `warning` \| `error` | `info` | Also changeable at runtime with `kelictl log-level` |

#### `[[listen]]` — one entry per inbound socket

| Key | Type | Required | Meaning |
|---|---|---|---|
| `proto` | `udp` \| `tcp` \| `tls` \| `wss` | **yes** | Transport |
| `addr` | IP address | no (`0.0.0.0`) | Bind address; must parse as an IP |
| `port` | int > 0 | **yes** | Bind port |
| `cert` / `key` | path | **yes for `tls`/`wss`** | Per-listener PEM cert and key. **Forbidden** on `udp`/`tcp` |

```toml
[[listen]]
proto = "udp"
addr  = "0.0.0.0"
port  = 5060

[[listen]]
proto = "wss"
addr  = "0.0.0.0"
port  = 8443
cert  = "/etc/pki/kelixip/fullchain.pem"
key   = "/etc/pki/kelixip/privkey.pem"
```

> A listener that cannot bind (port busy, unreadable cert) **aborts the boot** —
> a half-deaf server is worse than a failed start.
>
> UDP is **one socket per node** (the framework's single bidirectional UDP
> transport): extra `udp` entries are ignored with a warning, and `addr` only
> sets the IP advertised in Via/Contact — the socket itself listens everywhere.

#### `[module.<name>]` — loadable modules

One block per module to load. The block name is the module's registered name;
the code is `Kelix.Mod.<Camelized name>` unless an explicit `module = "..."` key
says otherwise. **No module ships inside the core release** — its `.beam` must be
installed in `module_dir`, or the block is logged and skipped.

Every module accepts `call_timeout_ms` (facade call bound, default 5000). See
[modules/](modules/README.md) for the rest; the two provided ones:

```toml
[module.auth_db]                    # docs: modules/auth_db.md
host          = "db.example.com"
port          = 3306
database      = "kamailio"
username      = "kamailio"
password      = "secret"
table         = "subscriber"
user_column   = "username"
domain_column = "domain"
ha1_column    = "ha1"               # ha1 = H(user:realm:pw); ha1b = H(user@domain:realm:pw)
password_hash = "md5"               # md5 | sha256

pool_size          = 4              # DB connections; 1 serialises every REGISTER
connect_timeout_ms = 5000
ssl                = false          # TLS to the database
ssl_ca_cert_file   = ""             # with a CA the server cert is verified; without, it is not
```

> `ha1` vs `ha1b` must match how your UAs authenticate: `ha1` when they send a
> bare username, `ha1b` when they send `user@domain`. Both are supported — the
> subscriber row is always looked up on the bare user.
>
> `password_hash` is **authoritative**: it is the algorithm advertised in the
> challenge (`MD5` / `SHA-256`) and the only one accepted back, because the
> stored HA1 was salted with that hash and no other. A client offering anything
> else is re-challenged.

`[module.registrar]` lives in **`domains.toml`**, not here (see below).

#### `[mediaserver.pool.<name>]` — the MCU pool

Round-robin selection with health-checking; the router injects the chosen server
into each call.

| Key | Type | Meaning |
|---|---|---|
| `module` | string | Adapter: `mendooze`, `mockup`, or a `MediaServer.Behaviour` module |
| `url` | string | Passed to the adapter's `connect/1`, e.g. `http://mcu1:8080` |
| `enabled` | bool (default `true`) | Toggle without a restart (`kelictl mcu <name> on\|off`) |

```toml
[mediaserver.pool.mcu1]
module = "mendooze"
url    = "http://mcu1.example.com:8080"

[mediaserver.pool.mcu2]
module  = "mendooze"
url     = "http://mcu2.example.com:8080"
enabled = false
```

#### `[control_api]` — the REST admin frontal

Absent ⇒ **disabled**. Present ⇒ enabled by default. See
[rest-api.md](rest-api.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | |
| `addr` | IP | `127.0.0.1` | Loopback by default — do not expose it without `mtls` |
| `port` | 1..65535 | `8090` | |
| `auth` | `token` \| `mtls` \| `none` | `token` | |
| `token` | string | — | **Required** for `auth = "token"` |
| `cert` / `key` / `cacert` | path | — | **Required** for `auth = "mtls"`, **forbidden** otherwise |

#### `[metrics]` — Prometheus `/metrics` + `/health`

Absent ⇒ **disabled**. No auth: bind it to loopback and let a local Prometheus
scrape it.

| Key | Type | Default |
|---|---|---|
| `enabled` | bool | `true` |
| `addr` | IP | `127.0.0.1` |
| `port` | 1..65535 | `9095` |

### domains.toml

#### `[[domain]]` — one entry per served domain

| Key | Type | Required | Meaning |
|---|---|---|---|
| `name` | string | **yes** | Nominal domain name. **This is also the digest `realm`** |
| `aliases` | list of strings | no | Other hosts routed to this domain (case-insensitive). A name/alias used twice rejects the file |
| `max_calls` | int > 0 | no | Per-domain concurrent-instance cap (`503` beyond) |

A request is routed by its R-URI host (falling back to the `To` host); no match
⇒ `404`. Then the method selects the **function** — `REGISTER` → `registrar`,
`INVITE` → `calls`, `SUBSCRIBE`/`PUBLISH`/`MESSAGE` → `presence` — and a function
with no block on that domain is **not enabled** ⇒ `405`.

#### `[domain.registrar]` / `[domain.presence]`

Presence of the block = the function is enabled.

| Key | Type | Required | Meaning |
|---|---|---|---|
| `script` | string | **yes** | Scenario script, resolved under `script_dir` (keep the `.exs`). A script may declare `config uses_modules: [:registrar, :auth_db]`, and is then refused at load if one is not loaded |
| `default_expires` | int > 0 | no | Overrides `[module.registrar].default_expires` **for this domain** |
| `min_expires` | int > 0 | no | Overrides `[module.registrar].min_expires` **for this domain** |
| `keepalive_period` | int > 0 | no | *Accepted and validated, but **not applied yet** — server-initiated OPTIONS keepalive towards registered UAs is not implemented (the framework's keepalive is outbound-only).* |

#### `[[domain.call]]` — the dial-plan (`calls`)

Ordered, **first match wins**, on the R-URI user-part. Each rule needs a
`script` plus either a `pattern` or `default = true`; the catch-all must be
**last**. No rule matches ⇒ `404`.

Pattern syntax (Asterisk-style, matching the **whole** user-part):

| Symbol | Matches |
|---|---|
| `X` | one digit `0-9` |
| `Z` | one digit `1-9` |
| `N` | one digit `2-9` |
| `[13-6]` | one character in the set/range |
| `.` | one or more of any character |
| `!` | zero or more of any character |
| anything else | itself, literally |

#### `[module.registrar]`

The usrloc store's own block. It lives here — not in `config.toml` — so it is
hot-reloadable alongside the domains it serves; a stray copy in `config.toml` is
ignored.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `max_contacts_per_aor` | int > 0 | `10` | Beyond it a new binding is refused with `403` |
| `min_expires` | int > 0 | `60` | Shortest registration granted; a shorter request gets `423` + `Min-Expires` |
| `default_expires` | int > 0 | `3600` | Granted when the request asks for no expiry, **and** the ceiling on what is granted |
| `call_timeout_ms` | int > 0 | `5000` | Facade call bound |

Both expiry bounds are per-domain-overridable in `[domain.registrar]` above.

#### A complete example

```toml
# /etc/kelixip/domains.toml
[[domain]]
name    = "example.com"
aliases = ["sip.example.com", "203.0.113.10"]

  [domain.registrar]
  script = "registrar.exs"

  [[domain.call]]
  pattern = "0[1-9]XXXXXXXX"        # French landline/mobile
  script  = "national.exs"

  [[domain.call]]
  default = true                    # catch-all, must be last
  script  = "default_call.exs"

[module.registrar]
max_contacts_per_aor = 5
min_expires          = 60
```

## Verify

```bash
systemctl status kelixip
kelictl status                            # listeners bound, modules loaded, domains version
curl -s http://127.0.0.1:9095/health      # {"status":"ok","live":true,"ready":true}
```

`kelictl status` is the one that tells you whether the install took: it lists the
**bound listeners** and the **modules actually loaded from `module_dir`** — a
`[module.x]` block whose package is missing is logged and skipped, so it shows up
here as an absence, not as an error at the first request.

Next: [running.md](running.md).
