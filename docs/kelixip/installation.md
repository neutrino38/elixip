# Installation

## Prerequisites

- **Alma Linux 9** (RPM) or **Ubuntu / Debian** (deb), x86_64 or aarch64. The release
  embeds its own ERTS — no system Erlang/Elixir required.
- A database only if you load [`auth_db`](modules/auth_db.md) (MariaDB/MySQL).

Each package is built for one distribution release: its embedded runtime is native
code, and the dependencies name that release's libraries. An RPM is `.el9`, a deb is
for the Ubuntu/Debian release it was built on.

## Packages

kelixip is shipped as a **core** release plus **one package per module**, so a
deployment installs only what it uses — the core itself implements no SIP function.

| Package | Contents |
|---|---|
| `kelixip` | the server + `kelictl` + the systemd unit + `/etc/kelixip` |
| `kelixip-mod-registrar` | the [registrar](modules/registrar.md) / user-location module |
| `kelixip-mod-auth_db` (RPM)<br>`kelixip-mod-auth-db` (deb) | the [database authentication](modules/auth_db.md) module |
| `kelixip-mod-mcu` | the [conference mixer](modules/mcu.md) — the one module that also needs a **reachable media server** |

```bash
# Alma Linux 9
dnf install kelixip kelixip-mod-registrar kelixip-mod-auth_db kelixip-mod-mcu
rpm -ivh kelixip-*.rpm                     # or, from the built files

# Ubuntu / Debian
apt install kelixip kelixip-mod-registrar kelixip-mod-auth-db kelixip-mod-mcu
apt install ./kelixip_*.deb ./kelixip-mod-registrar_*.deb   # from the built files
```

> Each module package carries its own document under `/usr/share/doc/<package>/`, so
> a host documents what it can actually do: `kelixip-mod-mcu` ships `mcu.md` (the
> block key by key, the control surface) and `mcu_module_guide.md` (operating and
> debugging a conference).

> The module's **registered name is `auth_db`** on both — the config block is
> `[module.auth_db]` everywhere. Only the deb *package* name differs, because a Debian
> package name may not contain an underscore.
>
> From files, prefer `apt install ./file.deb` over `dpkg -i`: apt pulls the library
> dependencies, `dpkg` only reports them missing.

A domain that enables a function whose module is not installed is a **config error
caught at load time** — it is not a runtime surprise. Installing a module later is a
package install plus `kelictl module reload <name>`; no restart.

Building the packages yourself — build-host toolchain included:
[BUILD.md § Building the RPM packages](../../BUILD.md#building-the-rpm-packages-alma-linux-9)
and [§ Building the deb packages](../../BUILD.md#building-the-deb-packages-ubuntu--debian).

## Filesystem layout (FHS, §12)

| Path | Contents |
|---|---|
| `/etc/kelixip/config.toml` | Infrastructure config (kept on upgrade, 0640 `root:kelixip`) |
| `/etc/kelixip/domains.toml` | Domains + dial-plan + registrar block (kept on upgrade) |
| `/etc/kelixip/tls/` | Listener certificates (0750 `root:kelixip`) |
| `/etc/sysconfig/kelixip` (RPM)<br>`/etc/default/kelixip` (deb) | Node name, cookie and the two TOML paths (kept on upgrade) |
| `/usr/share/kelixip/` | Scenario scripts (`script_dir`). The core ships the ones it can run on its own; `mcu.exs` and `mcu_adhoc.exs` come with `kelixip-mod-mcu`, since every conference verb they call is that module's |
| `/usr/lib/kelixip/` | The release itself (embedded ERTS) |
| `/usr/lib/kelixip/modules/` | Loadable modules (`module_dir`, **root-owned**) |
| `/usr/sbin/kelictl` | Admin CLI (a command inside the release) |
| `/usr/sbin/kelixip` | The release's own control script (`start`, `rpc`, …) |
| `/usr/share/bash-completion/completions/kelictl` | Shell completion for the CLI ([administration](administration.md#shell-completion)); inert without the `bash-completion` package |
| `/var/lib/kelixip/`, `/var/log/kelixip/` | Mutable state; logs when stdout is redirected |

`module_dir` is root-owned and **not writable by the service** on purpose: loading
a `.beam` is executing code.

## System user & service

The package creates an unprivileged `kelixip` system user and a systemd unit; the
service runs as that user, with `CAP_NET_BIND_SERVICE` as its only privilege (so a
`[[listen]]` entry may ask for port 443).

The install **enables the unit but does not start it**: the shipped `config.toml` is a
template that binds 5060 and serves no domain. Go through it first, then:

```bash
systemctl enable --now kelixip
systemctl status kelixip
```

Everything an admin needs to override lives in the **environment file** —
`/etc/sysconfig/kelixip` on Alma Linux, `/etc/default/kelixip` on Ubuntu/Debian, and
never in the unit, which the package replaces on upgrade:

| Variable | Default | Meaning |
|---|---|---|
| `RELEASE_NODE` | `kelixip@127.0.0.1` | Erlang node name. **Must match `server.node_name`** in config.toml |
| `KELIXIP_CONFIG` / `KELIXIP_DOMAINS` | the two FHS paths | Where the TOML files are read from |
| `RELEASE_COOKIE` | *(unset)* | Only to share one cookie across a cluster — see below |

`kelictl` reads the same file, so it targets the node the service actually runs;
changing `RELEASE_NODE` in one place is enough.

> **The distribution cookie is generated per installation.** It is the credential
> `kelictl` authenticates with, so no fixed cookie ships in the package: the
> post-install script generates `/usr/lib/kelixip/releases/COOKIE` from `/dev/urandom`
> (0640 `root:kelixip`), keeps it across upgrades and removes it on erase.

### SELinux (Alma Linux)

Alma Linux 9 runs SELinux **Enforcing**, and the release lives under `/usr/lib`,
where every file is labelled `lib_t`. That label is the entry point of no domain:
systemd execs `bin/kelixip` and the BEAM stays in systemd's own `init_t` domain,
where the Erlang distribution may not bind its listen socket. The node then exits
during boot:

```
Protocol 'inet_tcp': register/listen error: eacces
```

The post-install script labels the two launcher directories `bin_t`, which is what
`init_t` transitions to `unconfined_service_t` from (it needs
`policycoreutils-python-utils`, a package dependency):

```bash
semanage fcontext -a -t bin_t "/usr/lib/kelixip/bin(/.*)?"
semanage fcontext -a -t bin_t "/usr/lib/kelixip/erts-[^/]+/bin(/.*)?"
restorecon -R /usr/lib/kelixip/bin /usr/lib/kelixip/erts-*/bin
```

Those two directories only — the ERTS shared objects stay `lib_t`. Check the domain
the service actually got:

```bash
ps -eZ | grep beam.smp        # expect unconfined_service_t
```

`unconfined_service_t` is unrestricted, so **nothing else needs an SELinux rule**:
what the service may read and write is decided by the POSIX modes of the layout
table above — the scenario scripts (0644), the logs and the state directory (0750
`kelixip:kelixip`), the TOML files and the environment file (`root:kelixip`, group
readable), the cookie (0640 `root:kelixip`). `kelictl` needs no rule of its own
(see [administration](administration.md#administration-with-kelictl)).

A host that is `Permissive` or has SELinux disabled needs none of this. The
labelling is applied anyway, and costs nothing.

### Upgrades

`config.toml`, `domains.toml` and the environment file are **kept**: your version
survives the upgrade and the packaged one lands next to it — as `*.rpmnew` on the RPM
(`%config(noreplace)`), as `*.dpkg-dist` on the deb (a `conffile`; an interactive
`dpkg` may ask instead). Worth diffing either way, since new keys show up there first.
The unit is restarted by the upgrade, which drains in-progress scenarios first.

Removing the package stops the service and drops the generated cookie. On the deb, a
plain `apt remove` keeps `/var/lib/kelixip` and `/var/log/kelixip`; `apt purge` removes
them, along with the configuration. The `kelixip` system user is left in place on
purpose — files elsewhere may still belong to it.

## Configuration

kelixip reads **two TOML files**, deliberately split by lifecycle:

| File | Holds | Reload |
|---|---|---|
| `config.toml` | Infrastructure: `[server]`, `[log]`, listeners, media pool, most `[module.*]` blocks, control API, metrics | **Restart only** |
| `domains.toml` | The served domains, their dial-plan and the `[module.registrar]` block | **Hot** — `kelictl domain reload-all` (atomic: one bad value and the whole reload is rejected, the running config untouched) |

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
| `user_agent` | string | `Kelixip/1.5.0` | `User-Agent` / `Server` header value |
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
| `addr` | IP address | no (`0.0.0.0`) | Bind address, IPv4 or IPv6; it gives the listener its family. `0.0.0.0` binds every IPv4 interface; the IPv6 wildcard (`::`) is refused |
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
> The service reads `cert` and `key` as the unprivileged `kelixip` user, so a key
> installed 0600 `root:root` aborts that boot. Give the group the read right:
> `chown root:kelixip key.pem && chmod 0640 key.pem`. `/etc/kelixip/tls/` is
> already 0750 `root:kelixip` for that purpose.
>
> UDP is **one socket per node** (the framework's single bidirectional UDP
> transport): extra `udp` entries are ignored with a warning. An explicit `addr`
> binds that address and is the one advertised in Via/Contact; `0.0.0.0` listens
> on every IPv4 interface and advertises the first local IPv4 address.
>
> An IPv6 listener names an explicit address:
>
> ```toml
> [[listen]]
> proto = "udp"
> addr  = "2001:db8::1"
> port  = 5060
> ```
>
> One family per node for now, and it is the `udp` block that states it: an
> outbound leg resolves a name in the family of that block's `addr`. So an IPv6
> node names an IPv6 address there, and a node whose only IPv6 listener is tcp,
> tls or wss still dials IPv4 first.

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

#### `[mediaserver]` — the node's media settings

| Key | Type | Default | Meaning |
|---|---|---|---|
| `video_bitrate` | integer > 0 | `1500` | Video bitrate in kbps: what a video leg is encoded at, and the cap on the `b=AS:` this node answers with. The offered value wins when it is lower |

One bitrate for both media paths. A point-to-point call and a conference encode
video the same way, so the value is stated once here rather than per media server:
every pool entry gets it, and `[module.mcu] video_bitrate` overrides it for
conferences only.

```toml
[mediaserver]
video_bitrate = 2500
```

#### `[mediaserver.pool.<name>]` — the media servers

**The single place a media server is declared.** Point-to-point calls get one
per call (round-robin over the healthy, enabled entries; the router injects the
chosen one), and the `mcu` module opens one control channel per `mendooze` entry
and picks one per conference — a conference then stays on it for its life.

A malformed entry **aborts the boot**: a media server that silently failed to
load is a node that answers `503` to every call.

| Key | Type | Meaning |
|---|---|---|
| `module` | string, required | Adapter: `mendooze`, `mockup`, or a `MediaServer.Behaviour` module. Only `mendooze` entries are usable for conferences |
| `url` | string, required | Passed to the adapter's `connect/1`, e.g. `http://mcu1:8080`. An IPv6 address goes **in brackets**: `http://[fd00::12]:8080` |
| `enabled` | bool (default `true`) | Toggle without a restart (`kelictl mediaserver enable\|disable <name>`; `kelictl mediaserver list` shows the pool). Disabling stops **new** calls and conferences landing there; live ones stay |

> No media address here. The address a media server announces in the SDP (`c=`
> line and ICE candidates) is the server's own setting — `mediaserver --public-ip`,
> **mandatory behind a NAT** — and it reports it to kelixip on each
> `StartReceiving`. A media server too old to report it gets its calls refused
> with `500` rather than answered with a guessed address.

**IPv6.** Two facts about the media server, both of which bite at boot rather
than during a call:

- a server whose only public address is IPv6 needs `--default-profile publicv6`.
  The historical default is `publicv4`, and a default profile that is
  unavailable makes the media server refuse to start — deliberately, with the
  reason on stdout;
- `--internal-ip` restricts the XML-RPC control interface to the internal
  address, so the `url` above must then name that address rather than a public
  one or a loopback. With both an internal v4 and an internal v6, that interface
  listens on the **v4** one.

Without `--internal-ip` the control interface answers both families on one
socket, so nothing needs configuring for a v4 and a v6 controller to reach the
same server. A conference then asks for the profile matching each caller's own
family, per leg, and a call whose family the server does not carry is refused
rather than answered with an unreachable address.

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
