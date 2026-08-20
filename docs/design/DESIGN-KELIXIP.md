# DESIGN-KELIXIP.md — the kelixip application server

The as-built design of **kelixip**, the scriptable SIP application server:
supervision tree, configuration, dispatch, the loadable-module system, the
control layer, observability and packaging — plus the three modules shipped with
it (registrar, auth_db, mcu).

Kelixip is inspired by Kamailio and OpenSIPS, with one difference that decides
almost everything else: **its routing logic is an FSL scenario**, not a
configuration mini-language. It is built on the same stack and framework as the
test tool — [DESIGN-SIPSTACK.md](DESIGN-SIPSTACK.md),
[DESIGN-FRAMEWORK.md](DESIGN-FRAMEWORK.md),
[DESIGN-FSL.md](DESIGN-FSL.md) — and carries no SIP function of its own.

Operating the server — installing, configuring, the CLI and REST surfaces, the
module manuals — is [docs/kelixip/](../kelixip/README.md); building the
packages is [BUILD.md](../../BUILD.md).

---

## 1. The shape of the product

**The core ships no SIP function.** Everything a node does — accepting a
registration, placing a call, mixing a conference — comes from a script and from
loadable modules. A deployment that only runs an MCU loads no registrar, and its
release contains none.

That is not a preference, it is enforced by the build: the provided modules live
in a separate umbrella app (`apps/kelix_modules`) that `apps/kelixip` does **not**
depend on, so `mix release kelixip` cannot pull them in. They are installed as
`.beam` files into `server.module_dir` and loaded per configuration.

```
apps/elixip2      shared stack + FSL + media (library)
apps/elixipp      the test tool                     → escript
apps/kelixip      the server                        → OTP release + kelictl
apps/kelix_modules  registrar · auth_db · mcu       → .beam into module_dir
```

---

## 2. Supervision tree

`Kelix.Application` starts one root supervisor whose child order *is* the design:
registries and the resolver first, then stores, then the router, then the
listeners **last** — a listener must not accept before the router is ready to
route.

```
Kelix.Supervisor (:one_for_one)
├── Kelix.Config              parsed config.toml, read-only after boot
├── Registry.SIP.Transac · Registry.SIPTransport · Registry.SIPDialog
├── SIP.Resolver             DNS defaults
├── SIP.Session.ConfigRegistry   demoted to a primitive the Router configures
├── SIP.Auth.Secret · Kelix.NonceCache      stateless digest nonce (§6)
├── Kelix.ModuleSupervisor   one child per [module.<name>], from module_dir
├── Kelix.ScriptPreflight    validates every script named by domains.toml
├── Kelix.MediaPool          media-server pool, health check, failover
├── Kelix.ScriptRegistry     loaded scenario versions + refcounts
├── Kelix.Domains            hot-reloadable domains.toml (atomic swap)
├── Kelix.Router             stateless dispatch
├── Kelix.InstancePool       quota, instance accounting, drain
├── Kelix.Listener.Supervisor    one child per [[listen]] + a conn supervisor
├── Kelix.Control            the command layer, no transport of its own
├── Kelix.ControlAPI         REST frontal (Bandit/Plug), when enabled
└── Kelix.Metrics            telemetry → Prometheus, /metrics + /health
```

What the tool does imperatively, the server supervises. The stack registries,
started ad-hoc by `bootstrap_stack/0` in a one-shot run, become supervised
children; listeners, whose pids the tool discards, become restartable children
with their per-connection transports under a `DynamicSupervisor`.

**Graceful shutdown** reuses the FSL cooperative-stop contract exactly:
`{:scenario_ctl, :shutdown, :node_shutdown}` is broadcast to every instance, the
node waits for the drain with a deadline, kills the stragglers, then stops. This
is why a script is *required* to have an `on_shutdown` block, checked at load
time, and why the systemd unit's `TimeoutStopSec` sits just above the drain
deadline.

Instances are still `spawn_monitor`ed by `Kelix.InstancePool` rather than
supervised by a `DynamicSupervisor`. The monitor is what accounts for the quota
slot; a supervisor would add observability, and is the one item of this tree not
built.

---

## 3. Configuration

Two TOML files, deliberately split by lifetime:

| File | Holds | Reload |
|---|---|---|
| `config.toml` | node infrastructure: listeners, modules, media-server pool, control API, logging | restart |
| `domains.toml` | the served domains: enabled functions, scripts, dial plans, registrar bounds | **hot**, atomic |

`Kelix.Config` parses and validates the first at boot and pushes what belongs
there into the application env. Paths come from `KELIXIP_CONFIG` /
`KELIXIP_DOMAINS`, read in `runtime.exs`, defaulting to the FHS locations.

A bad or missing file **aborts the boot and says why on stderr** — a release
dying during boot flushes no Logger output, so journald would otherwise show
only "Runtime terminating".

`Kelix.Domains` owns the second and swaps versions atomically, so a reload never
exposes a half-applied routing table. `Kelix.DialPlan` compiles each domain's
rules once, at load, rather than interpreting them per request.

---

## 4. Dispatch

`Kelix.Router` registers itself as the registration, call and presence processing
module in `SIP.Session.ConfigRegistry`, so every out-of-dialog request funnels
through one function:

```
1. domain    match the R-URI host (fallback: To host) against the index → 404
2. function  REGISTER→registrar, INVITE→calls, SUBSCRIBE|PUBLISH|MESSAGE→presence → 405 + Allow
3. script    registrar/presence: the function's script
             calls: the dial plan, first match on the R-URI user part → 404
4. quota     per-domain max_calls, then server max_calls → 503
5. spawn     an instance of that script version, with injected config overrides
```

The Router is otherwise **stateless**: it reads `Kelix.Domains` and
`Kelix.ScriptRegistry` and holds nothing.

Step 5 is what keeps scripts generic: the instance's context is seeded with the
domain (which becomes the auth realm), the resolved expiry bounds and the
selected media-pool handle, so a script never hardcodes the domain it serves.

**There is no global routing script.** Config-driven dispatch picks the script;
runtime-data routing — ported numbers, time of day — lives *in* that script, in
Elixir. Nothing to build, and that is the point of the design.

The factory that spawns instances is shared with the test tool.
`Elixip.ScenarioUAS` (single scenario, single domain) and `Kelix.Router`
(multi-domain, script per rule) play the same accept/reject/spawn/quota role, so
the machinery lives once in **`Kelix.InstancePool`**: quota accounting keyed by
domain, instance monitoring, exit counters, shutdown broadcast. Both call
`SIP.Scenario.Runner.spawn_uas_instance/2`.

---

## 5. Scripts

`Kelix.ScriptRegistry` loads each script as a **versioned module** and refcounts
the instances using it. A reload compiles the new version alongside the old: new
calls take the new one, calls in progress keep the one they started with, and the
old version is dropped when its refcount reaches zero. No call is ever
interrupted by a reload, and no reload waits for the longest call.

`Kelix.ScriptPreflight` is an `:ignore` child that validates every script
`domains.toml` names — it must compile, be a scenario, and declare
`on_shutdown` — and **aborts the boot** if one fails. A server that boots with a
broken script would answer 500 to real traffic; failing at boot is the honest
outcome.

---

## 6. Authentication

Digest with `qop=auth`, realm = the domain. The nonce is the framework's
stateless one ([DESIGN-SIPSTACK.md](DESIGN-SIPSTACK.md#6-authentication));
`Kelix.NonceCache` adds the one piece statelessness cannot give — the `nc`
counter for replay detection — as an ETS table with a TTL equal to the nonce's
max age.

Deciding **whether** to challenge and against which credential store is the
`auth_db` module's business, invoked from the script. Which realm, which identity
the digest is held to, which requests are challengeable at all, and which module
mints, validates and keys the nonce are [DESIGN-AUTH.md](DESIGN-AUTH.md).

---

## 7. The module system

A module is a stateful OTP service **plus** stateless facades a script calls. Like
a Kamailio module it plugs in three ways: **config** (its `[module.<name>]`
block), **REST** (`/modules/<name>/…`), **CLI** (`kelictl <name> <cmd>`).

`Kelix.Module` behaviour: `validate_config/1`, `child_spec/2`, `describe/0`,
optional `reload/2`, plus two optional control callbacks and two optional
reporting ones.

| Piece | Role |
|---|---|
| `Kelix.ModuleSupervisor` | puts `module_dir` on the code path, resolves, validates, registers, starts one child per configured block; an invalid block is logged and skipped |
| `Kelix.ModuleRegistry` | name → `{module, config}`, and facade resolution by **configured name** — the core names no module at compile time |
| `Kelix.Control.Registry` | the control surfaces modules declared, feeding both frontals |
| `Kelix.Module.safe_call/3` | a facade call that answers `{:error, :down}` / `{:error, :timeout}` instead of exiting the script |

**Control surfaces are declared once and derived twice.** A module's
`describe_control/0` returns its commands — name, args, REST
`{method(s), path_template}`, read/write flag, help, and optionally `status`,
`location`, `errors` — and both frontals build themselves from that: the REST
router mounts the routes, `kelictl` generates the sub-commands and their
`--help`. Execution goes to `handle_control/2`, which **never checks auth** —
that is enforced at the frontal boundary, keeping module logic pure.

Path templates may carry `:param` segments, so a module exposes a resource tree
rather than flat verbs. Routes resolve **most-literal-first**, an ambiguous pair
is refused at *registration* time (the module keeps running, without its control
surface) rather than arbitrated per request, and arguments merge
**path < query < body** — a body key colliding with a path parameter is a `400`,
never a silent divergence between the URL and the effect.

> **A release runs the code server in embedded mode.** It never searches the code
> path: `Code.ensure_loaded?/1` answers `{:error, :embedded}` for anything not
> already loaded, and calling an undefined function triggers no implicit load.
> Loading a module installed after boot is therefore an explicit
> `:code.load_file/1` — which is what `kelictl module reload` does, so installing
> a new version of a module is an install plus a reload, never a restart.
>
> The rule bites one level deeper, which the MCU module found: a module of any
> size is spread over several beams, and in embedded mode the first call to a
> companion raises at boot inside `validate_config/1`, so the node never comes
> up. Resolution therefore loads **every beam sharing the module's namespace
> prefix**, from the directory the module's own beam came from, and reload
> refreshes them together — a package installs them together, and reloading only
> the named one would run new code against a stale companion.
>
> Consequence for scripts: a script calling a facade needs that module
> **configured**; the `[module.<name>]` block is what gets its code loaded and
> there is no lazy fallback. Boot warns when a domain enables a function whose
> same-named module is not loaded.

---

## 8. The provided modules

### 8.1 `registrar`

The location service. Per-domain binding store with `save`/`lookup`/`targets`,
built on the message layer's single reading of REGISTER lifetimes
([DESIGN-SIPSTACK.md](DESIGN-SIPSTACK.md) §2.3) and the framework's
`check_register/1` bounds. It handles `received`, flow and `Path`, so a NATed
registration is routable: a stored binding carries the flow (`tp_pid`), which is
what the transport Selector uses to reach a client it could never open a
connection to.

`save/2` answers `:registered` / `:unregistered` — a script must never re-derive
that from `expires == 0`. `targets/2` returns contacts in **q groups**, which is
how "these three in parallel, then that one" reaches the B2BUA forking layer
without the script computing anything.

Its `[module.registrar]` block lives in `domains.toml` rather than
`config.toml`: it is domain-tied and hot-reloadable.

### 8.2 `auth_db`

Credential lookup against MariaDB, exposed as a facade the script calls when it
decides to challenge. Today it authenticates REGISTER; extending it to INVITE
and to other backends (LDAP, HTTP, Diameter) behind an `Auth` behaviour is
designed but not built — see `docs/design/evolution-auth-db.md`; what is built is
[DESIGN-AUTH.md](DESIGN-AUTH.md).

### 8.3 `mcu` — conferencing

The largest module, and the one that exercises everything above: a reduced MCU
driving the Medooze media server over its own XML-RPC interface, with a scenario
per call, an adapter implementing `MediaServer.Behaviour` per leg, and a
node-scoped registry holding the conferences.

It has its own document — **[DESIGN-MCU.md](DESIGN-MCU.md)**.

Three things it proved about the module system, which is why it is worth naming
here: it is what found the embedded-mode companion-beam rule (§7), what drove
the nested-resource control surface (a conference is a resource tree, not a flat
verb list), and what the generic `status/0` and `poll_metrics/0` hooks were built
for.

## 9. Media pool

`Kelix.MediaPool` holds the configured media servers, round-robins across the
healthy ones, health-checks them and fails over. An operator can take one out of
rotation without restarting the node (`kelictl mediaserver`), which is what makes
a media-server upgrade a routine operation.

The pool hands a script its server through the injected context override (§4), so
a script never names one.

**`[mediaserver] video_bitrate` is a section key, not a pool key.** It says what a
video leg is encoded at, and it caps the `b=AS:` this node answers with. Both media
paths read that one node value: the point-to-point adapter through
`:elixip2/MediaServer.Mendooze[:video_bandwidth_kbps]`, conferences as the default of
the `mcu` module's `video_bitrate`. A conference may still state its own, and a
`conference.create` argument overrides that.

Per media server would be the wrong granularity: the pool hands out a server per
call, so a per-entry bitrate would make picture quality depend on which MCU the
round-robin landed on.

---

## 10. Control layer

**Parity by construction: one command layer, two frontals.**

`Kelix.Control` implements every verb — `status`, `monitor`, `registrations`,
`unregister`, `shutdown_scenario`, `reload_script`, `reload_domains`,
`module_reload`, `mediaserver_toggle`, `set_log_level`, `graceful_shutdown`,
`domains`/`domain`, `mediaservers`/`mediaserver` — plus `module_command/3`
routing into a module's `handle_control/2`.

- **`kelictl`** is `Kelix.Control.CLI` plus a release overlay driven by
  `kelixip rpc`. Dispatch is local when the target is this node (so the CLI is
  testable without distribution) and `:rpc.call` otherwise.
- **REST** is a `Plug.Router` on Bandit, one route per verb plus the
  module-contributed ones, each a thin translation onto the same `Kelix.Control`
  function. Authentication is a boundary plug: `token` (Bearer, constant-time
  compare), `mtls` (verified peer certificate, no anonymous), or `none`. The
  endpoint starts only when enabled.

Two read verbs exist because a version number is not an answer: `status` reported
only the snapshot version, so nothing short of reading the file on the server
told an operator which domains are actually served, with which functions,
scripts and dial plan — and the file on disk is not necessarily what the router
loaded. The same reasoning added the media-server listing.

---

## 11. Observability

`Kelix.Metrics` exposes Prometheus metrics and `/health` on the same Bandit
frontal. Dispatch and registrar events are labelled by domain, so a multi-tenant
node is readable per tenant.

Gauges are sampled by **one poller on one tick**: a module exporting
`poll_metrics/0` is sampled on that tick rather than running its own timer, and a
module exporting `status/0` contributes a line to `kelictl status`. The core
names no module in either case — a module exporting neither contributes nothing.

---

## 12. Packaging

The release embeds ERTS, so it is **natively linked**: the build must run on the
target OS. Two package families are produced from one staging tree — RPM for
Alma Linux 9, deb for Ubuntu/Debian — plus a container-based build for either
from any host.

The split follows §1: one **core** package (release, `kelictl`, systemd unit,
`/etc/kelixip` defaults as `%config(noreplace)`) and **one package per module**,
each installing its `.beam` files into `module_dir`. Installing the core gives a
node that boots and does nothing; a deployment adds exactly the modules it wants.

FHS layout, a systemd unit, and configuration that survives an upgrade are the
whole of the operator contract. The build procedures are in
[BUILD.md](../../BUILD.md), the packaging tree in
[packaging/README.md](../../packaging/README.md).

---

## 13. Invariants

1. The core ships no SIP function; the build enforces it, not a convention (§1).
2. Listeners start last, after the router is able to route (§2).
3. A failed configuration or a broken script aborts the boot, loudly (§3, §5).
4. A reload never interrupts a call and never waits for one (§5).
5. The core names no module at compile time; resolution is by configured name
   (§7).
6. A module declares its control surface once; REST and CLI derive from it (§7).
7. A module's beams are loaded — and reloaded — together, companions included
   (§7).
8. A script asks a module what happened (`:registered` / `:unregistered`); it
   never re-derives it from the message (§8.1).
9. Authentication is enforced at the frontal boundary, never inside a module
   (§7, §10).
