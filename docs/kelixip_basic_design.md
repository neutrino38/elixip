# Kelixip — Basic scope, detailed design

> Companion to [`kelixip_basic.md`](kelixip_basic.md) (the requirements / locked
> decisions). This document is the **implementation design**: OTP structure,
> module map, data structures, how each piece plugs into the existing elixip
> framework, new dependencies, and a phased delivery plan.
>
> Scope = **basic** (registrar + server infrastructure). `calls`/`presence`/HA
> are designed at the interface level only and flagged *roadmap*.
>
> Status: **design**. Section numbers mirror `kelixip_basic.md` where useful.

## Table of contents

1. [Starting point — what exists vs what is missing](#1-starting-point)
2. [OTP application & supervision tree](#2-otp-application--supervision-tree)
3. [Configuration layer (TOML)](#3-configuration-layer-toml)
4. [Dispatch: domain → function → script](#4-dispatch-domain--function--script)
5. [Script registry & versioned reload](#5-script-registry--versioned-reload)
6. [Registrar & usrloc store](#6-registrar--usrloc-store)
7. [Authentication: stateless nonce + qop](#7-authentication-stateless-nonce--qop)
8. [Loadable modules (.beam)](#8-loadable-modules-beam)
9. [Media server pool](#9-media-server-pool)
10. [Control layer, CLI & REST API](#10-control-layer-cli--rest-api)
11. [Observability: telemetry, metrics, health](#11-observability)
12. [Packaging: OTP release & systemd](#12-packaging)
13. [New dependencies](#13-new-dependencies)
14. [Migration & compatibility work](#14-migration--compatibility-work)
15. [Phased delivery plan](#15-phased-delivery-plan)
16. [Open questions](#16-open-questions)

---

## 1. Starting point

The elixip framework already provides everything below (kelixip *reuses* it, it
does not reimplement it):

| Layer | Reused as-is |
|---|---|
| Transports | `SIP.Transport.{UDP,TCP,TLS,WSS}` + `{TCP,TLS,WSS}Listener`, `Depack`, `Selector` |
| Transaction | `SIP.Transac` (ICT/IST/NICT/NIST), `SIP.Trans.Timer` |
| Dialog | `SIP.Dialog` / `SIP.DialogImpl`, `Registry.SIPDialog` |
| Session/DSL | `SIP.Scenario` + `SIP.Scenario.Runner`, `SIP.Session.*`, cooperative shutdown |
| UAS factory | `Elixip.ScenarioUAS` (quota 503, domain 604), `spawn_uas_instance/2` |
| Auth primitives | `SIP.Auth` (digest, HA1), `SIP.Msg.Ops.check_authrequest/3` |
| Media | `MediaServer.Behaviour`, `Mendooze`, `Mockup` |
| External config | `SIP.Scenario.ExternalConfig` (JSON) |

What is **missing** and must be built for kelixip basic (this is the real work):

1. **No OTP `Application` / supervision tree.** The escript bootstraps
   imperatively (`Runner.bootstrap_stack/0`, unsupervised listeners). A
   systemd-managed release needs a real supervision tree. **§2.**
2. **No declarative config.** Everything is `:elixip2` app env + CLI flags.
   TOML config + hot reload. **§3.**
3. **No multi-domain dispatch.** `SIP.Session.ConfigRegistry` holds a *single*
   registration/call/presence module. Kelixip needs domain→function→script
   routing with a dial-plan. **§4.**
4. **No script versioning.** Scenarios are loaded once. Kelixip needs versioned
   hot reload with ref-counting + the load-time contract checks. **§5.**
5. **No usrloc.** Registrations are ephemeral dialog processes keyed on
   `{fromtag, callid, totag}` — there is *no AOR-keyed location store*. **§6.**
6. **Weak/stateful auth.** `SIP.Auth.generate_nonce` is time-derived without a
   secret; the nonce is stateful per-dialog (`SIP.DialogImpl.Nonce`, 30 s); no
   `qop`. Replace with a stateless HMAC nonce + `qop=auth`. **§7.**
7. **No loadable module system, no media pool, no control layer, no metrics, no
   release packaging.** **§8–§12.**

kelixip is delivered as a **new top namespace `Kelix.*`** layered on top of
`SIP.*` / `MediaServer.*`, plus a small number of surgical changes inside the
framework (nonce, `qop`, connected-transport response routing). The `elixipp`
test tool keeps working unchanged (it does not start the `Kelix.Application`).

---

## 2. OTP application & supervision tree

### 2.1 Root application

`Kelix.Application` (`use Application`) lives in the **`apps/kelixip`** app
(umbrella, §12.0) with `mod: {Kelix.Application, []}` in that app's `mix.exs` — so
it starts only for the kelixip server. The shared **`apps/elixip`** library has no
`Application` callback, so `elixipp`/`mix scenario`/tests keep their imperative
bootstrap (`Runner.bootstrap_stack/0`). `Application.start/2` reads `--config`
(the TOML path) from an env var set by the boot script / systemd unit.

```
Kelix.Application  (use Application)
└── Kelix.Supervisor            (:one_for_one, root)
    ├── Kelix.Config             — GenServer: parsed config.toml (read-only after boot)
    ├── Registry.SIP.Transac       ┐  (the 3 stack registries, today started
    ├── Registry.SIPTransport      │   ad-hoc by bootstrap_stack/0 — now supervised)
    ├── Registry.SIPDialog         ┘
    ├── SIP.Resolver               — DNS defaults (was inside Selector.start/0)
    ├── SIP.Session.ConfigRegistry — kept, but demoted to a low-level primitive
    │                                 the Router configures (see §4)
    ├── Kelix.Secret             — Agent: ephemeral server_secret (boot-random)  §7
    ├── Kelix.NonceCache         — ETS owner: nonce→nc, TTL=max_age             §7
    ├── Kelix.ModuleSupervisor   — :one_for_one, loadable .beam from module_dir   §8
    │     └── (one child per [module.<name>] block — NONE are bundled in the core;
    │          e.g. Kelix.Mod.Registrar §6 / Kelix.Mod.AuthDb §7 / Kelix.Mod.RadiusBilling,
    │          each loaded only if configured — an MCU-only product loads none)
    ├── Kelix.MediaPool          — GenServer: MCU pool, health-check, failover   §9
    ├── Kelix.ScriptRegistry     — GenServer: loaded scenario versions + refcount §5
    ├── Kelix.Domains            — GenServer: hot-reloadable domains.toml (atomic) §4
    ├── Kelix.Router             — stateless dispatch; reads Domains + ScriptRegistry §4
    ├── Kelix.InstanceSupervisor — DynamicSupervisor: one child per scenario instance
    ├── Kelix.Listener.Supervisor
    │   ├── Kelix.Listener.ConnSupervisor  — DynamicSupervisor (per-connection transports)
    │   └── {UDP|TCP|TLS|WSS} listeners       — one child per [[listen]]
    ├── Kelix.Control            — the command layer (§10), no transport of its own
    ├── Kelix.ControlAPI         — REST frontal (Plug/Bandit), [control_api]     §10
    └── Kelix.Metrics            — telemetry → Prometheus, /metrics + /health     §11
```

Design choices:

- **Registries & ConfigRegistry become supervised children** instead of the
  current idempotent `start_link` inside `Runner.bootstrap_stack/0`. Boot order
  matters: registries and `SIP.Resolver` first, then stores, then the router,
  then listeners last (a listener must not accept before the router is ready).
- **Listeners become supervised.** Today `Elixipp.CLI.start_listeners/1` does
  `GenServer.start` and discards the pid. Kelixip introduces
  `Kelix.Listener.Supervisor` with one child spec per `[[listen]]` entry and a
  `DynamicSupervisor` for the per-connection transports the acceptors spawn
  (the acceptor `Task` stays inside each listener, unchanged). A crashing
  listener is restarted; existing connections are independent children.
- **Instances become supervised.** `spawn_uas_instance/2` currently does
  `spawn_monitor` of a bare process. For a long-running server we route it under
  `Kelix.InstanceSupervisor` (a `DynamicSupervisor`, `:temporary` children) so
  instances are observable, countable (metrics), and drainable
  (`graceful_shutdown`). The factory still `Process.monitor`s each child to free
  its quota slot — the monitor and the supervisor are complementary (monitor =
  slot accounting, supervisor = lifecycle/observability). `spawn_uas_instance/2`
  gains an option to start under a supervisor instead of `spawn_monitor`.

### 2.2 Graceful shutdown

systemd `stop` → `Kelix.Control.graceful_shutdown/1` (also the CLI/REST verb):
broadcast `{:scenario_ctl, :shutdown, :node_shutdown}` to every instance under
`Kelix.InstanceSupervisor`, wait for drain with a deadline, `Process.exit/2`
kill stragglers, then `System.stop/0`. This is exactly the existing cooperative
shutdown contract (§9.2 of the spec) — hence the load-time requirement that
every script has an `on_shutdown` block (§5.3). The systemd unit sets
`TimeoutStopSec` slightly above the drain deadline.

---

## 3. Configuration layer (TOML)

Two files, two lifecycles (spec §3). Parsed with a **pure-Elixir TOML parser**
(`toml` hex package; no NIF, bundles in a release — see §13).

### 3.1 `Kelix.Config` — infra (`config.toml`)

Loaded once at boot, held read-only in a GenServer. Responsibilities:

1. Parse + **validate** the whole file; any error aborts boot with a clear
   message (systemd sees a failed start — fail fast, never half-configured).
2. Translate infra keys into the `:elixip2` app env the framework already reads,
   so the lower layers need no change:

   | TOML | maps to |
   |---|---|
   | `server.user_agent` | `:elixip2/:useragent` |
   | `[[listen]]` entries | listener child specs (§2.1); TLS/WSS `cert`/`key` → per-listener opts (today `:tls_certfile`/`:tls_keyfile` are global — see below) |
   | `log.*` | Logger backend config (syslog vs stdout) |
   | `server.max_calls` | server-wide quota gate in the Router/factory |
   | `mediaserver.pool.*` | `Kelix.MediaPool` children (§9) |
   | `module.*` | `Kelix.ModuleSupervisor` children (§8) |
   | `control_api.*`, `metrics.*` | `Kelix.ControlAPI` / `Kelix.Metrics` |

3. **Per-listener certificates.** The framework listeners today read *global*
   `:tls_certfile`/`:tls_keyfile`. The spec wants `cert`/`key` per `[[listen]]`
   (§3.4). Small framework change: `TLSListener`/`WSSListener` `init/1` already
   accept an opts keyword (the 3rd tuple element) — thread `certfile`/`keyfile`
   through it, falling back to the global config for back-compat.

Logging: `log.target = "syslog"` selects a syslog backend
(`syslog` / `logger_syslog` dep, or the erlang `:os` `logger` handler);
`"stdout"` (or `--stdout`) keeps the console backend. `log.level` sets the
handler level.

### 3.2 `Kelix.Domains` — domains + dial-plan (`domains.toml`)

Hot-reloadable (spec §3.2, §9.2). Held in a GenServer behind an **atomic swap**:

```elixir
%Kelix.Domains{
  version: pos_integer,          # bumped on each successful reload
  domains: [%Kelix.Domain{}],  # order preserved (TOML array-of-tables)
  index: %{binary => %Kelix.Domain{}}  # name + each alias → domain, for O(1) lookup
}

%Kelix.Domain{
  name: binary,
  aliases: [binary],
  max_calls: pos_integer | nil,
  registrar: %{script: binary, default_expires: .., min_expires: .., keepalive_period: ..} | nil,
  presence:  %{script: binary} | nil,                                  # future
  match_rules: [%Kelix.MatchRule{}]  # calls function; [] if calls disabled  # future
}

%Kelix.matchRule{
  matcher: (binary -> boolean),  # compiled from `pattern` (§3.3) or `default: true`
  raw: binary,                   # the original pattern text, for `status`/logs
  script: binary,
  default?: boolean
}
```

**Reload is atomic / all-or-nothing** (spec §9.2): parse the whole file into a
new `%Kelix.Domains{}` off to the side — including compiling every dial-plan
pattern **and running the §5.3 load-time contract check on every referenced
script** — and only if the entire structure validates do we swap it in
(`:sys.replace_state`-style atomic assign). One bad element ⇒ reject, current
config untouched, error returned to the caller. Reads (`Kelix.Router`) always
see one consistent version.

### 3.3 Match plan pattern compiler (`Kelix.DialPlan`)

Asterisk extension patterns (spec §3.3) compiled **once at load** into a matcher.
Two viable implementations; the design picks **(b)**:

- (a) translate to a regex — concise but `.`/`!` semantics and `[...]` ranges
  need careful escaping.
- (b) a small hand-written NFA/char-walker — `X`→`[0-9]`, `Z`→`[1-9]`,
  `N`→`[2-9]`, `[set]`, literal, `.`→one-or-more-any (greedy, must reach end),
  `!`→zero-or-more-any. Predictable, unit-testable per symbol, no regex-escaping
  footguns. First-match-wins is just `Enum.find/2` over the ordered rule list;
  `default: true` is the catch-all (validated: at most one, last). No match and
  no catch-all ⇒ `404` (spec §3.3).

`regex = "..."` per rule is designed as an escape hatch but **out of basic
scope** (flagged, not implemented).

---

## 4. Dispatch: domain → function → script

The heart of kelixip and the main extension of the existing engine. Spec §2.1
routes an out-of-dialog request in three steps. Today
`SIP.DialogImpl.process_incoming_request/3` funnels every inbound request to the
*single* module held in `SIP.Session.ConfigRegistry`. Kelixip inserts a
**domain-aware router** in that seam.

### 4.1 `Kelix.Router`

Configured (once, at boot) as the registration **and** call **and** presence
processing module in `SIP.Session.ConfigRegistry` — so `internal_dispatch/4`
calls into the Router regardless of method. The Router is otherwise stateless;
it reads `Kelix.Domains` (current version) and `Kelix.ScriptRegistry`.

```
on_new_registration/3 ─┐
on_new_call/3          ├─► Kelix.Router.route(method, dialog_id, req, transaction_id)
on_new_subscribe/3 ────┘        │
                                ├─ 1. domain   = match_domain(req)      -> 404 if none
                                ├─ 2. function = function_for(method)   -> 405 if not enabled
                                ├─ 3. script   = pick_script(domain, function, req)
                                │        registrar/presence -> the function's script
                                │        calls -> DialPlan first-match -> 404 if none
                                ├─ 4. quota: per-domain max_calls, then server max_calls -> 503
                                └─ 5. spawn instance of `script` (versioned, §5), reply {:accept, pid}
```

- **Step 1 — domain.** Compare the R-URI host (fallback `To` host) against the
  `index` map (name + aliases), lowercased. Miss ⇒ `{:reject, 404, "Not Found"}`.
- **Step 2 — function.** `REGISTER→registrar`, `INVITE→calls`,
  `SUBSCRIBE|PUBLISH|MESSAGE→presence`. Block absent on the domain ⇒
  `{:reject, 405, "Method Not Allowed"}` (with an `Allow` header built from the
  enabled functions).
- **Step 3 — script.** For registrar/presence: the function's `script`. For
  calls: run the dial-plan against the R-URI user-part, first match wins, else
  `404`.
- **Step 4 — quota.** Per-domain `max_calls` then server `max_calls` (503). This
  supersedes the single flat quota currently in `Elixip.ScenarioUAS`.
- **Step 5 — spawn.** Ask `Kelix.ScriptRegistry` for the current version's
  module, spawn under `Kelix.InstanceSupervisor` via `spawn_uas_instance/2`
  with `dialog_pid`/`parent_pid`/`inbound_request`, plus **injected config
  overrides**: the domain name (→ auth realm §7), the resolved
  `default_expires`/`min_expires`, and the selected media-pool handle (§9). The
  instance's `%SIP.Context{}` therefore carries its domain — the script no longer
  hardcodes it (this is the migration in §14).

### 4.2 Relationship to `Elixip.ScenarioUAS`

`Elixip.ScenarioUAS` (the `elixipp` factory) and `Kelix.Router` play the same
role — accept/reject + spawn + quota — but the factory is *single-scenario,
single-domain* and the Router is *multi-domain, script-per-rule*. Rather than
fork, the design **extracts the shared machinery into `Kelix.InstancePool`**
(decided 2026-07-26): quota accounting, instance monitoring,
`{:scenario_exit,…}` counters, and cooperative-shutdown broadcast. Both
`Elixip.ScenarioUAS` (elixipp) and `Kelix.Router` (kelixip) use it; both
ultimately call `SIP.Scenario.Runner.spawn_uas_instance/2`.
**Per-domain quota lives in the pool, keyed by domain** — the Router asks the
pool for a slot under `(domain, function)` (checking per-domain `max_calls` then
server `max_calls`); `elixipp` uses a single unnamed bucket. DRY, consistent with
the "additive, no fork" guiding rule (§14).

> **No global routing script (spec §2.2).** The Router is pure config-driven
> dispatch. Runtime-data routing (ported number, time-of-day) lives *in the
> selected script* in Elixir, not in a mini-language — nothing to build here,
> it is a property of the design.

---

## 5. Script registry & versioned reload

### 5.1 `Kelix.ScriptRegistry`

A GenServer owning the mapping *script path → loaded versions*:

```elixir
%{
  "registrar-example.com.exs" => %{
    current: 7,                       # version handed to new instances
    versions: %{
      7 => %{module: RegistrarExampleV7, refcount: 12},
      6 => %{module: RegistrarExampleV6, refcount: 1}   # draining; unloaded at 0
    }
  }
}
```

- **Load** compiles the `.exs` (`SIP.Scenario.Loader.load_file!/1`) into a
  version-suffixed module name (or keeps the compiled module and tags it with a
  version integer in the registry — the module name from `Code.compile_file` is
  fixed, so the registry maps *path+version → the BEAM module* and increments a
  version counter; concurrent versions coexist because Elixir lets us
  recompile-and-purge selectively, or we rename via `Module.concat` at compile).
- **Contract check at load (§5.3)** runs here, before a version is published.
- **`current`** is what `Kelix.Router` spawns. Existing instances keep the
  version they started on (they already hold their `module` in the FSM context).
- **Refcount**: incremented when the Router spawns an instance of a version,
  decremented on `{:scenario_exit,…}` / `:DOWN`. When an old version hits 0 it is
  purged (`:code.purge`). No in-flight state migration (spec §9.2).

### 5.2 Reload commands

- `reload_script name…` — recompile → contract-check → publish as new `current`.
  In-flight instances unaffected; new ones get the new version; old versions
  drain and unload. (spec §9.3)
- `reload_script --notify name…` — same, **plus** send
  `{:scenario_ctl, :reloaded, version}` to in-flight instances of that script.
  This is a **new verb on the existing `:scenario_ctl` channel** — a long-lived
  `calls` script can choose to finish and recycle onto the new version; a
  registrar ignores it. The DSL auto-injects a no-op clause for `:reloaded`
  (like it does for `:shutdown`) so scripts that don't handle it are unaffected.
- `reload_domains` — atomic `domains.toml` reload (§3.2). Validates every
  referenced script through `ScriptRegistry` (contract check) as part of the
  all-or-nothing swap.

### 5.3 Load-time contract (mandatory, spec §9.2)

kelixip **refuses** a script (and logs a clear error) unless **both** hold:

1. `function_exported?(mod, :__scenario_type__, 0)` — *"… is not a valid kelixip
   scenario"*.
2. `function_exported?(mod, :__state___shutdown__, 1)` — i.e. it has an
   `on_shutdown` block — *"… does not handle cooperative shutdown (missing
   `on_shutdown`): rejected"*.

Rationale (spec): elixip makes every scenario shutdown-aware *by default*, but
that default is **abrupt** (terminates `:aborted`, no BYE, no media release). In
production kelixip forbids the default: every served script must prove it drains
cleanly. A registrar can satisfy it in one line
(`on_shutdown do scenario_aborted("shutdown") end`); a `calls` script puts BYE +
media release there. Applied uniformly to registrar/presence/calls, at boot
**and** at every reload.

This is a pure check on already-existing DSL constructs — no DSL change needed.

---

## 6. Registrar module (`Kelix.Mod.Registrar`) & usrloc

There is **no AOR-keyed location store today** — registrations are ephemeral
dialog processes. Kelixip adds a real usrloc (spec §12), *in memory* (basic
scope explicitly excludes persistence/HA).

Per the spec (§12.2) the registrar is a **loadable module** (`registrar.beam`,
`Kelix.Mod.Registrar`) — **not compiled into the core release** (decided
2026-07-26): it is a `.beam` dropped in `module_dir` and loaded per config, like
any other module (§8.3). The core kelixip release is **function-agnostic** — a
kelixip-based product that is, say, only an MCU does not load the registrar at
all. It is built on the `Kelix.Module` behaviour (§8) and started under
`Kelix.ModuleSupervisor` (Kamailio equivalent: `registrar` + `usrloc`). Its
facade is imported by the registrar
script (`import Kelix.Mod.Registrar`). It builds on the **Dialogue layer** and
`SIP.Session.Registrar`; **expiry is handled in the dialogue layer** (not a
bespoke timer here).

### 6.1 Storage — strong per-domain separation

> This is the storage note the spec (§12.2) explicitly marks *"à déplacer dans
> kelixip_basic_design.md"*.

Domains must be strongly separated — so **one ETS table per domain** (decided
2026-07-26), not a single shared table. `Kelix.Mod.Registrar` owns a small
top-level index `%{domain :: binary => tid}` and one ETS table per served domain:

```elixir
# per-domain ETS table (owned by Kelix.Mod.Registrar), key = aor
#   aor        :: binary  = user-part of the REGISTER `To` header (RFC 3261)
#   value      :: [contact_info]
# top-level:  %{ domain => :ets.tid }   — a domain's table is created when the
#                                          domain is added, dropped when removed
```

Strong isolation: a domain's bindings live in their own table (created/dropped
with the domain on `reload_domains`), no cross-domain key space, and a domain can
be flushed by dropping its table. Per-binding purge stays event-driven via a
**monitor on the dialog pid** (transport drop / dialog death → remove the
contact, emit `:disconnected`/`:expired`). Enumerate a domain for `kelictl regs`
by scanning its table; `regs` with no domain iterates the index.

Module parameter — from its **`[module.registrar]`** block, which (unlike other
modules' blocks in `config.toml`) lives in **`domains.toml`** so it is
hot-reloadable alongside the domains it serves (decided 2026-07-26): the
`Kelix.ModuleSupervisor` reads/reconfigures the registrar module from
`domains.toml` on `reload_domains`. Per-domain expiry bounds
(`default_expires`/`min_expires`) stay in `[domain.registrar]` (function
activation), distinct from the module param below.

Each `contact_info` stores (spec §12.2):

```elixir
%Kelix.Mod.Registrar.Contact{
  domain:     binary,
  contact:    %SIP.Uri{},        # the Contact SIP URI exactly as in the REGISTER
  received:   {proto, ip, port}, # REAL transport + source addr/port of the REGISTER
  dialog_pid: pid,               # the dialog process backing this registration
  info:       term | nil,        # arbitrary scenario-supplied data (save/3 arg)
  expires_at: DateTime.t()
}
```

`received` is the **real source** (not the announced Contact — a NATed
UA/browser puts a private, unusable address there, spec §12.1). Whether the
real transport/addr is read off the REGISTER message or off the dialog is an
open design point (spec §12.2 note) — see §6.4.

`[module.registrar]` param: **`max_contacts_per_aor`**.

### 6.2 Facade API — the four exported functions

```elixir
save(req, domain, info \\ nil) :: {:ok, granted} | {:error, {code, reason}}
```

Takes a REGISTER `req`, the resolved `domain`, and optional scenario `info`.
Extracts the contact(s), validates `Expires` against the `[domain.registrar]`
bounds (`default_expires`/`min_expires`), performs the register **or** unregister
(all contacts `expires=0`), and stores the bindings. It **does not compose the
SIP response**: it returns `{:ok, granted}` where `granted` carries the contacts
and expires **actually granted** (after clamp). The script feeds `granted` to
`SIP.Session.Registrar.accept_registration(req, dialog_pid, granted)`, which
merely echoes what was stored — so the `200 OK` matches the store *by
construction*, with the expiry bounds applied in **one place** (`save`), never
re-derived in the helper (a refactor of today's `accept_registration`, which
re-runs `check_register`/`adjust`). On error → `{:error, {code, reason}}` and the
script calls `reject_registration`. `save/3` subscribes to the dialog's events to
catch the unregister and the **transport drop** — on a **connected transport**
(WSS/TCP/TLS) a connection loss **invalidates** the registration.

```elixir
lookup(req) :: {:ok, [req]} | :notfound | {:error, reason}
```

Takes any SIP request to relay to a registered UA. Extracts the R-URI user-part
as the AOR to reach and the R-URI domain (aliases folded to the domain's nominal
`name`). Returns a list of **rewritten requests**, one per registered contact of
the AOR — each a copy of the input with its R-URI **replaced by exactly the
stored Contact** and `destip`/`destport`/`destproto` filled from `received`.
No contact ⇒ `:notfound`; error ⇒ `{:error, reason}`.

> **Routing contract (spec §12.2 note).** Passing a `lookup/1` R-URI to
> `SIP.Transport.Selector.select_transport/1` must resolve to **exactly** the
> transport usable to reach the UA — crucial for connected transports
> (TCP/TLS/WSS), whose clients MUST keep a permanent connection to the registrar.
> The rewritten R-URI carries the stored flow (`tp_pid`) **and** the resolved
> destination (`destip`/`destport`/`destproto`); `select_transport/1` must honor
> them instead of re-resolving — see §6.4 (this needs a real change; the Selector
> ignores a pre-set `tp_pid` today).

```elixir
subscribe_register_event(uri, pid)     # uri :: %SIP.Uri{} = aor@domain
unsubscribe_register_event(uri, pid)
```

Pub/sub on an `aor@domain` (may be **not yet registered**). The subscriber `pid`
receives:

```elixir
{:registrar, :registered,   "aor@domain"}
{:registrar, :unregistered, "aor@domain"}
{:registrar, :expired,      "aor@domain"}
{:registrar, :disconnected, "aor@domain"}
```

This is what a future presence server, a `calls`/B2BUA leg waiting on an offline
callee, or the future push-notification feature (§6.5) subscribe to.

### 6.3 NAT / flow routing (spec §12.1 — critical for WebRTC)

- Store `received` (real IP:port + proto), **not** the announced Contact.
- Store the **flow** (the connection's transport pid) for connected transports —
  you cannot dial *into* a browser, so inbound reuses the existing connection
  (RFC 5626); a connection drop invalidates the binding (§6.2 `save`).
- `lookup/1` routes every inbound request targeting the AOR onto that flow.
- `Path` (RFC 3327): **honored if present** (stored as return route), **not
  generated** in basic (edge-proxy/multi-hop is roadmap).

### 6.4 Framework touch-points

1. **Capture the receiving transport on an inbound REGISTER.** Already partly
   present: `SIP.Transport.ImplHelpers.process_incoming_message/7` attaches
   `tp_pid: self()` to the R-URI of inbound requests; `SIP.Dialog` holds the
   dialog pid. `save/3` reads the real transport/addr from there (open: from the
   message vs from the dialog, §16).
2. **Send over a specific flow — `Selector` change (decided 2026-07-26).** Today
   `select_transport/1` **ignores** a pre-set `tp_pid`: it always runs
   `resolve_and_add_dest` then looks up `Registry.SIPTransport` by
   `proto_ip:port`. Inbound connected transports (a client's WSS/TCP/TLS spawned
   by the Listener) are **not** in that registry, so the Selector would try to
   open a *new outbound* connection to the peer — impossible toward a NATed
   browser. Fix: add a two-level short-circuit at the top of `select_transport/1`:
   1. **`tp_pid` alive** → use it as-is (skip resolution *and* lookup);
   2. else **`destip` + `destport` present** → use `destip`/`destport`/`destproto`
      directly (skip DNS resolution), `destproto == nil` ⇒ default **UDP**, then
      `find_or_launch_transport` on that destination (works for UDP; a dead
      connected flow is unreachable anyway and its binding was already purged);
   3. else → the current full resolve from the R-URI.

   `registrar.lookup/1` stamps `tp_pid` + `destip`/`destport`/`destproto` from the
   stored binding, so both fast paths apply. Same open item as
   `uas_scenario_design.md` §8.1 (connected-transport response routing).

### 6.5 Push notifications — *future, not basic*

Spec §12.2: a later version associates an AOR with a push "contact" to wake iOS /
Google / Microsoft mobile apps via push notification. Independent of HA,
**explicitly not basic**. Naturally rides on `subscribe_register_event/2` and the
contact model above; flagged here so the storage/API don't preclude it.

> **Response ownership — resolved (spec §11.1/§12.3/§12.4).** Modules **decide**,
> the **script composes** the SIP response via the `SIP.Session.Registrar.*`
> helpers — no module ever builds a SIP message. `auth_db.do_registration_auth/2`
> returns a verdict (`:ok | {:requireauth, stale} | {:reject, code, reason}`);
> `registrar.save/3` returns `{:ok, granted}`; the thin `registrar.exs`
> orchestrator routes verdicts to `challenge_registration` / `accept_registration`
> / `reject_registration`. Each response type is composed in exactly one place.

---

## 7. Authentication: stateless nonce + qop

Replaces the current stateful per-dialog nonce and the secret-less
`SIP.Auth.generate_nonce` (spec §11.1). Applies to the registrar *and* all
dialogue challenges.

### 7.1 `Kelix.Nonce` — stateless HMAC

```
nonce = base64url( ts ‖ rand ‖ HMAC-SHA256(server_secret, ts ‖ rand ‖ realm) )
```

- `generate(realm)` — `ts` = unix seconds, `rand` = 8–16 random bytes, HMAC keyed
  by the boot `server_secret`, base64url (avoid `+`/`/`, spec §11.1).
- `validate(nonce, realm)` — recompute the HMAC (no storage), check it matches,
  check freshness `now − ts ≤ max_age` (config, 30–60 s; default 60). Beyond ⇒
  `:stale` → the challenge is re-issued with `stale=true` and the client
  transparently replays. `realm` bound into the HMAC ⇒ a nonce from one domain is
  useless on another.

`Kelix.Secret` (supervised Agent) holds the **ephemeral** `server_secret`,
regenerated at boot (a restart invalidates in-flight nonces ⇒ `stale`, harmless).
Designed to become a **shared** secret across nodes for HA (roadmap) — any node
then validates any node's nonce.

### 7.2 Anti-replay within the window — `qop=auth` + `nc`

`Kelix.NonceCache` — a supervised **ETS** table `nonce → max nc seen`, bounded,
TTL = `max_age`. On each authed request with `qop=auth`: reject if
`nc ≤ last seen`, else record. Soft state, per-node, lost harmlessly on restart
(⇒ `stale`). Old clients without `qop` fall back to window-only anti-replay
(`max_age` + `stale`).

### 7.3 `SIP.Auth` extension (framework change — flagged "à faire" in spec §14)

- Add a `qop=auth` response computation:
  `response = H(HA1 : nonce : nc : cnonce : qop : HA2)` — **in addition to** the
  current RFC 2069 form `H(HA1:nonce:HA2)` (kept for fallback). New arity on
  `compute_auth_response_from_ha1/…` (or a new function) carrying `nc`/`cnonce`/
  `qop`.
- The challenge builder (`SIP.Msg.Ops.challenge_request/7`) offers
  `qop="auth"` and uses `Kelix.Nonce.generate/1` instead of
  `SIP.Auth.generate_nonce/0`. **algorithm = MD5** (do not require SHA-256 /
  RFC 8760 — poorly supported). Note today the registrar challenge is hardcoded
  to `SHA256` in `SIP.DialogImpl.handle_call({:replyreq,…})` — change to MD5 and
  drive realm/qop from the router-injected domain.
- The verifier (`SIP.Msg.Ops.check_authrequest/3`) branches on the presence of
  `qop` in the client response: `qop=auth` → the nc/cnonce form + `NonceCache`
  check; no `qop` → the RFC 2069 form. `Kelix.Nonce.validate/2` replaces the
  stateful `SIP.Dialog.check_nonce/2` lookup.

### 7.4 Secret source & realm — the `auth_db` module

- **realm = the domain's nominal `name`** (one realm per domain, spec §11.1). If
  the R-URI targeted the domain via an **alias**, the challenge still returns the
  domain's nominal `name` as the realm — so the HMAC-bound realm (§7.1) is stable
  regardless of which alias the client used. The Router injects the nominal name.
- **secret via `auth_db`** (renamed from `subscriber_db`) in **HA1** form
  (`H(user:realm:password)`, no cleartext), where `H` is set by
  **`password_hash = "md5" | "sha256"`** (default `"md5"`) in `[module.auth_db]`;
  the DB, table, and the column holding the hash are configurable — mirrors
  Kamailio's `subscriber` table.
- **`auth_db` decides, the script composes** (spec §11.1 → §12.3). `auth_db`
  evaluates the client's Authorization against the stored HA1 (nonce validation
  via `Kelix.Nonce`, digest check via the extended `SIP.Auth` §7.3) and returns a
  **verdict** — it builds no SIP message:

  ```elixir
  do_registration_auth(req, domain) :: :ok | {:requireauth, stale :: bool} | {:reject, code, reason}
  ```

  The `registrar.exs` script maps the verdict onto the `SIP.Session.Registrar.*`
  helpers: `{:requireauth, stale}` → `challenge_registration(req, dialog_pid,
  realm: domain, stale: stale)`; `:ok` → `save/3` then `accept_registration`;
  `{:reject, …}` → `reject_registration`. This keeps SIP-response composition in
  the script (elixip's "scenario owns the response") while the DB-dependent
  decision lives in the module — it refines, rather than reverses, the earlier
  "auth is application-side" decision (decision in the module, composition in the
  script).

> **Note (spec §11.1 residual).** The spec text still writes *"défaut `ha1`"* next
> to the `"md5" | "sha256"` enum — `ha1` is not one of the two values (HA1 is the
> *format*, md5/sha256 the *hash inside it*). Read as **default `"md5"`**; flagged
> in §16 and corrected in the spec pass.

### 7.5 Removal / deprecation

`SIP.DialogImpl.Nonce` (stateful map + purge timer) and
`SIP.Auth.generate_nonce/0` are **removed** once callers move to
`Kelix.Nonce`. The nonce format is opaque to clients (they echo it) so the
switch is transparent — no interop risk (spec §11.1). `elixipp`'s UAC digest
already tolerates any nonce, so tests are unaffected.

---

## 8. Loadable modules (.beam)

Spec §5. A module is a stateful OTP service **plus** stateless facades imported
by scripts.

### 8.1 `Kelix.Module` behaviour

As specified (§5.1): `validate_config/1`, `child_spec/2`, `describe/0`, optional
`reload/2`. `Kelix.ModuleSupervisor` (`:one_for_one`) starts one child per
`[module.<name>]` block; the TOML `<name>` is the registered name used by facade
resolution. Provided modules live under the `Kelix.Mod.*` namespace
(`Kelix.Mod.Registrar`, `Kelix.Mod.AuthDb`, `Kelix.Mod.RadiusBilling`).

Like Kamailio modules (spec §5), a module has **three** ways to plug in:

1. **Config** — parameters read from its `[module.<name>]` block in `config.toml`.
   The one exception is `registrar`, whose `[module.registrar]` block lives in
   `domains.toml` (hot-reloadable, domain-tied — §6.1); its per-domain expiry
   bounds are separate, in `[domain.registrar]`.
2. **REST** — it may enrich the control API with `/modules/<name>/…` endpoints.
3. **CLI** — it may add `kelictl <name> <command> <args>` sub-commands.

REST + CLI extensions use a **declarative-registration** mechanism (decided
2026-07-26, spec §5.1/§10) — the same parity principle as the core
`Kelix.Control`: one declaration, both frontals derive from it.

- The `Kelix.Module` behaviour gains two **optional** callbacks:
  `describe_control/0` (returns the command list — `name`, `args`, `rest`
  `{method, path}`, `rw`, `help`) and `handle_control/2` (runs a command).
- At module start `Kelix.ModuleSupervisor` reads `describe_control/0` and
  registers the entries, keyed by module name, into a central
  **`Kelix.Control.Registry`** (ETS/Agent); it deregisters on stop/reload.
- Both frontals iterate that registry: `Kelix.ControlAPI` mounts the
  `/modules/<name>/…` routes, `kelictl` generates the `<name> <cmd>` sub-commands
  and their `--help`. Execution routes to `handle_control/2`.
- `handle_control/2` **never checks auth** — authentication is enforced at the
  frontal boundary (§10), keeping the module logic pure.

### 8.2 Facade contract (spec §5.2 — locked decisions)

- **Single instance** per module (multi-instance is future).
- **Non-blocking for the instance**: a facade returns `{:error, reason}` if the
  service is down — it never raises, so the scenario instance survives and keeps
  control of the SIP response.
- **`call_timeout_ms`** in `[module.<name>]` bounds a facade call (a slow DB does
  not freeze the instance) — implemented as the `GenServer.call` timeout wrapped
  in a `try` that converts exits to `{:error, :timeout}`.
- **Reload** (`module reload <name>`): `validate_config/1` first; then `reload/2`
  if exported, else a clean child restart.

### 8.3 Provided modules

First-party but **not compiled into the core release** (decided 2026-07-26):
each ships as a `.beam` in `module_dir` and is loaded only when a
`[module.<name>]` block declares it. The core release carries no SIP *function* —
a kelixip-based product loads exactly the modules it needs (an MCU-only product
loads none of these).

- **`registrar`** (`Kelix.Mod.Registrar`) — the usrloc / contact store and its
  `save`/`lookup`/`subscribe` API. Fully specified in §6.
- **`auth_db`** (`Kelix.Mod.AuthDb`) — MariaDB/MySQL access reading the
  `subscriber` table for registrar **auth**: HA1 lookup **and** the
  `401/accept/reject` verdict (§7.4). Needs a MySQL driver dep (`myxql`, §13); a
  connection pool is its supervised service; the DB/table/hash-column and
  `password_hash` are configurable.
- **`radius_billing`** (`Kelix.Mod.RadiusBilling`) — RADIUS billing. Hand-rolled
  UDP RADIUS client (no heavy dep).

Packaging then delivers the core release and these modules as **separate
artifacts** (e.g. rpm subpackages) so a deployment installs only what it uses
(§12).

Facade import in the registrar script: `import Kelix.Mod.Registrar` /
`import Kelix.Mod.AuthDb` — the facade is a thin stateless wrapper resolving the
service by its registered name and delegating (spec §5).

> Open (spec): `.beam` **code-reload versioning** / OTP `code_change`-style state
> migration is left unspecified — flagged §16.

---

## 9. Media server pool

Spec §6. Extends the current single-`:mediaserver` config to a pool.

### 9.1 `Kelix.MediaPool`

Supervised GenServer over the `[mediaserver.pool.*]` entries:

- **Selection** — round-robin over `enabled` + healthy MCUs for each new call.
- **Health-check** — periodic probe (reuse `MediaServer.Behaviour.connect/1` /
  a lightweight ping) marking each MCU up/down; failover skips down MCUs.
- **Enable/disable at runtime** — `mediaserver_toggle` (§10) flips a pool
  entry's `enabled` flag without restart.

Each pool entry wraps an existing `MediaServer.Mendooze` adapter instance
(reusing all of `lib/framework/mendooze/`). The Router injects the *selected* MCU
handle into the spawned instance's config (`mediaserver` override), so the DSL
`media_connect/0` macro connects to a pool-chosen server transparently. Metrics:
active sessions per MCU, MCU up/down (§11).

---

## 10. Control layer, CLI & REST API

Spec §9–§10. **Parity by construction**: one command layer, two frontals.

### 10.1 `Kelix.Control`

The single source of truth — every operation is a function here; neither frontal
holds business logic. Surface (spec §9.3):

| Function | R/W | CLI (`kelictl`) | REST |
|---|---|---|---|
| `status/0` — uptime, counters, pool, node state | R | `kelictl status` | `GET /status` |
| `monitor/0` — scenarios in progress | R | `kelictl monitor` | `GET /scenarios` |
| `registrations/1` | R | `kelictl regs [aor]` | `GET /registrations` |
| `unregister/2` | W | `kelictl unregister <aor> [contact]` | `DELETE /registrations/<aor>` |
| `shutdown_scenario/1` | W | `kelictl stop <id>` | `POST /scenarios/<id>/shutdown` |
| `reload_script/2` (notify?) | W | `kelictl reload-script [--notify] <name…>` | `POST /scripts/reload[?notify=1]` |
| `reload_domains/0` | W | `kelictl reload-domains` | `POST /domains/reload` |
| `module_reload/1` | W | `kelictl module reload <name>` | `POST /modules/<name>/reload` |
| `mediaserver_toggle/2` | W | `kelictl mcu <name> on\|off` | `POST /mediaservers/<name>` |
| `set_log_level/1` | W | `kelictl log-level <lvl>` | `PUT /log/level` |
| `graceful_shutdown/0` | W | `kelictl graceful-shutdown` | `POST /graceful-shutdown` |

Plus, per §8.1, **module-contributed commands**: `kelictl <module> <cmd> <args>`
↔ `… /modules/<name>/…`, sourced from each `Kelix.Mod.<Name>.Control`.

`monitor/0` reuses the in-memory store already feeding `elixipp --monitor`
(`SIP.Scenario.Monitor`). `registrations/1` reads the `Kelix.Mod.Registrar`
store (§6). `status/0` aggregates uptime + counters + pool state.

### 10.2 The `kelictl` CLI

`kelictl` is **a command shipped inside the `kelixip` release** (not a separate
escript — decided 2026-07-26, see §12), installed as **`/usr/sbin/kelictl`**
(spec §9.1). It is a *local client* of the running node over **Erlang
distribution / RPC**: it reads `server.node_name` + the cookie, does
`:rpc.call(node, Kelix.Control, fun, args)`, and renders the result (reusing the
Owl table rendering for `monitor`). The CLI logic (arg parsing, rendering) lives
in a `Kelix.Control.CLI` module compiled into the release; a `bin/kelictl`
overlay forwards `argv` to it. It runs no SIP stack. Because it only calls
`Kelix.Control` (and the registered `Kelix.Mod.<Name>.Control`), parity with REST
is automatic — adding a command = add the function + wire two thin frontals.

### 10.3 REST API (`Kelix.ControlAPI`)

A Plug router served by **Bandit** (§13), one endpoint per `Kelix.Control`
function, plus the module-registered `/modules/<name>/…` endpoints (§8.1, from
`Kelix.Control.Registry`).

**Auth is a boundary concern, separate from the command logic** (decided
2026-07-26). A Plug **middleware** validates the credential *before* dispatching
to `Kelix.Control` / `handle_control`: `[control_api]` defaults to **loopback +
token** (Bearer, constant-time compare); `auth = "mtls"` adds client-cert
verification for network exposure; `"none"` for trusted local. On the CLI side,
the Erlang distribution **cookie** is the credential (no token). Neither
`Kelix.Control` nor any module `handle_control/2` inspects tokens — they assume an
authenticated caller. **Basic model = a single admin token** (all commands, all
domains, incl. module commands); per-domain RBAC is roadmap (spec §10).

---

## 11. Observability

Spec §8.2. `:telemetry` events emitted at key points, exported as Prometheus.

- **`Kelix.Metrics`** attaches telemetry handlers and runs
  `TelemetryMetricsPrometheus` (§13), serving `/metrics` + `/health` on the
  `[metrics]` port (separate from control API, loopback by default). `/health`
  returns liveness (node up) + readiness (config loaded, listeners bound) for
  systemd / orchestrators.
- **Events** emitted from the router, `Kelix.Mod.Registrar`, transaction layer,
  transports, media pool. All key metrics carry a **`domain` label** (spec §8.2):
  registrations gauge / REGISTER rate / auth failures; active dialogs / call
  attempts-answered-failed / setup time; transactions by method + response class;
  transport messages in/out by proto + active WSS/TCP connections; media sessions
  per MCU + MCU up/down; system `503` (over `max_calls`), parse errors, timer
  B/F timeouts.
- Instrumentation is added at the framework seams the events describe (mostly the
  Router, `Kelix.Mod.Registrar`, `SIP.Transac`, transports). The `--monitor`
  TUI and per-instance PlantUML diagrams remain complementary debug tools.

---

## 12. Packaging

### 12.0 Repository structure — umbrella, 3 apps (decided 2026-07-26)

One git repo, restructured into a Mix **umbrella** so each artifact carries only
its own dependencies and the singular-`escript:` limitation disappears:

```
mix.exs                     # umbrella root (aggregate only)
apps/
  elixip/    # shared SIP stack + DSL + media = LIBRARY
             #   deps: jason, req, socket2, ex_sdp, xmlrpc, logger_file_backend
  elixipp/   # test tool → escript `elixipp`; depends on :elixip; + owl
  kelixip/   # server → release `kelixip` (+ `kelictl`); depends on :elixip;
             #   + toml, bandit, plug, telemetry*, myxql, (syslog)
```

- `elixipp` stays **lean** — it never pulls kelixip's HTTP/DB deps.
- `kelixip` owns the server, its deps, and `kelictl`.
- The middle `elixip` library depends on neither tool nor server.

Build/run each artifact:

```bash
mix compile                                          # all three apps
cd apps/elixipp && mix escript.build                 # -> elixipp
cd apps/kelixip && MIX_ENV=prod mix release kelixip  # -> release + bin/kelixip + bin/kelictl
```

> Migration note: this is a one-time refactor moving today's `lib/` into
> `apps/elixip/lib` (framework + DSL) and `apps/elixipp/lib` (the `Elixipp.CLI`
> tool), and creating `apps/kelixip`. It is prerequisite work for P0 (§15) — the
> `elixipp` escript and `mix test` must keep working throughout.

> **Implementation status (P0, 2026-07-26).** Done: umbrella created;
> `apps/elixip2` holds all current code + the elixipp escript; `apps/kelixip`
> added with `Kelix.Application` + release. The shared-library app keeps the name
> **`:elixip2`** (not renamed to `:elixip`) to avoid churn on 114 `:elixip2`
> config/env references — the `:elixip2 → :elixip` rename and the split of the
> tool into a distinct **`apps/elixipp`** are deferred follow-ups (so the current
> state is 2 apps: `elixip2` = library+tool, `kelixip` = server). Directory is
> `apps/elixip2` accordingly.

### 12.1 The `kelixip` release & FHS

Spec §7. The server is delivered as an **OTP release** (`mix release kelixip`,
embedded ERTS), not an escript — a properly managed service. **`kelictl` ships
inside this release** as a `bin/` command (option B, §10.2): a `Kelix.Control.CLI`
module + a `bin/kelictl` overlay that RPCs the running node — no second escript.

- `apps/kelixip/mix.exs`: a `releases:` section (`kelixip`) with
  `mod: {Kelix.Application, []}`, `include_erts: true`, a `rel/env.sh` exporting
  `RELEASE_NODE` (= `server.node_name`) and the cookie, the `bin/kelictl` overlay,
  and the TOML config path from an env var.
- **FHS layout** (spec §7): `/etc/kelixip/{config.toml,domains.toml,tls/}`,
  `/usr/share/kelixip/` (default scripts, package data), `/usr/lib/kelixip/`
  (release + `modules/`), `/var/lib/kelixip/` (mutable scripts, future usrloc),
  `/var/log/kelixip/` (if stdout redirected; else syslog).
- **systemd unit**: non-privileged `kelixip` user/group, `ExecStart` = release
  `start`, `ExecStop` = `Kelix.Control.graceful_shutdown` (drain, §2.2),
  `TimeoutStopSec` > drain deadline, `epmd` managed by the release.
- **Platforms**: Alma Linux 9 (rpm) + Ubuntu (deb). Build via a release →
  fpm/`rpmbuild`/`dpkg-deb` step (CI). `module_dir` must be `root`-owned,
  non-writable by the service (security, spec §11 — loading `.beam` = executing
  code).
- **Modules are separate artifacts** (decided 2026-07-26): the core release
  ships **no SIP function**; `registrar`/`auth_db`/`radius_billing` are packaged
  as **rpm/deb subpackages** (`kelixip-mod-registrar`, …) dropping their `.beam`
  into `module_dir`. A deployment installs only the modules it uses (e.g. an
  MCU-only product installs none). A domain that enables a function whose module
  is not installed is a **config error caught at load/`reload_domains`** (§3.2).

Launch: `kelixip --config /etc/kelixip/config.toml [--stdout]`.

---

## 13. New dependencies

| Dep | Purpose | Notes |
|---|---|---|
| `toml` | parse `config.toml` / `domains.toml` | pure Elixir, no NIF, release-safe |
| `bandit` + `plug` | REST control API + `/metrics` + `/health` HTTP | pure Elixir; `req` (present) is client-only |
| `telemetry`, `telemetry_metrics`, `telemetry_metrics_prometheus` | metrics | standard Elixir observability stack |
| `myxql` | `auth_db` MariaDB/MySQL driver | only needed when that module is built |
| syslog backend (`logger_syslog` or erlang `:logger` syslog handler) | `log.target = "syslog"` | evaluate vs journald-only |

All are pure-Elixir/BEAM (no C NIFs that would complicate the release) except the
MySQL driver, which is fine in a release. RADIUS for `radius_billing` can be a
hand-rolled UDP client (no heavy dep).

---

## 14. Migration & compatibility work

Flagged in the spec as **"à faire"**:

0. **Umbrella restructure (prerequisite, §12.0).** Move today's single `:elixip2`
   app into an umbrella: `apps/elixip` (framework + DSL, library), `apps/elixipp`
   (the `Elixipp.CLI` escript), `apps/kelixip` (server release + `kelictl`). Split
   deps accordingly. The `elixipp` escript, `mix scenario` and `mix test` must
   keep working throughout. This lands before P0.
1. **Pull domain config out of UAS INVITE scenarios** (spec §4, §14). Today
   `scenarios/uas_invite.exs` carries its own `config domains:` and the factory
   reads it. With kelixip's declarative dispatch the domain + routing come from
   `domains.toml`; the script keeps only call logic. Action: the Router injects
   the domain into the instance context; scripts stop declaring `domains:`. Keep
   `elixipp`'s `ScenarioUAS` path working (it still reads `config domains:`) — the
   two dispatchers coexist.
2. **Nonce migration** (§7.5): remove `SIP.DialogImpl.Nonce` +
   `SIP.Auth.generate_nonce`, switch the challenge/verify path to
   `Kelix.Nonce`. Update `scenarios/uas_register.exs`'s
   `check_registration_auth/3` (which currently calls `SIP.Dialog.check_nonce/2`)
   to the stateless validate.
3. **`qop=auth` in `SIP.Auth`** (§7.3) — additive, keeps RFC 2069 fallback.
4. **Per-listener certs** (§3.1) — thread cert/key through listener opts.
5. **Supervise the stack** (§2) — registries/ConfigRegistry/listeners as
   children; `Runner.bootstrap_stack/0` stays for `elixipp`/tests.
6. **Connected-transport response routing / send-over-flow** (§6.4) — the open
   item from `uas_scenario_design.md` §8.1.
7. **Auth logic moves out of the script into `auth_db`** (spec §11.1 → §12.3).
   Today `scenarios/uas_register.exs` holds `check_registration_auth/3` (the
   401/accept/reject decision) *in the script*. The spec's latest edit moves that
   decision **into the `auth_db` module**. This reverses the earlier
   "auth logic is application-side" decision and reshapes the registrar script
   into a thin orchestrator over `Kelix.Mod.AuthDb` + `Kelix.Mod.Registrar` — see
   the open question §16.

Guiding rule: **kelixip is additive**. The `elixipp` tool and existing tests must
keep passing; framework changes are backward-compatible (fallbacks, opts with
defaults).

---

## 15. Phased delivery plan

Ordered so each phase is independently testable and the framework changes land
before the features that need them.

| Phase | Deliverable | Depends on |
|---|---|---|
| **P0 — Umbrella + OTP skeleton** | restructure into `apps/elixip` + `apps/elixipp` + `apps/kelixip` (§12.0, keep `elixipp`/tests green); `Kelix.Application` + supervision tree; supervise registries/ConfigRegistry/listeners; `mix release kelixip` builds; boots with an empty config | — |
| **P1 — Config** | `toml` dep; `Kelix.Config` (infra→app env, per-listener certs); `Kelix.Domains` + `Kelix.DialPlan` compiler; atomic reload plumbing (no CLI yet) | P0 |
| **P2 — Dispatch** | `Kelix.Router` (domain→function→script, 404/405/503); wire as ConfigRegistry processing module; `Kelix.ScriptRegistry` (version-suffixed modules + refcount) + load-time contract check; extract `Kelix.InstancePool` (shared quota, per-domain) | P1 |
| **P5 — Module system** | `Kelix.Module` behaviour + `Kelix.ModuleSupervisor` + facade resolution + module control-surface registration (REST/CLI, §8.1) | P1 (config) |
| **P3 — Registrar module** | `Kelix.Mod.Registrar` (per-domain store; `save`/`lookup`/`subscribe`; received+flow+Path); NAT/flow inbound routing; send-over-flow framework hook | P2, P5 |
| **P4 — Auth** | `Kelix.Secret` + `Kelix.Nonce` (stateless HMAC) + `NonceCache`; `SIP.Auth` `qop=auth`; realm=domain (alias→nominal); remove stateful nonce; `Kelix.Mod.AuthDb` (HA1 lookup + 401/accept/reject) | P3, P5 |
| **P6 — Media pool** | `Kelix.MediaPool` (round-robin, health-check, failover, toggle) over the Mendooze adapter | P0 |
| **P6b — radius_billing** | `Kelix.Mod.RadiusBilling` | P5 |
| **P7 — Control layer** | `Kelix.Control` (all verbs); `kelictl` release command over RPC (`Kelix.Control.CLI` + `bin/kelictl` overlay); versioned/notify reload; graceful shutdown | P2–P6 |
| **P8 — REST API** | `bandit`+`plug` frontal; token/mtls auth; parity with CLI | P7 |
| **P9 — Observability** | telemetry events + Prometheus exporter; `/metrics` + `/health`; per-domain labels | P2+ |
| **P10 — Packaging (RPM d'abord)** | **produire le paquet RPM kelixip pour Alma Linux 9** : `mix release` (ERTS embarqué) → `.spec` (`%files` sur le layout FHS §12, `%pre`/`%post` créant l'utilisateur `kelixip` + l'unité systemd, `%config(noreplace)` sur `/etc/kelixip/*.toml`) → `rpmbuild`/`fpm` en CI, `module_dir` root-owned. Deb Ubuntu ensuite, même release. | P0–P9 |

P3+P4 (registrar + auth) are the functional core of "basic"; P0–P2 are the
enabling infrastructure; P7–P10 make it a product.

---

## 16. Open questions

All questions below were decided on **2026-07-26** unless marked otherwise.

1. **Shared factory vs Router-owned pooling** (§4.2) — **RESOLVED**: extract
   `Kelix.InstancePool` (quota + monitor + counters + shutdown broadcast), used by
   both `Elixip.ScenarioUAS` and `Kelix.Router`. Per-domain quota lives in the
   pool, keyed by `(domain, function)`.
2. **`Kelix.Module` contract** — **RESOLVED**: `describe/0`'s `exports` is
   **informational** in basic (introspection/help), not a runtime gate on facade
   imports (resolved at compile time by Elixir). `.beam` code-reload with state
   migration (`code_change`-style) is **out of basic** — reload = `validate_config`
   + `reload/2` or clean restart (§5.2 / §8.2); state migration is future.
3. **Script version identity** (§5.1) — **RESOLVED**: recompile each `.exs` into a
   **version-suffixed module name**. *Why it matters in practice:* the BEAM keeps
   only **two** code versions per module name (current + old), so if a script is
   reloaded while a long call still runs on an already-superseded version, a single
   name cannot hold all the in-flight versions. Distinct names per version remove
   that limit; each is purged (`:code.purge`) once its refcount hits 0. Cost: minor
   atom-table growth over many reloads (reloads are infrequent admin ops).
4. **Syslog backend choice** (§13) — **RESOLVED**: default to **stdout/journald**
   (systemd captures it); `log.target = "syslog"` optional via a small dep (to
   evaluate). Do not over-invest.
5. **usrloc storage shape** (§6.1) — **RESOLVED**: **one ETS table per domain**
   (strong domain separation), plus a top-level `%{domain => tid}` index; per-domain
   table created/dropped with the domain, per-binding purge via a monitor on the
   dialog pid. (Not a single shared table, not a Registry-per-domain.)
6. **`send-over-flow`** (§6.4) — **RESOLVED**: the `Selector` does **not** honor a
   pre-set `tp_pid` today, so add a two-level short-circuit to `select_transport/1`
   — (1) live `tp_pid` → use it; (2) `destip`+`destport` present → use the resolved
   dest directly (`destproto == nil` ⇒ UDP); (3) else full resolve. `lookup/1`
   stamps both. Same item as `uas_scenario_design.md` §8.1.

**Tensions from the spec's manual edits (§5, §11.1, §12) — all resolved:**

7. **Where does the SIP auth response get composed?** — **RESOLVED**
   (spec §11.1/§12.3/§12.4, 2026-07-26). Modules **decide** (`auth_db` verdict,
   `registrar.save/3 → {:ok, granted}`), the **`registrar.exs` script composes**
   via `SIP.Session.Registrar.*`. Each response type composed in exactly one
   place; `save` clamps expiry once, `accept_registration` only echoes `granted`.
   §12.3/§12.4 stubs filled.
8. **Registrar module config block.** — **RESOLVED** (2026-07-26). Aligned on the
   module convention: a **`[module.registrar]`** block holds the module param
   (`max_contacts_per_aor`), placed in **`domains.toml`** (hot-reloadable,
   domain-tied); per-domain expiry bounds stay in `[domain.registrar]`. The
   `Kelix.ModuleSupervisor` reads/reconfigures the registrar from `domains.toml`.
9. **AOR key source.** — **RESOLVED** (2026-07-26): the AOR is the user-part of
   the **`To`** header (RFC 3261).
10. **`password_hash` default.** — **RESOLVED**: default `"md5"` (`ha1` in the
    spec was an invalid leftover — HA1 is the format, md5/sha256 the hash inside;
    corrected in the spec).
11. **Module control-surface registration** — **RESOLVED** (2026-07-26, Option B):
    optional behaviour callbacks `describe_control/0` + `handle_control/2`,
    registered at module start into a central `Kelix.Control.Registry` that both
    frontals derive from (§8.1). Admin auth is enforced at the frontal boundary
    (REST Plug middleware / CLI Erlang cookie), separate from the command logic
    (§10.3); modules inherit the single admin token.
12. **First-party registrar as a "loadable module".** — **RESOLVED**: the
    registrar/auth_db/radius_billing are **not bundled** in the core release —
    they are `.beam` modules in `module_dir`, loaded per config, shipped as
    separate rpm/deb subpackages (§8.3, §12). The core release is
    **function-agnostic**: a kelixip-based product (e.g. an MCU) loads only the
    modules it needs, and may load none of these. The module system is thus both
    the internal architecture *and* the third-party extension point.

**Remaining open (not blocking basic):** none of the above. New items will be
logged here as implementation proceeds.
