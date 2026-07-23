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

kelixip is delivered as a **new top namespace `Kelixip.*`** layered on top of
`SIP.*` / `MediaServer.*`, plus a small number of surgical changes inside the
framework (nonce, `qop`, connected-transport response routing). The `elixipp`
test tool keeps working unchanged (it does not start the `Kelixip.Application`).

---

## 2. OTP application & supervision tree

### 2.1 Root application

Add `Kelixip.Application` (`use Application`) wired in `mix.exs` as
`mod: {Kelixip.Application, []}` **only for the kelixip release** (see §12) — the
`:elixip2` app itself stays library-style so `elixipp`/`mix scenario`/tests keep
their imperative bootstrap. The release's `application/0` env selects kelixip
mode; `Application.start/2` reads `--config` (the TOML path) from an env var set
by the boot script / systemd unit.

```
Kelixip.Application  (use Application)
└── Kelixip.Supervisor            (:one_for_one, root)
    ├── Kelixip.Config             — GenServer: parsed config.toml (read-only after boot)
    ├── Registry.SIP.Transac       ┐  (the 3 stack registries, today started
    ├── Registry.SIPTransport      │   ad-hoc by bootstrap_stack/0 — now supervised)
    ├── Registry.SIPDialog         ┘
    ├── SIP.Resolver               — DNS defaults (was inside Selector.start/0)
    ├── SIP.Session.ConfigRegistry — kept, but demoted to a low-level primitive
    │                                 the Router configures (see §4)
    ├── Kelixip.Secret             — Agent: ephemeral server_secret (boot-random)  §7
    ├── Kelixip.NonceCache         — ETS owner: nonce→nc, TTL=max_age             §7
    ├── Kelixip.ModuleSupervisor   — :one_for_one, loadable .beam services         §8
    ├── Kelixip.MediaPool          — GenServer: MCU pool, health-check, failover   §9
    ├── Kelixip.ScriptRegistry     — GenServer: loaded scenario versions + refcount §5
    ├── Kelixip.Registrar.Store    — usrloc (Registry or ETS), AOR-keyed           §6
    ├── Kelixip.Domains            — GenServer: hot-reloadable domains.toml (atomic) §4
    ├── Kelixip.Router             — stateless dispatch; reads Domains + ScriptRegistry §4
    ├── Kelixip.InstanceSupervisor — DynamicSupervisor: one child per scenario instance
    ├── Kelixip.Listener.Supervisor
    │   ├── Kelixip.Listener.ConnSupervisor  — DynamicSupervisor (per-connection transports)
    │   └── {UDP|TCP|TLS|WSS} listeners       — one child per [[listen]]
    ├── Kelixip.Control            — the command layer (§10), no transport of its own
    ├── Kelixip.ControlAPI         — REST frontal (Plug/Bandit), [control_api]     §10
    └── Kelixip.Metrics            — telemetry → Prometheus, /metrics + /health     §11
```

Design choices:

- **Registries & ConfigRegistry become supervised children** instead of the
  current idempotent `start_link` inside `Runner.bootstrap_stack/0`. Boot order
  matters: registries and `SIP.Resolver` first, then stores, then the router,
  then listeners last (a listener must not accept before the router is ready).
- **Listeners become supervised.** Today `Elixipp.CLI.start_listeners/1` does
  `GenServer.start` and discards the pid. Kelixip introduces
  `Kelixip.Listener.Supervisor` with one child spec per `[[listen]]` entry and a
  `DynamicSupervisor` for the per-connection transports the acceptors spawn
  (the acceptor `Task` stays inside each listener, unchanged). A crashing
  listener is restarted; existing connections are independent children.
- **Instances become supervised.** `spawn_uas_instance/2` currently does
  `spawn_monitor` of a bare process. For a long-running server we route it under
  `Kelixip.InstanceSupervisor` (a `DynamicSupervisor`, `:temporary` children) so
  instances are observable, countable (metrics), and drainable
  (`graceful_shutdown`). The factory still `Process.monitor`s each child to free
  its quota slot — the monitor and the supervisor are complementary (monitor =
  slot accounting, supervisor = lifecycle/observability). `spawn_uas_instance/2`
  gains an option to start under a supervisor instead of `spawn_monitor`.

### 2.2 Graceful shutdown

systemd `stop` → `Kelixip.Control.graceful_shutdown/1` (also the CLI/REST verb):
broadcast `{:scenario_ctl, :shutdown, :node_shutdown}` to every instance under
`Kelixip.InstanceSupervisor`, wait for drain with a deadline, `Process.exit/2`
kill stragglers, then `System.stop/0`. This is exactly the existing cooperative
shutdown contract (§9.2 of the spec) — hence the load-time requirement that
every script has an `on_shutdown` block (§5.3). The systemd unit sets
`TimeoutStopSec` slightly above the drain deadline.

---

## 3. Configuration layer (TOML)

Two files, two lifecycles (spec §3). Parsed with a **pure-Elixir TOML parser**
(`toml` hex package; no NIF, bundles in a release — see §13).

### 3.1 `Kelixip.Config` — infra (`config.toml`)

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
   | `mediaserver.pool.*` | `Kelixip.MediaPool` children (§9) |
   | `module.*` | `Kelixip.ModuleSupervisor` children (§8) |
   | `control_api.*`, `metrics.*` | `Kelixip.ControlAPI` / `Kelixip.Metrics` |

3. **Per-listener certificates.** The framework listeners today read *global*
   `:tls_certfile`/`:tls_keyfile`. The spec wants `cert`/`key` per `[[listen]]`
   (§3.4). Small framework change: `TLSListener`/`WSSListener` `init/1` already
   accept an opts keyword (the 3rd tuple element) — thread `certfile`/`keyfile`
   through it, falling back to the global config for back-compat.

Logging: `log.target = "syslog"` selects a syslog backend
(`syslog` / `logger_syslog` dep, or the erlang `:os` `logger` handler);
`"stdout"` (or `--stdout`) keeps the console backend. `log.level` sets the
handler level.

### 3.2 `Kelixip.Domains` — domains + dial-plan (`domains.toml`)

Hot-reloadable (spec §3.2, §9.2). Held in a GenServer behind an **atomic swap**:

```elixir
%Kelixip.Domains{
  version: pos_integer,          # bumped on each successful reload
  domains: [%Kelixip.Domain{}],  # order preserved (TOML array-of-tables)
  index: %{binary => %Kelixip.Domain{}}  # name + each alias → domain, for O(1) lookup
}

%Kelixip.Domain{
  name: binary,
  aliases: [binary],
  max_calls: pos_integer | nil,
  registrar: %{script: binary, default_expires: .., min_expires: .., keepalive_period: ..} | nil,
  presence:  %{script: binary} | nil,                                  # future
  dial_plan: [%Kelixip.DialRule{}]  # calls function; [] if calls disabled  # future
}

%Kelixip.DialRule{
  matcher: (binary -> boolean),  # compiled from `pattern` (§3.3) or `default: true`
  raw: binary,                   # the original pattern text, for `status`/logs
  script: binary,
  default?: boolean
}
```

**Reload is atomic / all-or-nothing** (spec §9.2): parse the whole file into a
new `%Kelixip.Domains{}` off to the side — including compiling every dial-plan
pattern **and running the §5.3 load-time contract check on every referenced
script** — and only if the entire structure validates do we swap it in
(`:sys.replace_state`-style atomic assign). One bad element ⇒ reject, current
config untouched, error returned to the caller. Reads (`Kelixip.Router`) always
see one consistent version.

### 3.3 Dial-plan pattern compiler (`Kelixip.DialPlan`)

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

### 4.1 `Kelixip.Router`

Configured (once, at boot) as the registration **and** call **and** presence
processing module in `SIP.Session.ConfigRegistry` — so `internal_dispatch/4`
calls into the Router regardless of method. The Router is otherwise stateless;
it reads `Kelixip.Domains` (current version) and `Kelixip.ScriptRegistry`.

```
on_new_registration/3 ─┐
on_new_call/3          ├─► Kelixip.Router.route(method, dialog_id, req, transaction_id)
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
- **Step 5 — spawn.** Ask `Kelixip.ScriptRegistry` for the current version's
  module, spawn under `Kelixip.InstanceSupervisor` via `spawn_uas_instance/2`
  with `dialog_pid`/`parent_pid`/`inbound_request`, plus **injected config
  overrides**: the domain name (→ auth realm §7), the resolved
  `default_expires`/`min_expires`, and the selected media-pool handle (§9). The
  instance's `%SIP.Context{}` therefore carries its domain — the script no longer
  hardcodes it (this is the migration in §14).

### 4.2 Relationship to `Elixip.ScenarioUAS`

`Elixip.ScenarioUAS` (the `elixipp` factory) and `Kelixip.Router` play the same
role — accept/reject + spawn + quota — but the factory is *single-scenario,
single-domain* and the Router is *multi-domain, script-per-rule*. Rather than
fork, the design **extracts the shared machinery** (quota accounting, instance
monitoring, `{:scenario_exit,…}` counters, cooperative shutdown broadcast) into
a small shared module (`Kelixip.InstancePool` / or keep it in `ScenarioUAS` and
have the Router delegate per (domain,function) slot). `elixipp` keeps using
`ScenarioUAS` directly; kelixip uses the Router. Both ultimately call
`SIP.Scenario.Runner.spawn_uas_instance/2`.

> **No global routing script (spec §2.2).** The Router is pure config-driven
> dispatch. Runtime-data routing (ported number, time-of-day) lives *in the
> selected script* in Elixir, not in a mini-language — nothing to build here,
> it is a property of the design.

---

## 5. Script registry & versioned reload

### 5.1 `Kelixip.ScriptRegistry`

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
- **`current`** is what `Kelixip.Router` spawns. Existing instances keep the
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

## 6. Registrar & usrloc store

There is **no AOR-keyed location store today** — registrations are ephemeral
dialog processes. Kelixip adds a real usrloc (spec §12), *in memory* (basic
scope explicitly excludes persistence/HA).

### 6.1 `Kelixip.Registrar.Store`

In-memory, AOR-keyed. Backed by ETS (a named `:set`/`:bag` owned by the
supervised store process) — chosen over `Registry` because bindings are *data*,
not processes, and we want range/prefix queries for `kelixip regs [aor]`.

```elixir
# key: {domain :: binary, aor :: binary}  (aor = user@domain, lowercased)
# value: list of bindings
%Kelixip.Registrar.Binding{
  contact:    %SIP.Uri{},        # the Contact as announced (may be private/NATed)
  received:   {ip, port},        # REAL source (spec §12.1) — used for routing, NOT contact
  transport:  {proto, tp_pid},   # flow handle for connected transports (WSS/TCP/TLS)
  flow_ref:   reference(),       # monitor of the transport pid → auto-purge on disconnect
  path:       [%SIP.Uri{}] | [], # RFC 3327 Path, honored if present, not generated (basic)
  cseq:       integer,
  call_id:    binary,
  expires_at: DateTime.t(),
  q:          float | nil
}
```

Operations: `put/replace/remove` (on REGISTER refresh / expires=0 / expiry
timer), `lookup(domain, aor)`, `all(domain \\ :all)` (for the monitor/CLI).
Expiry is timer-driven (per binding, like the current dialog nonce timer) *and*
event-driven: when a connected transport pid goes `:DOWN`, its bindings are
purged immediately (flow is dead — spec §12.2 rationale).

### 6.2 NAT / flow routing (spec §12.1 — critical for WebRTC)

- Store `received` (real IP:port), **not** the announced Contact.
- Store the **flow handle** (`transport` = the connection's transport pid) for
  connected transports — you cannot dial *into* a browser, so inbound reuses the
  existing connection (RFC 5626).
- Route every inbound request targeting the AOR onto the stored flow /
  `received`. This requires the framework to let the Registrar hand a specific
  transport pid to the outbound path — see §6.3.
- `Path` (RFC 3327): **honored if present** (stored as return route), **not
  generated** in basic (edge-proxy/multi-hop is roadmap).

### 6.3 Framework touch-points

Two small framework capabilities the usrloc needs:

1. **Capture the receiving transport on an inbound request.** Already partly
   present: `SIP.Transport.ImplHelpers.process_incoming_message/7` attaches
   `tp_pid: self()` to the R-URI of inbound requests. The registrar reads it off
   the REGISTER to fill `Binding.transport`.
2. **Send an out-of-dialog request over a specific flow.** `SIP.Transport.Selector`
   picks transports by destination; for connected flows we must *bypass*
   selection and reuse a known `tp_pid`. Add a `send-over-flow` path (a
   `%SIP.Uri{tp_pid: pid}` already short-circuits `find_or_launch_transport`, so
   this may be mostly wiring). This is the same open item flagged in
   `uas_scenario_design.md` §8.1 (connected-transport response routing).

> The registrar *script* remains application-side (spec §11.1): 401/accept/reject
> logic lives in the DSL. The `Store` is framework/infra the script calls into
> (it will be exposed as `SIP.Session.Registrar` helpers or a `Kelixip.Registrar`
> facade so the DSL stays declarative).

---

## 7. Authentication: stateless nonce + qop

Replaces the current stateful per-dialog nonce and the secret-less
`SIP.Auth.generate_nonce` (spec §11.1). Applies to the registrar *and* all
dialogue challenges.

### 7.1 `Kelixip.Nonce` — stateless HMAC

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

`Kelixip.Secret` (supervised Agent) holds the **ephemeral** `server_secret`,
regenerated at boot (a restart invalidates in-flight nonces ⇒ `stale`, harmless).
Designed to become a **shared** secret across nodes for HA (roadmap) — any node
then validates any node's nonce.

### 7.2 Anti-replay within the window — `qop=auth` + `nc`

`Kelixip.NonceCache` — a supervised **ETS** table `nonce → max nc seen`, bounded,
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
  `qop="auth"` and uses `Kelixip.Nonce.generate/1` instead of
  `SIP.Auth.generate_nonce/0`. **algorithm = MD5** (do not require SHA-256 /
  RFC 8760 — poorly supported). Note today the registrar challenge is hardcoded
  to `SHA256` in `SIP.DialogImpl.handle_call({:replyreq,…})` — change to MD5 and
  drive realm/qop from the router-injected domain.
- The verifier (`SIP.Msg.Ops.check_authrequest/3`) branches on the presence of
  `qop` in the client response: `qop=auth` → the nc/cnonce form + `NonceCache`
  check; no `qop` → the RFC 2069 form. `Kelixip.Nonce.validate/2` replaces the
  stateful `SIP.Dialog.check_nonce/2` lookup.

### 7.4 Secret source & realm

- **realm = the domain name** (one realm per domain), injected by the Router.
- **secret via `subscriber_db`** in **HA1** form (`MD5(user:realm:password)`),
  `password_format = "ha1" | "plain"` (default `ha1`) — mirrors Kamailio's
  `subscriber` table. The module only does the lookup; **401/accept/reject stays
  in the script.**

### 7.5 Removal / deprecation

`SIP.DialogImpl.Nonce` (stateful map + purge timer) and
`SIP.Auth.generate_nonce/0` are **removed** once callers move to
`Kelixip.Nonce`. The nonce format is opaque to clients (they echo it) so the
switch is transparent — no interop risk (spec §11.1). `elixipp`'s UAC digest
already tolerates any nonce, so tests are unaffected.

---

## 8. Loadable modules (.beam)

Spec §5. A module is a stateful OTP service **plus** stateless facades imported
by scripts.

### 8.1 `Kelixip.Module` behaviour

As specified (§5.1): `validate_config/1`, `child_spec/2`, `describe/0`, optional
`reload/2`. `Kelixip.ModuleSupervisor` (`:one_for_one`) starts one child per
`[module.<name>]` block; the TOML `<name>` is the registered name used by facade
resolution.

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

- **`subscriber_db`** — MariaDB/MySQL access reading the `subscriber` table for
  registrar **auth** (HA1 lookup, §7.4). Needs a MySQL driver dep
  (`myxql`, §13). A connection pool is the module's supervised service; facades
  (`lookup_ha1/2`, …) resolve it by name.
- **`radius_billing`** — RADIUS billing. Dep or hand-rolled UDP RADIUS client.

Facade import in a script: `import Kelixip.Module.SubscriberDB, only: [lookup_ha1: 2]`
— the facade module is a thin stateless wrapper that finds the service by name
and delegates (spec §5).

> Open (spec): `.beam` **code-reload versioning** / OTP `code_change`-style state
> migration is left unspecified — flagged §16.

---

## 9. Media server pool

Spec §6. Extends the current single-`:mediaserver` config to a pool.

### 9.1 `Kelixip.MediaPool`

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

### 10.1 `Kelixip.Control`

The single source of truth — every operation is a function here; neither frontal
holds business logic. Surface (spec §9.3):

| Function | R/W | CLI | REST |
|---|---|---|---|
| `monitor/0` | R | `kelixip monitor` | `GET /scenarios` |
| `registrations/1` | R | `kelixip regs [aor]` | `GET /registrations` |
| `status/0` | R | `kelixip status` | `GET /status` |
| `unregister/2` | W | `kelixip unregister <aor> [contact]` | `DELETE /registrations/<aor>` |
| `shutdown_scenario/1` | W | `kelixip stop <id>` | `POST /scenarios/<id>/shutdown` |
| `reload_script/2` (notify?) | W | `kelixip reload-script [--notify] <name…>` | `POST /scripts/reload[?notify=1]` |
| `reload_domains/0` | W | `kelixip reload-domains` | `POST /domains/reload` |
| `module_reload/1` | W | `kelixip module reload <name>` | `POST /modules/<name>/reload` |
| `mediaserver_toggle/2` | W | `kelixip mcu <name> on\|off` | `POST /mediaservers/<name>` |
| `set_log_level/1` | W | `kelixip log-level <lvl>` | `PUT /log/level` |
| `graceful_shutdown/0` | W | `kelixip graceful-shutdown` | `POST /graceful-shutdown` |

`monitor/0` reuses the in-memory store already feeding `elixipp --monitor`
(`SIP.Scenario.Monitor`). `registrations/1` reads `Kelixip.Registrar.Store`.
`status/0` aggregates uptime + counters + pool state.

### 10.2 The `kelixip` CLI

A **separate escript** (`kelixip`), distinct from `elixipp`. It is a *local
client* of the running node over **Erlang distribution / RPC**: it reads
`server.node_name` + the cookie, does `:rpc.call(node, Kelixip.Control, fun, args)`,
and renders the result (reusing the Owl table rendering for `monitor`). It runs
no SIP stack. Because it only calls `Kelixip.Control`, parity with REST is
automatic — adding a command = add the function + wire two thin frontals.

### 10.3 REST API (`Kelixip.ControlAPI`)

A Plug router served by **Bandit** (§13), one endpoint per `Kelixip.Control`
function. Defaults from `[control_api]`: **loopback + token auth** (Bearer token
compared in constant time). `auth = "mtls"` enables client-cert verification for
network exposure; `"none"` for trusted local only. **Basic auth model = a single
admin token** (all commands, all domains); per-domain RBAC is roadmap (spec §10).

---

## 11. Observability

Spec §8.2. `:telemetry` events emitted at key points, exported as Prometheus.

- **`Kelixip.Metrics`** attaches telemetry handlers and runs
  `TelemetryMetricsPrometheus` (§13), serving `/metrics` + `/health` on the
  `[metrics]` port (separate from control API, loopback by default). `/health`
  returns liveness (node up) + readiness (config loaded, listeners bound) for
  systemd / orchestrators.
- **Events** emitted from the router, registrar store, transaction layer,
  transports, media pool. All key metrics carry a **`domain` label** (spec §8.2):
  registrations gauge / REGISTER rate / auth failures; active dialogs / call
  attempts-answered-failed / setup time; transactions by method + response class;
  transport messages in/out by proto + active WSS/TCP connections; media sessions
  per MCU + MCU up/down; system `503` (over `max_calls`), parse errors, timer
  B/F timeouts.
- Instrumentation is added at the framework seams the events describe (mostly the
  Router, `Kelixip.Registrar.Store`, `SIP.Transac`, transports). The `--monitor`
  TUI and per-instance PlantUML diagrams remain complementary debug tools.

---

## 12. Packaging

Spec §7. Delivered as an **OTP release** (`mix release`, embedded ERTS), not an
escript — a properly managed service.

- `mix.exs`: add a `releases:` section (`kelixip`) with
  `mod: {Kelixip.Application, []}` active for the release, `include_erts: true`,
  a `rel/env.sh` exporting `RELEASE_NODE` (= `server.node_name`) and the cookie,
  and `TOML config path` from an env var.
- **FHS layout** (spec §7): `/etc/kelixip/{config.toml,domains.toml,tls/}`,
  `/usr/share/kelixip/` (default scripts, package data), `/usr/lib/kelixip/`
  (release + `modules/`), `/var/lib/kelixip/` (mutable scripts, future usrloc),
  `/var/log/kelixip/` (if stdout redirected; else syslog).
- **systemd unit**: non-privileged `kelixip` user/group, `ExecStart` = release
  `start`, `ExecStop` = `Kelixip.Control.graceful_shutdown` (drain, §2.2),
  `TimeoutStopSec` > drain deadline, `epmd` managed by the release.
- **Platforms**: Alma Linux 9 (rpm) + Ubuntu (deb). Build via a release →
  fpm/`rpmbuild`/`dpkg-deb` step (CI). `module_dir` must be `root`-owned,
  non-writable by the service (security, spec §11 — loading `.beam` = executing
  code).

Launch: `kelixip --config /etc/kelixip/config.toml [--stdout]`.

---

## 13. New dependencies

| Dep | Purpose | Notes |
|---|---|---|
| `toml` | parse `config.toml` / `domains.toml` | pure Elixir, no NIF, release-safe |
| `bandit` + `plug` | REST control API + `/metrics` + `/health` HTTP | pure Elixir; `req` (present) is client-only |
| `telemetry`, `telemetry_metrics`, `telemetry_metrics_prometheus` | metrics | standard Elixir observability stack |
| `myxql` | `subscriber_db` MariaDB/MySQL driver | only needed when that module is built |
| syslog backend (`logger_syslog` or erlang `:logger` syslog handler) | `log.target = "syslog"` | evaluate vs journald-only |

All are pure-Elixir/BEAM (no C NIFs that would complicate the release) except the
MySQL driver, which is fine in a release. RADIUS for `radius_billing` can be a
hand-rolled UDP client (no heavy dep).

---

## 14. Migration & compatibility work

Flagged in the spec as **"à faire"**:

1. **Pull domain config out of UAS INVITE scenarios** (spec §4, §14). Today
   `scenarios/uas_invite.exs` carries its own `config domains:` and the factory
   reads it. With kelixip's declarative dispatch the domain + routing come from
   `domains.toml`; the script keeps only call logic. Action: the Router injects
   the domain into the instance context; scripts stop declaring `domains:`. Keep
   `elixipp`'s `ScenarioUAS` path working (it still reads `config domains:`) — the
   two dispatchers coexist.
2. **Nonce migration** (§7.5): remove `SIP.DialogImpl.Nonce` +
   `SIP.Auth.generate_nonce`, switch the challenge/verify path to
   `Kelixip.Nonce`. Update `scenarios/uas_register.exs`'s
   `check_registration_auth/3` (which currently calls `SIP.Dialog.check_nonce/2`)
   to the stateless validate.
3. **`qop=auth` in `SIP.Auth`** (§7.3) — additive, keeps RFC 2069 fallback.
4. **Per-listener certs** (§3.1) — thread cert/key through listener opts.
5. **Supervise the stack** (§2) — registries/ConfigRegistry/listeners as
   children; `Runner.bootstrap_stack/0` stays for `elixipp`/tests.
6. **Connected-transport response routing / send-over-flow** (§6.3) — the open
   item from `uas_scenario_design.md` §8.1.

Guiding rule: **kelixip is additive**. The `elixipp` tool and existing tests must
keep passing; framework changes are backward-compatible (fallbacks, opts with
defaults).

---

## 15. Phased delivery plan

Ordered so each phase is independently testable and the framework changes land
before the features that need them.

| Phase | Deliverable | Depends on |
|---|---|---|
| **P0 — OTP skeleton** | `Kelixip.Application` + supervision tree; supervise registries/ConfigRegistry/listeners; `mix release` builds; boots with an empty config | — |
| **P1 — Config** | `toml` dep; `Kelixip.Config` (infra→app env, per-listener certs); `Kelixip.Domains` + `Kelixip.DialPlan` compiler; atomic reload plumbing (no CLI yet) | P0 |
| **P2 — Dispatch** | `Kelixip.Router` (domain→function→script, 404/405/503); wire as ConfigRegistry processing module; `Kelixip.ScriptRegistry` + load-time contract check; extract shared factory machinery | P1 |
| **P3 — Registrar + usrloc** | `Kelixip.Registrar.Store` (AOR-keyed, received+flow+Path); NAT/flow inbound routing; send-over-flow framework hook; registrar facade for the DSL | P2 |
| **P4 — Auth** | `Kelixip.Secret` + `Kelixip.Nonce` (stateless HMAC) + `NonceCache`; `SIP.Auth` `qop=auth` extension; realm=domain wiring; remove stateful nonce | P3 |
| **P5 — Modules** | `Kelixip.Module` behaviour + `ModuleSupervisor` + facade resolution; `subscriber_db` (HA1 lookup) feeding P4 auth; `radius_billing` | P1 (config), P4 (auth uses it) |
| **P6 — Media pool** | `Kelixip.MediaPool` (round-robin, health-check, failover, toggle) over the Mendooze adapter | P0 |
| **P7 — Control layer** | `Kelixip.Control` (all verbs); `kelixip` escript over RPC; versioned/notify reload; graceful shutdown | P2–P6 |
| **P8 — REST API** | `bandit`+`plug` frontal; token/mtls auth; parity with CLI | P7 |
| **P9 — Observability** | telemetry events + Prometheus exporter; `/metrics` + `/health`; per-domain labels | P2+ |
| **P10 — Packaging** | rpm (Alma 9) + deb (Ubuntu); systemd unit; FHS install; graceful stop wired to systemd | P0–P9 |

P3+P4 (registrar + auth) are the functional core of "basic"; P0–P2 are the
enabling infrastructure; P7–P10 make it a product.

---

## 16. Open questions

1. **Shared factory vs Router-owned pooling** (§4.2) — extract a
   `Kelixip.InstancePool` shared with `Elixip.ScenarioUAS`, or have the Router
   own per-(domain,function) slots and leave `ScenarioUAS` for `elixipp` only?
   Affects where per-domain quota lives.
2. **`Kelixip.Module` contract** (memory: "forks ouverts sur le contrat behaviour
   module") — is `describe/0`'s `exports` list *enforced* (facade import checked
   against it) or purely informational? And the `.beam` code-reload / state
   migration story (spec §5 open item, §8.3).
3. **Script version identity** (§5.1) — recompile into version-suffixed module
   names, or keep one module name and rely on `:code` purge/refcount? The former
   is cleaner for true concurrent versions but pollutes the atom table over many
   reloads.
4. **Syslog backend choice** (§13) — dedicated dep vs erlang `:logger` syslog
   handler vs journald-only (systemd captures stdout anyway).
5. **usrloc query shape** (§6.1) — ETS `:set` keyed by `{domain, aor}` with a
   binding list value, vs `:bag` with one row per binding. Impacts
   `registrations` filtering/pagination for large deployments.
6. **`send-over-flow`** (§6.3) — confirm a `%SIP.Uri{tp_pid: pid}` fully
   short-circuits `Selector` for out-of-dialog inbound routing, or whether the
   transaction layer needs an explicit "reply/route over this transport" path.
