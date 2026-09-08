# kelixip admin web UI — architecture note

Status: **exploratory** (2026-07-26, push mechanism decided 2026-08-21, domain
counters push decided 2026-09-07, registration detail push + admin-traced
destructive actions decided 2026-09-08). Captures the locked decisions for a
real-time web admin UI over kelixip. `Kelix.Control.subscribe_monitor/1`,
`subscribe_domain_counters/1`, `subscribe_registrations/2`, and the `admin`
argument on `unregister/4` / `shutdown_scenario/2` are implemented; the rest of
this note is still ahead of the code.

The app is **kelescope** (`github.com/neutrino38/kelescope`, separate repo). It
implements this note; its own Phase 1 (monitor + stop) plan lives in
`docs/conception/phase1-monitoring/SPEC.md` in that repo.

## Goal

A pretty, real-time admin console for a running kelixip node: view status,
scenarios in progress, registrations and media-pool health, and drive the same
write actions as `kelictl` (reload, toggle, unregister, stop, graceful-shutdown) —
with **live updates** (no manual refresh). Phoenix LiveView is the intended stack.

## Decision 1 — a separate app, not integrated into kelixip

The UI is a **standalone Phoenix app** (its own OTP release, its own deps, its
own repo — `kelescope`), **not** compiled into the kelixip SIP server and
**not** depending on `:elixip2` — it talks to kelixip over the network/cluster,
never in-process.

Rationale (same "each artifact carries only its own deps" doctrine as the
umbrella, §12.0, applied across a repo boundary instead of an app boundary):

- **Deps** — Phoenix/LiveView pulls a large tree (phoenix, plug, esbuild,
  tailwind, websock). It must not bloat the lean SIP server release.
- **Blast radius** — a crash or memory issue in the web tier must never touch the
  signaling plane. Separate OS process + release = fault isolation.
- **Lifecycle** — redeploy/restart the UI without touching call processing.
- **Attack surface** — the UI is network-exposed; keeping it off the SIP node
  reduces the signaling plane's exposure.

## Decision 2 — real-time over Erlang distribution, REST for outsiders

Because the UI is itself a BEAM node, **cluster it with kelixip** (same cookie —
the mechanism `kelictl` already uses; `rel/env.sh.eex` already starts kelixip
distributed). Then:

- **Reads + actions** — call `Kelix.Control` by RPC for the initial load
  (`status/0`, `monitor/0`, `registrations/1`) and for every write verb (reload,
  toggle, unregister, stop, …). Same functions as `kelictl`, zero duplication.
- **Live updates (push)** — the REST API (P8) is request/response (pull), so a
  REST-only UI would have to poll. Clustered, kelixip can **broadcast events** the
  LiveView receives as a push and re-renders on. Reserve **REST for non-BEAM
  clients** (scripts, third-party dashboards, other languages); the LiveView
  barely needs it.

### Push mechanism (decided 2026-08-21): subscriber list + `send/2`, no new dependency

Elixip has no Phoenix dependency today (checked: no `phoenix*` in `mix.lock`,
see `liveview-adapter.md`) and must stay that way. A distributed
`Phoenix.PubSub`, considered earlier for this event surface, would break that
doctrine for a single current consumer (kelescope's dashboard). Instead, reuse
the pattern already in the codebase:

- `Kelix.Mod.Registrar.subscribe_register_event/2` → `{:registrar, event,
  "aor@domain"}` (a pid subscribes to registration changes; state `subs: %{key
  => MapSet(pid)}`, notified by plain `send/2`) — the pattern to copy.
- `SIP.Scenario.Monitor` (`apps/elixip2/lib/elixipp/SIPScenarioMonitor.ex`) is
  the scenarios-in-progress store already feeding `--monitor` / `kelictl
  monitor`, via `calls/0` (pull-only today). Scenarios already push their state
  into it in real time (`SIPScenarioRunner.ex`'s `report/5`, `note_stay/4`,
  `note_command/2`, `note_account/1`, all `GenServer.cast`) — the push stops
  dead at `SIP.Scenario.Monitor`'s boundary; nothing relays it further.
- **What to add**: a subscriber list (`subs: MapSet(pid)`) in
  `SIP.Scenario.Monitor`'s state, plus `subscribe/1` / `unsubscribe/1`. After
  each successful `update/3` (state/event/command changed) and each `clear/1`
  (scenario ended), `send/2` the changed row (or the clear) to every
  subscriber — a remote pid works transparently once nodes are clustered.
  `Kelix.InstancePool` needs the same treatment for a scenario's *appearance*
  (`accept/4`) so a new row can show up before its first FSM report.
- **Expose it through `Kelix.Control`**, not directly: add
  `Kelix.Control.subscribe_monitor/1` (and `unsubscribe_monitor/1`) as the
  sanctioned entry point, consistent with the doctrine that `kelictl` and the
  REST API only ever talk to `Kelix.Control` (`control.ex`, module doc). The
  subscribing pid gets the current full snapshot (equivalent to `monitor/0`)
  as the call's return value, then row-level `send/2` updates as they happen —
  no polling on the kelescope side.

### Domain counters push (decided 2026-09-07)

kelescope's domain list (`domains/0`'s `active_calls` / `registrations`) had no
push counterpart: a domain's counters only changed on the next manual refresh.
Same subscriber-list-plus-`send/2` mechanism as scenario monitoring, split
across the two surfaces that actually hold each count:

- **Active calls** — `Kelix.InstancePool` already keeps `per_domain` (§4.2). It
  gained its own `counter_subs: MapSet(pid)` (kept apart from `monitor_subs`: a
  subscriber may want one push without the other) plus
  `subscribe_domain_counters/1` / `unsubscribe_domain_counters/1`. Every
  `accept/4` and every instance's `:DOWN` now also `send/2`s
  `{:kelix_domain_counter, domain, :active_calls, count}`.
- **Registrations** — `Kelix.Mod.Registrar` gained the same `count_subs` plus
  the same two functions, on the model of `subscribe_register_event/2`, but
  subscribing to every domain at once rather than one AOR: kelescope's domain
  list wants all of them live, and a per-AOR subscription for every AOR of
  every domain would be the wrong granularity to manage. `notify/4` (already
  called on every registered/unregistered/expired/disconnected transition)
  additionally `send/2`s `{:kelix_domain_counter, domain, :registrations,
  count}`, the count read off the domain's own ETS table size — cheap, and
  exactly what `Kelix.Control.domain/1` counts.
- **Exposed through `Kelix.Control`**, as one call: `subscribe_domain_counters/1`
  subscribes to both (the registrar half through `Kelix.ModuleRegistry.facade/4`,
  a no-op when the module is not loaded — no domain ever registers, so nothing
  is missed) and returns the current snapshot (`domains/0`'s shape); the pid
  then receives `{:kelix_domain_counter, domain, :active_calls | :registrations,
  count}` per counter change. `unsubscribe_domain_counters/1` stops both.

### Registration detail push + admin-traced destructive actions (decided 2026-09-08)

Two gaps `subscribe_domain_counters/1` deliberately left open (it pushes a
*count*, not the AORs behind it) and one the write verbs never had at all
(kelescope now asks who is doing something before it does it):

- **Registration detail push** — kelescope's registrations panel wants to open
  a domain and see it update live, not re-fetch on every AOR change.
  `Kelix.Mod.Registrar` gained `detail_subs: %{domain => MapSet(pid)}` (one
  domain at a time, unlike `count_subs`: kelescope only ever has one panel open,
  and the alternative — every domain's full detail to every subscriber — is the
  wrong granularity for something this much bigger than a count) plus
  `subscribe_registrations/2` / `unsubscribe_registrations/2`. `notify/4` now
  also renders and `send/2`s `{:kelix_registrations, domain, {:upsert,
  %{domain, aor, contacts}}}` when the AOR still has a live contact, or
  `{:remove, aor}` when its last one is gone — skipped entirely when nobody
  subscribed to that domain, so a domain nobody is watching costs nothing
  beyond the existing `count_subs` push. The render duplicates `Kelix.Control`'s
  contact rendering (`uri`/`source`/`transport` strings) rather than sharing it:
  the core cannot reference this module's struct at compile time (§16.12), so
  it renders through `Map.get` structurally; this side owns `%Contact{}`
  directly and renders it as itself. Exposed through
  `Kelix.Control.subscribe_registrations/2`, returning the same
  `%{domain, registrations}` entry `registrations/1` does.
- **Admin-traced `unregister` and `shutdown_scenario`** — kelescope confirms
  these two destructive actions in a popup that requires a name before sending
  the request, so the action can be traced back to a person in kelixip's own
  logs — kelictl and the REST frontal have no such identity to offer and are
  unaffected: `unregister/4` and `shutdown_scenario/2` are new arities, each
  calling the existing 3-/1-arity verb unchanged and then `Logger.info`-ing the
  domain/AOR/scenario id, the admin name and the outcome — kelictl/REST callers
  stay on the untraced arity, so their behaviour does not change either.
  Nothing here is authentication — `admin` is free text, exactly what kelescope
  collected in its popup — only a trace of who *said* they did it; real identity
  is `docs/design/kelixip_liveview.md`'s own open AuthN/Z question, not
  resolved by this.

## Security caveat (the one real risk)

Erlang distribution = **full trust between nodes** (shared cookie; RPC can call
anything). A compromised web node ⇒ full access to the SIP node. Therefore:

- Run the cluster on a **trusted management network** (or use **TLS
  distribution**).
- If the UI must ever live in a less-trusted zone, fall back to **REST + token /
  mTLS** (§10.3 auth boundary) and add **SSE/WebSocket streaming** to the REST
  frontal for real-time — that is plan B, not the default.

## Summary

`kelescope`, separate repo and release, clustered with kelixip like `kelictl`;
reads/actions via `Kelix.Control` RPC; **live updates via a subscriber list +
`send/2`** on `SIP.Scenario.Monitor` / `Kelix.InstancePool` (scenarios,
`subscribe_monitor/1`), on `Kelix.InstancePool` / `Kelix.Mod.Registrar` (domain
counters, `subscribe_domain_counters/1`), and on `Kelix.Mod.Registrar` alone
(one domain's registration detail, `subscribe_registrations/2`) — all three
implemented; `unregister/4` and `shutdown_scenario/2` trace an admin name in
kelixip's own logs, also implemented; REST (P8) reserved for external clients;
cluster only over a trusted network / TLS distribution.

## Open questions

- AuthN/Z for the UI itself (operators) — distinct from the node-trust question.
- Does the UI ever need to be reachable without clustering (→ REST + streaming)?
