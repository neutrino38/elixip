# kelixip admin web UI — architecture note

Status: **exploratory** (2026-07-26, push mechanism decided 2026-08-21). Captures
the locked decisions for a real-time web admin UI over kelixip. No code yet on
the kelixip side.

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
`send/2`** on `SIP.Scenario.Monitor` / `Kelix.InstancePool`, exposed through
new `Kelix.Control.subscribe_monitor/1` (to be added — no code yet); REST (P8)
reserved for external clients; cluster only over a trusted network / TLS
distribution.

## Open questions

- AuthN/Z for the UI itself (operators) — distinct from the node-trust question.
- Does the UI ever need to be reachable without clustering (→ REST + streaming)?
