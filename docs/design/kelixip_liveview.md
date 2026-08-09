# kelixip admin web UI — architecture note

Status: **exploratory** (2026-07-26). Captures the two locked decisions from an
early design discussion for a real-time web admin UI over kelixip. No code yet.

> **App name is TBD.** This note uses the placeholder **`kelixweb`** for the app /
> release; pick the real name before scaffolding and update this doc.

## Goal

A pretty, real-time admin console for a running kelixip node: view status,
scenarios in progress, registrations and media-pool health, and drive the same
write actions as `kelictl` (reload, toggle, unregister, stop, graceful-shutdown) —
with **live updates** (no manual refresh). Phoenix LiveView is the intended stack.

## Decision 1 — a separate app, not integrated into kelixip

The UI is a **standalone Phoenix app** (its own OTP release, its own deps),
**not** compiled into the kelixip SIP server. Preferably a new umbrella app
(`apps/kelixweb`) to share the monorepo tooling, but with its **own release** and
**not** depending on `:elixip2` — it talks to kelixip over the network/cluster,
never in-process.

Rationale (consistent with the umbrella philosophy, §12.0 — each artifact carries
only its own deps):

- **Deps** — Phoenix/LiveView pulls a large tree (phoenix, plug, esbuild,
  tailwind, websock). It must not bloat the lean SIP server release.
- **Blast radius** — a crash or memory issue in the web tier must never touch the
  signaling plane. Separate OS process + release = fault isolation.
- **Lifecycle** — redeploy/restart the UI without touching call processing.
- **Attack surface** — the UI is network-exposed; keeping it off the SIP node
  reduces the signaling plane's exposure.

## Decision 2 — real-time over Erlang distribution + PubSub, REST for outsiders

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

### Primitives to build on

- `Kelix.Mod.Registrar.subscribe_register_event/2` → `{:registrar, event,
  "aor@domain"}` (a pid subscribes to registration changes) — already exists.
- `SIP.Scenario.Monitor` — the scenarios-in-progress store already feeding
  `--monitor` / `kelictl monitor`.
- **P9 (observability)** telemetry is the natural consolidated event source
  (registrations, call attempts/answers, MCU up/down, counters). A small
  distributed **`Phoenix.PubSub`** over those telemetry events, which the LiveView
  `subscribe`s to, is the clean push path. *(This event/PubSub surface does not
  exist yet — it is the main thing to add on the kelixip side for this UI.)*

## Security caveat (the one real risk)

Erlang distribution = **full trust between nodes** (shared cookie; RPC can call
anything). A compromised web node ⇒ full access to the SIP node. Therefore:

- Run the cluster on a **trusted management network** (or use **TLS
  distribution**).
- If the UI must ever live in a less-trusted zone, fall back to **REST + token /
  mTLS** (§10.3 auth boundary) and add **SSE/WebSocket streaming** to the REST
  frontal for real-time — that is plan B, not the default.

## Summary

`apps/kelixweb` (name TBD), separate release, clustered with kelixip like
`kelictl`; reads/actions via `Kelix.Control` RPC; **live updates via a PubSub
event stream** (to be added, telemetry-sourced with P9); REST (P8) reserved for
external clients; cluster only over a trusted network / TLS distribution.

## Open questions

- App name (placeholder `kelixweb`).
- Shape of the kelixip-side event/PubSub surface (couple it to P9 telemetry?).
- AuthN/Z for the UI itself (operators) — distinct from the node-trust question.
- Does the UI ever need to be reachable without clustering (→ REST + streaming)?
