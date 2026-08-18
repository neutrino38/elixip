# FSL Elixir improvements: `stay` and `goto back`

Status: implemented. The reference is [`FSL.md`](../../FSL.md); this document
keeps the design rationale.

The two features below were designed for FSL/TS (`finite-state-language` project,
`spec/fsl-js-ts.md`), the TypeScript sibling of FSL.
The first one (`stay`) proved valuable enough during the FSL/TS design
review to be backported here. Keeping the two languages' transition models
aligned is an explicit goal — hence the choice, on the open point below, of the
FSL/TS behaviour: `stay` does not re-arm the state timeout.

## Background you need

- FSL is documented in [`FSL.md`](../../FSL.md) at the repo root.
- The macros live in `apps/elixip2/lib/dsl/SIPScenario.ex`; the FSM loop that
  interprets their `{:goto, …}` / `{:terminal, …}` control tuples lives in
  `apps/elixip2/lib/dsl/SIPScenarioRunner.ex`.

## Feature 1 — `stay`: handle an event without re-entering the state

### Problem

With `goto` alone, an `on_events` clause must end with a transition. Consuming
an event and keeping the wait means writing `goto loop` — which re-executes the
**whole state body**, replaying its side effects (re-sending a request, re-arming
work). Nothing says "I handled this event; keep listening, don't redo the state's
entry work".

Typical need (from real UI/call flows): answering an in-dialog MESSAGE or a
keepalive OPTIONS inside `call_established` without re-running the state
body; a UI mute toggle during a call.

### Specified semantics (aligned with FSL/TS)

- `stay` / `stay("desc")` — usable **only** inside an `on_events` clause;
  anywhere else it is a compile-time error where detectable, and a clean
  scenario failure otherwise.
- The FSM stays in the current state, the state body is **not** re-executed,
  and the scenario goes back to waiting **on the same `on_events`**.
- The transition is logged like a goto (`event: (state) -> (state) "desc"`),
  with the inferred event type, and reported to `SIP.Scenario.Monitor` so the
  live view shows the event was consumed.
- `lasterr` contract: like `goto`, `stay` must check `sip_ctx.lasterr` and
  abort with `scenario_failure` if not `:ok`.
- **`after` timer**: the timeout is the deadline of the *wait*, not of each
  event. `stay` does not re-arm it — the FSL/TS behaviour, chosen for
  alignment. Otherwise a keepalive answered every 10 s would hold a 30 s answer
  timeout open forever, which is a bug wearing a feature's clothes.

### How it is built

`on_events` expands to a `receive` wrapped in a self-calling closure, so `stay`
re-enters the wait without leaving the state function:

```elixir
fsl_wait = fn fsl_wait, var!(sip_ctx), fsl_deadline ->
  receive do
    # instrumented clauses
  after
    SIP.Scenario.remaining_timeout(fsl_deadline) -> ...
  end
end
fsl_wait.(fsl_wait, var!(sip_ctx), SIP.Scenario.deadline(30_000))
```

The closure and deadline variables are `Macro.unique_var/2`, so nested
`on_events` do not capture each other's.

`stay` is **rewritten in the clause AST** into a call back into that closure,
rather than returning a `{:stay, …}` descriptor the clause result is then
matched against. The descriptor version is the obvious design and it does not
survive contact with the compiler: Elixir infers the exact type each clause
returns, so in the normal case — no clause stays — the `{:stay, …}` branch is
provably dead and the compiler says so, once per state of every scenario. Nine
warnings for the two built-in scenarios alone.

Consequences of rewriting rather than dispatching:

- the recursion stops at a nested `on_events` / `receive`, and never walks the
  `after` body: a `stay` there belongs to another wait, or to none;
- `stay` outside an `on_events` is caught at compile time (`state/2` and
  `on_shutdown/1` walk their body), and the runner still fails the scenario on a
  `{:stay, …}` tuple that reaches it from a plain `receive` or an `after` body;
- `stay` becomes a reserved word inside a state body, like `next` and `loop`.

The injected shutdown and media-death clauses leave the state by construction,
so they are instrumented without the rewrite.

## Feature 2 — `goto back`: return to the previous state

### Problem

Some flows are "detour and come back" (fetch something over HTTP, show a
confirmation, answer a challenge). Without `back`, the detour state hardcodes
its return target, so it cannot be shared between callers.

### Specified semantics

- `goto back` / `goto back, "desc"` — transition to the state the FSM was in
  **before it entered the current state**.
- `loop` and `stay` do **not** change what `back` points to (re-entering a
  state is not "coming from" it).
- Two consecutive `goto back` toggle between two states (A→B, back→A,
  back→B): `back` is one slot, not a stack. A stack is explicitly out of scope
  (YAGNI until a scenario needs it).
- `goto back` from `initial_state` (or when no previous state exists) aborts
  with `scenario_failure("goto back with no previous state")`.
- Terminal transitions (`scenario_success/failure/aborted`) ignore the slot.

### How it is built

- `%SIP.Context{}` carries a `laststate` field (default `nil`), runner-owned
  like `currentstate`.
- `goto/3` maps the AST atom `back` to the pseudo-target `:__back__`, the way
  `next` and `loop` are already reserved.
- The runner writes `laststate` in `enter/3`, called on every transition, and
  only when the target differs from the state being left — so `goto loop`, an
  explicit self-goto and `stay` leave the slot alone.

## Tests

`apps/elixip2/test/scenario_stay_back_test.exs` covers both features: a state
body run once across three consumed events, the shutdown control message honoured
from inside a stay loop, the deadline not re-armed, the monitor seeing the stays,
`stay` outside an `on_events` refused at compile time, `goto back` returning
through a detour that also loops and stays, and `goto back` from `initial_state`
failing cleanly.

## Non-goals

- No mailbox-semantics change: unmatched messages already stay in the
  process mailbox (native selective receive) — nothing to do here, unlike
  FSL/TS which had to build a pending queue in its engine.
- No `back` stack, no history states, no hierarchical states.
