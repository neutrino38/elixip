# FSL Elixir improvements: `stay` and `goto back`

Status: proposal — 2026-08-15. Not yet implemented.

This is a **self-contained implementation prompt** for a future session.
The two features below were designed for FSL/TS (`finite-state-language` project,
`spec/fsl-js-ts.md`), the TypeScript sibling of this DSL.
The first one (`stay`) proved valuable enough during the FSL/TS design
review to be backported here. Keeping the two languages' transition models
aligned is an explicit goal.

## Background you need

- The DSL is documented in [`DSL.md`](../../DSL.md) at the repo root.
- The macros live in `apps/elixip2/lib/dsl/SIPScenario.ex`:
  - `state/2` (~line 156) generates one function `__state_<name>/1` per
    state, taking `sip_ctx`, with rescue/catch wrappers.
  - `goto/3` (~line 219) does **not** transition by itself: it returns a
    control tuple `{:goto, target, desc, event_type, sip_ctx}` (or
    `{:terminal, ...}` when `lasterr` is set) that the **runner** interprets.
  - `on_events/1` (~line 251) compiles to a plain `receive` after
    instrumenting the clauses (event-type inference, auto-store of UAS
    requests, injection of the cooperative-shutdown clause and of the
    media-server-death clause).
- The runner (look for the module that calls the `__state_*` functions and
  pattern-matches the `{:goto, ...}` tuples — grep for `:goto` under
  `apps/elixip2/lib/`) resolves `next` / `loop` / `:__shutdown__` and
  dispatches to the target state function.

## Feature 1 — `stay`: handle an event without re-entering the state

### Problem

Today an `on_events` clause **must** end with a transition. To consume an
event and keep waiting in the same state, scenarios write `goto loop` — but
`goto loop` re-executes the **whole state body**, replaying its side effects
(re-sending a request, re-arming work). There is no way to say "I handled
this event; keep listening, don't redo the state's entry work".

Typical need (from real UI/call flows): answering an in-dialog MESSAGE or a
keepalive OPTIONS inside `call_established` without re-running the state
body; a UI mute toggle during a call.

### Specified semantics (aligned with FSL/TS)

- `stay` / `stay("desc")` — usable **only** inside an `on_events` (or
  `receive`) clause; using it in a plain state body is a compile-time error
  if detectable, otherwise a runtime failure with a clear message.
- The FSM stays in the current state, the state body is **not** re-executed,
  and the scenario goes back to waiting **on the same `on_events`**.
- The transition is logged like a goto (`event: (state) -> (state) "desc"`),
  with the inferred event type, and reported to `SIP.Scenario.Monitor` so the
  live view shows the event was consumed.
- `lasterr` contract: like `goto`, `stay` must check `sip_ctx.lasterr` and
  abort with `scenario_failure` if not `:ok`.
- **`after` timer**: document the chosen behaviour. Re-entering a `receive`
  restarts its `after` — that is acceptable *if documented* (note: FSL/TS
  chose the opposite: `stay` does not re-arm the state timeout; a strict
  alignment would require tracking the deadline and passing a reduced
  `after` on re-entry — a `Process.send_after`-based deadline is one way).

### Implementation sketch

`on_events` currently expands to `{:receive, [], [blocks]}`. To support
re-entry it can instead expand to a recursive closure:

```elixir
var!(fsl_wait) = fn fsl_wait, var!(sip_ctx) ->
  receive do
    # instrumented clauses; a clause whose body evaluates to
    # {:stay, desc, type, ctx2} recurses: fsl_wait.(fsl_wait, ctx2)
  after ...
  end
end
var!(fsl_wait).(var!(fsl_wait), var!(sip_ctx))
```

The clean way is to have `stay` return a `{:stay, desc, event_type, sip_ctx}`
tuple (same family as `{:goto, ...}`) and wrap **each clause body** so that a
`:stay` result recurses into the closure while any other result propagates
out (it already propagates to the runner today). Points of care:

- the injected shutdown clause and media-death clause must keep working;
- the auto-store instrumentation must run again on each received event;
- the updated `sip_ctx` carried by the `:stay` tuple must be the one passed
  to the recursive call (appdata mutations survive);
- nested `on_events` in one state body: each gets its own closure variable —
  use a hygienic unique var, not a fixed name, if nesting is allowed.
- bare `receive` users are unaffected: `stay` is only guaranteed inside
  `on_events`.

## Feature 2 — `goto back`: return to the previous state

### Problem

Some flows are "detour and come back" (fetch something over HTTP, show a
confirmation, answer a challenge) and today the detour state must hardcode
its return target, so it cannot be shared between callers.

### Specified semantics

- `goto back` / `goto back, "desc"` — transition to the state the FSM was in
  **before it entered the current state**.
- `loop` and `stay` do **not** change what `back` points to (re-entering a
  state is not "coming from" it).
- Two consecutive `goto back` toggle between two states (A→B, back→A,
  back→B): document this — `back` is one slot, not a stack. A stack is
  explicitly out of scope (YAGNI until a scenario needs it).
- `goto back` from `initial_state` (or when no previous state exists) aborts
  with `scenario_failure("goto back with no previous state")`.
- Terminal transitions (`scenario_success/failure/aborted`) ignore the slot.

### Implementation sketch

- Add a `laststate` field to `%SIP.Context{}` (default `nil`). Like
  `currentstate`, it is runner-owned: scenarios must not set it manually
  (update the "do not modify" list in `DSL.md`'s sip_ctx section).
- The runner, when resolving `{:goto, target, ...}`: if `target != current`
  (i.e. not a `loop`), set `laststate = currentstate` before switching.
- In `goto/3` (`SIPScenario.ex`), treat the AST atom `back` like `next` and
  `loop` are treated today (see `state_atom/1` and the runner's resolution
  of those pseudo-targets): emit a `:__back__` pseudo-target resolved by the
  runner from `sip_ctx.laststate`.

## Acceptance criteria

1. `DSL.md` documents both macros (semantics above, including the `after`
   behaviour of `stay` and the one-slot nature of `back`).
2. New unit tests (pattern: existing scenario tests under
   `apps/elixip2/test/`):
   - `stay` consumes an event without re-running the state body (assert via
     a side-effect counter in appdata);
   - `stay` then a later `goto` still transitions correctly;
   - shutdown control message is still honoured inside a `stay` loop;
   - `goto back` A→B→A; `loop`/`stay` in B do not corrupt the slot;
   - `goto back` from `initial_state` fails the scenario cleanly.
3. Existing scenarios (`apps/elixip2/scenarios/*.exs`,
   `apps/kelixip/scripts/*.exs`) compile and pass unchanged.
4. Monitor output shows `stay` events (a scenario must never look frozen in
   `kelictl monitor` because its activity is all `stay`s).

## Non-goals

- No mailbox-semantics change: unmatched messages already stay in the
  process mailbox (native selective receive) — nothing to do here, unlike
  FSL/TS which had to build a pending queue in its engine.
- No `back` stack, no history states, no hierarchical states.
