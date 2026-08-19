# Service building blocks

**Status: implemented, 1.5.0.** A service building block is a reusable FSM
fragment: a scenario enters it, the block runs on the scenario's own process,
context, dialogs and mailbox, and hands control back by posting one event.

The user-facing reference is [FSL.md](../../FSL.md#service-building-blocks-sbb);
what remains to build is [sbb_evolutions.md](sbb_evolutions.md). This document is
the design of record — what the layer is, how the engine runs it, what a block
must declare, and the two blocks that ship.

## 1. What the layer is for

A scenario is a flat FSM: a list of `state` blocks, each an `on_events`. Every
call flow that shares a protocol sequence copies it. The establishment states of
a B2BUA — place the call, absorb the provisionals, hunt the peer's targets,
handle the caller giving up, wait for the ACK — existed **eight times** in this
repository, agreeing on everything but a handful of decisions, and the agreement
was copied rather than shared. A copy rots one script at a time: the ninth omits
whichever branch its author did not know about, and nothing says so.

A block makes the sequence shared. What stays with the scenario is what varies:
which target, which code to answer, whether an outcome is a success or a failure,
what to bill.

## 2. What a block is

An SBB is an Elixir module, **written in FSL itself**, that packages
one protocol- or service-level sequence behind a callable face:

```elixir
defmodule SBB.Call do
  defmacro __using__(_opts) do
    quote do
      defmacro call(dest, call_opts \\ []) do
        # expands to sbb_fsm(SBB.Call.Fsm, ...): the caller enters that FSM
      end
    end
  end

  defmodule SBB.Call.Fsm do
    # the complicated FSM that establishes the call goes here, written with the
    # same `state` / `on_events` verbs as any scenario. It ends its branches on
    # sbb_return({:connected, uri}) / sbb_return({:rejected, code, reason}) —
    # and on scenario_failure() only for what must kill the host too.
  end
end
```

- **A callable face, and it is a *subroutine call*.** An SBB exports one or
  several macros. Calling one inside a `state` body makes the **current
  process enter the SBB's FSM**: the sub-machine takes over the event loop and
  handles every event of the current process until it returns. The host does
  not keep an `on_events` loop of its own while the SBB runs — it is suspended
  at the call site, exactly like a subroutine call in any language.

  This settles what the 2026-08-12 draft left as its central open question
  ("same-process delegation vs. child process"). It was never really open:
  invariant 2 of [DESIGN-FSL.md](DESIGN-FSL.md#9-invariants) — *one FSM, one process,
  because the dialog and media layers bind their events to `self()`* — means an
  SBB in a process of its own **cannot receive the host's leg events at all**.
  "same call, same legs" and "child process" are contradictory on the BEAM. Same-process
  delegation is the only shape that works, and it honours the invariant
  instead of working around it.

  The entry point is `SIP.Scenario.sbb_fsm()` (name per the article; the design
  owns the signature). The BEAM call stack carries the SBB stack, so
  composition is a plain nesting of calls.

- **A high-level event contract, and one primitive to return.** The SBB
  talks back to its host exclusively through events. The event vocabulary is
  the SBB's public API: documented per SBB, meaningful at service level
  (`{:connected, dest_uri}`, `{:rejected, code, reason}`, `{:choice, key}`,
  `:disconnected`), never a raw SIP message.

  ```elixir
  sbb_return(event)
  ```

  posts `event` into the process mailbox, ends the sub-machine and hands
  control back to the host state **as a `stay()`** — the host body is not
  re-executed and its `after` deadline is not re-armed (invariant 6). The host
  resumes its `receive` and matches the event on the next turn.

  Two consequences to hold on to:

  - **the final event is not privileged.** Whatever the SBB ignored is still
    in the mailbox and gets matched first. `{:ms_event, …}` can therefore reach
    the host before `{:connected, uri}`. That is arrival order — the same rule
    FSL/TS states for its pending queue — and it is written here so nobody
    rediscovers it in a debugger;
  - **returning is mandatory.** An SBB that hands control back without posting
    anything re-blocks the host blind. Every SBB branch ends with `sbb_return`
    or with a propagated terminal, checked the way a scenario state is checked
    for ending on a transition macro.

  `sbb_return` exists *because* reusing `scenario_success` for the return would
  be a trap, and a well-aimed one: the `cancelling` state this layer replaced ended five of
  its six arms on `scenario_aborted(...)` as an entirely **normal** outcome.
  Its author, moving that block into an SBB, would write the trap on the first
  try — a clean ending silently becoming an `exit()` that kills the host. With
  `sbb_return`, no verb changes meaning depending on where it is written.

### 2.1 The shape of a return

Every block returns **`{namespace, outcome, data}`**: the namespace it declares,
an outcome atom, a map. Decided 2026-08-18, and the two halves are decided for
different reasons.

**The arity is fixed because upgrading a block must not touch its scenarios.** The article's vocabulary was
`{:call, :connected, uri}` next to `{:call, :rejected, code, reason}` next to
`{:call, :cancelled}` — three arities for one block. Teaching that block to
report one more thing then means a fourth element, which is a compile error in
every scenario matching the old one. A key added to a map is invisible to
whoever does not read it. That is the whole of "upgrade without touching
scenarios", in the one place it is cheap to get right.

**The namespace leads because the host reads patterns.** `{:call, :connected, _}`
says what happened at a glance, and two blocks called from the same state are
told apart by their first element, as everything else in `on_events` is.

The cost is one thing the framework cannot do for itself: a namespace is the
block author's word, so no table in `SIP.Scenario` can list them, and an unknown
leading atom otherwise reads as a SIP method — which would draw a block's return
in the sequence diagram as an arrow *from the peer*, an event that came from
nobody, attributed to the far end. So the namespaces are **learned**: expanding
`sbb_fsm(Block, …)` teaches the scenario the namespace that block declares, and a
face module teaches its own in `__using__`. Both happen at macro-expansion time,
before the `on_events` that will match the return.

### 2.2 What a block declares about itself

A block declares its vocabulary, and the declaration is load-bearing rather than
documentary:

```elixir
@sbb_namespace :call
@sbb_returns [
  connected: "the callee answered — %{uri, code}",
  rejected:  "a final ≥ 300 — %{code, reason}",
  cancelled: "the caller gave up and the callee confirmed — %{}"
]
```

- `sbb_return/1` **refuses an outcome that is not declared**, at compile time.
  The failure it prevents is the reason: a mistyped outcome does not crash, it
  leaves the host waiting on its `after` for an event nobody will ever send —
  thirty seconds of silence and nothing in the log;
- a bounded block gets `:timeout` in its vocabulary for free, and returns
  `{namespace, :timeout, %{block: module}}`, so the deadline is an outcome like
  any other rather than a special case the host has to know about;
- `__sbb_returns__/0` is the machine-readable half: what a block can send is
  available to whatever wants to show it.

## 3. The engine: a nested loop, and a throw

### 3.1 The engine already has the right shape

`SIP.Scenario.Runner.loop/4` is a plain tail-recursive dispatcher:

```elixir
defp loop(module, state_name, ctx, states) do
  case apply(module, :"__state_#{state_name}", [ctx]) do
    {:goto, target, desc, type, ctx2}     -> loop(module, target, enter(...), states)
    {:terminal, outcome, reason, _, ctx2} -> finalize(module, ctx2, outcome, reason)
    ...
  end
end
```

Nothing in it is bound to *the* scenario: it takes the module, the state name,
the context and the state list as arguments. **An SBB is that same loop, called
with the SBB's module and the host's context.** Same process, same mailbox, so
sharing the legs costs nothing: the dialogs and the media bindings that point at `self()`
point at the SBB too, because it *is* the same `self()`.

### 3.2 One new descriptor, one new loop

`sbb_return(event)` expands to a sixth descriptor next to `{:goto, …}`,
`{:stay, …}` and `{:terminal, …}`:

```elixir
{:sbb_return, event, ctx}
```

and a second loop consumes it:

```elixir
defp sbb_loop(module, state_name, ctx, states, deadline_ref) do
  case apply(module, :"__state_#{state_name}", [ctx]) do
    {:sbb_return, event, ctx2} ->
      {event, ctx2}                # posted by run_sbb/3, so one place does it

    {:terminal, outcome, reason, type, ctx2} ->
      throw({:sbb_terminal, outcome, reason, type, ctx2})

    # everything else — goto / next / loop / back / shutdown / stay — is handled
    # exactly as in loop/4, recursing into sbb_loop/4 instead of loop/4
  end
end
```

Two differences with `loop/4`, and only two: `sbb_loop/4` never calls
`finalize/4` (the host's legs, media and children are not the SBB's to release),
and it never reports an outcome to the parent FSM (the SBB has no parent
scenario — its caller is a state, not a process).

`send(self(), event)` rather than a return value is what makes the final event
land in the mailbox **behind** whatever the SBB left unconsumed. That is the
arrival-order rule stated above, and it is a property of the queue, not something
the design has to arrange.

### 3.3 Terminals escape by `throw`, and the engine is already transparent to it

A terminal written inside an SBB must unwind the whole stack — the SBB, any SBB
that called it, and the host. There are N nested `sbb_loop/4` frames between it
and `loop/4`, so it needs a non-local exit. `throw` is the only one that works,
and the engine turns out to be ready for it:

```elixir
try do
  unquote(body)                       # the state body, in SIP.Scenario.state/2
rescue
  e -> scenario_failure("exception!")
catch
  :exit, reason -> scenario_failure("exit!")
end
```

The wrapper every state body carries catches `rescue` (exceptions) and
`:exit` — **not `:throw`**. A thrown term passes through every state frame,
every `sbb_loop/4` frame, and arrives at the one place that must see it. No
change is needed to make that true; it only has to stay true, which §3.3 records
as a test.

`loop/4` — the root, reached only from `run_instance/2` — wraps its `apply/3`:

```elixir
case (try do
        apply(module, fun, [ctx])
      catch
        {:sbb_terminal, outcome, reason, type, ctx2} -> {:terminal, outcome, reason, type, ctx2}
      end) do
  ...unchanged...
end
```

The caught terminal is re-applied as if the host state had written it: the same
`report/5`, the same `finalize/4`, the same outcome in the tool's verdict tally.
An SBB that aborts the call is indistinguishable, downstream, from a host that
aborts it, host included.

`sbb_loop/4` does **not** catch it, so a terminal thrown three SBBs deep still
lands on the root. That is the whole of it: a call stack, unwound
by the runtime.

### 3.4 What `sbb_fsm` expands to

```elixir
defmacro sbb_fsm(module, opts \\ []) do
  quote do
    var!(sip_ctx) = SIP.Scenario.Runner.run_sbb(var!(sip_ctx), unquote(module), unquote(opts))
  end
end
```

`run_sbb/3` builds the block's entry context (§4), calls `sbb_loop/5` at
`:initial_state`, and returns the context to rebind — the same shape as
`spawn_fsm`, which also rebinds `sip_ctx`. The host state body then continues on
the next line.

## 4. The context: shared by default, three slots saved

### 4.1 Shared, because the legs are the same legs

The SBB receives **the host's `%SIP.Context{}` as it stands**. Not a copy, not a
subset: `dialogpid`, `mediaserverpid`, `lasterr`, the B2BUA legs, the request
`auto_store/2` stashed. An SBB that could not see the INVITE that is being
served could not package a single one of the sequences the catalogue
lists.

Three slots are saved on entry and restored on return, because they describe
*which machine is where* rather than what the call is:

| Slot | Why |
|---|---|
| `currentstate` | the host's state name; the monitor and `goto back` read it |
| `laststate` | `goto back` inside the SBB must not be able to jump into a host state |
| the `after` deadline | not in the struct — see §6 |

Everything else flows both ways, which is the point.

### 4.2 `appdata`: one shared map, one reserved sandbox

Two candidate rules, and the cheap one is wrong:

- *isolate `appdata`* — kills the shared legs. The SBB stops seeing `:inbound_request`, and
  the host stops seeing what the SBB learned;
- *share everything* — the sharing holds, but an SBB writing `:register_req` silently
  clobbers a host that uses the same key. That is the class of bug this codebase
  spends its comments warning about.

So: **`appdata` is shared, and every SBB gets one reserved key for its private
state**, `{:sbb, ModuleName}`, addressed through `sbb_data_get/1` and
`sbb_data_set/2`. Anything an SBB wants to *hand over* it writes to the shared
map under its own documented name, or — better — puts in the event it returns.
An SBB's scratch space cannot collide, and its output is deliberate.

`args:` at the call site seeds that sandbox, mirroring `spawn_fsm`'s `args:`
which seeds the child's appdata.

**The sandbox is cleared on every call**, so an SBB entered twice starts twice
from nothing — the serial hunt calling `call()` on target after target must not
inherit the previous attempt's scratch. The exception is explicit:
`sbb_fsm(module, resume: true)` keeps what is there, which is what an SBB
designed to be re-entered after an interruption needs (§8.3).

### 4.3 State names do not collide, and never could

`state foo` compiles to `def __state_foo(sip_ctx)` **in its own module**. The
host's `foo` and the SBB's `foo` are two functions in two modules; `sbb_loop/4`
dispatches on the SBB's module. There is nothing to namespace — the open
question was posed before the mechanism was fixed, and same-process delegation
answers it by construction. Only the *monitor* sees both names in one column,
which is §5.

## 5. Observability: the block's states show, qualified

`report/5` pushes `{call_id, scenario_label, username, state, event, type}` to
`SIP.Scenario.Monitor` when it is running, keyed on
`Process.get(:scenario_slot_id, self())`. A nested loop reporting its own states
under the host's slot would make the call look like it jumped into states its
scenario does not declare.

**The SBB reports, with a qualified state name**: `SBB.Call/waiting_answer`
instead of `waiting_answer`, on the host's row — one call, one row, and the
operator sees the sequence unfold instead of a call frozen in `place_call` for
thirty seconds. Making the sequence visible is the layer's purpose (§1);
hiding its states would be a strange way to serve it.

On return the host's `currentstate` is restored (§4.1) and reported, so the row
goes back to the host's vocabulary without a transition the scenario did not
write. A **nested** block shows the innermost one — that is where the call
actually is; the chain of enclosing blocks is not worth a column that has to fit
a terminal.

The stack of frames the qualification reads is pushed by `run_sbb/3` and popped
in its `after`, so a terminal or a deadline unwinding through it leaves the
reporting as it found it: the outcome that follows is the host's, and is reported
unqualified.

This is the *cheap* half of publishing a view. The expensive half — a block
publishing a structured view, Trix's `CallView` — is not built:
[sbb_evolutions.md](sbb_evolutions.md).

## 6. `sbb_fsm` belongs in a state body, not in an `on_events` clause

The host's `after` is suspended while a block runs.
Under the subroutine model that is free **in a state body** — the deadline does
not exist yet, since `on_events` computes it on entry:

```elixir
SIP.Scenario.deadline(timeout)   # System.monotonic_time(:millisecond) + ms
```

It is **absolute**, so it is not free inside an `on_events` clause: an SBB
called from a clause would burn the host's remaining timeout while it runs, and
a 30-second SBB under a 30-second host deadline would return into an `after`
that fires immediately. Shifting the deadline by the elapsed time is possible —
the deadline is a closure variable the `stay` rewrite already threads — but it
buys a corner case at the cost of making the engine's timing rules
state-dependent.

**So `sbb_fsm` is rejected at compile time inside an `on_events` clause**, the
way `stay` outside one already is (`check_stay_placement!/2` is the precedent,
and the check is the same AST walk in reverse):

```
sbb_fsm is only allowed in a state body, not in an on_events clause.
Give the block its own state and call it there.
```

The restriction reads as a feature: an SBB is a step of the flow, and a step of
the flow gets a state. It is also the shape the article's own example
takes — a `place_call` state whose body is one SBB call.

Consequence: on return, execution continues on the next line of the state body,
which is normally the host's `on_events` — where the returned event is matched,
against a **fresh** deadline. Handing control back as a `stay()` is what
it looks like from the outside; mechanically it is simply the body continuing.

## 7. Declaring a block, and keeping the loader out of trouble

### 7.1 `use SIP.SBB`

An SBB is written in FSL, so it needs `state`, `on_events`, `goto`, the session
mixins — everything `use SIP.Scenario` injects. It differs in three ways:

- it gains `sbb_return/1` and loses nothing else;
- it declares `__sbb__/0` returning `true`, and its vocabulary alongside it —
  `__sbb_namespace__/0`, `__sbb_returns__/0` (with `:timeout` folded in when the
  block is bounded), `__sbb_timeout__/0`, `__sbb_timeout_event__/0`;
- **it does not define `run/1`.**

That last point is not tidiness. `SIP.Scenario.Loader.scenario_module?/1` is:

```elixir
Code.ensure_loaded?(module) and
  function_exported?(module, :run, 1) and
  function_exported?(module, :__scenario_states__, 0)
```

and `load_file!/1` takes the **first** matching module in the compiled file. An
SBB defined above the scenario in the same `.exs`, carrying `run/1`, would be
loaded and run *as* the scenario. Withholding `run/1` makes that impossible by
construction; `load_file!/1` additionally skips modules exporting `__sbb__/0`,
so the diagnostic is right even if a future change reintroduces `run/1`.

`use SIP.SBB` and `use SIP.Scenario` therefore share one implementation with a
kind flag, rather than duplicating the `__before_compile__` machinery.

### 7.2 The macro face

The face is a module exporting macros through `__using__`:

```elixir
defmodule SBB.Call do
  defmacro __using__(_opts) do
    quote do
      defmacro call(dest, opts \\ []) do
        quote do: sbb_fsm(SBB.Call.Fsm, Keyword.put(unquote(opts), :args, %{dest: unquote(dest)}))
      end
    end
  end
end
```

A scenario writes `use SBB.Call` next to `use SIP.Scenario` and calls
`call(dest)`. Two compile-order rules follow, both of which must be documented
rather than discovered:

- the SBB module must be **compiled before** the `.exs` that `use`s it. True for
  free when it lives in `:elixip2` or in a loaded `Kelix.Mod.*`;
  true for a SBB defined earlier in the same file, since `Code.compile_file/1`
  compiles top to bottom;
- the face is optional. `sbb_fsm(SBB.Call.Fsm, args: %{dest: dest})` works with
  no `use` at all. The macro face is sugar and a place to put defaults, not the
  mechanism — which keeps a module-owned block simple: it ships the FSM, and the
  face if it wants one.

### 7.3 The deadline

`sbb_fsm(module, timeout: 30_000)`, defaulting to a module-level
`@sbb_timeout` the SBB declares, itself defaulting to 32 s — timer B, the bound
the cancel handshake derives. On expiry `run_sbb/3` returns
`{namespace, :timeout, %{block: module}}` exactly as if the SBB had returned it,
so the host has one arm to write and no special case; `@sbb_timeout_event`
overrides it, and the default already follows the return contract rather than
leaving each block to remember it.

Implementation: `run_sbb/3` arms `Process.send_after(self(), {:sbb_deadline,
ref}, timeout)` and `on_events` injects a clause matching it into every state of
an SBB — the same injection that already makes every wait shutdown-aware and
media-death-aware. A check around `apply/3` would never be reached by a block
blocked in a `receive`, and only a clause can wake one. The clause throws
`{:sbb_deadline_hit, ref, ctx}`; a nested block lets a parent's ref pass, so the
frame that armed the timer is always the one that answers. It bounds the block
as a whole, not each of its states — the block's own `after` clauses stay its
business.

This is *not* built on a general `task`-like primitive. The spec notes that
FSL/TS has `fx.task` and FSL Elixir has only `Valet` plus one `http_GET`
facade, and suggests the SBB deadline might want it. It does not: `Valet`
coordinates an **outside worker** whose result races a timeout, and an SBB is
in-process code the runner already owns. Closing that gap is worth doing on its
own merits, not as a detour through this one.

## 8. The two blocks that ship: `call` and `bridge`

They are separate blocks rather than one `call()` covering a whole call, and the
scripts say why better than an argument could.

### 8.1 The seam is where the scenarios already cut

`connected` plus `wait_far_bye_ok` carry **no policy at all**: every arm is a
`b2bua_forward` and a `stay`, down to the ones written out in full for the ACK
of a re-INVITE and for the default relay of INFO / MESSAGE / NOTIFY / REFER. The
establishment states — `place_call`, `proceeding`, `cancelling`, `wait_ack` —
are where the decisions live: which target, which code to answer, what to bill.

One block per side of that seam:

| Block | Absorbs | Returns |
|---|---|---|
| `call(opts)` | `place_call`, `proceeding`, the provisionals, the serial hunt, `cancelling`, `wait_ack` | `:connected` `%{uri, code}` · `:rejected` `%{code, reason}` · `:cancelled` `%{}` · `:answered_after_cancel` `%{uri}` · `:timeout` `%{}` |
| `bridge(opts)` | `connected`, `wait_far_bye_ok` | `:caller_hung_up` `%{reason}` · `:callee_hung_up` `%{reason}` · `:callee_left` `%{reason}` · `:interrupted` `%{message}` · `:max_duration` `%{}` · `:media_lost` `%{reason}` |

Both under the return contract (`{namespace, outcome, data}`), so the
table lists outcomes and the keys their map carries: `call()` speaks `:call`,
`bridge()` speaks `:bridge`.

What the host keeps is what varies across the copies: the exit it names (`goto releasing` for the media scenarios,
`scenario_success` for the others), its own vocabulary
(`customer-service.exs`), and its extra arms — `{:ms_event, _, :media_lost}`,
which is a *policy* decision (BYE both legs) and belongs to the host, not to the
relay.

### 8.2 Terminating is inside the two blocks, not beside them

There is no `hangup()` block. The reason was structural rather than economic, and
the conversion of phases 3–5 has since settled it by leaving nothing for such a
block to hold — see the count at the end of this section.

**CANCEL and BYE do not belong to the same phase.** A CANCEL cancels an INVITE
transaction in flight — `cancelling` is reached from `proceeding`, an
establishment state, so it is *inside* `call()`. A BYE ends an established
dialog — the `{:BYE, …}` arm of `connected` plus `wait_far_bye_ok` — so it is
*inside* `bridge()`. A block cutting across both would have to take control in
the middle of the other's sequence: not a building block, a leak.

**And nothing is missing without it.** §2 sets the test: if
forgetting a fragment can leave a phone off-hook, the fragment carries something
the framework should have owned. The scripts answer it in their own
`on_shutdown`:

> both legs are wound down by the automatic teardown — CANCEL what is ringing,
> BYE what is up — so there is nothing left to do here but say why we stopped.

A `hangup()` would carry no correctness, only visibility already available in
the two blocks' exit events. What stays with the scenario is what carries
policy: `releasing` and its `media_cleanup_ressources()`, the reason reported,
the billing.

**Closed 2026-08-18, on the converted scripts rather than on the argument.**
Across the three `direct-call*.exs`, the SIP teardown left outside `call()` and
`bridge()` is *one site*: the `{:bridge, :media_lost, _}` arm of the media
script, `b2bua_send_BYE()` and one reply — two macro calls expressing the
decision "there is no media left, end the call". Everything else that survived
the conversion is `media_cleanup_ressources()` (media, not SIP) and the
`scenario_aborted` verdicts. A block needs an FSM and events to wait for;
hanging up is one macro, and the waiting that follows it — the far end's 200 —
is already `bridge()`'s `wait_far_bye_ok`.

### 8.3 `bridge` interrupted and re-entered

`bridge()` consumes `{:bridge_break, message}` and returns
`{:bridge, :interrupted, message}`. The host does its business — play a prompt,
consult a backend, ask an operator — and calls `bridge(resume: true)` again. The
call is never torn down; only the relay pauses.

Nothing new is needed to deliver the break: the SBB runs in the scenario's
process, so `{:bridge_break, …}` is an ordinary message in the mailbox, sent by
`kelictl`, by a module, by a timer. `resume: true` is the §4.2 flag that keeps
the sandbox, so the block finds its counters where it left them.

**The window is the part to be careful about.** Between two `bridge()` calls the
call is still up, and in-dialog traffic keeps arriving. Nothing is lost — the
mailbox holds it, and the resumed block replays it — but nothing is *answered*
either, and the far end has protocol deadlines: an unanswered re-INVITE runs at
timer B, an unanswered BYE gets retransmitted. So the host's work between two
`bridge()` calls must be short, and "short" here means the scale of a prompt,
not of a human decision. A host that needs to hold the call for longer plays
something into it, which means it is inside the media SBBs, not between two
calls to this one.

This is the same shape of window as the one that produced the cancel race
— a scenario that stopped early, and what followed arriving with
nobody listening. It is bounded here rather than unbounded, but it is the same
family, and it deserves a test that sends a re-INVITE during an interruption.

### 8.4 A reservation on the name

`bridge` says two legs. The same block serves the `connected` state of a plain
UAC, which has one. For a B2BUA it is the right word and that is the primary use
case, so the name stands — recorded because the first single-leg user will feel
it.

### 8.5 Where they live, and what the module layout costs

Both blocks live in **`:elixip2`**, under one face module exporting both verbs:

```elixir
defmodule SBB.Call do
  defmacro __using__(_opts) do
    # Teach the scenario the namespaces of the blocks it is about to call, so
    # `on_events` classifies their returns even in a state written before the
    # call site (spec, "the shape of a return").
    SIP.Scenario.register_namespace(__CALLER__.module, :call)
    SIP.Scenario.register_namespace(__CALLER__.module, :bridge)
    quote(do: import(SBB.Call))
  end

  defmacro call(opts \\ []) do
    quote do: sbb_fsm(SBB.Call.Establish, unquote(opts))
  end

  defmacro bridge(opts \\ []) do
    quote do: sbb_fsm(SBB.Call.Bridge, unquote(opts))
  end

  defmodule Establish do
    use SIP.SBB
    @sbb_namespace :call
    @sbb_returns [connected: "…", rejected: "…", cancelled: "…"]
    # …
  end

  defmodule Bridge do
    use SIP.SBB
    @sbb_namespace :bridge
    @sbb_returns [ended: "…", interrupted: "…", max_duration: "…"]
    @sbb_timeout :infinity
    # …
  end
end
```

A scenario writes `use SBB.Call` (or `import SBB.Call`) next to `use
SIP.Scenario` and calls `call(args: %{dest: dest})`. Four things this shape
gets right, three of them the kind that are found by compiling:

- **the nested FSM is declared with its short name.** `defmodule SBB.Call.Call`
  *inside* `SBB.Call` defines `SBB.Call.SBB.Call.Call` — Elixir concatenates the
  outer name, it does not recognise the prefix. `defmodule Establish` is what
  yields `SBB.Call.Establish`;
- **the macro body quotes.** `defmacro call(opts), do: sbb_fsm(...)` expands
  `sbb_fsm` inside `SBB.Call`, where there is no `sip_ctx` to rebind. The body
  must `quote` and let the expansion land in the scenario;
- **`sbb_fsm` takes no context argument.** It reads and rebinds `var!(sip_ctx)`
  itself, and `var!` composes through a second macro layer — the whole FSL is
  built this way. The face passes the block and the options, nothing else;
- **`Establish` rather than `Call`.** `SBB.Call.Call` stutters and says nothing;
  the two nested names then read as the two halves of a call's life. Cosmetic,
  and the only one of the four that is a matter of taste.

`bridge`'s `@sbb_timeout :infinity` is not a detail: the bound exists so a leg
that says nothing cannot hold an instance for ever, and `call()` has timer B to
bound it with. A bridged call has no such timer — it ends when the dialog ends,
which is what the block is listening for. `arm_sbb_deadline/2` already takes
`:infinity` and arms nothing.

## 9. The frontier with `spawn_fsm`

FSL already has `spawn_fsm/2` (spawn a *child scenario* in its own monitored
process), `notify/2` and `notify_parent/1` (`{:parent_msg, …}` /
`{:child_msg, …}`). That is parent↔child between two full scenarios, each with
its own legs — a callee simulator, a load generator.

Both survive, and the frontier is sharp. It is worth stating in one line
because nothing states it today:

> **`spawn_fsm` when the other machine has legs of its own; `sbb_fsm` when the
> sequence belongs to the legs you already hold.**

`spawn_fsm` spawns an *actor*: a second party, concurrent, addressed by
messages, outliving the state that spawned it. `sbb_fsm` calls a *subroutine*:
no second party, no concurrency, the caller suspended until it returns.

Trix's `CallMachine` is the instructive borderline case: one instance per call,
its own `dialing / ringing / connected / hangingup` states, its own view — it
*looks* like the `call()` of §8. It is not, and the giveaway is one line of
its constructor: the `RTCSession` is handed to it in `args`. It **owns** its
leg, it does not observe the parent's. That is a `spawn`, and it is right to be
one.

## 10. One vocabulary across the two dialects

FSL exists twice — `:elixip2` on the BEAM, `finite-state-language` on npm
(spec `fsl-typescript/spec/fsl-js-ts.md` §8.4, which now implements the block
names it had reserved, and records this rule) — and Trix is a real consumer of
the second. Two implementations of one language may diverge on *mechanism*; they
must not diverge on *names*, because a name is the only thing a reader carries
from one dialect to the other.

**One concept, one name.** A concept present in both dialects is spelled
the same in both, modulo the casing convention of each language (`snake_case`
vs `camelCase`) and the `fx.` namespace TS uses where Elixir has bare macros.
Where the two spellings differ today, **the two converge — breaking and
reimplementing on either side is acceptable**; `finite-state-language` is
0.x with one known consumer, and Elixip carries deprecated aliases the way
`sub_fsm` was carried into 1.5.0.

| Concept | Elixir | TypeScript | Status |
|---|---|---|---|
| spawn a child machine | `spawn_fsm/2` | `fx.spawn` | **converged 1.5.0** — was `sub_fsm`, kept as a deprecated alias |
| enter a sub-machine (SBB) | `sbb_fsm/2` | `fx.sbb` | **implemented on both sides** — Elixir 1.5.0, `finite-state-language` 0.1.3 |
| return from an SBB | `sbb_return/1` | `fx.sbbReturn` | **implemented on both sides** |
| message to a child | `notify/2` | `fx.notify` | aligned |
| message to the parent | `notify_parent/1` | `fx.notifyParent` | aligned |
| message received from the parent | `{:parent_msg, p}` | `parent:msg` | **converged 1.5.0** — was `{:scenario_msg, :parent, p}` |
| message received from a child | `{:child_msg, name, p}` | `child:msg` | **converged 1.5.0** — was `{:scenario_msg, name, p}` |
| a child ended | `{:child_exit, name, outcome, reason}` | `child:exit` | **converged 1.5.0** — was `{:scenario_exit, …}` |
| cooperative shutdown | `on_shutdown` | `onShutdown` | aligned |
| terminals | `scenario_success` / `_failure` / `_aborted` | `success()` / `failure()` / `aborted()` | aligned (the prefix is a namespacing need Elixir has and TS does not) |
| bounded async work | — (`Valet`, and `http_GET` built on it) | `fx.task(work, tag)` | **gap on the Elixir side**: no FSL verb, only the `Valet` implementation and one `http_GET` facade over it |

Three points in that table need their reasoning recorded.

**The `child:` / `parent:` move was Elixir's, not TS's.** `scenario_msg` names
the transport and hides the direction; the direction is what every reader wants
and what both design documents already use in prose. TS cannot move the other
way: it dispatches on `type` alone and has no pattern matching, so
folding the two into one type with a `from` field would force an `if` in every
state — a real regression. Elixir loses nothing by splitting, since it matches
the discriminant either way.

Done in 1.5.0, and it is the one entry in the table that could **not** be
carried by a deprecated alias: an alias works for a macro, which is read at
compile time, and not for a message, which is matched at run time. A scenario
left on `{:scenario_msg, …}` would not fail — it would never be woken, and
would wait on its `after` without a word. So `on_events` reports the old shapes
as a **compile-time warning** naming the replacement, which is where the
mismatch is still visible.

**`fx.task` has no Elixir counterpart, and that is the gap to close.**
`Valet` is an implementation and `http_GET` is one facade over it; there is no
FSL verb for "run this work, bounded, deliver exactly one tagged event". TS
has it and builds `httpGet` on it. That inversion — the richer primitive on
the younger dialect — is a candidate for the SBB design, because an SBB with a
deadline wants exactly that machinery.

**What TS is not expected to support.** Convergence is on names, not on
coverage; a concept absent from one dialect is not a divergence:

- `spawn_fsm` by **file path** (`.exs` resolved next to the declaring file).
  TS machines are ESM imports; there is nothing to resolve;
- [`SIP.Scenario.CallDispatcher`](DESIGN-FSL.md#44-sipscenariocalldispatcher) — handing an inbound INVITE
  to a waiting child has no meaning in a browser;
- `goto back` and the `stay` variants Elixip is adding, already recorded as
  deferred in the TypeScript spec.

Conversely, Elixir does not get TS's **bounded, inspectable pending queue**:
the BEAM mailbox is unbounded and opaque. Same observable contract, opposite
behaviour under load — TS drops the oldest event with a warning at 32, Elixir
grows memory. Already true today; SBBs make it routine, because a sub-machine
that runs for 30 s ignoring everything outside its own sequence *is* the
`cancelling` specimen.

**Keeping it true.** The two specs live in two repositories that nothing
synchronises — the exact failure mode §1 describes for scenarios, applied to
the specifications themselves. Each side carries an explicit pointer to the
other, and this table is the shared part: changing a name here means changing
it there in the same breath.


---

## 11. Invariants

1. **One FSM *stack*, one process.** The dialog and media layers bind their
   events to `self()`, so a block running anywhere else could not receive the
   host's leg events at all. This is what makes a block a subroutine rather than
   a spawn, and it is not a preference
   ([DESIGN-FSL.md](DESIGN-FSL.md#9-invariants), invariant 2).
2. **The per-state `try` catches exceptions and `:exit`, never `:throw`.** Both
   non-local exits — a terminal and a deadline — cross every state frame and
   every nested block as thrown terms. A bare `catch value ->` added to that
   wrapper stops blocks propagating, silently;
   `apps/elixip2/test/sbb_fsm_test.exs` guards it.
3. **A block returns `{namespace, outcome, data}`**, three elements, the last a
   map. A block that learns to report one more thing adds a key; a fourth tuple
   element would be a compile error in every scenario matching the old one.
4. **Every branch of a block ends on `sbb_return` or on a propagated terminal.**
   One that falls through leaves the host waiting for an event nobody will send —
   a silence, not a crash, which is also why an undeclared outcome is refused at
   compile time.
5. **A block defines no `run/1`**, and the loader skips `__sbb__/0` modules. A
   block declared above the scenario in the same `.exs` would otherwise be loaded
   and run *as* the scenario.
6. **`sbb_fsm` is refused inside an `on_events` clause.** That clause's deadline
   is absolute, so a block called from one would burn the host's remaining
   timeout while it runs.
7. **A block consumes what its host has a policy for, and reports it.** An event
   a block does not consume waits in the mailbox for a block that never returns,
   so "the host keeps that arm" is not available: the block takes the event and
   hands back an outcome. `{:ms_event, _, :server_disconnected}` in particular
   must be handled explicitly by any block whose host has a policy for it —
   otherwise the clause `on_events` injects treats it as a shutdown.
8. **A cooperative shutdown reaching a block runs the host's `on_shutdown`.**
   Ending the scenario from inside the block instead skips the block where a
   script frees what the call reserved, and leaks it.
9. **An attribute read during macro expansion is written during macro
   expansion.** The namespaces `on_events` classifies with are gathered while
   `sbb_fsm` and the face modules expand; a `Module.register_attribute` call
   sitting in a `__using__` quote runs later, when the module body is evaluated,
   and clears what expansion had gathered.
