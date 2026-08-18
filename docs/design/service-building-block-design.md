# Service Building Blocks — conception

> **Status: design, 2026-08-18.** Answers the questions
> [service-building-block.md](service-building-block.md) leaves open at the end
> of its §4, for the requirements S1–S14 it states. That document says *what*
> the layer must provide; this one says *how*, against the engine as it stands
> in 1.5.0. Read the spec first — nothing here restates it.

## 1. What has to be decided

The spec fixes the observable behaviour: an SBB is a subroutine call on the
host's own legs (S1, S6), it returns by posting one event (S2), its terminals
propagate and kill the host (S8), it is bounded (S7), it composes (S12), and it
never carries a mandatory reaction (S9).

Five questions stand between that and code:

| | Question | Answered in |
|---|---|---|
| D1 | how a sub-machine runs inside the host's process, and how a terminal escapes it | §2 |
| D2 | what the two machines share through `%SIP.Context{}`, and what they must not | §3 |
| D3 | what the monitor shows while the host is suspended | §4 |
| D4 | where `sbb_fsm` may be written, given that an `on_events` deadline is absolute | §5 |
| D5 | how a module declares itself an SBB, how a `.exs` reaches its macro face, and what the loader must not confuse | §6 |

§7 turns the answers into a file-by-file change list and a phase plan.

## 2. D1 — The mechanism: a nested loop, and a throw

### 2.1 The engine already has the right shape

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
S6 costs nothing: the dialogs and the media bindings that point at `self()`
point at the SBB too, because it *is* the same `self()`.

### 2.2 One new descriptor, one new loop

`sbb_return(event)` expands to a sixth descriptor next to `{:goto, …}`,
`{:stay, …}` and `{:terminal, …}`:

```elixir
{:sbb_return, event, ctx}
```

and a second loop consumes it:

```elixir
defp sbb_loop(module, state_name, ctx, states) do
  case apply(module, :"__state_#{state_name}", [ctx]) do
    {:sbb_return, event, ctx2} ->
      send(self(), event)          # S2: the outcome is an event, queued like any other
      {:returned, ctx2}

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
arrival-order rule S2 states, and it is a property of the queue, not something
the design has to arrange.

### 2.3 Terminals escape by `throw`, and the engine is already transparent to it

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
change is needed to make that true; it only has to stay true, which §7 records
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
aborts it — which is exactly S8.

`sbb_loop/4` does **not** catch it, so a terminal thrown three SBBs deep still
lands on the root. That is the whole of S12's unwinding: a call stack, unwound
by the runtime.

### 2.4 What `sbb_fsm` expands to

```elixir
defmacro sbb_fsm(module, opts \\ []) do
  quote do
    var!(sip_ctx) = SIP.Scenario.Runner.run_sbb(var!(sip_ctx), unquote(module), unquote(opts))
  end
end
```

`run_sbb/3` builds the SBB's entry context (§3), calls `sbb_loop/4` at
`:initial_state`, and returns the context to rebind — the same shape as
`spawn_fsm`, which also rebinds `sip_ctx`. The host state body then continues on
the next line.

## 3. D2 — The context: shared by default, three slots saved

### 3.1 Shared, because S6 says so

The SBB receives **the host's `%SIP.Context{}` as it stands**. Not a copy, not a
subset: `dialogpid`, `mediaserverpid`, `lasterr`, the B2BUA legs, the request
`auto_store/2` stashed. An SBB that could not see the INVITE that is being
served could not package a single one of the sequences §5 of the spec lists.

Three slots are saved on entry and restored on return, because they describe
*which machine is where* rather than what the call is:

| Slot | Why |
|---|---|
| `currentstate` | the host's state name; the monitor and `goto back` read it |
| `laststate` | `goto back` inside the SBB must not be able to jump into a host state |
| the `after` deadline | not in the struct — see §5 |

Everything else flows both ways, which is the point.

### 3.2 `appdata`: one shared map, one reserved sandbox

Two candidate rules, and the cheap one is wrong:

- *isolate `appdata`* — kills S6. The SBB stops seeing `:inbound_request`, and
  the host stops seeing what the SBB learned;
- *share everything* — S6 holds, but an SBB writing `:register_req` silently
  clobbers a host that uses the same key. That is the class of bug this codebase
  spends its comments warning about.

So: **`appdata` is shared, and every SBB gets one reserved key for its private
state**, `{:sbb, ModuleName}`, addressed through `sbb_data_get/1` and
`sbb_data_set/2`. Anything an SBB wants to *hand over* it writes to the shared
map under its own documented name, or — better — puts in the event it returns.
An SBB's scratch space cannot collide, and its output is deliberate.

`args:` at the call site seeds that sandbox, mirroring `spawn_fsm`'s `args:`
which seeds the child's appdata.

### 3.3 State names do not collide, and never could

`state foo` compiles to `def __state_foo(sip_ctx)` **in its own module**. The
host's `foo` and the SBB's `foo` are two functions in two modules; `sbb_loop/4`
dispatches on the SBB's module. There is nothing to namespace — the open
question was posed before the mechanism was fixed, and same-process delegation
answers it by construction. Only the *monitor* sees both names in one column,
which is §4.

## 4. D3 — Observability: the SBB's states show, qualified

`report/5` pushes `{call_id, scenario_label, username, state, event, type}` to
`SIP.Scenario.Monitor` when it is running, keyed on
`Process.get(:scenario_slot_id, self())`. A nested loop reporting its own states
under the host's slot would make the call look like it jumped into states its
scenario does not declare.

**The SBB reports, with a qualified state name**: `SBB.Call/waiting_answer`
instead of `waiting_answer`, on the host's row — one call, one row, and the
operator sees the sequence unfold instead of a call frozen in `place_call` for
thirty seconds. Making the sequence visible is the layer's stated purpose (§1 of
the spec); hiding its states would be a strange way to serve it.

On return the host's `currentstate` is restored (§3.1) and reported, so the row
goes back to the host's vocabulary without a transition the scenario did not
write.

This is the *cheap* half of the spec's open question on publishing a view. The
expensive half — an SBB publishing a structured view, Trix's `CallView` — is
deliberately left out of this design: one line of monitor text answers "where is
this call", and nothing today consumes more.

## 5. D4 — `sbb_fsm` belongs in a state body, not in an `on_events` clause

The spec requires the host's `after` to be suspended while an SBB runs (S7).
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
the flow gets a state. It is also the shape the spec's own acceptance example
takes — a `place_call` state whose body is one SBB call.

Consequence: on return, execution continues on the next line of the state body,
which is normally the host's `on_events` — where the returned event is matched,
against a **fresh** deadline. "Handing control back as a `stay()`" (S2) is what
it looks like from the outside; mechanically it is simply the body continuing.

## 6. D5 — Declaring an SBB, and keeping the loader out of trouble

### 6.1 `use SIP.SBB`

An SBB is written in FSL, so it needs `state`, `on_events`, `goto`, the session
mixins — everything `use SIP.Scenario` injects. It differs in three ways:

- it gains `sbb_return/1` and loses nothing else;
- it declares `__sbb__/0` returning `true`;
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

### 6.2 The macro face

The spec's shape (§4.1) is a module exporting macros through `__using__`:

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
  free when it lives in `:elixip2` or in a loaded `Kelix.Mod.*` (S10, S11);
  true for a SBB defined earlier in the same file, since `Code.compile_file/1`
  compiles top to bottom;
- the face is optional. `sbb_fsm(SBB.Call.Fsm, args: %{dest: dest})` works with
  no `use` at all. The macro face is sugar and a place to put defaults, not the
  mechanism — which keeps S11 simple: a kelixip module ships the FSM, and the
  face if it wants one.

### 6.3 The deadline (S7)

`sbb_fsm(module, timeout: 30_000)`, defaulting to a module-level
`@sbb_timeout` the SBB declares, itself defaulting to 32 s — timer B, the bound
§3 of the spec derives. On expiry `run_sbb/3` returns the timeout event the SBB
declares (`@sbb_timeout_event`, default `{:sbb_timeout, module}`) exactly as if
the SBB had returned it, so the host has one arm to write and no special case.

Implementation: the deadline is checked by `sbb_loop/4` around its `apply/3`, in
the same absolute-time terms as `SIP.Scenario.deadline/1`. It bounds the SBB as
a whole, not each of its states — the SBB's own `after` clauses stay its
business.

This is *not* built on a general `task`-like primitive. The spec notes that
FSL/TS has `fx.task` and FSL Elixir has only `Valet` plus one `http_GET`
facade, and suggests the SBB deadline might want it. It does not: `Valet`
coordinates an **outside worker** whose result races a timeout, and an SBB is
in-process code the runner already owns. Closing that gap is worth doing on its
own merits (§8), not as a detour through this one.

## 7. Change list and phases

### 7.1 Files

| File | Change |
|---|---|
| `lib/dsl/SIPScenario.ex` | `sbb_fsm/1,2` and `sbb_return/1` macros; `sbb_data_get/1`, `sbb_data_set/2`; the `on_events` placement check; import lists |
| `lib/dsl/SIPSBB.ex` *(new)* | `use SIP.SBB` — `SIP.Scenario`'s `__using__` / `__before_compile__` with the SBB kind flag |
| `lib/dsl/SIPScenarioRunner.ex` | `run_sbb/3`, `sbb_loop/4`, the `throw` catch in `loop/4`, qualified `report/5` |
| `lib/dsl/SIPScenarioLoader.ex` | skip `__sbb__/0` modules in `load_file!/1` |
| `FSL.md` | the `sbb_fsm` / `sbb_return` section, next to sub-scenarios |
| `docs/design/DESIGN-FSL.md` | a section on SBBs under §4, and invariant 2 restated as "one FSM stack, one process" |

`SIP.Context` is unchanged: the saved slots live in `run_sbb/3`'s own frame, not
in the struct.

### 7.2 Phases

1. **The mechanism, bare.** `sbb_fsm` / `sbb_return`, `sbb_loop/4`, the throw
   path, the placement check. Tests on a toy SBB: return with an event, a
   terminal propagating from one and from two levels down, `goto`/`stay` inside
   an SBB, the deadline, an event the SBB ignores reaching the host afterwards.
2. **The context and the monitor.** Sandbox, saved slots, qualified reporting.
3. **The `cancelling` specimen** — acceptance criterion 2. Six B2BUA scenarios,
   `releasing` exits kept (S3), queue vocabulary kept (S4), `:ms_event` arms
   kept (S5). If it does not factor cleanly here, the mechanism is wrong and
   phases 4–5 do not start.
4. **The macro face and the loader**, with `use SBB.Cancelling` on one scenario
   to prove the sugar.
5. **`Kelixip.Mod.Call.call/1`** — acceptance criterion 1, the flagship SBB, and
   the first one shipped by a loadable module (S11).

Phases 1–2 are one commit's worth of engine work; 3 is where the design is
judged.

## 8. Deliberately not in this design

- **a structured view published by a running SBB** (Trix's `CallView`). §4 gives
  the monitor line; a richer view waits for a consumer;
- **an Elixir `fx.task` counterpart.** Real gap, wrong occasion — §6.3;
- **concurrent SBBs.** One point of control, by construction (S12);
- **an SBB owning legs of its own.** That is `spawn_fsm`, and the frontier is in
  §4.5 of the spec.
