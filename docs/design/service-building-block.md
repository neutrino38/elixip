# Service Building Blocks — reusable FSM fragments

> **Status: specification, revised 2026-08-18.** Started as a stub capturing the
> problem, one worked example and the invariant. EB's article *"Taming large
> state machines: Service Building Blocks in Elixip"* (2026-08) settled the
> *shape* of the mechanism: an SBB is a module exporting macros that launch a
> sub-state-machine which absorbs low-level events and posts high-level ones
> back to the host. §4 turns that shape plus the specimen's lessons into
> requirements. It is a **specification, not a design**: it says what the layer
> must provide and how to tell it works; the remaining design questions are
> listed at the end of §4.
>
> The 2026-08-18 revision settles three things the first draft left open. An SBB
> is a **subroutine call, not a co-routine** — the host process enters the
> sub-machine, which owns the event loop until `sbb_return` hands control back
> (S1, S2); three of the six open questions fall out of that. FSL now has
> **one vocabulary across its two dialects**, Elixir and TypeScript, with the
> divergences named and assigned a side to move (§4.6, S14). And the catalogue
> gained a shape: a call is **two** blocks, `call()` and `bridge()`, and there
> is no `hangup()` (§5.1). How all of it is built is
> [service-building-block-design.md](service-building-block-design.md).

## 1. What the layer is for

Today a scenario is a flat FSM: a list of `state` blocks, each an `on_events`
over the two legs. Two things follow from that shape:

- **every scenario re-states the same protocol sequences.** `direct-call.exs`
  and `direct-call-with-auth.exs` differ in a handful of decisions and agree on
  everything else. The agreement is copied, not shared — `b2bua.exs`, a third
  copy that agreed with `direct-call.exs` down to the state names, went unnoticed
  until this layer counted them, and was deleted rather than converted twice;
- **the copy silently rots.** The fifth script — the one not yet written — will
  omit whichever sequence its author did not know about, and nothing will say so.

A Service Building Block is a **reusable sub-state-machine behind a callable
face**: a scenario calls one macro inside a `state`, the SBB's own FSM absorbs
the low-level events (the provisionals, the CANCELs, the timer H of this
world), and the scenario's `on_events` receives a handful of high-level,
human-meaningful events — `{:connected, uri}`, `{:choice, language}`,
`:disconnected`. It is the FSL-level answer to the duplication that
`SIP.Msg.Ops` answered at the message level (CLAUDE.md, *Message Layer*), and
the Elixip incarnation of what makes the competition's scripts short:
Kamailio's `t_relay()` and Asterisk's `Dial()` are single calls hiding an
entire state machine written once by people who read the RFC — SBBs in a
trench coat. The lineage is JAIN SLEE's Service Building Blocks (JSR 240):
the idea was right, buried under Java boilerplate; here it gets a language.

## 2. The invariant the layer must not break

**A fragment makes a sequence visible; it must never be what makes it correct.**

Everything mandatory — what the RFC leaves no choice about — belongs in the
framework, where no script can omit it. A fragment then exposes that sequence in
the flow so the scenario can *observe* it (note the event, meter it, log it,
branch on it) and layer policy on top.

Belt and braces, the same split as everywhere else in this codebase:

| Layer | Owns | Example |
|---|---|---|
| Framework | the mandatory reading and the mandatory reaction | `SIP.Msg.Ops.requested_expires/2`; `SIP.Uri.serialize_ruri/1`; the §17.2.1 100 Trying |
| SBB fragment | the *visible* shape of a common sequence | the cancel race below |
| Scenario | the decisions | which code to answer, which target to try, what to bill |

The failure mode to design against: a scenario that forgets a fragment must
still be correct — merely less legible, and less able to report what happened.
If forgetting a fragment can leave a phone off-hook, the fragment is carrying
something the framework should have owned.

## 3. Worked example: the cancel race

The first candidate, and a good one precisely because it is **rigorously
identical** in all four B2BUA scripts. If it does not factor cleanly, the SBB
mechanism is wrong — not the scenario.

### What happens

The caller cancels; the CANCEL and the callee's answer cross on the wire. RFC
3261 §16.7 / §9.1: cancelling *asks*, it does not decide, and the transaction is
over only when a final response says so. So after a CANCEL the outbound leg may
still come back with:

- **487 Request Terminated** — the ordinary case, fast;
- **a 2xx** — the callee picked up before the CANCEL reached it. It MUST be
  ACKed (§13.2.2.4: the ACK of a 2xx is a transaction of its own, owned by the
  UAC core) and then ended with a BYE (§15). There is no other lawful outcome.

Observed in production on 2026-08-11 (see the incident in §6): the callee
answered, the scenario instance had already ended on `scenario_aborted("caller
cancelled")`, nobody ACKed the 200, and the callee stayed in a call that never
existed — retransmitting its 200 until it gave up.

### Why it is framework work, not scenario work

The reaction carries **zero policy**. A script that "decided" something else
would be violating the RFC. It is plumbing, and plumbing that four scripts would
otherwise each have to remember.

### Why the teardown could not already do it

The automatic teardown (`SIP.Session.B2bua`, `answer_orphan/2` +
`established?/1` + the BYE) is not missing the logic — it is missing **time**.
It runs inside the dying scenario process, in a straight line: it executes at
instant T and the late 2xx arrives at T+ε. `established?/1` reads the dialog's
remote tag, which is not set yet when it looks.

The corollary is that the fix is cheaper than it appears: **let the outbound leg
resolve before the teardown reads it, and the existing machinery finishes the
job by itself** — the leg is established by then, so `established?/1` answers
true and the BYE goes out. Only the 2xx's ACK needs its own care.

### Where the waiting must NOT live

Blocking the dying scenario instance until the leg resolves is the obvious
implementation and the wrong one: the outbound ICT's timer B bounds it at 32 s,
and an instance pinned for 32 s per cancelled call is a slot held in
`max_calls` — i.e. a mass-cancel turns into 503s for legitimate traffic. The
wait belongs somewhere that costs no instance slot.

### What landed (2026-08-12) — there is no wait

Chasing "where does the wait live" was the wrong question. **The dialog is not
linked to its application** (`SIP.Dialog.start_dialog/5` uses `GenServer.start`,
not `start_link`), so it outlives the scenario by construction and is simply
still there when the answer arrives. Nothing has to wait for anything.

So the floor sits in `SIP.DialogImpl`, on the response path
(`answer_nobody_awaits/2`): a 2xx to an INVITE, no live `state.app` ⇒ ACK the
transaction and post itself a BYE. No new process, no instance slot, no timer,
and it covers the crashed-instance case for free — not just the cancel race.

Two consequences for the SBB layer:

- the fragment does **not** have to carry the correctness. It is free to be
  purely about visibility: notice the race, note the account, meter it, decide
  whether to report `:answered_after_cancel` instead of `:abandoned`;
- the teardown in `SIP.Session.B2bua` was left alone. `wind_down_leg/2` still
  CANCELs an in-flight leg and walks away — which is now safe, because whatever
  the leg answers afterwards lands on a dialog that knows what to do with it.

Two latent bugs fell out of it, and both are worth noting because they are the
same *kind* of finding: a scenario that stops early does not exercise what
follows, so what follows can be quietly wrong for years.

- `b2bua_send_BYE/0` did not acknowledge the leg's 2xx before hanging up, and
  §15 ends an *established* dialog — one whose answer the far end is still
  retransmitting is not established as far as it is concerned. `do_send_bye/1`
  now calls `SIP.Dialog.ack_pending_invite/1` first (`:ok` when it was owed,
  `:none` when the ACK had long been relayed from the other leg, quiet either
  way). That also fixes the pre-existing `wait_ack` timeout path, which BYEd the
  callee without ever ACKing it.
- relaying the caller's CANCEL onto an attempt `b2bua_cancel_forward/0` had
  already cancelled answers `:bad_state` from the transaction layer. The pair is
  what every B2BUA scenario writes, so the duplicate is as old as the pair — it
  simply never surfaced, because the scenario ended on the next line. Now that
  it waits, the error reached `lasterr` and killed the instance.
  `ack_lasterr(:bad_state)` reads it as `:ok`: cancelling what is already being
  cancelled is not a failure, it is the request already granted.

### The `cancelling` state, as written today (2026-08-12)

The visible half now exists in every B2BUA scenario — the four EB listed, plus
`customer-service.exs`, because leaving any of them out is exactly the hole the
layer is supposed to close. The
`proceeding` state's CANCEL arm goes `goto(cancelling, "caller cancelled")`
instead of ending, and the new state reads:

```elixir
state cancelling do
  on_events do
    {:outbound, {487, _resp, _trans, _dlg}} ->
      scenario_aborted("caller cancelled, callee confirmed")

    {:outbound, {200, _resp, _trans, _dlg}} ->
      b2bua_send_BYE()
      scenario_success("callee answered after the cancellation; hung up")

    {:outbound, {code, _resp, _trans, _dlg}} when code in 100..199 ->
      goto(loop, "provisional #{code} after cancel")

    {:outbound, {code, _resp, _trans, _dlg}} when code >= 300 ->
      scenario_aborted("caller cancelled, callee answered #{code}")

    {:outbound, {:dialog_terminated, _dlg, _reason}} ->
      scenario_aborted("caller cancelled, outbound leg gone")

    {:dialog_terminated, _dlg, _reason} ->
      scenario_aborted("caller cancelled")
  after
    32_000 -> scenario_aborted("caller cancelled, callee never concluded")
  end
end
```

**This block is the specimen the SBB mechanism has to swallow.** Note what
varies across the six copies, because that is the hard part of the design, not
the sharing itself:

- the three media scenarios (`b2bua_media.exs`, `webrtc-gw.exs`) leave through
  `goto(releasing, …)` rather than ending, because `releasing` is where their
  media resources are freed. A fragment that hard-codes `scenario_aborted` is
  useless to them: **a fragment needs an exit the host scenario names**;
- `customer-service.exs` words every outcome in queue vocabulary ("abandoned",
  "agent") because that is what its monitor line means. **A fragment needs its
  labels parameterised**, or it degrades what the operator reads;
- `b2bua_media.exs` and `webrtc-gw.exs` add an `{:ms_event, _ref,
  :server_disconnected}` arm. **A fragment needs to be extensible with arms the
  host adds**, not sealed.

Exit naming, label parameterisation, arm extension: three requirements, from one
fragment. That is why this one was worth writing out by hand first.

### What the ICT does NOT need

`SIP.Transac.Common.handle_UAS_sip_response/2` already accepts a 2xx in the
`:cancelling` state — deliberately, with §16.7 cited in the comment — and
forwards it to `state.app`. **The ICT needs no change.** The gap is that
`state.app` is dead by then. Do not budget for ICT surgery before observing that
it is needed.

### The bound

Whatever the mechanism, the wait must be bounded. The ordinary 487 returns in
well under a second, but a callee that goes silent leaves only timer B (32 s) as
a limit. Without an explicit deadline, a dead leg leaks whatever is holding it.

## 4. First specification

What follows is the contract the SBB layer must honour. Each requirement is
labelled S*n* so the eventual design document can answer them one by one.
Requirements S3–S5 are the three the `cancelling` specimen forced (§3); S14
comes from keeping the two FSL dialects one language (§4.6); the rest come from
the article and from the constraints FSL already imposes.

### 4.1 What an SBB is

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

- **S1 — callable face, and it is a *subroutine call*.** An SBB exports one or
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
  S6 and "child process" are contradictory on the BEAM. Same-process
  delegation is the only shape that works, and it honours the invariant
  instead of working around it.

  The entry point is `SIP.Scenario.sbb_fsm()` (name per the article; the design
  owns the signature). The BEAM call stack carries the SBB stack, so
  composition (S12) is a plain nesting of calls.

- **S2 — high-level event contract, and one primitive to return.** The SBB
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
  be a trap, and a well-aimed one: the `cancelling` specimen of §3 ends five of
  its six arms on `scenario_aborted(...)` as an entirely **normal** outcome.
  Its author, moving that block into an SBB, would write the trap on the first
  try — a clean ending silently becoming an `exit()` that kills the host. With
  `sbb_return`, no verb changes meaning depending on where it is written.

#### S2 — the shape of a return

Every block returns **`{namespace, outcome, data}`**: the namespace it declares,
an outcome atom, a map. Decided 2026-08-18, and the two halves are decided for
different reasons.

**The arity is fixed because S13 needs it.** The article's vocabulary was
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

#### S2 — what a block declares about itself

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

### 4.2 What the specimen requires (S3–S5)

- **S3 — the host names the exits.** An SBB never terminates the host on a
  normal outcome, never `goto`s a host state, never chooses between
  `scenario_success` and `scenario_aborted` on the host's behalf. Every outcome
  is an event carried by `sbb_return`; the host's arm decides. (The media
  scenarios leave through `goto(releasing, …)`; a fragment that hard-codes the
  ending is useless to them.)
- **S4 — labels are parameterised.** Every string that reaches the monitor or
  the operator through the SBB is supplied or overridable at the call site.
  (`customer-service.exs` words its outcomes in queue vocabulary; the SBB must
  not degrade what the operator reads.)
- **S5 — unconsumed events wait, they are not lost.** The draft asked for
  simultaneous fall-through to a host loop running alongside the SBB. The
  subroutine model has no such loop, and it does not need one — the two
  reasons behind the requirement are both still served:

  - **the mailbox does the work by itself.** An Erlang `receive` leaves what it
    does not match in place. An event the SBB ignores is still there when the
    host resumes: FSL/TS's pending queue, in native form. Deferred instead of
    simultaneous;
  - **the case that motivated S5 is already covered elsewhere.** The
    `{:ms_event, _ref, :server_disconnected}` arm of the media scenarios is one
    of the two clauses **injected into every `on_events`**
    ([DESIGN-FSL.md](DESIGN-FSL.md#25-on_events)) —
    including the SBB's own, without its author thinking about it. The exact
    pattern S5 protected is protected by injection, not by routing.

  So: events an SBB does not consume stay pending and reach the host when it
  regains control; media death and cooperative shutdown traverse the SBB
  through the injected clauses. An SBB is extensible, not sealed.

### 4.3 Execution constraints

- **S6 — same call, same legs.** The SBB observes and acts on the *host's*
  session — its dialogs, transactions, `sip_ctx` — because the sequences it
  packages (the cancel race, the hunt, the in-dialog relay) are sequences *of
  the host's call*. Under S1 this costs nothing: same process, same mailbox,
  same bindings. It remains the load-bearing difference with `spawn_fsm`,
  whose child runs in its own process with its own legs (see §4.5).
- **S7 — bounded, and it carries the deadline alone.** Every SBB has a
  completion deadline (defaulted, overridable at the call site) and returns a
  distinct timeout event on expiry. No SBB may hold an instance slot
  open-endedly (§3, *The bound*). While an SBB runs, the **host state's `after`
  is suspended** — the time spent inside does not count against it. Two
  concurrent deadlines with no arbiter is the alternative, and it has no
  correct answer.
- **S8 — terminals propagate; there is nothing else to abort.** The host
  cannot leave a state while an SBB runs: it does not have control. The only
  ways out are `sbb_return`, the SBB's own timeout, or a **terminal
  propagating**: `scenario_failure` and `scenario_aborted` written inside an
  SBB keep exactly their ordinary meaning and tear down the whole stack, host
  included — the `exit()` of C. Mechanically that is a `throw` caught by the
  root runner, which is free: FSL already turns every exception into
  `scenario_failure`.

  The draft's "the host can leave a state while the SBB is armed" is therefore
  dropped rather than answered. Cooperative shutdown is unaffected: it arrives
  through the injected clause (S5), inside the SBB, and propagates.
- **S9 — the §2 invariant holds.** A scenario that does not use the SBB is
  still RFC-correct: everything mandatory stays in the framework
  (`answer_nobody_awaits/2` is the model). The SBB packages visibility and
  reusable *policy*, never the only copy of a mandatory reaction.

### 4.4 Distribution and evolution

- **S10 — lives in the base library.** The mechanism (`sbb_fsm()` and the
  glue) belongs to `:elixip2`, available to every derived tool — elixipp
  scenarios and kelixip scripts alike. **So do the blocks that are call flow
  rather than server policy**, `call` and `bridge` first (decision of
  2026-08-18, revising the article): they are verbs of the language, wanted by
  both FSL dialects, and a kelixip module would put them out of reach of the
  elixipp scenarios and of the framework's own suite — the two places they get
  exercised.
- **S11 — kelixip modules can export SBBs.** A loadable module
  (`Kelix.Mod.*`) can ship SBBs, which makes service building blocks
  dynamically loadable like the modules themselves. What belongs there is a
  block that needs the module's own state — an mcu `conference()`, a registrar
  lookup — not `call()`, which needs nothing but the legs the scenario holds.
- **S12 — SBBs compose.** An SBB's FSM, being FSL code, can itself call SBBs
  — building blocks made of building blocks. Under S1 this is a plain call
  stack, so it needs no mechanism of its own. What it does cost: a `call` and a
  `menu` cannot run *concurrently*; they compose in sequence, or the `menu` is
  called from inside the `call`.
- **S13 — upgrade without touching scenarios.** The compatibility surface of
  an SBB is its event vocabulary (S2). Upgrading an SBB — DTMF menu grows
  voice recognition, then a chatbot, then total-conversation text — must not
  require changes to host scenarios beyond, at most, *additive* arms for new
  events (the banking IVR walkthrough in the article is the reference
  narrative). Combined with BEAM hot code reloading this is what buys
  block upgrades without service interruption.

### 4.5 Relation to the existing primitives

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
*looks* like the flagship SBB of §5.1. It is not, and the giveaway is one line of
its constructor: the `RTCSession` is handed to it in `args`. It **owns** its
leg, it does not observe the parent's. That is a `spawn`, and it is right to be
one.

### 4.6 One vocabulary across the two dialects

FSL exists twice — `:elixip2` on the BEAM, `finite-state-language` on npm
(spec `fsl-typescript/spec/fsl-js-ts.md`, whose §8.4 reserves the SBB names on
that side and §11.5 records this rule) — and Trix is a real consumer of the
second. Two implementations of one language may diverge on *mechanism*; they
must not diverge on *names*, because a name is the only thing a reader carries
from one dialect to the other.

**S14 — one concept, one name.** A concept present in both dialects is spelled
the same in both, modulo the casing convention of each language (`snake_case`
vs `camelCase`) and the `fx.` namespace TS uses where Elixir has bare macros.
Where the two spellings differ today, **the two converge — breaking and
reimplementing on either side is acceptable**; `finite-state-language` is
0.x with one known consumer, and Elixip carries deprecated aliases the way
`sub_fsm` was carried into 1.5.0.

| Concept | Elixir | TypeScript | Status |
|---|---|---|---|
| spawn a child machine | `spawn_fsm/2` | `fx.spawn` | **converged 1.5.0** — was `sub_fsm`, kept as a deprecated alias |
| enter a sub-machine (SBB) | `sbb_fsm/2` | `fx.sbb` | new on both sides — free to fix now, expensive to fix twice |
| return from an SBB | `sbb_return/1` | `fx.sbbReturn` | new on both sides |
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
way: it dispatches on `type` alone and has no pattern matching (spec §10), so
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
deadline (S7) wants exactly that machinery.

**What TS is not expected to support.** Convergence is on names, not on
coverage; a concept absent from one dialect is not a divergence:

- `spawn_fsm` by **file path** (`.exs` resolved next to the declaring file).
  TS machines are ESM imports; there is nothing to resolve;
- [`SIP.Scenario.CallDispatcher`](DESIGN-FSL.md#44-sipscenariocalldispatcher) — handing an inbound INVITE
  to a waiting child has no meaning in a browser;
- `goto back` and the `stay` variants Elixip is adding, already recorded as
  deferred in the TS spec §11.4.

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

### 4.7 Acceptance

The spec is met when both of these hold:

1. the article's target scenario compiles and runs as written — a
   `place_call` state whose body is one `SBB.Call.call(...)` plus an
   `on_events` over `{:call, :connected, _}`, `{:call, :rejected, _}`,
   `{:call, :cancelled, _}` and `{:dialog_terminated, _, _}` — against a real
   callee, cancel race included. The article wrote one block where §5.1 now has
   two, so the criterion covers `bridge()` as well: the `connected` state that
   follows collapses the same way;
2. the `cancelling` state of §3 disappears into `call()` — it is a *branch* of
   establishment, not a block of its own (§5.1), and `{:call, :cancelled}` is
   already how criterion 1 spells its outcome — *without* flattening the
   differences between its copies: `releasing` exits kept (S3), queue
   vocabulary kept (S4), `:ms_event` arms kept (S5). Not every copy is converted
   — `apps/elixip2/scenarios/` deliberately stays raw FSL, so the suite keeps a
   block-free path to regress against and one worked example without the sugar;
   the criterion is met on the kelixip scripts, and the conversion carries the
   CANCEL test those scripts do not have yet. Scope and rationale:
   [service-building-block-design.md §8.3](service-building-block-design.md).

### 4.8 Open questions (deliberately not answered here)

Design work, answered in
[service-building-block-design.md](service-building-block-design.md) — the
nested `sbb_loop/4`, the terminal thrown past every state frame, the shared
context with one reserved sandbox per SBB, and why `sbb_fsm` is rejected inside
an `on_events` clause:

- how a `.exs` scenario pulls in the macro face (`use SBB.Call` semantics,
  compile order, what `SIP.Scenario.Loader` must do);
- state-name and appdata-key collisions between host and SBB FSMs — same
  process, so `ctx.appdata` and the monitor's `laststate` are shared and need
  a namespace;
- the exact `sbb_fsm()` / `sbb_return()` signatures, and how a terminal thrown
  inside an SBB is caught and re-applied by the root runner;
- whether the SBB deadline (S7) is built on a general `task`-like primitive,
  the one §4.6 records as missing on the Elixir side;
- how an SBB publishes a *view* while it runs, not only an outcome event —
  what `--monitor` shows while the host is suspended. Trix's `CallView`
  (republished on every significant change) is the precedent.

Three questions the 2026-08-18 revision **closed**, kept here so they are not
reopened by accident:

- ~~same-process delegation vs. child process~~ — decided by invariant 2 of
  [DESIGN-FSL.md](DESIGN-FSL.md#9-invariants), not by preference (S1);
- ~~what "armed" means across a host `goto`~~ — the host cannot `goto` while
  the SBB runs; there is no "armed" state (S8);
- ~~can two SBBs be armed at once~~ — no, and it needs no diagnostic: one
  point of control, a stack of calls (S1, S12).

## 5. The catalogue

### 5.1 The two flagship blocks: `call` and `bridge`

A call is **two** blocks, not one. The article's `Kelixip.Mod.Call.call/1`
covered the whole of a call's life; splitting it at the seam the six B2BUA
scripts already cut along is a decision of 2026-08-18, designed in
[service-building-block-design.md](service-building-block-design.md).

- **`call(dest, opts)` — establishment.** Places the outbound leg, absorbs the
  provisionals, hunts serially over the peer's targets, and owns the cancel race
  of §3 and timer H. Namespace `:call`; outcomes `:connected` (`%{uri, code}`),
  `:rejected` (`%{code, reason}`), `:cancelled` (`%{}`), `:answered_after_cancel`
  (`%{uri}`), `:timeout` (`%{}`). This is the one that turns the 310-line
  Alice-calls-Bob scenario into the four-arm version;
- **`bridge(opts)` — the established call.** The `connected` state's arms
  (re-INVITE, UPDATE, ACK, INFO, MESSAGE, REFER, the responses) plus
  `wait_far_bye_ok`: protocol plumbing written out in full in every B2BUA
  script, and carrying no policy whatsoever. Namespace `:bridge`; outcomes
  `:caller_hung_up` and `:callee_hung_up` (`%{reason}`) — which side ended the
  call is the outcome's name, not a field to look up — `:max_duration` (`%{}`),
  `:media_lost` (`%{reason}`), and `:interrupted` (`%{message}`) on
  `{:bridge_break, message}`, so a host can take the call back for a moment
  (play a prompt, consult a backend) and re-enter with `bridge(resume: true)`
  without ever tearing the call down. **It is the one block that is not bounded
  by a timer** (S7): a call lasts as long as it lasts, so `bridge()` declares
  `@sbb_timeout :infinity` and is bounded by the dialog instead — the mechanism
  takes `:infinity` for exactly this.

Both live in `:elixip2` under one face module, `SBB.Call`, exporting `call/1`
and `bridge/1` — see S10 and [the design's §7.5](service-building-block-design.md).

**There is no `hangup` block** — confirmed on the converted scripts, where the
SIP teardown left outside the two blocks is one two-line arm. The reason is
structural: a CANCEL cancels
an INVITE transaction in flight, so it belongs inside `call()`, while a BYE ends
an established dialog, so it belongs inside `bridge()`. A block spanning both
would have to take control in the middle of the other's sequence. Nothing is
missing without it either — per §2, the test is whether forgetting the fragment
can leave a phone off-hook, and the scripts answer in their own `on_shutdown`:
*"both legs are wound down by the automatic teardown — CANCEL what is ringing,
BYE what is up — so there is nothing left to do here but say why we stopped."*

### 5.2 Other fragments to look for

Not analysed yet — listed so the SBB design has more than one specimen to fit:

- the **authentication front** of `direct-call-with-auth.exs`: three states
  (`authenticate_caller` / `wait_credentials` / retry) that any scenario gating a
  request on a digest would repeat verbatim;
- **REGISTER challenge/accept/reject**, already noted in CLAUDE.md as
  application-side and therefore duplicated per registrar script;
- **generic menu / prompt-and-collect** — play the choices, collect the DTMF,
  handle retries and fat-fingered input, emit `{:choice, key}` /
  `:disconnected`. Not a B2BUA fragment at all, which is the point: it is the
  specimen that proves the event contract (S2, S13) is service-level, not
  SIP-level.

## 6. Origin

Came out of the 2026-08-11 forwarded-call incident (Alice → Bob hung, then rang
on CANCEL, then carried no media). Three framework bugs were fixed in the course
of it — a Request-URI built from a stored Contact, a body truncated by two
octets against its own Content-Length, and a To tag that killed a server
transaction. The cancel race is the fourth finding, and the only one that is not
purely framework work: it wants to be *visible* in the flow, because a call
answered after its cancellation is a billable and monitorable event, not just a
cleanup.

EB's position, which this document exists to honour: the scripts should carry
states for it — with the SBB layer making that sharing rather than duplication.
