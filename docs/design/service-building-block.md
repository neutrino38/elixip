# Service Building Blocks — reusable FSM fragments

> **Status: first specification (2026-08-12).** Started as a stub capturing the
> problem, one worked example and the invariant. The context announced then has
> arrived — EB's article *"Taming large state machines: Service Building Blocks
> in Elixip"* (2026-08) — and settles the *shape* of the mechanism: an SBB is a
> module exporting macros that launch a sub-state-machine which absorbs
> low-level events and posts high-level ones back to the host. §4 below turns
> that shape plus the specimen's lessons into requirements. It is a
> **specification, not a design**: it says what the layer must provide and how
> to tell it works; the open design questions are listed at the end of §4.

## 1. What the layer is for

Today a scenario is a flat FSM: a list of `state` blocks, each an `on_events`
over the two legs. Two things follow from that shape:

- **every scenario re-states the same protocol sequences.** `b2bua.exs`,
  `direct-call.exs` and `direct-call-with-auth.exs` differ in a handful of
  decisions and agree on everything else. The agreement is copied, not shared;
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

The visible half now exists in all six B2BUA scenarios — the four EB listed,
plus `customer-service.exs` and `apps/kelixip/scripts/b2bua.exs`, because
leaving two of them out is exactly the hole the layer is supposed to close. The
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
Requirements S3–S5 are the three the `cancelling` specimen forced (§3); the
rest come from the article and from the constraints FSL already imposes.

### 4.1 What an SBB is

An SBB is an Elixir module, **written in FSL itself**, that packages
one protocol- or service-level sequence behind a callable face:

```elixir
defmodule SBB.Call do
  defmacro __using__(_opts) do
    quote do
      defmacro call(dest, call_opts \\ []) do
        # glue that launches the SBB finite state machine
      end
    end
  end

  defmodule SBB.Call.Fsm do
    # the complicated FSM that establishes the call goes here,
    # written with the same `state` / `on_events` verbs as any scenario
  end
end
```

- **S1 — callable face.** An SBB exports one or several macros. Calling one
  inside a `state` body *arms* the SBB and returns immediately — FSL's
  non-blocking rule holds, the host keeps its `on_events` loop. The macro
  launches the SBB's FSM through a new `SIP.Scenario.sbb_fsm()` entry point
  (name per the article; the design owns the signature).
- **S2 — high-level event contract.** The SBB talks back to its host
  exclusively through events delivered to the host's `on_events`, matched in
  the same position as protocol events. The event vocabulary is the SBB's
  public API: documented per SBB, meaningful at service level
  (`{:connected, dest_uri}`, `{:rejected, code, reason}`, `{:choice, key}`,
  `:disconnected`), never a raw SIP message. On completion the SBB posts its
  outcome event to the host and its own FSM ends (`scenario_success()` in SBB
  context ends the *SBB*, never the host).

### 4.2 What the specimen requires (S3–S5)

- **S3 — the host names the exits.** An SBB never terminates the host, never
  `goto`s a host state, never chooses between `scenario_success` and
  `scenario_aborted` on the host's behalf. Every outcome is an event; the
  host's arm decides. (The media scenarios leave through `goto(releasing, …)`;
  a fragment that hard-codes the ending is useless to them.)
- **S4 — labels are parameterised.** Every string that reaches the monitor or
  the operator through the SBB is supplied or overridable at the call site.
  (`customer-service.exs` words its outcomes in queue vocabulary; the SBB must
  not degrade what the operator reads.)
- **S5 — unconsumed events fall through.** While an SBB is armed, events its
  FSM does not consume reach the host's `on_events` unchanged, so the host can
  keep arms of its own (`{:ms_event, _ref, :server_disconnected}` in the media
  scenarios). An SBB is extensible, not sealed.

### 4.3 Execution constraints

- **S6 — same call, same legs.** The SBB observes and acts on the *host's*
  session — its dialogs, transactions, `sip_ctx` — because the sequences it
  packages (the cancel race, the hunt, the in-dialog relay) are sequences *of
  the host's call*. This is the load-bearing difference with the existing
  `sub_fsm` macro, whose child runs in its own process with its own legs
  (see §4.5). How event delivery is routed to honour S5+S6 together is the
  central design question — the spec only fixes the observable behaviour.
- **S7 — bounded.** Every SBB carries a completion deadline (defaulted,
  overridable at the call site) and emits a distinct timeout outcome event on
  expiry. No SBB may hold an instance slot open-endedly (§3, *The bound*).
- **S8 — abortable.** The host can leave a state while an SBB is armed
  (`goto` on an unrelated event, cooperative shutdown, `on_shutdown`). The
  SBB winds down without leaking its legs' obligations — which, per S9, means
  at most losing *visibility*, never correctness.
- **S9 — the §2 invariant holds.** A scenario that does not use the SBB is
  still RFC-correct: everything mandatory stays in the framework
  (`answer_nobody_awaits/2` is the model). The SBB packages visibility and
  reusable *policy*, never the only copy of a mandatory reaction.

### 4.4 Distribution and evolution

- **S10 — lives in the base library.** The mechanism (`sbb_fsm()` and the
  glue) belongs to `:elixip2`, available to every derived tool — elixipp
  scenarios and kelixip scripts alike.
- **S11 — kelixip modules can export SBBs.** A loadable module
  (`Kelix.Mod.*`) can ship SBBs (`Kelixip.Mod.Call.call/1` in the article),
  which makes service building blocks dynamically loadable like the modules
  themselves.
- **S12 — SBBs compose.** An SBB's FSM, being FSL code, can itself call SBBs
  — building blocks made of building blocks.
- **S13 — upgrade without touching scenarios.** The compatibility surface of
  an SBB is its event vocabulary (S2). Upgrading an SBB — DTMF menu grows
  voice recognition, then a chatbot, then total-conversation text — must not
  require changes to host scenarios beyond, at most, *additive* arms for new
  events (the banking IVR walkthrough in the article is the reference
  narrative). Combined with BEAM hot code reloading this is what buys
  block upgrades without service interruption.

### 4.5 Relation to the existing primitives

FSL already has `sub_fsm/2` (spawn a *child scenario* in its own monitored
process), `notify/2` and `notify_parent/1` (`{:scenario_msg, name, payload}`
both ways). That is parent↔child between two full scenarios, each with its own
legs — a callee simulator, a load generator. An SBB is a different animal on
two counts: it works on the **host's** legs (S6), and its events land as
first-class `on_events` patterns, not wrapped in `:scenario_msg`. Whether
`sbb_fsm()` is built on `spawn_child` plumbing or on same-process delegation
is a design decision, not a spec one; the spec only requires S5 and S6 to hold
simultaneously.

### 4.6 Acceptance

The spec is met when both of these hold:

1. the article's target scenario compiles and runs as written — a
   `place_call` state whose body is one `Kelixip.Mod.Call.call(...)` plus an
   `on_events` over `{:connected, _}`, `{:rejected, _, _}`, `:cancelled` and
   `{:dialog_terminated, _, _}` — against a real callee, cancel race included;
2. the `cancelling` state of §3 collapses into an SBB call in all six B2BUA
   scenarios *without* flattening their differences: `releasing` exits kept
   (S3), queue vocabulary kept (S4), `:ms_event` arms kept (S5).

### 4.7 Open questions (deliberately not answered here)

Design work, to be answered in a follow-up conception document:

- same-process delegation vs. child process + event routing — how S5 (fall
  through) and S6 (same legs) are honoured together;
- what "armed" means across a host `goto`: does the SBB survive a state
  change, or is leaving the state the abort of S8?
- can two SBBs be armed at once in one state (a call *and* a menu)? If not,
  say so loudly at arm time;
- how a `.exs` scenario pulls in the macro face (`use SBB.Call` semantics,
  compile order, what `SIP.Scenario.Loader` must do);
- state-name and appdata-key collisions between host and SBB FSMs;
- the exact `sbb_fsm()` signature, and whether it subsumes today's
  `spawn_child`.

## 5. Other fragments to look for

Not analysed yet — listed so the SBB design has more than one specimen to fit:

- the **authentication front** of `direct-call-with-auth.exs`: three states
  (`authenticate_caller` / `wait_credentials` / retry) that any scenario gating a
  request on a digest would repeat verbatim;
- **serial hunting** over a peer's targets (`b2bua_hunting?/0` and the loop
  around it), identical in the fork scripts;
- **in-dialog relay**: the `connected` state's default arms (re-INVITE, UPDATE,
  INFO, MESSAGE, REFER, plus the responses) are protocol plumbing written out in
  full in every B2BUA script;
- **REGISTER challenge/accept/reject**, already noted in CLAUDE.md as
  application-side and therefore duplicated per registrar script;
- **call establishment as a whole** — the article's `Kelixip.Mod.Call.call/1`:
  place the outbound leg, absorb provisionals, hunting, the cancel race and
  timer H, emit `{:connected, uri}` / `{:rejected, code, reason}` /
  `:cancelled`. This is the flagship SBB — the one that turns the 310-line
  Alice-calls-Bob scenario into the four-arm version;
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
