# DESIGN-FSL.md — the SIP binding of FSL

**The language and its engine moved out.** FSL — states, transitions,
`on_events`, `stay`, `goto back`, sub-FSMs, cooperative shutdown, service
building blocks, the live registry, the journal and the PlantUML renderer — is a
package of its own since 2026-09-12, and its as-built design is
[**`finite-state-language/elixir/docs/design.md`**][fsl-design]. Read that first
if the question is about the language.

This document is what stayed: **the SIP binding**. FSL calls back into an
embedding for everything it must not know, and Elixip is the first one — the
answer to "what does SIP add to the state machine".

[fsl-design]: https://github.com/neutrino38/finite-state-language/blob/main/elixir/docs/design.md
[plan]: https://github.com/neutrino38/finite-state-language/blob/main/elixir/docs/extraction-plan.md

The language *reference* an integrator reads is still [FSL.md](../../FSL.md), and
it is deliberately one document rather than two: splitting it into "the FSL part"
and "the SIP part" because the code now lives in two repositories would move a
packaging problem onto the reader. The call, media and B2BUA verbs a scenario uses
belong to the session layer — [DESIGN-FRAMEWORK.md](DESIGN-FRAMEWORK.md); below
it, [DESIGN-SIPSTACK.md](DESIGN-SIPSTACK.md).

---

## 1. What a SIP scenario writes

`use SIP.Scenario`, and that is the name it **should** use: it is the one that
brings the SIP verbs with it.

```elixir
defmodule UAC.Invite do
  use SIP.Scenario

  config username: "toto", domain: "mydomain.com", passwd: "xxxx"

  state calling do
    send_INVITE("sip:bob@mydomain.com", :mediaserver, timeout: 30)
    goto wait_answer
  end
end
```

`SIP.Scenario` (`lib/dsl/SIPScenario.ex`, ~100 lines) is three `use` lines' worth
of SIP verbs — `SIP.Session.CallUAC`, `SIP.Session.Media`, `SIP.Session.B2bua` —
plus `use FSL.Machine, host: SIP.FSL.Host, ctx_var: :sip_ctx`. It also defines
`uas/1`, because `uac` and `uas` are role names in a protocol and the language
has no business knowing them (§3.5).

**The order of those lines is load-bearing.** The session mixins reach
`SIP.Context`, which records `sip_ctx` and this binding's own `set/3` / `get/2` as
the accessors the generic context macros go through — and that has to have
happened before `FSL.Machine` expands a single `state`, because that macro
generates the function head that binds the variable. A module attribute set inside
a `use`'s quote is *evaluated* when the module body runs, while sibling macro
calls are *expanded* before that.

`SIP.SBB` is the same arrangement for a service building block: `FSL.Block` plus
the SIP verbs, because a block runs in its host's process and acts on its host's
call.

---

## 2. The names Elixip keeps

Every module of the engine is reachable under the name three apps, a dozen tests,
`mix scenario` and the kelixip server call it by
(`lib/dsl/SIPScenarioFacades.ex`):

| Elixip's name | The engine |
|---|---|
| `SIP.Scenario` | `FSL.Machine` (+ the SIP verbs, §1) |
| `SIP.SBB` | `FSL.Block` (+ the SIP verbs) |
| `SIP.Scenario.Runner` | `FSL.Runner` |
| `SIP.Scenario.Loader` | `FSL.Loader` (+ the `:uac` default, §3.5) |
| `SIP.Scenario.Monitor` | `FSL.Monitor` (+ the three call-shape columns, §3.6) |
| `SIP.Scenario.SequenceJournal` | `FSL.Journal` |
| `SIP.Scenario.SequenceDiagram` | `FSL.Diagram.PlantUML` |
| `SIP.Context` | `FSL.Context` + the thirteen SIP session fields |
| `HTTP.Session` | `FSL.HTTP` |

These are **not** a transition device to be removed later. `.exs` scenarios and
kelixip scripts are loaded at **run** time, from `/etc/kelixip/scripts` and from
customer directories: a rename a compiler would catch here is a node that fails to
start there.

**Three things a facade cannot forward**, and they did change:

- the **registered name** of the live registry is `FSL.Monitor` — a
  `Process.whereis/1` and a supervision child spec name the process, not a
  function. Four sites: `Kelix.Application`'s tree, elixipp's `--monitor`
  bootstrap, `Kelix.InstancePool`'s subscription, and the runner's own `whereis`;
- its **push tag** is `{:fsl_monitor, …}`, with `Kelix.InstancePool`'s two
  `handle_info` clauses. Not compile-checked: a missed clause is a message that
  falls through and a live view that silently stops updating;
- `%FSL.Child{}` — a struct has no alias.

---

## 3. `SIP.FSL.Host` — what SIP adds to the state machine

`lib/framework/SIPFSLHost.ex`. Thirteen callbacks of the `FSL.Host` behaviour, and
the reason this module exists is as much readability as decoupling: the same
answers used to be spread across three files and two macro expansions — three
`use` lines, three calls injected into every `on_events` clause, one on state
entry, a media clause, an inference table, and four more couplings inside the
runner's teardown. Read here, top to bottom, it is one module.

The behaviour itself, and what each callback is *for*, is
[the package's design doc][fsl-design] §3. What follows is SIP's answers.

### 3.1 `bootstrap/0` — the layers

Transactions, the transport selector, the dialog layer, the session config
registry, and the node's auth secret (one server secret for the node's lifetime,
keying every digest nonce). Idempotent, so `run(true)` and `run(false)` are the
same code path. `SIP.Scenario.start_stack/0` is the public spelling.

kelixip supervises those layers itself instead (`Kelix.Application`), which is
why this is a callback and not a fixed startup.

### 3.2 `build_context/1` — the three-way routing

One `config` keyword list, three destinations, and a key goes to exactly one:

| Kind of key | Destination |
|---|---|
| a native property — `:username`, `:domain`, `:authusername`, `:displayname`, `:algorithm`, `:debug` | a `%SIP.Context{}` field |
| a **global** key — `:proxyuri`, `:proxyusesrv`, `:optionkeepaliveperiod`, `:mediaserver` | the `:elixip2` application env |
| anything else | `appdata`, so a scenario can read it back |

That routing is the whole reason `config` is a macro and not a map: the same
declaration seeds a per-session identity and a process-wide setting, and a
scenario should not have to know which is which. This is the single place the
global keys are applied, whether they come from the `config` block or from an
external JSON header (§4), so a scenario no longer has to `Application.put_env`
by hand in its `initial_state`.

`:passwd` is applied **last**, because computing `:ha1` needs `:authusername`,
`:domain` and `:algorithm` to be set first — which is why it cannot simply be a
fourth clause in the fold.

### 3.3 `apply_run_opts/2` — the two options only SIP can read

A UAS scenario does not create its dialog: the inbound request did, before the
instance existed.

| Option | Effect |
|---|---|
| `:dialog_pid` | seeds `sip_ctx.dialogpid`, so the reply macros target that dialog |
| `:inbound_request` | the request that created the instance, also in its mailbox. **Its presence is what makes this a server instance** as far as `account/2` is concerned |

FSL owns `:parent_pid`, `:self_name`, `:appdata`, `:slot_id` and
`:config_overrides`, and hands the rest over.

### 3.4 `on_event/2` and `on_state_enter/1` — every event

Three things, and the order is why they are one function:

1. **which leg, which transaction** (`SIP.Session.B2bua.note_event/1`). First,
   because it is what the `b2bua_*` verbs read to know where to act: a clause
   replying to the event it just matched is not asked for a direction.
2. **what a leg that has just died owes** (`note_leg_event/2`). A dialog dying is
   not news the scenario has to translate: whatever it decides next, the requests
   that leg was going to answer never will be, and someone is waiting for each of
   them. They are answered here, at once, on the leg they came from — so the
   caller hears about its callee going away now rather than at the teardown
   ([DESIGN-SIPSTACK.md](DESIGN-SIPSTACK.md#57-resilience), R6).
3. **the inbound request, stashed last** (`SIP.Session.CallUAS.auto_store/2`),
   with the dialog pid, in the slot `reply_invite*` and `last_uas_req/0` serve.
   That slot is why a scenario does not carry the request from state to state by
   hand.

`on_state_enter/1` forgets the leg and the transaction, so an `after` body acts on
the inbound leg rather than on whatever the previous state matched.

### 3.5 `event_type/1` and the `uas` vocabulary

`:ms_event` is `:media`; **anything else** SIP is shown — a method atom, a status
code, a bound variable — is `:sip`. The fallback is the point, and it is why this
is a host decision: an unrecognised leading atom read as coming *from the peer*,
and drawn that way in the sequence diagram, is a sentence about SIP.

`uas :register` sets FSL's opaque `__scenario_type__/0` slot to `:uas_register`;
`SIP.Scenario`'s `__using__` sets `:uac` as the default, and
`SIP.Scenario.Loader.scenario_type/1` applies it for a module compiled before the
annotation existed. `elixipp` reads it to decide between the outbound client mode
and the listening server mode.

### 3.6 `account/2` and the monitor's columns

`account(ctx, :initial)` answers the identity the inbound request asserts —
digest username, else P-Asserted-Identity, else From, the framework's single
reading of that question (`SIP.Msg.Ops.asserted_username/1`). A UAC keeps showing
its own account.

`account(ctx, :subsequent)` answers `""` for a server instance, and that is not
laziness: an empty username is how the registry is told *keep what you have*.
Re-pushing the resolved identity on every transition would clobber the AOR a
registrar noted or the conference DID an MCU call joined with
`note_account/1` — which are the whole point of that call.

"Is this a server instance" is decided on the **inbound request**, not on the
`uas` annotation: that annotation tells `elixipp` to open listeners, and a kelixip
script carries none — the server knows a script serves inbound traffic from
`domains.toml`.

Three columns are SIP's, declared with their defaults by
`SIP.FSL.Host.monitor_columns/0` and passed to the registry by whoever starts it:
`medias`, `mediaserver`, `outbound`. Each is written through the generic
`FSL.Monitor.note/2` by a one-line wrapper on `SIP.Scenario.Monitor` — they are
*values*, not mechanism: a list of media kinds rendered as letters
(`SIP.Msg.Ops.media_kinds/1`), a server's declared name, and a URI rendered as a
request target (`SIP.Uri.serialize_ruri/1`).

### 3.7 `injected_clauses/1` and `clause_covers?/2` — the media failure domain

One clause, prepended to every `on_events`: the media server going away.
`:server_disconnected` is delivered to every sink and acted upon by nothing, so a
scenario without a clause for it would sit waiting for media that cannot come
until its own `after` fires — if it has one. Six reference scenarios closed that
by hand; the seventh was always going to forget
([DESIGN-FRAMEWORK.md](DESIGN-FRAMEWORK.md#67-the-media-server-as-a-failure-domain),
R8).

The reaction is the cooperative shutdown a controller would have asked for, so
`on_shutdown` runs if declared (`:aborted` otherwise), the legs and the media are
released, and the caller is answered. R6's rule applied to the media plane: a dead
resource ends the call it was serving, promptly, instead of being discovered at
teardown. Idempotent by construction, because it leaves the state.

The suppression test is **deliberately generous**: a clause matching
`{:ms_event, _, :server_disconnected}` obviously covers it, but so does one
matching every media event, and so does a catch-all. Erring that way leaves the
scenario in charge, which is the safe direction.

> **The asymmetry with FSL's own shutdown clause is deliberate.** That one is the
> FSM control protocol and only an explicit `:scenario_ctl` clause opts out of it;
> a scenario that merely writes `event -> …` has not thereby declined to be
> stoppable, and one that could not be stopped would be a node that cannot drain.
> This one is a policy default.

### 3.8 `finalize/1` — the legs, then the media

One callback and not two, because the order between them is one rule: a leg left
behind holds a call up at the far end, and it is the leg that carries the media
the server is about to stop serving. Releasing the media first would leave the far
end with a live call and nothing on it.

`release_media` waits (bounded, 5 s) for the dialog's termination event before
releasing, and accepts it **tagged** as well as bare — a B2BUA outbound leg's
`{:outbound, {:dialog_terminated, …}}` says just as much about the call being
over, and ignoring it stalled the teardown for the full five seconds with no error
at all.

Where this step sits among the other four — children, the binding, `cleanup/1`,
the parent — is the FSM's and stays in `FSL.Runner`.

**What it is handed is the context the failing state had built**, and that takes
a mechanism rather than a convention: the context is a stack variable, and the
`rescue` clause of `state` sees the bindings of the moment the `try` was entered.
So the three doors a scenario writes this context through — `SIP.Context.set/3`,
`appdata_set/3` and `assert_identity/2` — each hand what they produce to
`FSL.Context.snapshot/1`, which keeps it off the stack, and the clause reads it
back with `FSL.Context.latest/1`. A scenario whose `place_call` state raised
after setting both legs up released neither of them, held its MCU session until
the RTP watchdog, and left the caller unable to hang up (dev71, 2026-09-21).

### 3.9 `journal_started/1` and `journal_collect/0` — the SIP trace

The sequence journal lives in the scenario's process; the SIP messages never pass
through it. The transaction layer sends and receives them on behalf of a dialog,
so what a traced run put on the wire has to be recorded elsewhere and handed over.
`SIP.Scenario.SipTrace` is that elsewhere, and these two callbacks are how it is
plugged into `FSL.Journal` — which knows nothing of SIP beyond a `:message` event
it draws as it is told.

`SipTrace` is one public ETS table, `:sip_scenario_trace`, with two kinds of row:
who traces for whom (`{:watch, pid}` → `{scenario_pid, leg_tag}`), and the
recorded events, in order.

- **`journal_started/1`**, called in the scenario's process when its journal
  starts: the scenario watches itself. A dialog that learns its application
  (`SIP.DialogImpl.bind_app/2`, the one place it does) binds itself to the
  scenario that application is traced under, with its leg tag. Two things predate
  the journal and are caught up here: the dialog already in the context — a UAS
  instance's, or a UAC's when `debug` was set mid-run — is adopted; the request a
  UAS instance was spawned for, which crossed its transaction before anyone
  traced, goes straight in with `FSL.Journal.record/1`.
- **The transaction layer records**, against its `app` pid, every message it puts
  on or takes off the wire — first copy and retransmissions alike: through
  `SIP.Transac.Common.sendout_msg/2`, the two retransmission timers of
  `SIP.Trans.Timer`, the last-response resend of `SIP.IST` and `SIP.NIST`, and
  the eight `{:onsipmsg, …}` clauses. A retransmission is re-sent from its wire
  form, and read back through `SIPMsg.parse/2`, not a regex of its own.
- **`journal_collect/0`** hands the rows over at flush, and forgets them and the
  bindings. `FSL.Journal` merges them with its own events on the timestamps, and
  calls it again at `clear/0` so a run that never flushes leaves nothing behind.

The event is built here, in SIP terms, and drawn there without them: `lane` is
the Call-ID, `party` the leg tag, `peer` the address and transport
(`10.0.0.1:5060/udp`), `label` the line a reader expects (`INVITE #1 +SDP`,
`200 OK / 1 INVITE`, `(retransmission)`), `reply` for a response, `repeat` for a
retransmission. The renderer gives each Call-ID a lane, so a B2BUA shows its two
legs side by side and a registration next to a call gets a lane of its own.

**Why the transaction layer.** It is the one that has both what went out and for
whom. A transport instance sees every byte but knows only a socket; a dialog
knows its scenario but sees a copy of each message, without the retransmissions
or the ACK of a non-2xx. A transaction sees everything the wire carries and knows
its dialog, which knows its scenario: two hops, one table. The price is what a
transaction never sees — a stateless reply of the dialog layer (a 481 to a request
no dialog matches), an out-of-dialog OPTIONS — documented in
[ELIXIPP.md](../../ELIXIPP.md).

**The cost when nobody traces.** The table does not exist until the first scenario
watches itself, so every hook stops at an `:ets.whereis`. Once it exists, a message
of an untraced dialog costs one key lookup. The GenServer that owns the table
monitors each watched scenario and drops the rows of one that dies without
flushing.

---

## 4. External JSON configuration

`SIP.Scenario.ExternalConfig` (`lib/dsl/SIPScenarioExternalConfig.ex`) stays
Elixip's: its whole model is SIP accounts. It loads a file holding a header and N
accounts and parameterizes a run without touching the scenario:

```json
{ "domain": "example.net", "proxyuri": "sip:sip.example.com:5060",
  "accounts": [ { "username": "3397…", "password": "…" } ] }
```

Precedence is one line and it is the whole model:

```
scenario config block  <  JSON header  <  JSON account
```

`overrides_for/2` produces the keyword list for instance *n*, handed to
`FSL.Runner.run_instance/2` as `:config_overrides` — which is already the seam.
`build_context/1` then applies the same three-way routing as §3.2, so a header
`proxyuri` reaches the application env and an account `username` reaches the
context.

Validation is **strict** — unknown key, missing required account field,
unresolved domain or type mismatch all raise with a message naming the offender.
The JSON→atom conversion is restricted to a whitelist of known keys, so a
malformed file cannot exhaust the atom table.

---

## 5. `SIP.Scenario.CallDispatcher`

The one piece needed to make a **child** scenario answer an inbound call, and the
implementation of `c:FSL.Host.spawn_child/2` for a `:uas_invite` child.

`spawn_child/5` registers the child as waiting and installs the dispatcher as the
call-processing module — unless the application already configured one
(`Elixip.ScenarioUAS` in elixipp server mode), which is never silently
overridden. On an inbound INVITE the dispatcher hands the dialog to the first
waiting child (`{:accept, pid}`), which then receives `{:INVITE, req, trans,
dlg}` — exactly what a UAS scenario waits for. One child handles one call; with
none waiting the INVITE gets `486 Busy Here`.

Unlike elixipp's `Elixip.ScenarioUAS` factory
([DESIGN-ELIXIPP.md](DESIGN-ELIXIPP.md)), it spawns nothing per call: the parent
scenario controls the lifecycle by spawning another child when it wants to take
another call. That is what keeps a two-party test scenario self-contained — it
needs no server mode.

---

## 6. Server scenarios

There is **no separate runner**. `FSL.Runner.run_instance/2` takes the options a
server instance needs (§3.3), and `spawn_uas_instance/2` wraps it in a
`spawn_monitor`, which is what a factory calls per inbound dialog.

Two contracts specific to a server instance:

- **the initial state emits nothing.** It falls straight through to a state that
  waits in `on_events`. There is no race to lose — the triggering request is
  already in the instance's mailbox when it starts.
- **the context is seeded from the inbound request**, not from an account of the
  external config: a server scenario has no outbound `passwd`/`ha1`. Credentials
  for verifying a challenge are resolved at challenge time, from whatever account
  source the application has.

The reply verbs themselves (`accept_registration`, `reply_invite`, …) are session
mixins — [DESIGN-FRAMEWORK.md](DESIGN-FRAMEWORK.md).

---

## 7. What `SBB.Call` is, and why it is here

`lib/dsl/sbb/call.ex`. A **concrete** service building block, written in FSL, that
does the B2BUA call flow: the hunt loop, the early-media rule and the profile
ladder an integrator should not have to write in order to route a call to a
subscriber. `call()` after Asterisk's `Dial()`; `bridge/1` came with it, the
established call being a block of its own.

It is a **consumer** of the block mechanism, not part of it — which is why the
extraction left it here while `FSL.Block` moved. It is in `:elixip2` rather than
in a kelixip module because it is call flow rather than server policy, and both
FSL dialects want it. `queue()`, after `Queue()`, stays future work and stays
kelixip's, because it takes names for objects the server owns.

Design: [DESIGN-SBB.md](DESIGN-SBB.md).

---

## 8. Invariants of the binding

1. The scenario-visible surface did not change across the extraction: no `.exs`
   scenario, no kelixip script and no `use SIP.Scenario` line was touched.
2. `%SIP.Context{}` is `FSL.Context.fields()` plus the SIP session's, and
   `@after_compile FSL.Context` makes forgetting the first half a compile error.
3. Message interpretation stays in the message layer, in exactly one place — see
   CLAUDE.md. `SIP.FSL.Host` reads a request in exactly two callbacks
   (`account/2`, `on_event/2`) and delegates both readings.
4. A scenario states a call flow; it does not implement one. A private helper
   carrying real logic in an `.exs` is a missing macro in the framework, not a
   style choice.
5. A state that fails tears down what it had allocated: `finalize/1` reads the
   context the state built, not the one it was entered with (§3.8).
6. No SIP symbol may reappear in `lib/fsl/` of the package — enforced by
   `mix compile --warnings-as-errors` over there, in a project that depends on no
   binding. The whole [extraction plan][plan] exists to keep that true.
