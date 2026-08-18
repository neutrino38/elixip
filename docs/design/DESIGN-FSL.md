# DESIGN-FSL.md — the Finite State Language and its engine

The as-built design of **FSL**, the domain-specific language in which call
scenarios are written, and of the engine that runs them. Everything described
here is implemented and covered by tests; it lives in
`apps/elixip2/lib/dsl/`.

This document is the **why and how it is built**. The language *reference* —
what to write in a scenario, macro by macro, with examples — is
[FSL.md](../../FSL.md); this one explains what those macros expand to and why. The
call, media and B2BUA macros a scenario also uses belong to the session layer:
[DESIGN-FRAMEWORK.md](DESIGN-FRAMEWORK.md). Below both,
[DESIGN-SIPSTACK.md](DESIGN-SIPSTACK.md).

---

## 1. The compilation model

A scenario is a plain Elixir module — usually an `.exs` file — that does
`use SIP.Scenario`. That single line pulls in the language *and* three session
mixins (`SIP.Session.CallUAC`, `SIP.Session.Media`, `SIP.Session.B2bua`), so the
call and media verbs are in scope inside the states without further ceremony. A
server scenario adds its own mixin (`use SIP.Session.CallUAS`,
`use SIP.Session.RegisterUAC`, …).

Each `state name do … end` compiles to a function `__state_<name>/1` taking the
implicit `sip_ctx`. Its body must end with a **transition macro**, which returns
a *transition descriptor* — a tuple the runner consumes:

| Descriptor | Meaning |
|---|---|
| `{:goto, target, desc, type, ctx}` | move to another state |
| `{:stay, desc, type, ctx}` | (error path only — see §2.4) |
| `{:terminal, :success \| :failure \| :aborted, reason, type, ctx}` | the scenario ends |

`@before_compile` generates three introspection functions —
`__scenario_states__/0` (declaration order, which is what `goto next` means),
`__scenario_config__/0`, `__scenario_type__/0` — plus the `run/1` entry point.

**A state never calls the next state.** It returns a descriptor and the runner
performs the transition (§3.2). That is what keeps the call stack flat across an
arbitrary number of transitions: a call that rings for an hour and loops through
a thousand keep-alives has the same stack depth as one that answers immediately.

---

## 2. The language surface

| Macro | Role |
|---|---|
| `config/1` | declare the SIP identity and parameters; builds the initial `%SIP.Context{}` |
| `uas/1` | declare a server scenario (`uas :register` → `:uas_register`) |
| `state/2` | declare a state |
| `goto/1..3` | transition |
| `stay/0..2` | consume an event, keep waiting |
| `on_events/1` | typed `receive` |
| `scenario_success/failure/aborted` | terminals |
| `spawn_fsm/2`, `notify/2`, `notify_parent/1`, `on_shutdown/1` | sub-FSMs and cooperative shutdown |

### 2.1 `config` and the context

`config` stores a keyword list read at instantiation by
`SIP.Scenario.Runner.build_context/1`, which routes each key to one of three
places: a native `%SIP.Context{}` property (`username`, `domain`, `ha1`
computed from `passwd`, …), the `:elixip2` **application env** for a global key
(`proxyuri`, `proxyusesrv`, `optionkeepaliveperiod`, `mediaserver`), or the
context **appdata** map for anything else.

That three-way routing is the whole reason `config` is a macro and not a map:
the same declaration seeds a per-session identity and a process-wide setting,
and a scenario should not have to know which is which.

The `%SIP.Context{}` itself — what a state sees as `sip_ctx`, and what
`ctx_set` / `appdata_set` write into — is described in
[DESIGN-FRAMEWORK.md](DESIGN-FRAMEWORK.md). Two of its fields are owned by the
engine and by nothing else: `currentstate` and `laststate` (§2.3).

### 2.2 `state`

Beyond declaring the function, the `state` macro installs the safety net that
makes a scenario failure *a scenario failure* rather than a dead process:

- it **rescues** exceptions → `scenario_failure("exception!")`;
- it **catches exits** → `scenario_failure("exit!")`. Every SIP primitive is a
  `GenServer.call` toward a dialog or a transport that may have died between the
  check and the call. Until this existed, such an exit killed the scenario
  process outright and `finalize/4` never ran: no B2BUA leg was torn down, no
  media released, and the caller of a relayed INVITE waited forever for a final
  response nobody would send. The stack's own R3/R6 keep the ordinary cases from
  getting here; this is the net under them, so that **whatever happens the
  scenario ends** — which is what runs the teardown that answers the caller;
- it clears the inferred event type and the B2BUA event binding, so a `goto`
  written outside an `on_events` clause is untyped and an `after` body acts on
  the inbound leg rather than on whatever the previous state matched.

### 2.3 `goto`

Four target kinds: a named state, `next` (the next declared state), `loop`
(re-enter this one) and `back` (the state entered before this one). `next`,
`loop` and `back` are reserved words; `back` is mapped at expansion time to the
pseudo-target `:__back__` so it cannot collide with a state actually named
`back`.

**`back` is one slot, not a stack.** The runner writes `ctx.laststate` in
`enter/3` on every transition *that actually changes state* — `goto loop`, an
explicit self-goto and `stay` leave it alone, because re-entering a state is not
"coming from" it. Two consecutive `goto back` therefore toggle between two
states, and `goto back` with no previous state fails the scenario cleanly. A
stack is deliberately out of scope until a scenario needs one.

**The `lasterr` contract.** Every transition macro first checks
`sip_ctx.lasterr`; anything other than `:ok` aborts the scenario as a failure
instead of transitioning. This is what lets a session verb report an error by
writing the context, and a scenario stay readable without an `if` after every
call.

**Event typing.** `goto target, desc, type` records what kind of event caused
the move (`:sip`, `:media`, `:timer`, `:http`, `:db`, …). When the type is
omitted and the `goto` sits inside an `on_events` clause, it is **inferred from
the matched pattern** at compile time (`{:ms_event, …}` → `:media`, the other SIP
tuples → `:sip`) and passed through the process dictionary. An explicit type
always wins. The type is what makes the live monitor and the sequence diagram
readable, so it is collected by default rather than on request.

### 2.4 `stay` — and why it is a rewrite, not a descriptor

`stay` consumes the matched event and goes back to waiting **on the same
`on_events`**, without re-running the state body. `goto loop` cannot do this: it
re-executes the body and replays its side effects — re-sending a request,
re-arming work, re-allocating media. Answering an in-dialog MESSAGE or a
keep-alive OPTIONS inside `call_established` needs exactly that distinction.

The `after` timeout is **not** re-armed: it is the deadline of the *wait*,
computed once when the block is entered (`SIP.Scenario.deadline/1`), and a
`stay` comes back with the time that is left
(`SIP.Scenario.remaining_timeout/1`). Otherwise a keep-alive answered every 10 s
would hold a 30 s answer timeout open forever — a bug wearing a feature's
clothes. This also matches FSL/TS, the TypeScript sibling language, whose
transition model we keep aligned on purpose.

`stay` is **rewritten in the clause AST** into a call back into the wait
closure, rather than returning a `{:stay, …}` descriptor that the clause result
is matched against. The descriptor version is the obvious design and it does not
survive contact with the compiler: Elixir infers the exact type each clause
returns, so in the normal case — no clause stays — the `{:stay, …}` branch is
provably dead and the compiler says so, once per state of every scenario. Nine
warnings for the two built-in scenarios alone.

Consequences of rewriting rather than dispatching:

- the recursion stops at a nested `on_events` / `receive`, and never walks the
  `after` body — a `stay` there belongs to another wait, or to none;
- `stay` outside an `on_events` is caught at **compile time** (`state/2` and
  `on_shutdown/1` walk their body for it);
- the runner still fails the scenario on a `{:stay, …}` tuple that reaches it,
  which is how a `stay` in a hand-written `receive` is reported;
- `stay` is a reserved word inside a state body, like `next` and `loop`.

A `stay` is logged and reported to the monitor like a transition
`(state) -> (state)`, so a scenario whose whole activity is `stay` never looks
frozen in the live view.

### 2.5 `on_events`

A `receive` whose clauses are instrumented at compile time. Four things happen
to every clause:

1. **type inference** from the pattern (§2.3);
2. **auto-store** of the matched event: the pattern is bound through an
   as-pattern and `SIP.Session.CallUAS.auto_store/2` is called on it, stashing an
   inbound INVITE/UPDATE and its transaction pid in the context — which is why
   `reply_invite` needs no argument repeating what just arrived, and why a
   scenario does not carry the request from state to state by hand;
3. **`stay` rewriting** (§2.4);
4. **wait closure**: the `receive` lives inside a self-calling closure so `stay`
   re-enters it without leaving the state function. The closure and deadline
   variables are `Macro.unique_var/2`, so nested `on_events` never capture each
   other's.

Two clauses are **injected** unless the scenario handles them itself, and they
are prepended so a catch-all `_ ->` cannot swallow them first:

| Injected clause | Why |
|---|---|
| `{:scenario_ctl, :shutdown, _}` → `:__shutdown__` | makes every wait cooperatively stoppable (§4.4) without the scenario writer thinking about it |
| `{:ms_event, _, :server_disconnected}` → `:__shutdown__` | the media server's death is delivered to every sink and acted on by nothing: a scenario without a clause for it waits for media that will never come, until its own `after` fires — if it has one |

Both leave the state by construction, so they are instrumented without the
`stay` rewrite — a dead `{:stay, …}` branch there would be one compiler warning
per state, again.

### 2.6 Terminals

`scenario_success` and `scenario_failure` are the two ordinary outcomes;
`scenario_failure` also writes `errorreason` into the context.
`scenario_aborted` is a **third** outcome for a controller-driven wind-down, kept
distinct so a graceful stop is not counted as a failure in the tool's verdict
tally.

---

## 3. The engine

### 3.1 One FSM, one process

`SIP.Scenario.Runner.run_instance/2` runs the whole FSM **in the calling
process**. This is not an implementation detail one could relax: the dialog and
media layers bind SIP and media events to `self()`, so two FSMs sharing a
process would share one mailbox and steal each other's responses and
`{:ms_event, …}`. Every consequence in §4 follows from this single constraint.

`bootstrap_stack/0` starts the SIP layers and is idempotent, so `run(true)` (the
one-shot mode of `mix scenario` and `elixipp`) and `run(false)` (many instances
over an already-started stack) are the same code path.

### 3.2 The loop

`loop/4` applies `__state_<name>/1`, matches the descriptor, resolves the
pseudo-targets, logs the transition, reports it to `SIP.Scenario.Monitor` and
the sequence journal, then tail-calls itself on the next state. Four descriptors
are error paths that end the scenario cleanly rather than crashing it:

| Situation | Outcome |
|---|---|
| `goto` to an undeclared state | failure `{:unknown_state, target}` |
| `goto back` with no previous state | failure, "goto back with no previous state" |
| `{:stay, …}` reaching the runner | failure `{:stay_outside_on_events, state}` |
| anything that is not a descriptor | failure `{:invalid_transition, state}` — a state that forgot its transition macro |

`:__shutdown__` is resolved here too: if the scenario declared `on_shutdown`,
the runner enters it as a state; otherwise it terminates with the `:aborted`
outcome.

### 3.3 Teardown — `finalize/4`

The order is fixed and it matters:

```
shutdown_children      # sub-FSMs first: they release their own resources
  → release_b2bua_legs # a leg left behind holds a call up at the far end
    → release_media    # after waiting for {:dialog_terminated, …}, max 5 s
      → cleanup/1      # the scenario's own optional callback
        → notify_parent_exit
          → flush the sequence journal
```

`release_media` waits for the dialog's termination event before releasing the
media resources, and accepts it **tagged** as well as bare — a B2BUA outbound
leg's `{:outbound, {:dialog_terminated, …}}` says just as much about the call
being over, and ignoring it stalled the teardown for the full five seconds.

---

## 4. Sub-FSMs

### 4.1 The shape

`spawn_fsm target, as: :name, args: %{…}` spawns another scenario as a **separate
monitored process** and stores a `%SIP.Scenario.Child{name, pid, ref, module}`
handle in `ctx.appdata[:__children__]`, so it survives across states. `target` is
a compiled module or a path to an `.exs` file — resolved against the directory
of the file that *declares* it (include semantics), not against the current
working directory. Resolving against the cwd is what made
`spawn_fsm "scenarios/uas_invite.exs"` die with a bare "exception!" for anyone not
standing in `apps/elixip2`.

Decisions, all deliberate:

| Question | Choice |
|---|---|
| parent reference in the child | a dedicated `parent_pid` field on `%SIP.Context{}` |
| OTP coupling | **monitor only** (`spawn_monitor`), no link — a child crash must not kill the parent |
| cleanup when the parent ends | cooperative shutdown message, then a hard kill after a 5 s grace period |
| nesting | a full tree: a child may spawn its own children |
| scope of the shutdown protocol | **generalized** — the same control message any controller uses, including elixipp's graceful stop |
| the event names | `{:parent_msg, …}` / `{:child_msg, …}` / `{:child_exit, …}` since 1.5.0, matching `parent:msg` / `child:msg` / `child:exit` of the TypeScript FSL. They were one `{:scenario_msg, from, …}` for both directions: that names the transport and hides the direction, and TS cannot fold the two into one type because it dispatches on the type alone. A message takes no deprecated alias, so `on_events` warns at compile time when a scenario matches an old shape |
| the name | `spawn_fsm`, after `fx.spawn` of the TypeScript FSL — one name per concept across the two dialects. Spelled `sub_fsm` up to 1.4.1; the old macro is kept as a deprecated alias sharing the same expansion, because `.exs` scenarios are loaded at run time and a rename would break them in the field, not at compile time |

### 4.2 The message protocol

Three families, all plain `send/2` into the FSM's mailbox and matched in
`on_events`:

| Message | Direction | Meaning |
|---|---|---|
| `{:parent_msg, payload}` | parent → child | application message downwards. The sender was always `:parent`, so the name is dropped from the tuple and put in the tag |
| `{:child_msg, name, payload}` | child → parent | application message upwards, tagged with the name the parent assigned at spawn (`as:`), so the parent matches a stable literal in every state |
| `{:scenario_ctl, :shutdown, reason}` | controller → FSM | cooperative stop. The 3-tuple envelope leaves room for future verbs without changing shape |
| `{:child_exit, name, outcome, reason}` | child → parent | how the child ended |
| `{:DOWN, ref, :process, pid, reason}` | OTP → parent | safety net when the child died without reporting |

### 4.3 Cooperative shutdown

A shutdown request is *observed* by the injected `on_events` clause (§2.5), which
jumps to the reserved `:__shutdown__` state. The scenario's `on_shutdown` block
runs there — release resources, send a BYE, end with `scenario_aborted` — and
when there is none the runner ends the scenario as `:aborted` by itself. A
parent tearing down asks every child, waits (bounded) for their `:DOWN`, and
hard-kills the stragglers past the grace period.

### 4.4 `SIP.Scenario.CallDispatcher`

The one piece needed to make a **child** answer an inbound call.
`spawn_child/5` registers a `:uas_invite` child as waiting and installs the
dispatcher as the call-processing module. On an inbound INVITE it hands the
dialog to the first waiting child (`{:accept, pid}`), which then receives
`{:INVITE, req, trans, dlg}` — exactly what a UAS scenario waits for. One child
handles one call; with none waiting the INVITE gets `486 Busy Here`.

Unlike elixipp's `Elixip.ScenarioUAS` factory (see
[DESIGN-ELIXIPP.md](DESIGN-ELIXIPP.md)), it spawns nothing per call: the parent
scenario controls the lifecycle by spawning another child when it wants to take
another call. That is what keeps the FSL layer self-contained — a two-party test
scenario needs no server mode.

---

## 5. Server scenarios

A scenario declares itself a server with `uas :register` / `uas :invite`, which
sets `@scenario_type` and is read back through `__scenario_type__/0`; the
default is `:uac`. `SIP.Scenario.Loader.scenario_type/1` exposes it — that is
how `elixipp` decides between the outbound client mode and the listening server
mode, and it defaults to `:uac` for a module compiled before the annotation
existed.

There is **no separate runner**. `run_instance/2` takes the options a server
instance needs:

| Option | Effect |
|---|---|
| `:dialog_pid` | seeds `ctx.dialogpid`, so the reply macros target that dialog |
| `:inbound_request` | the request that created the instance, also in the mailbox |
| `:parent_pid` | the factory, which gets `{:child_exit, …}` and releases its quota slot |
| `:config_overrides` | the external-JSON overrides (§6) |

`spawn_uas_instance/2` wraps `run_instance/2` in a `spawn_monitor`, which is what
a factory calls per inbound dialog.

Two contracts specific to a server instance:

- **the initial state emits nothing.** It falls straight through to a state that
  waits in `on_events`. There is no race to lose — the triggering request is
  already in the instance's mailbox when it starts.
- **the context is seeded from the inbound request**, not from an account of the
  external config: a server scenario has no outbound `passwd`/`ha1`. Credentials
  for verifying a challenge are resolved at challenge time, from whatever
  account source the application has.

The reply verbs themselves (`accept_registration`, `reply_invite`, …) are
session mixins — [DESIGN-FRAMEWORK.md](DESIGN-FRAMEWORK.md).

---

## 6. External JSON configuration

`SIP.Scenario.ExternalConfig` loads a file holding a header and N accounts, and
parameterizes a run without touching the scenario:

```json
{ "domain": "example.net", "proxyuri": "sip:sip.example.com:5060",
  "accounts": [ { "username": "3397…", "password": "…" } ] }
```

Precedence is one line and it is the whole model:

```
scenario config block  <  JSON header  <  JSON account
```

`overrides_for/2` produces the keyword list for instance *n*, handed to
`run_instance/2` as `:config_overrides`; `build_context/1` then applies the
same three-way key routing as §2.1, so a header `proxyuri` reaches the
application env and an account `username` reaches the context.

Validation is **strict** — unknown key, missing required account field,
unresolved domain or type mismatch all raise with a message naming the offender.
The JSON→atom conversion is restricted to a whitelist of known keys, so a
malformed file cannot exhaust the atom table.

---

## 7. Observability

Two sinks, both no-ops when not started, so a production run pays nothing:

- **`SIP.Scenario.Monitor`** — an in-memory registry of the running instances
  feeding elixipp's `--monitor` live view: one row per call (a sub-FSM gets its
  own, under its parent), holding the scenario name, the last command sent, the
  current state and the event that caused the last transition. The runner reports
  transitions; the session `send_*` macros report commands. Detailed in
  [DESIGN-ELIXIPP.md](DESIGN-ELIXIPP.md).
- **`SIP.Scenario.SequenceJournal`** — a per-instance chronological journal
  (commands, transitions, outcome) kept in the **process dictionary** of the
  scenario process, which is precisely where the runner, the macros and the
  reporting all run. It is therefore isolated per call with no registry and no
  message passing. `SIP.Scenario.SequenceDiagram` renders it as PlantUML at
  `finalize` time, when `--log-sequence` is set or the scenario's debug flag is
  on.

---

## 8. Loading and running a scenario

`SIP.Scenario.Loader` has two entry points and one predicate:

- `load_file!/1` compiles an `.exs` and returns the module that defines both
  `run/1` and `__scenario_states__/0` — the signature of `use SIP.Scenario`;
- `load_module!/1` resolves a name (`"UAC.Register"`) among already-compiled
  modules;
- `scenario_type/1` (§5).

Both paths exist on purpose. `lib/built-in-scenarios/` holds the scenarios
**compiled into** the escript (`UAC.Invite`, `UAC.Register`), which run by module
name with no file present; `apps/elixip2/scenarios/` holds editable `.exs`
copies loaded by path, deliberately under different module names
(`UAC.InviteExample`, `UAC.RegisterExample`) so both can coexist.

`mix scenario` runs either form and exits `0`/`1`, so a scenario is a CI check.

---

## 9. Invariants

1. A state ends with a transition macro and returns a descriptor; it never calls
   the next state (§1).
2. One FSM, one process — because the dialog and media layers bind their events
   to `self()` (§3.1).
3. A scenario always *ends*: an exception or an exit inside a state becomes a
   failure, so teardown runs (§2.2).
4. Teardown order is children → B2BUA legs → media → cleanup → parent (§3.3).
5. `laststate` is written only when the state actually changes (§2.3).
6. `stay` does not re-arm the `after` deadline (§2.4).
7. Every `on_events` is stoppable and media-death-aware, whether or not the
   author thought about it (§2.5).
8. A scenario states a call flow; it does not implement one. A private helper
   carrying real logic in an `.exs` is a missing macro in the framework, not a
   style choice.
