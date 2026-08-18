# kelixip call control: `call()` and `queue()` — future work

**Status: out of scope.** Nothing here is built or committed to. This records a
direction so the pieces being built now (the B2BUA primitives of
[DESIGN-FRAMEWORK.md](DESIGN-FRAMEWORK.md#5-b2bua), the registrar, presence) are not shaped in a
way that forecloses it.

## 1. Why a layer above the primitives

The B2BUA design is deliberate about where things live: the framework offers
low-level primitives, the scenario writes the policy, and anything expressible
in FSL stays in FSL. That is the right split — but it means a working
call takes a scenario with five or six states, and an ACD queue rather more.
Asked to route a call to a subscriber, an integrator should not have to write
the hunt loop, the early-media rule of §7.4 and the profile ladder of §7.5.

So a layer above, offering the two verbs Asterisk made the vocabulary of the
field:

```elixir
Kelixip.B2bua.call(...)     # the equivalent of Dial()
Kelixip.B2bua.queue(...)    # the equivalent of Queue()
```

They are **not** a replacement for the primitives, and the primitives must stay
usable directly — that is what makes an unusual call flow possible at all. The
two verbs are the paved road, not the only road.

## 2. What it needs from FSL first

`call()` and `queue()` are not functions in the ordinary sense: they run a
**finite state machine** — ringing, early media, fallback, teardown — inside the
caller's scenario, and hand control back when the call ends. FSL has no way
to express that today: `spawn_fsm` spawns a *separate process* with its own
mailbox, which is the wrong shape here, because the SIP events belong to the
calling scenario's dialogs.

So the prerequisite is **reusable FSM fragments**: a named group of states,
parameterised, that a scenario can enter and return from, running in its own
process and mailbox. Roughly:

```elixir
state route_it do
  invoke Kelixip.B2bua.call, peer: trunk("ovh"), profile: :avp, returning: call_done
end

state call_done do
  # the fragment left `sip_ctx` carrying its outcome
end
```

Open: whether a fragment is a macro expanding states into the caller at compile
time, or a runtime construct with an explicit return state. The first keeps the
monitor and the sequence diagram honest (every state is a real state); the
second composes better. This is the design question to settle before either
verb is worth writing.

## 3. What it needs from kelixip

The verbs take *names*, not URIs — that is the whole point. Which means kelixip
has to own the objects those names refer to. Taking `chan_pjsip` as the model,
since it separates cleanly what Asterisk's older channel drivers conflated:

### 3.1 SIP trunks

An `endpoint`-like object: where an operator or a PBX is reached, over which
transport, with which identity.

- outbound **registration** to the far end (an elixip UAC scenario already does
  this — `scenarios/uac_register.exs` — what is missing is running it as a
  supervised, long-lived node service rather than a test run);
- **liveness by OPTIONS**, per `chan_pjsip`'s `aor/qualify`: the dialog layer
  already sends and counts keepalives (`SIP.DialogImpl.KeepAlive`); the missing
  part is a trunk-level *state* (up / down / degraded) other things can read;
- that state is what `%SIP.B2bua.Peer{trunk_pid:}` was reserved for
  (DESIGN-FRAMEWORK.md) — a hunt should skip a trunk known to be down rather
  than time out against it.

### 3.2 Queue agents

An agent is a *subscriber* plus two live states, and neither is the queue's to
invent:

- **registration state** — is a device bound for this AOR? That is the
  registrar's (`Kelix.Mod.Registrar`), and `targets/2` already answers it;
- **busy state** — is the agent on a call? That is presence's
  (`SIP.Session.Presence`, and the dialog state the node already holds).

The queue's own state is what neither of those knows: penalty, wrap-up, last
call taken, login/logout. `Kelix.Mod.Queue` would implement the
`SIP.B2bua.TargetProvider` behaviour of DESIGN-FRAMEWORK.md and join the three
together — which is exactly why that behaviour asks for a reservation handle and
an attempt outcome.

### 3.3 `queue_log`

The target is Asterisk's `queue_log`: one line per queue event (ENTERQUEUE,
CONNECT, COMPLETECALLER, ABANDON, RINGNOANSWER…), which every wallboard and
reporting tool in the field knows how to read. The hunt progress events of
DESIGN-FRAMEWORK.md exist to make it derivable — `:serial_attempting`,
`:serial_not_reachable` with its cause, `:serial_connected`, `:serial_waiting` —
so the mapping is a small module and not an instrumentation project. Worth
checking the mapping is total before §3.6 is implemented, since a missing event
is cheap to add now and awkward later.

## 4. What this does NOT change

The primitives keep their contract. `call()` and `queue()` are written **in**
FSL, on top of `b2bua_forward/3`, `b2bua_try_next/0`,
`b2bua_cancel_forward/0` and the rest — if either verb turns out to need a new
primitive, that is a finding about the primitives, to be taken back to
DESIGN-FRAMEWORK.md rather than worked around here.

And `elixip2` stays free of any of this: trunks, agents and queues are kelixip
objects, reached from a script the way §3.2 reaches the registrar.
