# kelixip call control: `queue()` — future work

**Status: partly built.** `call()` exists — see below; `queue()` and the kelixip
objects both verbs take names from do not. This records a direction so the pieces
being built now (the B2BUA primitives of
[DESIGN-FRAMEWORK.md](DESIGN-FRAMEWORK.md#5-b2bua), the registrar, presence) are not shaped in a
way that forecloses it.

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
  (`SIP.Session.Presence.SharedCallAppearece`, and the dialog state the node already holds).
- **availabability state** - this is a state published by the client into the
  presence server using a PUBLISH SIP message. It handles the login/logout
  of the agent.

The queue's distribution algorithm needs to compose these three states to decide
whether the call is to be distributed to the agent or not.

The queue itself need to maintiain an internal state to handle call distribution
policies, penalty, wrap-up, last call taken.

`Kelix.Mod.Queue` would implement the
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
DESIGN-FRAMEWORK.md rather than worked around here. `call()` was written that
way and needed none.

And `elixip2` stays free of any of this: trunks, agents and queues are kelixip
objects, reached from a script the way §3.2 reaches the registrar.
