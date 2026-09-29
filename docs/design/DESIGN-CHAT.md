# DESIGN-CHAT.md — instant messaging

What kelixip does with MESSAGE: peer-to-peer chat, chatrooms, attachments,
offline delivery, and scenarios acting as chatbots.

The build order of objective 1 is [chat-basic-plan.md](chat-basic-plan.md).

Presence is its neighbour, not its subject: the subscription layer, the event
packages, the buddy list and the consent flow are
[DESIGN-PRESENCE.md](DESIGN-PRESENCE.md). The two meet at the Silo, which holds a
message until a device registers, and in the composite state that says whether a
correspondent is reachable at all.

## Objectives

**1 — Peer-to-peer instant messaging (MESSAGE).** Between two subscribers of a
domain, with the sender's message stored and delivered later when the recipient
has no reachable binding.

Sending: can a user record an audio / video / text message, or a photo, and push
it as an attachment?

**2 — Instant messaging between a UA and a scenario acting as a chatbot**, with
long-lived sessions.

The first idea is `.exs` scenarios able to describe chatbot flows and to resume a
conversation when needed.

## Dispatch: `chat` is a function of its own

`Kelix.Router` files MESSAGE under the `presence` function today. It becomes a
fourth `function_kind`, `:chat`, selected the way the dial plan is: the
`[[domain.chat]]` blocks are tried in order, the first whose `pattern` matches
the R-URI user part wins, and the block carrying `default = true` is the
catch-all and must come last.

```toml
[[domain.chat]]
pattern = "mybot"
script = "mybot.exs"

[[domain.chat]]
pattern = "room-."            # dial-plan syntax: `.` is one or more of anything
script="chatroom.exs"

[[domain.chat]]
default = true                    # catch-all, must be last
script="p2p-chat.exs"
```

SUBSCRIBE and PUBLISH stay with `presence`; only MESSAGE moves. A domain with no
`[[domain.chat]]` block does not have the function, and a MESSAGE for it is
answered 405 with `Allow`, like any other disabled function
([DESIGN-KELIXIP.md](DESIGN-KELIXIP.md#4-dispatch)).

This concerns the **out-of-dialog** MESSAGE only. One sent inside an established
call reaches its dialog, and therefore the scenario running that call, without
passing through the Router at all.

## The Silo module

Store-and-forward: a MESSAGE addressed to an AOR with no reachable binding is
stored and delivered when one of the user's devices registers. Retention period,
per-AOR count and size limits, persistence across a restart.

### It is not tsilo

The kamailio module the idea comes from solves a different problem, and the
difference decides the design:

| | tsilo | this Silo |
|---|---|---|
| what is stored | a **live server transaction** | a **message**, serialized |
| what the sender already got | nothing final — it is waiting | a final (202) |
| horizon | seconds to a minute (transaction timers) | hours, days |
| persistence | impossible: a process and a socket | required |
| delivery | a branch added to the existing transaction | a **new** UAC transaction |
| failure | 480/408 to the caller who waited | an IMDN, or nothing |

**The tsilo half needs no module here: the B2BUA already has it.** An INVITE for
an unregistered user is a `SIP.B2bua.TargetProvider` answering `{:wait, ms}` —
the `%Hunt{}` outlives the leg precisely because "the caller is queued and
nothing has been dialled yet", the transaction stays with the B2BUA, and the
provider hands over a target once a contact appears. It is the same mechanism the
ACD needs for an agent becoming free. Delayed forking is therefore a provider, not
a silo, and the Silo must not grow that second face — the push-woken INVITE,
kamailio's tsilo case, is written out step by step in
[DESIGN-PRESENCE.md](DESIGN-PRESENCE.md#push-and-the-deferred-invite).

### No coupling with the registrar

tsilo is woken by the REGISTER script itself, not by the registrar, and that is
the right model here too — for a stronger reason than purity: **ordering**.
Delivery must happen *after* the 200 OK to the REGISTER; a MESSAGE pushed while
the client is still completing its registration is lost. An event emitted from
`save/2` would fire too early. The script sequences it: `save` → reply 200 →
`Silo.flush(aor, contacts)`.

So the question this section used to ask — require a registrar in the same
domain, or define a behaviour? — is answered by **neither**. The Silo does not
know the registrar, the registrar does not know the Silo, and the behaviour has
no object. The same holds for deciding whether an AOR exists at all: that is
`auth_db`'s answer, read by the script, which returns **404** rather than storing
for a destination that does not exist — otherwise filling a node's storage costs
an attacker nothing.

The price of script-side wiring is that a script which forgets the call fails
silently. The guard is a metric — *messages expired with no delivery attempt* —
not a coupling.

> One case has no script to hang on: a binding **expiring**. Nothing arrives to
> announce it. The Silo does not care; the composite presence state does, since a
> watcher must learn that Alice went offline. That event is owed by the registrar
> to presence, and is settled with objective 1 — not here.

### A kelixip module, not elixip2

Its profile is the registrar's, feature for feature: persistent state,
per-domain configuration (retention, quotas), strong isolation, and an obvious
control surface (list and purge an AOR's queue, expose the counters). The three
arguments for elixip2 do not survive contact:

- *testing it without kelixip* — modules are already tested in
  `apps/kelix_modules`, the only place both halves are present;
- *elixipp might need it* — elixipp plays UACs and UASs; a silo has no role in a
  test scenario except to test the silo, which is done from `kelix_modules`;
- *rebuilding the message is SIP* — true, and that is exactly the part which does
  belong to elixip2: **the rebuilding primitives, not the silo**. They belong to
  the message layer regardless.

The deciding rule is kelixip's own: the core ships no SIP function, functions are
modules. Store-and-forward is a SIP function.

### What is stored

Not the raw message replayed. Via, Call-ID, CSeq, Max-Forwards and Route belong
to the transaction, and delivery is a new one. What is kept is the identities,
the Content-Type, the body, the arrival date, and an **allowlist** of headers to
preserve — Subject, the IMDN headers, Conversation-ID / Contribution-ID for RCS,
P-Asserted-Identity. The request that goes out is rebuilt through
`SIP.MsgTemplate`.

### Multi-device: fan out at delivery, not at storage

Every modern client — and IMDN with them — expects the message on every device.
Duplicating it per device at storage time asks a question with no good answer
(the devices known when it was sent, or the ones that will appear during
retention?), so the fan-out happens at delivery instead: **one stored message,
carrying the set of devices already served**. Each flush delivers to the present
contacts absent from that set and adds them to it. A device registering two days
later still gets what is in retention, and storage does not grow with the number
of devices.

**A device is identified by its `+sip.instance`** (RFC 5626), never by the
contact URI or the IP, which change at every re-registration and would cause the
same message to be delivered again. It is a header parameter, read with
`get_header_param/2` — the case the two-parameter-sets rule exists for. A device
sending none falls back to its contact URI, with the duplicate risk accepted.

Consequence to accept: a message is never "consumed". Retention and quotas are
the only reclamation mechanisms.

### Retention

Three sources, in precedence order, and the domain has the last word:

1. **the sender asks**, in standard SIP: on a non-INVITE request `Expires` gives
   the lifetime of the *content* (RFC 3261 §20.19). A MESSAGE carrying one is
   already saying how long it is worth storing. Read in the message layer like
   every other header, never re-derived by a script;
2. **the script imposes** — `Silo.store(msg, retention: 120)` — because it knows
   what configuration cannot: a one-time code is worth two minutes, a personal
   message three days;
3. **the domain defaults**, and **caps**: the granted retention is the requested
   one bounded by the domain's maximum. Same demand-and-bounds shape as
   `check_register/1`, and what stops a sender from granting itself three weeks
   of storage.

**Two timers, never merged into one**: *retention* (how long the message stays
deliverable — hours, days) and the *wake-up window* (how long a REGISTER is
awaited after a push before the push counts as lost — seconds, minutes).

On expiry with no delivery, the loop closes back on the sender: an IMDN `failed`
if the MESSAGE asked for one, otherwise a counter — the one that betrays a script
which forgot to call `flush`.

### Push is the other half of the same flow

Store, push, await the REGISTER, deliver. The Silo holds the message and the
wake-up window; the push service holds the device tokens of objective 1. Neither
is useful alone for a sleeping mobile.

### Horizontal scale

Several kelixip nodes serving one domain is a requirement (scale-out and
redundancy), which settles the storage:

- **shared storage, in SQL — MySQL/MariaDB *or* PostgreSQL** — the pair
  `auth_db` already supports: `Kelix.Mod.AuthDb.Pool` takes
  `driver = "mysql" | "postgres"`, MyXQL and Postgrex share the same connection
  options, and both drivers are already dependencies of `apps/kelixip`. Only the
  default port and the placeholder syntax (`?` versus `$1`) differ. Redundancy
  becomes the database's (solved) problem, and no Erlang cluster is required of
  operations. **The dependency on an external RDBMS is accepted**, which settles
  the two alternatives: a replicated mnesia (`disc_copies` — literally persistent,
  replicated ETS, and the only serious contender) would buy a split-brain on a
  partition between sites and a schema to administer for the same service, and
  plain ETS is ruled out by what separates this module from the registrar.

  > **Why the registrar may live in ETS and this module may not.** The
  > registrar's data is rebuildable by its own owners: a binding lost in a restart
  > is recreated by the handset within the minute. A stored message is not — it is
  > gone, and the sender already got its 202. That is what makes persistence a
  > requirement here and a convenience there. ETS keeps one legitimate role: a
  > local index in front of the database ("does this AOR have anything pending?"),
  > to spare an SQL round trip on every REGISTER. Positive entries only — a
  > negative cache would be wrong across nodes, since a message stored by A
  > invalidates nothing on B;
- **waking stays local**: the REGISTER reaches node B, B reads the shared store
  and delivers over the contact it has just registered itself. No inter-node
  message — the junction is made through the data;
- **a lease, not a plain table**: two nodes can flush one AOR at the same
  instant. Each attempt claims a message with a conditional update and an
  expiring lease, so a node dying mid-delivery does not hold it forever. It is a
  work queue.

Supporting both engines costs more here than it does in `auth_db`, which only
reads. Three rules keep the cost flat:

- **the claim is a conditional UPDATE, not `SKIP LOCKED`.**
  `UPDATE … SET claimed_by = ?, claimed_until = ? WHERE id = ? AND claimed_by IS
  NULL`, then read the affected-row count. It is portable to every version of
  both engines, where `SELECT … FOR UPDATE SKIP LOCKED` would impose PostgreSQL
  ≥ 9.5 and MariaDB ≥ 10.6 for no gain at this volume;
- **the dialect differences are known and few**: `BLOB` / `BYTEA` for the body,
  `DATETIME` / `TIMESTAMPTZ` for the dates, `BIGINT AUTO_INCREMENT` / `BIGSERIAL`
  for the key, `ON DUPLICATE KEY UPDATE` / `ON CONFLICT DO UPDATE` for an upsert,
  plus the placeholders. Everything else is one statement for both;
- **the module owns a schema, and does not migrate it.** Unlike `auth_db`, which
  reads a base someone else owns, the Silo needs tables of its own. The DDL for
  both engines ships with the package; the module checks the schema and its
  version at start and **refuses to start** if it is absent or stale, rather than
  altering a production database by itself.

**The pool is the Silo's own, never `auth_db`'s.** Sharing one pool between the
two modules fails on four counts, the first of them blocking:

- **it is not necessarily the same database.** `auth_db` reads the subscriber
  base, which usually belongs to the operator's own IS — another host, sometimes
  read-only, possibly another engine than the one chosen for the silo. A pool
  points at one target; sharing assumes a coincidence nothing guarantees;
- **the grants differ.** `auth_db`'s account should hold SELECT alone on a base
  containing every HA1; the Silo writes and deletes. One pool means one account —
  so either write access on the subscriber base, or read access to the secrets
  from the silo. That is a security property, not a preference;
- **it would couple latency on the worst path.** A node catching up on a burst of
  deliveries after a restart saturates its pool; behind a shared one, REGISTERs
  queue up — and authentication is exactly what must not depend on the silo's
  throughput. The two `pool_size` values size on unrelated profiles anyway;
- **modules are independent by construction.** `[module.silo]` must work with no
  `[module.auth_db]` configured. A shared pool would recreate a module-to-module
  dependency, the one this design refused for the registrar.

What is shared is the **code and the configuration, not the connection**: the
opening logic — TLS first, backoff, driver resolution, the common option set —
is written once inside `auth_db`'s pool today and private to it; it is that code
the Silo needs, not a second copy, since copied the two will diverge — the
failure this codebase has already paid for once. Extracted as a common
`Kelix.DB.Pool`, optionally fed by defaults from a shared `[database]` block in
`config.toml`, each module keeps its own block, its own account and its own named
pool (`Kelix.Mod.Silo.Conn` beside `Kelix.Mod.AuthDb.Conn`).

One pool per module, not per domain — `auth_db` registers a single connection
pool under a fixed name, and domain isolation lives in the schema. The Silo
follows it: the domain is a column, never a pool.

> **Scale-out itself is out of scope for this document.** It is not a property of
> this module: it reaches the registrar — whose
> bindings are per-node ETS today, and whose `flow_pid` makes a binding created on
> B unusable from A — and presence, whose PUBLISH on A must notify watchers whose
> subscriptions live on B. Three tiers: **data without a process** (this module,
> published states, ACD queues), which shared storage settles; **the registrar**,
> where only the flow is hard; and **live processes** (dialogs, subscriptions,
> B2BUA legs, media sessions), which are not shared but located and routed. The
> standing recommendation is independent nodes coordinated through the database,
> with `Path` / Service-Route for the flow, rather than an Erlang cluster whose
> partition turns a local failure into a global one. A track of its own, to be settled in
> [DESIGN-KELIXIP.md](DESIGN-KELIXIP.md) before it gets decided three times
> incompatibly.

## Conversations

Page mode follows no dialog: every MESSAGE opens one of its own and closes it
60 s later. A chat scenario is therefore bound to a **conversation**, not to a
dialog — a key declared per `[[domain.chat]]` block (`pair`, `peers`, `to`)
built from the `From` and `To` AORs, never from the source address. The source
decides **trust** (whether a message is re-challenged), not routing. A
conversation ends when idle, can hibernate on request into a serialized state,
and expires on the `conversation` module's TTL. The phases are C3b–C3d of
[chat-basic-plan.md](chat-basic-plan.md).

## Peer-to-peer chat

A chat B2BUA — to be specified. A MESSAGE is not a session, so "B2BUA" here
cannot mean the two-leg machinery of a call: what is relayed is a transaction and
an identity rewrite, not a dialog with legs. What the term should name is open.

## Chatrooms

- a kelixip module,
- chatroom objects, like the MCU module's conferences,
- functions to post messages.

## Media

Configure a media directory for photo and video, plus a thumbnail. Send the URL
inside a MESSAGE? Take inspiration from RCS?

Media expiry; download by the client?

Open, and not only as a format question: a download URL that is enough to know is
a URL that leaks. Whether the link is authenticated, and against which identity,
is part of this choice. The session-mode alternative is MSRP (RFC 4975), which
carries the content in-band instead.

And what about RCS, while we are at it?

## Bot

A minimal module building grammars is needed. How are messages to be processed?

## References

The instant-messaging specifications. The presence, consent and subscription ones
are in [DESIGN-PRESENCE.md](DESIGN-PRESENCE.md#references).

| RFC | Title | Why it is here |
|---|---|---|
| [3428](https://www.rfc-editor.org/rfc/rfc3428) | SIP Extension for Instant Messaging | The MESSAGE method: objective 1 |
| [5438](https://www.rfc-editor.org/rfc/rfc5438) | Instant Message Disposition Notification (IMDN) | Delivery and read receipts — what a modern client expects, and what the Silo must honour when it delivers a stored message late |
| [4975](https://www.rfc-editor.org/rfc/rfc4975) | MSRP | The session-mode alternative for large content. The "media by URL" idea above is the other branch; both are open |
| [5365](https://www.rfc-editor.org/rfc/rfc5365) | Multiple-Recipient MESSAGE Requests | One route to chatroom fan-out |
| [4103](https://www.rfc-editor.org/rfc/rfc4103) | RTP Payload for Text Conversation (T.140) | Already carried by the MCU; the real-time-text neighbour of instant messaging |
| [3261](https://www.rfc-editor.org/rfc/rfc3261) | SIP | §20.19 `Expires` on a non-INVITE request — the retention a sender may ask for |

# Test terminals

Shared with presence — see
[DESIGN-PRESENCE.md](DESIGN-PRESENCE.md#test-terminals).
