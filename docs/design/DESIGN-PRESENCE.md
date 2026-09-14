# Presence and instant messaging

## Objectives

Implement RFC 3856 and use it creatively, as follows.

**1 — A composite state**, carrying at once:

- the user's registration state
- the presence state the user publishes
- call occupancy, through RFC 7463 — Shared Line Appearance
- the location, either published by the user or derived from IP geolocation
- the devices registered for push notification

**2 — Peer-to-peer instant messaging (MESSAGE).**

An `.exs` script handling:

- the subscription that enters a buddy list (`SUBSCRIBE monami@domain.com`)
- `NOTIFY sip:monami@domain.com`, and its acceptance or refusal
- `NOTIFY sip:jechercheunami@domain.com` with the outcome

Open question: how does a user obtain their buddy list? Lead: RFC 4662 (RLS — one
subscription for the whole list), with the list itself held in XCAP (RFC 4826).
See *References*.

Sending: can a user record an audio / video / text message, or a photo, and push
it as an attachment?

**3 — Instant messaging between a UA and a scenario acting as a chatbot**, with
long-lived sessions.

The first idea is `.exs` scenarios able to describe chatbot flows and to resume a
conversation when needed.

**4 — A Service Building Block for presence-based Automatic Call Distribution.**

The idea is asterisk's `app_queue` with a purely SIP interface. Queues are
persistent objects, like the MCU module's conferences: they are created, edited
and destroyed through `kelictl` commands, the REST API and a dedicated kelescope
view.

Subscribing to a queue would be done like this:

```
SUBSCRIBE sip:queuename@acddomain
```

The SUBSCRIBE would be handled by a scenario, e.g. `acd-agent-subscribe.exs`,
which after its own checks calls `ACD.add_agent(queue, agent_sip_uri)`:

```elixir
STATE add_to_queue do
    req = last_req()
    ACD.add_agent(req.ruri.userpart, req.pai)
    ...
end
```

A user's call to an agent is queued through
`ACD.queue_call(queue_name, req, options)`.

It would look like this — to be refined, and revisited if need be:

```elixir
STATE queue_call do
    req = last_uas_req()
    ACD.queue_call("myqueue", req, [])

    on_events do
        { :queued, queue_entry } -> goto session_progress
        { :unknown_queue, queue_entry } -> ...
        { :empty_queue, queue_entry } -> ...
    end
end

STATE session_progress do
    reply_invite_with_sdp(183, [media: :tc, webrtc: :if_offered])
    on_events do
        {:ACK, _req, _trans, _dlg} -> goto play_background
        {:CANCEL, _req, _trans, _dlg} ->
            ACD.cancel_queue_call("myqueue")
    end
end

STATE session_progress do

    media_play("background.mp4")
    on_events do
        {:ms_event, _res, :player_ended} -> stay()
```

The SBB places the call in the queue (held by a process of its own?). The next
available agent — one who subscribed to the queue, is not handling a call, is
registered and has declared themselves available — is selected according to the
queue's policy, and the B2BUA module is used to connect them to the caller. If
the agent answers, done. Otherwise the next agent is tried, possibly changing the
agent's presence state along the way (the `autopause` option).

The B2BUA's hunt function is obviously what is used here.

`ACD.SBB.queue()` will have to end up as easy to use as asterisk's `app_queue()`.

## Configuration in domains.toml

```toml
[[domain.presence]]
event-package=<event package>
publish=publish-<event package>.exs
subscribe=subscribe-<event package>.exs
notify=notify-<event package>.exs

[[domain.chat]]
pattern = "mybot"
script = "mybot.exs"

[[domain.chat]]
pattern="room-.*"
script="chatroom.exs"

[[domain.chat]]
default = true                    # catch-all, must be last
script="p2p-chat.exs"
```

# Design notes

## Implementation in elixip2

- SIP stack: handling of presence
- `SIP.Presence.*` — the message-body parsers
- presence UAC and presence UAS scenarios
- chat scenario

## The subscription layer (framework)

RFC 6665 describes an entity the stack does not have. A SUBSCRIBE currently
creates a generic dialog with a hardcoded 600 s lifetime, and nothing carries the
event package, the negotiated expiry, the `Subscription-State`, the refresh or
the final NOTIFY. That entity is what this layer adds — below presence, below
chat, below the ACD, and shared by all three.

**The framework holds one subscription; a kelixip module holds the collection.**
One subscription is a dialog's point of view: its event package and `id`, its
negotiated expiry, its state, its refresh. Who is subscribed to which resource —
and therefore who must be notified when a state changes — is the `presence`
module's business. The split is what lets `elixipp` play a watcher and a notifier
end to end, with no kelixip node, which is the condition for testing any of this.

### Decisions

**1. No process per subscription.** The state lives in the session layer above
the dialog — `SIPSessionSubscribe.ex`, symmetric with `SIPSessionInvite.ex` — and
the timers live in the dialog, which already carries `expirationtimer` and
`keepalivetimer`. A dedicated process would make three for one SUBSCRIBE.

Two consequences, neither of them neutral:

- **a subscription pins a script version.** It lives as long as the scenario
  instance that accepted it: 3600 s for presence against minutes for a call. The
  hot reload refcounts versions ([DESIGN-KELIXIP.md](DESIGN-KELIXIP.md#5-scripts)),
  so a replaced version stays resident for hours, and a node with script churn
  keeps several. "No call is interrupted by a reload" now reads "and no
  subscription either, for an hour".
- **nothing survives a restart.** Neither dialog nor subscription. Every refresh
  then lands on an unknown subscription and is answered **481** — never accepted
  as if it were new, which would leave the watcher believing its subscription is
  established while no NOTIFY ever comes. A correct watcher re-subscribes. The
  module's collection may persist its published states; it cannot resurrect the
  dialogs, so persistence buys nothing for the subscriptions themselves.

**2. An event package is a behaviour.** `SIP.EventPackage`, so the subscription
layer knows nothing of PIDF:

| Callback | Answers |
|---|---|
| `name/0` | `"presence"`, `"dialog"`, `"message-summary"` — matched against `Event`, else **489 Bad Event**, and composed into `Allow-Events` |
| `default_expires/0`, `max_expires/0`, `min_expires/0` | the expiry bounds; below the minimum the notifier answers **423**. The default belongs to the package (3600 s for presence), never to the framework |
| `content_types/0` | plural: the SUBSCRIBE carries `Accept`, and the notifier picks from that list or answers **406** |
| `parse/2`, `serialize/2` | the body, in both directions |

The negotiation is the subscription layer's — it reads `Event`, `Accept` and
`Expires` and asks the package what it can produce. The package never reads a SIP
message.

Three implementations in v1, which is what justifies the behaviour rather than a
hardcoded package: `presence` (RFC 3856), `presence.winfo` (RFC 3857) — consent
is an event package of its own, and it is what answers "NOTIFY my friend, accept
or not" in the objectives above — and `dialog` (RFC 4235) as soon as the
composite state wants call occupancy.

#### Who registers a package

Three questions hide behind "registering": whether the **code is loaded**,
whether the **node knows** the package (the `name → module` table that answers
489 and composes `Allow-Events`), and whether a **domain enables** it. The third
is already answered by `domains.toml` — a config key selecting packages
node-wide, the way `:mediaserver` selects an adapter, would be a second place
deciding the same thing.

**The registry lives in elixip2, and kelixip is one of its clients.** The
provided packages are compiled into the framework, which exposes
`SIP.EventPackage.register/1` and `unregister/1`; a kelixip module may declare
itself as an event package by calling it on start. elixipp therefore runs the
base packages with no kelixip node, and no dependency is inverted.

Four rules a registry mutable at run time needs:

1. **`:persistent_term` holds the table.** It is read on the path of every
   SUBSCRIBE, PUBLISH and NOTIFY, and written once at boot plus once per module
   reload — that profile exactly. Not an ETS table with a process of its own to
   supervise.
2. **Start order stays out of the contract.** A domain naming a package whose
   module has not started yet cannot be validated. kelixip already settled the
   same case for domain functions: a **warning at boot**, not a refusal
   ([DESIGN-KELIXIP.md](DESIGN-KELIXIP.md#7-the-module-system)). Same here, and a
   **489** at run time if the package is still absent. Anything stricter carves
   "modules start before domains are validated" into stone.
3. **`register/1` is idempotent and paired with `unregister/1`.** A kelixip
   module reloads hot: a reload replaces the entry, a module removed drops it. An
   entry left pointing at an unloaded module kills the next SUBSCRIBE — in
   embedded mode nothing reloads it implicitly.
4. **Collisions are decided at registration, never at use.** A third party
   **overriding** a provided package (an operator with their own PIDF) is
   legitimate, allowed, and logged at warning naming both modules. Two third
   parties claiming one name: the second is **refused**. Otherwise module start
   order silently decides SIP behaviour — the reason an ambiguous control route
   is refused at registration too.

**Scope for v1:** the three packages stay in elixip2 and the `presence` module
does **not** register itself — it would be consuming an API meant for third
parties. `register/1` exists for a proprietary package and for tests, where a
dummy package exercises the subscription layer without PIDF.

Two consequences to hold on to:

- **`Allow-Events` is a property of the domain, not of the node.** Two domains on
  one node may offer different packages, and `Event: dialog` on a domain that
  does not enable it is answered **489** even though the code is loaded.
- **the Router reads `Event`.** With one `[[domain.presence]]` block per package,
  dispatch step 3 can no longer pick the script from the method alone. That
  reading belongs to `SIP.Msg.Ops` like every other, and the **489 is the
  Router's**, raised before any script runs — a script never has to check that
  the package concerns it.

**Full state only in v1.** Partial state — `application/pidf-diff+xml` (RFC 5262),
and the `dialog` package's own deltas — is an **optional** callback added later.
The subscription layer emits complete state until it exists.

**3. The subscription key carries the event type and `id` from the start.** RFC
6665 keys a subscription on Call-ID + both tags + event type + `id`, and several
subscriptions may share one dialog. Real clients do not (Linphone opens one
dialog per subscription), so **v1 refuses a second package on an existing
dialog** — but the key is complete from day one, because widening it later is a
breaking change to everything that stores one.

**4. The final NOTIFY belongs to the framework.** It arms the timer on the
negotiated expiry and emits `Subscription-State: terminated;reason=timeout` if
the scenario has not terminated the subscription itself. Left to the script it
would be forgotten in three scripts out of four, and the subscription would leak
on the watcher's side — the same failure mode `requested_expires/2` was written
to end.

**5. The watcher refreshes by itself.** Symmetric with `RegisterUAC`: the
framework re-SUBSCRIBEs before expiry, and an `app_drives_…` control hands the
refresh back to the scenario when it wants it.

**6. Two concrete defects this layer must close:**

- **the 600 s hardcoded dialog lifetime** for SUBSCRIBE, in
  `SIP.Dialog.start_new_dialog_for/3`, becomes the negotiated expiry. This is a
  **second** reading in `SIP.Msg.Ops`, not a reuse of `requested_expires/2`: a
  SUBSCRIBE has no Contact `expires` parameter, its default comes from the event
  package, and the notifier may shorten the value it grants or answer 423. Same
  rule, different rules ([CLAUDE.md](../../CLAUDE.md), *Message Layer*): one
  reading, in the message layer, and every caller delegates.
- **the NOTIFY/200 race.** RFC 6665 requires the notifier to send the 2xx before
  the first NOTIFY, and UDP reorders anyway. The watcher must therefore accept a
  NOTIFY whose To tag matches no known dialog yet, matching on Call-ID plus the
  local From tag and adopting the tag it carries.

**7. Termination contract.** Exactly one `{:subscription_terminated, ref, reason}`
to the application, with the RFC 6665 reasons — `deactivated`, `probation`,
`rejected`, `timeout`, `giveup`, `noresource`, `invariant`. "Exactly one" is the
contract, as it is for `{:dialog_terminated, …}`
([DESIGN-SIPSTACK.md](DESIGN-SIPSTACK.md#55-the-termination-contract)).
`deactivated` and `probation` mean *subscribe again*, and the framework does it
without waking the scenario; the other five are terminal and surface.

### What this leaves to the module

The `presence` module owns the collection: resource → subscribers, the published
state per resource, the authorisation policy fed by `presence.winfo`, and the
fan-out that turns one PUBLISH into N NOTIFYs. It calls into this layer to send
each of them; it never parses a SUBSCRIBE.

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
a silo, and the Silo must not grow that second face.

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

## The kelixip Presence module

A generic pub/sub module for presence. Like the registrar, one per domain with
strong isolation. Depends on the Silo module.

It handles SUBSCRIBE and PUBLISH, and sends the NOTIFYs.

## Chat

Peer-to-peer chat: a chat B2BUA.

Chatrooms:

- a kelixip module,
- chatroom objects, like the MCU module's conferences,
- functions to post messages.

Media support: configure a media directory for photo and video, plus a thumbnail.
Send the URL inside a MESSAGE? Take inspiration from RCS?

Media expiry; download by the client?

And what about RCS, while we are at it?

## Bot

A minimal module building grammars is needed. How are messages to be processed?

# Test terminals

- Linphone as the first reference
- Extend Trix to go further
- what about RCS?
# References

The specifications this document builds on, and what each one settles.

### The notification mechanism

| RFC | Title | Why it is here |
|---|---|---|
| [6665](https://www.rfc-editor.org/rfc/rfc6665) | SIP-Specific Event Notification | The subscription layer. **Obsoletes RFC 3265** — read 6665, not 3265: the dialog is created by the 2xx to the SUBSCRIBE and no longer by the NOTIFY, and `202 Accepted` is deprecated |
| [3261](https://www.rfc-editor.org/rfc/rfc3261) | SIP | §12 dialogs, §20 headers, the transaction machines |
| [3903](https://www.rfc-editor.org/rfc/rfc3903) | Event State Publication (PUBLISH) | The publish half: `SIP-If-Match`, the entity-tag lifecycle, refresh and remove |

### Presence itself

| RFC | Title | Why it is here |
|---|---|---|
| [3856](https://www.rfc-editor.org/rfc/rfc3856) | A Presence Event Package for SIP | The `presence` package: the objective of this document |
| [3863](https://www.rfc-editor.org/rfc/rfc3863) | PIDF | The document format `SIP.Presence.*` parses and serializes |
| [4479](https://www.rfc-editor.org/rfc/rfc4479) | A Data Model for Presence | Person / service / device — the three-level model the composite state needs to say "Alice is available, on this device, for this service" |
| [4480](https://www.rfc-editor.org/rfc/rfc4480) | RPID | The rich-presence extensions to PIDF: activity, mood, place-type. Where a published location lands |
| [5262](https://www.rfc-editor.org/rfc/rfc5262) | PIDF Extension for Partial Presence | `application/pidf-diff+xml`. **Deferred**: v1 emits full state |
| [5263](https://www.rfc-editor.org/rfc/rfc5263) | Partial Notification of Presence Information | The SIP side of the same deferral |

### Consent and the buddy list

| RFC | Title | Why it is here |
|---|---|---|
| [3857](https://www.rfc-editor.org/rfc/rfc3857) | Watcher Information Event Template-Package | `presence.winfo` — the second `SIP.EventPackage` implementation. This is what tells Alice that Bob wants to watch her, and what carries her answer |
| [3858](https://www.rfc-editor.org/rfc/rfc3858) | XML Format for Watcher Information | Its body |
| [5025](https://www.rfc-editor.org/rfc/rfc5025) | Presence Authorization Rules | The policy document behind a `pending` subscription: who may watch, and how much they see |
| [4662](https://www.rfc-editor.org/rfc/rfc4662) | Resource List Subscriptions (RLS) | **Answers the open question above.** One SUBSCRIBE to a list URI, one NOTIFY carrying the state of every buddy as `multipart/related`. Without it a client opens one subscription per buddy |
| [4826](https://www.rfc-editor.org/rfc/rfc4826) | XCAP Resource Lists | Where the list itself lives |
| [4825](https://www.rfc-editor.org/rfc/rfc4825) | XCAP | How a client reads and edits that list — HTTP, not SIP. A dependency outside the SIP stack |

### Call state, for the composite state

| RFC | Title | Why it is here |
|---|---|---|
| [4235](https://www.rfc-editor.org/rfc/rfc4235) | An INVITE-Initiated Dialog Event Package | The real prerequisite of objective 1's occupancy: RFC 7463 is built on it, so this package comes first |
| [7463](https://www.rfc-editor.org/rfc/rfc7463) | Shared Appearances of a SIP AOR | Shared line appearance — appearance numbers and their seize/release arbitration, on top of 4235 |

### Instant messaging

| RFC | Title | Why it is here |
|---|---|---|
| [3428](https://www.rfc-editor.org/rfc/rfc3428) | SIP Extension for Instant Messaging | The MESSAGE method: objective 2 |
| [5438](https://www.rfc-editor.org/rfc/rfc5438) | Instant Message Disposition Notification (IMDN) | Delivery and read receipts — what a modern client expects, and what the Silo module must honour when it delivers a stored message late |
| [4975](https://www.rfc-editor.org/rfc/rfc4975) | MSRP | The session-mode alternative for large content. The "media by URL" idea in the Chat section is the other branch; both are open |
| [5365](https://www.rfc-editor.org/rfc/rfc5365) | Multiple-Recipient MESSAGE Requests | One route to chatroom fan-out |
| [4103](https://www.rfc-editor.org/rfc/rfc4103) | RTP Payload for Text Conversation (T.140) | Already carried by the MCU; the real-time-text neighbour of instant messaging |
