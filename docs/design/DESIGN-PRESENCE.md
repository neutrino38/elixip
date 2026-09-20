# DESIGN-PRESENCE.md — presence

Registration state, published state, consent, and the composite state a
subscriber presents to the others. Instant messaging is its neighbour and lives
in [DESIGN-CHAT.md](DESIGN-CHAT.md), which also holds the Silo.

The order this gets built in — the scope of *basic* presence, the phases, and what
each one proves — is [presence-basic-plan.md](presence-basic-plan.md).

## Objectives

Implement RFC 3856 and use it creatively, as follows.

**1 — A composite state**, carrying at once:

- the user's registration state
- the presence state the user publishes
- call occupancy, through RFC 7463 — Shared Line Appearance
- the location, either published by the user or derived from IP geolocation
- the devices registered for push notification

**2 — The buddy list and the consent flow.**

An `.exs` script handling:

- the subscription that enters a buddy list (`SUBSCRIBE monami@domain.com`)
- `NOTIFY sip:monami@domain.com`, and its acceptance or refusal
- `NOTIFY sip:jechercheunami@domain.com` with the outcome

Open question: how does a user obtain their buddy list? Lead: RFC 4662 (RLS — one
subscription for the whole list), with the list itself held in XCAP (RFC 4826).
See *References*.

**3 — A Service Building Block for presence-based Automatic Call Distribution.**

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
```

MESSAGE is dispatched by its own `[[domain.chat]]` blocks — see
[DESIGN-CHAT.md](DESIGN-CHAT.md#dispatch-chat-is-a-function-of-its-own).

# Design notes

## Implementation in elixip2

- SIP stack: handling of presence
- `SIP.Presence.*` — the message-body parsers
- presence UAC and presence UAS scenarios

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

Store-and-forward for MESSAGE lives in
[DESIGN-CHAT.md](DESIGN-CHAT.md#the-silo-module). It is a neighbour of presence,
not a part of it: its trigger is a registration, and what it stores is chat.

## Push and the deferred INVITE

A call to a sleeping mobile is the other half of the push story: the INVITE
arrives, the callee has no live binding, a push wakes the handset, it REGISTERs,
and the call must then reach it. kamailio does this with **tsilo** — the
transaction is stored by AOR and re-targeted from the REGISTER script. **Here
nothing is stored**, because the pieces already exist:

| kamailio | kelixip |
|---|---|
| `t_newtran()` + 100 Trying | the B2BUA holds the inbound IST; the scenario has answered 100 |
| `ts_store()` | the target provider answers `{:wait, ms}`: the `%Hunt{}` is parked, `waiting: true`, no leg created |
| sending the push | by the provider — the one that just found no contact |
| indexing by AOR | `Kelix.Mod.Registrar.subscribe_register_event(uri, pid)`, which takes a **currently unregistered** URI |
| `save("location")` then `ts_append()` | `save/2`, then the registrar emits `{:registrar, :upsert, "aor@domain"}` to its subscribers |
| `t_append_branches()` | the woken scenario calls `b2bua_try_next()`, the provider is asked again and now answers `{:ok, uri}` — the leg goes out |
| expiry | the state's `after ms` → `b2bua_try_next()` → `:exhausted` → 480 |

`{:wait, ms}` arms **no timer of its own**: it records `{:serial_waiting, ms,
now()}` and returns. The scenario decides when to retry, in a state carrying both
`on_events` and `after`, so an external event resumes the hunt immediately and
`ms` is only a ceiling.

**Why kamailio must store and this does not.** tsilo is the memory its language
lacks: the script ends when routing ends, nothing remembers the transaction, so
it has to be deposited somewhere and found again by AOR. Here the scenario
instance **is** that memory — a live process stopped in a state, with the inbound
transaction held by the B2BUA underneath it. What still has to be indexed by AOR
is not the transaction but "someone is waiting for this wake-up": a table of
pids, already monitored, and with no reason to persist — the caller is on the
line, and if the node dies the call dies with it.

Two reservations:

- **the order of the wake-up.** The registrar emits on `save`, so possibly
  **before** the 200 OK to the REGISTER — the opposite of what the Silo requires.
  A handset receiving an INVITE before its own registration is confirmed may
  refuse it. Either the emission follows the response, or the call scenario
  allows itself a grace delay before dialling;
- **it is single-node.** The INVITE waits on A, the REGISTER may land on B, and
  the subscription is local. Not a regression — tsilo is local, unreplicated
  memory too, and kamailio answers it with routing affinity. It belongs to the
  "live processes" tier of the scale-out track
  ([DESIGN-CHAT.md](DESIGN-CHAT.md#horizontal-scale)).

## The kelixip Presence module

A generic pub/sub module for presence. Like the registrar, one per domain with
strong isolation.

Open question: the first draft had it **depend on the Silo**
([DESIGN-CHAT.md](DESIGN-CHAT.md#the-silo-module)). Store-and-forward and a
state store are not the same object, and what presence needs is the second —
published states surviving a restart. Undecided.

It handles SUBSCRIBE and PUBLISH, and sends the NOTIFYs.

## The data model is kamailio's

```sql
-- kamailio 6.1, utils/kamctl/postgres/presence-create.sql (byte-identical on master).
-- The two tables presence reads and writes; the rest of that file is not ours.
presentity      (username, domain, event, etag, expires, received_time, body,
                 sender, priority, ruid)
active_watchers (presentity_uri, watcher_username, watcher_domain, to_user, to_domain,
                 event, event_id, to_tag, from_tag, callid, local_cseq, remote_cseq,
                 contact, record_route, expires, status, reason, version, socket_info,
                 local_contact, from_user, from_domain, updated, updated_winfo,
                 flags, user_agent)
```

The goal is one thing: **kelixip is able to use kamailio's database format**. It
does not own the schema — kamailio does — and it does not claim to use the base
the way kamailio uses it. It reads and writes `presentity` (the published document
per resource: PUBLISH's body, its entity-tag and its lifetime) and
`active_watchers` (one live subscription: what `%SIP.Subscription{}` carries, plus
the dialog carrying it), and it touches nothing else in that database.

`watchers`, `xcap` and `pua` are **not part of this**. A kamailio base has them
and they stay exactly as they are: kelixip neither reads, writes, creates nor
migrates them. `watchers` is the consent decision, which arrives with
`presence.winfo` and not before — until then the authorisation policy is a config
key, and inventing rows in a table we do not use would be writing state nobody
reads. `xcap` belongs to the buddy list (RLS), and `pua` is kamailio's own client
side, whose counterpart here is the watcher scenario, not a row.

### Three columns that decide the shape of our own records

- **`expires` is an absolute epoch second**, not a remaining lifetime: kamailio
  writes `expires + time(NULL)` and reads back `expires - time(NULL)`
  (`presence/subscribe.c`, `presence/presentity.c`), and `received_time` is the
  same. Our records hold those absolute values, so nothing converts between the
  struct and the row — a conversion in the middle is where the sign error lives.
- **`status` is kamailio's enum**, not ours: 1 active, 2 pending (the column's
  default), 3 terminated, 4 waiting, 5 polite-block (`presence/subscribe.h`).
  `:pending | :active | :terminated` maps onto it, and the integer is what is
  stored.
- **`event` is the package name as a string** (`presence`, `presence.winfo`,
  `dialog`) with `event_id` beside it — exactly the `{package, id}` pair the
  subscription key already carries, and `UNIQUE (callid, to_tag, from_tag)` is
  that key's other half.

### What compatibility means here — and what it does not

**The format, not the usage.** What is promised is that the rows are kamailio's
rows: those two tables, those columns, those value conventions — `expires`
absolute, `status` as the enum above, `event` as the package name. An existing
kamailio presence base is therefore usable as it stands, and what kelixip writes
into it stays readable by the tooling an operator already has. On opening a base,
`version` is checked for the table versions we know (`presentity` 5,
`active_watchers` 12) and an unknown one is refused; no DDL of ours ever runs
against it.

**Using the base the way kamailio does is not promised**, and is not a goal. Its
query patterns, its DB_ONLY and DB_FALLBACK modes, its cluster bookkeeping
(`updated`, `updated_winfo`, `flags`) and the timing of its refreshes and sweeps
are its own; kelixip fills those columns with the defaults the schema states and
treats them as opaque. The direct consequence, stated rather than left to be
discovered: **the two servers working on one base at the same time is not a
supported configuration**, and nothing here is designed to make it one.

Reading a row correctly and acting on a row another server is also acting on are
two different claims. Only the first is made.

### What this does not import

kamailio's **module split** is not ours. `presence`, `presence_xml`, `pua`, `rls`
and `xcap_server` are five modules because the C side needs them to be; here the
document format is an `SIP.EventPackage` implementation and the store is one
module. The tables are shared, the decomposition is not.

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

### The data model

| Source | What it settles |
|---|---|
| [kamailio `presence-create.sql`](https://github.com/kamailio/kamailio/blob/6.1/utils/kamctl/postgres/presence-create.sql) | `presentity` and `active_watchers` — the two tables the presence store reads and writes, with their columns and constraints (6.1, identical on master) |
| `presence/subscribe.h`, `presence/subscribe.c`, `presence/presentity.c` | what the columns actually carry: the `status` enum, and `expires` as an absolute epoch second |

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

In [DESIGN-CHAT.md](DESIGN-CHAT.md#references).
