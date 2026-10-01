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

How a user obtains their buddy list is answered below, in *The buddy list*: the
client brings it, in the SUBSCRIBE itself (RFC 5367), and no XCAP server is
needed for that.

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
state per resource, and the fan-out that turns one PUBLISH into N NOTIFYs. It
calls into this layer to send each of them; it never parses a SUBSCRIBE.

**Admission is not its.** Whether a watcher may watch a presentity is decided by
the subscribe script, where every other per-deployment decision lives — a key in
the module would be a second place deciding it. The consent flow that answers the
question properly (`presence.winfo` feeding RFC 5025 authorization rules) plugs
into this same collection when it arrives.

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

## The buddy list

One SUBSCRIBE covering N buddies, answered by one NOTIFY carrying the state of
each (RFC 4662). A client that cannot do this opens one subscription per buddy —
one dialog, one timer and one refresh each — and a roster of thirty costs thirty
of everything.

### The list is in the request

RFC 4662 assumes the list is held on the server and named by a URI. RFC 5367 has
the watcher put it **in its own SUBSCRIBE** instead, under
`Content-Disposition: recipient-list`, and that is the one real clients send —
captured from Linphone Desktop 6.2.2 on 2026-09-22:

```
SUBSCRIBE sip:rls@sip.linphone.org SIP/2.0
From: "Bob" <sip:bob@weshwesh.eu>;tag=sxplenBxl
Supported: eventlist
Require: recipient-list-subscribe
Content-Type: application/resource-lists+xml
Content-Encoding: deflate
Content-Disposition: recipient-list
Accept: multipart/related
Accept: application/pidf+xml
Accept: application/rlmi+xml
```

So no XCAP server and no list store: the node reads `application/resource-lists+xml`
(`SIP.Presence.ResourceLists`) and subscribes to what it names. XCAP (RFC 4825 /
4826) re-enters the day a deployment wants the list to survive the client that
holds it, and it changes nothing below.

### Three consequences, and they are what the design is

**The Request-URI names a list, not a presentity.** `sip:rls@sip.linphone.org` is
hard-coded in the client, whatever the account's own domain is. Two things follow.
The node declares that host as a **domain of its own** in `domains.toml`, serving
nothing but presence, because routing is by R-URI host and that is the host
arriving. And the watcher is authenticated on the realm of its **own `From`**
(`realm: :from_domain`) — challenging on the routed domain asks for credentials
that exist nowhere.

A client whose list URI is a setting can point it at its own domain instead
(`sip:rls@example.com`). The domain's `[[domain.presence]]` block then routes it
with a SUBSCRIBE rule — `pattern = "rls"`, the list script — ahead of the
catch-all serving the domain's users. SUBSCRIBE rules are the dial-plan's reading
on the R-URI user part, first match wins: a list is not one of the domain's users,
and neither is a range of conference rooms, so each gets a rule of its own. Both
forms serve the same script.

**A resource belongs to the domain of its own URI.** The three entries of one
buddy list routinely sit on three domains, none of which has to be the routed one.
`Kelix.Mod.Presence` therefore keys every resource on the domain its URI names,
and the domain that routed the request is only a fallback for an entry that
carries none. Keying on the routed domain files every buddy under a domain nobody
publishes on — the watcher then gets state for nobody, for ever, with no error
anywhere.

**An entry we do not serve is reported, not omitted.** A list names whatever the
client put in it. An entry on a domain this node does not serve gets
`<instance state="terminated" reason="noresource"/>` in the manifest: the watcher
stops waiting for it. It is not registered as a watcher either — the list is the
client's, so the number of domains in it would be the client's too, and each one
costs a table and a monitor. The `[outbound]` domain of a later phase is what will
take those entries over by subscribing to their own servers.

**A resource nobody publishes is answered by its registrations.** An unpublished
state and an unknown resource used to be the same `nil`, so a subscriber of this
very node who publishes nothing was reported `noresource`, as if it did not
exist. The state of a resource is now, in order: the live publication; else
**open** while a device of the presentity is registered; else, on a domain with a
registrar and for a user `auth_db` knows, **closed**; else no state, `noresource`.
The subscriber check runs in the watcher's process, never in the collection's: it
is a query on the subscriber base.

**The registrar script reports, the collection does not follow.** Registrations
reach the collection from `registrar-presence.exs`, which calls
`registration_changed/1` after each save and `registration_ended/1` when its
dialog ends — the connection dropped, or the registration was not refreshed. The
collection does not subscribe to the registrar's events: a domain opts in by the
registrar script it runs, and the report is a state of that script, visible to
`kelictl monitor` like every other step of the flow.

Neither report carries a status. The collection asks the registrar, inside its
own process, whether any device of the AOR still holds a binding: two devices
reporting at once are then answered in turn, each against the store as the other
left it, and one handset leaving never closes a subscriber another keeps
registered. The ending dialog's own bindings are left out of that question — the
store may not have dropped them yet — and so are those over a connected transport
whose dialog is already dead. A change is pushed only when the status moves and
nothing live is published; a refreshing REGISTER pushes nothing.

**A registration always has an instance to report its end.** The script's wait
for a refresh ends when its dialog's bindings lapse in the registrar
(`Kelix.Mod.Registrar.remaining_ms/1`), not when the dialog's own timer fires:
that timer is re-armed by every REGISTER received, refused ones included, on the
lifetime asked rather than the one granted. And a refused REGISTER changes no
binding, so a refused refresh returns to that wait instead of ending the session
— `registrar.exs` ends it after five idle seconds, which left a binding running
with nobody to report its lapse.

### What goes back

A `multipart/related` (RFC 2387) whose root part is an **RLMI manifest**
(`SIP.Presence.Rlmi`) naming every resource, each pointing through a `cid` at the
part carrying its document. The manifest is indexed by `start=`, not by position,
so the parts may be read in any order.

`version` counts the NOTIFYs of one subscription and `fullState` says whether what
follows is all of it: the first NOTIFY is full, the ones after it carry only what
changed. Both are the **subscription's** — `%SIP.Subscription{}.version`, which
the framework increments — because two watchers of one list have their own
counters.

The state changes are **batched** in the script (500 ms): the fan-out pushes one
buddy at a time, and a roster coming online would otherwise produce one NOTIFY per
buddy, each carrying the whole envelope.

### `Content-Encoding` is not an optimisation here

The captured SUBSCRIBE arrives deflated and asks for the answer deflated. A list
NOTIFY carrying one PIDF per buddy passes the UDP MTU, and IPv6 does not fragment
in transit: without the compression the NOTIFY does not arrive at all. The stack
reads `deflate` on the way in (`SIP.Msg.BodyCoding`, both the zlib and the raw
form — the field means both) and applies it on the way out past 1200 octets, low
enough to matter and high enough to leave a small NOTIFY readable in a capture.

## The kelixip Presence module

A generic pub/sub module for presence. Like the registrar, one per domain with
strong isolation.

Open question: the first draft had it **depend on the Silo**
([DESIGN-CHAT.md](DESIGN-CHAT.md#the-silo-module)). Store-and-forward and a
state store are not the same object, and what presence needs is the second —
published states surviving a restart. Undecided.

It handles SUBSCRIBE and PUBLISH, and sends the NOTIFYs.

### Reported states

A presentity does not always publish. A registered handset is open because the
registrar says so, and a conference room is open because the MCU says so; neither
sends a PUBLISH. The module therefore takes states from other modules through one
generic entry, `report(domain, user, source, doc)`, rather than one hard-coded
path per source.

- A reported state is held per `{resource, source}`; `nil` withdraws it. Between
  two sources, the most recent report wins, as the most recent publication does.
- The reporting process is monitored. When it dies, every state it reported is
  withdrawn, and a module that restarts reports again.
- Watchers are pushed when the **resolved** state of the resource changes, and
  only then. A source repeating itself, or reporting under a live publication,
  costs nobody a NOTIFY.

The state of a resource resolves, in order, to: its live publication; a reported
state; open while registered; closed on a registrar domain for a subscriber
`auth_db` knows; no state.

**No state is `noresource`.** A watcher told "closed" about a resource that does
not exist waits for something that will never come. The reference subscribe
script ends the subscription with `terminated;reason=noresource` when the
resource has no state at subscribe time, and when the state goes while it is
watched — a room destroyed under its watcher. A list subscription reports the
entry the same way. The same holds for a user on a domain with no registrar.

**Existence belongs to the module.** "Does this presentity exist" used to be one
question to the subscriber base, and a DID is not a subscriber. `exists?/2` owns
it now: a subscriber `auth_db` knows, or a resource some source reports a state
for. A presentity that does not exist is refused `404` before any subscription is
created.

**The link is a module of its own.** Neither `mcu` nor `presence` depends on the
other — both are optional packages, and a node running one without the other must
not change. `mcu_presence` follows the MCU's live push and reports each room
(`sip:<did>@<domain>`): open, open with the RPID activity `busy` when full, closed
while its media server is lost. Its plan is
[mcu-presence-plan.md](mcu-presence-plan.md).

The registrar keeps its own path (`registration_changed/1`); moving it onto
`report/4` is possible, and not done.

### One publication per publisher

PUBLISH names no device: no Contact, no `+sip.instance`, and a From every device
of the user shares. The publisher is therefore the **flow** the PUBLISH arrives
on — the connection over TCP, TLS or WSS, the source address and port over UDP
(`SIP.Publication.same_publisher?/2`). Three rules follow:

- **One publication per publisher and resource.** An initial PUBLISH from a
  publisher that already holds one replaces it. A client that lost its
  entity-tag across a reconnection starts over; it does not leave its old state
  beside the new one, to resurface when the new one is removed.
- **A publication does not outlive its connection.** Over a connection-oriented
  transport the connection is monitored; when it drops, what was published over
  it is removed and the watchers are told. A WebRTC client closed without an
  unPUBLISH leaves nothing behind — the registrar applies the same rule to
  bindings.
- **An un-REGISTER is the device's unPUBLISH**, and so is the end of its
  registration. `registration_changed/1` and `registration_ended/1` remove what
  the device published, on every package of the AOR — the latter unless the
  device still holds a binding over the same flow, through another dialog.

Between publishers, what is notified is the publication whose state **changed**
last. A refresh carries no state and moves nothing: a device that only refreshes
does not take over from one that changed its state since. A proxy that relays
several devices of one user over one connection makes them one publisher; the
composite state is where that is answered.

### Call occupancy

Whether a user is on the phone is one fact read through three doors: a BLF key
(`Event: dialog`, RFC 4235), the composite presence (`on-the-phone`), and the
ACD's feed. `dialog_state` produces it; the build order is
[dialog-state-plan.md](dialog-state-plan.md).

**Invariant: a dialog is reported under a user only when a module proved its far
end is that user.** A dialog does not know who is at the other end. Its `From` is
a claim, and on the outbound leg of a B2BUA its Request-URI is a Contact. Two
modules prove it, and they stamp the dialog (`SIP.Dialog.set_remote_aor/2`):

| The leg | Who proves it | With what |
|---|---|---|
| inbound — a user is calling | `auth_db`, `SBB.authenticate` | the digest |
| outbound — a user is called | `registrar`, `targets/2` | the leg's contacts are that user's bindings |

A dialog nobody stamped reports nothing, so a trunk carrying our domain in its
`From` lights no key, and a trunk-to-trunk node pays one field per dialog. Reading
"a user of the domain" off a host part is the mistake this rule exists to prevent.

A stamped dialog pushes its call state through `SIP.Dialog.Events`, read as RFC
4235 reads it. The call is `terminated` when a BYE leaves or arrives, not when
the BYE is answered (RFC 3261 §15.1.1). A challenge (401/407) on the creating
INVITE is no refusal, and a 487 to our CANCEL is `cancelled`.

`dialog_state` aggregates every dialog of a user into one document per package,
since presence keeps one report per source: "latest wins" would drop a waiting
call. On the `dialog` package, a user `auth_db` knows and who is on no call
resolves to an empty document, not to no state — `noresource` would end the
subscription of every idle phone at subscribe time.

Neither `presence` nor the B2BUA depends on `dialog_state`. It holds the link, as
`mcu_presence` does, and its package is named so the `Presence*` glob of the
presence package does not take it.

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
`presence.winfo` and not before — until then admission is decided by the subscribe
script, and inventing rows in a table we do not use would be writing state nobody
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
| [4662](https://www.rfc-editor.org/rfc/rfc4662) | Resource List Subscriptions (RLS) | **Implemented** — see *The buddy list*. One SUBSCRIBE to a list URI, one NOTIFY carrying the state of every buddy as `multipart/related`. Without it a client opens one subscription per buddy |
| [5367](https://www.rfc-editor.org/rfc/rfc5367) | Subscriptions to Request-Contained Resource Lists | **Implemented.** The list travels in the SUBSCRIBE, which is what real clients send, and what makes a list server possible with no list store |
| [2387](https://www.rfc-editor.org/rfc/rfc2387) | The MIME Multipart/Related Content-type | The envelope of a list NOTIFY: `type=` names the manifest, `start=` points at it, `Content-ID` addresses each part |
| [4826](https://www.rfc-editor.org/rfc/rfc4826) | XCAP Resource Lists | Where a list lives when it is the SERVER that holds it. Deferred: the client brings its own |
| [4825](https://www.rfc-editor.org/rfc/rfc4825) | XCAP | How a client reads and edits that list — HTTP, not SIP. A dependency outside the SIP stack |

### Call state, for the composite state

| RFC | Title | Why it is here |
|---|---|---|
| [4235](https://www.rfc-editor.org/rfc/rfc4235) | An INVITE-Initiated Dialog Event Package | The real prerequisite of objective 1's occupancy: RFC 7463 is built on it, so this package comes first |
| [7463](https://www.rfc-editor.org/rfc/rfc7463) | Shared Appearances of a SIP AOR | Shared line appearance — appearance numbers and their seize/release arbitration, on top of 4235 |

### Instant messaging

In [DESIGN-CHAT.md](DESIGN-CHAT.md#references).
