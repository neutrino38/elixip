# presence-basic-plan.md — building basic presence

**Status: P1 through P7 are implemented.** The design is
[DESIGN-PRESENCE.md](DESIGN-PRESENCE.md); this document is the order it gets built
in, what each phase delivers, and what proves it.

No media anywhere: presence touches neither the media layer nor a media server, so
every phase below compiles, runs and is tested with no MCU in the picture.

## 1. Scope

Basic presence is **one watcher, one resource, full state**.

| In v1 | Why it is the floor |
|---|---|
| the subscription layer (RFC 6665) | nothing else in this list can exist without it, and chat and the ACD share it |
| the `presence` package (RFC 3856) over PIDF (RFC 3863) | the objective of the design document |
| PUBLISH (RFC 3903) | without it a state can only be *watched*, never *set* |
| per-domain dispatch by event package, 489 before any script | a script must never have to check that the package concerns it |
| the kelixip `presence` module: the collection and the fan-out | one PUBLISH becomes N NOTIFYs somewhere, and it is not the framework |
| elixipp watcher + notifier scenarios | the condition for testing any of this without a node |
| reference scripts, module doc, packaging | a function nobody can install is not shipped |
| the record shape of kamailio 6.1's `presentity` and `active_watchers` | using kamailio's format is decided by the record, not by the backend added later ([DESIGN-PRESENCE.md](DESIGN-PRESENCE.md#the-data-model-is-kamailios)) |

| Out of v1 | Where it re-enters |
|---|---|
| consent / `presence.winfo` (RFC 3857, 3858, 5025) | a second `SIP.EventPackage` over the same layer and the same collection; v1's admission is one `case` in the subscribe script |
| the buddy list: RLS (RFC 4662) + XCAP (RFC 4825/4826) | a client subscribes once per buddy in v1 |
| the `dialog` package (RFC 4235) and shared line appearance (RFC 7463) | objective 1's call occupancy, a third package |
| the ACD service building block | needs a queue object and the B2BUA hunt, neither of which is presence |
| partial state (RFC 5262/5263) | optional callbacks on the package behaviour |
| the composite state's location and push-device facets | they are *sources* feeding a document v1 can already carry |
| MESSAGE | [DESIGN-CHAT.md](DESIGN-CHAT.md#dispatch-chat-is-a-function-of-its-own) — its own function |
| the SQL backend behind the collection | §6 — v1 holds kamailio's rows in memory; reaching a real base is a backend, not a redesign |

## 2. The starting point

What exists today, as found on 2026-09-20.

| Piece | State |
|---|---|
| `SIP.Session.Presence` (`framework/SIPSessionPresence.ex`) | five callbacks of arity 2, no implementation, nothing calls them |
| `SIP.Session.ConfigRegistry` | a `presence:` struct field with no setter and no `dispatch/3` clause: an inbound SUBSCRIBE lands on the catch-all and is answered **501** |
| `SIP.Dialog.start_new_dialog_for/3` | PUBLISH, REGISTER and SUBSCRIBE all get the same hardcoded 600 s dialog |
| `SIP.DialogImpl.arm_expiration_timer/2` | clauses for INVITE and REGISTER, then a no-op default |
| dialog matching | an outbound dialog is registered `{fromtag, callid, nil}` until `add_totag/2` sees the first answer, so a NOTIFY overtaking the 200 matches nothing and is answered **481** |
| `SIP.Session.CallInDialog.do_send_notify/4` | exists for REFER sipfrag: `Event` written as a raw string key, content type defaulting to `message/sipfrag` |
| `SIPMsg` | no atom key for `Event`, `Accept`, `Subscription-State`, `SIP-If-Match`, `Allow-Events` — each keeps the spelling the peer sent, so every read of them is case-insensitive |
| `Kelix.Router` | SUBSCRIBE / PUBLISH / MESSAGE → `:presence`, one script per domain, `Event` unread |
| `Kelix.Domains` | `@presence_keys %{"script" => :string}` — a single block per domain |
| `Kelix.Options` | `@allow "OPTIONS, REGISTER"`, a fixed list deliberately not derived from the configuration |
| `Kelix.Mod.Registrar` | the precedent for a collection with subscribers: `subscribe_registrations/2`, `subscribe_register_event/2`, `{:registrar, :upsert, aor}` |

## 3. Phases

### P1 — the readings, in the message layer

```elixir
SIP.Msg.Ops.event_package(req)          #=> {"presence", nil} | {"presence", "abc"} | nil
SIP.Msg.Ops.accepted_content_types(req) #=> ["application/pidf+xml"] | []
SIP.Msg.Ops.subscription_expires(req, package_default)  #=> 3600
SIP.Msg.Ops.subscription_state(notify)  #=> {:active, %{"expires" => 3600}}
                                        #   {:terminated, %{"reason" => "timeout"}}
SIP.Msg.Ops.publish_etag(req)           #=> "dx200xyz" | nil    (SIP-If-Match)
SIP.Msg.Ops.allow_events(names)         #=> "presence, presence.winfo"
```

**Delivers** one reading of each presence header, in the layer that owns message
interpretation ([CLAUDE.md](../../CLAUDE.md), *Message Layer*). `Event`'s package
name is case-insensitive and its `id` is not; an absent `Accept` means "the
package's default type", not "nothing acceptable".

`subscription_expires/2` is a **second** expiry reading, not a reuse of
`requested_expires/2`: a SUBSCRIBE carries no Contact `expires` parameter, its
default comes from the event package, and the notifier may grant less.

**Files** `framework/SIPMsgOps.ex`, `framework/SIPMsg.ex` (atom keys and canonical
spellings for the five headers; the readings stay tolerant of a string key, which
is what a hand-built message carries), `test/msg_ops_presence_test.exs`.

**Tests** one table-driven test per header, each including junk: a valueless
`;expires`, `Event: PRESENCE`, an `Accept` spread over two header lines, a
`Subscription-State` with an unknown reason. A handset's malformed value must not
crash the dialog reading it — the rule `parse_expires/2` already encodes.

**Done when** every reading answers identically for a parsed and for a hand-built
message.

### P2 — `SIP.EventPackage` and its registry

```elixir
defmodule SIP.EventPackage do
  @callback name() :: binary()                  # "presence"
  @callback default_expires() :: pos_integer()  # 3600 for presence
  @callback min_expires() :: pos_integer()
  @callback max_expires() :: pos_integer()
  @callback content_types() :: [binary()]       # in preference order
  @callback parse(content_type :: binary(), body :: binary()) :: {:ok, term} | {:error, term}
  @callback serialize(content_type :: binary(), state :: term) :: {:ok, binary()} | {:error, term}

  def register(module, opts \\ [])   # origin: :builtin | :third_party
  def unregister(name)
  def lookup(name)                   # {:ok, module} | :error
  def names()
end
```

**Delivers** the `name → module` table in `:persistent_term`, and the four rules of
the design: `register/1` idempotent and paired with `unregister/1`; a third party
**overriding** a provided package allowed and logged at warning naming both
modules; a second third party claiming one name **refused**; an unknown package a
run-time **489**, never a boot refusal.

Writes are serialized by their callers — the boot path and
`Kelix.ModuleSupervisor`, each a single process. That is the whole reason this is
not an ETS table with a process of its own to supervise.

**Files** `framework/SIPEventPackage.ex`, `test/event_package_registry_test.exs`,
`test/support/event_packages/dummy.ex` — a package with a `text/plain` body, which
exercises the subscription layer with no PIDF in sight. That dummy is what the
behaviour is *for*, and it is what makes P3 testable before P4 exists.

**Done when** the dummy registers, is looked up, survives a re-register, refuses a
second third-party claim, and disappears on unregister.

### P3 — the subscription layer

The notifier, as a script reads:

```elixir
state authorize do
  case accept_subscription(expires: :negotiated) do
    {:ok, _sub} -> notify(state_doc()); goto(subscribed, "200 + NOTIFY")
    # the verb has already answered 423 / 406 / 489
    {:error, code} -> goto(wait_subscribe, "#{code}")
  end
end

state subscribed do
  on_events do
    {:presence, :state, _resource, doc} -> notify(doc); stay()
    {:SUBSCRIBE, _req, _t, _d} -> goto(authorize, "refresh")
    {:subscription_terminated, _ref, reason} -> scenario_success("#{reason}")
  end
end
```

**Delivers**

- `%SIP.Subscription{}` with the **complete** key from day one —
  `{callid, local_tag, remote_tag, package, id}`. Widening it later is a breaking
  change to everything that stores one. It is also `active_watchers`'s own key:
  `UNIQUE (callid, to_tag, from_tag)` plus `event` and `event_id`.
- the struct carries what an `active_watchers` row carries, under those names and
  with those value domains — `status` as kamailio's integer (1 active, 2 pending,
  3 terminated), `expires` absolute, `local_cseq` / `remote_cseq` / `version` /
  `record_route` / `socket_info` / `local_contact` alongside. No field is invented
  that the row has no column for, and none of the row's columns is left unfilled.
- the notifier half (`SIP.Session.Notifier`): the negotiation (`Event` against the
  registry, `Accept` against `content_types/0`, `Expires` against the package
  bounds) and its refusals **423**, **406**, **489**; `accept_subscription/1`,
  `reject_subscription/2`, `notify/2`, `terminate_subscription/1`.
- the final NOTIFY, armed by the framework on the granted expiry
  (`Subscription-State: terminated;reason=timeout`). Never left to the script.
- the watcher half (`SIP.Session.SubscribeUAC`): `send_SUBSCRIBE/3`,
  `send_auth_SUBSCRIBE/4`, the refresh before expiry with an `app_drives_refresh`
  control, the automatic 200 to an inbound NOTIFY, and `process_subscribe_reply/2`
  wired into `SIP.Session.dispatch_reply/3`.
- exactly one `{:subscription_terminated, ref, reason}` per subscription;
  `deactivated` and `probation` re-subscribed by the framework without waking the
  scenario, the other five surfaced.
- the dispatch: `SIP.Session.Presence`'s callbacks become arity 3 (the
  server-transaction pid, like `on_new_registration/3`), `ConfigRegistry` gains
  `set_presence_processing_module/1` and the SUBSCRIBE / PUBLISH clauses of
  `dispatch/3`. Until this, an inbound SUBSCRIBE is answered 501.
- the two framework defects of the design's decision 6: `arm_expiration_timer/2`
  gains a SUBSCRIBE clause reading `subscription_expires/2`, re-armed on the
  **granted** value (`SIP.Dialog.set_expiration/2`, called by
  `accept_subscription/1`); and `process_incoming_request/3` matches a NOTIFY no
  dialog claims on `{to_tag, callid, nil}` — Call-ID plus our local tag — adopting
  the tag it carries. PUBLISH's 600 s dialog drops to its transaction's lifetime.
- v1 refuses a second event package on an existing dialog (**489**).

**Files** `framework/SIPSessionSubscribe.ex` (Notifier, SubscribeUAC,
`SIP.Subscription`), `framework/SIPSessionPresence.ex`, `framework/SIPSession.ex`,
`framework/SIPDialog.ex`, `framework/SIPDialogImpl.ex`, `dsl/SIPScenario.ex`.

**Tests** `test/subscription_layer_test.exs`, over the mockup transport: accept,
refresh, expiry, termination; 423 below the minimum; 406 on an unusable `Accept`;
489 on an unknown package; **a NOTIFY injected before the 200** (the race, driven
by `SIP.Test.Peers.Manual`); one and only one `{:subscription_terminated, …}`; a
subscription whose dialog dies. One new canned peer,
`SIP.Test.Peers.NotifyingUAS`.

**Done when** a watcher scenario and a notifier scenario run against each other
over the mockup transport through P2's dummy package — no PIDF, no node.

**Delivered 2026-09-20**, with two things settled differently from the paragraphs
above, both for the same reason — a scenario instance is the only process a
subscription has, and it is blocked in a `receive` it cannot be made to leave and
re-enter:

- **the watcher's refresh is sent by the dialog**, not by the session layer. The
  dialog holds the timer (decision 1 already put it there), the `Event`, the `id`,
  the route set and the lifetime that was granted, which is the whole of a
  refresh; its response surfaces like any other, because what to do about a
  refresh answered 401 or 481 is a decision and decisions are the scenario's.
  `SIP.Dialog.app_drives_refresh/1` hands the schedule back, symmetric with
  `app_drives_keepalive/1`.
- **`deactivated` and `probation` are surfaced like the other five reasons**
  rather than re-subscribed under the scenario's feet. Re-subscribing opens a NEW
  dialog — the old one is terminated by definition — and the only process that can
  open one is the scenario. `send_SUBSCRIBE/3` recreates it on its own, standalone
  method that SUBSCRIBE is, so a watcher that wants the behaviour writes one
  clause. Closing this properly is a `SIP.Session.SubscribeUAC` re-subscribe verb
  driven from an injected clause, which the language cannot express today: an
  injected clause must LEAVE its state (`FSL.Machine`), and a refresh stays.

Two defects beyond the two decision 6 names were found and closed on the way, both
of them fatal to a subscription and neither visible before something used one:
`SIP.DialogImpl` initialised an outbound dialog's remote sequence number to 1
instead of leaving it empty (RFC 3261 §12.2.2), so the first NOTIFY — every
notifier in the field numbers it CSeq 1 — was answered *500 Out of order*; and the
2xx to a SUBSCRIBE carried no `Contact`, which RFC 6665 §4.2.1.2 makes mandatory
for a dialog-forming request, so the notifier was unreachable for the
un-SUBSCRIBE.

### P4 — the `presence` package

```elixir
SIP.Presence.Pidf.parse(body)
#=> {:ok, %SIP.Presence.Doc{entity: "sip:bob@ives.fr",
#          tuples: [%{id: "t1", status: :open, contact: "sip:bob@10.0.0.4",
#                     note: "In a meeting", activity: :meeting}]}}

SIP.Presence.Pidf.serialize(%SIP.Presence.Doc{})  #=> {:ok, "<?xml version=…"}
```

**Delivers** `SIP.Presence.Doc` (the document: RFC 3863, plus the RPID `<note>`
and `activity` a real client sends), `SIP.Presence.Pidf`, and
`SIP.EventPackage.Presence` over them — `default_expires 3600`,
`content_types ["application/pidf+xml"]`.

The body comes off the network and is untrusted. Entity expansion — not the XML —
is the risk, so the parsing is bounded (a body over 64 kB is refused unread) and a
`<!DOCTYPE` in the prolog is refused outright: a PIDF document has no use for a
DTD, and every entity attack needs one.

**Tests** round-trip on documents captured from Linphone, stored as
`test/PIDF-*.xml` beside the existing `SIP-*.txt`; a document carrying an unknown
namespace still usable; and the refusals — truncated XML, a doctype, an
oversized body.

**Done when** P3's suite passes again with `SIP.EventPackage.Presence` substituted
for the dummy package. That substitution is the proof the behaviour is a
behaviour.

**Delivered 2026-09-20.** Three things settled differently from the paragraphs
above:

- **the parser is `:erlsom`, not `:xmerl`.** It was already in the tree — `:xmlrpc`
  pulls it, and parses untrusted input with it for the same reason — it resolves
  nothing external whatever a `SYSTEM` identifier says, and it bounds entity
  nesting and expanded size on its own. `:xmerl`'s equivalent is an option set to
  get right per OTP release, which is one more thing to verify at every upgrade;
  it is declared explicitly in `apps/elixip2/mix.exs` rather than used
  transitively.
- **the RPID facet lands on the person, not in the tuple.** A presentity has one
  activity and N devices, which is where PIDF puts them and what a `<dm:person>`
  says; folding the activity into each tuple would have made the document unable
  to say which of two devices is the open one. `activity` is an **atom** for the
  values RFC 4480 names and the **raw string** for anything else — a document is
  unauthenticated input, and the atom table does not grow with what a stranger
  publishes.
- **the substitution is one suite run twice**, `test/support/subscription_suite.ex`
  parameterised by `SIP.Test.SubscriptionTraits` — six answers wide: the package,
  a document, how to read one back, an unusable content type, a lifetime it accepts
  and one it refuses. Two files asserting the same things in their own words would
  drift apart at the first fix applied to one of them, and the proof is only worth
  anything while the two runs are the same run.

`SIP.EventPackage.register_builtins/0` is what puts the package in the table, from
`SIP.FSL.Host.bootstrap/0` and from `Kelix.Application`. A run that never named a
package would otherwise answer 489 to a SUBSCRIBE for the one package this
release is about.

### P5 — PUBLISH

```elixir
state publish do
  req = last_uas_req()

  case Kelix.Mod.Presence.publish(sip_ctx, req) do
    {:ok, etag, expires} -> reply_publish(200, etag: etag, expires: expires)
                            scenario_success("published")
    {:error, 412} -> reply_publish(412); scenario_failure("stale etag")
    {:error, {code, reason}} -> reply_publish(code, reason); scenario_failure(reason)
  end
end
```

**Delivers** `SIP.Session.Publish`: the verbs and the RFC 3903 reading —
`SIP-If-Match`, `Expires`, an empty body as a refresh, `Expires: 0` as a removal —
with the **412** on a stale or unknown entity-tag and the 415 / 423 refusals.

The entity-tag lifecycle is *state*, so it lives in the collection (P7), not in
the instance: one PUBLISH is one transaction, and its instance is gone long
before the refresh arrives.

What it writes is a `presentity` row: `(username, domain, event, etag)` is the
unique key, `body` is the document, and `expires` is an **absolute** epoch second
— kamailio's convention, adopted here so nothing converts between the struct and
the row.

**Done when** publish → refresh → remove works against an in-memory collection
stub, and a refresh carrying a stale tag is answered 412.

**Delivered 2026-09-21**, with four things settled differently from the
paragraphs above, the first of them the one that matters:

- **the script hands the collection a `%SIP.Publication{}`, not the request.**
  `check_publish/1` is the verb: it reads the PUBLISH against the package
  registry and answers the **489**, the **400** (neither a tag nor a body, RFC
  3903 §11.3.2), the **415** (with `Accept`) and the **423** (with `Min-Expires`)
  itself, then hands over a presentity row already read — the operation, the
  entity-tag presented, the document parsed by the package, and an absolute
  `expires`. Handing the module the raw request, as the sample above did, puts a
  second reading of the message in the module ([CLAUDE.md](../../CLAUDE.md),
  *Message Layer*) and makes every script check which package it is serving.
  What is left to the collection is the **412** and the tag it issues, which are
  the two things only the holder of the tags can know.
- **`SIP.Publication` is the `presentity` row**, under that row's names and with
  its value domains, exactly as `%SIP.Subscription{}` is an `active_watchers`
  row (decision 2). `key/1` is `(username, domain, event, etag)` — the tag is
  part of it, since §4.1 lets a handset and a desk phone hold state for one
  presentity at the same time — and `resource/1` is the coarser key the fan-out
  will notify on.
- **a successful publication is given a NEW entity-tag** (§4.1), which is the
  collection's to mint (`SIP.Publication.new_etag/0`). The framework's rule is
  the other one: a 200 answering a removal carries **no** `SIP-ETag`, because
  there is no state left to name — a publisher handed one there would present it
  on its next refresh and be answered 412 for ever.
- **the reading landed in the message layer**, not in `SIPSessionPublish.ex`:
  `publish_operation/2` (which of the four things a PUBLISH asks for),
  `entity_tag/1` (the `SIP-ETag` granted, the other half of `publish_etag/1`),
  `body_string/1` and `body_content_type/1` are `SIP.Msg.Ops`'s, for the reason
  every other header reading is. `SIP-ETag` gains its atom key in `SIPMsg`
  beside the five of P1.

One thing found on the way: `SIPMsg.parse/2` refuses a message whose `Expires`
is not a number and one whose body states no `Content-Type`, so the junk
`publish_operation/2` has to survive is the junk a template or a script writes,
never a peer's. The tests say so where it would otherwise look like an untested
branch.

**Files** `framework/SIPSessionPublish.ex` (`SIP.Publication` and
`SIP.Session.Publish`), `framework/SIPMsgOps.ex`, `framework/SIPMsg.ex`,
`framework/SIPSessionInvite.ex` (`auto_store/2` stores a PUBLISH too),
`dsl/SIPScenario.ex`, `test/publish_test.exs`,
`test/support/publish_suite.ex`, `test/support/publish_collection.ex`,
`test/support/presence_uas.ex`.

**Tests** one suite run twice, over the dummy package and over `presence`, the
way P4 settled it — `SIP.Test.PublishSuite` parameterised by the same
`SIP.Test.SubscriptionTraits`, which needed no seventh callback. The collection
it publishes into is a named Agent *outside* the instance
(`SIP.Test.PublishCollection`), which is decision 5 asserted rather than
assumed: a stub living in the scenario would prove the opposite. A third module
covers what the dummy package cannot express — a body that is the right content
type and still unreadable (a truncated document, a `<!DOCTYPE`), answered 400
and published nowhere.

### P6 — elixipp, end to end with no node

```
elixipp --listen udp:5060 apps/elixip2/scenarios/uas_presence.exs
elixipp apps/elixip2/scenarios/uac_subscribe.exs --to sip:bob@127.0.0.1:5060
```

**Delivers** `uas :presence` (scenario type `:uas_presence`), its wiring in
`Elixip.ScenarioUAS` — which answers **489** when the inbound `Event` is not the
package the scenario declares, so the script never checks —, the `spawn_child/2`
clause in `SIP.FSL.Host`, the CLI's server mode, and two reference scenarios:
`scenarios/uac_subscribe.exs` (watcher: subscribe, refresh, render each NOTIFY)
and `scenarios/uas_presence.exs` (notifier: accept, notify, terminate).

**Files** `dsl/SIPScenario.ex`, `elixipp/ElixippScenarioUAS.ex`,
`framework/SIPFSLHost.ex`, `apps/elixipp/lib/elixipp/ElixippCLI.ex`,
`apps/elixip2/scenarios/*.exs`, `ELIXIPP.md`, `test/uas_presence_test.exs`,
`test/reference_scenarios_test.exs`.

**Done when** the two scenarios run against each other on localhost UDP, the
monitor shows the SUBSCRIBE / 200 / NOTIFY sequence, and a Linphone client
subscribing to the notifier displays the state it receives. This phase is what
says whether the layer is usable; everything after it is productisation.

**Delivered 2026-09-21.** Four things settled differently from the paragraphs
above:

- **the package a presence server serves is a config key**, `config
  event_package: "presence"`, read by `Elixip.ScenarioUAS` the way `domains:` is
  read for a call server. A scenario that declares none is not checked at the
  factory at all — its instance's `accept_subscription/1` still answers the 489,
  so a `dialog` or a proprietary package needs no change here.
- **the factory serves both halves.** SUBSCRIBE and PUBLISH land on the same
  presence slot and get an instance of the same scenario; which of the two it
  answers is decided by the states it writes. So `uas_presence.exs` also answers
  a PUBLISH — a Linphone that publishes its own state gets a 200 rather than a
  transaction that times out — while keeping nothing, since the collection is
  kelixip's (P7).
- **`spawn_child/2` refuses `:uas_presence` as a sub-FSM**, beside `:uas_register`
  and for the same reason: both are reached through a factory registered as the
  processing module for their method, not through a per-child dispatcher like
  `SIP.Scenario.CallDispatcher`. A sub-FSM would wait for a request that is
  routed elsewhere, so it says so instead.
- **the watcher reads a NOTIFY through the framework.**
  `SIP.Session.SubscribeUAC.notified_document/1` hands back the document the
  event package made of the body — the package of the subscription we hold, or
  the one the NOTIFY's own `Event` names when the 200 has not come back yet. The
  reference watcher would otherwise have re-derived a content type and an XML
  parser in a `defp`, which is the symptom CLAUDE.md names.

The end-to-end run is what found the one defect of this phase, and it is a
framework one: a script `notify/1`s on every SUBSCRIBE it accepts, including an
un-SUBSCRIBE — so a watcher was sent `active;expires=0` one second before the
final NOTIFY that contradicted it. `accept_subscription/1` now marks a
subscription granted 0 as **terminated** (kamailio's status 3), and `notify/1` on
a terminated subscription sends nothing: the only NOTIFY still owed is the final
one, which is the dialog's (decision 4). Left in the script, every notifier ever
written would have had to know it.

**Files** `elixipp/ElixippScenarioUAS.ex`, `framework/SIPSessionSubscribe.ex`,
`framework/SIPFSLHost.ex`, `framework/SIPDialogImpl.ex`,
`apps/elixipp/lib/elixipp/ElixippCLI.ex`, `apps/elixip2/scenarios/uac_subscribe.exs`,
`apps/elixip2/scenarios/uas_presence.exs`, `ELIXIPP.md`,
`test/uas_presence_test.exs`, `test/support/subscription_suite.ex`.

**Tests** `test/uas_presence_test.exs` drives the two reference scenarios — the
files an operator runs, not fixtures written to pass — through the factory over
the mockup transport, and `test/reference_scenarios_test.exs` picks them up on
its own. The un-SUBSCRIBE regression lives in the subscription suite, so it is
asserted once per event package.

Proven on the wire on 2026-09-21, two `elixipp` processes on localhost UDP:
SUBSCRIBE / 200 / NOTIFY, the dialog's own refresh at half the granted lifetime
with its NOTIFY, then un-SUBSCRIBE / 200 / final NOTIFY and both scenarios ending
successfully. The Linphone half of the "done when" is the operator's.

### P7 — kelixip

```toml
[[domain.presence]]
event-package = "presence"
subscribe = "presence-subscribe.exs"
publish = "presence-publish.exs"

[module.presence]
call_timeout_ms = 5000
```

**Delivers**

- `Kelix.Domains`: `presence` becomes a **list** of blocks keyed by
  `event-package`, each naming its `subscribe` and `publish` script; both scripts
  of every block go through `check_scripts/1`, and two blocks claiming one package
  are refused at parse time.
- `Kelix.Router`: dispatch step 3 reads `Event` (through P1) to pick the block and
  raises the **489** itself, before any script runs; `Allow-Events` is composed per
  domain from its blocks.
- `Kelix.Mod.Presence`: the collection — resource → subscribers, the published
  document and its entity-tag per resource, and the fan-out that turns one PUBLISH
  into N pushes. One per domain, isolated, like the registrar
  ([DESIGN-KELIXIP.md](DESIGN-KELIXIP.md#7-the-module-system)). Its records are
  `presentity` and `active_watchers` rows held in memory.
- `kelictl presence` renders those columns under those names — `etag`, `expires`,
  `status`, `event`, `presentity_uri` — so an operator reading it and an operator
  reading the kamailio table they migrated from are reading one vocabulary.
- its control surface, declared once (`describe_control/0`): `kelictl presence
  list`, `show <aor>`, `watchers <aor>`, `remove <aor>`, and the REST paths under
  `/modules/presence`.
- the reference scripts `apps/kelixip/scripts/presence-subscribe.exs` and
  `presence-publish.exs`.
- packaging: `%package mod-presence` and `%files mod-presence` in
  `packaging/rpm/kelixip.spec`, `packaging/deb/control-mod-presence.in`, the
  `build_module` line in `packaging/build-deb.sh`, a commented block in
  `packaging/config/domains.toml`, and `docs/kelixip/modules/presence.md`.
- `Kelix.Options`: `@allow` gains SUBSCRIBE, PUBLISH and NOTIFY.

**Tests** `apps/kelixip/test/router_test.exs` (Event → block, and the 489 with its
`Allow-Events`), `domains_test.exs` (several blocks, a duplicate package refused,
the pre-P7 single table),  `apps/kelix_modules/test/presence_test.exs`
(collection, fan-out, a watcher dying, the control surface) and
`presence_script_test.exs` — both reference scripts driven through spawned
instances, the way `registrar_script_test.exs` is.

**Done when** a node with one domain, `[module.presence]` and the two scripts
serves a Linphone → Linphone exchange, and `kelictl presence list` shows it.

**Delivered 2026-09-21.** Five things settled differently from the paragraphs
above, the first of them the one that matters:

- **the module decides nothing about who may watch whom.** The `policy` key —
  `open | registered | allowlist` — is not delivered and is not deferred: it is
  **dropped**. Admission is the script's, and `presence-subscribe.exs` is where a
  deployment writes its rule; a key here would be a second place deciding it, and
  the real answer is RFC 5025 authorization rules carried over XCAP with
  `presence.winfo` to feed them, which is a phase of its own plugging into this
  same collection. What the reference script *does* check is that the presentity
  is a subscriber of this deployment (`Kelix.Mod.AuthDb.subscriber?/2`, new —
  the existence question without the secret that answers it); anything else is
  **404**, never an empty state a watcher would wait on for an hour.
  `[module.presence]` carries `call_timeout_ms` and nothing else: `default_expires`
  goes the same way, the bounds of a subscription belonging to the event package
  (RFC 6665 §4.4.1).
- **a refusal can carry headers now.** The 489 is worth sending only with the
  `Allow-Events` naming what the domain *does* serve (§4.4.7), and the
  application's verdict could not carry one: `{:reject, code, reason}` reached the
  server transaction through four layers that replied with `fields = []`. The
  tuple gains an optional fourth element, all the way down —
  `SIP.DialogImpl.init/1`, `SIP.Dialog.start_dialog/5`, `process_UAS_request/2` —
  and the three-element shape is untouched, so every other rejection reads as it
  did.
- **MESSAGE leaves the presence function.** It carries no `Event`, so with one
  block per package it can name none of them; page-mode chat is a function of its
  own ([DESIGN-CHAT.md](DESIGN-CHAT.md#dispatch-chat-is-a-function-of-its-own))
  and an out-of-dialog MESSAGE is answered **405** until `[[domain.chat]]` lands.
  Routing it to a subscription script would have been a choice nothing documents.
- **`publish` is optional on a block, `subscribe` is not.** A package published by
  nobody — `dialog` (RFC 4235) — is subscribed to all the same, and a PUBLISH for
  it is **405** rather than a script that would have to refuse it.
- **the subscription's identity columns were not filled.** `watcher_username`,
  `watcher_domain`, `to_user`, `to_domain`, `from_user` and `from_domain` were
  left `nil` by P3, and `kelictl presence watchers` cannot name a watcher without
  them. They are filled at acceptance, through one new reading in the message
  layer (`SIP.Msg.Ops.header_aor/2`). `local_contact` stays empty: it is the
  dialog's to know, and nothing reads it yet.

`Kelix.Options` advertises `INVITE, ACK, CANCEL, BYE` beside the new `SUBSCRIBE,
PUBLISH, NOTIFY`: the call function had landed without the list being updated, and
a probe catches that lie in one request.

**Files** `apps/kelixip/lib/kelix/{domain,domains,router,options,control,metrics}.ex`,
`control/cli.ex`, `metrics/emit.ex`, `module_supervisor.ex`,
`apps/kelix_modules/lib/kelix/mod/{presence,auth_db}.ex`,
`apps/elixip2/lib/framework/{SIPMsgOps,SIPSessionSubscribe,SIPDialog,SIPDialogImpl,SIPTransactionCommon}.ex`,
`apps/kelixip/scripts/presence-{subscribe,publish}.exs`, `packaging/*`,
`docs/kelixip/{installation.md,modules/presence.md}`.

**Not proven yet:** the Linphone → Linphone exchange on a real node, and
`kelictl presence list` against it. Everything below that line is green.

## 4. Decisions this plan takes

1. **The fan-out reaches the scenario, not the dialog.** The module pushes
   `{:presence, :state, resource, doc}` to each subscriber's instance and the
   instance sends the NOTIFY from its own state. The module could hold the dialog
   pid and call the subscription layer itself, but then the NOTIFY is invisible to
   `kelictl monitor` and to the sequence diagram, and a scenario parked in a state
   would no longer describe what the node is doing. The precedent is
   `Kelix.Mod.Registrar.subscribe_registrations/2` and `{:registrar, :upsert, aor}`.
2. **No persistence in v1, but the records are kamailio's rows.** Nothing can
   resurrect a dialog (design decision 1), so persisting state buys one correct
   answer to a PUBLISH refresh after a restart and nothing else — the collection
   stays in memory, like the registrar's, and the Silo dependency the design
   leaves open is not taken. What *is* taken from day one is the **shape**: the
   fields, their names and their value domains are `presentity` and
   `active_watchers` columns
   ([DESIGN-PRESENCE.md](DESIGN-PRESENCE.md#the-data-model-is-kamailios)). A
   backend then writes rows it already holds; a struct designed freely now is a
   migration later, and the migration is what never gets written.
3. **`Allow-Events` does not go on the OPTIONS answer.** It is a property of the
   domain, and `Kelix.Options` deliberately does not derive its answer from
   reloadable configuration. It goes on the responses that already know their
   domain: the 2xx to a SUBSCRIBE, and the 489.
4. **The authorization policy is the script's, not a config key.** *Revised on
   delivery (P7): this decision read "a config key, `open | registered |
   allowlist`", and the key is not delivered.* Admission is one `case` in
   `presence-subscribe.exs`, where every other per-deployment decision already
   lives; the reference script checks that the presentity exists in the subscriber
   base and admits, and a rule of one's own is written in that same state. RFC
   5025's policy document and the `presence.winfo` flow that feeds it are the
   consent phase, and they plug into this same collection.
5. **A PUBLISH instance is short-lived.** Its dialog lives as long as its
   transaction; the entity-tag lifecycle is collection state.
6. **The `presence` module does not register its own event package.** The three
   packages stay compiled into elixip2 (design, *Scope for v1*); `register/1`
   exists for a proprietary package and for tests.
7. **The format, not the usage — two tables, and no DDL.** What is promised is
   that the rows are kamailio's rows, so an existing kamailio base is usable as it
   stands: `presentity` and `active_watchers`, with `watchers`, `xcap` and `pua`
   left untouched. How kelixip *uses* that base is its own — its queries, its
   sweep, its bookkeeping — so the two servers working on one base at the same
   time is not a supported configuration, and nothing in this plan works towards
   making it one.

## 5. Order, and what runs in parallel

P1 → P2 → P3 is the spine, and it is sequential. P4 and P5 both depend on P3 and
are independent of each other. P6 depends on P4. P7 depends on P4 and P5; its
packaging work depends on nothing and can be done at any time.

**The release gate is P6.** A version shipping the subscription layer with no tool
able to drive it has no way of being tested in the field. P7 ships in the same
version or the next one: it is the productisation of something already proven.

Version: **1.6.0** (the tree is 1.5.4). A new SIP function is a minor, and the
number lives in the places [CLAUDE.md](../../CLAUDE.md) lists — four manifests
(one of them twice), two User-Agent defaults, two spec files with `Release:` back
to 1, and a deb changelog entry.

## 6. After v1 — the database backend

What is left once the records already are the rows:

- a store behind the collection (`postgrex`, a dependency kelixip does not yet
  carry), opening a base kamailio created and checking `version` for the table
  versions it knows — `presentity` 5, `active_watchers` 12 — rather than running
  any DDL of its own;
- the sweep of expired rows — kamailio's is a timer over `expires < now()`, and
  ours has one already for the in-memory collection;
- a round trip proven against a real base: rows written by kamailio read back by
  kelixip and the reverse, which is what "uses the format" has to mean before it
  is written in a release note.

None of it changes a line of the subscription layer, which is the point of taking
the shape now.

## 7. Risks

- **a subscription pins a script version for an hour** (design decision 1). A node
  with script churn keeps several versions resident. There is nothing to fix, but
  `kelictl` should say how many versions are pinned and by what — P7 is where that
  line is added.
- **it is single-node.** A subscription is local, like the deferred INVITE's
  wake-up, and belongs to the same scale-out tier
  ([DESIGN-CHAT.md](DESIGN-CHAT.md#horizontal-scale)).
- **Linphone is the only reference client** until P6 says otherwise. What a real
  client actually sends as PIDF, and what it does with a `pending` subscription,
  is measured there — not assumed here.
- **the 481 on every refresh after a restart** is correct and will look like a
  regression to whoever sees it first. A correct watcher re-subscribes; the log
  line saying so is written in P3, not afterwards.
- **the kamailio columns nobody here has exercised.** `updated`, `updated_winfo`,
  `flags`, `priority` and `ruid` are written blind in v1 — their meaning comes
  from kamailio's source, not from a node we have run. They are inert while we
  only use the format, and they are the first thing to look at the day someone
  points the two servers at one base anyway.
