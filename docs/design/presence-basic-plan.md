# presence-basic-plan.md — building basic presence

**Status: plan. Nothing below is implemented.** The design is
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
| consent / `presence.winfo` (RFC 3857, 3858, 5025) | a second `SIP.EventPackage` over the same layer and the same collection; v1's policy is a config key |
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

The body comes off the network and is untrusted. Parsing goes through OTP's
`:xmerl_scan` with external entity fetching disabled and a bound on the body size;
the exact option set is verified against the OTP 26 xmerl surface when this phase
is written, since entity expansion — not the XML — is the risk. `:xmerl` joins the
release's applications.

**Tests** round-trip on documents captured from Linphone, stored as
`test/PIDF-*.xml` beside the existing `SIP-*.txt`; a document carrying an unknown
namespace still usable; and the refusals — truncated XML, a doctype, an
oversized body.

**Done when** P3's suite passes again with `SIP.EventPackage.Presence` substituted
for the dummy package. That substitution is the proof the behaviour is a
behaviour.

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

**Files** `framework/SIPSessionPublish.ex`, `test/publish_test.exs`.

**Done when** publish → refresh → remove works against an in-memory collection
stub, and a refresh carrying a stale tag is answered 412.

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

### P7 — kelixip

```toml
[[domain.presence]]
event-package = "presence"
subscribe = "presence-subscribe.exs"
publish = "presence-publish.exs"

[module.presence]
policy = "registered"          # open | registered | allowlist
default_expires = 3600
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
  document and its entity-tag per resource, the authorization policy, and the
  fan-out that turns one PUBLISH into N pushes. One per domain, isolated, like the
  registrar ([DESIGN-KELIXIP.md](DESIGN-KELIXIP.md#7-the-module-system)). Its
  records are `presentity` and `active_watchers` rows held in memory. The policy
  is a config key and writes nothing: `watchers` is kamailio's consent table and
  belongs to the winfo phase, so v1 neither fills it nor reads it.
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

**Tests** `apps/kelixip/test/router_presence_test.exs` (Event → block, and the
489), `domains_test.exs` (several blocks, a duplicate package refused),
`apps/kelix_modules/test/presence_test.exs` (collection, policy, fan-out, a
subscriber dying) and `presence_script_test.exs` — both reference scripts driven
over the mockup transport, the way `registrar_script_test.exs` is.

**Done when** a node with one domain, `[module.presence]` and the two scripts
serves a Linphone → Linphone exchange, and `kelictl presence list` shows it.

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
4. **The authorization policy is a config key, not a document.** `open |
   registered | allowlist`. RFC 5025's policy document and the `presence.winfo`
   flow that feeds it are the consent phase, and they plug into this same
   collection.
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
