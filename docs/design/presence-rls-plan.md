# presence-rls-plan.md — serving a buddy list

**Status: L0 through L7 are implemented.** The design is
[DESIGN-PRESENCE.md](DESIGN-PRESENCE.md#the-buddy-list); this document is the
order it got built in, what each lot delivers, and what proves it.

It continues [presence-basic-plan.md](presence-basic-plan.md), which left the
buddy list out of v1: a client subscribed once per buddy.

## 1. What made it necessary

A Linphone Desktop 6.2.2 client opens its roster with a single SUBSCRIBE,
captured on 2026-09-22:

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
Accept-Encoding: deflate
```

Its three entries sat on three domains, none of them the routed one. The node
could neither serve it nor refuse it correctly: `Require` was read nowhere, a
deflated body could not be parsed, there was no RLMI and no `multipart/related`,
and the collection keyed every resource on the domain that routed the request.

## 2. Scope

| In | Why |
|---|---|
| the list in the request (RFC 5367) | it is what real clients send, and it needs no list store |
| RLMI + `multipart/related` (RFC 4662, RFC 2387) | the answer's format; there is no other |
| `Content-Encoding: deflate`, both ways | a list NOTIFY is past the UDP MTU and IPv6 does not fragment in transit |
| `Require` / **420** in the subscription layer | without it the node cannot even refuse a list subscription correctly |
| a resource keyed on the domain of its own URI | the entries of one list sit on several domains |
| `presence-rls.exs`, packaged and documented | a function nobody can install is not shipped |

| Out | Where it re-enters |
|---|---|
| XCAP (RFC 4825/4826) | the day a deployment wants the list to outlive the client holding it; it changes nothing below |
| back-to-back subscriptions for entries we do not serve | the `[outbound]` domain; until then those entries are reported `noresource` |
| `pidf-diff` partial documents (RFC 5262/5263) | partial NOTIFYs here carry whole documents for the resources that changed |
| a blanket `Require` check on every method | it would newly refuse the `Require: timer` of INVITEs that work today |

## 3. Lots

### L0 — `Require` and 420 Bad Extension

`SIP.Msg.Ops.required_extensions/1` and `supported_extensions/1`;
`SIP.Session.Notifier.negotiate/2` refuses an extension the layer does not
implement with **420** and an `Unsupported` naming it.

*Proved by* `subscription_suite.ex`, so it runs over both event packages.

### L1 — `Content-Encoding` on the way in

`SIP.Msg.BodyCoding.decode/2` (zlib and raw deflate — the field means both), wired
into `SIPMsg.add_body/2` **after** the `Content-Length` cut, since the length
counts compressed octets. The header is dropped with the compression it named. A
coding we cannot undo is answered **415** with `Accept-Encoding`, through the
transport's stateless refusal path.

*Proved by* `body_encoding_test.exs`, over the captured SUBSCRIBE.

### L2 — a resource belongs to the domain of its own URI

`Kelix.Mod.Presence`: the routed domain becomes a fallback, the ETS tables are
keyed on the resource's domain, `watch_many/3` files one list across several
domains under one monitor, and `unwatch/1` sweeps them all.

*Proved by* `presence_test.exs`: a watcher admitted through one domain is reached
by a PUBLISH on another.

### L3 — RLMI, resource-lists, `multipart/related`

`SIP.Presence.Rlmi` (both directions), `SIP.Presence.ResourceLists` (read only),
`Content-ID` on a serialized part, `SIPMsg.parse_multi_part_body/2` over any
multipart subtype, and `SIP.Msg.Ops.compose_multipart/2` for `type=` and `start=`.

*Proved by* `rlmi_test.exs`.

### L4 — the list subscription in the notifier

`SIP.Msg.Ops.recipient_list/1` is the single reading of what makes a SUBSCRIBE a
list subscription. `%SIP.Subscription{}` gains `list_uri`, `list_entries` and
`body_encoding`; the dialog stamps `Require: eventlist` from them. `notify_list/1`
composes the manifest and the parts in one pass, so an instance's `cid` and the
`Content-ID` of its part cannot drift apart.

*Proved by* `list_subscription_test.exs`, end to end over the mockup transport.

### L5 — compression on the way out

`SIP.Msg.BodyCoding.encode/2`, applied past 1200 octets when the watcher
advertised `deflate`.

### L6 — the script, the routing and the configuration

`presence-rls.exs`: authentication on the watcher's own realm
(`realm: :from_domain`), `watch_many/3`, a full-state NOTIFY, then one partial
NOTIFY per 500 ms batch. The list URI is declared as a domain of its own in
`domains.toml`.

*Proved by* `presence_script_test.exs`, which drives the installed script.

### L7 — documentation

[DESIGN-PRESENCE.md](DESIGN-PRESENCE.md#the-buddy-list),
[docs/kelixip/modules/presence.md](../kelixip/modules/presence.md), the shipped
`domains.toml` and this file.

## 4. What was found on the way

Two defects the list NOTIFY uncovered, both older than this work and both in the
single-part path:

- `SIP.Msg.Ops.update_sip_msg/2` dropped the boundary of a multipart body of
  **one** part, and overwrote the message's Content-Type with the part's;
- `SIPMsg.serialize_body/1` then wrote that part's payload alone, under a
  Content-Length computed over the delimiters.

Together they produced a message announcing a multipart Content-Type and a length
nobody could match, over a bare body. A list NOTIFY naming one buddy with no
published state is exactly that message.
