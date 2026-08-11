# Release 1.3.0

2026-08-10 — 81 commits since 1.2.1 (2026-08-08). Theme of the release: **the
B2BUA**. A scenario can now terminate an incoming call and place a second one of
its own, then relay between the two for as long as they live — with a media
server in the middle if it wants one. That covers the three shapes this was built
for: a proxy-like call to a subscriber registered on several devices, a customer
service hunting a list of numbers, and a WebRTC-to-SIP gateway. All three ship as
commented reference scenarios.

Unlike a proxy the server stays a user agent on both sides: it owns two dialogs,
it can hang either of them up, it stays in the signalling path for the whole call,
and it can meter.

The B2BUA is additive: a scenario written against 1.2.1 compiles and runs
identically. One thing outside it does change contract — `Kelix.Mod.Registrar.save`
now answers `{:registered, …}` / `{:unregistered, …}` instead of `{:ok, …}`; see
[registrar](#registrar) below.

## Framework changes

### The B2BUA itself

- new **`SIP.Session.B2bua`**, pulled in by `use SIP.Scenario` — one FSM drives
  **two** dialogs. The inbound leg stays the scenario's own dialog and everything
  already known keeps its meaning; the outbound leg's events arrive **tagged**
  (`{:outbound, {200, resp, trans, dlg}}`), so an `on_events` clause tells the two
  apart by shape. The relay verbs take no direction — they act on the *other* leg,
  whichever the matched event came from, so one clause states a rule once and
  works both ways
- `b2bua_forward/3` creates the outbound leg, `b2bua_forward/1` relays a request
  onto the other leg, `b2bua_forward_reply/1` relays a response back, and
  `b2bua_reply/3..4` answers here and relays nothing. Nothing is relayed unless
  the scenario says so
- a forwarded request is **re-addressed wholesale** — Call-ID, CSeq, tags, route
  set, Contact — so nothing dialog-scoped from one leg reaches the other. ACK and
  CANCEL are translated onto the correlated INVITE transaction rather than re-sent
- **teardown is automatic**, however the scenario ends: an attempt still ringing is
  CANCELled, an established leg is BYEd, and every relayed request still unanswered
  gets a final response on the leg it came from. A scenario never unwinds its legs
  by hand

### Where the second call goes

- new **`%SIP.B2bua.Peer{}`**: an ordered target list plus the policy that goes
  with it — `fork`, `ruri` (rewrite to the target or only route to it), `retry_on`,
  `use_srv`, `outbound_proxy`, `profile`, `fallback_on`, `notify_progress`. A
  binary or a `%SIP.Uri{}` is shorthand for a one-target peer
- **serial hunting**: a device that refuses sends the call to the next target.
  `b2bua_hunting?/0` is how a scenario tells "this device said no" from "the call
  is over" — a refusal from one target is swallowed and the next is tried
- **parallel forking**: an entry of `uris` is a *rung* and a nested entry is a group
  rung all at once (RFC 3261 §16.6). The first `2xx` wins the rung, the losers are
  CANCELled, and the caller gets **one** final response — a non-2xx is withheld
  while a sibling is still pending and the best of the rung surfaces when the last
  one falls. Serial is that same rule with a rung of one, not a second code path
- forking creates branches **inside** the leg's dialog, never a second leg: a hunt
  over ten devices is one outbound dialog and nothing above it notices how many
  were tried
- **dynamic targets**: the `SIP.B2bua.TargetProvider` behaviour hands out targets
  one at a time instead of a static list, with `b2bua_try_next/0` and a per-target
  ring timeout (`b2bua_ring_timeout/0`)
- `b2bua_cancel_forward/0` stops the search on purpose — distinct from relaying the
  caller's CANCEL, which tells the *callee* to stop ringing
- hunt progress can be surfaced as `{:outbound, …}` events (`notify_progress`)
- **SRV failover**: `use_srv: true` expands each URI into one target per SRV
  destination and the hunt walks them. A domain publishing no SRV keeps its URI as
  given, so the flag is safe to leave on
- per-peer `outbound_proxy`, winning over the global `:proxyuri`

### Media between the two legs

- `{:mediaserver, opts}` as the third argument of `b2bua_forward/3`: both legs
  terminate their media on the server, the bodies that cross are **ours** in both
  directions and neither side ever sees the other's SDP. `false` keeps the SDP
  crossing verbatim with no media server involved
- new **`bridge/3` and `unbridge/2`** in `MediaServer.Behaviour`, implemented by
  `MediaServer.Mendooze`: one media session, **two endpoints**, attached to each
  other — an arrangement confirmed against a real Medooze rather than assumed
- **transcoder chains** when the two sides do not share a codec. `transcode:` is a
  policy per media: `:avoid` (default) connects the endpoints directly when they
  agree and transcodes only when they do not, `:force` always transcodes so each
  side is served the codec it asked for, `:forbid` fails the call instead
- `inbound:` / `outbound:` say how each leg terminates its media (`webrtc:` takes
  `:yes`, `:no`, `:if_offered`, `:no_avp`) — this is where a gateway is expressed
- the bridge is **automatic**: it is built when the `2xx` is relayed, the first
  moment both SDPs are known. `b2bua_bridge/1` wires it earlier for early media,
  `b2bua_unbridge/0` takes the media path down without ending the call
- media handles are **leg-qualified**, and the media plane is call-scoped: the
  server going away takes the **call** down, not one leg
  (`{:media_timeout, media}`, `:media_lost`, `:server_disconnected`)
- a `2xx` whose media cannot be bridged reaches the scenario as a `488` — it reads
  as one device refusing rather than as the call failing; `b2bua_media_error/0`
  carries the reason

### Re-offers on an established call

- **`b2bua_reoffer_kind/1`** classifies a re-INVITE or an UPDATE: `:hold`,
  `:resume`, `:media_change`, `:address_change`, `:no_sdp`, `:no_change`,
  `:unknown`. With a media server in the middle, a peer that merely *moved* (a new
  `c=`, a new port, an ICE restart) has changed nothing the far end can see
- **`b2bua_reply_reoffer/1`** answers such a re-offer locally and relays nothing. An
  offerless re-INVITE is answered with an offer of ours whose answer arrives in the
  ACK; that ACK is absorbed, so the scenario keeps its single ACK clause

### Offer profiles

- new **`SIP.B2bua.Profile`** and the `webrtc → avpf → avp` ladder: a callee
  answering `488` is refusing the **body**, not the call, so it is asked again in a
  language it may speak before anything else is tried. `%Peer{profile:}` takes
  `:webrtc_required`, `:webrtc_if_supported`, `:avpf_required`, `:avpf_if_supported`
  or `:avp`; `fallback_on` says which finals walk the ladder down (default `[488]`)
- a fallback is a **new INVITE to the same target** on a new CSeq, carrying an offer
  built by a fresh endpoint — a local description belongs to the endpoint that made
  it, so another profile means another endpoint. The caller is not part of any of
  it: their answer was decided when their offer was read
- each new rung of targets **restarts the ladder at the top** — what one phone
  refused says nothing about the next one
- `rtp_profile: :avp | :avpf` is a new connection option in **both** media adapters;
  the middle rung had no way to be expressed before, an offer being binary
- `profile: nil` is the default and is not a rung of that ladder: the offer comes
  from the `outbound:` options exactly as before

### Dialog, transaction and message layers

- `SIP.Dialog.fork_branch/2` and `/3` — branches inside one dialog, with `body:` for
  a new offer on a new CSeq; `start_dialog/5` takes `:tag` and `:fork`
- a **client-transaction timeout is reported to the application as a synthetic 408**
  (RFC 3261 §17.1.1.2 / §8.1.3.1). Nothing was said at all before: a request that
  got no answer left the scenario waiting on its own `after` clause with no idea
  why, and a hunt never moved past an unreachable device
- a re-INVITE is answered on its own transaction, and its ACK lands there
- leg-crossing rules (purge/copy of what must not cross) live in `SIP.Msg.Ops`

### The registrar session layer

- the `SIP.Session.Registrar` verbs take the **scenario context** as their first
  argument — `challenge_registration(sip_ctx, req, …)`,
  `accept_registration(sip_ctx, req, granted)`,
  `reject_registration(sip_ctx, req, code, reason)`. The dialog pid is read off the
  context instead of being threaded through every state by hand. The previous
  `(req, dialog_pid, …)` forms are unchanged and still work
- `challenge_registration/3` also accepts an **already-built WWW-Authenticate
  parameter map** as its third argument (a keyword list keeps the old meaning: let
  the dialog layer mint the nonce). That is what an application minting its own
  stateless nonce needs — kelixip's `Kelix.Auth.challenge_www_authenticate/2` — and
  it had no choice but to bypass the session layer and call `reply/6` itself
- `accept_registration(sip_ctx, req, granted)` answers straight from what a location
  service granted (`%{aor, contacts, expires}`): every current binding with its own
  remaining lifetime (RFC 3261 §10.3 step 8), no Contact header at all when the last
  one is gone, and the AOR named to the monitor
- `reject_registration/4` puts the mandatory `Min-Expires` on a 423 when it is given
  the bound as an integer (§10.3 step 7). Composing that header was left to each
  script, and a 423 without it tells the client nothing it can act on

### Resilience

- the dialog traps exits and converts a transaction crash into a synthetic 408; the
  scenario engine catches exits so teardown always runs
- connectionless transport re-selection: a dead socket is a send failure, and UDP
  recovers from it
- a transport going down during a hunt is a **branch** failure, not the death of the
  dialog
- a leg that dies answers what it owed — its pending requests get a final response —
  before the scenario decides what to do
- `media_cleanup_ressources()` is what a scenario releases with on the way out: it
  skips dead handles and releases both legs, where `media_stop()` does not

## Framework corrections

- **SRV resolution never worked.** `resolve_srv_multiple/2` pattern-matched its index
  against `0`, so every other index raised `FunctionClauseError`; the "no more
  priorities" branch was dead; the weighted draw ran once per priority group and
  discarded the rest, where RFC 2782 uses weight to *order* a group; and an
  all-zero-weight group reached `:rand.uniform(0)` and crashed — weight 0 being
  exactly what an operator that does not load-balance publishes. Rewritten as
  `order_srv/1` (pure, tested without a resolver) + `srv_targets/1`
- **a client transaction in `:cancelling` dropped every final response.** So a
  cancelled INVITE was never ACKed (§17.1.1.2), the dialog was never told the branch
  had ended, and a `2xx` crossing our CANCEL was discarded before anything could
  clean it up. Cancelling asks; only a final decides
- every branch after the first ignored the peer's `ruri: :keep` (a trunk's second
  branch was rewritten to the gateway's URI) and its `outbound_proxy`
- `address_in_dialog/2` restores **both** identities on an outbound dialog
- **the registrar scenarios still watched for `:tcp_closed` / `:tls_closed` /
  `:wss_closed`**, which the dialog layer stopped sending when the three
  per-protocol clauses became one `:transport_down` (§14.4, R4). The guard matched
  nothing, so a client whose connection dropped fell through to the catch-all and
  was recorded as a registration that ended normally. Both
  [`registrar.exs`](../../apps/kelixip/scripts/registrar.exs) and
  [`uas_register.exs`](../../apps/elixip2/scenarios/uas_register.exs) now match
  `:transport_down`
- **a refused REGISTER no longer ends the registrar instance.** Nothing monitors
  the app pid, so the dialog outlives the scenario: it kept matching the next
  REGISTER of that Call-ID and casting it to a dead process, leaving the client
  with no answer at all until the dialog's own expiration timer fired — up to an
  hour. 400 / 403 / 503 are answered and the instance keeps waiting; only the
  dialog ending (un-registration, transport down, expiry) ends it
- **mendooze: media arriving before the answer no longer loses `:ice_connected`.**
  The receive plane opens early — `EndpointStartReceiving` is what allocates the port
  we advertise — so the far end can be sending well before its SDP reaches us, which
  as a UAC is the ordinary case. Each early `{:media_connected, media}` was evaluated
  against an empty expectation set, discarded, and never re-armed: a scenario waiting
  on `:ice_connected` waited for ever while the media flowed. This is as old as the
  connectivity redesign and affects **any** UAC scenario, not only the B2BUA

## Domain Specific Language changes

- new **Connecting calls (B2BUA)** section in [DSL.md](../../DSL.md); the `b2bua_*`
  macros need no opt-in beyond `use SIP.Scenario`
- the `@media` attribute takes the `{:mediaserver, inbound:, outbound:, transcode:}`
  form described above
- like the other DSL verbs, the B2BUA macros rebind the scenario context in place:
  they return nothing and their verdict is read from `sip_ctx.lasterr`
- **`last_uas_req()` now covers REGISTER**, not only INVITE / re-INVITE / UPDATE. A
  registrar instance serves a succession of REGISTERs on one dialog — the
  unauthenticated one, the digest replay, then every refresh — and each state must
  act on the last one received. Scripts were storing it by hand
  (`appdata_set(:register_req, req)`), and the fallback to the request that spawned
  the instance made forgetting it silent *and* wrong: the scenario authenticated the
  refresh but saved the contacts of the very first request

## elixipp testing tool changes

No functional change. Four reference scenarios ship with it:

- `b2bua_basic.exs` and `b2bua_media.exs` — the same call, the same states; the
  difference between the two files is what a media server costs. Worth reading as a
  pair
- `customer-service.exs` — a short number answered by hunting a list of numbers
  serially
- `webrtc-gw.exs` — a WebRTC call re-sent to a SIP phone through a media server,
  walking the offer-profile ladder to find what the phone speaks

## kelixip

- two reference scripts for the B2BUA:
  [`direct-call.exs`](../../apps/kelixip/scripts/direct-call.exs) (kamailio's
  `lookup("location"); t_relay()` done as a B2BUA — and the difference is that we
  stay in the signalling path for the whole call) and
  [`b2bua.exs`](../../apps/kelixip/scripts/b2bua.exs)
- `mcu.exs` / `mcu_adhoc.exs` also tear the call down on `:server_disconnected`
  reported by their **own** media connection, not only on the module's relay of it:
  `media_connect/0` makes the script the event sink, so both routes reach it and
  neither is guaranteed to be first

### kelictl

No change.

### REST API changes

No change. The `mcu` codec keys (`audio_codecs`, `video_codecs`, `text_codecs`,
`video_fmtp`) announced in 1.2.1 as becoming an error are **still accepted and
ignored with a warning** — the change is deferred, not made.

### Packaging

- `mcu.exs` and `mcu_adhoc.exs` now ship with **`kelixip-mod-mcu`** instead of the
  core. Every conference verb they call is the module's, so a core-only host had two
  scripts it could not run. `script_dir` itself still belongs to the core, which the
  module package depends on at the same version
- no new package and no new path otherwise

### auth_db

No change.

### registrar

- **`save/2` takes the scenario context**: `save(sip_ctx, req)` reads the served
  domain and the backing dialog off it, so a script carries neither. The
  `save(req, domain, dialog_pid, info)` form stays for callers with no context
- **`save` says what happened to the AOR**, not merely that the store accepted the
  request: `{:registered, granted}` / `{:unregistered, granted}` where it used to
  answer `{:ok, granted}`. The two demand different things of the script — a
  registration is answered and then waited on for its refresh, an un-registration is
  answered and the session is over — and a script re-deriving it from
  `granted.expires == 0` gets it wrong on the request that drops one of two
  bindings, which still leaves the AOR registered. **Breaking** for any code
  matching `{:ok, granted}`
- the facade reports to the monitor (`:db` command `registrar_save`), so a registrar
  instance shows what it is doing between the REGISTER and the 200 rather than
  sitting apparently idle
- new **`targets/2`**: where to call the AOR a request asks for, returned as a
  `%SIP.B2bua.Peer{}` ready to hand to `b2bua_forward/3`. The B2BUA-shaped
  counterpart of `lookup/1` — a B2BUA builds its own forwarded request and needs
  targets, not rewritten requests
- the contacts come back **grouped by descending Contact `q`** (absent `q` ranks
  top; equal `q` keeps registration order), each stamped with its destination and
  registration flow, with `fork: :parallel` — so a subscriber's devices of equal
  preference ring at the same time and the groups are walked in order. A script
  wanting another policy edits the struct it gets back
- one atom per failure, each mapping to one SIP answer: `:notfound` (480),
  `:no_aor` (400), `:unavailable` (500)

### mcu

- `bridge/3` and `unbridge/2` answer `{:error, :not_supported}` / `:ok`. A
  conference leg's far end is the mixer, and a mixer is what two legs are already
  joined **through**: bridging a pair directly would take them out of the mix. A
  two-party call is a conference of two

## Documentation

- new **[B2BUA.md](../../B2BUA.md)** — the scenario writer's side: the complete macro
  reference, the `%Peer{}` target form, the media modes, the offer-profile ladder,
  and the three use cases commented end to end
- the **mcu module document** was rewritten and reviewed
- [registrar.md](../kelixip/modules/registrar.md) documents `targets/2`
- design documents: `b2bua_module.md` (the *why*, with the phasing table now closed
  through P5), `b2bua_media_impl_plan.md`, `b2bua_offer_profiles_plan.md`,
  `mediagw_b2bua_jsr309.md`

## Test suite

Not a release feature, but the reason the suite can be trusted at this size. The
order-dependence was traced with data — five full runs before, five after, failures
aggregated by module — and the causes fixed rather than worked around:

- a global config (`:proxyuri`, `:proxyusesrv`) that six modules wrote and one
  restored, so whichever ran last decided what the next one saw
- the fake JSR309 server died with the test process that opened its listen socket,
  while every connection was still tearing down: 447 refused teardown RPCs per run
- the shared UDP mockup singleton, now one instance per suite
- 120 tests moved to async; two shared support modules replaced 15 copies of the
  same helper across 20 fixture sites

## Dependencies

- [mediaserver 1.12.2](https://github.com/neutrino38/mediaserver/releases/tag/1.12.2)
  — unchanged since 1.2.1. The B2BUA media work asked nothing new of the server: the
  two-endpoint arrangement, the transcoder chains and the `rtp_profile:` option all
  use RPCs it already exposes, read from its own source and exercised against a live
  one
