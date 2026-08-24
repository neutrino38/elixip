# DESIGN-MCU.md — the conferencing module

The as-built design of **`mcu`**, the kelixip conferencing module: a reduced MCU
distilled from the Java `mcuGold` application server and rebuilt on the Medooze
MCU XML-RPC API (`POST /mcu`).

It is a loadable kelixip module and follows every rule of
[DESIGN-KELIXIP.md](DESIGN-KELIXIP.md) §7 — it is separated out here only because
it is a subsystem the size of a product. Operating it is
[docs/kelixip/modules/mcu.md](../kelixip/modules/mcu.md) (configuration and
commands), [mcu_module_guide.md](../kelixip/modules/mcu_module_guide.md)
(writing a script, reading the logs of a failed call) and
[mcu-api.md](../kelixip/modules/mcu-api.md) (the REST surface).

The deliverable is deliberately **two artefacts and no new frontal**: a module
and a script. Everything else it needs already existed.

---

## 1. Scope

**In:** inbound call handling (an INVITE whose R-URI user-part matches a DID
joins that conference), a REST/CLI surface to create, modify, list and destroy
conferences, audio + video mixing on the default mosaic and sidebar with an
optional automatic layout, **total conversation** (T.140 real-time text with RFC
4103 redundancy), and the three transport cases a real deployment brings —
plain RTP/AVP(F), SDES-SRTP, and DTLS-SRTP + ICE-lite — classified explicitly
rather than falling out of per-attribute handling.

**Out, and why it is safe:** conference templates and ad-hoc creation on an
unknown DID (an unknown DID is a `404`); an admin web UI (REST and `kelictl`
only); outbound calls (they need B2BUA legs); RTMP/Flash, recording of
broadcasters, document sharing/BFCP, extra mosaics and sidebars, SOAP event
listeners, a CDR engine, join-time authentication. Each was dropped against a
reason, not by omission; the parameters that would carry them (the participant
role, for instance) are still passed correctly, so adding one back is additive.

**Non-goals worth stating:** no multi-MCU conference (a conference is pinned to
the media server chosen at creation), no admission control (reaching the DID *is*
joining). Persistence is deliberately partial: a declared room comes back after a
restart, the calls in it do not (§4.1).

---

## 2. What was kept from mcuGold, and what was not

The Java code is the reference for **call-flow correctness**, not for structure.
Three things were transcribed faithfully:

1. **The RPC ordering** of an inbound call. Getting it wrong yields a media
   server that answers an error to everything and sends no RTP.
2. **The split between answer-time and ACK-time work.** Receiving starts *before*
   answering (the local ports are needed for the SDP); sending starts, and the
   mixer is joined, only on the **ACK**. A caller that never ACKs never enters the
   mix, and no RTP leaves the MCU before the call is established.
3. **Who generates which secret.** For SDES the *controller* generates the local
   key; for ICE the *controller* generates ufrag and password; only the DTLS
   fingerprint comes from the server (server-wide, cacheable).

What was discarded: the `Participant` god object — 3 700 lines mixing SIP dialog
state, SDP parsing, XML-RPC and mixer policy. Here the SIP state **is the
scenario instance**, the SDP and RPC work is the adapter, and the mixer policy is
the module. That split is the design.

---

## 3. Architecture

```
 SIP ──INVITE──▶ Kelix.Router ──dial-plan──▶ InstancePool
                                                 │ spawns
                                                 ▼
                                          mcu.exs  (1 per call)
                        facade calls  ┌──────────┴─────────┐  media FSL
                                      ▼                    ▼
                          Kelix.Mod.Mcu            Kelix.Mod.Mcu.Adapter
                       (GenServer + ETS)            MediaServer.Behaviour
                       conferences, DIDs,             1 process per call
                       participants, quota                   │
                                │                            │
                                ▼                            ▼
                     Kelix.Mod.Mcu.Client            Kelix.Mod.Mcu.Sdp
                     XML-RPC POST /mcu                (offer/answer)
                                │
                                ▼
                     Kelix.Mod.Mcu.EventQueue ──── FPU, events ──▶ scenarios
                     GET /events/mcu/<queueId>
```

| Process | Scope | Role |
|---|---|---|
| `Kelix.Mod.Mcu` | node | conference registry (ETS), DID index, quota, control commands |
| `.Client` | node, one per MCU | the XML-RPC channel; serialises calls under `xmlrpc_timeout_ms` |
| `.EventQueue` | node, one per MCU | chunked long-poll, decode, dispatch to the owning participant's scenario |
| `.Adapter` conn | **call** | one per leg: `{conf_id, part_id, media map, crypto, ports}` |
| `mcu.exs` | call | the SIP state machine |

Supervision is **`rest_for_one`**: the registry owns the ETS tables the others
read. The MCU list comes from the configuration at boot, not from
`Kelix.MediaPool` — the node starts its modules *before* the pool. An MCU
unreachable at boot does not prevent the module from starting: its client comes
up marked `down`, and conferences on it are refused with a clear error.

**The adapter implements `MediaServer.Behaviour` on purpose.** The media FSL then
works unchanged: `media_connect()`, `reply_invite_with_sdp/2` and `media_stop()`
in `mcu.exs` are the same macros a plain UAS scenario uses. The mapping is
mostly direct — `create_peer_connection/3` is `CreateParticipant` in the
conference named by the options, `set_remote_offer/2` is the whole answer-time
sequence, `close_peer_connection/1` is stop + `DeleteParticipant`. Player,
recorder and echo answer `{:error, :not_supported}`: the API has the RPCs, the
perimeter does not need them.

Conference-level operations have **no place in that behaviour and are not forced
into it**: they are plain functions on the module, reached through its facade.

---

## 4. Data model

A **conference** carries its kelixip `uid` (stable for its life, and what REST
clients use), its `domain` and `did`, the MCU it is pinned to and the MCU-side
`conf_id` (an implementation detail that changes if it is ever recreated), the
mixer settings (VAD, rate), which `m=` sections it answers at all (`medias` — the
codecs inside them are the server's call, §6), the video codec it states first in
its answers, one **inline video profile**, the mosaic layout, the quota and the
auto-destroy flag, plus its participants.

Storage is one ETS table keyed by `uid` plus a `{domain, did} → uid` index, owned
by the module's GenServer. **Reads go straight to ETS** — the hot path is one DID
lookup per INVITE — while writes go through the GenServer, which is what
serialises "create this conference" against the media server. Same pattern as the
registrar module.

A **participant** row is owned by the module, so `list`/`show` can report it and
the quota is authoritative; the *media detail* belongs to the adapter connection,
and the module keeps only what a human wants to see.

**DID allocation.** `create` may omit the DID, in which case the module takes the
lowest free number in the domain's configured range and returns it. An explicit
DID is always honoured, **including one outside the range** — the range is an
allocation pool, not an admission filter. An exhausted range is a `409`.
Allocation runs inside the `create` call, so two concurrent creates cannot get
the same number.

Two consequences an operator meets: a DID is unique **per domain**, and the
dial-plan pattern must cover the allocation range — a range outside the pattern
yields conferences nobody can dial, so `create` **warns** when the DID it
allocated matches no dial rule.

### 4.1 What survives the node

A conference has two halves, and only one can outlive the node: the **definition**
— what somebody declared, from the domain and DID down to the video profile, the
pinned slots and the MCU it is pinned to — and the **runtime**, which is the
MCU-side `conf_id`, the participants, the `stale` flag and a running recording.

`Kelix.Mod.Mcu.Store` writes the definition to one JSON file,
`[module.mcu] conference_file`, rewritten whole on every change and read once at
module start. It cannot write the runtime half: its encoder names the fields it
emits, one by one, so a field added to the struct stays out of the file until
someone decides it belongs there. JSON because the `toml` dependency only reads and
an operator must be able to read what a node will bring back; not `:mnesia`, whose
schema binds to a node name an `/etc/default/kelixip` edit can change, for a data
set that fits in a page in a module that is hot-loadable. The write is atomic — a
sibling `.tmp` and a rename — so a node killed mid-save loses the last change and
never the file. No `conference_file`, no persistence, said once at start.

**Only rooms somebody declared are written**: every REST/CLI create, and the scripts
that ask for `owner: :none`. A room made for one call (`owner: :caller`) is not —
bringing it back at every boot would be a room nobody asked for, and a conference
per call would mean a file write per call.

**Restoring reuses the media-server recovery of §10 rather than duplicating
creation.** A row read from the file is inserted `stale`, with no `conf_id`, so the
path that already rebuilds a conference after an MCU restart is what gives it its
server-side existence when the control channel comes up. One code path creates a
conference, and a DID cannot be handed out twice.

**Failure has a direction: never destroy the operator's file.** A file that does not
parse disables persistence for the run and is left untouched — restoring nothing is
recoverable, overwriting is not. A single malformed *row* costs only its own room,
named in the log. A failed write is logged and the command still succeeds: a
conference that exists is worth more than a file that is up to date.

**Values may be written by hand.** `"vad": "full"`, `"video": {"size": "hd720p"}`
are read by the same vocabulary functions that accept an operator's input at the
control surface, so an entry means here exactly what it means there.
Pre-provisioning a room by editing the file is a supported thing to do, knowing
kelixip rewrites the file on the next change.

---

## 5. An inbound call

Routing uses the existing dispatch, with no new mechanism: a dial rule points the
conference DIDs at `mcu.exs`, `Kelix.Router` resolves domain → `calls` → script,
and the instance is spawned with its domain injected. The script asks the module
which conference the user part designates; an unknown DID is a `404`.

```
INVITE (offer)
  → lookup_did             404 if unknown
  → reserve                quota: 486 / 603
  → 180 Ringing
  → create_peer_connection  CreateParticipant
  → set_remote_offer        per media, in this order:
        SetLocalCryptoSDES / SetLocalSTUNCredentials   (secure / ICE)
        SetRTPProperties(codec intent)                 BEFORE
        StartReceiving  ────────────────────────────▶  recPort, ip, fmtpByPt
        SetRemoteCryptoDTLS|SDES, SetRemoteSTUNCredentials
        SetRTPProperties(transport: rtcp-mux, natLatch, feedback)
  → 200 OK (answer)
  ← ACK
  → attach                  per media: SetCodec + StartSending
                            AddSidebarParticipant (audio) / AddMosaicParticipant (video)
                            SetCompositionType (if the layout is automatic)
```

The two rules of §2 are visible in that sequence: receiving is armed before the
answer because the answer needs the ports, and nothing is sent or mixed before
the ACK.

**The admission call wires the leg.** `admit/4` — the context-aware form the
reference scripts use — settles the three things an admitted conference leg needs
before `media_connect/0`, none of which is a call-flow decision: the local identity
(the conference DID, which is what an in-dialog request we originate puts in From
and To, and without which `send_BYE()` has no URI to build), the connection options
(which conference this leg joins, and `nat_latch`, because a conference leg always
*answers* an offer, so the address it is told to send to is the private one the
caller wrote down), and the media server (a conference is pinned to its MCU, so the
leg must reach the server holding the mixer rather than whatever the pool hands
out). A script that copied that plumbing was stating what a conference leg *is*,
not what its call flow does. A script needing other connection options sets them
after `admit`; the last write wins.

**Joining is not authenticated.** The reference script challenges nobody, because
the module has no business owning an auth policy the SIP layer already expresses
three ways (an upstream trusted proxy, a digest challenge against the `auth_db`
module, a secret in the R-URI). A deployment that wants one copies `mcu.exs`,
inserts the challenge before the admission call and points its dial rule at the
copy — no module change, no core change. The cost is recorded as a known
limitation, not hidden.

**Errors say what they mean.** "No codec in common" is a `488` — the offer is
unusable and retrying is pointless — while a media-server RPC failure is a `500`,
which is ours and may work on a retry. One code for both would tell the peer the
wrong thing about what to do next; making that expressible required the media
error hook to accept a function rather than a fixed pair.

### 5.1 The leg's life in the mix, as a block

Everything after the `200` is one service building block,
`Kelix.Mod.Mcu.SBB.Conference`, called `Mcu.SBB.conference()`
([DESIGN-SBB.md](DESIGN-SBB.md#74-a-kelixip-module-publishes-its-blocks): a
kelixip module publishes functions a script calls for a *decision*, and blocks a
script enters for a *sequence*). A script enters it where it would have written
`goto(in_call)`, and the three states that used to follow — `in_call`,
`in_conference`, `hanging_up` — are gone from the scripts.

They were worth removing because they carried **no conference policy at all**.
They carried SIP: which ACK is the first one, that an INFO is answered whether or
not it is an RFC 5168 request, that a BYE is answered before the slot is
released, that our own BYE is followed by a wait for its 200, that a leg gone
silent is a leg to hang up. And being a copy, the second script had already lost
three clauses of it — `on_events` compiles to a `receive` and nothing injects a
catch-all, so a media event the ad-hoc script had never been taught about matched
no clause and stayed in the mailbox for the whole call. A leg whose media died
held its slot until the 2 h backstop, and nothing reported it. That is
[DESIGN-SBB.md](DESIGN-SBB.md) §1 in one file pair.

**The seam is the answer.** The block never composes a response to an offer,
which is why it takes no `media:` and no `webrtc:` argument: the `200`, its media
set, its secure mode and its error mapping are the deployment's, and they stay in
the script's `answering` state. What the block owns is the sequence between that
answer and whatever ends the leg.

**One argument**, and the BYE's own 10 s wait is not one — it has a single caller
and a single right value. `:idle_timeout`, 2 h, is the G3 backstop against a leg
that goes silent; every event the block consumes re-arms it, so it is *idle* and
not a maximum call duration. The name differs from `bridge`'s `:max_duration` on
purpose: same shape, opposite meaning.

**Two families of outcome**, and the difference is what state the leg is left in.
The first hands the call back **whole** — nothing answered, nothing released — so
the script acts and re-enters with `goto(loop, …)`:

| Outcome | Data | What happened |
|---|---|---|
| `:renegotiation` | `%{method: :INVITE \| :UPDATE, req, transaction, dialog}` | a re-INVITE or an UPDATE arrived, **unanswered** |
| `:message` | `%{envelope}` | a peer's script said something (§9) |

The second means the leg is out: the media connection is released and
`Kelix.Mod.Mcu.leave/2` has run with the reason named, in that order. The script
names the verdict; it frees nothing.

| Outcome | Data | What happened |
|---|---|---|
| `:caller_hung_up` | `%{reason: :bye \| term}` | a BYE, answered; or the dialog went away on its own |
| `:cancelled` | `%{}` | a CANCEL around the answer — the IST sent the 487, the teardown was ours |
| `:mcu_lost` | `%{via: :mcu_event \| :ms_event, bye_answered}` | the media server went away; our BYE is out |
| `:media_timeout` | `%{media, bye_answered}` | every media of this leg went silent (§10, P7/S1); our BYE is out |
| `:idle_timeout` | `%{bye_answered}` | the G3 backstop fired; our BYE is out |
| `:attach_refused` | `%{reason}` | the mix refused the leg at ACK time (`:jsr309_media_already_in_use`) |

`bye_answered: false` is a **key rather than an outcome**: whether a hang-up was
acknowledged is a detail of an ending, not a different ending. And there is no
`:timeout` — `@sbb_timeout :infinity`, because a conference leg lasts as long as
its dialog and `:idle_timeout` is the bound.

**A renegotiation comes back unanswered, because answering it is a policy.** A
deployment may refuse an added media, cap a resolution, or answer with a
different media set than it accepted at the start. The request travels **inside
the outcome** rather than being re-posted: `sbb_return/1` posts one event and
ends the block, so a `send(self(), {:INVITE, …})` on top of it would leave two
events — the host would match its own `{:INVITE, …}` clause first, re-enter the
block, and the block would then find `{:conference, :renegotiation, …}` in its
own mailbox with no clause for it. That is the drift above, rebuilt on purpose.
Most arms never read `req`: the block matched the request in an `on_events` of
its own, which is what stores it in the shared context, so the script's
`reply_invite_with_sdp/2` finds it without being given it.

**Re-entry is correct without the host saying anything.** The leg's phase lives
in the *shared* `appdata` under `:mcu_leg_phase`, never in the block's sandbox —
a sandbox is cleared on every entry, so a block keyed on it would re-run the
ACK-time sequence each time the host came back, and every collaboration message
would re-attach the leg.

| Value | Meaning on entry | Set when |
|---|---|---|
| absent / `:awaiting_ack` | the next ACK is the first one: **attach** | the script answered a 200 and entered; a re-INVITE was handed back |
| `:attach_pending` | **attach now**, before waiting for anything | an UPDATE was handed back (RFC 3311 §5.1: its 200 concludes the offer/answer, no ACK follows) |
| `:in_mix` | an ACK is a retransmission: ignore it | the leg attached |

A `resume:` flag would have done the same job and could be forgotten, which is
why the phase is read rather than declared. Two consequences are accepted rather
than engineered around. A script that **refuses** a re-INVITE (488) leaves the
phase at `:awaiting_ack`; no ACK ever comes — the server transaction absorbs the
ACK of a non-2xx (RFC 3261 §17.2.1) — so nothing re-attaches and the leg keeps
the media it had, which is what a refusal means. A script that refuses an
**UPDATE** costs one redundant `attach`, since the block cannot see which code
the script chose; `attach` re-applies the codecs the leg already has.

**The window** is `bridge`'s ([DESIGN-SBB.md](DESIGN-SBB.md#83-bridge-interrupted-and-re-entered)):
between two entries the call is up and nothing answers it. For a message that is
a log line. For a renegotiation the script owes a response inside timer B, so
that arm answers first and does its bookkeeping after.

**Nothing is left in the mailbox.** Both event families get a floor below the
clauses that carry a policy, so an event the block was never taught about
re-arms the idle deadline instead of accumulating — the failure above, closed by
construction rather than by remembering. The same rule is why a second
`:server_disconnected` is consumed while we hang up: both routes fire for one
dead server, and the clause `on_events` would otherwise inject turns the second
into a shutdown, losing the outcome the teardown exists to report.

**One trap the block inherited and now holds once.** `Kelix.Mod.Mcu.attach/1`
leaves its verdict in `lasterr`, and `goto` aborts the scenario as a failure on
anything but `:ok` — so a transient RPC failure plus a `goto` on the next line
kills a call the reference policy says to keep. The policy: a transient failure
is logged and the call **kept**, because the caller can hear the problem and hang
up, and tearing down a confirmed dialog on an RPC hiccup is worse. Only the
JSR309 mutual exclusion ends the leg, through `:attach_refused`.

**A cooperative shutdown leaves the block and reaches the script.** The block
declares no `{:scenario_ctl, :shutdown, _}` clause and needs none: the injected
clause jumps to `:__shutdown__`, the block has no `on_shutdown`, so the engine
throws and the root re-applies it as the transition the host state would have
written. The script's `on_shutdown` runs with the block unwound — which is where
the graceful ending now lives whole, including the wait for the BYE's 200. One
behaviour changed with it, and it is a fix: a kick, a drain and a node shutdown
are three ways to stop a leg from outside, and the scripts counted the first two
as `:success` and the third as `:aborted`. They are one path with one verdict.

`play.exs` and `record.exs` carry an `in_call` / `in_conference` pair of the same
shape. They are JSR-309 media scripts, not conference legs: this block does not
cover them, and no attempt is made to generalise it into one that would.

---

## 6. Negotiation

Codec arbitration is **delegated to the media server**, per the framework rule
([DESIGN-FRAMEWORK.md](DESIGN-FRAMEWORK.md) §6.1): `StartReceiving` carries the
peer's offer and returns the verdict — the payload types the server accepted with
the exact `fmtp` it will use — and the answer is built from that. The module's
codec configuration was **deleted**, not demoted: a list maintained here in
parallel with the server's real capabilities is a copy, and a copy drifts.

Two boundary cases are part of the contract: an accepted payload type with an
**empty** fmtp is advertised with an `a=rtpmap` and no `a=fmtp`, and an
**absent** one is not advertised at all. A server that returns no verdict (an
older build) falls back to local construction, byte-for-byte identical to the
previous behaviour — the rolling-upgrade path, tested as a first-class case.

The three transport cases are classified explicitly and traced, and an offer
carrying **both** `a=crypto` and `a=fingerprint` is classified DTLS. The answered
feedback set is the **intersection** with the offer: a caller asking for nothing
gets nothing.

**One preference, and it is an order rather than a set.** A conference may name the
video codec it states **first** in its answers (`preferred_video_codec`, defaulting
to the node's). It reorders and never adds: a codec the caller did not offer, or one
the server's verdict left out, cannot be moved anywhere — so it states no
capability, filters nothing, and cannot make a call fail. Both misses are logged per
leg, naming which of the two dropped it, which is the answer a codec list could
never give: "the caller never offered it", or "the media server refused it". One
reading serves both sides of the preference — the order of the answer's rtpmaps, and
the payload type the mixer encodes towards that leg.

This does not contradict the delegation above: the answerer owns the *preference*
(RFC 3264 §6.1), and the server's verdict is a **set** — it says what it accepts,
never in which order.

For H.264, the answer keeps the offer's profile, and the announced level follows
RFC 6184 asymmetry: ours when both sides allow asymmetry, the offer's otherwise —
the case that must keep producing today's answer for a plain SIP handset. The
encoder is bound to the minimum of the two. An offer naming a level above our
decoding capability is answered with our maximum, keeping the payload type and
emitting a warning that names both levels and the participant; the log is the
only evidence that this happened, so its absence is a test failure.

### 6.1 The address a leg announces

A leg's `c=` line is the address the **media server** reported on its first
`StartReceiving`, and it never was a value held here. What the module chooses is
which of the server's addresses that is: an addressing profile, asked for as the
last parameter of `StartReceiving` and `StartSending` (MCU API §6.7 bis). A server
carries up to four — `publicv4`, `publicv6`, `internalv4`, `internalv6` — and
`GetNetworkProfiles` is asked at every connection what it really has. No profile
list is written on this side, for the same reason no codec list is (§6).

**The family comes from the peer, not from the node.** It is read off the offer:
the media's `c=` address, or the first readable `a=candidate` when the offer
blackholes it, which is what a browser does. A node-wide setting would be right
for one leg and wrong for the other on the very topology this exists for — one
conference answering an IPv4 caller in `IN IP4` and an IPv6 caller in `IN IP6`.

Three rules hold the rest:

- **decided once per leg.** Symmetric RTP means one socket in both directions, so
  the server fixes the profile at the first `Start*` and refuses a second,
  different one rather than rebind a media under a port it has already published.
  A renegotiation — a hold spelled `c=IN IP6 ::` names no family — reuses what the
  leg fixed;
- **no fallback.** A family the server declares unavailable fails the call. The
  fallback would answer 200 with an address the caller cannot reach: no media,
  nothing logged, and the peer left to discover it;
- **a server that does not carry the notion is called exactly as before.** No
  `GetNetworkProfiles`, no profile parameter, the server's own default — the same
  rolling-upgrade path the codec verdict has.

Only the public profiles are asked for. Which side of the network a correspondent
sits on is step 6 of [multi-interface.md](multi-interface.md), where a node learns
to classify an address; until then a conference reached through an `internal`
listener announces the public address.

---

## 7. Real-time text

Text is mixed by the MCU's **own text mixer**, which needs no join RPC — the
server wires every participant into it at creation — and no layout: a text leg is
not a mosaic tile. Dropping `text` from a conference's media list turns it off,
and an `m=text` section is then declined with port 0.

**Text over WebSocket** is shipped: a participant that cannot carry T.140 over
RTP gets a WebSocket door instead. One RPC configures the participant's media
connection and returns the full URL, which the adapter publishes in its answer.
A text-less admission — or a media server that cannot host the WebSocket —
**omits** every `m=text` section from the answer rather than echoing it at port 0.

---

## 8. Driving a conference from a script

A conference used to be an administrative object: REST or `kelictl` created it
and the script only ever joined one. That covers the booked-conference case and
nothing else. Three requested flows need the script to own the conference: an
ad-hoc room on a DID nobody booked, a room per caller built from data only the
script has (the `From`, an `auth_db` lookup), and a room that outlives its creator
— or does not.

None of that is expressible through the control API from inside a call: the
script would have to speak HTTP to its own node.

So five functions sit on the module's facade beside the admission ones —
`create_conference/2`, `ensure_conference/3`, `update_conference/2`,
`destroy_conference/1`, `conferences/1` — all routed through
`Kelix.Module.safe_call/3`, so a wedged module is an error the script answers
with, never a hung call. They take a **keyword list with atom keys** rather than
the string-keyed map the control commands receive: a script writes Elixir, not
JSON. The *values* are not asymmetric — the same vocabulary parser reads both.

The module still creates nothing by itself. What this widens is the exposure
already noted: whoever reaches an ad-hoc DID can create a room, not merely join
one.

---

## 9. The collaboration channel

A participant's script needs to tell the *other participants' scripts* something:
a raised hand, a floor-control token, "I am sharing my screen", "mute yourself".

**This is a signalling channel, not text.** The MCU already mixes T.140 between
the legs that negotiated it, in the media server, and that is what a Total
Conversation client displays. This channel is invisible to the mixer and carries
application state between scripts. Conflating them would mean re-implementing,
badly, a mixer that already works.

Two rules define it:

- **the module is a bus, the script owns the wire.** The module does the
  addressing and the fan-out — it is the only thing that knows who is in the
  conference — and delivers to the recipient's *scenario process*. That scenario
  decides what the message becomes: an in-dialog MESSAGE, an INFO, a state
  change, or nothing. The module never writes on the wire and never renders
  anything into the mix. Same principle as asking a scenario to wind down rather
  than tearing its dialog down behind its back.
- **membership is the permission.** The sender is identified by its own
  participant handle and the conference is deduced from it. A script passes no
  conference id, so it cannot address one it is not in: there is no
  cross-conference messaging and no permission model to write, review, or get
  wrong. The check is the one every other participant-level call already does.

A leg receives nothing unless its script **declares that it accepts messages** —
by design, and the first thing to check when a message "does not arrive".

---

## 10. Failure modes

| Situation | Behaviour |
|---|---|
| **RPC failure mid-setup** | every multi-RPC sequence is written as *acquire → on error, release what was acquired*: the participant is deleted, the caller gets a `500`, the row and the quota slot are freed |
| **MCU restart** | detected by the poller or by a transport error on an RPC. The entry is marked `down`, its conferences `stale`, every live participant's scenario is told so it can hang up. When it returns, stale conferences are **recreated** with the same `uid` and a new server id, so their DIDs work again; the calls are gone |
| **Scenario crash** | the module monitors each participant's scenario and runs the same teardown as a clean leave. It also monitors the **creator** of a script-made conference — with a different verdict: a dead participant is always removed, a dead creator takes only an **empty** conference with it |
| **kelixip restart** | the calls go with the node; the declared definitions come back from `conference_file` (§4.1), inserted `stale` and rebuilt by the recovery path above. Either way the media server may hold orphans: at module start, and whenever a control channel comes back, every conference the registry does not know is deleted |

That last sweep keys on the **server-side id**, not on our tag, although the tag
*is* our uid — an older server truncates it, so tag matching would match nothing,
and the consequence would not be an under-collecting sweep but the opposite: run
right after a restart recovery, it would delete every conference that recovery
had just rebuilt. It also **deletes nothing** when the reply cannot be decoded
with confidence: a misparse here destroys live conferences rather than leaking
dead ones. This is safe because a node owns its media servers exclusively.

---

## 11. Observability

Prometheus, through the core's emitter: conference and participant gauges per
MCU, a call counter labelled by result (`joined`, `404`, `486`, `488`, `503`,
`500`), RPC duration and error counters by method, a media-server up gauge, and a
media-timeout counter — a non-zero rate on that last one is the operator's signal
that legs are dying silently.

Logs: one line per conference create/delete and per participant join/leave, a
warning on any server-reported failure, an error on an MCU going down. **Every
line carries the conference uid**, so a call is followable end to end.

`kelictl status` gains an `mcu:` line through the generic module-status hook —
no core change ([DESIGN-KELIXIP.md](DESIGN-KELIXIP.md) §11).

**The event vocabulary is frozen, its transport is not built.** Everything the
module observes is emitted internally as one canonical event, read today by three
consumers (the logger, the metrics emitter, and the owning scenario). Adding
per-conference HTTP callbacks later is a fourth consumer — a transport change,
not a redesign.

---

## 12. Known limitations

| # | Limitation |
|---|---|
| L3 | no trickle ICE |
| L5 | a conference's **calls** do not survive a kelixip restart; its definition does, when `conference_file` is set (§4.1) |
| L6 | no outbound calls (dial-out into a conference) — needs B2BUA legs |
| L7 | a live participant's video profile is not renegotiated when the conference profile changes, and every leg is encoded at the same size and frame rate — **S6** of [mcu_server_evolutions.md](mcu_server_evolutions.md) makes both a consequence of the server's rate control instead of a setting |
| L8 | **anyone who can dial the DID joins**; the perimeter must be protected upstream or by a derived script |
| L9 | event callbacks to an external UI are not delivered — only logged and metered (§11) |
| L10 | with script-driven creation, L8 widens: reaching an ad-hoc DID creates a room |
| L11 | the empty-slot logo cannot be unset on a live conference (no reset RPC) |
| L12 | a recording is not resumed after a media-server restart, and the partial file is left in place — deliberate |
| L13 | recording always captures the default mosaic and sidebar |
| L14 | an unreadable logo is not reported: the server answers OK whatever the picture did |
| L16 | a script that does not declare it accepts messages receives none, by design (§9) |
| L17 | the collaboration channel has no total order across senders and no delivery receipt |
| L18 | a leg stopped from outside always leaves with `:bye`: `shutdown_clause/0` drops the reason on its way to `on_shutdown`, so a kick, a drain and a node shutdown are indistinguishable there. One line in the framework would carry it, and a kicked leg could then `leave(:kick)` (§5.1) |
| L19 | **text over WebSocket has no IPv6 form.** The media server builds the URL it returns as `scheme://host:port`, with no brackets (`multiconf.cpp`): an IPv6 announced address yields `ws://fd00::1:9090/…`, which parses as host `fd00`, port 80. The section is answered with a URL nothing can dial. Audio and video are unaffected, and the fix belongs to the server |

**Media liveness is wired on this side and depends on the server.** The adapter
arms an inactivity watchdog per receiving media at the ACK, and the event
vocabulary declares `participant.media_connected` / `participant.media_timeout`
so a consumer written today needs no change when they start arriving — but the
emission is a media-server increment, specified in
[docs/design/mcu_server_evolutions.md](mcu_server_evolutions.md).
Delegated codec negotiation (§6) landed on this side: the module's codec lists
are gone, and the old configuration keys are accepted with a warning naming
their replacement.

**What this side owes its scripts is delivered**: the three states every
conference script used to copy are the `Mcu.SBB.conference()` block, in the
module that owns them (§5.1).

---

## 13. Invariants

1. Receiving is armed before the answer; sending and mixing wait for the ACK
   (§2, §5).
2. The scenario owns the SIP dialog, the adapter owns the media, the module owns
   the roster — nothing owns two of the three (§3, §9).
3. The media server arbitrates codecs; the module holds no codec list. A
   conference states at most one video codec *preference*, which can only reorder
   what the server accepted (§6).
4. Reads hit ETS, writes go through the GenServer (§4).
5. A conference is pinned to one media server and never migrates (§1, §4).
6. Every log line carries the conference uid (§11).
7. The orphan sweep deletes nothing it is not sure about (§10).
8. Membership is the permission; there is no cross-conference addressing (§9).
9. The family of a leg's media address comes from the offer, and its addressing
   profile is fixed once and never fallen back from (§6.1).
10. A leg's life in the mix is the block's, and there is one copy of it. A script
   states the answer, the renegotiation policy and the verdicts; it holds no
   loop, frees nothing the block released, and reads the leg's phase from the
   shared `appdata` rather than declaring it (§5.1).
