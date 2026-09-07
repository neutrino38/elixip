# DESIGN-FRAMEWORK.md — session, B2BUA and media

The as-built design of the layer between the SIP stack and the language: the
**session layer** (what an application plugs into, and the mixins a scenario
composes), the **B2BUA** primitives, and the **media** layer with its media-server
adapters. It lives in `apps/elixip2/lib/framework/`.

Everything here is implemented and covered by tests. Below it,
[DESIGN-SIPSTACK.md](DESIGN-SIPSTACK.md); above it,
[DESIGN-FSL.md](DESIGN-FSL.md). The user-facing counterparts are
[B2BUA.md](../../B2BUA.md) (writing a B2BUA scenario) and
[CODEC-NEGOTIATION.md](../../CODEC-NEGOTIATION.md) (what the rules do to a real call).

---

## 1. What this layer is for

The stack terminates SIP; the language expresses a flow. Between the two,
something must hold **per-call state that outlives a transaction and spans more
than one dialog**, and offer verbs at the altitude a scenario writes at. That is
the session layer:

```
  scenario (FSL)              states, policy
      │  use SIP.Scenario pulls in ↓
  session mixins               CallUAC · CallUAS · CallInDialog · Media · B2bua
      │  all thread %SIP.Context{}
  session behaviours           Call · Registrar · Options   (what an app implements)
      │  dispatched by ConfigRegistry
  dialog / transaction / transport
```

Two rules shape everything below:

> **A scenario states a call flow; it does not implement one.** A private helper
> in an `.exs` that reads a header, decides a policy or composes a response is a
> **missing macro here**, not a style problem. Fix it in the mixin and every
> scenario gets the fix.

> **What the media server knows about itself, the media server is asked.** It is
> the source of truth for its own capabilities and verdicts — which codecs it
> carries, with which `fmtp`, on which address and port. Elixip drives it; it
> does not model it (§6.1).

---

## 2. The context

`%SIP.Context{}` is the value every session verb takes and returns, and what a
scenario sees as `sip_ctx`. It carries the SIP identity (`username`,
`authusername`, `displayname`, `domain`, `ha1`/`ha1b`, `algorithm`), the current
dialog (`dialogpid`, `ftag`), the media handles (`mediaservermodule`,
`mediaserverpid`), the FSM position (`currentstate`, `laststate` — owned by the
engine), the error slot (`lasterr`, `errorreason`), the parent FSM
(`parent_pid`), and an open `appdata` map for everything else.

Two access paths, deliberately distinct: `ctx_set/2` for the declared struct
properties, `appdata_set/3` for the rest. Anything a mixin needs to remember
between states — the last inbound INVITE and its transaction, the media legs, the
B2BUA state, the sub-FSM handles — lives in `appdata` under a reserved key.

**`lasterr` is the error channel.** A verb that fails writes it and returns the
context; the next transition macro sees it and fails the scenario (see
[DESIGN-FSL.md](DESIGN-FSL.md) §2.3). This is why the mixins can be written as
statements rather than as a chain of `case` expressions, and why a scenario stays
readable.

---

## 3. The session behaviours

An application tells the framework what to do with an **inbound request that
creates a dialog** by implementing a behaviour and registering the module in
`SIP.Session.ConfigRegistry` — an Agent holding one module per concern
(`callprocessing`, `registration`, `options`, `presence`).

| Behaviour | Callback | Returns |
|---|---|---|
| `SIP.Session.Call` | `on_new_call(dialog_pid, invite, trans_pid)` | `{:accept, app_pid}` \| `{:reject, code, reason}` |
| | `on_call_end(dialog_pid, app_pid)` | ignored |
| `SIP.Session.Registrar` | `on_new_registration(dialog_pid, register, trans_pid)` | `{:accept, app_pid}` \| `{:reject, code, reason}` |
| | `on_registration_expired(dialog_pid, app_pid)` | ignored |
| `SIP.Session.Options` | `on_options(req, trans_pid)` | the answer to an out-of-dialog OPTIONS |

The dialog layer calls `ConfigRegistry`'s dispatcher, which applies the
configured module or — with none configured — rejects with `500`. That single
indirection is what lets the same stack be a test tool, a server, or a unit test
without any of them knowing about the others: `elixipp` registers
`Elixip.ScenarioUAS`, kelixip registers its router, an FSL parent scenario
registers `SIP.Scenario.CallDispatcher`.

`{:accept, app_pid}` is the whole contract: the dialog then delivers every event
of that dialog to `app_pid` as `{method, req, trans_pid, dialog_pid}` /
`{code, resp, trans_pid, dialog_pid}` / `{:dialog_terminated, pid, reason}`, and
the application never deals with retransmissions, CSeq or tags.

`SIP.Session.Registrar` also exposes **`check_register/1`**, the policy helper
that bounds what a REGISTER asks for (min/max expires, max contacts) on top of
the message layer's single reading of the lifetimes
([DESIGN-SIPSTACK.md](DESIGN-SIPSTACK.md) §2.3). Deciding *whether* to accept —
challenge, reject, store — is application code, in the scenario or in a kelixip
module, never in the framework.

---

## 4. The mixins

Each is a `use`-able module injecting macros that operate on `var!(sip_ctx)` and
rebind it. `use SIP.Scenario` pulls in `CallUAC`, `Media` and `B2bua`; a server
scenario adds `CallUAS` or `RegisterUAC` explicitly.

| Mixin | What it gives a scenario |
|---|---|
| `SIP.Session.CallUAC` | place a call: `send_INVITE`, `process_invite_reply`, `send_CANCEL`, `send_BYE`, digest replay on a challenge |
| `SIP.Session.CallUAS` | answer one: `reply_invite`, `reply_invite_with_sdp`, `redirect_invite`, `challenge_invite`, and `auto_store/2` |
| `SIP.Session.CallInDialog` | what both sides send inside an established dialog (re-INVITE, UPDATE, MESSAGE, INFO, OPTIONS…) |
| `SIP.Session.RegisterUAC` | register against a proxy: `send_REGISTER`, refresh, un-register |
| `SIP.Session.Media` | `media_connect`, `media_play`, `media_record`, `media_start_echo`, `media_stop`, `media_cleanup_ressources`, and the SDP verbs `get_sdp_offer` / `get_sdp_answer` |
| `SIP.Session.B2bua` | the `b2bua_*` verbs (§5) |
| `SIP.Session.Presence` | placeholder — the behaviour exists, no verbs yet |

**`auto_store/2` is why a UAS scenario has no plumbing.** Called by the
`on_events` instrumentation on every matched event, it stashes an inbound
INVITE/UPDATE and its transaction pid in the context, so `reply_invite(200,
"OK")` needs no argument repeating what just arrived and no state has to carry
the request forward by hand. A **tagged** event (a B2BUA outbound leg) is stored
under leg-qualified keys and never in the inbound slot, so `reply_invite*` keeps
targeting the inbound leg only.

The initial UAC transaction is captured the same way: the dialog layer publishes
`{:onnewdialog, :ok, tid}` to the app process during creation, so it is already
in the mailbox when `start_dialog` returns; the mixin consumes it and stores it,
with a timeout that is only a safety net.

---

## 5. B2BUA

A B2BUA is written as a plain FSL scenario: **one FSM, two dialogs**, both
feeding the same `on_events` mailbox. The framework provides primitives; the
policy stays in the scenario.

### 5.1 Layer split

| Layer | Owns |
|---|---|
| `SIP.Msg.Ops` | `prepare_forwarded_request/2` (strip hop-scoped headers), `forwarded_reply_fields/1` (what a relayed response copies) |
| `SIP.DialogImpl` | the per-dialog **event tag**, plus everything it already does: CSeq, tags, Call-ID, route set, remote target, branches |
| `SIP.Session.B2bua` | leg bookkeeping, request↔response correlation, the `b2bua_*` verbs, automatic teardown |
| the scenario | the relay policy, as states |

### 5.2 Telling the legs apart

Both dialogs deliver the same tuple shapes to the same process. Discriminating on
`dialog_pid` in guards works and is unreadable; FSL needs a **literal** to
pattern-match. So a dialog can be created with `tag: :outbound`, and it then
**wraps** every message it sends:

```elixir
{:outbound, {200, resp, trans_pid, dialog_pid}}
{:outbound, {:dialog_terminated, dialog_pid, reason}}
```

Wrapping (a nested 2-tuple) rather than flattening covers every event kind with
one rule — including `:dialog_terminated` and `:onnewdialog`, whose arity a flat
tag would change — and lets a catch-all `{:outbound, evt}` clause relay whatever
arrives. An untagged dialog behaves exactly as before, so the inbound leg and
every pre-existing scenario are untouched.

The `on_events` instrumentation records the **leg** of the matched event
(mirroring the event type), which is what lets the relay verbs infer their
direction without being told.

### 5.3 Creating the outbound leg

`b2bua_forward(req, peer, media)`, in order:

1. `prepare_forwarded_request/2` — strip `Via`, `Route`, `Record-Route`, `Path`,
   `Contact`, the `From`/`To` tags and **`Call-ID`** (left nil so a fresh one is
   minted: reusing the inbound Call-ID and from-tag would collide with the
   inbound dialog in `Registry.SIPDialog`). Decrement `Max-Forwards`; at zero,
   `lasterr = :too_many_hops` and the scenario answers 483.
2. Apply the peer's R-URI policy (`:peer` rewrites to the branch target,
   `:keep` stamps only the destination fields), then resolve.
3. `SIP.Dialog.start_dialog(…, tag: :outbound)` and consume the tagged
   `{:onnewdialog, :ok, tid}` to capture the initial client transaction, needed
   later for CANCEL and ACK. Deliberately **not** through the ordinary send
   helper, which routes via `sip_ctx.dialogpid` — the *inbound* leg.
4. Store the leg in `appdata[:__b2bua__]` as a `%SIP.B2bua.Leg{}` inside a
   `%SIP.B2bua.State{legs:, pending:}`.

`sip_ctx.dialogpid` keeps pointing at the inbound leg, so `reply_invite*`,
`send_BYE` and every other existing verb keep their meaning.

**One outbound leg per scenario.** A second `b2bua_forward/3` while one is alive
sets `lasterr = :outbound_leg_exists`. Forking does not need more legs — it
happens *below* the leg, inside its dialog (§5.5). Generalizing to N legs
(attended transfer, 3pcc) only widens the `legs` map and the tag atoms.

### 5.4 The peer

`%SIP.B2bua.Peer{}` is the description of *where and how* to call:

| Field | Role |
|---|---|
| `uris` / `provider` | the target(s), fixed or produced by a `SIP.B2bua.TargetProvider` process |
| `ruri` | `:peer` (rewrite the R-URI) or `:keep` |
| `fork` | `:serial` (hunt) or `:parallel` |
| `retry_on` | which final codes advance the hunt (408 included — a dead branch is reported as a synthetic 408) |
| `outbound_proxy`, `use_srv` | next hop and SRV expansion / failover |
| `profile`, `fallback_on` | the offer ladder (§5.8) |

### 5.5 Forking — the kamailio TM model

The initial request goes to several targets as several **client transactions of
the same dialog**: same Call-ID, from-tag and CSeq, one fresh Via branch each
(`SIP.Dialog.fork_branch/3`). The dialog keeps a branch table, adopts the to-tag
of a **2xx only**, CANCELs the losers, and stays alive when a branch returns a
non-2xx final because there may be another target to try.

- **Serial** — `%Peer{fork: :serial}` plus `retry_on`: the session keeps the list
  of untried targets on the leg and arms the next one when a branch fails.
  `b2bua_hunting?/0` tells a scenario a hunt is in progress.
- **Parallel** — the dialog **withholds and aggregates**: it does not report one
  branch's final while another is alive, so the session never has to reason about
  a partial rung. A late 2xx arriving after a winner is ACKed and immediately
  BYEd, as RFC 3261 requires.
- **Dynamic targets** — a `TargetProvider` process yields targets one at a time
  (`b2bua_try_next/0`, a per-attempt ring timeout), which is what a call queue
  needs; `b2bua_cancel_forward/0` interrupts a hunt, with 487 kept out of the
  default `retry_on` so the interruption is not mistaken for a failed branch.
- **Progress events** let a scenario watch a hunt rather than infer it.

Q-group ordering comes from the location service: a registrar's `targets/2`
returns *groups*, which is how "ring these three in parallel, then that one"
is expressed without the scenario computing anything.

### 5.6 Relaying

| Verb | Does |
|---|---|
| `b2bua_forward/1` | relay an in-dialog request to the other leg, direction inferred from the matched event's leg |
| `b2bua_forward_reply/1` | relay a response back, correlated to the request that caused it through the `pending` map |
| `b2bua_reply/3..4` | answer locally on the inbound leg, without touching the outbound one |
| `b2bua_challenge/2..3` | challenge the caller (digest), same shape |
| `b2bua_send_BYE/0` | hang up a leg |
| `b2bua_reoffer_kind/1`, `b2bua_reply_reoffer/1` | classify and answer a re-offer (hold, resume, codec change) |

Correlation is per-leg and per-CSeq, in `pending`: a relayed response must find
*its* request, and two overlapping in-dialog transactions on the same leg are
ordinary.

**A B2BUA rewrites the Contact on both legs, unconditionally**, with the
transport that will actually carry the message. It is a UA on each leg — it adds
no Via and records no route — so the Contact we stamp is the only thing telling
a peer where to send its in-dialog requests. The mechanics are in
[DESIGN-SIPSTACK.md](DESIGN-SIPSTACK.md) §3.7; the rule is stated here because
this is the layer that would be tempted to forward the peer's own Contact
through.

### 5.7 Media modes

| Mode | Behaviour |
|---|---|
| `false` | pure signaling: SDP relayed verbatim, media flows peer-to-peer, nothing to release |
| `{:mediaserver, opts}` | both legs terminate on the media server: relay, transcoding, WebRTC↔RTP gatewaying |
| `{:rtpengine, opts}` | **reserved and refused today** with an explicit error rather than a pretence; it belongs to the `borderline` work |

`{:mediaserver, …}` is **one connection, two endpoints**: one media session
carrying one endpoint per SIP leg, wired by a per-media object that chooses the
codecs of both at once and generates both SDPs. Not two connections joined
afterwards — the server's join primitive takes a single session id. The
choreography on the initial INVITE is: `set_remote_offer(PC_in, offer_A)` →
`get_local_offer(PC_out)` → on the outbound 2xx, `set_remote_answer(PC_out,
answer_B)` → answer the inbound leg with `PC_in`'s local answer. The same
choreography runs on **every re-offer**, which is what makes hold, resume and
codec changes work through the bridge.

`SIP.Session.Media`'s handles became **leg-qualified** for this, with the bare
key kept as an alias for the inbound leg so every pre-B2BUA scenario is
unchanged.

### 5.8 Offer profiles

Only meaningful with a media server: choosing a profile means *generating* an
offer, and without one the offer is the caller's, relayed verbatim — an AVP
caller cannot be turned into a WebRTC one.

The ladder is `webrtc → avpf → avp`, declared per peer
(`profile: :webrtc_if_supported`, `fallback_on:`); a `_required` profile has a
single rung. Three things it took to make it real, none of them obvious from the
specification:

1. **the ladder is walked by the rung, not by the target** — the dialog withholds
   every branch failure until the last branch of the rung falls, so the session
   never sees one target's final;
2. **a fallback branch carries a new CSeq** — two different bodies under one CSeq
   are a merged request (§8.2.2.2) to a UAS whose server transaction is still
   alive, which one ACKed 488 later it is;
3. **another profile means another endpoint** — ports, DTLS material and `m=`
   profiles are fixed at `create_peer_connection`, so the outbound endpoint is
   closed and rebuilt in the same media session.

Two behaviours found by testing rather than by reading: a peer with a ladder
**declares `fork:` to the dialog even with one target** (without it a 488 ends
the dialog instead of the branch, and there is nothing left to arm the next
profile on); and **each new rung of targets restarts the ladder at the top** —
carrying the descent across targets would offer a browser plain AVP because a
desk phone refused WebRTC before it, making a reachable contact unreachable for
being second in the list.

### 5.9 Lifecycle

Teardown is automatic and ordered: the scenario's `finalize` releases the B2BUA
legs **before** the media, because a leg left behind holds a call up at the far
end ([DESIGN-FSL.md](DESIGN-FSL.md) §3.3). A leg dying on its own is not a
scenario failure: the leg-death hook purges it and answers its pending requests,
so the surviving leg gets a final response instead of silence.

The stack-level resilience behaviours (R1–R6) are in
[DESIGN-SIPSTACK.md](DESIGN-SIPSTACK.md) §5.7. The media server as a failure
domain (R8) is §6.7 below.

---

## 6. Media

### 6.1 The rule

> No codec table, no capability list, no port range, no `fmtp` guess written on
> this side of the wire when the server can be asked.

The cost of the copy is measured. A `@default_video_codecs` of `["H264", "VP8"]`
survived while the server had carried AV1 for months: a caller and a callee that
both did AV1 were offered H.264/VP8, the callee declined the video, and the call
died on a 488 with perfectly good audio on both sides. One layer down, the very
call that should have answered the question was a hardcoded array of eight audio
codecs that did not list OPUS, the one every real call uses. Three copies of one
list, none of them true.

When the server *cannot* yet be asked, that is a hole in its API to be closed,
not a licence to declare the answer here.

### 6.2 The behaviour

`MediaServer.Behaviour` is the contract; implementations are interchangeable and
selected by configuration.

| Group | Callbacks |
|---|---|
| Server | `connect/1`, `disconnect/2` |
| Peer connection | `create_peer_connection/3`, `get_local_offer/1`, `set_remote_answer/2`, `set_remote_offer/2`, `add_remote_candidate/2`, `call_answered/1`, `close_peer_connection/1` |
| Bridging | `bridge/3`, `unbridge/2` |
| Player | `create_player/3`, `start_player/1`, `pause_player/1`, `stop_player/1` |
| Recorder | `create_recorder/4`, `start_recorder/1`, `stop_recorder/1` |
| Echo | `create_echo/1`, `stop_echo/1` |

Conceptual mapping to the media server:

```
media server process               server    :: pid()
Endpoint + Transport (ICE/DTLS)     conn_ref  :: reference()
Player   (file → outgoing stream)   player_ref
Recorder (incoming stream → file)   recorder_ref
Echo     (loopback, for testing)    echo_ref
```

Events reach the scenario as `{:ms_event, ref, event}`: connection
(`:ice_connected`, `:ice_failed`, `{:ice_candidate, c}`, `{:media_connected,
media}`, `:media_send_only`, `:closed`), player (`:player_started`,
`:player_ended`, `{:player_error, r}`), recorder (`:recorder_started`,
`{:recorder_stopped, reason}`) and server (`:server_disconnected`).

Teardown order is fixed:
`stop_player`/`stop_recorder`/`stop_echo` → `close_peer_connection` → `disconnect`.

Two implementations: **`MediaServer.Mockup`**, an in-process stub that answers
like a gateway (real offer/answer asymmetry, not an echo of the offer) so call
flows are testable in CI; and **`MediaServer.Mendooze`**, the real adapter.

### 6.3 The Mendooze adapter

Drives the Mendooze MCU over its JSR309 **XML-RPC** control interface. Five
modules, one process shape:

| Module | Role |
|---|---|
| `XmlRpc` | one `POST` per call; envelope decoding (`returnCode`/`returnVal`/`errorMsg`), negative-id check, configurable timeout |
| `Mendooze` (server) | one GenServer per media server: creates the event queue, starts the poller, routes events to the connections, broadcasts `:server_disconnected` |
| `Conn` | one GenServer per peer connection: the whole offer/answer and resource lifecycle |
| `EventPoller` | a chunked HTTP long-poll decoded frame by frame, with a reconnect policy |
| `Sdp` | pure functions: build and parse offers and answers |

Events are correlated by **tag**: every resource is created with a name the
adapter chose, so an event names the object it belongs to and the server needs no
per-object subscription.

The poller is the fragile part by nature — a long-poll over HTTP — so its policy
is explicit configuration rather than a constant: `poller_retry_ms` between
reconnects, `poller_max_failures` consecutive failures before the server is
declared gone. A `:server_disconnected` then reaches every scenario, where the
injected `on_events` clause acts on it ([DESIGN-FSL.md](DESIGN-FSL.md) §2.5).

### 6.4 Delegated negotiation

The server returns, on `EndpointStartReceiving`, **what it actually selected** —
every codec it will carry with the exact `fmtp` it will use. The adapter threads
that through to the SDP builder instead of computing an answer from a local
table. This is §6.1 applied to the one place it is hardest: the answer.

The offer is therefore the menu and the server arbitrates. It also means an
answer stays correct when the server gains a codec, with no change on this side.

### 6.5 WebRTC SDP

The adapter builds and parses browser-shaped SDP on both sides of the
negotiation: DTLS-SRTP with `a=fingerprint`/`a=setup`, ICE credentials and
complete candidates (ICE-lite on the answering side, never on the offering one),
`rtcp-mux`, `UDP/TLS/RTP/SAVPF`, `a=mid`, RTCP feedback.

Three details that each cost a real call:

- **`a=mid` is echoed even on a rejected section.** JSEP asks for it on every
  answer section and a browser matches its transceivers by that name. No SIP
  handset and no gateway offers a mid, so nothing exercised it until a browser
  did.
- **the answer is complete**: parsing returns *every* offered `m=` in order,
  unsupported ones as stubs, and the answerers emit one answer section per offer
  section, declining the rest with a port-0 rejection.
- **`telephone-event` follows the primary codec's clock**, selected per clock
  rate rather than assumed at 8000.

#### Real-time text on a WebRTC leg

A browser cannot carry T.140 on an RTP profile — `RTCPeerConnection` has no
`m=text`. There are two ways round it, and the adapter drives both:

- a **WebSocket** beside the call, which the peer asks for with its own
  `m=text … TCP/WS t140` section and we answer with a URL. We never offer one:
  it is a door, opened when someone knocks;
- a **WebRTC data channel** (RFC 8865): `m=application … UDP/DTLS/SCTP
  webrtc-datachannel`, inside the leg's own DTLS and ICE. It is answered when
  offered, **and it is what our own offers carry by default on a WebRTC leg** —
  `text_transport: :data_channel | :rtp` in the leg's options, defaulting to the
  data channel with DTLS and to RTP without.

Three things that are NOT symmetric with the WebSocket case, each of them a call
that would have failed:

- **a data channel section is declined with port 0, never omitted.** It is in the
  browser's real offer, and libwebrtc counts the answer's `m=` lines against its
  own. The WebSocket omission exists for one deployed client that injects and
  strips its own section;
- **the `m=` line says `application`, the medium is the call's text.** The parsed
  descriptor carries both, and a rejection uses the offered name — renaming it
  loses the section the peer offered;
- **no `a=dcmap`** (RFC 8864) in our offers or answers: declaring the channel in
  the SDP is what tells a peer *not* to open it in band, and the media server
  binds its text channel on the DCEP `OPEN`.

`a=sctp-port` and `a=max-message-size` come from the media server
(`SetupDataChannel`), never from a constant on this side — the same rule as the
announced address.

### 6.6 Media connectivity — when may a scenario send?

`:ice_connected` used to mean "some media flowed", and that is not the same
question as "may I start the player". Playing a file to a NATed Linphone, the
opening keyframe was systematically lost: audio latched at t=11.33 and released
the milestone, the scenario sent its IDR at t=11.75 to the **announced** address,
and the peer's first inbound video packet — which is what makes the server latch
the real one — arrived only at t=12.38, a second later, because the client was
still opening its camera. The video leg had not reached a state; the controller
had emitted a connection-level event out of a per-media fact.

A cross-media fix was evaluated and rejected: NAT mappings are independent
(measured, four legs, four unrelated ports), so there is nothing to infer.

The contract is three events, and one derivation rule. Let **R** be the set of
negotiated media on which *the peer transmits* (normalised to our point of view,
since direction attributes are written from the writer's):

1. **R empty** → nothing will ever come back: emit `:media_send_only` once, after
   sending has started on every media. `:ice_connected` is never emitted.
2. **`:video` ∈ R** → emit `:ice_connected` on `{:media_connected, :video}`.
3. **otherwise** → on the first `{:media_connected, m}`, any `m` ∈ R.

`{:media_connected, media}` is raw and repeats — the server re-arms it on every
receive cycle, so a re-INVITE that reopens the receive plane produces a fresh
one, which is exactly the signal a scenario wanting to know media restarted
needs. `:ice_connected` is **one-shot for the life of the connection**:
re-emitting it on a re-INVITE would restart playback in every scenario that keys
its playing state off it, so a hold/resume would loop the call.

There is deliberately **no implicit timeout**: a scenario that wants to give up
waiting arms its own `after`, where the deadline is visible.

### 6.7 The media server as a failure domain

A media server that dies is not a SIP failure and no SIP timer covers it. The
adapter therefore detects it (§6.3) and turns it into an event every scenario
handles by default, and the B2BUA releases the bridge with the legs. What is
*not* solved is fine-grained partial failure — one endpoint gone while the
session lives — which the server's API does not report today.

### 6.8 Configuration

```elixir
config :elixip2, :mediaserver,
  module: :mockup,           # :mockup | :mendooze | a MediaServer.Behaviour module
  url: "sip:localhost:8080"

config :elixip2, MediaServer.Mendooze,
  xmlrpc_timeout_ms: 2_000,  # a local control RPC answers in ms; longer only blocks the scenario
  rtp_timeout_ms: 10_000,    # inactivity watchdog
  poller_retry_ms: 1_000,
  poller_max_failures: 5,
  video_bandwidth_kbps: 1500,      # what a video leg is encoded at, and the b=AS advertised
                                   #   (an answer takes the min with the offer)
  bitrate_feedback: [:remb, :tmmbr],  # which RTCP bitrate-feedback forms may be answered
  transport_cc: false              # transport-wide-cc on WebRTC video legs, off by default
```

`video_bandwidth_kbps` is one value per node, and on a kelixip node it comes from
`[mediaserver] video_bitrate` — the same key that defaults the mcu module's
([DESIGN-KELIXIP.md](DESIGN-KELIXIP.md) §9). `bitrate_feedback` narrows what is
answered and never widens it: a form absent from the offer is never advertised, and
each answered form has its server-side switch. `transport_cc` negotiates the
transport-wide congestion-control header extension and its `a=rtcp-fb`, which is what
feeds the media server's send-side bandwidth estimator; the negotiation contract is
recorded in
[notes/kelixip-transport-wide-cc.md](notes/kelixip-transport-wide-cc.md).

The `:mediaserver` key is overridable **per scenario** (a `config` block key) and
**per run** (an external-JSON header key); the runner routes it to the
application env. A scenario may still hardcode an adapter with the two-argument
`media_connect(module, url)`, which is what a test does.

### 6.9 Recording a two-leg call

A recorder is attached to an endpoint and writes what that endpoint **receives**.
That single fact settles the shape of call recording:

* **two recorders, two files.** The inbound one holds what the caller sent, the
  outbound one what the callee sent; one recorder records half a conversation.
  A single file holding both sides would need a mixer port to record from, which
  is a conference, not a B2BUA (§5.7 — one session, one endpoint per leg);
* **each records the medias of its own leg.** The three medias of a Total
  Conversation call are recorded only if both legs were negotiated with the
  three. Attaching, and detaching on the way out, follow the leg — not the
  connection, whose media list is the inbound leg's;
* **the media action slot is per leg** (§5.7), so the two recorders coexist and
  a second action on either leg is refused rather than stacked.

Both recorders report through one event shape, so a scenario reads the leg from
the handle (`media_leg_of/1`) rather than from the event. And stopping is not
optional: closing the file is what writes an MP4 index, so `media_stop(leg: :all)`
and the automatic teardown both stop every leg's action before closing anything.

Two limits are the media server's, not ours. The MP4 container carries H.264, so
a call that settles on VP8 or AV1 records audio and text and no video — steering
the negotiation for the recorder's sake is a deployment choice, not a framework
one (§6.1: the server is asked, never modelled). And `echoVideo` must stay off on
a relayed leg: it is what a caller recording a message expects to see, and what
the far end of a call must never receive.

---

## 7. Invariants

1. A scenario states a flow; a helper carrying real logic in an `.exs` is a
   missing macro here (§1).
2. `lasterr` is the error channel; a verb reports through the context, not by
   raising (§2).
3. An application receives dialog events and nothing else — no retransmission,
   no CSeq, no tags (§3).
4. A B2BUA rewrites the Contact on both legs, with the real transport (§5.6).
5. A forwarded request gets a fresh Call-ID; reusing the inbound one collides in
   the dialog registry (§5.3).
6. Forking happens inside a leg's dialog, not by creating legs (§5.5).
7. The media server is asked, never modelled (§6.1, §6.4).
8. `:ice_connected` means "the media that matters flows", once per connection
   (§6.6).
9. Teardown order: legs before media, resources before the connection, the
   connection before the server (§5.9, §6.2).
10. A media resource follows the leg it was attached to, never the connection —
    two legs do not carry the same medias, nor the same endpoint (§6.9).
