# B2BUA P3 — implementation plan (`{:mediaserver, …}` mode)

Turns [b2bua_module.md](b2bua_module.md) §7 into work items, with the media-server
model settled by the source study of the Java gateway
([mediagw_b2bua_jsr309.md](mediagw_b2bua_jsr309.md)).

Two decisions are already made and everything below assumes them:

- **one connection, two endpoints** — a B2BUA call has ONE media-server
  connection (one `MediaSession`, one `MediaServer.Mendooze.Conn` process)
  carrying TWO endpoints, one per SIP leg. Not two connections joined
  afterwards: `EndpointAttachToEndpoint` takes a single session id, and the
  codec negotiation crosses the legs (study §2, §5);
- **transcoding is a policy, per media** — `:force | :avoid | :forbid` for
  audio and for video, `:avoid` by default; text is always bridged, never
  transcoded (study §11).

## 0. The handle: `{conn, leg}`

`MediaServer.conn_ref` becomes:

```elixir
@type conn_ref :: pid() | {conn :: pid(), leg :: atom()}
```

A single-leg connection keeps returning a bare pid, so `MediaServer.Mockup` and
every existing scenario are untouched. A B2BUA connection hands out
`{conn_pid, :inbound}` and `{conn_pid, :outbound}` — one connection, two
endpoints, addressed separately. The framework never inspects the handle; only
the adapter does.

Nothing in `SIP.Session.Media` needs to know: `safe_ms_call/3` already tolerates
a non-pid handle, and every other call site passes the handle straight back to
the adapter.

Two new `MediaServer.Behaviour` callbacks:

```elixir
@callback bridge(a :: conn_ref(), b :: conn_ref(), opts :: keyword()) :: :ok | {:error, term()}
@callback unbridge(a :: conn_ref(), b :: conn_ref()) :: :ok
```

`opts` carries the transcoding policy: `[audio: :avoid, video: :avoid]`.

And one new `create_peer_connection/3` option:

```elixir
bridge_with: conn_ref()   # create this endpoint inside that connection's media session
```

The two are **not** redundant, and the Java gateway is why: `bridge_with` says
*where the endpoint lives*, decided at call setup (`EndpointCreate` in the same
`MediaSession`); `bridge/3` says *wire them now*, which only becomes possible
once both SDPs are negotiated (`buildBridge`, called from `processSDPAnswer`).

## Order of work

R2/R4/R5 are fully testable on `MediaServer.Mockup`; R3 needs a live Medooze
(`MENDOOZE_URL`). So the framework lands first and the adapter second — the
opposite of the order the design lists them in.

| | What | Testable in CI | |
|---|---|---|---|
| **R1** | leg-qualified media handles in `SIP.Session.Media` | yes | ✅ |
| **R2** | `bridge/3` + `unbridge/2` in the behaviour, `MediaServer.Mockup` implementation | yes | ✅ |
| **R2b** | `{:media_timeout, media}` and the derived `:media_lost` | yes | ✅ |
| **R4** | the offer/answer choreography in `SIP.Session.B2bua`, the implicit bridge (R4.1) and the failure semantics (R4.2) | yes | ✅ |
| **R5** | `scenarios/b2bua_media.exs` + its own test | yes | ✅ |
| **R3** | `MediaServer.Mendooze.Conn`: two endpoints, cross-leg negotiation, the bridge | E2E, gated | |
| **R6** | §14.6 — the media server as a failure domain | partly | scenario clauses ✅, framework default open |

**State (2026-08-09): the framework half is done and green.** The media mode
works end to end on `MediaServer.Mockup` — 105 tests across the B2BUA and media
suites — and `MediaServer.Mendooze.bridge/3` refuses plainly until R3 gives it
two endpoints in one session. What remains: R3, and the framework default of R6.

Two things moved during the implementation and are worth knowing before reading
the sections above:

- the media failure reason is read through **`b2bua_media_error/0`**, not
  `lasterr` (see R4.2);
- `b2bua_media.exs` still relays every re-INVITE, because `b2bua_reoffer_kind/1`
  (R4.1b) is not built. The table in R4.1b is the target, not the current
  behaviour.

---

## R1 — Leg-qualified media handles

**File**: `apps/elixip2/lib/framework/SIPSessionMedia.ex`.

Today the mixin is single-slot: `:mediapeerconnectionid`, `:mediaactionid`,
`:mediaaction` in the context appdata. They become leg-scoped, with the bare key
kept as the `:inbound` alias so that **no existing scenario or macro changes**:

```elixir
defp pc_key(:inbound), do: :mediapeerconnectionid
defp pc_key(leg),      do: {:mediapeerconnectionid, leg}
```

Same for the action keys. The leg is an option, defaulting to `:inbound`:

| function | today | after |
|---|---|---|
| `get_sdp_offer/3` | `(ctx, webrtc, medias)` | `get_sdp_offer/4` — `(ctx, webrtc, medias, opts)`, `opts[:leg]` |
| `get_sdp_answer/3` | `(ctx, offer, opts)` | unchanged arity, `opts[:leg]` |
| `process_sdp_answer/2` | `(ctx, answer)` | `process_sdp_answer/3`, third arg the leg |
| `start_echo/1`, `start_player/3`, `start_recorder/4`, `stop_media/1` | — | an `opts[:leg]` |
| `media_cleanup_ressources/1` | one connection | **every** leg's connection, then the server |

`ensure_peer_connection/3` gains the leg and the `:bridge_with` option; it is the
one place that decides whether an endpoint is created standalone or inside an
existing connection.

The DSL macros keep their current arity and gain an optional keyword list, so
`media_play("f.mp4", leg: :outbound)` reads the way the rest of the DSL does.

**Tests**: extend `media_test.exs` (or the closest existing suite) with two legs
on the Mockup — handles are distinct, cleanup releases both, and the bare key
still addresses the inbound one.

## R2 — `bridge/3` and `unbridge/2`

**Files**: `lib/framework/MediaServer.ex`, `lib/framework/MediaServerMockup.ex`.

Behaviour: the two callbacks and the `conn_ref` type of §0, documented with the
teardown order (`unbridge` → `close_peer_connection` → `disconnect`).

`MediaServer.Mockup` implements a real bridge, not a stub: each `Mockup.Conn`
already owns a UDP socket and learns its peer's address from the first packet
received (`handle_info({:udp, …})`). `bridge/3` sets a `peer_conn` on each side;
an incoming packet is then forwarded to the other connection's remote address
instead of being echoed. That makes the CI test of R5 an actual media path —
two mock endpoints, packets crossing — rather than an assertion that a function
was called.

`bridge_with:` is accepted and ignored by the Mockup: a mock connection has no
media session to share.

The transcoding policy is validated here (`:force | :avoid | :forbid` per media,
anything else is an error) so a scenario typo fails at the DSL rather than
inside the adapter.

**Tests**: `media_bridge_test.exs` — two mock connections, `bridge/3`, a datagram
sent into one comes out of the other; `unbridge/2` stops it; a bad policy value
is refused.

## R4 — The choreography in `SIP.Session.B2bua`

**File**: `lib/framework/SIPSessionB2bua.ex`.

`do_create_leg/5` currently refuses anything but `media: false`
(`{:b2bua, :media_mode_not_implemented, media}`). It accepts:

```elixir
{:mediaserver,
   inbound:   [webrtc: :if_offered, media: :audio_video],
   outbound:  [webrtc: :no, media: :audio_video],
   transcode: [audio: :avoid, video: :avoid]}
```

**On `b2bua_forward(req, peer, {:mediaserver, opts})`** — the caller's offer is
in `req`:

1. `set_remote_offer(PC_in, offer_A)` — creates the inbound endpoint if needed
   and yields **the caller's answer**, which is *kept*, not sent: the caller is
   not answered until the callee is;
2. `create_peer_connection(server, self(), outbound_opts ++ [bridge_with: PC_in])`
   then `get_local_offer(PC_out)` — the body of the forwarded INVITE. This is
   where the profile conversion happens (WebRTC ↔ plain RTP);
3. the forwarded request's body is replaced by that offer, and the leg is created
   as it is today.

**On the outbound 2xx**, inside `do_relay_reply/2` when the leg is in
`:mediaserver` mode:

1. `set_remote_answer(PC_out, answer_B)`;
2. `bridge(PC_in, PC_out, transcode_policy)` — the `buildBridge` moment;
3. the relayed 200's body becomes **PC_in's local answer** (step 1 above), not
   the callee's SDP.

A failure at any of these three answers the caller `488` (or `500` for a
media-server error) instead of relaying the 200, and hangs up the callee.

**On an outbound 18x carrying SDP**: §7.4 settles it — with a media server the
caller's answer comes from the media server and never changes, so an early-media
SDP from the callee is a *media* event, not something to relay. The body is
stripped and the provisional relayed without it. A hunt therefore stays open,
which is the whole point of §7.4's "early media and forking together require a
media server".

**On ACK**: nothing. The Java gateway re-arms the direction on ACK because its
`startSending`/`startReceiving` are idempotent guards; here the bridge is built
at answer time and there is nothing left to arm. Worth a comment, not code.

**Teardown**: `release_legs/1` is unchanged; the media is released after it by
`Runner.finalize/4`, and R1 makes that release both legs.

**Tests**: extend `b2bua_session_test.exs` — the three-step choreography with a
mock media server, the body substitution in both directions, the 18x strip, and
the failure paths.

### R4.1 — The scenario does not build the bridge

**A scenario never calls a bridge primitive in the normal case.** The bridge is
built by `b2bua_forward_reply/1` itself, when it relays the callee's 2xx on a
`{:mediaserver, …}` leg — the only moment at which both SDPs exist, and exactly
where the Java gateway builds it (`processSDPAnswer` → `buildBridge`). So the
media scenario writes the same line as the signalling one:

```elixir
{:outbound, {200, resp, _trans, _dlg}} ->
  b2bua_forward_reply(resp)          # ← sets the remote answer, bridges, and
  goto(wait_ack, "200 OK relayed")   #   substitutes the body. Same line as b2bua_basic.
```

That is what keeps §12's claim true: `b2bua_media.exs` is the *same FSM* as
`b2bua_basic.exs` plus `media_connect()` and one changed argument. If building
the bridge were the scenario's job, every relay policy would have to remember to
do it, and the one that forgot would relay a 200 whose SDP promises a media path
nobody wired.

Explicit primitives exist for the cases where the policy must take over, and are
**idempotent** with the automatic build:

| macro | for |
|---|---|
| `b2bua_bridge/0..1` | bridging early: the callee's 183 carries an answer and the scenario wants its media through during ringing. Optional opts override the transcoding policy for this call |
| `b2bua_unbridge/0` | taking the media path down without ending the call — putting the caller on hold to play an announcement, re-pointing a hunt |

`b2bua_forward_reply/1` bridges only if `b2bua_bridge/0..1` has not already done
it, so a scenario that bridged on the 183 relays the 200 without a second attach.

### R4.1b — Re-INVITE and UPDATE: four cases, and where they diverge

A re-INVITE or an UPDATE on an established call carries four different
intentions, and the mode decides which of them cross:

| what changed in the offer | signalling (`false`) | `{:mediaserver, …}` |
|---|---|---|
| **hold / retrieve** (`a=sendonly`, `a=inactive`, and back) | relay | **relay** — the far end must stop sending, or play its own hold |
| **a media added or withdrawn** (a new `m=`, or one set to port 0) | relay | **relay** — only the far end can offer or drop it |
| **a changed address** (`c=`, port, ICE restart, new DTLS fingerprint) | relay | **local** — the peer moved, *our* endpoint did not, and the far end's media path is unchanged |
| **a session-timer refresh** (RFC 4028, usually no SDP) | relay | **local** — each leg has its own timer, and we are a UA on both |

The signalling column is one rule, not four: the SDP belongs to the endpoints, so
every one of these is a conversation between them that the B2BUA only carries.
Even the timer refresh crosses, and for a reason worth writing down — answering
it locally would mean putting **our own** offer in the 200 (RFC 3261 §14.2, an
offerless re-INVITE is answered with an offer), and a signalling B2BUA has no
media of its own to offer.

The media column needs the framework to *read* the re-offer, which is message
interpretation and therefore belongs in exactly one place (CLAUDE.md, Message
Layer). A reader macro over the previous offer stored on that leg:

```elixir
b2bua_reoffer_kind(req)   # => :hold | :resume | :media_change | :address_change | :no_sdp
```

`:hold`/`:resume`/`:media_change` are *propagated* — relayed as a re-INVITE on
the other leg, with our own offer substituted the way the initial INVITE was
(R4). `:address_change` and `:no_sdp` are *local*: the media server is fed the
new remote description on that leg only, and the 200 carries its answer. The
scenario writes the policy, the framework does the reading:

```elixir
{m, req, _trans, _dlg} when m in [:INVITE, :UPDATE] ->
  case b2bua_reoffer_kind(req) do
    kind when kind in [:address_change, :no_sdp] ->
      b2bua_reply_reoffer(req)                 # answered here, far end undisturbed
      goto(loop, "re-offer handled locally (#{kind})")

    kind ->
      b2bua_forward(req)                       # the far end has to know
      goto(loop, "re-offer relayed (#{kind})")
  end
```

This is the Java gateway's `propagate` flag, made explicit and inverted in its
default. `MediaGwSipServlet` decides it from the SIP session state and defaults a
re-INVITE on an established call to **local** (`updateLocally = true`), which is
why `processSDP` has to refuse a media addition outright — "we cannot add or
enable a new media" (`MediaTranscodingSession.java:427-435`). Reading the offer
instead of the session state is what lets the first two rows work.

**Not in P3**: full RFC 4028 support (negotiating `Session-Expires`/`Min-SE` per
leg, being the refresher, sending our own refreshes). Detecting an offerless
re-INVITE and answering it locally is enough to keep a session timer from
crossing; owning the timer is a separate piece of work.

### R4.1c — The ACK of a re-INVITE (found while exploring, fixed 2026-08-09)

Not a media item — it broke the *signalling* B2BUA, and it had to be fixed
before any of the above could be relayed at all.

RFC 3261 §13.2.2.4 makes the ACK of a 2xx a transaction of its own, so every
re-INVITE that crosses owes one back on the transaction *it* opened.
`correlated_invite/2` posted it on `%Leg{initial_trans}` — the initial INVITE's
transaction, done minutes earlier. Worse than losing the ACK: the relay returned
`{:error, :nosuchtransaction}` and the scenario died on it. Both reference
scenarios also excluded ACK from their relay (`m != :ACK`), so it never got that
far anyway.

Fixed by `%State{last_invite}`, keyed by the leg an INVITE was **sent to**, and
symmetric — a re-INVITE from the *callee* is relayed onto the inbound leg where
we are the UAC for it, so the callee's ACK now has an inbound client transaction
to act on. The previous code returned `nil` there unconditionally, which made
callee-originated re-INVITEs unacknowledgeable by construction.

### R4.1d — A relayed request whose far end never answers

Verified rather than built: the P2d R1 machinery already carries it end to end.
The outbound client transaction's timer F fires → `SIP.DialogImpl` converts it
into a synthetic 408 (`timeout_response/1`, RFC 3261 §17.1.1.2 / §8.1.3.1) →
delivered as `{:outbound, {408, resp, trans_pid, dlg}}` → the scenario relays it
like any other final → `pending[trans_pid]` finds the request it answers →
`SIP.Dialog.reply/5` puts the 408 on the leg the request came from, on **that
request**, not on the call. The call survives; one dead in-dialog request is not
a hangup.

Now covered by a test that shortens `:sip_timer_T1` instead of waiting 32 s. The
mirror direction (a callee-originated request the caller never answers) uses the
same correlation with `orig_leg: :outbound`; testing it needs two real
transports, so it belongs in `b2bua_three_party_test.exs`.

### R4.2 — Failure semantics

Three failure points, and they are not the same failure.

**(a) The caller's offer cannot be used** — `set_remote_offer(PC_in, offer_A)`
fails (no common codec, malformed SDP, a WebRTC offer to a leg configured
`webrtc: :no`). Nothing has been sent anywhere. No outbound leg is created;
`lasterr` is `{:b2bua, :media_setup_failed, {:inbound, reason}}` and the
reference scenario answers **488 Not Acceptable Here** — the caller asked for
media we cannot carry, and that is a statement about their offer.

**(b) Our own offer cannot be built** — `create_peer_connection(bridge_with:)` or
`get_local_offer(PC_out)` fails. Also before anything left the box, but it is our
fault, not the caller's: `{:b2bua, :media_setup_failed, {:outbound, reason}}` and
**500 Server Internal Error**.

**(c) The bridge cannot be built** — `set_remote_answer(PC_out, answer_B)` or
`bridge/3` fails (the callee's answer is unusable, no common codec under
`transcode: :forbid`, an RPC error). This one is different in kind, because **the
callee has already answered 200 and believes the call is up**. Three things are
owed, in this order:

1. **ACK the 2xx, then BYE that leg** — RFC 3261 §13.2.2.4: a 2xx must be
   acknowledged, and a dialog that was established is ended with a BYE, not by
   dropping it. The framework does this itself rather than leaving it to the
   scenario: it is an obligation, not a policy, and a scenario that forgot it
   would leave the callee retransmitting its 200 into a dialog nobody ends;
2. **reset the outbound endpoint** — it was keyed with the failed answer's
   security material and rtpMap. `restart_leg(:outbound)` (the Java gateway's
   `restartLeg`) stops sending on it and forgets the remote state, **keeping the
   local offer**: the offer we make does not depend on the callee, so the next
   branch of the hunt reuses it unchanged. Without this, attempt N+1 inherits
   attempt N's negotiation;
3. **report it as a branch failure, not as the call's answer.** It is treated
   exactly like a `488` from that target: `b2bua_hunting?/0` stays true if the
   peer has targets left, and the next one is tried. A callee whose media we
   cannot bridge *is* "this device did not work, try the next" — which is the
   whole value of a hunt.

The reason is readable through **`b2bua_media_error/0`**, not through `lasterr`
— a distinction that only became obvious in the writing. The relay that follows
a media failure *succeeds*: the caller gets their 488. So `lasterr`, which is the
outcome of the last operation, says `:ok`, truthfully, and would have overwritten
anything put there. Why the call went that way is a different question and gets a
reader of its own. When the hunt is exhausted the caller gets the code the
scenario chooses; the reference scenario answers **488**.

**Tests** (Mockup): a mock connection can be told to refuse — an
`ice_delay_ms`-style option makes `set_remote_offer`/`set_remote_answer`/`bridge`
return `{:error, reason}` on demand — which makes all three paths CI-testable,
including "the 200 was ACKed and BYEd and the hunt moved on".

## R2b — `:media_lost`: a leg that went silent on every media

The question this answers: *how does a scenario catch an RTP timeout on the
**whole** outbound leg?*

The raw material is already there. `Conn` arms `EndpointStartRTPTimeout` per
media, and **only for the medias the peer said it would send**
(`peer_sends?(desc)`; the others get a timeout of 0, i.e. disabled). That set is
the same **R** the connectivity design already tracks as `recv_medias`
([media-connectivity.md](media-connectivity.md) §4). The server's
`endpoint_disconnected` event names the media that fell silent.

What is missing is that the adapter throws the media away:

```elixir
# MediaServerMendoozeConn.ex:430 — today
send(state.event_sink, {:ms_event, self(), :media_timeout})
```

So the shape mirrors `{:media_connected, media}` → `:ice_connected` exactly, in
reverse:

| event | meaning | cardinality |
|---|---|---|
| `{:media_timeout, media}` | the watchdog fired for that one media | repeats — the server re-arms on each `StartReceiving` |
| `:media_lost` | **every** media of R has timed out: the peer stopped sending, full stop | once per loss episode; the latch clears when any media reconnects |

The derivation is exact rather than heuristic, because the timeout is armed on
precisely the medias of R: accumulate the timed-out medias in a set and emit
`:media_lost` when it covers R. A peer that negotiated video and only stopped its
video produces `{:media_timeout, :video}` and no `:media_lost` — which is the
distinction a B2BUA needs, since one dead media is a media problem and every dead
media is a dead call.

With the leg-qualified handles of R3b the event ref *is* the leg, so the scenario
clause is the whole answer to the question:

```elixir
{:ms_event, {_conn, :outbound}, :media_lost} ->
  b2bua_send_BYE()
  b2bua_reply(last_uas_req(), 200, "OK")      # or a BYE if the caller is answered
  scenario_failure("callee stopped sending media")
```

This is elixip's version of the Java gateway's `isActive()` — which polls
`EndpointGetStatistics` and compares `totalRecvBytes` on every application-session
expiry (study §8). The server-side watchdog gives the same fact without the
polling, and per media rather than for the endpoint as a whole.

`MediaServer.Mockup` grows the same two events (drive them from a test message)
so R5's scenario clause is covered in CI.

**Backward compatibility**: `:media_timeout` bare becomes `{:media_timeout,
media}`. The only consumer of the bare form is `MediaServer`'s own type; the MCU
module's `:media_timeout` is a different event on a different path
(`Kelix.Mod.Mcu.EventQueue`) and is untouched.

## R5 — `scenarios/b2bua_media.exs`

A **new file**, never an edit of `b2bua_basic.exs` — the design says why (§12):
`b2bua_basic.exs` is the acceptance test for "a complete B2BUA in ~60 lines" and
teaching it about media costs it exactly the property it exists to demonstrate.
The two then read as a pair: same call, same states, the difference being
precisely what a media server costs.

Same FSM as `b2bua_basic.exs`, plus:

- `media_connect()` in `initial_state`;
- `b2bua_forward(req, ctx_get(:peer), {:mediaserver, …})` instead of `false`;
- the §14.6 clause of R6;
- `media_cleanup_ressources()` on the way out.

**Test**: `apps/elixip2/test/b2bua_media_scenario_test.exs`, alongside
`b2bua_scenario_test.exs` rather than inside it — same harness (stub inbound
dialog, UDP mockup peer, its own named mockup instance), with the Mockup media
server and an assertion that a datagram crosses.

## R3 — `MediaServer.Mendooze.Conn`: two endpoints

The big one, and the only one CI cannot cover. Split in three so each step is
reviewable and the mono-leg path is never in doubt:

### R3a — extract the per-leg state (pure refactor)

`Conn`'s state is flat today: `endpoint_id`, `medias`, `local_ports`,
`local_crypto`, `local_ice`, `local_sdes`, `ws_urls`, `proposed_recv`,
`accepted`, `connected`, `recv_medias`, `ice_notified` all describe **one
endpoint**. They move into a `%Conn.Leg{}` struct — the transposition of the
Java `Leg` — and the state becomes:

```elixir
%{
  # the connection: one MediaSession
  server: pid, base_url: …, sess_id: …, sess_tag: …, event_sink: pid,
  legs: %{inbound: %Conn.Leg{}},          # :outbound appears in R3b
  bridges: %{},                            # {media, role} => %Conn.Bridge{}  (R3c)
  players: %{}, recorders: %{}, echo: nil
}
```

Every helper that touches per-leg fields takes the leg. No behaviour change, no
new RPC: the mono-leg case is today's code with `leg = :inbound`. The suite must
be green before R3b starts — this is the step that protects the UAC, UAS and MCU
paths.

### R3b — the second endpoint

- `create_peer_connection(server, sink, bridge_with: {conn, :inbound})` routes to
  the owning `Conn`, which does `EndpointCreate(sess_id, "<tag>-out", …)` and
  returns `{conn, :outbound}`;
- **event demultiplexing**: server events are routed to a `Conn` by session tag
  (`MediaServer.Mendooze.handle_info/2`), and both endpoints now share one. The
  `Conn` demuxes by `endpointId`, which endpoint events carry (study §2). Events
  are re-emitted to the sink tagged with the leg's handle, so a scenario tells
  `{:ms_event, {conn, :inbound}, :ice_connected}` from the outbound one;
- teardown deletes both endpoints before the session.

### R3c — the bridge and the cross-leg negotiation

The part the study exists for. Per `(media, role)`:

- **codec selection across the legs** (study §5): the `snd` rtpMap of a leg is
  built from what the *other* leg can receive, and one encoder is chosen for
  both at once. This is where the R2 policy is applied:

  | policy | behaviour |
  |---|---|
  | `:force` | always transcode; each leg answered with the first codec of its own list |
  | `:avoid` | a codec both legs support → direct attach; none → transcode |
  | `:forbid` | a codec both legs support → direct attach; none → fail the call (488) |

  and, in every mode, no usable audio codec at all fails the call;
- **direct attach**: `EndpointAttachToEndpoint` in both directions plus
  `EndpointSetRTPProperties(…, %{"useOriSeqNum" => "1"})` on both endpoints;
- **transcoding**: `Video|AudioTranscoderCreate` + `EndpointAttachTo…Transcoder`
  + `…TranscoderAttachToEndpoint` + `…TranscoderSetCodec`, one chain per
  direction;
- **direction control** (study §4): starting a direction touches both endpoints,
  and *SDP arriving on a leg unblocks the direction that sends toward that leg*.
  `EndpointStartReceiving` allocates and returns the local port, so it must run
  before that leg's SDP is generated — which is already how `Conn` works;
- `unbridge`: `EndpointDettach` on both, plus the transcoder deletes.

Text keeps the Java behaviour verbatim: always attached, never transcoded,
including the WS/WSS transport switch `Conn` already implements
(`ConfigureMediaConnection`).

**Tests**: an E2E gated on `MENDOOZE_URL`, in the shape of the existing Mendooze
E2E — a call bridged end to end, one with a forced transcode, one with
`:forbid` and no common codec expecting the 488.

## R6 — §14.6: the media server as a failure domain

Two parts, and only the first is P3's:

1. **the scenario clause** — `b2bua_media.exs` handles
   `{:ms_event, _, :server_disconnected}` by hanging up both legs (BYE the
   callee, 500 the caller if it is not yet answered) and calling
   `media_cleanup_ressources/0`, never `media_stop/0`: the server is already
   gone, and only the former skips dead handles. Six reference scenarios already
   carry this clause by hand (§14.6); this is the seventh;
2. **the framework default** (R8 proper) — a scenario that does *not* handle it
   gets a cooperative shutdown. Sketched in §14.6, not P3: it needs the media
   mixin to monitor the server pid, the reaction to be idempotent (the MCU case
   receives the fact twice), and the `@call_timeout` of `Conn` to become
   configurable while staying a multiple of `xmlrpc_timeout_ms`.

What P3 *does* settle is the scope question §14.6 left open: with one media
session per call, a dead media server takes **the call** down, not one leg. The
reaction belongs at the scenario level, which is where the clause above puts it.

## What this plan does not do

- **parallel forking** (P4) — a hunt still re-points one outbound endpoint;
- **`{:rtpengine, …}`** — deferred to the `borderline` work, still refused with
  `{:b2bua, :media_mode_not_implemented, …}`;
- **the `_media` siblings of use cases (b), (c) and (d)** (§12) — they follow
  once (a) exists, each as its own file, never as a flag;
- **offer-profile fallback on 488** (§7.5) — the Java `tryOtherMode` shows the
  two-rung version; the full ladder needs `fork_branch/2` to carry a replacement
  offer, which is P4's seam.
