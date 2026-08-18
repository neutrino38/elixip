# Media-server evolutions for the MCU API (Mendooze)

**Status: server-side work, not implemented.** Extracted from the module design
when it was consolidated into [`DESIGN-MCU.md`](DESIGN-MCU.md), which keeps
only what is built. Everything below is a change to make in the **mediaserver**
repository (the Mendooze fork), not in elixip.

The controller side is ready for all of it: the adapter arms the watchdog per
receiving media, and the event vocabulary already declares
`participant.media_connected` / `participant.media_timeout`, so a consumer
written today needs no change when the server starts emitting them.

## What is left

Changes to make in the media server (`../mediaserver`, the Mendooze fork) so the
MCU API reaches feature parity with JSR-309 on the point that still hurts: **no
media watchdog** (S1). The "media established" notification (S2) falls out of the
same wiring, for free.

The other items of the original plan have landed: **S3** delegated codec
negotiation, **S4** the server announcing its own address, **S5** text over
WebSocket. The sequencing section is kept for its risk table.

**Why this is small.** The mechanisms already exist in **shared** server code and
are already exercised by the JSR-309 path; what is missing is the MCU-side
wiring and the RPC/event surface:

| Mechanism | Where it already lives | Used today by |
|---|---|---|
| RTP inactivity watchdog | `RTPSession::ArmRTPTimeout` + `Listener::onRTPTimeout` (`mcu/src/rtpsession.cpp`, `mcu/include/rtpsession.h`) | JSR-309 (`MediaSession::EndpointStartRTPTimeout`) |
| "first RTP packet received" | `RTPSession::Listener::onRTPPacketReceived` + `ArmRTPReceivedNotification` | JSR-309 (`EndpointConnectedEvent`) |
| Codec negotiation + local fmtp derivation | `CodecNegotiator::Negotiate` (**libmedikit**, `third_party/fontventa/libmedikit/medkit/negotiator.h`) | JSR-309 (`Endpoint::Port::NegotiateReceiving`) |
| `codec.*` property intake | `VideoStream::SetRTPProperties` / `AudioStream::SetRTPProperties` (`mcu/src/videostream.cpp:199`, `audiostream.cpp:127`) | **the MCU path itself** — the JSR-309 code documents that it copied this convention |

Both listener hooks are **non-pure** virtuals, so `RTPParticipant` can implement
them without touching JSR-309 or any other `RTPSession::Listener`.

> **Wire contract.** `MCU::Events` codes (`mcu/include/mcu.h`) are shared with
> every controller — mcuGold included. New types are **appended**; existing codes
> are never renumbered nor reused. Same discipline as `JSR309Event::Events`.

## S1 — RTP inactivity watchdog for MCU participants (P7)

Closes **L1 (G3)**: today a participant whose RTP stops stays in the mix, holds
its quota slot and keeps a mosaic tile, until the script's idle timeout — hours.

**New RPC**, mirroring `EndpointStartRTPTimeout`:

| Method | Params | Returns |
|---|---|---|
| `StartRTPTimeout` | `(i confId, i partId, i media, i timeoutMs[, i role])` | `[]` |

`timeoutMs > 0` (re)configures the threshold **and arms** the watchdog, with the
chronometer starting *now*; `0` disarms. Arming from the answer instant (not from
participant creation) is what makes "answered but no media ever arrived"
detectable while never surveilling the ringing phase — the same reasoning as the
JSR-309 flow, where the call is armed after the SDP answer is sent.

**New event**, appended to `MCU::Events`:

| Type | Name | Tuple |
|---|---|---|
| `3` | `ParticipantMediaTimeout` | `(i type, i confId, s tag, i partId, i media, i role)` |

Emitted **once** per active→inactive transition, following the existing FPU
path: `RTPParticipant::onRTPTimeout` (new override) → new
`MultiConf::Listener::onParticipantMediaTimeout` → `MCU::onParticipantMediaTimeout`
→ `eventMngr->AddEvent(queueId, new ParticipantMediaTimeoutEvent(…))`, next to
`PlayerRequestFPUEvent` in `mcu/include/mcu.h`.

**kelixip side.** The adapter arms the watchdog per media **at the ACK**, once
`start_sending_all/1` has put the leg in the mix — the first moment the 200 OK is
known to have gone out. That is what makes "answered but no media ever arrived"
detectable while never surveilling the ringing phase; a caller that never ACKs is
the script's idle timeout to catch. It **never arms text** (T.140 is legitimately
silent between keystrokes) and treats a failed arm as non-fatal but logged: a leg
that carries media is worth more than a leg that is monitored, and a fleet where
nothing is ever armed must not pass for working. `rtp_timeout_ms` travels on the
**conference** (from `[module.mcu]`, default `10000`, `0` disables), like `video`,
so the adapter reads it off the leg it is setting up rather than from a script knob.

**Hold disarms, and the criterion is not "hold".** The watchdog watches *our
reception*, so what matters is whether the **peer will send**: `a=recvonly`,
`a=inactive` or `c=0.0.0.0` (RFC 3264 §8.4, the legacy hold every old handset uses)
⇒ disarm that media. A caller holding with `a=sendonly` keeps sending music-on-hold,
so its RTP never stops and its watchdog stays armed — treating that as a hold would
have disarmed a leg that is perfectly observable. A **renegotiation** applies this at
the *answer* rather than waiting for an ACK: the dialog is already established, so
there is no ringing phase to avoid surveilling, and the ACK path returns early on an
attached leg — waiting for it would leave a resumed media unwatched for good.

Without this half, P7 hangs up held calls: ten seconds of `rtp_timeout_ms` is an
ordinary consultation transfer.

**One dead media is not a dead leg — the AND (decided 2026-08-05).** The server
reports one media at a time; the *controller* decides what constitutes a dead leg,
and it only tells the scenario once **every watched media is silent** (watched = the
medias this leg negotiated, minus text). Per-media events are still emitted for the
operator view: "video died, audio alive" is the most common complaint about a video
call and this event is its only witness, so suppressing it would be a real loss.
The AND's state is a `silent` map on the participant row — event 3 sets a media's
flag, **event 4 clears it**, which is what makes a media that comes back forgettable.
Without that clearing, a leg that flapped once would be reaped the next time any
*other* media hiccupped.

The decision to do this in the controller rather than the media server rests on three
things: whoever ANDs needs that state machine anyway (the server would build the same
one), the reset signal is already on the wire, and "how many dead medias make a dead
leg" is policy — while a server-side AND would also have forced a wire-contract
question, since the `media` field of an "everything is silent" event has no honest
value. An **empty** watched set (a timeout reaching a leg whose ACK was never
processed) satisfies the AND on the first event, deliberately: one dead media is then
all the evidence there will ever be.

`mcu.exs` gains `{:mcu_event, :media_timeout, media}` → BYE + `leave(:media_timeout)`,
in **both** the `in_call` and `in_conference` states, plus a 3-tuple catch-all — its
existing catch-all only matched 2-tuples, so these messages would have gone
unhandled. New event `participant.media_timeout` in the §11.1 vocabulary (already
declared), and `silent` is exposable in `participant.show` so an operator sees *which*
media died rather than a boolean.

## S2 — "media established" event (P7, same wiring)

Closes **L2 (G4)** at no extra cost, since `onRTPPacketReceived` is the sibling
hook of `onRTPTimeout` on the same listener:

| Type | Name | Tuple |
|---|---|---|
| `4` | `ParticipantMediaConnected` | `(i type, i confId, s tag, i partId, i media, i role)` |

Emitted once per media **per reception cycle** — the first validated RTP/SRTP
packet, which for a secure leg intrinsically proves the DTLS handshake completed
— and re-armed by a `StopReceiving` → `StartReceiving` cycle.

**kelixip side.** The adapter can finally honour the behaviour's
`{:ms_event, conn, :ice_connected}`, which makes `Kelix.Mod.Mcu.Adapter`
event-complete against `MediaServer.Behaviour` and lets a script gate on media
actually flowing. Two immediate uses: joining the mosaic **when video really
arrives** rather than at ACK time (materially better for WebRTC legs, and it is
what mcuGold approximates with its `onMediaChanged` heuristic), and reporting a
`participant.media_connected` event for the operator view.

## Sequencing and risk

| | P7 (S1 + S2) | P8a (S3 plumbing) | P8c (ingestion) | S4 (done) |
|---|---|---|---|---|
| Server change | additive: 1 RPC, 2 event types, 2 listener overrides | 1 optional param, 1 return element, 1 negotiator call, filtered map installed | `remoteFmtp` honoured, RFC 6184 §8.2.2 in `GetFmtpParams`, `effectiveProps` to the encoder — **the only genuinely new algorithm in S3** | 1 argument, 1 global setting, 1 return value enriched |
| Breaks an existing client? | no (append-only) | no (`returnVal[0..1]` unchanged, param optional) | no (fmtp values change, shape does not) | no (`returnVal[0]` unchanged) |
| kelixip change | arm/disarm + 2 event handlers | **deletes** local arbitration and 4 config keys; adds the offer struct, the property split, the transport-case trace and the `a=rtcp-fb` intersection | none | reads the address, deletes two config keys |
| Closes | L1, L2 | most of L4 | the rest of L4 | G2 |
| Risk if skipped | dead legs occupy the mix for hours | silent one-way media on exotic fmtp | media that connects and never arrives behind NAT |

P7 first: it is smaller, purely additive on both sides, and fixes an operational
hazard rather than an interop refinement. Both are independent of P0′-P6 and of
each other — S3 does not need the watchdog, and the watchdog does not need the
enriched return.

