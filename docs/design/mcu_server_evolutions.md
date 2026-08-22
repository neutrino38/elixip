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
same wiring, for free. **S6** is separate and larger: it makes a leg's encoded
geometry an output of the rate controller instead of a setting.

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

The controller side is wired: `{:mcu_event, :media_timeout, media}` → BYE +
`leave(:media_timeout)` → `{:conference, :media_timeout, …}` lives in the
`Mcu.SBB.conference()` block, so it is handled once for every conference script
rather than per state per script. New event `participant.media_timeout` in the §11.1 vocabulary (already
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

## S6 — the encoded geometry is a consequence of the bitrate, not a setting

**A leg's encoding size is not something anyone configures: it is what the bitrate
that leg can actually carry allows.** Encoding 720p at 300 kb/s is a bad trade — the
right answer is fewer pixels, not worse ones — and nobody outside the rate
controller knows when that moment arrives. So the size stops being a knob and
becomes an output of the regulation loop, which lifts **L7** on the geometry axis
without adding one argument to the control surface.

**All of it runs in the media server.** kelixip does not see the send-side bandwidth
estimate, and deriving a resolution from an estimate we do not observe is the exact
coupling `CLAUDE.md` forbids: what the media server knows about itself, the media
server is asked. It is also why the answer is *not* a per-participant `size` field on
`conference.update` — a field would have to be set by someone who cannot know when to
change it.

What the server does:

1. **At leg setup**, derive the encoding size from the requested bitrate — the one
   `SetVideoCodec` carries, itself already bounded by the offer's `b=AS`.
2. **When the send-side estimate forces the bitrate down**, recompute the size and
   reconfigure the encoder by inserting a resizer into the videopipe. The new size
   **preserves the aspect ratio**, which is free by construction when it derives from
   scaling the canvas rather than from picking another entry in the medooze size enum
   — where `hd720p` is the only 16:9 and every step down distorts.
   `VideoRescaler::Letterbox` stays as the safety net; it is no longer the nominal
   path.
3. **Frame rate follows the same logic, within bounds.** The configured `fps` is a
   **maximum**. The controller may lower it to `max(fps − 10, 5)` and no further:
   below that, cadence stops being the useful knob and resolution takes over. A
   conference at the default 30 can be regulated down to 20 fps; one configured at 12
   hits the floor of 5.

**What this removes from kelixip.** `video.size` disappears — from the `Conference`
struct, from `conference.create` / `conference.update`, from the `[module.mcu]` key
`video_size` and from the rendering. The one geometry that stays configured is the
**canvas**, `layout.size`, which `SetCompositionType` already carries: it is the only
one that remains conference-level once each leg encodes at its own size. Migration
through `Config.retired_keys/0`, like the codec keys P8a retired — accepted one
release with a warning naming the replacement, refused after. `align_sizes/4`,
`sized_by/2` and their "canvas size ignored" warning go with it; they only ever
arbitrated a conflict between two names for one number.

**What kelixip keeps:** `fps` as the maximum described above, `bitrate` as the
initial target, and `intra_period`. Those stay operator-facing because the ceiling is
a policy — how much of a node's uplink one conference may claim — and policy is the
half kelixip owns.

It also settles a standing incoherence: `answer_bandwidth/2` announces
`min(offered b=AS, conference bitrate)` while `SetVideoCodec` receives the conference
bitrate unconditionally. The announced value becomes the regulator's initial ceiling,
so what we promise is what we send.

Open before implementation, all server-side:

- the **CPU/VAAPI budget** of N encoders at N geometries, which is the reason the
  single profile was attractive in the first place;
- **reconfiguring without a keyframe storm**: a resizer inserted mid-stream forces an
  IDR, and N legs resizing on the same congestion event must not all emit one at once;
- the interaction with the **H.264 level we announce**. A level bounds resolution ×
  frame rate, so regulating *downwards* is always legal, but the announced level must
  remain the ceiling the encoder is bound by;
- whether `SetVideoCodec` keeps its `size` argument for compatibility with mcuGold, as
  `SetCompositionType` kept its own under S4.

## Sequencing and risk

| | P7 (S1 + S2) | P8a (S3 plumbing) | P8c (ingestion) | S4 (done) |
|---|---|---|---|---|
| Server change | additive: 1 RPC, 2 event types, 2 listener overrides | 1 optional param, 1 return element, 1 negotiator call, filtered map installed | `remoteFmtp` honoured, RFC 6184 §8.2.2 in `GetFmtpParams`, `effectiveProps` to the encoder — **the only genuinely new algorithm in S3** | 1 argument, 1 global setting, 1 return value enriched |
| Breaks an existing client? | no (append-only) | no (`returnVal[0..1]` unchanged, param optional) | no (fmtp values change, shape does not) | no (`returnVal[0]` unchanged) |
| kelixip change | arm/disarm + 2 event handlers | **deletes** local arbitration and 4 config keys; adds the offer struct, the property split, the transport-case trace and the `a=rtcp-fb` intersection | none | reads the address, deletes two config keys |
| Closes | L1, L2 | most of L4 | the rest of L4 | G2 |
| Risk if skipped | dead legs occupy the mix for hours | silent one-way media on exotic fmtp | media that connects and never arrives behind NAT |

S6 is not in that table: it is the only item here that is not additive on the
kelixip side, and it is sequenced after P7/P8 for that reason.

P7 first: it is smaller, purely additive on both sides, and fixes an operational
hazard rather than an interop refinement. Both are independent of P0′-P6 and of
each other — S3 does not need the watchdog, and the watchdog does not need the
enriched return.

