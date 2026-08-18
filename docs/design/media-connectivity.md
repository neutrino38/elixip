# Media connectivity events

How the controller learns that media actually flows, and when a scenario may
start sending into a leg.

Status: implemented and verified end to end 2026-08-08, against a live Linphone
(capture `/home/ebuu/linphone-A.pcap`, 13:55). The server log shows `media
connected on audio` **not** releasing the milestone, `media connected on video`
releasing it, and the player created immediately after; on the wire the first IDR
leaves at t=9.444 to the **latched** address, after the first inbound video packet
at t=9.300. The only packets still sent to the announced SDP address are the
media server's three NAT priming datagrams, which carry **no payload**.

Before the change, the same call sent the IDR 623 ms *early*, to an address
nothing listened on.

## 1. The incident

Playing a file to a NATed Linphone, the opening keyframe was systematically
lost. Measured on two captures (`/home/ebuu/linphone-A.pcap`,
`/home/ebuu/linphone-D.pcap`), call D:

| t (s) | event |
|---|---|
| 11.269 | media server NAT priming burst towards the **SDP** address |
| 11.332 | first inbound **audio** RTP -> audio latched -> `:ice_connected` |
| 11.659 | inbound STUN on the video port (28 B) — not RTP, does not latch |
| 11.753 | scenario starts the player: **IDR sent to the SDP address, lost** |
| 12.376 | first inbound **video** RTP |
| 12.390 | server switches the video send address, 14 ms later |

The media server is not slow: it latches on its next send after the first
inbound RTP. The peer is late — Linphone starts its video stream about one
second after its audio stream, because it is still opening the camera and the
encoder. Call A shows the same shape.

So `:ice_connected` was not early relative to a state already reached; **the
video leg had reached no state at all**. The controller emitted a
connection-level event out of a per-media fact.

A cross-media fix (infer the other legs from the one that latched) was evaluated
and rejected: the NAT mappings are independent, with no relation to infer from.

| call | media | announced | observed source |
|---|---|---|---|
| D | audio | 52791 | 43297 |
| D | video | 33962 | 55149 |
| A | audio | 54600 | 39622 |
| A | video | 38743 | 33485 |

## 2. What the media server already provides

**No media server change is required.** `EndpointConnectedEvent` (JSR-309 event
type 7, `ParticipantMediaConnected` (4) on the conference API) is already
per-media and already fires on the first *validated* packet:

- `RTPSession::onRTPPacket` notifies after the optional `srtp_unprotect`
  (`rtpsession.cpp:2166-2174`), one-shot, re-armed by every `StartReceiving`;
- `RTPEndpoint::onRTPPacketReceived` posts the event (`RTPEndpoint.cpp:383-391`)
  and its XML-RPC value carries the media (`RTPEndpoint.cpp:450`).

The two cases usually stated separately are one mechanism: in the clear it is
"first decodable RTP packet"; under SRTP/DTLS a successful decrypt **proves** the
handshake completed. Nothing else needs to be signalled.

What is wrong is downstream: `MediaServer.Mendooze.Conn` collapses every media
into a single connection-level `:ice_connected` behind the `connected_notified`
flag (`MediaServerMendoozeConn.ex:429-446`).

## 3. The contract

Three events on the `event_sink`, all carrying the connection pid.

| event | meaning |
|---|---|
| `{:ms_event, conn, {:media_connected, media}}` | the server validated the first inbound packet of `media` (`:audio`, `:video`, `:text`). Raw, one per media, re-emitted on each receive cycle. |
| `{:ms_event, conn, :ice_connected}` | derived milestone: the leg the scenario was waiting for is up. Emitted **at most once** per connection — see §5. |
| `{:ms_event, conn, :media_send_only}` | no inbound packet will ever arrive on any negotiated media, so no `:ice_connected` is coming. Emitted once, right after `EndpointStartSending` has been issued for every media. |

`:ice_connected` keeps its name for compatibility with existing scenarios, and
keeps being the event a scenario waits on before sending into the leg. It stops
meaning "some media flows" and starts meaning "the media that matters flows".

The raw per-media event is emitted **in addition**, not instead: a scenario that
wants a finer policy (start audio early, video late) has the material without a
new case being added to §4, and the derivation rule stays testable on its own.

## 4. Deriving `:ice_connected`

SDP direction attributes are written from the point of view of whoever writes
them, which is the ambiguity that makes a naive "all media are sendonly" rule
self-contradictory. Normalise first, to **our** point of view, per negotiated
media `m`, from the direction on the peer's side of the negotiation:

- the peer **transmits** on `m` iff its direction is `sendrecv` or `sendonly`;
- we transmit on `m` iff its direction is `sendrecv` or `recvonly`.

Let **R** = the set of negotiated media on which the peer transmits — i.e. the
only media on which a `{:media_connected, _}` can ever arrive.

Then, in order:

1. **R is empty** — nothing will ever come back. Emit `:media_send_only` once,
   after `EndpointStartSending` has been issued for every media. `:ice_connected`
   is **never** emitted.
2. **`:video` ∈ R** — emit `:ice_connected` on `{:media_connected, :video}`.
3. **otherwise** — emit `:ice_connected` on the first `{:media_connected, m}`
   for any `m` ∈ R.

Three branches, mutually exclusive, no unreachable clause. Rule 1 covers both
send-only cases; rule 2 is the ordinary video call and the one that fixes §1;
rule 3 is the audio-only (or text-only) call.

> **Known limitation, deliberately not solved here.** If video is negotiated but
> `:video` ∉ R — we send video, the peer never does — rule 3 applies and the
> video leg can never latch, because comedia needs an inbound packet. Behind a
> symmetric NAT that leg cannot work at all: the peer never opens the pinhole.
> No event ordering fixes that; the honest signal is that the scenario proceeds
> and video is one-way lost.

## 5. Re-negotiation

`{:media_connected, media}` follows the server: the type-7 notification is
re-armed by every `StartReceiving`, so a re-INVITE that reopens the receive plane
produces a fresh event per media. That is the useful signal for a scenario that
wants to know media restarted.

`:ice_connected` is **one-shot for the life of the connection**: the first time
the rule of §4 is satisfied, and never again. Re-emitting it on every re-INVITE
would restart playback in every scenario that keys its `start_playing` state off
it — a scripted call would loop on a hold/resume. Scenarios needing the
re-negotiation signal use the raw event.

## 6. No implicit timeout

Neither the adapter nor the framework arms a timer. A peer that negotiates
`sendrecv` video and never sends any (camera denied, one-way NAT failure)
produces no `:ice_connected`, by design.

**It is the scenario's job** to bound the wait, with an `after` clause in the
`on_events` block that waits for it. `apps/elixip2/scenarios/play.exs` already
does (`answering`, `after 15_000 -> scenario_failure(...)`); the others must be
audited — see §7.

This is a behaviour change worth stating plainly: a video call whose video leg
never carries inbound RTP used to start playing on the audio latch, and will now
wait, then hit the scenario's timeout. That is the intended trade — sending a
keyframe into an unlatched leg is worse than waiting — but a scenario with no
`after` clause will hang instead of playing audio.

## 7. Impact

Changed:

| file | what |
|---|---|
| `apps/elixip2/lib/framework/mendooze/MediaServerMendoozeConn.ex` | the rule (§4), the three events, the per-media state |
| `apps/elixip2/lib/framework/MediaServer.ex` | the behaviour's event type and documentation |
| `apps/elixip2/lib/framework/MediaServerMockup.ex` | the same rule; it was a plain timer, so tests would otherwise validate a behaviour production does not have. Video is scheduled **last** on purpose — that is the ordering real peers show, and the one the rule must survive |

Audited and left alone: every scenario waiting on `:ice_connected` already bounds
the wait, so §6 needed no change — `uac_invite.ex:88` (`after 5_000`),
`uac_invite.exs:85` (`after 10_000`), `play.exs` (`after 15_000`). The
`SIPScenario.ex` occurrence is a `@doc` example, which already shows an `after`
clause.

The MCU module is a different surface and is unaffected: it consumes the
conference API's `ParticipantMediaConnected` (event type 4), already per-media,
and never emits `:ice_connected`.

## 8. Implementation notes

The adapter has what it needs but drops it today:

- `Sdp.parse/1` already returns `:direction` per media
  (`MediaServerMendoozeSdp.ex:779` and `:833`, defaulting to `:sendrecv`); the
  negotiation paths discard it. Capture it when `state.medias` is narrowed to the
  answered set (`set_remote_offer`, `MediaServerMendoozeConn.ex:258`, and the
  `set_remote_answer` path) and store **R** alongside.
- Replace the `connected_notified :: boolean` flag with the pair
  `connected :: MapSet.t(media)` and `ice_notified :: boolean`.
- `:media_send_only` is emitted from the place that already loops
  `EndpointStartSending` over the medias (`apply_remote_media/4`,
  `MediaServerMendoozeConn.ex:1020-1037`), once the loop has completed for all of
  them — not per media.
- A text-over-WebSocket section has no RTP leg and never produces a connectivity
  event; it must be excluded from **R** (`apply_remote_media(state, %{transport:
  :ws}, ...)` is already the branch that skips the remote side).

## 9. Test plan

| test | asserts |
|---|---|
| unit, adapter | audio+video `sendrecv`: a `{:media_connected, :audio}` alone does **not** emit `:ice_connected`; the `:video` one does |
| unit, adapter | audio only: `{:media_connected, :audio}` emits `:ice_connected` |
| unit, adapter | all media send-only: `:media_send_only` is emitted after the last `EndpointStartSending`, and no `:ice_connected` ever |
| unit, adapter | video negotiated but peer send-only on audio only (`:video` ∉ R): `:ice_connected` on audio, per the §4 limitation |
| unit, adapter | a second receive cycle re-emits `{:media_connected, :video}` and does **not** re-emit `:ice_connected` |
| unit, mockup | the same four rules, so scenario tests exercise the real policy |
| scenario | `play.exs` against the mockup: the player is created **after** the video connectivity event, never before |
| regression | the capture of §1 replayed: the first IDR leaves after the video send address has been latched |
