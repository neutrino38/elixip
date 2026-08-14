# How `mediagw-b2bua` drives JSR309 — the media plane of a B2BUA

Source study of `../mediagw-b2bua` (Java, SIP Servlet + `XmlRPCJSR309Client`),
written because elixip's B2BUA P3 (`{:mediaserver, …}` mode, see
[b2bua_module.md](b2bua_module.md) §7) is going to do **the same thing**, and the
Java code is the only place where "the same thing" is written down completely.

It answers the question P3 was blocked on: *how do you connect two peer
connections on a Medooze media server?* The short answer is that there is no
"connect two connections" primitive — there is one media session holding two
endpoints, and a per-media object that wires them together, chooses the codecs
of both at once, and generates both SDPs. The long answer is below.

The reference for what the RPCs mean stays
[mendooze_interface.md](mendooze_interface.md); this document is about how they
are **composed** for a back-to-back call.

## 1. The classes, and what each one owns

| Class | Role |
|---|---|
| `MediaGwSipServlet` | the SIP side: every SDP body in or out goes through `processContent/7`, which decides what to feed the media session and what body to put on the message it forwards |
| `MediaSessionFactory` | one `XmlRPCJSR309Client` for the whole application; creates one `MediaTranscodingSession` per call, and runs the inactivity watchdog |
| `MediaTranscodingSession` | **the call's media plane**: one JSR309 `MediaSession`, two `Endpoint`s, one event queue, and the map of bridges. Implements `IMediaSession` |
| `MediaBridge` | **one per (media type, media role)**: the pair of `Leg`s for that media, the attach/transcoder wiring, and the `m=` line generator for either side |
| `Leg` (+ `WebSocketLeg`) | one side of one media: transport type, remote ip/port, the `rcv` and `snd` rtpMaps, crypto and ICE material, the four `EndpointStart/Stop*` calls |
| `IceInfo`, `CryptoInfo`, `H264Params` | SDP-level material, parsed from the peer and generated for us |

`MediaRelaySession` is a second `IMediaSession` implementation for a
pass-through/NAT-relay mode; it is entirely `UnsupportedOperationException` and
was never finished. Ignore it.

## 2. The object model on the media server

```
MediaSession                    "<sip application session id>"   ← ONE per CALL
├── Endpoint  "<id>-in"         the caller's RTP/SRTP/DTLS connection
└── Endpoint  "<id>-out"        the callee's
```

`MediaTranscodingSession`'s constructor (`MediaTranscodingSession.java:249-267`):

```java
sessionId = client.MediaSessionCreate(name, queueId);
inbound   = new SessionAttributes(name + "-in");    // → EndpointCreate(sessionId, tag, true, true, true)
outbound  = new SessionAttributes(name + "-out");
sessionLocalCryptoInfo = CryptoInfo.Generate(client);   // one DTLS fingerprint for the call
sessionLocalCryptoInfo.setup = "passive";
```

Three facts to keep:

- **one `MediaSession` per call, two `Endpoint`s in it.** Not one session per
  leg. This is not a style choice: `EndpointAttachToEndpoint(sessionId, epA,
  epB, media)` takes a *single* session id, so two endpoints can only be
  connected if they live in the same session;
- the endpoints are created with **audio, video and text all enabled**
  (`EndpointCreate(sessionId, tag, true, true, true)`), whatever the call turns
  out to negotiate. What a media actually does is decided later, per media, by
  the bridge;
- each endpoint gets its ICE candidates once, at creation, and only for audio:
  `GetMediaCandidates(sessionId, endpointId, RTP, AUDIO)`. The per-media port is
  patched into the candidate at SDP-generation time
  (`MediaBridge.java:817-838` — `i.updatePort(l.snd.port)`, the comment there
  says why).

The event queue is created **per media session** (`startEventListener`,
`:1055-1079`) and read by a `MediaSessionEventQueue` long-poll; events carry the
`endpointId`, which is how a `FastPictureUpdate` is attributed to a leg
(`onEvent`, `:1107-1143`). Elixip does this differently — one queue per *server
connection*, events routed by session tag — which matters for §11.

## 3. The bridge: one `MediaBridge` per (media, role)

```java
EnumMap<Codecs.MediaType, Map<Codecs.MediaRole, MediaBridge>> bridges;
```

The role dimension is not decoration: it comes from `a=content:` (RFC 4796), so
one call can carry two video bridges — `VIDEO_MAIN` and `VIDEO_SLIDES` (BFCP
presentation). A `m=video` with a `content` that is neither is rejected with
port 0 (`MediaTranscodingSession.java:396-419`).

Each `MediaBridge` holds two `Leg`s (`inbound`, `outbound`) and has three states:

| state | when | RPCs |
|---|---|---|
| `IDLE` | nothing wired | — |
| `BRIDGING` | the two legs selected the **same** encoder, and the media is not audio | `EndpointAttachToEndpoint` ×2 (one per direction) + `EndpointSetRTPProperties(…, {"useOriSeqNum": "1"})` on both endpoints |
| `TRANSCODING` | the encoders differ, **or the media is audio** | a transcoder per direction, attached endpoint→transcoder→endpoint |

`MediaBridge.buildBridge/5` (`MediaBridge.java:455-574`) is the whole thing:

```java
if (needTranscoding() == 0 && media != MediaType.AUDIO) {
    client.EndpointAttachToEndpoint(sessionId, inEP,  outEP, media);
    client.EndpointAttachToEndpoint(sessionId, outEP, inEP,  media);
    // keep the original RTP sequence numbers when relaying
    client.EndpointSetRTPProperties(sessionId, inEP,  media, {"useOriSeqNum": "1"});
    client.EndpointSetRTPProperties(sessionId, outEP, media, {"useOriSeqNum": "1"});
} else switch (media) {
    case VIDEO:
        transcoderIdIn = client.VideoTranscoderCreate(sessionId, "video transcoder in");
        client.EndpointAttachToVideoTranscoder(sessionId, inEP, transcoderIdIn);
        client.VideoTranscoderAttachToEndpoint(sessionId, transcoderIdIn, outEP);
        // …and the symmetric chain out→in…
        client.VideoTranscoderSetCodec(sessionId, transcoderIdIn, inbound.selectedEncoder,
                                       CIF, 20 /*fps*/, outbound.bitrate, 200 /*intra period*/,
                                       inbound.getSelectedCodecParams());
        break;
    case AUDIO:
        // same shape with AudioTranscoderCreate / EndpointAttachToAudioTranscoder /
        // AudioTranscoderAttachToEndpoint / AudioTranscoderSetCodec
        break;
    default:
        throw new XmlRpcException("Transcoding for text is not supported");
}
```

Two consequences worth stating plainly, because they are decisions and not
mechanics:

- **audio is always transcoded**, even when both legs picked the same codec.
  The condition excludes `AUDIO` from the direct-attach path outright. It costs
  CPU on every call and buys resampling, DTMF handling and a clean re-packing;
- **text is never transcoded** (`needTranscoding()` returns 0 for `TEXT`, and
  the transcoding branch throws for it) — text is always a direct attach, which
  is what makes the T.140 ↔ text-over-WebSocket gateway of §7 work.

`needTranscoding()` itself is one line: `selectedEncoder != otherLeg.selectedEncoder`
(`Leg.java:636-638`). A commented-out extension would also transcode on an H.264
`packetization-mode` mismatch.

Undoing it (`stopBridge`, `MediaBridge.java:392-453`) is symmetric:
`EndpointDettach` on both endpoints, plus `Video|AudioTranscoderDettach` +
`…Delete` when transcoders were created.

## 4. Direction control: `startReceiving` / `startSending`

This is the part that is easy to get backwards, and the one the SIP layer calls
most often. The flags are named **from the outbound leg's point of view**:

```java
// MediaBridge.java:704-721 — "receiving" = callee → us → caller
public void startReceiving(sessionId, inEP, outEP, bitrate) {
    if (!receiving && inbound.rcv.port > 0) {
        outbound.startReceiving(sessionId, outEP);   // EndpointStartReceiving(S, outEP, media, outbound.snd.rtpMap)
        inbound.startSending(sessionId, inEP);       // EndpointStartSending(S, inEP, media, inbound.rcv.ip, inbound.rcv.port, inbound.rcv.rtpMap)
        receiving = true;
    }
}

// MediaBridge.java:681-701 — "sending" = caller → us → callee
public void startSending(sessionId, inEP, outEP, bitrate) {
    if (!sending && outbound.rcv.port > 0) {
        outbound.startSending(sessionId, outEP);
        inbound.startReceiving(sessionId, inEP);
        sending = true;
    }
}
```

The rule underneath, which is what a port of this has to preserve:

> **SDP arriving on a leg unblocks the direction that sends *toward* that leg.**

An offer from the caller tells us where to send the caller's media, so it is
`startReceiving()` (callee→caller) that becomes possible; the callee's answer
tells us where to send to the callee, so it is `startSending()`. The guards
(`inbound.rcv.port > 0`, `outbound.rcv.port > 0`) say exactly that, and a port
of 0 — a declined `m=` line — leaves that direction down, which is the correct
handling of a one-way media.

Two more things happen in these four calls (`Leg.java:654-690`):

- `EndpointStartReceiving(S, EP, media, snd.rtpMap)` **returns the local RTP
  port**, stored in `snd.port`. It is the port advertised in the SDP for that
  leg — so the receive plane must be started *before* the SDP for that leg is
  generated. Elixip's `Conn` already works this way;
- the rtpMap given to `StartReceiving` is the leg's **snd** map, built from what
  the *other* leg can receive (§5). The rtpMap given to `StartSending` is the
  leg's own `rcv` map, i.e. the peer's own numbering.

`restartLeg/1` (`MediaTranscodingSession.java:829-853`) is the re-INVITE
variant: stop and start one side without touching the `sending`/`receiving`
flags.

## 5. Codec negotiation crosses the legs — the load-bearing constraint

This is why the two legs of a B2BUA cannot be negotiated independently.

1. `Leg.parseRtpMap(md)` fills `leg.rcv.rtpMap` (payload type → codec) and
   `codecsPri` from the peer's `m=` line — *what this peer can send us*;
2. on an **answer**, `MediaBridge.populateSndRtpMap` first calls
   `selectCodec()` → `inbound.selectEncoderForLegs(outbound)`
   (`Leg.java:604-634`), which picks **one encoder for both legs at once**: a
   codec common to the two peers if there is one, otherwise each leg keeps its
   own and the bridge switches to transcoding;
3. `leg.buildSndRtpMap(otherLeg, offer)` then builds the map this leg will
   **propose**, out of what the other leg can receive — per media, with its own
   rules for audio (wideband first), text (T140RED handling) and video;
4. `MediaBridge.createMediaDescription(...)` refuses to answer a media whose
   *other* leg has no receive codecs: port 0 (`MediaBridge.java:807-815`).

So the SDP offered on leg B is a function of the SDP received on leg A, and the
answer sent on leg A is a function of the answer received on leg B. A design
that negotiates each peer connection in isolation and then tries to "join" them
cannot express step 2 — it will transcode every call, or fail one where a
common codec existed.

**Step 2 landed 2026-08-12** in `MediaServer.Mendooze.Conn`, which is the one
process holding both legs (§10): each leg records `peer_codecs` — every code the
peer can carry, in the peer's own `m=` order — and `select_codecs/4` reads both
lists at bridge time under the §11 policy. It had cost a real call: two legs that
both carried opus were declared to disagree, because comparing two independently
settled *heads* is not the same question as "is there a codec both peers support".
The SDP the caller is *told* followed the same day: `bridge/3` may now answer
`{:ok, %{inbound_answer: sdp}}`, the caller's answer rebuilt once both legs are
known, and `attach_legs/3` puts it in the plan in place of the one held since the
INVITE. Safe because that body is only ever emitted from `complete_media` — no
1xx carries it — so nothing observable moved.

**On a RELAYED media the rebuilt answer is restricted to the intersection of the
two legs' codec lists.** That is what makes every codec left in it honest: the
caller may switch between them mid-call with no renegotiation, and
`RTPMultiplexer::TryCodec` will bridge, because it only bridges for a codec
present in the sink endpoint's outgoing map. Announcing more — which the first
pass has to do, knowing only one leg — leaves the caller free to pick a codec the
callee never accepted, and a relay has nothing to convert it with.

A TRANSCODED media keeps the wide answer, in the caller's order: the transcoder
converts whatever arrives, so every offered codec stays legitimately on the table.

Two bounds worth keeping in sight:

- **an answer may only contain payload types from the offer** (RFC 3264 §6.1): a
  PT number means nothing outside the SDP that declared it. So the answer can
  never carry a codec the callee answered but the caller never offered — only the
  mirror case is available, the caller's codecs the callee lacks, which is exactly
  the set a transcoder serves. Our *offer* to the callee has no such bound; we are
  the offerer there.
- **the wiring is the policy's, not the selection's** (landed 2026-08-12, once the
  media server gained video bridging). `:forbid` is the only policy that gets a
  plain `Endpoint ↔ Endpoint`; `:avoid` and `:force` both get
  `Endpoint ↔ Transcoder ↔ Endpoint`.

  Putting a transcoder in `:avoid`'s path reads backwards until you look at what a
  JSR-309 transcoder does: it decides **per incoming packet**. `TryCodec` asks the
  sink whether it can carry the codec that just arrived and, when it can, the
  packet is forwarded untouched — `RTPMultiplexer::Multiplex` copies nothing. So
  the steady state of an `:avoid` call whose legs agree is still a relay, and the
  day a peer switches codec mid-stream the path follows instead of breaking, with
  no renegotiation. A plain attach cannot do that: it would relay a codec the far
  end never accepted. This is why the answer for a transcoded media may stay wide
  (below) — the two halves are one design.

  `useOriSeqNum` is deliberately absent from that path. It also sets `useOriTS`
  (`rtpsession.cpp:526-529`) and copies both numbers off the incoming packet:
  right while the transcoder bridges, wrong the moment its encoder produces the
  packet instead, since an encoded frame carries no meaningful sequence of the
  source's. Re-stamping is safe either way — `RTPEndpoint::onRTPPacket` advances
  the outgoing timestamp by the incoming DELTA, so packets of one frame keep one
  timestamp and frame grouping survives. Only on the static attach path, where
  nothing else can ever produce a packet, is preserving the peer's own numbering
  both safe and worth having.

Session-level bandwidth crosses too: `b=AS`/`b=TIAS` parsed on one leg is copied
to the other (defaulting to 512 kbit/s), and video is offered `bitrate - 64` to
leave room for audio (`MediaTranscodingSession.java:684-694`).

## 6. Generating the SDP for a leg

`createSDPToForward(isOffer, leg, textMode, secure, rtpMux, ice, rtcpFb, useInfoFIR)`
(`MediaTranscodingSession.java:589-704`):

1. text mode may **recreate the leg's transport** first (RTP ↔ WS/WSS, §7);
2. session level: origin/connection from the leg's primary ICE candidate,
   `b=AS` from the leg's bitrate, `a=ice-lite` when ICE is on, the ICE
   credentials when the peer had ICE, the session DTLS fingerprint when the peer
   was secure;
3. one `m=` line per bridge, from `MediaBridge.createMediaDescription(...)`,
   which is where the difference between an offer and an answer lives:

   | | offer | answer |
   |---|---|---|
   | secure | our crypto if we have it | ours **and** the peer's |
   | rtcp-fb | always offered | only what the peer offered |
   | ICE | when the transport is RTP/SRTP | that, **and** the peer had ICE |
   | rtcp-mux | as asked | as asked **and** the peer muxes |
   | DTLS setup | `actpass` | (the session default, `passive`) |

   and where the side effects sit: `EndpointSetLocalSTUNCredentials`,
   `EndpointSetLocalCryptoSDES`, and `EndpointSetRTPProperties(…, {"useExtFIR":
   "1"})` when RTCP feedback is off but keyframes must still be requestable.

## 7. Per-leg, per-media state on the server

Everything below is `(endpoint, media)`-scoped, applied by
`Leg.configureRemoteInfos` at parse time (`Leg.java:1134-1161`):

```
EndpointSetRemoteCryptoDTLS(S, EP, media, hash, fingerprint)
EndpointSetLocalCryptoSDES (S, EP, media, suite, key)
EndpointSetRemoteSTUNCredentials(S, EP, media, frag, pwd)
EndpointSetRTPProperties  (S, EP, media, props)
```

**Transport switching** is per leg and per media
(`MediaBridge.recreateLegIfNeeded`, `:240-285`): the `m=` proto decides whether
the `Leg` object is a plain RTP/SRTP one or a `WebSocketLeg`, and the latter
calls

```java
client.ConfigureMediaConnection(sessionId, endpointId, media, VIDEO_MAIN, WS, token, "t140");
wsaddr = client.GetMediaCandidates(sessionId, endpointId, WS, TEXT);
```

to obtain the `ws://…` URL published in the SDP. Switching a leg builds a **new
`Leg` object** and replays the start/stop calls that were active on the old one
(`startRecreatedLeg`, `:168-196`) — a re-INVITE that turns RFC 4103 text into
text-over-WebSocket does not disturb the other leg.

## 8. The SIP choreography

`MediaGwSipServlet.processContent(...)` (`:330-445`) is the single entry point.
`leg` is true for the inbound leg, `propagate` is false when the request is
answered locally instead of being relayed (a re-INVITE for a local update).

**A request carrying SDP (the offer), relayed:**

```
processSDPOffer(sdp, legId, propagate=true)      // parse, create/refresh the bridges of that leg
startReceiving()   if the offer came from the inbound leg
startSending()     otherwise
createSDPOffer(otherLegId, …)                    // → the body of the forwarded INVITE
```

Note what does **not** happen: `processSDPOffer` with `propagate=true` does not
call `buildBridge` (`MediaTranscodingSession.java:725`). Nothing is attached
until an answer comes back — there is nothing to attach to yet.

**A request carrying SDP, answered locally** (`propagate=false`): `restartLeg(legId)`
then `createSDPAnswer(legId, …)`. New media may not be added this way; a `m=`
line that was not already there is declined with port 0
(`MediaTranscodingSession.java:427-435`).

**A response carrying SDP (the answer):**

```
// call in progress — the stop/process/start triple, on the side the answer arrived from
stopReceiving();  processSDPAnswer(sdp, legId, prop);  startReceiving()   // answer on the inbound leg
stopSending();    processSDPAnswer(sdp, legId, prop);  startSending()     // answer on the outbound leg

createSDPAnswer(otherLegId, …)                   // → the body of the relayed 200
```

`processSDPAnswer` always ends with `buildBridge(activeMedias)` — **this is
where the endpoints are actually attached** or the transcoders created, and
where a media that disappeared from the SDP has its bridge stopped.

**ACK** (`doAck`, `:455-490`): `startReceiving()` / `startSending()` again,
idempotent through the `sending`/`receiving` flags.

**488 on the outbound INVITE** (`tryOtherMode`, `:566-618`): a second INVITE to
the same target with the *other* offer profile — WebRTC if the first was plain
SIP, plain SIP if it was WebRTC. This is exactly the offer-profile fallback of
[b2bua_module.md](b2bua_module.md) §7.5, with a two-rung ladder.

**Teardown** (`delete/0`, `:942-988`): stop every bridge → `EndpointDelete` ×2 →
`MediaSessionDelete` → `EventQueueDelete`.

**Keyframes** (`sendFullIntraframe/1`): `VideoTranscoderFPU(S, trId)` when
transcoding, `EndpointRequestUpdate(S, otherEP, media)` when bridging — i.e. ask
the *far* peer, since in bridging mode we have no encoder to reset.

**Liveness** (`isActive/0` + `MediaSessionFactory.checkActivity`): every
application-session expiry, `EndpointGetStatistics(S, outEP)` is polled and
`totalRecvBytes` compared to the previous reading. No progress → the call is
terminated and the media session deleted. This is the RTP-inactivity watchdog;
elixip gets the same result from the server-side `EndpointStartRTPTimeout`.

## 9. The RPC inventory

Used by `mediagw-b2bua`, grouped by what elixip already does:

| | RPC |
|---|---|
| **elixip already calls these** | `MediaSessionCreate/Delete`, `EndpointCreate/Delete`, `EndpointStart/StopReceiving`, `EndpointStart/StopSending`, `EndpointSetRTPProperties`, `EndpointSetLocalCryptoSDES`, `EndpointSetRemoteCryptoDTLS`, `EndpointSetLocal/RemoteSTUNCredentials`, `EndpointRequestUpdate`, `GetMediaCandidates`, `ConfigureMediaConnection`, `EventQueueCreate/Delete`, `EndpointAttachToEndpoint` + `EndpointDettach` (echo: an endpoint attached to itself) |
| **new for P3** | `EndpointAttachToEndpoint` *between two endpoints*, `EndpointGetStatistics` |
| **new if transcoding is in scope** | `Video/AudioTranscoderCreate`, `…Delete`, `EndpointAttachTo…Transcoder`, `…TranscoderAttachToEndpoint`, `…TranscoderSetCodec`, `VideoTranscoderFPU`, `AudioTranscoderDetach`/`Dettach`, `VideoTranscoderDettach` |
| **not needed** (conferencing — the MCU module's territory) | `Audio/VideoMixer*`, `…MixerPort*`, `VideoMixerMosaic*` |

## 10. What elixip has, and where it stops

`MediaServer.Mendooze.Conn` is a faithful implementation of **one `Leg` plus one
`Endpoint`**: it parses the peer's SDP, keys the security material, calls
`EndpointStartReceiving` to allocate the port, generates the SDP, calls
`EndpointStartSending`, arms the RTP timeout, and tears everything down in the
right order. The negotiation it does is *against its own codec tables*
(`@default_audio_codecs` &c.) — the UAC/UAS case, where the media server is one
end of the call.

What P3 adds is not a missing RPC. It is the layer above `Leg` that
`MediaTranscodingSession` + `MediaBridge` are: an object that owns **two**
endpoints and negotiates them **against each other**.

The gap, concretely:

1. **one media session, two endpoints.** Today `Conn.init/1` does
   `MediaSessionCreate` + `EndpointCreate` as one indivisible act, and
   `MediaServer.Mendooze` routes server events to a `Conn` by session tag. Two
   endpoints in one session means either one `Conn` owning both (and demuxing
   its events by `endpointId` — which endpoint events carry) or two `Conn`s
   sharing a session, which the tag-keyed registry cannot express as it stands;
2. **cross-leg codec selection** (§5). The `snd` rtpMap of a leg is derived from
   the other leg's `rcv` codecs. `Conn` has no notion of an "other leg", and the
   `MediaServer.Behaviour` API (`get_local_offer/1`, `set_remote_offer/2`) has
   no place to pass one;
3. **the bridge is per media and per role**, not per connection — including the
   two-video-bridge (`main` + `slides`) case;
4. **direction control is cross-leg** (§4): starting a direction touches *both*
   endpoints, and is triggered by SDP arriving on the leg that direction sends
   toward.

Which settles the shape of the P3 primitive. A `bridge(conn_a, conn_b)` callback
added to `MediaServer.Behaviour` is the right *interface* for the DSL — one verb,
media-server-agnostic, and `MediaServer.Mockup` can implement it by looping RTP
between two mock connections. But behind it, for Mendooze, the two legs cannot
be two independently negotiated `Conn`s: the answer to leg A depends on the offer
of leg B. The Elixir counterpart of `MediaTranscodingSession` — one process
holding both endpoints and both `Leg` states — is what actually implements it.

What that means for §14.6's failure domain is already visible here: a media
server that dies takes the *call* down, not one leg, which is exactly what "one
media session per call" says on the server side too.

## 11. The transcoding policy elixip adds (decided 2026-08-09)

The Java gateway hardcodes its answer to "do we transcode?": audio always,
video only when the codecs differ, text never (§3). elixip makes the first two
**configurable per media**, in the `media_opts` of `{:mediaserver, media_opts}`,
because a test tool needs to rehearse a leg that must not be transcoded as much
as one that must.

Three values, same three for audio and for video, and — since 2026-08-12 — the
same *meaning* for both, which the two-column table below used to split.

The selection is one act for both legs (§5), stated over the two peer lists:

```
L  = what the caller offered,  in the CALLER's order
L' = what the callee answered, in the CALLEE's order
```

| value | selection | when L ∩ L' = ∅ | wiring | the caller's answer |
|---|---|---|---|---|
| `:force` | `{hd(L), hd(L')}` — each leg keeps the head of **its own** list, so each peer is served the codec IT asked for | already the selection | `EP ↔ TR ↔ EP` | every offered codec the server accepted, in the offer's order |
| `:avoid` *(default)* | the first codec of **L** that also appears in L', for **both** legs | fall back to `{hd(L), hd(L')}` | `EP ↔ TR ↔ EP` | the same list, with L ∩ L' floated to the **front** |
| `:forbid` | same as `:avoid` | the media is **refused** (488) | `EP ↔ EP` | **only** L ∩ L' |

The transcoder a `:avoid` call carries is not a cost it failed to avoid: it bridges
per packet while the legs agree (§5), and the answer's ordering is what keeps them
agreeing — the caller's natural pick is the codec that needs no conversion. What
`:avoid` avoids is *converting*, not *being able to*.

Transcoding is not a fourth decision: it is what two *different* selections mean,
and a direct attach is what one selection twice means. `L`'s order decides the
common codec because the caller's preference is the one a gateway has no business
overruling.

Two consequences worth stating, because both are deliberate deviations:

- **`:force` no longer CONVERTS when the two heads agree.** It used to, for audio,
  matching the Java gateway. Careful with the wording, which this bullet got wrong
  until 2026-08-12: the transcoder is still in the path — the wiring is the
  policy's, and only `:forbid` gets a plain attach — but a transcoder whose two
  ends carry the same codec bridges per packet and converts nothing. The guarantee
  `:force` sells, "this leg gets the codec IT asked for", is unaffected either way.
  What is genuinely lost is the ability to force a *conversion* when the legs
  already agree, which a test tool might want to rehearse; `:force` with two
  deliberately different `audio_codec:` lists is how to get one now.
- **`:avoid` may pick a codec that is neither leg's first choice.** With
  `L = [opus, PCMU]` and `L' = [PCMU, opus]` it picks opus for both, though the
  callee ranked PCMU first. Relaying the caller's preference beats honouring the
  callee's and paying for a transcoder.

In every mode, **no usable audio codec at all fails the call** — a call with no
audio is not a call, and the alternative (a port-0 audio line and a video-only
session) is worse than a clean 488.

`:avoid` is the default rather than the Java `:force` because transcoding costs
CPU on every call and, for a signalling test, changes what the far end sees.
`:force` is kept because it is what production runs today, and because it is the
only mode that *guarantees* a given codec on a given leg.

**Text is not configurable**: always bridged, never transcoded, exactly as the
Java gateway does it — T.140 / T140RED handling on each side and the WS/WSS
transport switch of §7. That is the one behaviour that has to be inherited
unchanged, since it is what the text gateway *is*.

The policy is evaluated per `(media, role)` at answer time, in the single place
that sees both legs — the cross-leg encoder selection of §5. It is a policy on
the outcome of that selection, not a second negotiation next to it.
