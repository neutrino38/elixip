# Mendooze — server-side work to support a WebRTC *client* (UAC) controller

Companion to `docs/webrtc_sdp_design.md` (§2.5, §2.7). Elixip is being
extended so that elixipp can place calls **as a WebRTC UAC** (browser-shaped
offer, `setup:actpass`) toward the IVeS WebRTC gateway. In that call
direction the mendooze endpoint driven by elixip sits on the **offerer**
side, a role the server has never exercised in production: existing
deployments (the Java mediagw) always put mendooze on the *answerer* side,
facing browsers that are ICE-full and DTLS-active.

Consequences, in decreasing priority:

| # | Topic | Design ref | Priority |
|---|---|---|---|
| P1 | Audit: what does the endpoint already do as offerer? | Q2/Q4/Q5 | do first |
| P2 | DTLS **active** (client) role | Q4 | blocking |
| P3 | Outbound STUN connectivity checks (ICE-lite peer) | Q5 | blocking unless audit proves latching suffices |
| P4 | `GetMediaCandidates` per-media port | Q3 | nice-to-have |
| P5 | Connectivity event (DTLS up / first RTP) | — | nice-to-have |

Each prompt below is self-contained and copy-pasteable for a coding agent
working on the mediaserver repo
(<https://github.com/neutrino38/mediaserver>, branch `feat/alma_linux9`,
API spec `xmlrpc_jsr309_api.md`). They follow the same conventions as the
delegated-negotiation prompt (enriched `EndpointStartReceiving` return):
backward-compatible API, tolerant-client detection, spec updated in the same
change.

---

## Prompt P1 — Audit the offerer-side capabilities (investigation, no code change)

```
In this repo (medooze-based MCU with the XML-RPC JSR309 control interface,
spec in xmlrpc_jsr309_api.md), audit what an Endpoint does when the SIP
controller uses it on the OFFERER side of a WebRTC call, i.e.:

  EndpointGetLocalCryptoDTLSFingerprint("sha-256")
  EndpointSetLocalSTUNCredentials(sess, ep, media, ufrag, pwd)
  EndpointStartReceiving(sess, ep, media, rtpMap)      -> local port
  ... local SDP offer sent, remote answer received ...
  EndpointSetRemoteSTUNCredentials(sess, ep, media, ufrag, pwd)
  EndpointSetRemoteCryptoDTLS(sess, ep, media, setup="passive", hash, fp)
  EndpointStartSending(sess, ep, media, ip, port, rtpMap)

The remote party is another mendooze-backed gateway: ICE-lite (it will
never send STUN binding requests) and DTLS passive (it will never send a
DTLS ClientHello; it waits for ours).

Answer these questions precisely, with file/function references:

1. DTLS role: when EndpointSetRemoteCryptoDTLS is called with setup=
   "passive" (or "actpass"), does the endpoint's DTLS connection take the
   CLIENT role and emit a ClientHello? If so, when (on which trigger:
   SetRemoteCryptoDTLS itself, StartSending, first received packet?) and to
   which destination address/port? If the role is hardcoded server/passive,
   say so and locate where the role would have to be decided.
2. ICE: after EndpointSetRemoteSTUNCredentials, does the endpoint ever send
   STUN binding requests (as controlling or otherwise)? Or does it only
   answer inbound checks? Where is the remote transport address for such
   requests taken from (StartSending destination? learned/latched source?).
3. Media gating: does the endpoint require a completed inbound STUN check,
   or a completed DTLS handshake, before (a) sending RTP toward the
   StartSending destination and (b) accepting/decrypting inbound SRTP? Or
   does it latch on the first plausible inbound packet?
4. The "secure" RTP property (EndpointSetRTPProperties {"secure": "1"}):
   is it still required to enable SRTP when EndpointSetRemoteCryptoDTLS /
   EndpointSetLocalCryptoSDES are used, or is it implied now? Legacy
   controllers set it; the new Elixir controller currently does not.
5. EndpointAddICECandidate: confirm which candidate types/components are
   retained and whether a candidate can serve as the DTLS/STUN destination
   when StartSending has not been called yet.

Deliverable: a short written report (markdown) answering 1-5 with code
references, concluding for each of P2/P3 below whether the change is
REQUIRED, ALREADY WORKS, or WORKS WITH CAVEATS (state them).
```

---

## Prompt P2 — DTLS active (client) role on the endpoint (blocking, pending P1)

```
Context: the XML-RPC JSR309 controller (see xmlrpc_jsr309_api.md) can now
sit on the OFFERER side of a WebRTC call: the local SDP offer carries
a=setup:actpass, and the remote answer carries a=setup:passive. Per RFC
5763 the offerer must then run the DTLS handshake as CLIENT (send the
ClientHello). Today's deployments only exercised the SERVER role (remote
browsers are always active).

Required change: when EndpointSetRemoteCryptoDTLS(sess, ep, media, setup,
hash, fingerprint) is called with setup="passive":

- the endpoint's DTLS transport for that media must take the CLIENT role;
- the handshake must start as soon as a destination is known — the
  EndpointStartSending(ip, port) destination (calls may arrive in either
  order: SetRemoteCryptoDTLS before or after StartSending; handle both);
- retransmit ClientHello per DTLS rules until answered or a timeout raises
  the existing transport-error path;
- setup="active" keeps today's behavior (we are DTLS server);
  setup="actpass": keep current default (server role) — the controller
  always resolves actpass before calling.
- SRTP keys derived from the handshake must be installed for both
  directions exactly as in the server-role path.

Constraints:
- no API change (same method, same arguments — only honoring the setup
  argument that is already transmitted);
- no behavior change for setup="active" (regression risk on every
  browser-facing deployment);
- if the "secure" RTP property is still a prerequisite for SRTP (see audit
  P1 question 4), set it implicitly when SetRemoteCryptoDTLS is called, and
  document it in xmlrpc_jsr309_api.md.

Acceptance:
1. Unit/integration: two endpoints on one server, A configured
   setup="passive" remote (A is client), B configured setup="active"
   remote (B is server); wire A.StartSending -> B's receive port and
   vice versa; assert the handshake completes and SRTP flows both ways.
2. The existing browser-facing test suite (server role) is unchanged.
3. xmlrpc_jsr309_api.md: document the role mapping of the setup argument
   in the EndpointSetRemoteCryptoDTLS section.
```

---

## Prompt P3 — Outbound STUN binding requests toward an ICE-lite peer (pending P1)

```
Context: same offerer-side scenario as the DTLS client change. The remote
gateway is ICE-lite: it answers STUN binding requests but never sends any.
If our endpoint also never sends checks, no ICE pair is ever validated;
whether media and DTLS still flow depends on gating/latching (audit P1
question 3).

Required change (skip if the audit shows media+DTLS are not gated on ICE):
after both EndpointSetRemoteSTUNCredentials and EndpointStartSending have
been called for a media, the endpoint sends STUN binding requests to the
StartSending destination:

- USERNAME = remoteUfrag:localUfrag, MESSAGE-INTEGRITY with the remote
  password (we authenticate as the ICE-controlling side; include
  ICE-CONTROLLING and USE-CANDIDATE - the peer is lite, aggressive
  nomination is fine);
- repeat until a valid binding response arrives, then mark the pair valid
  and unblock whatever was gated on it (DTLS start, RTP send/receive);
- keep answering inbound checks exactly as today (browser-facing role
  unchanged).

Constraints: no API change; behavior only activates when remote STUN
credentials are set AND the endpoint never received an inbound check for
that media (i.e. the peer is lite) - or simply always, checks toward a
full peer are harmless.

Acceptance:
1. Two endpoints on one server, both with local+remote STUN credentials
   crossed and StartSending wired: assert binding request/response pairs
   are exchanged and media flows.
2. Browser-facing suite unchanged (inbound checks still answered).
3. xmlrpc_jsr309_api.md: note under EndpointSetRemoteSTUNCredentials that
   setting them enables outbound checks toward the StartSending address.
```

---

## Prompt P4 — `GetMediaCandidates` returns the per-media receive port (nice-to-have)

```
Context: GetMediaCandidates(sess, ep, proto, media) returns candidate
strings ("rtp://ip:port") whose port is not the media's actual receive
port; every controller (Java mediagw, Elixir elixip) works around it by
substituting the EndpointStartReceiving return into its a=candidate lines
("Gros HACK" comment in the Java IceInfo.updatePort).

Required change: when EndpointStartReceiving has already been called for
(media), GetMediaCandidates returns that media's actual receive port in
the candidate string; before StartReceiving, keep the current value
(controllers call StartReceiving first anyway).

Constraints: same return format (list of "rtp://ip:port" strings) — this
is a value fix, not a shape change; update the GetMediaCandidates section
of xmlrpc_jsr309_api.md accordingly.

Acceptance: StartReceiving(media=X) -> GetMediaCandidates(media=X) returns
the same port as StartReceiving's return, per media; legacy call order
(GetMediaCandidates first) unchanged.
```

---

## Prompt P5 — connectivity event on the event queue (nice-to-have)

```
Context: the JSR309 event queue (EventQueueCreate + HTTP long-poll, spec
section on events) has no positive "media is flowing" signal — only the
inactivity timeout (endpoint disconnected). Controllers synthesize their
"connected" event optimistically. For a test tool this weakens assertions:
elixip fires :ice_connected without proof.

Required change: emit a new event on the endpoint's queue the first time,
per media, that BOTH hold: (a) the DTLS handshake is complete (or the
media is not DTLS), and (b) a first RTP/SRTP packet was received. One
event per media, re-armed after an EndpointStopReceiving/StartReceiving
cycle. Payload mirrors the existing endpoint events:
[type, sessTag, endpointId, media] with a new type constant appended after
the existing ones (tolerant clients ignore unknown types - same
compatibility pattern as the EventQueueCreate sourceName gap).

Acceptance: loopback test (two endpoints wired): the event fires exactly
once per media per side after media starts; never fires when no media is
sent; documented in xmlrpc_jsr309_api.md next to the existing event types.
```

---

## Suggested sequencing with the elixip side

1. Run **P1** now — its report may downgrade P2/P3 to "already works",
   which unblocks elixip phase 4 (real-platform E2E) with no server change.
2. **P2** (and **P3** if required) before the elixip real-platform E2E
   (`webrtc_sdp_design.md` §2.9 phase 4) — they are its known blockers
   (Q4/Q5).
3. **P4/P5** any time; elixip's D6 workaround and synthetic
   `:ice_connected` are their client-side counterparts to remove
   (the detection is per-call and backward compatible in both cases).
