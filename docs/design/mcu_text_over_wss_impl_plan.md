# Text over WebSocket for a conference participant — implementation plan

Chantier **S5** of [mcu_module.md](mcu_module.md) §16.6; lifts limitation **L15**.
Companion of `jsr309_text_over_wss.md` (media-server repo), whose §11 states the
problem and whose §5-§7 carry the decisions this plan inherits (URL form, no
keepalive, omission instead of port 0, U+FFFD, bounded replay buffer).

Two repos are touched:

- **mediaserver** (`/home/ebuu/mediaserver`, C++): the *door on the conference
  API* — it does not exist. `ConfigureMediaConnection` has zero occurrence in
  `mcu/src/xmlrpcmcu.cpp`, the only WebSocket handler is
  `wsServer.AddHandler("/jsr309", &jsr309Manager)` (`main.cpp:478`), and
  `WSEndpoint` is reachable only through the JSR-309 stage.
- **elixip** (this repo): the mirror, in the MCU adapter
  (`apps/kelix_modules/lib/kelix/mod/mcu/adapter/conn.ex`), of what the JSR-309
  adapter already does (`MediaServerMendoozeConn.ex:762-857`, shipped
  2026-08-07). The SDP layer already parses and builds these sections
  (`transport: :ws`); nothing changes there.

## 1. Goal

A WebRTC participant of a **conference** gets real-time text: the browser
connects a WebSocket directly to the media server, whose frames are bridged
into the conference **text mixer** — so the participant chats with every other
leg, RTP T.140 phones included. The controller does signalling only (decision A
of `jsr309_text_over_wss.md` §7 stands: the WebSocket is terminated by the
media server).

**Explicit requirement (2026-08-08):** when a participant is admitted without
text — `:text` absent from the participant's media set (`requested_medias(opts)
∩ conf.medias`, adapter `init/1`) — the `m=text` section is **removed entirely
from the SDP answer**, WS *and* RTP forms alike. Never a port-0 echo: the
deployed Elioz client does not digest it (`jsr309_text_over_wss.md` §6.3). This
is a deliberate deviation from RFC 3264 §6 (which wants a rejected stream
answered with port 0); audio/video keep the RFC behaviour.

## 2. What exists, what is missing

| | JSR-309 (template, done) | Conference API (to build) |
|---|---|---|
| Configure RPC | `ConfigureMediaConnection` `(iiiiiss)` → ok (`xmlrpcjsr309.cpp:2799-2845`, `Endpoint.cpp:682-737`) | **missing** — nothing in `xmlrpcmcu.cpp` |
| Address to publish | `GetMediaCandidates` builds `ws://`/`wss://` from `RTPSession::GetAnnouncedIp()` + `WSEndpoint` statics (`Endpoint.cpp:741-800`) | **missing** — `StartReceiving` returns `(port, ip, fmtpByPt)` only (`xmlrpcmcu.cpp:2164`), no scheme, no URL |
| Token registry | `MediaSession::tokens`, token → endpoint (`MediaSession.cpp:1993-2045`) | **missing** — but `MultiConf` already has the RTMP precedent (`ParticipantTokens`, `multiconf.h:217, 222-224`) |
| WebSocket door | `/jsr309/<sessId>/<token>` → `MediaSession::onNewMediaConnection` (`JSR309Manager.cpp:300-359`) | **missing** — `MCU` implements no `WebSocketServer::Handler`; `MultiConf::GetRTPParticipant` is private (`multiconf.h:198-201`) |
| Media plane | `WSEndpoint`: WS ⇄ T.140/RED RTP, replay buffer 32/5 s, U+FFFD, BOM (`WSEndpoint.cpp`) | **partly reusable** — see D2: the conference bridge speaks `TextFrame` with the mixer, not RTP |
| Controller answer | `open_offered_receive(%{transport: :ws})` + `ws_answer_spec` + conditional omission (`MediaServerMendoozeConn.ex:762-857, 1327-1345, 1848-1864`) | adapter **rejects unconditionally** (`conn.ex:262-265` `ws_text_section?/1`, guard `transport == :rtp` in `answerable?/2` `conn.ex:1472-1479`) |

Two small pre-existing defects to fix on the way (found 2026-08-08):

- the MCU adapter's `@ws_text_protocols` (`conn.ex:1147`) is missing `TCP/WS` —
  the one proto the deployed Elioz client actually emits; the SDP layer accepts
  all four (`MediaServerMendoozeSdp.ex:644`). The list becomes useless anyway
  (detection moves to `transport: :ws`), so it is deleted, not fixed;
- the adapter-neutral facade `MediaServer.SdpTools` does not re-export
  `ws_url_attribute/1` — the MCU adapter is forbidden to call
  `MediaServer.Mendooze.Sdp` directly (facade moduledoc), so one `defdelegate`
  is added.

## 3. Decisions

- **D1 — one RPC, returning the URL.** The conference API gains a single
  `ConfigureParticipantMediaConnection(confId, partId, media, proto, token)`
  returning `(s url)`. No conference `GetMediaCandidates`: the JSR-309 pair
  exists for historical reasons; here the URL is known at configure time
  (scheme from `WSEndpoint::IsLocalSecure()`, host from
  `RTPSession::GetAnnouncedIp()` — or `--websocket-host` — port from
  `WSEndpoint::GetLocalPort()`, all already-global statics wired in
  `main.cpp:494-514`). The scheme is decided by the **server**, never the
  controller (decision B of the JSR-309 design).
- **D2 — the bridge sits at the mixer seam, not at a port swap.**
  `RTPParticipant` has no `Endpoint::Port` abstraction to swap: `TextStream
  text;` is a by-value member (`rtpparticipant.h:108`) whose input/output pair
  is copied once in `Init()` (`textstream.cpp:84-103`, no setter). The swap is
  therefore: stop the participant's **text RTP half** and run a new, small
  **`ParticipantTextWS`** component directly against
  `textMixer.GetSharedInput/GetSharedOutput(partId)` (the same shared pointers
  `MultiConf::CreateParticipant` wires at `multiconf.cpp:629-630`).
  Consequence: **no RTP, no RED, no payload types on this leg** — the bridge
  speaks `TextFrame` with the mixer in both directions. RED remains a per-RTP-leg
  affair that the other participants already negotiate; decision E of the
  JSR-309 design ("propose T140RED to the other leg") is satisfied for free by
  the mixer.
- **D3 — WebSocket path `/mcu/<confId>/<token>`.** `MCU` implements
  `WebSocketServer::Handler` (interface: `websocketserver.h:24-28`) and
  `main.cpp` registers `wsServer.AddHandler("/mcu", &mcu)` next to `/jsr309`.
  Resolution: parse confId + token (the `JSR309Manager::onWebSocketConnection`
  `StringParser` sequence is the template), `MCU::GetConferenceRef` (public,
  `mcu.h:53`), then a new `MultiConf::onNewMediaConnection(ws, token)` that
  looks the token up and hands the socket to the participant's
  `ParticipantTextWS`. Prefix routing is safe: handlers are matched by
  `uri.find(prefix)==0` in reverse map order (`websocketserver.cpp:389-408`)
  and `/mcu` vs `/jsr309` do not overlap.
- **D4 — tokens live in `MultiConf` and die with the participant.** Keyed
  token → `(partId)`, one fresh token per (re)configuration, reconnection on
  the same token tolerated (the bridge's `onOpen` closes the previous socket,
  like `WSEndpoint.cpp:35-44`). Unlike the JSR-309 side (known leak, risk #3 of
  its design), `DeleteParticipant` and conference teardown **remove** the
  participant's tokens and `End()` the bridge.
- **D5 — the URL is published in the gateway form** (decision D of the JSR-309
  design, unchanged): value protocol-relative (`//host:port/mcu/<confId>/<token>`),
  scheme carried by the attribute **name** (`a=ws` in clear, `a=wss` in TLS).
  `Sdp.ws_url_attribute/1` already produces the pair.
- **D6 — nothing else runs on the WS text leg.** No `StartReceiving`, no
  `StartSending`, no `SetTextCodec`, no crypto, no ICE, no `StartRTPTimeout`
  (the adapter already never arms text, `conn.ex:877-905`), no applicative
  keepalive. Teardown needs nothing new: `DeleteParticipant` does it (D4).
- **D7 — omission is the only failure mode, and the only "no".** Three cases,
  one behaviour:
  1. `:text` not in the participant's medias (**admit() without text**): every
     `m=text` section — WS *or RTP* — is omitted from the answer entirely;
  2. WS configuration fails (RPC fault, empty URL): section omitted, the
     audio/video legs and the call stand (mirror of
     `MediaServerMendoozeConn.ex:832-855`);
  3. the peer offers `a=setup:passive`: nobody would connect; section omitted
     (mirror of `conn.ex` guard at `MediaServerMendoozeConn.ex:769-778`).
  Edge case: an offer whose sections are **all** omitted yields an answer with
  zero m-lines, which is not an answer — reject the INVITE with 488.
- **D8 — the server defends the invariant D6 cannot see.** After the text port
  is switched to WS, `MultiConf::StartReceiving/StartSending(TEXT)` on that
  participant returns an error instead of silently opening a plain RTP text
  stream — today `proto` is ignored for non-BFCP media
  (`multiconf.cpp:1383-1442`), which is exactly the silent-RTP trap.

## 4. Server work (mediaserver repo, branch `feat/mcu-improvments`)

### S5.1 — the `ParticipantTextWS` bridge

New class under `mcu/src/` (not `jsr309/`): `WebSocket::Listener` + a small
pull thread. It owns:

- WS → mixer: `onMessageStart/Data/End` assemble the UTF-8 message into a
  `TextFrame` and call `textOutput->SendFrame(frame)` (what
  `TextStream::RecText` does at `textstream.cpp:380-395`, minus RTP/RED);
- mixer → WS: a thread looping `frame = textInput->GetFrame(timeout)` →
  `ws->SendMessage(utf8)` (the `TextStream::SendText` pull pattern,
  `textstream.cpp:414+`, minus the encoder);
- the **bounded pending buffer** (32 frames / 5 s) replayed at `onOpen`, and
  **U+FFFD** in both directions on close/reset — same policies as
  `WSEndpoint.cpp:35-68, 125-173, 197-244, 310-344`. Factor small shared
  helpers out of `WSEndpoint` where convenient (BOM ping-pong, pending-buffer),
  but do **not** try to reuse `WSEndpoint` itself: it inherits
  `Endpoint::Port`/`RTPMultiplexer` and throws for anything but the JSR-309
  wiring.

### S5.2 — the door in `MultiConf`

`MultiConf::ConfigureParticipantMediaConnection(partId, media, proto, token)`:

1. only `media == MediaFrame::Text && proto == MediaFrame::WS` is accepted
   (anything else: error — the enum row `MediaProtocol WS = 2` is already
   documented on this API, `MCU-API.md:176`);
2. resolve the `RTPParticipant`, stop its text RTP half
   (`StopReceiving/StopSending(TEXT)` — `rtpparticipant.cpp:285-297, 413-424`);
3. create the `ParticipantTextWS` on
   `textMixer.GetSharedInput/GetSharedOutput(partId)`; idempotent re-call
   replaces the token and tolerates the running bridge;
4. register token → partId (new map next to the RTMP `ParticipantTokens`,
   `multiconf.h:217-224`); build and return the URL (D1);
5. `DeleteParticipant`/`End()` remove the tokens and end the bridge (D4);
6. guard `StartReceiving/StartSending(TEXT)` while in WS mode (D8).

`MultiConf::onNewMediaConnection(WebSocket*, token)`: lookup → 404 on unknown
token (mirror `MediaSession.cpp:2050-2079`), else `Accept` on the bridge.

### S5.3 — XML-RPC + WebSocket registration

- `xmlrpcmcu.cpp`: handler `ConfigureParticipantMediaConnection` `(iiiis)` =
  `confId, partId, media, proto, token` → `(s url)`, next to `StartReceiving`
  (`:2012`), dispatch-table entry near `:2479`;
- `MCU` implements `WebSocketServer::Handler::onWebSocketConnection`, parsing
  `/mcu/<confId>/<token>` (template: `JSR309Manager.cpp:300-359`);
- `main.cpp`: `wsServer.AddHandler("/mcu", &mcu)` beside `:478`;
- `MCU-API.md`: document the new RPC (§6.5/§6.7), the `/mcu/...` WS door and
  the UAS sequence variant (WS text leg: configure **instead of**
  StartReceiving/SetTextCodec).

### S5.4 — server tests

Smoke/unit, against the binary as for the JSR-309 phases: the RPC returns a
`ws://` URL in clear and `wss://` with `--websocket-secure`; a connection on
`/mcu/<confId>/<token>` is accepted, unknown token → 404; text typed on the
WebSocket comes out as T140/T140RED RTP on another participant's leg and
conversely (the mixer path); replay buffer at `onOpen`; U+FFFD on close;
`DeleteParticipant` closes the socket and frees the token;
`StartReceiving(TEXT)` after the switch fails (D8).

## 5. Controller work (elixip repo)

### C5.0 — chores (no behaviour change elsewhere)

- `MediaServerSdpTools.ex`: `defdelegate ws_url_attribute(url)` (facade gap);
- `conn.ex`: delete `@ws_text_protocols`/`ws_text_section?/1` protocol
  matching — detection keys on the parsed `transport: :ws` (which already
  covers the four protos, `TCP/WS` included).

### C5.1 — the WS text path in `Kelix.Mod.Mcu.Adapter.Conn`

Mirror of `MediaServerMendoozeConn.ex:762-857`, transposed:

- in `handle_call({:set_remote_offer, sdp})` (`conn.ex:240-286`): drop the
  unconditional `Enum.reject(&ws_text_section?/1)`; a `transport: :ws` desc
  with `:text` in `state.medias` and peer setup ≠ `passive` goes through:
  - mint the token (reuse the `ws_token()` shape,
    `MediaServerMendoozeConn.ex:1357-1367`),
  - one RPC: `ConfigureParticipantMediaConnection(conf_id, part_id,
    @media_int.text, @proto_ws, token)` → URL (note `@proto_ws 2` joins the
    constants at `conn.ex:44-58`),
  - answer spec: `Sdp.ws_url_attribute(url)`, proto mirroring the offer,
    `t140` literal, `a=setup:passive`, `a=connection:new`, port = the WS
    server port taken from the URL, no rtpmap/fmtp/crypto (the SDP layer's
    `build_media` WS clause does this already,
    `MediaServerMendoozeSdp.ex:333-340`);
- `answerable?/2` (`conn.ex:1472-1479`): stays RTP-only; the WS desc takes its
  own branch, as on the JSR-309 side;
- **never** for this leg: `StartReceiving`, `StartSending`
  (`start_sending_all/1` `conn.ex:907-928` filters it out), `SetTextCodec`,
  crypto, watchdog (already text-free, `conn.ex:877-905`);
- failure of the RPC → log + omit the section, the call stands (D7.2);
- teardown unchanged: `DeleteParticipant` (`conn.ex:1486-1499`) closes the
  socket server-side (D4).

### C5.2 — whole-section omission on admit() without text (the 2026-08-08 requirement)

When `:text ∉ state.medias` (participant admitted without text — the media set
is fixed in the adapter's `init/1` as `requested_medias(opts) ∩ conf.medias`):

- **every** `m=text` section of the offer is omitted from the answer — the WS
  form (as today) **and the RTP form**, which today is declined with port 0
  via `reject_spec/1` (`conn.ex:1155-1162`). The omission happens where the
  answer is assembled (`conn.ex:262-265`), keyed on `desc.type == :text and
  :text not in state.medias`;
- port-0 stays the behaviour for rejected **audio/video** sections (RFC 3264);
- if the omissions leave an answer with zero m-lines, the offer is refused:
  `{:error, :no_media}` → 488 from the script path (D7 edge case);
- re-INVITE follows: a text section appearing mid-call on a text-less
  participant is omitted again (the media set does not change after admit).

### C5.3 — Mockup (optional alignment)

`MediaServerMockup.ex:412-424` declines `transport: :ws` with port 0. Align on
omission so call-flow tests rehearse the real adapters' behaviour, and update
`media_mockup_test.exs:186-197` accordingly. Small, isolated, can ship with
C5.1 or be dropped.

### C5.4 — tests

| File | Change |
|---|---|
| `apps/kelix_modules/test/mcu_webrtc_test.exs:276-289, 436-448` | the two "omitted, not declined" tests are **rewritten**: with text admitted and the stub answering the new RPC, the answer carries `m=text`, `a=ws`, `a=setup:passive`, `a=connection:new`, no rtpmap/fmtp/crypto |
| `apps/kelix_modules/test/support/mcu_stub.exs` | add the `ConfigureParticipantMediaConnection` handler (returns a canned URL; a failing variant for the omission test) |
| new tests (same file or `mcu_webrtc_test.exs`) | mirror the four JSR-309 tests (`mendooze_conn_test.exs:1243-1355`): answered with URL; `a=wss` when the stub returns `wss://`; peer `a=setup:passive` → omitted; RPC failure → text lost, call stands |
| **admit() without text** | offer with audio+video+text (RTP **and** WS fixtures): answer has **no `m=text` at all** (`refute answer =~ "m=text"`), audio/video answered; offer with text only → 488 |
| `apps/kelix_modules/test/mcu_call_test.exs:836-925` | the RTP T.140 path must keep passing untouched (text admitted, RTP offer → unchanged rtpmap/RED/SetTextCodec behaviour) |
| `apps/kelix_modules/test/mcu_secure_test.exs` | assert no crypto lines on the WS text section of a secure call |

### C5.5 — docs & memory

- `docs/design/mcu_module.md`: lift **L15**, rewrite **§16.6 (S5)** as
  "shipped" pointing here, add the answer rule (text omission on admit without
  text) to the §6 answer rules and the API table (`StartReceiving` untouched;
  new RPC row);
- `jsr309_text_over_wss.md` §11 (media-server repo): point to this plan;
- memory `jsr309-text-over-wss` / `mcu` notes: update once shipped.

## 6. Phasing

| # | Repo | Deliverable | Depends on |
|---|---|---|---|
| 1 | mediaserver | `ParticipantTextWS` bridge (S5.1) | — |
| 2 | mediaserver | `MultiConf` door + token map + guards (S5.2) | 1 |
| 3 | mediaserver | XML-RPC + `/mcu` WS handler + `MCU-API.md` (S5.3) | 2 |
| 4 | elixip | chores C5.0 | — |
| 5 | elixip | adapter WS path (C5.1) + stub/tests (C5.4) | 3 (for E2E; stub-level work can start against the S5.3 contract) |
| 6 | elixip | **whole-section omission on admit() without text** (C5.2) | 4 — independent of the server phases, can ship first |
| 7 | elixip | mockup alignment (C5.3) | — |
| 8 | both | E2E against the real binary: browser WS ⇄ RTP T.140 phone through the mixer; then the Elioz interop campaign | 1-6 |

Phase 6 is deliberately independent: it fixes today's port-0 echo on RTP text
for text-less admits, needs no server change, and can land immediately.

## 7. Risks

1. **Security** — same as JSR-309 (its risk #1): the token travels in SDP; in
   clear (`ws://`) the text is readable on the wire. TLS
   (`--websocket-secure`) is the remedy; nothing new here.
2. **The pull thread's lifecycle** is the one genuinely new server mechanism
   (JSR-309 had `RTPMultiplexer` instead): it must stop cleanly on
   `DeleteParticipant`, `End()`, and on re-configuration — `GetFrame(timeout)`
   + `Cancel()` (`text.h:121-132`) is the existing pattern (`TextStream`
   stops its `sendTextThread` the same way).
3. **Client TLS defect n°6** (repo-version Elioz reads only `a=ws`): the
   fallback — absolute `https://` URL under `a=ws` — is proven on the deployed
   client (2026-08-07) and applies identically here.
4. **Ordering with other MCU chantiers**: `conn.ex` is also the landing zone
   of S3/P8 leftovers; rebase cost only, no coupling.
5. **RFC 3264 deviation** (C5.2): omission of the RTP text m-line is
   non-compliant on purpose. A strict SIP endpoint re-INVITEing over the
   shorter answer should be exercised once in interop; the mismatch is benign
   (the omitted stream simply does not exist for us).

## 8. Non-goals

- No text for RTMP/broadcast participants; no conference-side RED negotiation
  on the WS leg (D2 makes it meaningless); no applicative keepalive; no
  "text connected" MCU event (can join the `MCU::Events` enum later if a
  script ever needs it); no change to the JSR-309 path.
