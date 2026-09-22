# ws-text-client-plan.md — the client-mode WebSocket text leg

**Status: lots 1 to 6 done, lot 7 ready to run (§7).** The framework side of real-time
text is [DESIGN-FRAMEWORK.md](DESIGN-FRAMEWORK.md#65-webrtc-sdp); this document is
what gets built to drive a media server that plays the browser, in which order,
and what proves each step.

## 1. What this chantier delivers

One new value of one leg option:

```elixir
send_INVITE(target, :mediaserver,
  webrtc: :yes,
  media: [:audio, :video, :text],
  text_transport: :ws            # the new one
)
```

With it, elixip offers `m=text … TCP/WSS t140` as an **active** endpoint, reads
the URL the answerer publishes, and tells the media server to open a WebSocket
towards it. Audio and video stay in RTP on the same endpoint.

That is the missing half of an automated Total Conversation test: today the text
peer of a WebRTC call has to be a real browser.

## 2. Where each side stands

| Piece | Side | State |
|---|---|---|
| WebSocket **server** text leg (a peer knocks, we answer a URL) | elixip | was already there — `open_offered_receive/2`, `ws_answer_spec/2` |
| WebSocket **client** text leg (the server dials out) | media server | lots 0–6 on branch `feat/wss-client` (`docs/conception/WS-CLIENT/SPEC.md`) |
| `ConnectMediaConnection(sessionId, endpointId, media, role, url)` | media server | done (`mcu/src/jsr309/xmlrpcjsr309.cpp`) |
| the same verb on the control plane | elixip | lots 3 and 4 |
| offering a text-over-WebSocket section | elixip | lot 2 |
| reading the answer's URL | elixip | lot 1 |

**Prerequisite**: the media server must run a `feat/wss-client` build. Against
an older one, `ConnectMediaConnection` is an unknown method, and the text medium
is dropped with a warning (§4.4) rather than losing the call.

## 3. What the media server does with the leg

From `WS-CLIENT/SPEC.md`, and it shapes what elixip may expect:

- `ConnectMediaConnection` **arms** the leg. Its success does not mean the
  WebSocket is open. Only an unusable URL is an immediate fault.
- the opening has a 10 s deadline, and a failed or lost connection is retried
  **every 5 s, indefinitely**, until the leg is destroyed;
- `EndpointConnectedEvent` (7) fires at **every** opening,
  `EndpointDisconnectedEvent` (6) at every loss of an established connection. A
  failed *attempt* publishes nothing. Both already carry `(joinableId, media,
  role)` and elixip already maps them to `{:media_connected, :text}` and
  `{:media_timeout, :text}`;
- in client mode the server publishes **no local URL**: `GetMediaCandidates`
  returns the configured remote URL, and `GetLocalMediaPort` fails. So nothing
  in our offer can come from the server.

## 4. Design

### 4.1 The offer we emit

Shaped after the deployed Elioz/WebRTComm client, which is what the IVeS gateway
answers every day:

```
m=text 9 TCP/WSS t140
a=setup:active
a=connection:new
a=sendrecv
```

- **`a=setup:active`** is the whole point: we connect, the peer hosts. Our own
  answerer declines a `passive` offer for the symmetric reason;
- **no `a=ws` / `a=wss` attribute**: we have no URL to publish;
- the **port is decorative** — an active endpoint binds nothing, and RFC 4145 §4
  puts the discard port there;
- the **protocol is decorative too**: the scheme that matters is the one in the
  answer's attribute *name*. Our answerer echoes the offered protocol verbatim,
  and so does the gateway.

`Sdp.build/1` already built this section (`build_media/1` on the `ws_text` key,
with `setup:` overridable and a `nil` URL emitting no attribute). No SDP
construction was added.

### 4.2 Nothing happens at offer time

A client-mode text leg opens **no receive plane**: `ConnectMediaConnection` does
the port switch itself, and it needs the URL we do not have yet. So
`start_receiving_all/2` skips the medium entirely — no `ConfigureMediaConnection`
(it demands a token, meaningless here), no `EndpointStartReceiving`, no
`GetMediaCandidates`.

Two consequences, both held by code:

- `offer_media_spec/3` must not reach for `state.local_ports[:text]` — it is
  absent. The medium has its own branch, keyed like the data channel one;
- the session's `c=` line can never come from this leg. A leg whose **only**
  medium is a client-mode WebSocket therefore has no offer to build at all, and
  says so (`:no_local_media_address`) instead of emitting an SDP with no address.

### 4.3 The arming, on the answer

`apply_remote_media/3` already had a `transport: :ws` clause that did nothing —
correct for the server mode, and the exact hook for this one. When the leg
offered `:ws`, it calls:

```
ConnectMediaConnection(sess_id, endpoint_id, 2 /* text */, 0 /* main */, url)
```

`url` is the answer's `a=ws` / `a=wss` value, made absolute (§4.5).

The two roles are told apart by `ws_urls`: a leg that **minted** a URL is the
server of its own WebSocket. Both can carry `text_transport: :ws` in their
options, so the option alone does not answer the question.

### 4.4 A text failure is not a call failure

The policy already applied to both other text transports, kept verbatim: no URL
in the answer, an unusable one, or an RPC error is logged as a warning, the text
medium is dropped from the leg, and the audio/video call stands.

Dropping it from the leg — not merely leaving it un-negotiated — is what keeps a
player from attaching to a text port the media server holds nothing for, which
would fail the whole playback.

### 4.5 The scheme travels in the attribute name

`find_ws_url/1` returned the attribute *value* and forgot which attribute it came
from. The historical gateway publishes protocol-relative values
(`//host:port/path`), so `ws` and `wss` were indistinguishable — and
`ConnectMediaConnection` needs an absolute URL. The parser now returns an
absolute one, using the attribute name as the scheme. `ws_url_attribute/1`
already did the reverse direction and names the rule.

## 5. Lots

Each lot compiles, passes `mix test` for its app, and ships alone.

| Lot | Content | Proof |
|---|---|---|
| 1 ✔ | `find_ws_url/1` keeps the scheme and yields an absolute URL | `mendooze_sdp_test.exs`: both attribute names crossed with the three value forms. No behaviour change for the answerer, which ignores the field |
| 2 ✔ | `text_transport: :ws` accepted (`MediaServer.ex` typedoc included); the offer section; no receive plane; the `offer_media_spec/3` branch; no offer without a local address | `mendooze_conn_test.exs`: the offer carries `m=text 9 TCP/WSS t140`, `a=setup:active` and no `a=ws`; no `ConfigureMediaConnection`, `EndpointStartReceiving` or `GetMediaCandidates` for text; a text-only leg answers `:no_local_media_address` |
| 3 ✔ | the arming on the answer + the failure policy | `mendooze_conn_test.exs`: `ConnectMediaConnection` called with the answer's absolute URL; an answer without a URL and a server that refuses the verb each keep the call and drop the medium, player attachments included |
| 4 ✔ | `ConnectMediaConnectionReq` in `moteli_jsr309.proto` | the file's own rule: the `/jsr309` API and this file change together |
| 5 ✔ | the broadened meaning of events 6 and 7 for a WS text leg — **verification only, no code changed**: `receiving_medias/1` already excludes `:ws` from R | `mendooze_conn_test.exs`: a text opening emits `{:media_connected, :text}` and does **not** release `:ice_connected`; a text loss emits `{:media_timeout, :text}` and no `:media_lost` |
| 6 ✔ | `scenarios/uac_invite_webrtc.exs`, `DESIGN-FRAMEWORK.md#65` | reading: the design says what we offer as a client and what we still never offer as a server |
| 7 | end-to-end recette | a real call, `WS-CLIENT/SPEC.md` §7: a three-track `.mp4` played to an Asterisk echo through the WebRTC gateway, the return recorded and compared. Its prerequisite is now met (§7) |

Lots 1 to 5 touch no scenario and no document: they are useful alone and change
nothing for a leg that does not ask for `:ws`.

## 6. Arbitrages

Settled on 2026-09-22.

| Question | Decision | What it rules out |
|---|---|---|
| the offered port | `9` (RFC 4145 §4 for an active endpoint) | a dummy RTP-shaped number, as the deployed client emits: it names a port nothing holds |
| the offered protocol | `TCP/WSS`, fixed | an option for a token that decides nothing — the scheme comes from the answer attribute's name |
| `:ws` off a WebRTC leg | allowed anywhere | the `:data_channel` treatment (logged, falls back to RTP): a WebSocket is beside the call, not inside its DTLS, so there is nothing to fall back from |
| the recette scenario | extend `uac_invite_webrtc.exs` | a second, nearly identical Total Conversation scenario to keep in step |

## 7. Playing and recording at once

The recette plays a three-track `.mp4` **and** records what the echo returns, on
the same leg, at the same time. A media action used to be single-slot per leg:
a connection played, recorded or echoed, and the second request was dropped with
a warning.

The slot is now **per leg and per kind** (`SIP.Session.Media`). A player feeds
what an endpoint sends and a recorder takes what it receives — opposite
directions, wired by two media server calls that never touch each other, and the
media server has carried both at once all along. Only a second action of the
**same** kind on one leg is still refused.

What it changes for a scenario:

| Before | Now |
|---|---|
| one handle per leg, `media_action(ctx, leg)` → `{kind, handle}` | one per kind, `media_action(ctx, kind, leg)` → handle |
| appdata `:mediaactionid` / `:mediaaction` | `:mediaplayerid`, `:mediarecorderid`, `:mediaechoid` (bare key for `:inbound`, `{key, leg}` otherwise) |
| `media_stop()` stopped the one action | stops **every** action of the leg; `media_stop(kind: :player)` stops one; `leg: :all` still spans the legs |

A `kind:` typo raises `ArgumentError` at the call, rather than stopping nothing
and losing a recording with no line to say why.

`scenarios/uac_invite_webrtc.exs` is the shape the recette wants: the recorder
starts **before** the player (what comes back begins arriving as soon as we
send), and the player's EOF leads to a `draining_record` state that keeps
recording for 3 s — the echo's return lags the source, and without that tail the
returned file stops short of its end.

Two weaker forms were rejected: playing and recording in two passes (it no
longer proves a round trip), and driving a Recorder around the macros (it moves
the limitation instead of lifting it).

## 8. Out of scope

- the conference participant text leg (`ParticipantTextWS`), which stays server
  only on the media server side, so the MCU module is untouched;
- offering a WebSocket **as a server** in our own offers. That remains what it
  was: a door we open when a peer knocks;
- audio and video, which stay in RTP — "playing the browser" concerns the text
  channel only;
- the `MediaServer.Mockup`, which has no WebSocket to open. A `:ws` leg is a
  Mendooze one; the Mockup keeps offering text over RTP.
