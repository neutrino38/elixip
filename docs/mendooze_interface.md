# MediaServer.Mendooze — Interface Design

Revision 2 — aligned with the updated server documentation
[`xmlrpc_jsr309_api.md`](https://github.com/neutrino38/mediaserver/blob/feat/alma_linux9/xmlrpc_jsr309_api.md)
(branch `feat/alma_linux9`). All six API gaps identified in revision 1 are now
implemented server-side; this document integrates them and refines the Elixip
implementation plan (§12).

## 1. Overview

`MediaServer.Mendooze` implements `MediaServer.Behaviour` against the
**Mendooze MCU** (fork at `neutrino38/mediaserver`, branch `feat/alma_linux9`).
We use the **JSR309** XML-RPC interface exclusively.

| Channel | Endpoint | Notes |
|---------|----------|-------|
| Control | `POST http://<host>:8080/jsr309` | standard XML-RPC, `Content-Type: text/xml` |
| Events  | `GET http://<host>:8080/events/jsr309/<queueId>` | HTTP chunked long-poll (§5) |
| Media (WebRTC/WS) | `ws://<host>:9090/jsr309` | **out of scope** for the initial implementation |

### 1.1 Response envelope

Every method returns the same XML-RPC struct — success is signalled by
`returnCode`, **not** by an XML-RPC fault:

```
success: { "returnCode": 1, "returnVal": [ ... ] }   # [] for void commands
failure: { "returnCode": 0, "errorMsg": "..." }      # HTTP 200 nonetheless!
```

A real XML-RPC fault (HTTP 500) only occurs on parameter parsing errors. The
Elixir client must check `returnCode == 1` after **every** call and surface
`errorMsg` otherwise. Created ids are integers ≥ 0; a negative id also means
failure. On a mid-setup failure, run the teardown sequence (§11) so no
session/endpoint leaks server-side.

All strings are UTF-8. Parameters are positional — order matters.

---

## 2. Mendooze JSR309 Concepts

The server organises resources in a two-level hierarchy (mixers/transcoders
omitted — not used by the initial implementation):

```
MediaSession  (sessionId, tag)
  └── Endpoint  (endpointId)  ← one RTP/SRTP/DTLS connection (audio+video+text)
        (joined to) Player / Recorder / other Endpoint / Mixer …
```

An **EventQueue** is server-side; the client creates one queue per `connect/1`
and reads events via HTTP long-poll. Events of a session are routed to the
queue whose `queueId` was passed to `MediaSessionCreate`.

**Events carry tags, not numeric ids** (except endpoint events which carry
`joinableId`): `sessionTag` is the string passed to `MediaSessionCreate`,
`playerTag` / `recorderTag` the names passed to `PlayerCreate` /
`RecorderCreate`. Since Elixip chooses those names, event routing is by tag —
see §5.2.

---

## 3. Process Architecture

Only **two GenServer modules** are needed:

```
MediaServer.Mendooze              (server pid — connect/disconnect)
  ├── MediaServer.Mendooze.EventPoller   (Task — HTTP chunked long-poll)
  └── MediaServer.Mendooze.Conn          (one GenServer per peer connection)
```

Player, Recorder, and Echo are **not processes** — they are entries in the
Conn state map. The reference returned to the caller is an opaque tuple
`{conn_pid, :player | :recorder | :echo, make_ref()}` that routes directly
back to the Conn GenServer (already reflected in
`MediaServer.resource_ref/0`).

### 3.1 Server state (`MediaServer.Mendooze`)

```elixir
%{
  base_url:    String.t(),    # "http://host:8080"
  queue_id:    integer(),     # from EventQueueCreate
  source_path: String.t(),    # sourceName, e.g. "/events/jsr309/7"
  poller:      pid(),         # EventPoller task
  conns:       %{String.t() => pid()}   # session_tag → Conn pid  (or ETS)
}
```

### 3.2 Conn state (`MediaServer.Mendooze.Conn`)

```elixir
%{
  server:      pid(),
  event_sink:  pid(),
  sess_id:     integer(),
  sess_tag:    String.t(),    # unique, chosen by us, key for event routing
  endpoint_id: integer(),
  opts:        keyword(),
  medias:      [0 | 1],       # MediaFrame::Type values active on this conn
  local_ports: %{audio: integer() | nil, video: integer() | nil},
  status:      :init | :active | :closed,

  # sub-resources — server ids AND tags stored here
  players:   %{reference() => %{player_id: integer(), tag: String.t(), opts: keyword()}},
  recorders: %{reference() => %{recorder_id: integer(), tag: String.t(),
                                file: String.t(), opts: keyword()}},
  echo:      nil | reference()   # at most one echo per endpoint
}
```

### 3.3 Tag naming convention

Tags are the event-routing keys, so they must be unique:

- `sess_tag` — `"cx-" <> <unique integer>` (from `:erlang.unique_integer/1`),
  one per Conn; also used as the `EndpointCreate` name.
- `playerTag` / `recorderTag` — `"p-<n>"` / `"r-<n>"`, unique **within** the
  session (a per-Conn counter).

### 3.4 Media parameter

`media` is a single `MediaFrame::Type` integer (`0`=audio, `1`=video,
`2`=text). **There is no combined audio+video value** — every per-media call
(`Attach…`, `Dettach`, `StartSending/Receiving`, crypto, watchdog…) is
repeated for each entry of `state.medias`. The `MediaServer.media_kind()`
`:audio_video` therefore expands to two RPC calls everywhere.

---

## 4. `MediaServer.Behaviour` → JSR309 Mapping

### 4.1 `connect/1`

```
EventQueueCreate()  → [queue_id, source_name]
```

Start the `EventPoller` task on `{base_url}{source_name}`. Tolerant decoding:
if `returnVal[1]` is absent (older server), fall back to
`"/events/jsr309/#{queue_id}"`. Return `{:ok, server_pid}`.

### 4.2 `disconnect/2`

```
EventQueueDelete(queue_id)
```

The server closes the event stream when the queue is deleted, which ends the
poller task naturally (also `Task.shutdown/2` as belt-and-braces). All Conn
GenServers are already stopped by their callers (teardown order §11); with
`force: true`, close any remaining Conn first.

### 4.3 `create_peer_connection/3`

```
MediaSessionCreate(sess_tag, queue_id)                       → sess_id
EndpointCreate(sess_id, sess_tag, audio?, video?, text=false) → endpoint_id
```

`audio?`/`video?` derive from `conn_opts[:media]` (default `:audio_video`).
Spawn `MediaServer.Mendooze.Conn`; register `sess_tag → conn_pid` in the
server registry. Return `{:ok, conn_pid}`.

**Codec mapping** from `conn_opts`:

| `conn_opts` key        | JSR309 usage                                        |
|------------------------|-----------------------------------------------------|
| `audio_codec`          | rtp_map of `EndpointStartReceiving/StartSending`    |
| `video_codec`          | idem for video                                      |
| `webrtc_support`       | selects the DTLS/ICE path in §4.4–4.6               |
| `ice_servers`          | ignored initially (no full ICE agent server-side)   |

### 4.4 `get_local_offer/1` — UAC flow (doc §9.2)

Inside the Conn GenServer, for each media:

1. Local security (before any media starts):
   - DTLS: `EndpointGetLocalCryptoDTLSFingerprint("sha-256")` → `fingerprint`
     (global call — no `sessionId`)
   - ICE: `EndpointSetLocalSTUNCredentials(S, EP, media, ufrag, pwd)`
     (ufrag/pwd generated locally, published in the SDP)
   - SDES (non-WebRTC SRTP): `EndpointSetLocalCryptoSDES(S, EP, media, suite, key)`
2. `EndpointStartReceiving(S, EP, media, rtp_map)` → local port
3. `GetMediaCandidates(S, EP, protocol=0 /*RTP*/, media)` → `"rtp://ip:port"`
   — the authoritative local address for the SDP `c=`/`m=` lines (do **not**
   derive it from `base_url`)
4. Build the SDP offer with `ExSDP`: local ports + candidates + local crypto
   (`a=fingerprint`, `a=setup:actpass`, `a=ice-ufrag/pwd`) + offered payload
   types (mirror of the `rtp_map` used in step 2).

Store `local_ports`. Return `{:ok, sdp_string}`.

### 4.5 `set_remote_answer/2` — UAC flow, continued

Parse the SDP answer with `ExSDP`; for each media:

```
EndpointSetRTPProperties(S, EP, media, %{"rtcp-mux" => "1", ...})   # from answer attrs
EndpointSetRemoteCryptoDTLS(S, EP, media, setup, hash, fingerprint) # or SDES / none
EndpointSetRemoteSTUNCredentials(S, EP, media, ufrag, pwd)          # if ICE
EndpointStartSending(S, EP, media, remote_ip, remote_port, rtp_map) # codecs retained
EndpointStartRTPTimeout(S, EP, media, timeout_ms)                   # arm watchdog LAST
```

Remote security is set **before** `EndpointStartSending`; the watchdog is
armed **after** the answer has been processed (doc §9.6), so no false
`EndpointDisconnectedEvent` fires during ringing. Then send
`{:ms_event, conn_pid, :ice_connected}` to `event_sink` — mendooze has no
"media flowing" event; loss of media is what gets reported (event 6).

### 4.6 `set_remote_offer/2` — UAS flow (doc §9.1)

For each media of the offer:

1. `EndpointSetRTPProperties(S, EP, media, props)` — offer attributes
2. Remote security from the offer (`SetRemoteCryptoDTLS`/`SDES`,
   `SetRemoteSTUNCredentials`)
3. Local security for the answer (fingerprint / local STUN credentials / SDES key)
4. `EndpointStartReceiving(S, EP, media, rtp_map)` → local port
5. `GetMediaCandidates(S, EP, 0, media)` → local address
6. `EndpointStartSending(S, EP, media, remote_ip, remote_port, rtp_map)`

Then build the answer SDP (`a=setup:active`), arm the watchdog
(`EndpointStartRTPTimeout`) and send `:ice_connected`. Return
`{:ok, answer_sdp}`.

> Note: the server doc arms the watchdog *after the 200 OK is emitted on the
> wire*. The behaviour has no "answer sent" callback, so we arm it when
> `set_remote_offer/2` returns — the answer leaves within milliseconds; the
> few-ms early start of a multi-second timeout is harmless for a test tool.

### 4.7 `add_remote_candidate/2`

~~No-op~~ **Now supported** (gap #1 closed):

```
EndpointAddICECandidate(S, EP, media, candidate)
```

`candidate` is the SDP `candidate:` attribute line (prefix optional). The
server only retains the RTP-component UDP `host`/`srflx` candidate and
re-targets sending if its priority is higher — a "lite" behaviour, no full ICE
agent (no connectivity checks). The Conn extracts the media from the
`sdpMLineIndex`/`mid` if provided by the caller, else applies it to audio.

### 4.8 `close_peer_connection/1`

Inside `Conn.terminate/2`, per media then per object (doc §9.5):

```
EndpointStopSending(S, EP, media)      # per media
EndpointStopReceiving(S, EP, media)
EndpointDettach(S, EP, media)          # if anything attached
EndpointDelete(S, EP)
MediaSessionDelete(S)                  # cascades any leftovers
```

Send `{:ms_event, conn_pid, :closed}` to `event_sink`; unregister `sess_tag`.

### 4.9 `create_player/3`

```
PlayerCreate(S, player_tag)                       → player_id
PlayerOpen(S, player_id, file_path)
EndpointAttachToPlayer(S, EP, player_id, media)   # per media
```

If `start_time` opt present: `PlayerSeek(S, player_id, start_time_ms)`.

Store `%{player_id: player_id, tag: player_tag, opts: opts}` in
`state.players[ref]`. Return `{:ok, {conn_pid, :player, ref}}`.

### 4.10 `start_player/1`

```
PlayerPlay(S, player_id)
```

No synthetic event: the server emits `PlayerStartedEvent` (type 3), which the
poller routes back as `:player_started` (§5.1). Gap #2 closed.

### 4.11 `pause_player/1`

```
PlayerStop(S, player_id)   # pause — does not delete
```

(Resume = `PlayerPlay` again; `loop` opt = re-`PlayerSeek(0)` + `PlayerPlay`
on `:player_ended`, handled inside Conn.)

### 4.12 `stop_player/1`

```
PlayerStop(S, player_id)
EndpointDettach(S, EP, media)          # per media
PlayerClose(S, player_id)
PlayerDelete(S, player_id)
```

Remove entry from `state.players`.

### 4.13 `create_recorder/4`

```
RecorderCreate(S, recorder_tag)                        → recorder_id
RecorderAttachToEndpoint(S, recorder_id, EP, media)    # per media
```

Store `%{recorder_id: …, tag: …, file: file_path, opts: opts}`. The
`duration_ms` argument is kept for `start_recorder/1` — **no client-side
fallback timer anymore** (gap #4 closed): the server enforces `maxDuration`.

`stop_on_silence` / `stop_on_dtmf` opts: the server defines the corresponding
stop reasons (2, 3) but does **not implement them yet** — log a warning and
ignore these opts for now (§6, residual limitations).

Return `{:ok, {conn_pid, :recorder, ref}}`.

### 4.14 `start_recorder/1`

```
RecorderRecord(S, recorder_id, file_path, duration_ms)   # 4th param optional, 0 = unlimited
```

No synthetic event: the server emits `RecorderStartedEvent` (type 4) →
`:recorder_started`. Gap #3 closed.

### 4.15 `stop_recorder/1`

```
RecorderStop(S, recorder_id)
RecorderDettach(S, recorder_id, media)   # per media
RecorderDelete(S, recorder_id)
```

Remove from `state.recorders`. The server emits `RecorderStoppedEvent(reason=0)`
on `RecorderStop` → `{:recorder_stopped, :caller}`; do not synthesise it.

### 4.16 `create_echo/1`

```
EndpointAttachToEndpoint(S, EP, EP, media)   # per media — source = itself
```

Store `ref` in `state.echo`. Send
`{:ms_event, {conn_pid, :echo, ref}, :echo_started}` (no server event for
attaches). Return `{:ok, {conn_pid, :echo, ref}}`.

### 4.17 `stop_echo/1`

```
EndpointDettach(S, EP, media)   # per media
```

Clear `state.echo`.

---

## 5. Event Poller

`MediaServer.Mendooze.EventPoller` is a supervised `Task`:

```
GET {base_url}{source_path} HTTP/1.1        # e.g. /events/jsr309/7
```

The server responds with `Transfer-Encoding: chunked`, `Content-Type:
text/xml`, and keeps the connection open (up to 30 s per cycle):

- each event is one serialised XML-RPC `<methodResponse>` containing the event
  tuple, whose **first int is the event type**;
- a bare `\r\n` chunk is a **keep-alive** — skip it, it is not an event;
- the stream closes when the queue is deleted (`EventQueueDelete`) → normal
  poller termination.

The poller decodes each `<methodResponse>` and casts the decoded tuple to the
server GenServer.

### 5.1 Event dispatch table

All six event types are now implemented server-side (`JSR309Event.h`; the
numeric codes are a wire contract — never reordered):

| # | Server event | Tuple payload | Routed as |
|---|--------------|---------------|-----------|
| 1 | `PlayerEndOfFileEvent` | `(sessionTag, playerTag)` | `{:ms_event, {conn, :player, ref}, :player_ended}` |
| 2 | `ExternalFIRRequestedEvent` | `(sessionTag, joinableId, media, role)` | internal — `EndpointRequestUpdate(S, EP, media)` |
| 3 | `PlayerStartedEvent` | `(sessionTag, playerTag)` | `{:ms_event, {conn, :player, ref}, :player_started}` |
| 4 | `RecorderStartedEvent` | `(sessionTag, recorderTag)` | `{:ms_event, {conn, :recorder, ref}, :recorder_started}` |
| 5 | `RecorderStoppedEvent` | `(sessionTag, recorderTag, reason)` | `{:ms_event, {conn, :recorder, ref}, {:recorder_stopped, reason}}` |
| 6 | `EndpointDisconnectedEvent` | `(sessionTag, joinableId, media, role)` | `{:ms_event, conn_pid, :media_timeout}` (see §7) |

Recorder stop reasons: `0 → :caller`, `1 → :duration`, `2 → :silence`,
`3 → :dtmf` (2 and 3 not emitted yet server-side).

### 5.2 Dispatch mechanics

The server GenServer resolves `sessionTag → conn_pid` (its registry) and casts
the event to the Conn, which resolves `playerTag`/`recorderTag → ref` from its
own state and forwards the translated `{:ms_event, …}` to `event_sink`.
Unknown tags are logged and dropped (late events after teardown are expected).

### 5.3 Reconnect policy

On HTTP connection drop (other than queue deletion), the poller sleeps 1 s and
retries. After 5 consecutive failures it casts `{:poller_down}` to the server
GenServer, which broadcasts `{:ms_event, server_pid, :server_disconnected}` to
the `event_sink` of every registered Conn.

---

## 6. Residual Server Limitations

The six gaps of revision 1 are closed. Remaining limitations to design around:

| # | Limitation | Client-side handling |
|---|------------|----------------------|
| 1 | Recorder stop-on-silence / stop-on-DTMF (reasons 2, 3) not implemented | warn + ignore the opts; revisit later |
| 2 | Trickle ICE is "lite" (RTP component, host/srflx, highest-priority wins; no connectivity checks) | fine for test-tool use; no `ice_servers` handling |
| 3 | No "media flowing" event (only the loss event 6) | keep synthetic `:ice_connected` after `EndpointStartSending` |
| 4 | Watchdog must be armed/disarmed explicitly | arm after answer (§4.5/§4.6); disarm (`timeoutMs=0`) on hold, re-arm on resume when re-INVITE support lands |

---

## 7. Type Changes to `MediaServer.Behaviour`

`resource_ref/0` already covers the tagged-tuple handle. Two additions:

1. **New event** for RTP-inactivity loss (event 6):

```elixir
@type event :: ... | :media_timeout
```

Applications should treat `{:ms_event, conn_pid, :media_timeout}` as media
loss (hang up or retry per policy). The Mockup never emits it.

2. `recorder_opts` — document that `stop_on_silence`/`stop_on_dtmf` are
   accepted but currently inoperative with the Mendooze adapter.

---

## 8. Codec Mapping

Values from `mcu/include/codecs.h` (corrected in this revision):

| SDP name | Clock | Mendooze constant | Value |
|----------|-------|-------------------|-------|
| `PCMU`   | 8000  | `PCMU`            | 0     |
| `PCMA`   | 8000  | `PCMA`            | 8     |
| `G722`   | 8000  | `G722`            | 9     |
| `opus`   | 48000 | `OPUS`            | **98** |
| `telephone-event` | 8000 | `TELEPHONE_EVENT` | 100 |
| `H264`   | 90000 | `H264`            | 99    |
| `VP8`    | 90000 | `VP8`             | 107   |
| `red` (T.140) | 1000 | `T140RED`     | **105** |
| `t140`   | 1000  | `T140`            | **106** |

**`rtp_map` format** (both `StartReceiving` and `StartSending`): an XML-RPC
struct whose **keys are payload types as strings** and **values are the codec
constants as integers**, e.g. `%{"0" => 0, "8" => 8, "101" => 100}`. The
receive map (what we accept) and the send map (what was negotiated) may
differ. The `conn_opts` `:audio_codec`/`:video_codec` strings select which
entries go into the offer's receive map.

---

## 9. Module Structure

```
lib/framework/
├── MediaServer.ex                    # Behaviour (existing — add :media_timeout)
├── MediaServerMockup.ex              # Test stub (existing — unchanged)
└── mendooze/
    ├── MediaServerMendooze.ex        # MediaServer.Mendooze
    │                                 # GenServer — lifecycle + sess_tag registry
    ├── MediaServerMendoozeConn.ex    # MediaServer.Mendooze.Conn
    │                                 # GenServer — peer connection + sub-resources
    ├── MediaServerMendoozePoller.ex  # MediaServer.Mendooze.EventPoller
    │                                 # Task — chunked long-poll + event decode
    ├── MediaServerMendoozeXmlRpc.ex  # MediaServer.Mendooze.XmlRpc
    │                                 # :httpc + xmlrpc pkg; envelope check
    │                                 # (returnCode/errorMsg) in ONE place
    └── MediaServerMendoozeSdp.ex     # MediaServer.Mendooze.Sdp
                                      # ExSDP build/parse helpers, codec tables
```

`XmlRpc.call(base_url, method, params)` returns `{:ok, return_val_list}` or
`{:error, error_msg | http_reason}` — every higher layer stays free of
envelope handling. `Sdp` is pure functions → directly unit-testable.

---

## 10. Dependencies & Configuration

```elixir
# mix.exs
{:xmlrpc, "~> 1.4"}   # XML-RPC encode/decode; :httpc (stdlib) for HTTP
```

`ex_sdp` is already a project dependency.

```elixir
# config/config.exs
config :elixip2, MediaServer.Mendooze,
  host: "127.0.0.1",
  http_port: 8080,          # XML-RPC control + events
  ws_port: 9090,            # WebRTC/WS media (unused for now)
  connect_timeout_ms: 5_000,
  xmlrpc_timeout_ms: 10_000,
  rtp_timeout_ms: 10_000    # EndpointStartRTPTimeout watchdog threshold
```

---

## 11. Teardown Order

```
stop_player / stop_recorder / stop_echo     (stop + detach + delete resource)
    → close_peer_connection                 (stop send/recv, delete endpoint + session)
        → disconnect                        (EventQueueDelete → poller ends)
```

On any RPC failure during setup, the Conn runs its part of this sequence
before returning the error (server doc §9.6 — no leaked sessions).

---

## 12. Implementation Plan (Elixip side)

Bottom-up, each phase compiles, is tested, and is committable on its own.

### Phase 1 — XML-RPC client (`XmlRpc` module) — DONE (2865b4a)
- Add `{:xmlrpc, "~> 1.4"}`; wrap `:httpc` POST to `/jsr309`.
- Envelope decoding: `returnCode`/`returnVal`/`errorMsg`, negative-id check,
  UTF-8, configurable timeout.
- **Tests**: unit tests against a minimal `:gen_tcp`/Plug loopback returning
  canned XML — success, applicative error, HTTP error, timeout.

### Phase 2 — SDP helpers (`Sdp` module) — DONE (9039b50)
- Codec tables (§8) and `rtp_map` construction (offer/answer, asymmetric).
- Offer/answer build + parse with `ExSDP`: `c=`/`m=` from
  `GetMediaCandidates` output (`rtp://ip:port`), `a=fingerprint`, `a=setup`,
  `a=ice-ufrag/pwd`, `a=rtcp-mux`, SDES `a=crypto`.
- **Tests**: pure round-trip tests offer→parse, answer→parse, audio-only,
  audio+video, RTP-clear / SDES / DTLS variants.

### Phase 3 — Event poller — DONE
- Chunked GET decode loop: split `<methodResponse>` frames, skip `\r\n`
  keep-alives, decode event tuples (types 1–6, unknown types logged).
- Reconnect policy (§5.3); clean stop on queue deletion.
- **Tests**: feed the frame decoder captured/canned chunk streams (pure
  function on binaries → easy unit tests); reconnect logic with a fake HTTP
  server.

### Phase 4 — Server GenServer (`MediaServer.Mendooze`) — DONE
- `connect/1` (EventQueueCreate + poller start, `sourceName` fallback),
  `disconnect/2`, `sess_tag → conn_pid` registry, event routing to Conns,
  `:server_disconnected` broadcast.
- **Tests**: against a scripted fake JSR309 HTTP server (one module reused by
  all integration-style tests).

### Phase 5 — Conn GenServer — DONE
- `create_peer_connection/3`, `get_local_offer/1`, `set_remote_answer/2`,
  `set_remote_offer/2`, `close_peer_connection/1` — plain RTP, one media.
  Includes `EndpointSetRTPProperties`, watchdog arming, `:ice_connected`
  synthesis, failure-path teardown.
- Then extend: video media, DTLS+ICE (`webrtc_support`), SDES,
  `add_remote_candidate/2`.
- **Tests**: fake-server driven, asserting exact RPC sequences/order per §9
  of the server doc (order of crypto vs start calls, watchdog last).

### Phase 6 — Player / Recorder / Echo — DONE
- §4.9–4.17 including tag-based event routing (types 1, 3, 4, 5) and
  `maxDuration` on `RecorderRecord`; `:media_timeout` on event 6.
- **Tests**: fake-server events pushed through the poller → assert
  `event_sink` deliveries.

### Phase 7 — Behaviour update + Mockup parity — DONE
- Add `:media_timeout` to `MediaServer.event/0`; adjust docs.
- Verify `MediaServer.Mockup` still satisfies the behaviour (no change
  expected beyond the type union).

### Phase 8 — Integration with the DSL and a real server — DONE
- Adapter selection is config-driven: `config :elixip2, :mediaserver,
  module: :mockup | :mendooze | Module, url: "..."`. A new zero-arg
  `media_connect/0` DSL macro reads it via
  `SIP.Session.Media.use_mediaserver/1`; the two-arg `media_connect/2` still
  works for explicit selection. The `:mediaserver` key is a global scenario
  `config` key (routed to the app env by the runner) and an external-JSON
  header key (`"mediaserver": {"module": ..., "url": ...}`, module
  whitelisted). `MediaServer.Mendooze.connect/1` accepts a URL string
  (`http://host:port`, default port 8080) as well as `{host, port}`. The
  built-in `UAC.Invite` scenario now uses `media_connect/0`.
- **Tests**: config-driven selection (Mockup + Mendooze against the fake
  server), external-JSON `mediaserver` header parsing. Real-server E2E in
  `test/mendooze_integration_test.exs` (offer/answer loopback between two
  endpoints, player lifecycle, echo) gated by `@describetag skip:` on
  `MENDOOZE_URL` so `mix test` stays green without a server. Run against a
  real Mendooze with:
  `MENDOOZE_URL=http://host:8080 mix test test/mendooze_integration_test.exs`.

### Deferred (explicitly out of scope for now)
- WebRTC media over WS (`ws://:9090/jsr309`), `GetMediaCandidates`/
  `ConfigureMediaConnection` for WS transport.
- Mixers, mosaics, transcoders (conference features).
- Hold / re-INVITE renegotiation (watchdog disarm/re-arm, `StopSending` +
  `StartSending` with new address) — requires behaviour-level renegotiation
  callbacks first.
