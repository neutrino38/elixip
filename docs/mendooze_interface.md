# MediaServer.Mendooze — Interface Design

## 1. Overview

`MediaServer.Mendooze` implements `MediaServer.Behaviour` against the
**Mendooze MCU** (fork at `neutrino38/mediaserver`, branch `feat/alma_linux9`).
The MCU exposes three independent XML-RPC interfaces; we use the **JSR309**
one exclusively, as it is the general-purpose controller API.

Control channel: **HTTP XML-RPC** on port `9090` (default).  
Event channel: **HTTP SSE / chunked long-poll** on the same port, path
`/{eventSourceName}`.  
Optional media channel (WebRTC over WebSocket): **WS** on port `8100`,
path `/jsr309/{sessionId}/{token}` — out of scope for the initial
implementation.

---

## 2. Mendooze JSR309 Concepts

The server organises resources in a two-level hierarchy:

```
MediaSession  (1)
  └── Endpoint  (N)   ← one per media stream direction / peer
        ├── Player    (opt, N)
        ├── Recorder  (opt, N)
        └── AudioMixer / VideoMixer (opt, advanced MCU use)
```

An **EventQueue** is server-side; the client creates one queue per connection
and subscribes to events via HTTP long-poll.

---

## 3. Process Architecture

Only **two GenServer modules** are needed:

```
MediaServer.Mendooze              (server pid — connect/disconnect)
  ├── MediaServer.Mendooze.EventPoller   (Task — HTTP SSE long-poll)
  └── MediaServer.Mendooze.Conn          (one GenServer per peer connection)
```

Player, Recorder, and Echo are **not processes** — they are entries in the
Conn state map.  The reference returned to the caller is an opaque tuple
`{conn_pid, :player | :recorder | :echo, make_ref()}` that routes directly
back to the Conn GenServer.

### 3.1 Server state (`MediaServer.Mendooze`)

```elixir
%{
  base_url:    String.t(),    # "http://host:9090"
  queue_id:    integer(),     # created on connect/1
  source_name: String.t(),    # event SSE path component
  poller:      pid(),         # EventPoller task
  conns:       %{reference() => pid()}   # conn_ref → Conn pid
}
```

### 3.2 Conn state (`MediaServer.Mendooze.Conn`)

```elixir
%{
  server:      pid(),
  event_sink:  pid(),
  sess_id:     integer(),
  endpoint_id: integer(),
  opts:        keyword(),
  local_ports: %{audio: integer() | nil, video: integer() | nil},
  status:      :init | :active | :closed,

  # sub-resources — all server-side IDs stored here
  players:   %{reference() => %{player_id: integer(), opts: keyword()}},
  recorders: %{reference() => %{recorder_id: integer(), file: String.t(), opts: keyword()}},
  echo:      nil | reference()   # at most one echo per endpoint
}
```

The Erlang `reference()` (from `make_ref()`) is the opaque handle returned to
callers.  The full resource ref passed across the API boundary is the tuple
`{conn_pid, :player | :recorder | :echo, ref}`.

### 3.3 Type change to `MediaServer.Behaviour`

The current `@type ms_event` uses `ref :: pid()`.  With this design the ref is
a tagged tuple, so the type becomes:

```elixir
@type resource_ref :: pid() | {pid(), :player | :recorder | :echo, reference()}
@type ms_event :: {:ms_event, resource_ref(), event()}
```

All callbacks that previously typed their handle as `pid()` change to `term()`
(or `resource_ref()`).  The Mockup continues using bare pids — both are valid
`resource_ref` values.

---

## 4. `MediaServer.Behaviour` → JSR309 Mapping

### 4.1 `connect/1`

```
EventQueueCreate()  → {queue_id, source_name}
```
Start `EventPoller` task that HTTP-GET long-polls `{base_url}/{source_name}`.
Return `{:ok, server_pid}`.

> **Gap #6**: the current `EventQueueCreate` returns only an integer.  It
> should return `{queueId, sourceName}` so the client knows the SSE path
> without a second call.

### 4.2 `disconnect/2`

```
EventQueueDelete(queue_id)
```
Stop the poller task.  All Conn GenServers are already stopped by their
callers before `disconnect/2` is reached (teardown order in §10).

### 4.3 `create_peer_connection/3`

```
MediaSessionCreate(name, queue_id)  → sess_id
EndpointCreate(sess_id, name,
               audio_supported, video_supported, text=false)  → endpoint_id
```
Spawn `MediaServer.Mendooze.Conn` GenServer.  Register
`{:endpoint, endpoint_id}` → `conn_pid` in server ETS.
Return `{:ok, conn_pid}`.

**Codec mapping** from `conn_opts`:

| `conn_opts` key        | JSR309 action                                      |
|------------------------|----------------------------------------------------|
| `audio_codec`          | stored; used in `EndpointStartReceiving` rtp_map   |
| `video_codec`          | idem for video                                     |
| `webrtc_support: :yes` | use DTLS path in §4.4                              |
| `ice_servers`          | embedded in local SDP `a=ice-ufrag/pwd`            |

### 4.4 `get_local_offer/1`

Called with `conn_pid`.  Steps inside the Conn GenServer:

1. `EndpointStartReceiving(sess_id, endpoint_id, :audio, rtp_map)` → `audio_port`
2. `EndpointStartReceiving(sess_id, endpoint_id, :video, rtp_map)` → `video_port`
   (skip if `media: :audio` or `media: :video`)
3. If `webrtc_support` ∈ `[:yes, :if_offered]`:
   - `EndpointGetLocalCryptoDTLSFingerprint("sha-256")` → `fingerprint`
   - `EndpointSetLocalSTUNCredentials(…, ufrag, pwd)`
4. Build SDP offer with `ExSDP`:
   - `c=` : server IP extracted from `base_url`
   - `m=audio {audio_port} RTP/SAVPF …`
   - `a=fingerprint:sha-256 {fingerprint}` (if DTLS)
   - `a=ice-ufrag/pwd` (if ICE)
   - `a=setup:actpass`

Store `local_ports` in Conn state.  Return `{:ok, sdp_string}`.

### 4.5 `set_remote_answer/2`

Parse SDP answer with `ExSDP`; extract remote IP/ports, DTLS fingerprint,
ICE credentials.

```
EndpointSetRemoteCryptoDTLS(sess_id, endpoint_id, :audio, setup, "sha-256", fp)
EndpointSetRemoteSTUNCredentials(sess_id, endpoint_id, :audio, ufrag, pwd)
EndpointStartSending(sess_id, endpoint_id, :audio, remote_ip, remote_port, rtp_map)
# repeat for :video if present
```

After successful `EndpointStartSending`, send `{:ms_event, conn_pid,
:ice_connected}` to `event_sink` — mendooze does not emit an explicit
"media flowing" event for traditional RTP.

### 4.6 `set_remote_offer/2`

1. Parse offer SDP; extract codec list, remote IP/ports, crypto.
2. `EndpointStartReceiving` for each media → local ports.
3. `EndpointSetRemoteCryptoDTLS` / `EndpointSetRemoteSTUNCredentials`
4. `EndpointStartSending` for each media.
5. Build answer SDP (`a=setup:active`).
6. Send `:ice_connected` to `event_sink`.

Return `{:ok, answer_sdp}`.

### 4.7 `add_remote_candidate/2`

**No-op** — mendooze does not support trickle ICE.

> **Gap #1**: add `EndpointAddICECandidate(sessId, endpointId, media, candidate)`
> XML-RPC method to the server for true trickle ICE support.

### 4.8 `close_peer_connection/1`

Called with `conn_pid`.  Inside `Conn.terminate/2`:

```
EndpointStopReceiving(…, :audio)  EndpointStopReceiving(…, :video)
EndpointStopSending(…, :audio)    EndpointStopSending(…, :video)
EndpointDelete(sess_id, endpoint_id)
MediaSessionDelete(sess_id)
```

Send `{:ms_event, conn_pid, :closed}` to `event_sink`.
Unregister from server ETS.

### 4.9 `create_player/3`

```
PlayerCreate(sess_id, name)                          → player_id
PlayerOpen(sess_id, player_id, file_path)
EndpointAttachToPlayer(sess_id, endpoint_id, player_id, :audio)
EndpointAttachToPlayer(sess_id, endpoint_id, player_id, :video)
```
If `start_time` opt present: `PlayerSeek(sess_id, player_id, start_time_ms)`.

Store `%{player_id: player_id, opts: opts}` in `state.players[ref]`.
Register `{:player, player_id}` → `{conn_pid, ref}` in server ETS.

Return `{:ok, {conn_pid, :player, ref}}`.

### 4.10 `start_player/1`

`start_player({conn_pid, :player, ref})` → `GenServer.call(conn_pid, {:start_player, ref})`

```
PlayerPlay(sess_id, player_id)
```
Send `{:ms_event, {conn_pid, :player, ref}, :player_started}` to `event_sink`
immediately (no server-side confirmation yet — see Gap #2).

### 4.11 `pause_player/1`

```
PlayerStop(sess_id, player_id)   # pause — does not delete
```

### 4.12 `stop_player/1`

```
PlayerStop(sess_id, player_id)
EndpointDettach(sess_id, endpoint_id, :audio)
EndpointDettach(sess_id, endpoint_id, :video)
PlayerClose(sess_id, player_id)
PlayerDelete(sess_id, player_id)
```
Remove entry from `state.players` and unregister from ETS.

### 4.13 `create_recorder/4`

```
RecorderCreate(sess_id, name)                                 → recorder_id
RecorderAttachToEndpoint(sess_id, recorder_id, endpoint_id, :audio)
RecorderAttachToEndpoint(sess_id, recorder_id, endpoint_id, :video)
```
Store `%{recorder_id: recorder_id, file: file_path, opts: opts}` in
`state.recorders[ref]`.  If `duration_ms > 0`, schedule a client-side timer
as fallback (sends `{:recorder_timeout, ref}` to self) until Gap #4 is fixed.

Register `{:recorder, recorder_id}` → `{conn_pid, ref}` in server ETS.

Return `{:ok, {conn_pid, :recorder, ref}}`.

### 4.14 `start_recorder/1`

```
RecorderRecord(sess_id, recorder_id, file_path)
```
Send `{:ms_event, {conn_pid, :recorder, ref}, :recorder_started}` immediately.

### 4.15 `stop_recorder/1`

```
RecorderStop(sess_id, recorder_id)
RecorderDettach(sess_id, recorder_id, :audio_video)
RecorderDelete(sess_id, recorder_id)
```
Cancel the client-side duration timer if set.
Remove from `state.recorders` and ETS.
Send `{:ms_event, {conn_pid, :recorder, ref}, {:recorder_stopped, :caller}}`.

### 4.16 `create_echo/1`

```
EndpointAttachToEndpoint(sess_id, endpoint_id, endpoint_id, :audio_video)
```
Store `ref` in `state.echo`.
Send `{:ms_event, {conn_pid, :echo, ref}, :echo_started}`.
Return `{:ok, {conn_pid, :echo, ref}}`.

### 4.17 `stop_echo/1`

```
EndpointDettach(sess_id, endpoint_id, :audio_video)
```
Clear `state.echo`.

---

## 5. Event Poller

`MediaServer.Mendooze.EventPoller` is a supervised `Task`:

```
GET http://host:9090/{source_name} HTTP/1.1
Accept: text/event-stream
```

The server responds with `Transfer-Encoding: chunked`.  Each chunk is an
XML-RPC-serialised `JSR309Event`.  The poller decodes each chunk and forwards
it to the server GenServer via `GenServer.cast/2`.

The server GenServer looks up `{resource_type, server_int_id}` in the ETS
table → `{conn_pid, ref}`, then casts the translated event to the Conn
GenServer, which forwards it to `event_sink`.

### 5.1 Event dispatch table

| Server event type              | `event_sink` receives                               |
|--------------------------------|-----------------------------------------------------|
| `PlayerEndOfFileEvent` (1)     | `{:ms_event, {conn, :player, ref}, :player_ended}`  |
| `ExternalFIRRequestedEvent` (2)| internal only — call `EndpointRequestUpdate`        |
| `PlayerStartedEvent` (3) ★     | `{:ms_event, {conn, :player, ref}, :player_started}`|
| `RecorderStoppedEvent` (4) ★   | `{:ms_event, {conn, :recorder, ref}, {:recorder_stopped, reason}}` |
| `EndpointDisconnected` (5) ★   | `{:ms_event, conn_pid, :closed}`                    |

★ = new events to add to the C++ server (see §6).

### 5.2 Reconnect policy

On HTTP connection drop, the poller sleeps 1 s and retries.  After 5
consecutive failures it casts `{:server_disconnected}` to the server GenServer,
which broadcasts `{:ms_event, server_pid, :server_disconnected}` to all
registered `event_sink` pids.

---

## 6. API Gaps and Required Server Extensions

| # | Gap | Impact | Proposed fix |
|---|-----|--------|--------------|
| 1 | No trickle ICE | `add_remote_candidate/2` is a no-op | Add `EndpointAddICECandidate(sessId, endpointId, media, candidate)` |
| 2 | No `PlayerStartedEvent` | event fired synthetically after `PlayerPlay` | Add `PlayerStartedEvent = 3` in `JSR309Event::Events` |
| 3 | No `RecorderStartedEvent` | event fired synthetically after `RecorderRecord` | Add `RecorderStartedEvent = 4` |
| 4 | No `RecorderStoppedEvent` | stop-reason unknown; client uses a fallback timer | Add `RecorderStoppedEvent = 5` with reason (0=caller, 1=duration, 2=silence, 3=dtmf) |
| 5 | No `EndpointDisconnectedEvent` | silent peer disconnects undetected | Add `EndpointDisconnectedEvent = 6` on RTP timeout |
| 6 | `EventQueueCreate` returns `int` only | poller needs the SSE path string | Return `{queueId, sourceName}` from `EventQueueCreate` |

---

## 7. Codec Mapping

| Mendooze constant | Value | SDP name | Clock |
|-------------------|-------|----------|-------|
| `PCMU`            | 0     | `PCMU`   | 8000  |
| `PCMA`            | 8     | `PCMA`   | 8000  |
| `G722`            | 9     | `G722`   | 8000  |
| `OPUS`            | 111   | `OPUS`   | 48000 |
| `H264`            | 99    | `H264`   | 90000 |
| `VP8`             | 107   | `VP8`    | 90000 |
| `T140RED`         | 96    | `RED`    | 1000  |
| `T140`            | 98    | `T140`   | 1000  |

The `conn_opts` `:audio_codec` / `:video_codec` strings are translated to
integer PT values in the `rtp_map` argument of `EndpointStartReceiving` /
`EndpointStartSending`.

---

## 8. Module Structure

```
lib/framework/
├── MediaServer.ex                    # Behaviour (existing — type resource_ref added)
├── MediaServerMockup.ex              # Test stub (existing — unchanged)
└── mendooze/
    ├── MediaServerMendooze.ex        # MediaServer.Mendooze
    │                                 # GenServer — server lifecycle + ETS registry
    ├── MediaServerMendoozeConn.ex    # MediaServer.Mendooze.Conn
    │                                 # GenServer — peer connection + all sub-resources
    ├── MediaServerMendoozePoller.ex  # MediaServer.Mendooze.EventPoller
    │                                 # Task — HTTP SSE long-poll + dispatch
    └── MediaServerMendoozeXmlRpc.ex  # MediaServer.Mendooze.XmlRpc
                                      # thin wrapper: :httpc + xmlrpc hex package
```

---

## 9. Dependencies

```elixir
# mix.exs
{:xmlrpc, "~> 1.4"}   # XML-RPC encode/decode; :httpc (stdlib) for HTTP
```

`ex_sdp` is already a project dependency.

---

## 10. Configuration

```elixir
# config/config.exs
config :elixip, MediaServer.Mendooze,
  host: "127.0.0.1",
  http_port: 9090,
  ws_port: 8100,
  connect_timeout_ms: 5_000,
  xmlrpc_timeout_ms: 10_000
```

---

## 11. Teardown Order

```
stop_player / stop_recorder / stop_echo     (detach + delete server-side resource)
    → close_peer_connection                 (stop/delete endpoint + session)
        → disconnect                        (delete event queue, stop poller)
```
