# Mendooze — server crash / event-queue teardown on the JSR309 XML-RPC control path

Debugging prompt for a coding agent working on the **mediaserver** repo
(<https://github.com/neutrino38/mediaserver>, branch `feat/webrtc-improvement`,
API spec `xmlrpc_jsr309_api.md`). The XML-RPC front is
`Xmlrpc-c_Abyss/1.51.0`.

The Elixir controller (elixip `MediaServer.Mendooze` adapter) cannot complete
the very first steps of a call against the running server
(`http://172.21.105.71:9090`): every `EndpointCreate` fails with *"The media
Session does not exist"*, and the operator reports the **server appears to
crash** in its own logs. The failure is at the base session/event-queue layer,
before any SDP or media work — it is not WebRTC-specific.

```
Reproduce the failure below and find the crash. The client is a standard
XML-RPC caller plus one long-lived streaming HTTP GET for the event queue.

=== What the client does, in order ===

1. EventQueueCreate()
     -> returns [queueId, sourcePath]
     observed: [475791360, "/events/jsr309/475791360"]

2. Immediately opens a LONG-LIVED, CHUNKED HTTP GET on
     <base_url><sourcePath>      e.g. GET http://172.21.105.71:9090/events/jsr309/475791360
   - plain HTTP/1.1 GET, no special request headers
   - the client expects the server to KEEP THIS CONNECTION OPEN and stream
     event frames into it (comet / long-poll style): each event is one
     serialized XML-RPC <methodResponse>...</methodResponse>; a bare "\r\n"
     chunk every ~30 s is treated as a keep-alive.
   - the client holds this GET open for the whole session (separate TCP
     connection from the synchronous RPCs below).

3. MediaSessionCreate(sessionTag :: string, queueId :: int)
     -> expected: a NEW numeric sessionId, distinct from queueId
     observed: [475791360]   <-- it echoes the queueId back (SEE Q1)

4. EndpointCreate(sessionId :: int, sessionTag :: string,
                  hasAudio :: bool, hasVideo :: bool, hasText :: bool)
     observed: returnCode 0, errorMsg "The media Session does not exist"

5. On teardown: EventQueueDelete(queueId) / MediaSessionDelete(sessionId)
     observed: "Event queue does not exist" / "Session does not exist"

=== Observed symptoms (client side) ===

- The streaming GET of step 2 is closed by the server almost immediately
  (TCP reset / connection closed remotely) BEFORE step 3 even runs.
- A later poll on the same /events/jsr309/<queueId> path returns
  HTTP 404 "Not found" (server header: Xmlrpc-c_Abyss/1.51.0), i.e. the
  queue no longer exists.
- MediaSessionCreate returns an id; EndpointCreate with that id then reports
  the session does not exist; MediaSessionDelete likewise.
- The operator sees the server process crash in its logs around this point.

=== KEY isolation result (two raw runs, no elixip abstractions) ===

The EndpointCreate failure reproduces WITHOUT any event queue and WITHOUT ever
opening the long-poll GET — so the core bug is in the MediaSessionCreate ->
EndpointCreate path itself, independent of the event stream:

  A) No event queue at all:
       MediaSessionCreate("probe-noq", 0)     -> [480313344]
       EndpointCreate(480313344, "probe-noq", true,false,false)
                                              -> "The media Session does not exist"

  B) Event queue created, long-poll GET NEVER opened:
       EventQueueCreate()                     -> [491847680, ...]
       MediaSessionCreate("probe-q", 491847680) -> [491847680]   (== the queueId arg)
       EndpointCreate(491847680, "probe-q", ...) -> "The media Session does not exist"

Note in (A) the returned id (480313344) is unrelated to any queue, while in (B)
it equals the queueId argument. Two consecutive create calls (EventQueueCreate
then MediaSessionCreate) returning the SAME id (491847680) is itself a red flag:
either MediaSessionCreate echoes an argument instead of allocating a session, or
the id allocator returns stale/duplicate values.

A strong hypothesis: the session created by MediaSessionCreate is not visible to
the subsequent EndpointCreate request — e.g. each XML-RPC request is served by a
separate Abyss worker/process without a shared session store, so the session
lives only in the worker that created it and is gone by the next request. That
would also explain the crashes (a faulting/exiting worker) and the "does not
exist" on every follow-up call, queue included.

=== Please answer / fix, with file + function references ===

Q1. MediaSessionCreate return contract: is it SUPPOSED to return a distinct
    sessionId, or is a session identified by the queueId (one session per
    queue)? The client feeds MediaSessionCreate's return value as the first
    argument of EndpointCreate. If the contract changed, say so and update
    xmlrpc_jsr309_api.md; otherwise explain why the returned id is not a
    valid session for EndpointCreate.

Q2. The streaming event GET (step 2): does the Abyss HTTP handler support a
    long-lived chunked GET that stays open and is written to incrementally?
    Find where /events/jsr309/<id> is served. Does opening it (or holding it
    open) crash the server or tear down the queue? A stack trace / log
    excerpt of the crash is the key deliverable.

Q3. Lifecycle coupling: is the MediaSession (and the whole server) bound to
    the event-queue GET connection such that when that GET drops (or the
    handler faults), the queue and its sessions are destroyed? If the crash
    in Q2 restarts the process, that would explain the 404 and every
    subsequent "does not exist".

Q4. [Already answered by the isolation result above: the failure DOES occur
    without the event GET, so the fault is in MediaSessionCreate/EndpointCreate
    themselves, not the event stream.] Confirm where the in-memory MediaSession
    store lives and whether it is shared across XML-RPC requests. If Abyss
    serves each request in a separate process/thread without shared session
    state, that is the bug — MediaSessionCreate's session is invisible to the
    next request's EndpointCreate.

Deliverable: the crash root cause (with the server-side stack trace and the
offending handler), a fix that lets the long-lived event GET stay open while
sessions/endpoints are created against the same queue, and — if Q1 shows a
contract change — the updated MediaSessionCreate/EndpointCreate section of
xmlrpc_jsr309_api.md.
```

## Notes for the elixip side (context, no action required from the server agent)

- The client long-poll is `MediaServer.Mendooze.EventPoller`
  (`lib/framework/mendooze/MediaServerMendoozePoller.ex`): async streaming
  `:httpc` GET, `stream: :self`, on its own `:httpc` profile so it never
  blocks the synchronous RPCs.
- Session/endpoint creation is `MediaServer.Mendooze.Conn.init/1`
  (`MediaSessionCreate [sessTag, queueId]` then
  `EndpointCreate [sessId, sessTag, a?, v?, t?]`).
- A three-call raw repro (no elixip abstractions) is:
  `EventQueueCreate []` → open GET on the returned path →
  `MediaSessionCreate ["probe", queueId]` → `EndpointCreate [ret, "probe", true, false, false]`.
