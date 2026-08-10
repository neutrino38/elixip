# MOTELI reboot — RabbitMQ + protobuf control plane for the media servers

Status: **draft for discussion** — 2026-08-10
Target release: **elixip 2.0** (the whole plan; nothing here lands in 1.x)

## 1. Context and goals

Today kelixip drives the Mendooze media servers over two plaintext XML-RPC
control planes plus a chunked HTTP long-poll per event queue:

| Plane | Endpoint | Verbs | Client (elixip side) | Consumer |
|---|---|---|---|---|
| JSR-309 (point-to-point legs) | `POST /jsr309` + `GET /events/jsr309/<q>` | 82 | `MediaServer.Mendooze.XmlRpc` + `EventPoller` | `Kelix.MediaPool` → scenarios |
| MCU (conferences) | `POST /mcu` + `GET /events/mcu/<q>` | 68 | `Kelix.Mod.Mcu.XmlRpc` + `Mcu.EventQueue` | `Kelix.Mod.Mcu` |

This architecture has three structural problems:

1. **kelixip must know the whole pool statically.** The pool is declared in
   `config.toml` (`[mediaserver.pool.<name>]`); adding or removing a media
   server is a config change + reload on every kelixip node.
2. **No transport security and no authentication.** The XML-RPC server
   (xmlrpc-c/Abyss) is plaintext HTTP only; the event streams, the image
   upload endpoint and even the `GET /stop` shutdown URL are unauthenticated.
   Deployments rely entirely on network isolation.
3. **kelixip does the health probing and load balancing itself** (two
   round-robins: `Kelix.MediaPool` for legs, `Kelix.Mod.Mcu.pick_mcu/2` for
   conferences), with a probe protocol (`connect` + `disconnect(force: true)`
   every 30 s / 5 s) that scales poorly with pool size and only observes the
   `/jsr309` half.

The MOTELI project (historical) already solved the transport problem once:
media servers and controllers both connect **outbound** to a RabbitMQ broker
and exchange protobuf messages. The connector still exists in the media
server tree (`mcu/src/moteli/`) but is dead code (`#ifdef MOTELI`, never
enabled by `install.ksh`) and implements an obsolete API.

**Goals of the reboot** (in order):

- G1 — Outbound-only connections: kelixip nodes *and* media servers dial the
  broker; nobody listens on a control port anymore.
- G2 — TLS everywhere on the control plane (`amqps://`), with per-client
  credentials (and optionally mutual TLS).
- G3 — Natural pooling: adding a media server = starting it with the broker
  URL; removing one = stopping it. No kelixip config change.
- G4 — Autodiscovery: kelixip learns pool membership, health and capabilities
  from the bus itself.
- G5 — HA: survive a media-server restart (existing stale/recreate logic must
  keep working), a broker restart, and leave the door open to multiple
  kelixip nodes on the same bus.

Non-goals: changing the media plane (RTP/SRTP, text-over-WS on `:9090`) or
the JSR-309/MCU object models themselves. This is a **transport swap**, verbs
are ported 1:1.

## 2. What the legacy MOTELI connector gives us

Files: `/home/ebuu/mediaserver/mcu/src/moteli/{mcu.proto, rabbitmqserver.*, rabbitmqmcu.*}`
(~1300 lines of C++), hooks in `main.cpp` under `#ifdef MOTELI`
(`--rq-host` / `--rq-queue` options, instantiation, start/stop), build switch
`MOTELI=yes` in `Makefile.rpm` (adds `-lamqpcpp -lrabbitmq -lprotobuf` and a
`protoc` codegen rule).

**Reusable:**

- The overall pattern: a `McuRabbitServer` (connection + queues + consumer
  thread + reconnect loop) and a `McuRabbitHandler` (decode → dispatch into
  `MCU*` → reply). The reboot keeps this two-class shape.
- The `main.cpp` integration points and CLI plumbing.
- The AMQP property usage (`reply_to`, `correlation_id`, `message_id`,
  `Content-Type`) — correct idea, kept.
- The private-queue naming idea (per-instance queue), reworked in §4.

**Discarded:**

- **The `.proto` itself.** It models the *old* coarse API (22 generic
  CRUD messages: `CreateMcuObjectReq`, `StartMediaReq` with explicit RTP
  addresses and rtpmaps…) — pre-SDP, pre-ICE/DTLS, no player/recorder/echo,
  no JSR-309. Its enums are stale and partly wrong versus the current code
  (`VP8 = 118` vs today's 107, `AMR` collides, `T140/T140RED` shifted,
  no OPUS/AV1/G7221/BFCP, 7 picture sizes vs 18, 9 mosaics vs 12). Full
  rewrite.
- **proto2 with `required` fields** — the exact anti-pattern that blocks
  schema evolution. The reboot uses proto3.
- **The ad-hoc framing** ("entête BULL": 2 ASCII digits = type-name length,
  then the type name, then the protobuf bytes). Replaced by a single
  envelope message with a `oneof` (§3).
- **The vendored `AMQPcpp` wrapper** — plaintext `amqp://` only, unbuilt,
  unmaintained. Replaced (§5.1).
- Correlation ids duplicated inside the protobuf bodies — AMQP properties
  already carry them.

## 3. Message format

Decision: **protobuf, proto3 syntax** (with explicit `optional` where field
presence matters). Rationale: first-class C++ support and an existing
codegen chain in the media server build (`staticdeps/bin/protoc`); two mature
Elixir libraries; well-understood evolution rules for a pool where media
servers and kelixip will not upgrade in lockstep.

Alternatives considered and set aside:

- *JSON + JSON Schema*: readable in the RabbitMQ management UI and `jason` is
  already a dep, but the schema is advisory (nothing forces the C++ side to
  conform), there is no C++ type codegen, and the contract discipline is
  precisely what we want to harden.
- *Avro*: strong evolution story but heavy C++ integration and a Kafka-shaped
  Elixir ecosystem; pointless without a schema registry.
- *FlatBuffers / Cap'n Proto*: zero-copy buys nothing for small control
  messages; Elixir support is anecdotal.
- *ASN.1*: native compiler in OTP but poor C++ ergonomics (`asn1c`) and rare
  skills.

Elixir library: **`protox`** (compiles the `.proto` into modules at build
time via a macro — no generated files to commit and no protoc *plugin*).
Verified at P0 (protox 1.7.8): the four schemas compile and a
`ControlRequest` round-trips. One correction discovered doing so: protox
**does require the `protoc` binary on build hosts** (all maintained
versions shell out to it for parsing), so `protobuf-compiler` joins the
build dependencies of the RPM/deb build containers either way.
`protobuf-elixir` remains the fallback.

### 3.1 Schema organization

Four files (the envelope must import both planes, so it lives apart to keep
imports acyclic) — **written at P0**, in `apps/elixip2/priv/proto/`:

```
apps/elixip2/priv/proto/
├── moteli_common.proto    # shared enums, Error, stats, SdpOffer, conventions
├── moteli_mcu.proto       # the /mcu verbs (Req/Resp) + the 4 MCU events
├── moteli_jsr309.proto    # the /jsr309 verbs (Req/Resp) + the 7 JSR-309 events
└── moteli_bus.proto       # ControlRequest/ControlResponse/Event envelopes,
                           #   Presence/Bye, Ping/Drain/Resume
```

Package `moteli.v2` (the version is in the package name; a breaking change
means `moteli.v3`, and a server may serve both during a migration). At P1
the files are mirrored into the media server repo (next to the code that
implements them); a checked-in hash keeps the copies honest.

**Maintenance rule (decided 2026-08-10): any change to the XML-RPC API
(MCU-API.md / xmlrpc_jsr309_api.md) MUST update these `.proto` files in the
same change set**, so the 2.0 bus protocol never lags the HTTP one. The rule
is stated in each file's header and in the media server repo's CLAUDE.md.

### 3.2 Envelope

One root message per direction, dispatched by `oneof` — one parse entry
point on each side, self-describing, extensible without touching the
decoder:

```proto
message ControlRequest {          // controller → media server
  oneof body {
    // MCU plane
    CreateConferenceReq   create_conference   = 10;
    DeleteConferenceReq   delete_conference   = 11;
    CreateParticipantReq  create_participant  = 12;
    StartReceivingReq     start_receiving     = 13;
    // ... one entry per verb, tag ranges reserved per group
    // JSR-309 plane (range 200+)
    MediaSessionCreateReq media_session_create = 200;
    // ...
  }
}

message ControlResponse {         // media server → controller (RPC replies)
  oneof body {
    Error                  error               = 1;
    Empty                  ok                  = 2;   // void verbs
    CreateConferenceResp   create_conference   = 10;
    StartReceivingResp     start_receiving     = 13;
    // ...
  }
}

message Event {                   // media server → controller (async)
  string instance   = 1;          // media server name (see §4.1)
  fixed64 boot_epoch = 2;         // incarnation (see §4.4)
  oneof body {
    McuEvent    mcu    = 10;      // FPU request, doc sharing, media timeout/connected
    Jsr309Event jsr309 = 11;      // player/recorder/endpoint events
  }
}

message Error {
  ErrCode code    = 1;            // NOT_FOUND, INVALID_PARAMETER, OVER_CAPACITY, ...
  string  message = 2;
}
```

Rules:

- **Correlation lives in AMQP properties only** (`correlation_id`,
  `reply_to`, `message_id`), never in the body. The AMQP `type` property
  carries the verb name for observability/routing without deserializing.
- `Content-Type: application/x-moteli-v2+protobuf`.
- The `returnCode 1/0 + errorMsg` XML envelope and the "negative id means
  failure" rule collapse into the `Error` branch of the response `oneof`.
  The bare-`0` quirk of the security handlers disappears.
- XML-RPC's overload-by-arity (older, shorter signatures) becomes proto3
  optional fields with the current defaults documented in the schema
  (`role = VIDEO_MAIN`, `proto = TCP`, …).
- XML-RPC structs (`rtpMap`, `properties`, `fmtpByPt`, the `offer` struct)
  become `map<string, string>` / `map<string, int32>` — same shape, typed.
- Enums are regenerated **from the current C++ tables** (`AudioCodec::Type`,
  `VideoCodec::Type` incl. AV1 = 110, `TextCodec`, `Mosaic::Type` 0..11, the
  18-entry resolution index, VAD modes, slot specials), marked append-only.
- Event codes keep the existing append-only discipline; unknown `oneof`
  branches are ignored (proto3 gives us this for free).

## 4. Bus topology

```
                RabbitMQ (amqps://, one vhost per SIP domain, §4.9)
                     ┌─────────────────────────────────────────┐
 kelixip node A ────▶│ queue   kelixip.alloc.mcu    (quorum)   │◀──── mediaserver ms1
 kelixip node B ────▶│ queue   kelixip.alloc.jsr309 (quorum)   │◀──── mediaserver ms2
                     │ queue   kelixip.rpc.ms1    (exclusive)  │◀──── ...
                     │ queue   kelixip.rpc.ms2    (exclusive)  │
                     │ exchange  kelixip.presence   (fanout)   │
                     │ exchange  kelixip.events     (topic)    │
                     │ (replies: direct reply-to)              │
                     └─────────────────────────────────────────┘
```

Everyone connects **outbound** to the broker (G1). Nothing below requires a
kelixip listener or a media-server listener.

**Naming convention** (decided 2026-08-10): every broker resource — vhost,
exchanges, queues — lives in the **`kelixip.*` namespace** (originally
drafted as `moteli.*`, renamed for clarity: the product is kelixip, MOTELI
is only the historical codename of the transport pattern). "MOTELI" remains
in the protocol identity (`moteli.v2` protobuf package, `Content-Type
application/x-moteli-v2+protobuf`, the `mcu/src/moteli/` directory) since
those name the wire contract, not the deployment. The build flag does NOT
keep the codename: `MOTELI=yes` is renamed to **`RABBITMQ=yes`** when the
path is revived (§5.3). Any implementation code MUST use the `kelixip.*`
resource names from day one; nothing on the bus may declare `moteli.*`
resources.

### 4.1 Identity

Each media server is started with a stable **instance name** (`--rq-name ms1`,
replacing today's pool-entry name) and generates a **boot epoch** (monotonic
timestamp captured once at startup). `(instance, boot_epoch)` is the identity
carried by presence messages and events.

### 4.2 Session establishment — competing consumers ("first to consume wins")

Placement is done **by the broker, not by kelixip** — the pattern the
original MOTELI deployment used, structured to lean on RabbitMQ's *native*
work-distribution machinery rather than reimplementing any of it:

- A direct exchange `kelixip.alloc` with routing keys `mcu` / `jsr309`,
  bound to two shared **quorum queues** `kelixip.alloc.mcu` (new
  conferences: `CreateConference`) and `kelixip.alloc.jsr309` (new media
  sessions: `MediaSessionCreate`). Every willing media server consumes both
  or either. Why quorum: §4.8.
- **Fair dispatch = manual acks + small prefetch.** Unlike the legacy
  connector (which consumed `AMQP_NOACK`), consumers use explicit acks with
  `basic.qos` prefetch = the number of establishments the server is willing
  to process concurrently (1–2 is right: establishment is short). The broker
  never delivers to a consumer whose prefetch window is full, so **a busy
  server is skipped automatically** — "least busy wins" without any load
  reporting. The server acks *after* the session object exists and the
  response is published.
- **The winner owns the session.** Its response (via `reply_to`) carries its
  `instance` name and `boot_epoch`; the controller pins the session to
  `kelixip.rpc.<instance>` for everything that follows.
- **Failover of the establishment itself, for free**: if a server crashes
  after delivery but before ack, the broker requeues the request and another
  consumer wins it. The `redelivered` flag tells the new winner it may be a
  retry; establishment verbs must therefore be idempotent-friendly (a
  controller-chosen establishment id in the request lets a server detect a
  duplicate it already answered). The quorum queue's native
  `x-delivery-limit` (with the `x-delivery-count` header) bounds the
  attempts, so a poison request that kills every server it lands on is
  dropped/dead-lettered instead of looping across the pool.
- **Fast-fail via per-message TTL + DLX** rather than only a caller timeout:
  establishment messages carry `expiration` ≈ 2 s and the alloc queues have
  a dead-letter exchange `kelixip.alloc.dlx`. If no server consumes (empty
  or saturated pool), the message expires and lands on the DLX; controllers
  bind a queue to it and turn the dead-lettered request into an immediate
  "no media server available" (today's 503/fallback) instead of waiting out
  the RPC timeout. (TTL caveat: expiry is enforced at the queue head — exact
  under FIFO consumption, which is our case.)
- **Drain without disappearing** (option): consumer priorities
  (`x-priority`) make a draining or de-preferred server consume only when
  no higher-priority consumer has capacity — softer than stopping
  consumption outright (§4.4). Quorum-queue support for consumer priorities
  is recent (RabbitMQ 4.x) — gate this refinement on the deployed broker
  version; stop-consuming remains the portable fallback.
- Admission control thus stays **server-side and truthful** (prefetch +
  consume/stop/priority), with no capacity reporting, no stale load figures,
  no selection code in kelixip — and it composes with multiple kelixip
  nodes with zero coordination.

### 4.3 In-session RPC (request/response)

- Each media server declares `kelixip.rpc.<instance>` as an **exclusive
  queue** (declared on — and owned by — its consuming AMQP connection):
  - **Lifecycle exactly equals the server's bus connection**: the broker
    deletes the queue the instant the TCP/TLS connection dies — no
    auto-delete/consumer-cancel dance, no stale queue to garbage-collect.
  - **Duplicate-instance protection for free**: a second media server
    started with the same `--rq-name` gets `RESOURCE_LOCKED` on declare and
    refuses to boot — a misconfiguration caught at startup instead of two
    servers splitting one identity's traffic.
  - Exclusivity restricts *consumption and queue operations* to the owning
    connection, **not routing**: controllers publish to it through the
    default exchange from their own connections as usual.
  - In a cluster the queue is node-local (it lives on the broker node the
    server connected to); publishes from controllers attached to other nodes
    are routed across the cluster transparently.
  - It cannot be durable or quorum — and must not be: its contents are
    meaningless the moment the owner is gone (in-flight RPCs to a dead
    server have no valid answer; the mandatory-return path below reports
    them synchronously).
  - A **bus-connection blip** destroys the queue while the server (and its
    sessions) live on: the server re-declares on reconnect; controllers see
    returned publishes with an *unchanged* `boot_epoch` in presence →
    "temporarily unreachable, retry within the call timeout", **not**
    `mark_stale` (§4.6).
  One queue per server preserves the per-server ordering that
  `Kelix.Mod.Mcu.Client` relies on today, while the server side may still
  process with a small thread pool (§5.2) — each controller call is
  synchronous per caller, so per-caller ordering holds.
- Controllers publish requests to that queue (default exchange) with
  `reply_to = amq.rabbitmq.reply-to` (RabbitMQ **direct reply-to**: no reply
  queue to manage, replies ride the publishing channel) and a per-call
  `correlation_id`. Timeout stays the caller's job (10 s today, unchanged).
- Publishes use the **`mandatory` flag + publisher confirms**: if the target
  queue is gone (server died, queue auto-deleted), the publish is returned
  immediately — dead-server detection becomes synchronous instead of waiting
  for a timeout.
- Adding a participant to an **existing** conference is in-session traffic
  (the conference is pinned), not an allocation.

### 4.4 Presence (G4) — for lifecycle and observability, not selection

Competing consumers solve *placement*; they do not tell kelixip that "the
server holding conference X just died" or restarted. That is what presence
is for:

- Every media server publishes a `Presence` message on `kelixip.presence`
  every **5 s** (TTL 5 s on the message so late joiners don't read stale
  data), and a final `Bye` on clean shutdown:

```proto
message Presence {
  string  instance      = 1;
  fixed64 boot_epoch    = 2;
  repeated Plane planes = 3;     // MCU, JSR309
  string  version       = 4;     // media server build version
  bool    accepting     = 5;     // currently consuming the alloc queues?
  Capacity capacity     = 6;     // informational: conferences, endpoints, CPU hint
}
message Bye { string instance = 1; fixed64 boot_epoch = 2; }
```

- Each kelixip node binds a private **exclusive** queue to
  `kelixip.presence` and maintains the live instance table
  (up/down/restarted). Its role:
  - **HA bookkeeping**: 3 missed heartbeats (15 s) or a `boot_epoch` change
    on a pinned instance drives the existing `mark_stale` / participant
    notification pipeline (§4.6);
  - telemetry (`mediaserver.up`/`.down`) and operator visibility (`kelictl`
    listing the discovered pool);
  - it **replaces the 30 s/5 s `connect`-probe** and retires the
    `purpose: :health_check` contract.
- **Administrative drain moves server-side**: today `enabled = false` in
  kelixip's pool config excludes a server; with broker-side placement,
  exclusion means the server stops consuming the allocation queues. A
  `Drain`/`Resume` verb on the server's private queue (surfaced through
  `kelictl`) provides the same operation; `Presence.accepting` makes the
  state visible.
- The old asymmetry rule survives in spirit: presence alone declares an
  instance up; a session holder may still flag it suspect early after
  repeated in-session RPC timeouts.

### 4.5 Events

- Media servers publish `Event` messages to the topic exchange
  `kelixip.events` with routing key `<instance>.<plane>.<tag>` (the tag is
  what routes today: conference tag on `/mcu`, `sess_tag`/player/recorder
  tags on `/jsr309`).
- Each kelixip node declares one private **exclusive** queue and binds
  `<instance>.#` for the servers it uses (or `#` — volume is low). This
  **replaces `EventQueueCreate`/`EventQueueDelete` and both long-poll
  pollers** entirely; the mixer-scoped queue notion disappears from the
  wire (the server publishes everything; binding does the filtering).
- Multiple kelixip nodes each get their own copy (topic exchange fan-out) —
  the groundwork for G5 multi-controller.

### 4.6 Restart vs. blip — preserving the HA semantics (G5)

Today's behavior that must survive, mapped to the new signals:

| Today | Reboot |
|---|---|
| Long-poll breaks, retries, `max_failures` → stream down | Broker connection drop → client reconnect loop (both sides); kelixip marks *all* entries suspect only after a grace period |
| Event queue 404 = server restarted → `renew_queue` + `mark_stale` | `boot_epoch` changed in `Presence`/`Event` → `mark_stale/1` then `recreate_stale/2` + `gc_orphans/2`, exactly as today |
| Health transition → `mediaserver.down`/`.up` telemetry + `MediaPool.recheck` | Same hooks, driven by presence instead of probes |
| JSR-309 plane: `:server_disconnected` fan-out to sinks | Same, triggered by presence loss of the instance backing the connection |

The `boot_epoch` is the load-bearing piece: it cleanly separates "I couldn't
hear the server for a while" (broker blip, no state lost) from "the server
restarted" (all conference/session ids are gone → stale/recreate). Today
that distinction is inferred from a 404 on the event queue; the epoch makes
it explicit and works even if the broker was down while the server
restarted.

### 4.7 Broker deployment and TLS (G2)

- `amqps://` on 5671, server certificate from the existing
  `/etc/mediaserver` PEM machinery on the media-server side; kelixip gets a
  client credential per node. Username/password per client at minimum;
  mutual TLS (`ssl_options.verify_peer` + client certs) as the target.
- One vhost **per SIP domain** (`kelixip.<domain>`, §4.9) with permissions
  scoping inside each: media servers may only consume `kelixip.rpc.<own
  name>` and the alloc queues, and publish to the two exchanges;
  controllers the reverse.
- Broker HA: the broker is a *rendezvous*, not a store. The only durable
  objects are the two alloc queues (quorum, §4.8) and their DLX, whose
  contents are 2-second-TTL establishment requests — losing them costs a
  retry, never state. Everything else (RPC, presence, event queues) is
  exclusive and per-connection. A broker restart therefore loses nothing
  that matters — both sides reconnect and presence repopulates the pool
  within one heartbeat period.
  The HA target (two controllers + broker cluster surviving any single
  instance loss) fixes the topology at a **3-node RabbitMQ cluster** — see
  §4.10 for the analysis and the connection strategy. Media keeps flowing
  during any broker outage; only *control* (new calls, teardowns) is
  briefly unavailable.
- **Decided (2026-08-10): RabbitMQ is a deployment prerequisite**, documented
  in the kelixip installation guide — it is not shipped or packaged by
  kelixip (same status as the media server itself).

### 4.8 Queue types — where quorum queues earn their cost, and where they don't

Since RabbitMQ 4.0 removed classic mirrored queues, **quorum queues are the
only replicated option** — the question is not "quorum or mirroring" but
"which queues deserve replication at all".

| Queue | Type | Why |
|---|---|---|
| `kelixip.alloc.mcu` / `.jsr309` (+ DLX target) | **quorum** | The only shared, long-lived objects every participant depends on. In a cluster they stay available through a broker-node failure (Raft, majority). Bonus features used by §4.2: native `x-delivery-limit` / `x-delivery-count` (poison-request bound), robust requeue-on-consumer-death semantics. |
| `kelixip.rpc.<instance>` | **exclusive (classic)** | Must die with its owner; replication is meaningless (contents are worthless without the server) and exclusive queues cannot be quorum by definition. Keeps the RPC path on the cheapest, lowest-latency queue type. |
| presence / event queues (controller side) | **exclusive (classic)** | Per-consumer, rebuilt in one heartbeat period after any loss. |

Quorum limitations, checked against our use:

- *Must be durable, cannot be exclusive or auto-delete* — fine, that is what
  the alloc queues want anyway.
- *Raft write amplification / fsync on the publish path* — milliseconds; the
  allocation rate (session establishments) is orders of magnitude below
  where this matters. It is precisely why the **high-rate RPC path does NOT
  ride a quorum queue**.
- *Per-message TTL supported (≥ 3.10) but enforced at the queue head* —
  exact under FIFO consumption, our case (§4.2).
- *No message priorities (`x-max-priority`)* — unused.
- *Global QoS unsupported, per-consumer prefetch only* — per-consumer
  prefetch is exactly our admission mechanism.
- *Consumer priorities* — supported on quorum queues only in recent
  RabbitMQ (4.x); the §4.2 soft-drain refinement is gated on the deployed
  version.
- *Memory/disk footprint per queue* — we have exactly two (+ DLX), not
  thousands.

Deployment note: declare the alloc queues `x-queue-type: quorum`
unconditionally — on a single-node broker a quorum queue simply has a
replication factor of 1 and behaves like a durable classic queue, and the
declaration doesn't change when the cluster grows (`rabbitmq-queues
grow` adds members without redeclaring). This sets the broker version floor
at **RabbitMQ ≥ 3.13, recommended 4.x** — to be stated in the prerequisite
documentation (§4.7).

### 4.9 SIP-domain isolation — one vhost per domain

Assumptions for this iteration: **kelixip is multi-domain** (it is the
controller and already routes per domain via `domains.toml`); **a media
server is mono-domain**.

**Decision: isolation by RabbitMQ virtual host, not by exchange.** The AMQP
permission model is *per-vhost*: a media server's credential exists only in
its domain's vhost, so it is physically unable to observe or inject traffic
in any other domain — isolation is enforced by the broker, not by naming
discipline. The exchange-per-domain alternative (single vhost, per-domain
resource prefixes + regex permissions) was rejected: it duplicates the
alloc queues per domain anyway, turns security into a regex-review problem,
and offers no per-domain resource limits or policies.

- **Vhost naming**: `kelixip.<domain>` (e.g. `kelixip.visio.example.com`).
  Inside every vhost the topology of §4.1–§4.8 is **replicated identically**
  — same queue and exchange names, same types. Nothing on the bus is
  renamed per domain: the domain lives entirely in the connection
  parameters.
- **Media server side (mono-domain)**: the domain is invisible to the code —
  it is just the vhost path of `--rq-url
  amqps://ms1:pass@broker/kelixip.<domain>`. Zero domain logic in C++.
- **kelixip side (multi-domain)**: one AMQP connection per served domain
  (a connection is bound to a single vhost). Per domain: one presence
  table, one event queue, one alloc publisher. Dozens of domains =
  dozens of connections — fine; thousands would call the vhost choice into
  question, revisit then.
- **Sharing a pool between domains** stays possible without breaking the
  model: several `[[domain]]` entries may point at the *same* vhost
  (`mediaserver.vhost` below) — those domains then share the media servers
  connected there. The mono-domain assumption is about the media server's
  connection, not the business mapping.
- **Provisioning**: creating a domain now includes broker provisioning
  (vhost + one controller user + one user per media server + permissions).
  Scriptable against the management API; a `kelixip-provision-domain`
  helper (packaging) and the exact `rabbitmqctl` incantations go in the
  installation guide. The broker being a prerequisite (§4.7), provisioning
  tooling is documentation + helper script, not kelixip runtime behavior.
- **Restart/HA semantics (§4.6) are per-domain** as a natural consequence:
  a media server restart only disturbs its own vhost.

**`domains.toml` — the `[domain.mediaserver]` block** (kelixip side).
Consistent with the file's philosophy — the block's presence enables
bus-based media for the domain; a domain without it has no media servers
(or, during the transition, falls back to the static `config.toml` pool):

```toml
[[domain]]
name = "visio.example.com"
# ...

  [domain.mediaserver]
  # Vhost carrying this domain's media bus. Default: "kelixip.<name>".
  # Point several domains at the same vhost to share a media-server pool.
  #vhost = "kelixip.visio.example.com"

  # Per-domain controller credential on that vhost (least privilege:
  # a leaked credential opens one domain, not all of them).
  username      = "kelixip-visio"
  password_file = "/etc/kelixip/secrets/visio.mq"   # or inline `password`

  # Optional broker override; default is the global [mediaserver.bus]
  # url list in config.toml (URL without vhost path — vhost comes from
  # this block).
  #urls = ["amqps://broker2.example.com"]

  # Which planes this domain may allocate on (default: both).
  #planes = ["mcu", "jsr309"]

  # Establishment TTL (§4.2) — per-domain override, default 2000.
  #alloc_timeout_ms = 2000
```

Global, non-per-domain parameters live in `config.toml` under a new
`[mediaserver.bus]` section: broker URL list, CA bundle, client TLS
cert/key (mTLS), AMQP heartbeat, reconnect backoff, and the default
`alloc_timeout_ms`. Split rationale: what identifies *the broker* is
node-global and rarely changes (config.toml, restart); what identifies *a
domain on the broker* is hot-reloadable with the rest of the domain
(`kelictl domain reload-all` opens/closes the per-vhost connections
atomically with the domain add/remove).

### 4.10 HA topology — two controllers, clustered broker, connection strategy

Target: **two redundant kelixip controllers** (BEAM-distributed; their
software structure is a separate design, out of scope here) and a
**clustered RabbitMQ**; the resulting network must survive the loss of any
one controller instance *or* any one broker instance. This section settles
the bus-level consequences only: queue types, and how many
connections/queues each participant maintains.

**Broker cluster: 3 nodes, not 2.** A two-node RabbitMQ cluster fails the
requirement twice over: a 2-replica quorum queue loses availability the
moment *either* node dies (a majority of 2 is 2), and there is no sane
partition strategy (`pause_minority` with two nodes pauses both sides).
The third node can be a small VM — colocated with one of the controller
machines if needed — since it only carries the third Raft replica of the
alloc queues (+ DLX) per vhost, with next to no traffic. Cluster settings:
`cluster_partition_handling = pause_minority`, Khepri metadata store on
4.x. The §4.8 queue-type table is unchanged; the quorum choice for the
alloc queues is simply what makes them survive a broker-node loss
(sub-second-to-seconds Raft re-election pause, absorbed by the §4.2
establishment retries).

**One connection per participant — no per-broker duplication.** The load-
bearing fact: **cluster routing decouples the attachment point from the
queue location**. A controller attached to node B publishes into an
exclusive queue whose owner is connected to node A; the cluster routes
internally. From this:

- A media server keeps **one** connection (URL list of the three nodes,
  jittered reconnect, re-declare its exclusive queue on reconnect). A
  standing connection per broker node would only shrink reconnect latency —
  it cannot remove the failure window, which is already covered end to end:
  `mandatory` returns give the publisher certainty ("not queued" → safe
  retry, no duplicate), callers retry within the 10 s RPC timeout, the
  presence `boot_epoch` separates blip from restart (§4.6), and in-progress
  calls' media does not traverse the broker at all.
- A **private queue per broker node is counter-indicated**, not just
  unnecessary: an exclusive queue cannot be declared from two connections —
  that `RESOURCE_LOCKED` *is* the duplicate-instance guard (§4.3), and
  working around it (per-broker names `kelixip.rpc.ms1.<node>`, dual
  addresses in presence, controller-side failover between them) buys a
  few seconds of reconnect latency at the price of complexity in both the
  C++ and the Elixir clients.
- Controllers: one connection per vhost as designed (§4.9), **spread across
  the broker nodes** (rotate the URL list per vhost) so a node loss only
  disturbs a slice of the domains at a time.
- What is genuinely lost when a broker node dies: RPC requests *already
  sitting* in exclusive queues homed on that node (they die with the
  queue → caller timeout, ~seconds of exposure); up to one presence
  heartbeat; and events published while an affected controller's exclusive
  event queue is being re-declared (an unbound topic exchange drops, it
  does not buffer — a controller may miss e.g. one `player_ended` during
  its reconnect window, and scenario-level timeouts must remain the
  backstop for missed events, as they already are today for a lost
  long-poll frame). All absorbed by the existing timeout/grace machinery.

**Failure walkthrough:**

| Loss | What happens |
|---|---|
| 1 broker node | Alloc queues stay available (Raft majority). Participants attached to the dead node reconnect to a survivor and re-declare their exclusive queues; publishes toward the vanished queues are `mandatory`-returned and retried. No `mark_stale` anywhere (`boot_epoch` unchanged). |
| 1 controller | Nothing on the bus fails over: each controller owns its own exclusive presence/event queues and already holds the full pool view; the surviving one keeps allocating. Recovering the dead controller's *sessions* is a kelixip-layer concern (BEAM distribution), designed separately. |
| 1 media server | §4.6 unchanged (presence loss / epoch change → stale/recreate). |

**Fallback when only two machines exist:** do **not** build a 2-node
cluster. The sane two-machine pattern is **two independent brokers with
client-side redundancy**: every participant keeps one connection *per
broker*; a media server declares its private queue and consumes the alloc
queues *on each broker*, and publishes presence and events *to both*;
controllers deduplicate by `message_id` and pick one broker per
establishment (failover on return/timeout). This is the one world where
"one connection per RabbitMQ, one private queue per RabbitMQ" is the right
answer — it is the pattern's foundation — at the cost of duplicated client
logic in both C++ and Elixir plus event dedup. Documented as a fallback,
not the recommendation; the alloc queues degrade to plain durable classic
queues there (no cluster to replicate across).

## 5. Media-server side (C++)

### 5.1 AMQP client library

Replace vendored `AMQPcpp` with **rabbitmq-c** (`librabbitmq`) used directly:
it is packaged for EL9, supports `amqps://` (OpenSSL), and the wrapper we
need is small (one connection, two consumers, one publisher). AMQP-CPP
(Copernica) is the alternative if we want an event-loop style; not required.

### 5.2 Structure

Revive the two-class shape under `mcu/src/moteli/`:

- `MoteliBus` (ex-`McuRabbitServer`): owns the TLS connection, declares
  `kelixip.rpc.<instance>` (**exclusive** — a `RESOURCE_LOCKED` on declare
  means a duplicate instance name: log and exit), consumes the alloc queues
  with **manual acks + prefetch** (the legacy `AMQP_NOACK` consumption is
  gone: the ack is sent after the session exists and the response is
  published, so an unacked establishment fails over to another server,
  §4.2), runs the presence timer and the reconnect loop (keep the existing
  loop's shape; add jittered backoff, re-declare the exclusive queue on
  reconnect).
- `MoteliDispatcher` (ex-`McuRabbitHandler`): decodes `ControlRequest`,
  dispatches into `MCU*` / the JSR-309 `MediaSessionManager`, publishes
  `ControlResponse` to `reply_to`.

Threading: the Abyss front-end runs every XML-RPC call on its own connection
thread and the core is already thread-safe (`MCU::mutex` + `shared_ptr`
conference refs). The AMQP consumer thread therefore hands each request to a
**small worker pool** (N≈4, `prefetch = N`) rather than calling inline —
keeps slow verbs (ImageMagick text rendering, the reason for Abyss's 1 MB
stack override) from stalling the whole control plane. Worker stacks must be
sized like Abyss's (`handleReqStackSize` lesson).

Events: `MCU` and the JSR-309 side already funnel events through their
streaming handlers; add a `MoteliBus` sink implementing the same producer
interface (`CreateEventQueue`/`AddEvent` equivalent) that publishes to
`kelixip.events` instead of enqueueing for long-poll. The two sinks
implement the same producer interface but are **mutually exclusive in a
given build** (§5.3).

### 5.3 Build & packaging

- Re-enable the legacy `MOTELI=yes` build path in `Makefile.rpm`, **renamed
  to `RABBITMQ=yes`** (and the `#ifdef MOTELI` guards in `main.cpp` become
  `#ifdef RABBITMQ`); deps become `protobuf` (v3) + `librabbitmq` per the
  almalinux9 port plan §G.
- CLI: `--rq-url amqps://user:pass@broker/kelixip` (full URL replaces
  `--rq-host`), `--rq-name <instance>`, `--rq-ca/--rq-cert/--rq-key`
  (default to the DTLS PEM pair as the WS server does).
- **`RABBITMQ=yes` excludes the XML-RPC control plane** (decided
  2026-08-10): the two transports are mutually exclusive in a binary. The
  most practical form is conditional registration in `main.cpp` —
  `#ifndef RABBITMQ` around the `/mcu` and `/jsr309` `XmlHandler`
  registrations, the `/events/*` streaming handlers and the `/upload/*`
  handler — so the handler sources still compile everywhere but nothing
  binds in an MQ build. The `/status/*` pages keep working in both builds
  (bound to localhost, §5.4). Consequence: migration dual-stack happens at
  the **pool level** (an XML-RPC server and an MQ server side by side, each
  running its own build), never inside one process.

### 5.4 Loose ends on the HTTP surface

- `POST /upload/mcu/app/<tag>` (mosaic overlay / background images): add an
  `UploadImage` verb with a `bytes` payload (images are well under AMQP's
  default frame limits). Since an MQ build has no `/upload` handler (§5.3),
  this verb ships **with the MCU plane port (P2)**, not later.
- `/status/*` pages and `GET /stop` stay HTTP but should be bound to
  localhost once MOTELI is the primary control plane (that closes the
  unauthenticated shutdown hole as a side effect).

## 6. Elixir side

Principle: **swap the transport under the existing adapters, keep the logic.**
The RPC-sequence logic (`MediaServer.Mendooze.Conn`, `Sdp`,
`Kelix.Mod.Mcu.Adapter`) is transport-agnostic already — it calls a small
`call(verb, args)` surface and consumes `{:*_event, ...}` messages.

New pieces (in `apps/elixip2`, so both the tool and the server can use them):

- `Moteli.Bus` — one supervised AMQP connection **per vhost** (i.e. per
  served domain, §4.9; lib: `{:amqp, "~> 3.x"}`), channels per consumer,
  reconnect with backoff. Publisher confirms + mandatory for RPC publishes.
  A `Moteli.Bus.Supervisor` maps `domains.toml` reloads to connection
  starts/stops (domain added → connect its vhost; removed → drain and
  close).
- `Moteli.Rpc` — request/response over direct reply-to with per-call
  timeout; encodes/decodes the protox-generated structs.
- `Moteli.Presence` — consumes `kelixip.presence`, maintains the live
  instance table `{instance, boot_epoch, planes, capacity, last_seen}`,
  emits `{:presence, :up | :down | :restarted | :bye, instance}` to
  subscribers.
- `Moteli.Events` — declares the node's event queue, binds, translates
  `Event` protobufs into the existing tuple vocabulary and routes by tag
  (same tag-routing tables as today).

Adapters:

- `MediaServer.Mendooze` gains a sibling `MediaServer.MendoozeMq` (same
  `MediaServer.Behaviour`, same `Conn`/`Sdp` modules, `XmlRpc`+`EventPoller`
  replaced by `Moteli.Rpc`+`Moteli.Events`). Selected per pool entry via the
  existing `module:` field — the pool can mix XML-RPC and MQ servers during
  migration.
- `Kelix.Mod.Mcu.Client`/`EventQueue` likewise get MQ twins; `renew_queue`
  logic is replaced by the `:restarted` presence signal feeding the existing
  `mark_stale`/`recreate_stale`/`gc_orphans` pipeline unchanged.
- `Kelix.MediaPool` **stops selecting** for MQ servers: new-session
  placement goes through the allocation queues (§4.2), so `checkout/1` only
  serves the remaining static/mockup entries during the transition. The
  presence table (§4.4) becomes the pool's source of truth for instance
  state, telemetry and `kelictl` display. `config.toml` keeps an optional
  static section for the transition and for the mockup adapter; a
  `[mediaserver.discovery]` block configures the broker URL and credentials.
- `Kelix.Mod.Mcu.pick_mcu/2` disappears for new conferences (broker
  placement); routing a new participant to an *existing* conference keeps
  using the pinned instance, as today.

Dependencies added: `{:amqp, ...}` and `{:protox, ...}` in
`apps/elixip2/mix.exs` (both reachable from `apps/kelix_modules` through the
existing dependency chain).

## 7. Phasing

1. **P0 — Schemas.** Write the three `.proto` files by transcribing
   MCU-API.md and xmlrpc_jsr309_api.md verb by verb (the enum tables come
   from the C++ headers). Review is the deliverable: this file *is* the
   protocol.
2. **P1 — C++ bus skeleton.** `MoteliBus` on rabbitmq-c with TLS, presence
   publishing, `kelixip.rpc.<instance>` consumer answering a `Ping` verb.
   Testable with `rabbitmqadmin`/a 20-line Elixir script.
3. **P2 — MCU plane.** Port the 68 `/mcu` verbs + 4 events; Elixir
   `Moteli.*` core + `Kelix.Mod.Mcu` MQ twins; end-to-end conference test
   against the existing `mcu.exs` reference scenario.
4. **P3 — JSR-309 plane.** Port the 82 verbs + 7 events;
   `MediaServer.MendoozeMq`; run the existing `MENDOOZE_URL` E2E suite over
   MQ.
5. **P4 — Placement & discovery cutover.** New sessions through the
   allocation queues, presence table live, retire the connect-probe and
   `pick_mcu`; dual-stack soak (one XML-RPC and one MQ server side by side),
   then flip the packaged default.
6. **P5 — Hardening.** Mutual TLS, vhost permission tightening, bind
   `/status` + `/stop` to localhost, remove the static pool section.

P2 before P3 because the MCU plane has the richer HA machinery to validate
(stale/recreate) and the smaller elixip-side blast radius (the module is
already isolated behind its own supervisor).

## 8. Open questions

- **Prefetch/admission policy**: what should a media server's default
  allocation prefetch be, and which local signals (CPU, endpoint count)
  should make it stop consuming the allocation queues? Server-side decision,
  to be settled during P2 with real load figures.
- **Multi-controller (full kelixip HA)**: the bus design supports several
  kelixip nodes (per-node event/presence queues), but conference ownership
  lives in `Kelix.Mod.Mcu` ETS today. Out of scope here; the topology just
  must not preclude it — and it doesn't.
- ~~protox vs protobuf-elixir~~ — resolved at P0: protox 1.7.8 compiles the
  four schemas and round-trips the `oneof`-heavy envelope and `map<>`
  fields; `protoc` is required on build hosts (§3).
