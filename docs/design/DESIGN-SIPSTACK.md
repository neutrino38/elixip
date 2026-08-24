# DESIGN-SIPSTACK.md — the SIP stack

The as-built design of the SIP protocol stack: **transport, message, transaction
and dialog**. Everything described here is implemented, tested and running in
production traffic; it lives in `apps/elixip2/lib/framework/` and is shared by
both artifacts of the repo.

This document is the **why and how it is built**. It is not a user guide: for
running the tool see [ELIXIPP.md](../../ELIXIPP.md), for certificates and transport
configuration [TLS_WSS.md](../../TLS_WSS.md). The layers above this one are in
[DESIGN-FRAMEWORK.md](DESIGN-FRAMEWORK.md) (session, media, B2BUA),
[DESIGN-FSL.md](DESIGN-FSL.md) (the language and its engine),
[DESIGN-KELIXIP.md](DESIGN-KELIXIP.md) (the server) and
[DESIGN-ELIXIPP.md](DESIGN-ELIXIPP.md) (the test tool).

---

## 1. Layer map and process model

```
                 scenario / session layer          → DESIGN-FRAMEWORK.md
                            ▲
   SIP.Dialog ──────────────┤   one process per dialog
   SIP.DialogImpl           │   Registry.SIPDialog, key {from-tag, Call-ID, to-tag}
                            ▲
   SIP.Transac ─────────────┤   one process per transaction (ICT/IST/NICT/NIST)
   SIP.Trans.Timer          │   Registry.SIP.Transac, key = Via branch
                            ▲
   SIPMsg · SIP.Msg.Ops ────┤   parse / serialize / interpret — no process
   SIP.Uri · SIP.MsgTemplate│
                            ▲
   SIP.Transport.* ─────────┘   one process per socket or per accepted connection
   SIP.Transport.Selector       Registry.SIPTransport, key = instance name
```

| Registry | Key | One entry per |
|---|---|---|
| `Registry.SIPTransport` | instance name — `"UDP"`, `"TCP_1.2.3.4:5060"` | transport instance the Selector may reuse (§3.6) |
| `Registry.SIP.Transac` | Via `branch` value | transaction |
| `Registry.SIPDialog` | `{from-tag, Call-ID, to-tag}` | dialog |

Each layer is started once by `start/0` (`SIP.Transport.Selector.start/0`,
`SIP.Transac.start/0`, `SIP.Dialog.start/0`), which creates its registry and
tolerates an already-started one — a property the test suite depends on, since
several test modules boot the stack.

**Everything is a process, and every process is addressable by a cached pid.**
That is the stack's central design choice and the source of its two recurring
hazards: a cached pid can be dead (§3.8) and a process that crashes must not
take its neighbours down (§5.7).

---

## 2. Message layer

No process. Four modules, one rule.

> **Message interpretation belongs here, in exactly one place.** Anything that
> reads meaning out of a SIP message — header precedence, defaults, tolerance
> for malformed values, "what is this request actually asking for" — is message
> layer code. Callers layer their **policy** on top of that single reading
> (bounds, per-domain config, which SIP code to answer), never their own
> re-parse.

The rule is not stylistic. The REGISTER lifetime rule (RFC 3261 §10.2.4) had
been re-derived five times across the dialog layer, the session mixins, the
kelixip registrar module and a reference scenario, and no two agreed: one read
the header first, so a rebinding handset was taken for an un-registration; one
ignored the header, so a real phone's registration evaporated after 1 s; one
crashed on a valueless `;expires`. Each was found in production traffic, one at
a time, and fixing one never fixed the others.

### 2.1 `SIPMsg` — parse and serialize

Parses a message into a map (`method` atom for a request, `method: false` and a
`response` code for a response) and serializes it back. It also answers
`keepalive?/1` — a bare CRLF ping is not a message and not an error, and saying
so here keeps three error lines per ping out of the server log.

A parse failure **raises**. Callers that face the network catch it (§3.2); a
scenario never sees a half-parsed message.

### 2.2 `SIP.Uri` — two parameter sets that are not interchangeable

`%SIP.Uri{}` keeps URI parameters and header parameters apart:

| Field | Holds | RFC | Examples |
|---|---|---|---|
| `params` | what is *inside* the angle brackets | §25.1 `uri-parameters` | `transport`, `user`, `maddr`, `ttl`, `lr` |
| `hparams` | what follows the closing bracket | `contact-params`, `to-param` | `expires`, `q`, `tag`, `+sip.instance`, `reg-id` |

Read with `get_uri_param/2` or `get_header_param/2`, write with
`set_uri_param/3` or `set_header_param/3` (each clears the name on the other
side), remove with `delete_param/2`. Never hand-build a `params:` map holding a
header parameter.

A Request-URI is not a header value: it is `SIP-URI / SIPS-URI / absoluteURI`,
so it is serialized by `serialize_ruri/1` (= `to_request_uri/1`), which drops the
display name, the header parameters and `method` while keeping **every** URI
parameter — §19.1.5 makes carrying the unknown ones mandatory, so it is never an
allowlist. `SIPMsg` uses it for the Request-Line and the digest computation uses
the same string.

The two sets used to share one map. Forwarding a registered Contact then emitted
`INVITE "Bob" <sip:bob@host>;+sip.instance="<urn:uuid:…>" SIP/2.0` — a
Request-Line with two tokens where one URI belongs — which the callee dropped
without a single response, so every call to a Linphone handset hung in
`proceeding` until the scenario timed out. The denylist of "parameters that are
really header parameters" that preceded this could not be completed: it listed
`q` and `expires`, and traffic brought `+sip.instance`, `+org.linphone.specs`,
`reg-id`, `methods`, `pub-gruu`.

The struct also carries the **resolved transport**: `destip`, `destport`,
`destproto`, `tp_module`, `tp_pid` (nil on a freshly parsed URI, `has_tp_info/1`
tells them apart). That is what turns a URI into a routable destination and what
the Selector reads first (§3.6).

### 2.3 `SIP.Msg.Ops` — the single reading

| Group | Functions |
|---|---|
| REGISTER lifetime | `requested_expires/2`, `contact_lifetimes/2`, `contact_expires/3`, `expires_header/1`, `unregister?/2` — Contact `;expires` wins when present, else the `Expires` header, else the §20.19 default, resolved **per contact** |
| Identity | `asserted_username/1`, `auth_username/1`, `from_username/1`, `to_username/1`, `target_aor/1` |
| Classification | `in_dialog?/1`, `is_response_for?/2`, `reoffer_kind/2`, `sdp_body/1` |
| Construction | `add_via/4`, `reply_to_request/5`, `challenge_request/7`, `ack_request/5`, `cancel_request/1`, `update_sip_msg/2` |
| Forwarding (B2BUA) | `prepare_forwarded_request/2`, `forwarded_reply_fields/1` — the purge/copy of hop-by-hop headers |
| Generation | `generate_branch_value/0`, `generate_from_or_to_tag/0`, `generate_boundary/0`, `add_transaction_id/1` |
| Digest | `add_authorization_to_req/6`, `check_authrequest/3` (see §6) |

`add_via/4` validates the port range and the transport token, and raises on an
impossible Via rather than emitting one.

### 2.4 `SIP.MsgTemplate`

Builds the common requests and responses from a template plus bindings. Used by
`SIP.Transac.start_uac_transaction_with_template/4` and by the FSL macros, so a
scenario never assembles headers by hand.

---

## 3. Transport layer

### 3.1 The contract

A transport is a **plain GenServer, one per flow**: one per bound UDP socket, one
per accepted or opened TCP/TLS/WSS connection. It is reached by
`GenServer.call(pid, {:sendmsg, msg, ip, port})` and it pushes what it receives
upwards. There is no behaviour module; the shared body lives in
`SIP.Transport.ImplHelpers`, which every implementation calls:

| Helper | Role |
|---|---|
| `connect/3` | outbound socket setup, common to TCP/TLS/WSS |
| `process_incoming_message/7` | the whole inbound pipeline (§3.2) |
| `notify_transport_down/2` | broadcast a dead flow to the dialogs using it |
| `remote_address/1` | peer address off a `:gen_tcp` port, an `:sslsocket` or a `Socket.Web` |

Each module exports `transport_str/0` (`"UDP"`, `"TCP"`, …), which the Selector
uses to name an instance and `SIP.Transport.build_contact_uri/2` to stamp a
Contact.

### 3.2 The inbound pipeline

`process_incoming_message/7` applies, in this order:

1. **keep-alive?** → dropped with a debug line. Not an error.
2. **STUN?** (`SIP.Stun.decode/1`) → dropped, and the log names STUN. A SIP UDP
   port legitimately receives these: RFC 5626 §4.4.2 makes a STUN Binding
   Request the keep-alive of an outbound UDP flow, and ICE clients and scanners
   land there too. We answer nothing — we are not a STUN server — so the sender
   gives up on the flow, and the log line is a lead instead of a parser error.
3. **parse and dispatch**, wrapped in a `try/rescue`. One peer's odd datagram
   must not take down the transport that serves everyone else on the socket. It
   did: a Linphone ACK with no Content-Length raised inside the parser, the
   process died, the ACK never reached its transaction — so the call answered and
   then carried no media — and each retransmission killed the restarted process
   again. Dropping the datagram with a log is what a transport owes its other
   dialogs; the parse bug it uncovers is fixed in the message layer.
4. `SIP.Transac.process_sip_message/3` matches an existing transaction. On
   `:no_matching_transaction`:
   - a **response** → dropped with a warning;
   - an **ACK** → straight to `SIP.Dialog.process_incoming_request/3`. The ACK of
     a 2xx carries a new branch (§13.2.2.4) and creates no server transaction
     (§17.2.3), so the TU is its only correct destination;
   - any other **request** → a new UAS transaction, stamped with the local
     address (the transport's own resolved IP/port, not the socket's `0.0.0.0`
     wildcard) and with the R-URI enriched (§3.4).

### 3.3 `SIP.Transport.Depack` — stream reassembly

TCP and TLS deliver a byte stream with no message boundaries, so both feed a
`%Depack{}` buffer: `wait_for_msg → reading_headers → reading_body`, driven by
`Content-Length`, emitting complete messages and re-processing trailing bytes so
pipelined messages are not lost.

**WSS does not use it** — WebSocket frames are already message-delimited.

A CRLF keep-alive reaches the first-line parser having already lost its CRLF, so
it shows up as an *empty* line: the buffer asks the message layer
(`SIPMsg.keepalive?/1`) instead of pattern-matching on `"\r\n"`, which never
matched. Every ping used to take the error path and flush the buffer, dropping
whatever valid message was pipelined behind it.

### 3.4 Listeners

Three listeners — `TCPListener`, `TLSListener`, `WSSListener` — with one model:

```
SIP.Transport.<X>Listener          one per bound port
   │  binds a server socket, runs an accept loop in a linked Task
   ├── SIP.Transport.<X>  :inbound     one per accepted connection
   └── SIP.Transport.<X>  :inbound     …
```

The connection transport is the **same module** as the outbound one, with a
second `init/1` clause for an accepted socket. No new module per direction.

A listener is **not** in `Registry.SIPTransport`, and neither are the
connections it spawns: they are not destinations anyone resolves to. It is
started by whoever owns the port — `elixipp`'s `--listen`, kelixip's listener
supervisor — and it holds its connections itself.

**Ownership transfer.** The accept loop hands the socket to the spawned process
(`controlling_process` / `:ssl.controlling_process`) and only then activates it.
Activating first would deliver the first packets to the acceptor, which is not
the process that will parse them.

**Connection limit.** Read at startup from the app env, per transport:
`:tcp_max_connections`, `:tls_max_connections`, `:wss_max_connections`. Over the
limit the accepted socket is closed immediately and a warning logged — rejecting
at the transport layer is what a saturated system does anyway, and it costs no
SIP response.

**Bookkeeping.** `connections` is keyed by **monitor reference**, so a `:DOWN`
is an O(1) lookup; a reverse index on `{peer_ip, peer_port}` serves outbound
routing through an existing connection.

**The reply path is not the Selector's business.** When a request arrives,
`process_incoming_message/7` enriches its R-URI with
`destip`/`destport`/`tp_module`/`tp_pid: self()`. The transactions then reply
through that pid, so a response goes back over the very connection the request
came in on (§18.2.2) without any lookup. This is also what makes replies to a
**NATed** client work, and the Selector reuses the same field (§3.6, level 1).

### 3.5 Per-transport specifics

| | Reliable | Reassembly | Listener | Notes |
|---|---|---|---|---|
| UDP | no | — | shared socket | binds `:udp_local_addr`, or every interface of the node's family when it is unset; `:udp_local_port` (default 5060). Opened straight through `:gen_udp` so the family and the address reach the socket. A bind failure aborts the boot, so the log spells the posix reason out |
| TCP | yes | `Depack` | `TCPListener` | one process per connection |
| TLS | yes | `Depack` | `TLSListener` | mirrors TCP; `:ssl` API, `:sslsocket` cases in the helpers; per-listener `:tls_certfile` / `:tls_keyfile` |
| WSS | yes | none | `WSSListener` | TLS accept + WebSocket upgrade, then `Socket.Web.active/2` |

**WSS activation is the one asymmetry.** `Socket.Web.active/2` spawns a
*separate reader process* that delivers `{:web, ws, data}` frames. The WSS
GenServer **monitors that reader**, so a silent disconnect stops the GenServer
and decrements the listener's connection count. Without the monitor a browser
that vanished left a live process holding a dead socket, and the listener
counted it forever.

### 3.6 `SIP.Transport.Selector` — three levels

Picking a transport for an outbound message is answered in this order, and the
first answer wins:

1. **An existing flow.** The URI carries a live `tp_pid` — an inbound connection
   spawned by a listener (a NATed browser's WSS/TCP/TLS) or a socket we already
   hold. Use it as-is: no DNS, and deliberately **no `Registry.SIPTransport`
   lookup** either. That lookup is the trap: inbound connections are not
   registered there, so it would try to open a *new outbound* connection to the
   peer — impossible toward a NATed client, pointless for a socket we hold. The
   transport module must be known (`tp_module` or `destproto`); it is never
   guessed.
2. **A resolved destination.** IP and port already known (a stored binding's
   `received`, a configured next hop). Skip DNS. No `destproto` ⇒ UDP.
3. **Resolve the R-URI** through `SIP.Resolver` (NAPTR/SRV/A), then find or
   launch the transport instance in `Registry.SIPTransport`.

A `;unittest=<value>` R-URI short-circuits all three to the in-process mockup
(§8), and keeps winning over an existing flow so the test suite is unaffected by
level 1.

**Instance naming decides sharing.** At level 3 the instance name is
`"<PROTO>_<ip>:<port>"` for a **reliable** transport — one process per
destination, since a connection *is* the destination — and the bare protocol
(`"UDP"`) for an unreliable one, so a single socket serves every peer. A
transport module may override the name by exporting `select_instance/1`; the
test mockup uses that to give a suite one instance per simulated peer. The
lookup is checked for liveness and the `:already_started` race is treated as a
hit, because two scenarios starting at once resolve the same destination.

Once found, the pid is written into the URI (`tp_pid`) and travels with the
message — which is what turns it into the cached pid of §3.8 and the level-1
flow of a later request.

### 3.7 Via and Contact stamping

`SIP.Transport.build_contact_uri/2` and `add_contact_header/3` are the single
place a Contact is built, from the transport that will actually carry the
message: its address, its port, **and its transport**, lower case.

The transport is part of the address, not a decoration. `sip:host:5070` reads as
UDP to every UA (RFC 3263 §4.1), so a dialog established over TCP whose Contact
omits it gets its BYE aimed at a UDP port — the call then never hangs up on an
otherwise working leg. And the value goes out lower case: case-insensitive on
paper (§19.1.4), case-sensitive in the field. We emitted `transport=TCP`, and a
capture shows the caller ACKing over UDP a dialog whose every other message was
TCP, having failed to recognise it.

The B2BUA consequences of this rule (rewriting the Contact on both legs,
unconditionally) belong to the session layer — see
[DESIGN-FRAMEWORK.md](DESIGN-FRAMEWORK.md).

### 3.8 A cached pid can be dead

A transport pid is cached — in a transaction's state, in a dialog's `msg.ruri` —
so it long outlives any liveness check. `GenServer.call` on a dead one raises an
exit **in the caller's callback**, and the callers are a transaction (whose death
used to take its dialog with it) and a dialog handling a scenario's call (whose
exit propagated to the scenario and skipped its whole teardown).

`SIP.Transport.safe_call/2` turns that into `:transporterror` — a return value
every caller already handles, because a send can always fail. On a connectionless
transport the caller may then re-select and retry; on a connected one the flow is
gone and `notify_transport_down/2` broadcasts it to the dialogs once, from
`terminate/2`.

### 3.9 Configuration keys

| Key | Default | Effect |
|---|---|---|
| `:udp_local_port` | 5060 | UDP bind port |
| `:udp_local_addr` | first local address of the node's family | the address the socket binds AND the one advertised in Via/Contact |
| `:udp_family` | `:ipv4` | the node's family when `:udp_local_addr` is unset. Read through `SIP.NetUtils.preferred_family/0`, which the resolver reads too |
| `:tcp_max_connections` / `:tls_max_connections` / `:wss_max_connections` | 100 | accepted connections per listener |
| `:tls_certfile` / `:tls_keyfile` | see `TLS_WSS.md` | listener certificate, overridable per listener |
| `:sip_timer_T1` | 500 ms | base of timers B, F, H |
| `:optionkeepaliveperiod` | 15 s | OPTIONS keep-alive interval (§5.6) |
| `:unittest_transport` | — | mockup module, set by `test_helper.exs` only |

---

## 4. Transaction layer

### 4.1 Four machines over one core

| Module | Role | Initial state |
|---|---|---|
| `SIP.ICT` | INVITE client | `:sending` |
| `SIP.IST` | INVITE server | `:trying` |
| `SIP.NICT` | non-INVITE client | `:sending` |
| `SIP.NIST` | non-INVITE server | `:trying` |

The four modules hold their entry point and what is specific to them; the
transitions themselves are in **`SIP.Transac.Common`**, which also sends through
the transport (always via `safe_call`, §3.8), builds responses, arms timers and
ends the transaction. That is why a state machine module is barely a hundred
lines. The shared state set is `:sending` / `:trying` → `:proceeding` →
`:confirmed` / `:rejected` → `:terminated`, plus `:cancelling` for a client
transaction whose CANCEL is in flight.

### 4.2 Timers

`SIP.Trans.Timer` owns them all. `T1 = 500 ms` (overridable), `T2 = 4 s`,
`T4 = 5 s`.

| Timer | Armed by | Purpose |
|---|---|---|
| A | ICT/NICT | retransmission over an unreliable transport, doubling up to T2 |
| B | ICT | overall client-transaction timeout (64·T1) |
| D | ICT | absorb response retransmissions after a final |
| F | NICT | non-INVITE overall timeout |
| H | IST | wait for the ACK of a non-2xx final |
| K | NIST/IST | absorb retransmissions after a final (`:default`, `:after_ack` or explicit) |
| 100 | IST | send `100 Trying` after 200 ms if the TU has not answered |

Timer 100 is deliberately **delayed**: an application that answers immediately
(a rejection, a redirect) sends one response instead of two.

### 4.3 Entry points

| Function | Use |
|---|---|
| `start_uac_transaction/2`, `..._with_template/4` | send a request; an ACK or a response is rejected by a guard |
| `start_uas_transaction/2` | called by the transport for an inbound request |
| `process_sip_message/3` | match an inbound message to its transaction (by Via branch) |
| `reply/5`, `reply_req/6` | answer a server transaction |
| `confirm_uas_transaction/2` | hand an ACK to the IST that is retransmitting its 2xx |
| `ack_uac_transaction/1`, `cancel_uac_transaction/1` | ACK / CANCEL a client transaction |

An ACK never starts a transaction: for a non-2xx it is absorbed by the IST, for
a 2xx it belongs to the dialog (§3.2).

---

## 5. Dialog layer

`SIP.Dialog` is the API, `SIP.DialogImpl` the GenServer.

### 5.1 Identity

A dialog is `{from-tag, Call-ID, to-tag}`, registered in `Registry.SIPDialog`.
Creating an outbound dialog fills in what the request lacks: a generated Call-ID,
a generated from-tag written into the From URI's **header** parameters. The
to-tag arrives with the dialog-establishing response — and a *forked* dialog
adopts only a **2xx**'s tag.

### 5.2 State

Beyond the identity the dialog holds: the initiating message, the `allows` list,
the **route set** (Record-Route of the establishing response), the **remote
target** (its Contact), the direction, the transactions it owns as a map
`pid => %{req:, module:}`, the transaction that will close it, the IST still
waiting for an ACK, the application pid, an optional event `tag`, and the
forking branch table.

The transactions are a map and not a pid list because a transaction that
**crashes** says nothing: to hand the application the synthetic 408 it is owed
the dialog must name the request that died with it (Call-ID, CSeq, both
identities) and tell a client transaction from a server one — only the former's
failure is the application's business.

`ist_awaiting_ack` exists because the ACK of a 2xx matches no transaction: the
dialog receives it and must tell that IST to stop retransmitting (§13.3.1.4).

### 5.3 API

`start_dialog/5`, `process_incoming_request/3`, `new_request/2`, `reply/5`,
`challenge/4`, `ack/2`, `ack_pending_invite/1`, `cancel/2`, `fork_branch/3`,
`terminate/2`, `broadcast/1`, plus the keep-alive controls.

### 5.4 Forking

The initial request may go to several targets as several client transactions of
**this** dialog — same Call-ID, from-tag and CSeq, one fresh Via branch each
(the kamailio TM model). `branches` maps each transaction to its target;
`forking` says the hunt is on, which is what keeps the dialog alive when a branch
returns a non-2xx final: there may be another target to try. The winner is
adopted on both layers, the losers are CANCELled, a late 2xx is ACKed then BYEd.

Serial hunting, parallel forking and q-group policy are **session-layer**
concerns — see [DESIGN-FRAMEWORK.md](DESIGN-FRAMEWORK.md).

### 5.5 The termination contract

When a call ends the dialog sends the application exactly one
`{:dialog_terminated, dialog_pid, reason}`. Applications release their
call-scoped resources on it — a media connection above all. "Exactly one" is
part of the contract: a transport-down and a BYE arriving together used to
produce two, and the second one tore down a session that had already been
rebuilt.

### 5.6 OPTIONS keep-alive

`SIP.DialogKeepAlive` is composed into `SIP.DialogImpl` — pure functions over the
dialog state, no process of its own; the timer lives in the dialog GenServer and
fires `{:timeout, tref, :optionskeepalive}`. It keeps an outbound dialog
(typically a REGISTER one) and its NAT binding alive every
`:optionkeepaliveperiod` seconds. An application can take it over
(`app_drives_keepalive/1`).

### 5.7 Resilience

The stack survives a crash or a disconnection under a leg. Six behaviours, all
implemented and covered by a failure-injection test set:

| | Behaviour |
|---|---|
| R1 | the dialog traps exits; a transaction crash becomes a **synthetic 408** to the application (§17.1.1.2 / §8.1.3.1 give it the same meaning as a timeout) |
| R2 | the scenario engine catches exits, so teardown always runs |
| R3 | connectionless transport re-selection, and exit-safe transport calls (§3.8) |
| R4 | transport-down is broadcast once, from `terminate/2` |
| R5 | a transport dying during a hunt is a **branch** failure, not a dialog death |
| R6 | a leg death purges the leg and answers its pending requests |

---

## 6. Authentication

| Module | Role |
|---|---|
| `SIP.Auth` | digest computation and verification, MD5 / SHA1 / SHA256, `qop=auth` |
| `SIP.Auth.Nonce` | **stateless** nonce: `base64url(ts ‖ rand ‖ HMAC-SHA256(secret, ts ‖ rand ‖ realm))`. Validation recomputes the HMAC — no storage — and checks `now − ts ≤ max_age`; beyond that it is `:stale`, the challenge is re-issued with `stale=true` and the client replays transparently. The realm is bound into the HMAC, so a nonce minted for one domain is useless on another |
| `SIP.Auth.Secret` | the server secret keying the nonce. Ephemeral, regenerated at boot (a restart only costs one `stale=true` round trip), designed to become shared across nodes for HA |

The message-layer side is `challenge_request/7`, `add_authorization_to_req/6`
and `check_authrequest/3` (§2.3). **Who** is challenged, and against which
backend, is application policy — see
[DESIGN-KELIXIP.md](DESIGN-KELIXIP.md) for the `auth_db` module.

---

## 7. Resolution and network utilities

- **`SIP.Resolver`** — DNS for SIP: NAPTR/SRV/A. SRV ordering (RFC 2782, priority
  then weighted random) is a **pure, public** function (`order_srv/1`): that is
  where all the logic is, and testing it must not need a DNS server. The lookup
  around it does the I/O and nothing else.
- **`SIP.NetUtils`** — interface enumeration, IPv4/IPv6 parsing and formatting
  (`ip2string/1`, `parse_address/1`), and `pick_free_port/2` (a free port ≥ 5000,
  used when no local port is imposed so two instances coexist on one host).
- **`SIP.Stun`** — enough of RFC 5389 to tell a STUN message from a SIP one on a
  shared port and decode its header (§3.2). Demultiplexing is unambiguous, by the
  rule RFC 7983 uses for the same problem.

---

## 8. Testing the stack

Test support lives in `apps/elixip2/test/support/`, compiled in `:test` only.

- **`SIP.Test.Transport.Mockup`** — an in-process fake transport. The Selector
  routes any `;unittest=…` R-URI to it through the `:unittest_transport` app env,
  so the library references no test code. `;unittest=1` is the shared instance;
  any other value (`;unittest=callee`) names an instance of its own, which is how
  a B2BUA suite gets one peer per leg.
- **`SIP.Test.Peer`** — the behaviour of a simulated remote party: pure callbacks
  returning actions (`{:inject, msg, after_ms}`, `{:notify, event}`). Canned
  peers in `SIP.Test.Peers.*` (Passive, AnsweringUAS, BusyUAS, NoAnswerUAS,
  ChallengingUAS, RegisterOK), one module per scenario, delays as options.
  `SIP.Test.Peers.Manual` is the exception — the test drives it one message at a
  time, because a B2BUA suite asserts on the request that went out before
  deciding how the far end answers it.
- **`SIP.Test.Probe`** — a normalized event stream to the test process:
  `{:sip_mockup, {:request_sent | :response_sent, …}}`.

---

## 9. Invariants

The short list. Breaking one of these has cost a production incident before.

1. Message interpretation happens in the message layer, once (§2).
2. URI parameters and header parameters are different sets; a Request-URI goes
   out through `serialize_ruri/1` (§2.2).
3. A Contact carries the transport that will actually carry the message, lower
   case (§3.7).
4. A transport is called through `safe_call/2`; a cached pid may be dead (§3.8).
5. An inbound request's R-URI carries its flow; replies follow it, never a fresh
   resolution (§3.4).
6. One peer's bad packet never kills a transport process (§3.2).
7. A dialog sends exactly one `{:dialog_terminated, …}` (§5.5).
8. The ACK of a 2xx belongs to the dialog, not to a transaction (§3.2, §5.2).
