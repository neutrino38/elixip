# Release 1.5.2

2026-09-06 — 85 commits since 1.5.1 (2026-08-22). Theme: **a node has several
faces**. One kelixip now speaks IPv4 and IPv6, on an internal side and a public
side, and it announces to each correspondent the address that correspondent can
reach. Six of the seven steps of
[multi-interface.md](../design/multi-interface.md) are delivered.

Three other deliveries: real-time text travels on a WebRTC data channel
(RFC 8865), a B2BUA call is recorded on both legs, and kelixip **asks** the media
server what it can do instead of declaring it.

Reference: [multi-interface.md](../design/multi-interface.md) for the network
design, [installation.md](../kelixip/installation.md) for the new `config.toml`
keys.

## Multi-interface and IPv6

The bulk of this release. Every step is described in
[multi-interface.md](../design/multi-interface.md).

### Message layer

- An IPv6 address is written in brackets in a SIP message (RFC 3261 §19.1.1), and
  is read in both forms. `SIP.NetUtils.sip_host/1` is the one place that puts the
  brackets on. That conversion had been copied five times.
- A malformed host no longer raises out of the parser.

### Listeners

Three new keys in a `[[listen]]` block. All optional: a 1.5.1 configuration works
as it stands.

| Key | Role |
|---|---|
| `addr` | accepts an IPv6 address. It is what gives the listener its family. **Absent**, the listener takes both families, one socket each |
| `tag` | `internal` or `public` (default). Which side of the network this listener sits on |
| `networks` | list of CIDRs. The networks that define the internal side. When present it **replaces** the automatic detection |
| `advertise` | the public face of `addr`, for a machine behind a 1:1 NAT |

- An `internal` listener defines the internal network. By default, by the subnet
  of the interface carrying its `addr`. `networks` is for an internal network
  reached through a router, or when the interface carries a /16 while the
  internal network is a /24.
- An `internal` listener with neither `addr` nor `networks` is refused at boot. It
  sits on every subnet, so it defines none.
- TCP, TLS and WSS can all three bind on an explicit IPv6 address.
- UDP is now **one socket per family**, and the selector picks by destination. A
  second `udp` entry of a family already bound is ignored with a warning.

### `advertise` — one interface, two faces

On a VM behind a 1:1 NAT the operator knows the public address. An AWS EIP does
not move, and nothing on the machine can derive it. `advertise` names it.

It is **not a flat substitution**. The same interface serves both sides: a private
UA and a public UA arrive on the same socket, because the NAT rewrote the
destination. Each has to see the face it can reach.

| The peer is… | What it receives |
|---|---|
| public | the advertised address (`advertise`) |
| internal | the bound address (`addr`) |
| unknown | the advertised address — a NATed node serves mostly the outside |

The substitution happens at publication time, in one place
(`SIP.Transport.publish_ip/2`). The transport keeps answering the address it
really binds: the media layer reads it to choose an interface.

Three things carry it: the Contact, the Via, and the SDP address. Route and
Record-Route need nothing — a B2BUA is a UA on each leg, it never writes an
address of its own in them.

Two constraints, refused at boot: an explicit `addr` is required, and the same
family as `addr`.

- **No STUN client.** It would add a network dependency at boot and a failure
  mode, for no information this key does not already carry. The media server made
  the same choice with `--public-ip`.

### Network profiles of the media

- The `MediaServer.Mendooze` adapter queries the server (`GetNetworkProfiles`) on
  connection. No profile list is written on the kelixip side.
- The pool re-reads each server's profiles on every health probe, so a media
  server restarting with other addresses is followed on its own.
- Each leg derives its profile from the local address it uses, and sets it on
  `EndpointStartReceiving` and `EndpointStartSending`.
- The B2BUA resolves its targets **before** trying one (`b2bua_resolve/1`), marks
  each with its network side, then asks the pool for a server carrying every
  profile in play.
- A hunt walking through several profiles gets **one endpoint per profile**, built
  when it reaches that profile. The address of the `c=` line is fixed when the
  endpoint is created: it cannot be renegotiated in place.

### MCU module

- The MCU module places each leg on the profile of its correspondent's family. A
  call whose family the server does not carry is refused, rather than accepted
  with an unreachable address.
- Interoperability fixed between Chrome and an IPv6-only MCU conference.

Two operational points, both of which bite at boot rather than during a call:

- a media server whose only public address is IPv6 wants
  `--default-profile publicv6`. The historical default is `publicv4`, and an
  unavailable default profile makes the media server refuse to start;
- `--internal-ip` restricts the XML-RPC interface to the internal address. The
  pool's `url` must then name that address. An IPv6 goes **in brackets**:
  `http://[fd00::12]:8080`.

## Security — the outbound TLS leg verifies

`ImplHelpers.connect/3` passed `verify: false`. Every outbound TLS or WSS leg
therefore accepted any certificate, from anyone able to answer on the address.

```toml
[tls]
verify = false            # default, as in 1.5.1
#verify = true
#ca = "/etc/kelixip/tls/interco-ca.pem"
```

- **The name checked is the SIP domain of the URI, never the resolved address**
  (RFC 5922 §7.2). Without that, OTP falls back to the address dialled, which
  needs an iPAddress SAN almost no SIP certificate carries.
- The key is **node-wide**, not per listener: it says who this node is willing to
  talk to. `[[listen]] cert`/`key` remains the inbound side.
- `verify` stays `false` by default. Verifying a peer supposes an authority agreed
  with it, so an interconnection agreement. Name `ca` at the same time as you turn
  `verify` to `true`.
- A `ca` that cannot be read fails the boot.
- Step 7 is only half delivered: **inbound** mTLS (`verify_peer` on the listener)
  is still to do. An mTLS served by a client that verifies nothing is theatre, so
  this half goes first.

## Real-time text on a WebRTC data channel (RFC 8865)

A browser cannot carry T.140 on an RTP profile: `RTCPeerConnection` has no
`m=text`. There are two ways round it, and the adapter drives both.

- The **WebSocket** beside the call: the peer asks for it, we answer a URL. We
  never offer one. It is a door, opened when someone knocks.
- The **data channel** (RFC 8865): `m=application … UDP/DTLS/SCTP
  webrtc-datachannel`, inside the leg's own DTLS and ICE. It is answered when
  offered, **and it is what our own offers carry by default on a WebRTC leg**.
  `text_transport: :rtp` asks for an `m=text` instead; a leg without DTLS gets RTP
  whatever it asks for.

This holds for a B2BUA leg as much as for an MCU conference leg.

Three differences with the WebSocket case, each one a call that would have
failed:

- a data channel section is **declined with port 0**, never omitted. It is in the
  browser's real offer, and libwebrtc counts the answer's `m=` lines against its
  own;
- the `m=` line says `application`, the medium is the call's text. A rejection
  uses the offered name;
- **no `a=dcmap`** (RFC 8864). Declaring the channel in the SDP is what tells a
  peer *not* to open it in band, and the media server binds its text channel on
  the DCEP `OPEN`.

`a=sctp-port` and `a=max-message-size` come from the media server
(`SetupDataChannel`), never from a constant on this side.

The MOTELI protobuf contract follows in the same lot: `PROTO_SCTP`,
`SetupDataChannel` and `SetupParticipantDataChannel`.

## Recording both legs of a B2BUA call

A recorder is attached to an endpoint and writes what that endpoint **receives**.
Recording a whole call therefore takes two of them, one per leg.

```elixir
media_record("/rec/#{id}-caller.mp4", 0, wait_video: false)
media_record("/rec/#{id}-callee.mp4", 0, leg: :outbound, wait_video: false)
```

- Nothing mixes the two. A single file holding both sides is a conference, not a
  B2BUA.
- Each recorder writes the medias **its own** leg carries. The three medias of a
  Total Conversation call are recorded only if both legs were negotiated with the
  three.
- `media_leg_of/1` says which leg a handle carried by an `{:ms_event, …}` belongs
  to. That is what lets a two-leg scenario read `:media_lost` and
  `{:media_timeout, media}`.
- A leg has one action slot: one player, recorder or echo at a time. A second
  request on a busy leg is refused with a warning.
- `media_stop()` stops one leg — `:inbound` by default, `leg: :outbound` for the
  other — and `media_stop(leg: :all)` stops every leg at once.
- Stopping matters: closing the file is what writes the MP4 index.
  `media_cleanup_ressources()` already stops every leg on the way out.

## The media server describes itself

`kelictl mediaserver show <name>` now displays what the media server **answers**
on its `GET /status/general` endpoint, re-read on the same 30 s probe cycle as
the addressing profiles. `kelictl mediaserver list` gains a `version` column. The
body is also exposed verbatim by the REST API.

```
server:       mediaserver 1.14.0, up 3h12m5s (mcu-01, pid 4711)
ffmpeg:       5.1.10
audio decode: OPUS PCMU PCMA G722 AAC AMR-WB AMR SPEEX16 GSM
video encode: H264 VP8 AV1 H263_1998 MPEG4 SORENSON
text:         rfc4103 yes (redundancy yes), rfc8865 yes, websocket yes
profiles:
  publicv4    bind * (every interface)  announced 203.0.113.9  (default)
  publicv6    bind 2001:db8::12         announced 2001:db8::12
```

Nothing in there is configured on this side, and that is the whole point. A
controller that cannot **ask** ends up **declaring**, and that copy drifts:
kelixip offered H.264 and VP8 for months while the server carried AV1, and an
AV1 ↔ AV1 call died on a 488 with perfect audio at both ends.

Two warnings for whoever reads it:

- `video decode` and `video encode` are not the same list, and neither are the
  audio ones. `decode` is what the server can **receive**, `encode` what it can
  **emit**. VP6 arrives in RTMP streams and no encoder for it exists anywhere.
- A profile carries **two addresses**. `bind` is the interface the socket takes,
  `announced` is what the peer sees in the SDP. They differ behind a NAT.

`server: unknown` means the server does not describe itself: an older binary, or
the `mockup` adapter. Selection and health do not depend on it.

## MCU module

- **`Mcu.SBB.conference(opts)`** publishes a leg's whole life in the mix as a
  service building block. The block absorbs the SIP a conference leg owes whatever
  the deployment: the ACK that puts the participant in the mix and the
  retransmitted copies that must not re-run it, an INFO answered `200` whether or
  not it asks for a frame, the RFC 5168 frame requests in both directions, a BYE
  answered before the slot is released, our own BYE followed by a wait for its
  `200`, and a leg gone silent hung up.
- It **never** composes a response to an offer: your `answering` state states the
  `200`, and a renegotiation comes back for you to answer.
- What the block fixes on the way: `on_events` compiles to a `receive` and nothing
  injects a catch-all clause. A media event a script had never been taught about
  matched no clause and sat in the mailbox for the whole call. A leg whose media
  died held its slot until the 2 h backstop, silently. The block puts a floor
  under both event families.
- `mcu.exs` and `mcu_adhoc.exs` take the block. They had already drifted apart by
  three clauses.
- A script that takes the block no longer calls `attach()` nor `do_attach/1`.
- **Hold and resume fixed**: a hold is a `sendrecv` → `sendonly` transition, not a
  direction. A hold longer than 10 s killed an audio-only leg through the RTP
  watchdog.
- **No more ICE restart on every renegotiation**: a fresh ufrag/pwd on each offer
  kept Linphone from leaving the hold. Confirmed in traffic on 2026-08-23.
- **Improved H.264 selection** when the caller advertises several profiles and
  several packetization modes: the `main` profile and packetization mode 1 are
  preferred.

## auth_db module

- **PostgreSQL** is a second driver for the `subscriber` table. `driver =
  "postgres"` in `[module.auth_db]`, default port 5432. `mysql` remains the
  default, so a 1.5.1 configuration does not move.
- The driver appears in `kelictl auth_db show`.
- **`SBB.authenticate(realm: "…")` finally uses the option passed** instead of
  ignoring it. The entry options of a service building block are now really handed
  to the block, which holds for every block.

## Framework

- **`SIP.Msg.Ops` owns the RFC 5168 primitive**, in both directions: reading a
  picture-fast-update request out of a message, and composing one. It was a pair
  of private functions copied into each MCU reference script, where neither the
  content type nor the primitive was checked the same way twice. Any video leg
  meets that question, not only a conference leg.
- `SIP.NetUtils.net_side/1` is the one place a correspondent is classified
  internal or public. It answers from the node's topology, never from the address:
  a site can route RFC 1918 space it does not consider internal, and an internal
  network can be globally addressable IPv6.
- `%SIP.Uri{}` gains `net_side`, beside `destip` and `tp_pid`. It stores only the
  side: the family is read off `destip`.

## kelictl

- **`kelictl monitor continuous`**: the same view as `monitor`, redrawn live as
  scenarios appear, change state or end. No polling. Runs until stdin closes
  (Ctrl+D).

## Packaging

- **`elixipp` is packaged**: `packaging/build-rpm-elixipp.sh` produces an RPM
  carrying the escript in `/usr/bin/elixipp`, plus `ELIXIPP.md` and `FSL.md`. It
  is pure BEAM bytecode, so it has no target-OS requirement — unlike the kelixip
  package, whose release embeds a natively-linked ERTS.
- `elixipp` is installed on whatever host runs test scenarios, never on a kelixip
  node.
- `packaging/build-rpm.sh` now produces only the RPMs of the current version.
- **SELinux on Alma Linux 9**: the post-install script labels the two launcher
  directories `bin_t`, which is what puts the service in the
  `unconfined_service_t` domain. Without it the node exited during boot on
  `Protocol 'inet_tcp': register/listen error: eacces`. The package now depends on
  `policycoreutils-python-utils`.
- `kelictl` checks the cookie before using it, and says what to do instead of
  letting a `cat: Permission denied` through.
- The service reads `cert` and `key` as the unprivileged `kelixip` user: a key
  installed 0600 `root:root` fails that boot. `/etc/kelixip/tls/` is already 0750
  `root:kelixip` for that purpose.

## Documentation

- [multi-interface.md](../design/multi-interface.md) is the network design: the
  seven steps, what is delivered, and the two keys set aside (`[network]` at node
  level, and the STUN client).
- [installation.md](../kelixip/installation.md) documents `tag`, `networks`,
  `advertise`, the `[tls]` section, IPv6 on the media server side and SELinux.
- [administration.md](../kelixip/administration.md) explains what the media server
  says about itself, and how to read it.
- [DESIGN-FRAMEWORK.md §6.5](../design/DESIGN-FRAMEWORK.md) covers text on a
  WebRTC leg, and the three asymmetries with the WebSocket.
- [mcu.md](../kelixip/modules/mcu.md) separates what the module publishes:
  functions and macros for a **decision**, blocks for a **sequence**.
- [B2BUA.md](../../B2BUA.md) and
  [CODEC-NEGOTIATION.md](../../CODEC-NEGOTIATION.md) state where each codec lever
  belongs, which no warning says: `video_codec:` / `audio_codec:` / `text_codec:`
  act on `outbound:`, the leg we offer on, and are a **hard bound** there;
  `prefer_codecs:` acts on `inbound:`, the leg we answer on, and only reorders.
- `FSL.md` documents `media_record` per leg, `media_leg_of/1` and
  `media_stop(opts)`.
- `CLAUDE.md` rules that the `docs/design/DESIGN-*.md` corpus is English.
- `docs/design/mcu_module_evolutions.md` is gone, its content having joined
  `DESIGN-MCU.md`.

## Dependencies

- [Medooze mediaserver](https://github.com/neutrino38/mediaserver) **1.14.0 is
  required**: the `GET /status/general` endpoint, `GetNetworkProfiles` and the
  data channel RPCs arrive there.
- `socket2` now tracks the fork's `master` branch (`2cf11407`), which carries the
  IPv6 support and the mTLS options.
- `postgrex` 0.22.4 is added, for auth_db's PostgreSQL driver.

## Versions

The User-Agent is `Kelixip/1.5.2` on the server and `Elixipp-1.5.2` on the test
tool.
