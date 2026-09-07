# Release 1.5.2

2026-09-06 — 85 commits since 1.5.1 (2026-08-22). Theme: **a node has several
faces**. One kelixip now speaks IPv4 and IPv6, on an internal side and a public
side, and it announces to each correspondent the address that correspondent can
reach. Six of the seven steps of
[multi-interface.md](../design/multi-interface.md) are delivered.

Three other deliveries: 
- real-time text travels on a WebRTC data channel
(RFC 8865), 
- a B2BUA call can recorded on both legs, i
- and kelixip **asks** the media server what it can do instead of declaring it.

Reference: [multi-interface.md](../design/multi-interface.md) for the network
design, [installation.md](../kelixip/installation.md) for the new `config.toml`
keys.

## Multi-interface and IPv6

The bulk of this release. Every step is described in
[multi-interface.md](../design/multi-interface.md).

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

Two operational points, both of which may prevent a mediaserver to start:

- a media server whose only public address is IPv6 requires `--default-profile publicv6`. 
- `--internal-ip` restricts the XML-RPC interface to the internal address. 

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

Two constraints, refused at boot: an explicit `addr` is required, and the same
family as `addr`.

- **No STUN client.** It would add a network dependency at boot and a failure
  mode, for no information this key does not already carry. The media server made
  the same choice with `--public-ip`.

## Security — the outbound TLS leg verifies
### Network profiles of the media

- The `MediaServer.Mendooze` adapter queries the server (`GetNetworkProfiles`) on
  connection.
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


## Security — the outbound TLS leg checks

TLS verification can be activated.

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

## Real-time text on a WebRTC data channel (RFC 8865)

Support for parsing **data channel** (RFC 8865)i SDPs: `m=application … UDP/DTLS/SCTP
  webrtc-datachannel` and use it for carrying realtime text.

T.140 over data channel is offered by default on a WebRTC leg.
`text_transport: :rtp` asks for an `m=text` instead; a leg without DTLS gets RTP
  whatever it asks for.

Text over Websocket is still supported.

The MOTELI protobuf contract follows in the same lot: `PROTO_SCTP`,
`SetupDataChannel` and `SetupParticipantDataChannel`.

## Recording both legs of a B2BUA call

A recorder is attached to an endpoint and writes what that endpoint **receives**.
Recording a whole call therefore takes two of them, one per leg.

```elixir
media_record("/rec/#{id}-caller.mp4", 0, wait_video: false)
media_record("/rec/#{id}-callee.mp4", 0, leg: :outbound, wait_video: false)
```

## The media server describes itself

`kelictl mediaserver show <name>` now displays what the media server **answers**

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

`server: unknown` means the server does not describe itself: an older binary, or
the `mockup` adapter. Selection and health do not depend on it.

## MCU module

- New **`Mcu.SBB.conference(opts)`** that handles the conferencing after admission.
  This aims to simplify conferencing scripts.
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

- **PostgreSQL** driver support
- The driver appears in `kelictl auth_db show`.
- **`SBB.authenticate(realm: "…")` finally uses the domain option passed** instead of
  ignoring it. 

## Framework

- **`SIP.Msg.Ops` implements RFC 5168 Fast Update Request**, in both directions: reading a
  picture-fast-update request out of a message, 
- `SIP.NetUtils.net_side/1` is the one place a correspondent is classified
  internal or public. It answers from the node's topology, never from the address:
- `%SIP.Uri{}` gains `net_side`, beside `destip` and `tp_pid`. It stores only the
  side: the family is read off `destip`.

## kelictl

- **`kelictl monitor continuous`**: the same view as `monitor`, redrawn live as
  scenarios appear, change state or end. No polling. Runs until stdin closes
  (Ctrl+D).

## Packaging

- **`elixipp` is now packaged**: `packaging/build-rpm-elixipp.sh` produces an RPM
  carrying the command `/usr/bin/elixipp`, plus `ELIXIPP.md` and `FSL.md`. 
- `packaging/build-rpm.sh` now produces only the RPMs of the current version.
- **SELinux on Alma Linux 9**: the post-install script labels the two launcher
  directories `bin_t`, 
- `kelictl` checks the cookie before using it, 
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

## Dependencies

- [Medooze mediaserver](https://github.com/neutrino38/mediaserver) **1.14.0 is
  required**: the `GET /status/general` endpoint, `GetNetworkProfiles` and the
  data channel RPCs arrive there.
- `postgrex` 0.22.4 is added, for auth_db's PostgreSQL driver.

