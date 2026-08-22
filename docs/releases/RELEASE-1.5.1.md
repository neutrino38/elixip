# Release 1.5.1

2026-08-20 — 21 commits since 1.5.0 (2026-08-19). Theme: **a conference an
operator declared comes back**. The `mcu` module gains persistent definitions, a
video codec preference, and an admission call that wires the leg it admits. Two
signalling refusals that ended live calls are fixed, and the node's video
bandwidth becomes one key instead of two compiled-in defaults.

Reference: [docs/kelixip/modules/mcu.md](../kelixip/modules/mcu.md) to operate
the module and [DESIGN-MCU.md](../design/DESIGN-MCU.md) for how it is built.

## MCU kelixip module

- MCU conferences are now persistent and are recreated upon restarting kelixip
- only conferences created using kelictl or REST API are persisted
- `[module.mcu] conference_file` specify the persistance file to be used. If
  not set persistency is not activated.

For more details refert to [DESIGN-MCU.md](../design/DESIGN-MCU.md#41-what-survives-the-node).


- using kelixip or the REST API, it is now possible to specify a preferred video
  codec for a confererence. In that case, the SDP answer sent back will place this
  codec as its preferred choice *if the offer contains this codec*.

- `Kelix.Mod.Mcu.admit/4` takes care of setting the right variable in `sip_ctx`.
- **Conference video defaults**: `video_fps` 30 and `video_bitrate` 1500 kb/s.
- The mosaic canvas and video encoder size are held equal: naming one moves the
  other, and naming both differently keeps the **encoded** one and warns.

## Mediaserver

- `[mediaserver] video_bitrate` is one key per node — what a video leg is encoded
  at, and the cap on the `b=AS:` answered. It replaces two compiled-in defaults,
  800 kb/s on one media path and 1024 on the other, neither reachable from
  `config.toml`. Conferences may still override it.
- `[mediaserver] bitrate_feedback` narrows which RTCP bitrate-feedback dialects
  are answered (`goog-remb`, `tmmbr`, or `none`); `goog-remb` is answered and
  switched on server-side.
- `[mediaserver] transport_cc` negotiates transport-wide congestion control on
  WebRTC video legs. **Off by default**: the media server does not yet report
  arrivals for the streams it receives.

## Media fixes

- **A leg that offers ICE to a peer answering without it now trggers the NAT latch
  NAT.** 
- **A renegotiation no longer drops the media on a WebRTC leg.** 

## Signalling fixes

- support for **UPDATE without SDP**: it is the RFC 4028 session-timer refresh, 
  and it is answered with a bare 200 (RFC 3311 §5.1) and not propagated to the
  other leg.
- **A REGISTER refresh arriving on a new connection prolongs its registration.**
  A reconnecting client reused an old dialog and got a second registrar session
  while the first stayed live until its transport dropped.
- **WSS keep-alive**: ping/pong is handled, so an idle WebSocket is no longer
  dropped by whatever sits in the middle.
- Inbound SIP messages are logged at debug level, which is what makes any of the
  above readable after the fact.
- The User-Agent is `Kelixip/1.5.1` on the server and `Elixipp-1.5.1` on the

## Reference scripts

- The three `direct-call*.exs` are the SBB versions of 1.5.0, and the
  session-timer rule they were carrying moved into `bridge()`. They state no
  in-dialog plumbing at all.
- `b2bua.exs` is gone (1.5.0): it was a copy of `direct-call.exs`.

## Documentation

- [DESIGN-MCU.md](../design/DESIGN-MCU.md) covers persistence, the admission
  wiring and the codec preference.
- The encoded geometry as an output of rate control rather than a setting —
  is specified in
  [mcu_server_evolutions.md](../design/mcu_server_evolutions.md), where the
  server-side work lives. (`video='vga 30fps 1024k'`), the rooms-that-survive
  section, and the wiring table under `admit()`.
- `FSL.md` documents what `media_record/3` actually acts on, and which of its
  declared options the media server implements — none of four.
- The transport-wide-cc implementation prompt moves to
  [notes/](../design/notes/kelixip-transport-wide-cc.md), the contract it records
  being its remaining value.


## Packaging

- `conference_file` wants a writable directory for the `kelixip` user; the
  shipped example is `/var/lib/kelixip/conferences.json`.

## Dependencies

- [Medooze mediaserver](https://github.com/neutrino38/mediaserver) **1.13.0
  is required**
