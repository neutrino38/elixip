# Release 1.5.1

2026-08-20 — 21 commits since 1.5.0 (2026-08-19). Theme: **a conference an
operator declared comes back**. The `mcu` module gains persistent definitions, a
video codec preference, and an admission call that wires the leg it admits. Two
signalling refusals that ended live calls are fixed, and the node's video
bandwidth becomes one key instead of two compiled-in defaults.

Reference: [docs/kelixip/modules/mcu.md](../kelixip/modules/mcu.md) to operate
the module and [DESIGN-MCU.md](../design/DESIGN-MCU.md) for how it is built.

## Conferences that survive a restart

- `[module.mcu] conference_file` holds the conference **definitions** as JSON,
  rewritten whole on every change and read once at module start. The calls still
  go with the node; the rooms come back.
- Only rooms somebody declared are written — every REST/CLI create, and a script
  asking for `owner: :none`. A room made for one call is not: resurrecting it at
  every boot would be a room nobody asked for.
- A restored row is inserted `stale`, with no server-side id, so the path that
  already rebuilds a conference after a media-server restart is what gives it its
  MCU-side existence. There is no second way to create a conference, and a DID
  cannot be handed out twice.
- Failure has a direction: **the operator's file is never destroyed.** A file
  that does not parse disables persistence for the run and is left alone; one
  malformed row costs only its own room, named in the log; a failed write is
  logged and the command still succeeds.
- The file is meant to be readable and hand-editable: `"vad": "full"`,
  `"video": {"size": "hd720p"}` are read by the same vocabulary that accepts an
  operator's input at the control surface.
- Unset, there is no persistence, and the module says so once at start.

Design: [DESIGN-MCU.md](../design/DESIGN-MCU.md#41-what-survives-the-node).

## A conference can name its video codec

- `preferred_video_codec` (a conference field, `[module.mcu]` default) names the
  video codec a conference states **first** in its answers, hence what the mixer
  encodes towards a leg that offered it.
- It is a preference and not a codec list: it moves a payload type the caller
  offered **and** the media server accepted, and nothing else. It states no
  capability, filters nothing, and cannot make a call fail.
- A miss is logged per leg, naming which of the two dropped it — the answer a
  codec list could never give: "the caller never offered it", or "the media
  server refused it".
- This does not walk back the delegated negotiation of 1.2.1: the answerer owns
  the *order* (RFC 3264 §6.1) and the server's verdict is a *set*.
- The point-to-point path takes the same idea per media:
  `reply_invite_with_sdp(200, prefer_codecs: [video: ["H264"]])`. `record.exs`
  uses it because MP4 carries no VP8 — a recording that would otherwise need
  transcoding, or lose its video.

## Admission wires the leg

- `Kelix.Mod.Mcu.admit/4` now sets the three things an admitted conference leg
  needs before `media_connect()`: its local identity (the conference DID),
  its connection options (which conference it joins, and `nat_latch`), and the
  media server the conference is pinned to.
- None of that is a call-flow decision, so `mcu.exs` and `mcu_adhoc.exs` stopped
  stating it. A script needing other connection options sets them after `admit`.

## Bandwidth

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
- Deriving a leg's picture size from what its bitrate really carries is designed
  and not built — it is server-side work (S6 of
  [mcu_server_evolutions.md](../design/mcu_server_evolutions.md)).

## Signalling fixes

- **An offerless UPDATE no longer ends the call.** It is the RFC 4028
  session-timer refresh, and it is answered with a bare 200 (RFC 3311 §5.1)
  rather than raising. Clients refresh every 45 s, so this killed long calls.
- **And it is answered on the leg it arrived on**, in either direction. A
  session timer runs between us and *one* peer, on a leg where we are its UA;
  relaying the refresh puts a request on a leg that has a timer of its own.
  `bridge()` applies the rule whatever the media mode, so a signalling B2BUA gets
  it too.
- **A REGISTER refresh arriving on a new connection prolongs its registration.**
  A reconnecting client reused an old dialog and got a second registrar session
  while the first stayed live until its transport dropped.
- **WSS keep-alive**: ping/pong is handled, so an idle WebSocket is no longer
  dropped by whatever sits in the middle.
- Inbound SIP messages are logged at debug level, which is what makes any of the
  above readable after the fact.

## Reference scripts

- The three `direct-call*.exs` are the SBB versions of 1.5.0, and the
  session-timer rule they were carrying moved into `bridge()`. They state no
  in-dialog plumbing at all.
- `b2bua.exs` is gone (1.5.0): it was a copy of `direct-call.exs`.

## Documentation

- [DESIGN-MCU.md](../design/DESIGN-MCU.md) covers persistence, the admission
  wiring and the codec preference; "no persistence" is no longer a non-goal.
- S6 — the encoded geometry as an output of rate control rather than a setting —
  is specified in
  [mcu_server_evolutions.md](../design/mcu_server_evolutions.md), where the
  server-side work lives.
- The `mcu` module doc gains the encoder profile's short form
  (`video='vga 30fps 1024k'`), the rooms-that-survive section, and the wiring
  table under `admit()`.
- `FSL.md` documents what `media_record/3` actually acts on, and which of its
  declared options the media server implements — none of four.
- The transport-wide-cc implementation prompt moves to
  [notes/](../design/notes/kelixip-transport-wide-cc.md), the contract it records
  being its remaining value.

## Breaking changes

- **Conference video defaults follow what an operator names**: `video_fps` 15 →
  30 and `video_bitrate` 1024 → 1500 kb/s. A conference created without naming
  them changes.
- The mosaic canvas and the encoded size are held equal: naming one moves the
  other, and naming both differently keeps the **encoded** one and warns.
- The User-Agent is `Kelixip/1.5.1` on the server and `Elixipp-1.5.1` on the
  tool.

## Dependencies

- `socket2` moves to `d7c3f07` on the `feat/active-ws` branch of the fork — the
  WebSocket fixes behind the keep-alive work, previously carried as a local patch
  in `deps/`.

## Packaging

- new `[mediaserver]` keys: `video_bitrate`, `bitrate_feedback`, `transport_cc`.
- new `[module.mcu]` keys: `preferred_video_codec`, `conference_file`;
  `video_fps` and `video_bitrate` defaults change as above.
- `conference_file` wants a writable directory for the `kelixip` user; the
  shipped example is `/var/lib/kelixip/conferences.json`.
