# Release 1.2.1

2026-08-07 — 31 commits since 1.2.0 (2026-08-04). Theme of the release:
**interoperability**. Codec negotiation is now delegated to the medooze media
server, which is what made the interop campaign possible: WebRTC calls with MS Edge
and Chrome, and with Linphone 6.2.0 in SDES as well as DTLS. Basic recording and
playback have been retested. On the kelixip side, a configuration that cannot be
served is now refused at boot and at reload instead of failing call by call.

## Framework changes

- media: support for non standard realtime text over Websocket
- media: refined H.264 negociation with a tolerance when `packetization_mode` parameter is absent
- media: added AV1 support
- fully delegated codec negociation to medooze media server. The offer is the menu:
  the media server picks, and the answer is built from its verdict — which is
  checked against the offer before it goes out, so a server that accepts something
  that was never proposed is caught here rather than by the caller
- media: RFC 5939 transport capability negotiation is parsed, so an AVPF *potential
  configuration* is answered with real feedback instead of being ignored
- media: `a=rtcp-fb` is answered on video whatever the RTP profile says — Linphone
  6.2.0 offers `RTP/SAVP` while asking for `ccm tmmbr`/`ccm fir` and reads the answer's
  attributes, not its profile string. An assumed deviation from RFC 4585 §4; the
  answered profile itself is unchanged, and the matching media-server switches
  (`useNACK`/`useRtcpFIR`/`tmmbr`) follow the answered set as before
- media: `nack pli` joins the answerable feedback types, 
- medias: :ice_connected event is issued using a combination per media connectivity
  events to maximize the chance of media connectivity.

## Framework corrections

- corrected SRTP call handling with proven interop with Linphone 6.2.0
- corrected WebRTC call handling with proven interop with Edge
- the answer now follows the order the caller offered its codecs in, and the profile
  it names is the one the media server reported it accepted
- `UDP/TLS/RTP/SAVP` — the DTLS profile a plain SIP phone offers — is accepted
- SIP: a missing `Content-Length` on a datagram is no longer a parse error (it is
  optional there), and a malformed message no longer takes the transport down
- SIP: corrected in-dialog UAC requests and loose routing handling.

## Domain Specific Language changes

No change.

## elixipp testing tool changes

No change.

## kelixip

- scenario are prechecked before kelixip is started or reloaded (kelictl domain `reload-all`).
  in case a check fails the reload is refused with the running configuration untouched.
- If scenario precheck fails during kelixip startup, the boot process is aborted.
- two scenarios files with the same module cannot be loaded.
- `systemctl reload kelixip` is now supported with the same prechecks. A refused reload
  makes the command fail, so systemd and the journal report it

### kelictl

- new `kelictl reload-all`: `domains.toml`, to reload kelixip configurations that
  can be applied live. Note that config.toml change cannot be applied live.
- `kelictl domain show <domain>` list the modules associated with the scenarios and
  indicate whether they are up to date, missing, cannot compile or changed.

### REST API changes

- new `POST /reload-all`, the same operation as `kelictl reload-all`: `200` with a
  per-stage report, `400` with the reason when it was refused
- `mcu`: `audio_codecs`, `video_codecs`, `text_codecs` and `video_fmtp` are **no
  longer honoured** on `conference.create` / `conference.update` — the media server
  arbitrates codecs. They are accepted and ignored for this release, with a warning
  in the log, and become an error in the next one. Use `medias` to choose which of
  audio / video / text a conference answers, and `dtmf` to stop proposing
  telephone-event

### Packaging

- the systemd unit's reload command changed (see above); no new package, no new
  path. `systemctl daemon-reload` is done by the package scriptlets as usual
- the `kelixip-mod-mcu` package now also ships the REST API reference of the module

### auth_db

No change.

### registrar

No change.

### mcu

- **new: a collaboration channel between participants script.** A participant's script can
  collaborate other participants' scripts —i e.g. a raised hand, a floor-control
  token — addressed to everyone, to everyone but itself, or to one participant 
- support for participant with text over WebSocket.
- As codec negotiation is delegated to the media server (see *Framework changes*): a
  conference no longer holds codec lists
- admit()  has new `medias` parameter to specify with which of audio / video / text
  medias a participant is admitted conference. 
- Correction of mosaic aspect ratio based on the received video format
- RTP inactivity watchdog: a leg is killed only once **every** watched media has
  gone silent
- realtime text over WebSocket is answered on the **JSR-309** path only; on the
  conference path the WebSocket text section is omitted from the answer, which is
  what the tested client requires

## Documentation

- new **[mcu REST API reference](../kelixip/modules/mcu-api.md)**: every endpoint of
  the module, its arguments, its JSON payloads and its statuses — enough to write a
  client from. 
- reloading a running node is documented end to end (what is applied live, what
  needs a restart, what a refusal looks like) in
  [administration.md](../kelixip/administration.md#reloading-a-running-node) and
  [running.md](../kelixip/running.md)

## Dependencies

- [mediaserver 1.12.2](https://github.com/neutrino38/mediaserver/releases/tag/1.12.2) 
