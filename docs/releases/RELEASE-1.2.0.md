# Release 1.2.0

2026-08-04 — 48 commits since 1.1.0 (2026-07-29). Theme of the release: kelixip
learns to process calls — a new **mcu** conference module, the UAS INVITE path
hardened against real proxies and NATs, and a reworked kelictl/REST control
surface.

The MCU is the old-style one with decoding/encoding, image composition on the
server. However it has been renovated and is one of the few Total Conversation
capable MCU with full realtime text (T.140) support and a real text mixer.

## Framework changes

- media: symmetric-NAT latching — the media server can be asked to re-target its
  RTP to the source address it actually observes (`natLatch`).
  `MediaServer.Mendooze` infers it from the negotiation direction (we answer →
  latch, we offered → don't); a `nat_latch: true | false` connection option
  overrides the inference
- per-connection media options (`media_conn_opts`) travel from a scenario down
  to the media adapter
- the IST no longer emits the automatic 100 Trying (deliberate deviation from
  RFC 3261 §17.2.1): behind a proxy that answers its own 100, it was a duplicate
  on the wire. A slow scenario sends `reply_invite(100, "Trying")` itself; the
  IST still absorbs INVITE retransmissions until the first answer

## Framework corrections

- the 200 OK of an INVITE was retransmitted until timer H (32 s) even though the
  ACK had arrived: a proxy re-branches the ACK of a 2xx, so it matched no server
  transaction. The dialog now hands the ACK to the IST that answered. Every
  resent 200 also drew a new ACK that re-ran the scenario's ACK handler
  (attaching the same participant to a conference several times)
- an INVITE retransmission arriving before the application had answered was
  logged and dropped; the IST now absorbs it while there is no response and
  resends the last one once there is. Also fixed: on reliable transports the
  stored "last response" could be the previous one
- Mendooze health check improved, parasitic traces removed

## Domain Specific Language changes

No change.

## elixipp testing tool changes

No change.

## kelixip

Major release: kelixip now processes calls (UAS INVITE) through the dial-plan
and domain scripts — first call function is conferencing via the new mcu module.
A reference call script ships with the core, `scripts/mcu.exs`: it routes a
dialled DID into a conference and maps module verdicts onto SIP responses
(404 / 486 / 488 / 503), deciding no policy itself — the template to derive an
operator's own call scripts from.

- media server pool: a module holding a permanent channel can flag a server as
  suspect (`MediaPool.recheck/3`) — a dead server is detected within seconds
  instead of the 30 s probe cycle; entries believed down are re-probed every 5 s
- module loader: a module's companion beams (e.g. `Mcu.Config`) are loaded and
  reloaded together with the named one — required in a release (embedded code
  server)

### kelictl — command syntax heavily reworked

- commands are regrouped under core nouns:
  - `domain list | show <d> | reload-all` (replaces `reload-domains`)
  - `mediaserver list | show | enable | disable <name>` (replaces `mcu <name> on|off`)
  - `registration list [domain] | show <domain> <aor> | remove <domain> <aor> [contact]`
    (replaces `regs` / `unregister`) — scoped by domain, with everything the
    registrar stores (expiry both ways, source, transport, RFC 5626 identity)
- runtime discovery: `module list`, `kelictl <module> help [cmd]` and
  `GET /modules` publish each module's commands, routes, arguments and help —
  the core names no module
- module command results are rendered from the command's own declaration
  (tables, detail views, human labels for wire enums, nested blocks for rosters
  and per-media statistics) instead of raw Elixir terms
- a failed module command exits with the class it declared: 2 bad argument,
  3 not found, 4 conflict, 5 unavailable (FW-5) — same declaration drives the
  REST status codes
- fixes: `log-level` now reaches the sinks (console/file), not just the primary
  level; the `bin/kelictl` overlay forwards argv as a list so shell quoting
  survives the rpc hop

### REST API changes

- module control commands are nested resources: `/modules/<mod>/…` per each
  command's declared route (FW-4/FW-2)
- registrations are nested under their domain: `GET|DELETE
  /domains/<d>/registrations[/<aor>]`; `GET /registrations` stays as the
  cross-domain view
- new: `GET /domains[/<d>]`, `GET /mediaservers[/<name>]` (configuration,
  operator switch, pool health and per-module health in one view),
  `GET /modules[/<name>]`

### Packaging

- one package per module next to the core: `kelixip`, `kelixip-mod-mcu`,
  `kelixip-mod-registrar`, `kelixip-mod-auth_db` (RPM and deb), each carrying
  its own documentation under `/usr/share/doc/<package>/`

## kelixip modules changes

### auth_db

No change.

### registrar

- `registration show` support: the stored binding detail (expiry, source,
  transport, instance/reg-id) is exposed to the control surface

### mcu

New module: a SIP conference bridge driving the Mendooze MCU over its XML-RPC
`/mcu` interface. See `docs/kelixip/modules/mcu.md` and the module guide.

- calls land in a conference by DID through the dial-plan and the `mcu.exs`
  reference script; `mcu_adhoc.exs` shows a scenario creating, updating and
  destroying conferences itself
- media: audio, video (named mosaic layouts, automatic or manual, H.264 profile
  enforced on the encoder, FPU both ways) and T.140 text with RFC 4103
  redundancy — total conversation by default
- security: SDES and DTLS-SRTP, ICE-lite legs
- takes its media servers from the shared `[mediaserver.pool.*]` (no duplicate
  declaration); a conference can be pinned to one server; survives a media
  server restart, sweeps orphaned conferences, exports Prometheus metrics
- admin surface (kelictl + REST): `conference.create/update/destroy/list/show`,
  `participant.*` (list, show, update, kick), `recording.start/stop`, slot
  pinning (`slot.list/update`), conference logo — layouts are entered as names
  (`layout='2x2 vga'`, `layout=auto`), the wire integers stay accepted
- a name banner can be overlaid on a leg's tile: `admit/3` takes
  `displayname: "..."` or `:auto` (derived from the `From` header)
- fixes: a retransmitted ACK (RFC 3261 §13.2.2.4) re-attached the leg and
  re-emitted `participant.joined` per copy — the reference scenarios now split
  `in_call` into `in_call` + `in_conference` so only the first ACK runs the
  ACK-time sequence, and the registry guards on the participant's state
- the shipped `[module.mcu]` sample block was incomplete while claiming to hold
  the defaults; notably its `audio_codecs` line omitted `TELEPHONE-EVENT`, so
  uncommenting it as shipped silently turned DTMF off

## Documentation

- the design and specification documents are gathered under `docs/design/`; the
  kelixip README points at the user documentation instead of the design docs
- each module ships its own guide (`docs/kelixip/modules/`), installed with its
  package

## Dependencies

- (mediaserver 1.12.0)[https://github.com/neutrino38/mediaserver/releases/tag/1.12.0] and above (MCU XML-RPC interface, `natLatch`,
  `StartReceiving` returning the announce address).
