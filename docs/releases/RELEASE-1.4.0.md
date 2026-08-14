# Release 1.4.0

2026-08-14 — 49 commits since 1.3.0 (2026-08-10). Theme: **the media relay
proven in traffic**. The 1.3.0 B2BUA was exercised against real Linphone 6.2.0
endpoints in both directions — registration, digest auth on INVITE, relay under
`transcode: :avoid`, and real VP8 ↔ H.264 transcoding. Not exercised yet:
real-time text relay, and a SIP ↔ WebRTC call through the B2BUA.

## Framework changes

### Codec negotiation across the two legs

See [CODEC-NEGOTIATION.md](../../CODEC-NEGOTIATION.md), new with this release.

- **cross-leg selection** (`mediagw_b2bua_jsr309.md` §5): each leg records
  `peer_codecs` and the codec is picked once for both legs. Transcoding is no
  longer a decision of its own — it is what two different selections mean.
- **wideband speex** (`speex/16000`) enters the Mendooze vocabulary and the
  default outbound audio menu. The clock rate is now part of the codec identity,
  so `speex/8000` no longer matches; validated in traffic both directions.
- **the wiring is the policy's**: `:forbid` attaches `Endpoint ↔ Endpoint`,
  `:avoid` and `:force` both go through the transcoder. The transcoder decides
  per packet, so an `:avoid` call whose legs agree stays a relay.
- **the answer is shaped by the other leg**: a relayed media announces the
  intersection, a transcoded one keeps the whole offer with the common codecs
  first. Nothing is ever added (RFC 3264 §6.1).
- **the peer's format order decides the codec**, not the payload-type number. A
  static PT used to beat a dynamic one, so two opus legs were bridged by a PCMU
  transcoder.
- **the video send map carries every codec the leg can receive**, one PT per
  codec, with the selection taken at bridge time. Pinning it at answer time let
  H.264 go out labelled AV1.
- **the answer rebuilt at bridge time is now actually sent**. `complete_media`
  computed it, stored it, and sent the stale one from INVITE time.
- **AV1 joins the default outgoing video offer** (`AV1, H264, VP8`). The
  outbound leg offered from a static list without it, so an AV1-to-AV1 call died
  on a 488.
- **a media the callee declined no longer kills the call**. `{:not_negotiated,
  media}` is fatal for audio only; anything else is declined with port 0.

### In the tree since the tag, not yet validated in traffic

- **a declined media is propagated across the B2BUA**: a port-0 section in an
  answer (RFC 3264 §6) or a re-offer (§5.1) is recorded as the peer's verdict and
  declined on the other leg too. 

### NAT, media timing, and giving up

- **NAT latching on both legs**, not only where we answer an offer. A NATed
  callee writing a private address in its answer used to get every outgoing
  packet sent to an unroutable address.
- **the RTP inactivity watchdog is armed when the call is answered**, not at SDP
  negotiation. 
- **a wedged media server is given up on in 2 seconds**, not 10. A JSR-309 RPC
  answers in 2–15 ms; per-RPC timeout 10 s → 2 s, enclosing GenServer 30 s → 10 s.
- **no media server means a 503 — never the test stub**. A pooled MCU that went
  away used to fall back to the global config, whose default is `:mockup`;
  `Kelix.Router.media_override/1` now returns `:unavailable` instead.

### SIP correctness on the wire

Six defects, all measured in the captures of 2026-08-14 and confirmed fixed the
same day, both directions:

- **URI parameters are serialized inside angle brackets**. Unbracketed, RFC 3261
  §20 reads them as header parameters, so a Contact saying `transport=tcp` still
  got its ACK and BYE over UDP.
- **the stamped Contact carries the transport, in lower case**. A B2BUA-built
  Contact had no `transport` at all — `sip:host:5070` reads as UDP (RFC 3263
  §4.1) — and upper-case `TCP` went unrecognized in the field.
- **the Contact identity crosses the B2BUA**: userpart and display name are
  relayed both ways. Host, port and transport stay the leg's own.
- **Route is no longer echoed into responses** (RFC 3261 Table 3). Record-Route
  still crosses into the 2xx.
- **a dialog hangs up once**: a relayed BYE used to be followed by the teardown's
  own 48 ms later. A second BYE is now refused while one is in flight.
- **the ACK of a 2xx gets a fresh Via branch** (§17.1.1.3). The ACK of a non-2xx
  keeps the INVITE's, as before.

### Keep-alives and STUN on the SIP port

- **CRLF keep-alives** (RFC 5626 §4.4.1) are recognized and consumed on stream
  and datagram transports. 
- new **`SIP.Stun`**: STUN is demultiplexed from SIP by the RFC 7983 rule,
  decoded and logged. We do not answer a Binding Response yet.

### The registrar session

Field-validated on 2026-08-11 against a Linphone re-enabling its account, which
left two registrar sessions for one binding. Three causes:

- `SIP.DialogImpl` arms the expiration timer from the request that creates the
  dialog. A REGISTER accepted on the first request produced a dialog with no
  timer at all.
- new **`SIP.Dialog.terminate/2`**: end a dialog from outside, stating why. The
  application gets the promised `{:dialog_terminated, _, reason}`.
- `Kelix.Mod.Registrar` hands the binding over and **supersedes** the previous
  dialog. 

The registrar verbs gained context-first forms (`challenge_registration/3`,
`accept_registration/3`), reading the verdict from `lasterr` like every other DSL
verb. The positional forms stay.

### Authenticating calls, not only registrations

- **`SIP.Msg.Ops.challenge_header/1`** is the one home of the 401 →
  `WWW-Authenticate` / 407 → `Proxy-Authenticate` mapping. It had two copies.
- new `from_username/1`, `to_username/1`, `in_dialog?/1` — the raw claims.
  Deliberately not the digest-verified name, which cannot fail against itself.

## Framework corrections

- **ex_sdp 1.2**: the `a=fingerprint` hash compared case-insensitively (RFC 8122
  §5) and the `m=` fmt list parsed for every RTP profile, both upstream now. Our
  two local workarounds are gone; `fmtp_raw` stays.
- **the callee-side hangup is covered**: a BYE arriving on the outbound leg had
  no test in either suite. The relay logs now name the leg.
- diagnosed, not a defect: the PT 0 packets heading every RTP stream are 54-byte
  bare headers, the media server's NAT priming. No audio ever left as PCMU.

## Domain Specific Language changes

- new **`b2bua_challenge/2..3`**: the application builds the challenge and the
  verb sends it on the leg the event came from. 407 is the default, since many
  UAs will not retry a 401 on an INVITE.
- new **`b2bua_media_unavailable?/0`** — how a script tells "no media server"
  from a codec problem. It answers 503 rather than 488.
- `use_mediaserver` now sets `:lasterr` to `:ok` on success. Failure was already
  reported there.

## elixipp testing tool changes

No functional change (version bump, SBoM licensing metadata). The built-in
scenarios run by module name work again — see Framework corrections.

## kelixip

- **`User-Agent: Kelixip/1.4.0`**.
- new [`direct-call-with-auth.exs`](../../apps/kelixip/scripts/direct-call-with-auth.exs):
  `direct-call.exs` plus three states in front of the call, the module answering
  a verdict and the script composing the SIP. A refused INVITE does not end the
  instance.
- new [`direct-call-with-auth-and-media.exs`](../../apps/kelixip/scripts/direct-call-with-auth-and-media.exs):
  the same call with the media relay in the middle. `transcode: :avoid` on audio
  and video, plus the 503 branch.
- `registrar.exs` gains a `wait_auth_register` state. A challenged registration
  waits for the authenticated REGISTER in a state of its own.
- `play.exs` and `record.exs` gain `ringing` and `no_media_server` states, so the
  180 comes after the media server is known to exist. `record.exs` joins the
  repository, where it existed only as a hand-copied file on the target.
- `Kelix.Auth.challenge_www_authenticate/2` is renamed **`challenge_params/2`**:
  the params are identical for 401 and 407. No alias left behind.

### kelictl

- new **`kelictl auth_db show`** (`GET /modules/auth_db/db`): a live `SELECT 1`,
  where the link points, TLS or clear with the reason — never the password.
  `down` is an answer, so the command stays usable when the base is unreachable.

### REST API changes

No change. The `mcu` codec keys announced in 1.2.1 as becoming an error are still
accepted and ignored with a warning.

### auth_db

- **it authenticates any request, not only REGISTER**: new `authenticate/3`
  returns the same verdict plus the proven identity. `do_registration_auth/3` is
  that function applied to a registration.
- new `challengeable?/1` — an initial request other than ACK, CANCEL and OPTIONS.
  ACK carries no response, CANCEL must be accepted, OPTIONS is liveness probing.
- new **identity check**: a valid digest proves who holds the password, not that
  the `From` is theirs. `identity_check` = `strict` / `warn` / `off`, shipped as
  `warn`.
- a refused request logs one line naming the cause (`bad_password`,
  `unknown_user`, `bad_realm`). The wire answer stays a bare 403.
- **the DB link tries TLS first**
- new `fetch_credential/3`: facade.

### registrar

- **`save/2` takes the scenario context**, reading domain and dialog from it. The
  positional form stays.
- the binding hand-over on re-registration is the module half of the
  one-session-per-binding fix (see *The registrar session*).

### mcu

- `call_answered/1` is a documented no-op. A conference leg arms its watchdog at
  `attach/1`, already after the ringing.
- `xmlrpc_timeout_ms` 10 s → 2 s. The per-RPC timeout must fire before the 5 s
  the caller waits, or a slow server makes the caller EXIT.

### Packaging

- version 1.4.0 across the RPM spec, the deb changelog and the shipped
  `config.toml`.
- `config.toml` documents `ssl_ca_cert_file` and `allow_insecure_db_connection`.

## Documentation

- new **[CODEC-NEGOTIATION.md](../../CODEC-NEGOTIATION.md)**: how a codec is
  chosen for each leg, with use cases.
  §Media is corrected and points there.
- [registrar.md](../kelixip/modules/registrar.md) absorbs the REST API endpoints
  related to registrar.

## Test suite

- the JSR-309 test double returns an fmtp verdict shaped like the real server's.
  It is what let the PCMU misreading be reproduced with Linphone's own SDP.
- `MediaServer.Mockup.bridge/3` can rebuild the answer at bridge time (opt-in).
  The half of the contract it skipped is where the stale-answer bug lived.
- the callee-side hangup is on the wire in the signalling and media suites.

## Known issues

- **Linphone Desktop 6.2.0/6.3.0 on Windows**: answering from the toast
  notification breaks the call window — no hangup, no BYE, ghost call. Not a
  kelixip bug, reported as
  [linphone-desktop#1011](https://github.com/BelledonneCommunications/linphone-desktop/issues/1011).

## Dependencies

- [mediaserver](https://github.com/neutrino38/mediaserver) **newer than 1.12.3
  is required**

## Security

- CycloneDX SBoM generation is integrated.
- the auth_db TLS-first link and the identity check are security changes as much
  as module ones.
