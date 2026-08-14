# Release 1.4.0

2026-08-14 — 49 commits since 1.3.0 (2026-08-10). Theme of the release: **the
media relay proven in traffic**. The B2BUA that 1.3.0 introduced has been
exercised against real Linphone 6.2.0 endpoints in both call directions:
registration, digest authentication on INVITE, media relay under
`transcode: :avoid`, and **real VP8 ↔ H.264 transcoding**, all confirmed in
captures. Getting there surfaced — and fixed — defects at every layer: the
codec selection, the SDP answers, the NAT handling, the RTP watchdog, and six
SIP wire-correctness bugs, each one measured in a capture before it was fixed.

Not exercised in traffic yet: real-time text relay, and a SIP ↔ WebRTC call
through the B2BUA.

## Framework changes

### Codec negotiation across the two legs

See [CODEC-NEGOTIATION.md](../../CODEC-NEGOTIATION.md), new with this release —
the principles, the use cases as SDP in / SDP out, and the payload-type
arithmetic in annex.

- **cross-leg selection** (`mediagw_b2bua_jsr309.md` §5, prescribed there and
  unimplemented until now): each leg records `peer_codecs` — every codec the
  peer can carry, in the peer's own `m=` order — and the codec is picked **once
  for both legs**: under `:avoid`, the first codec of the caller's list the
  callee also carries. Transcoding stops being a decision of its own: it is
  what two different selections mean.
- **wideband speex** (`speex/16000`, the one variant the media server factory
  carries) enters the Mendooze codec vocabulary and the default outbound audio
  menu (`OPUS, PCMU, PCMA, SPEEX`). The table's clock rate is now part of the
  codec's identity: RFC 5574 registers the single name "speex" at three rates,
  so `speex/8000` — which the server cannot decode — no longer matches. A
  speex-only callee used to decline the audio outright while the server could
  have transcoded it all along. Validated in traffic on 2026-08-14, both
  directions, once the media server was fixed to open its speex decoder and to
  return a wideband frame whole.
- **the wiring is the policy's, not the selection's**: `:forbid` is the only
  policy wiring a direct `Endpoint ↔ Endpoint` attach; `:avoid` and `:force`
  both wire `Endpoint ↔ Transcoder ↔ Endpoint`. The JSR-309 transcoder decides
  **per incoming packet** and relays untouched while both legs carry the same
  codec, so the steady state of an `:avoid` call whose legs agree is still a
  relay — and a peer switching codec mid-stream is followed instead of broken.
- **the answer is shaped by what the other leg carries**: a relayed media may
  announce only the intersection of the two legs' lists; a transcoded one keeps
  everything the caller offered, with the codecs both legs carry floated to the
  front under `:avoid`. Nothing is ever *added*: an answer only carries payload
  types the offer declared (RFC 3264 §6.1).
- **the peer's format order decides which codec a leg settled on**, not the
  payload-type number. An answer of `m=audio … RTP/AVP 98 0 8 101` with opus at
  98 used to read as PCMU (a static PT always beat a dynamic one), which
  silently inverted `:avoid`: two opus legs were declared to disagree and a
  PCMU transcoder bridged opus to itself.
- **the video send map carries every codec the leg can receive, one payload
  type per codec** — not the caller's primary alone. The selection is taken at
  bridge time from the intersection, and pinning the map at answer time let the
  server stamp a stream with the wrong payload type: an AV1-offering caller
  meeting an H.264-only callee received H.264 labelled AV1 and decoded noise.
- **the answer rebuilt at bridge time is now actually sent**: `bridge/3`
  returns the caller's answer narrowed and reordered once both legs are known,
  and `complete_media` used to compute it, store it — and send the stale one
  captured at INVITE time.
- **AV1 joins the default outgoing video offer** (`AV1, H264, VP8`). The
  inbound leg always had it — there we answer, and the offer is the menu — but
  the outbound leg offered from a static list that ignored it, so an
  AV1-to-AV1 call died on a 488 with perfectly good audio.
- **a media the callee declined no longer kills the call**:
  `{:not_negotiated, media}` is fatal for audio only ("a call with no audio is
  not a call"); any other media is declined with port 0 in the rebuilt answer
  and the call goes on.

### In the tree since the tag, not yet validated in traffic

One change present in this release's tree, from the audio-transcoding test of
2026-08-14 (VP8 both sides, disjoint audio codecs):

- **a declined media is propagated across the B2BUA instead of half-served**: a
  port-0 section in an answer (RFC 3264 §6) or a re-offer (§5.1) is recorded as
  the peer's verdict — nothing is started towards port 0, no bridge is built on
  that media, and the *other* leg's rebuilt answer declines it too. It used to
  be processed as live: `EndpointStartSending` aimed at port 0, an audio
  transcoder bridging into the void, and the caller granted `sendrecv` audio it
  could never hear.

### NAT, media timing, and giving up

- **NAT latching on both legs**, not only where we answer an offer. A NATed
  callee writes its private address in an *answer* exactly as an offerer writes
  it in an offer; the capture of 2026-08-12 shows a callee answering
  `c=IN IP4 172.22.x.x` while its RTP arrived from elsewhere — every outgoing
  packet went to an unroutable address and the callee heard nothing for the
  whole call. Asking the server to latch is safe: `RTPSession::NatCorrectable`
  is narrow and one-shot; ICE stays the one exclusion.
- **the RTP inactivity watchdog is armed when the call is answered**, not when
  the SDP is negotiated. It used to arm during ringing — silent by definition —
  and killed a working call ten seconds into a 17-second ring. New
  `MediaServer.Behaviour.call_answered/1`, driven by `reply_invite_with_sdp(200)`,
  by the 2xx to our own INVITE (never a 183), and by `B2bua.complete_media`.
  Confirmed in traffic: watchdogs armed ~200 ms after the 200 OK, none during
  ringing, and the outbound video left unarmed until the re-INVITE that turned
  the camera on.
- **a media server that stops answering is given up on in 2 seconds**, not 10.
  A JSR-309 control RPC on the same host answers in 2–15 ms; ten seconds of
  patience meant a wedged server blocked the scenario inside the RPC while the
  caller retransmitted its BYE into the void. Per-RPC timeout 10 s → 2 s,
  enclosing GenServer timeout 30 s → 10 s.
- **no media server means the call is refused with a 503 — never served by the
  test stub.** A pooled MCU that went away used to make the router fall back to
  the global `:mediaserver` config, whose default is `module: :mockup`: real
  traffic signalled perfectly through a stub and nobody saw or heard anything.
  `Kelix.Router.media_override/1` now distinguishes three outcomes — an MCU, no
  pool at all (config applies: the pool-less deployment and elixipp), and **a
  pool with nothing serviceable**, which resolves to the `:unavailable` verdict
  that `use_mediaserver` refuses to turn into an adapter. The refusal is loud.

### SIP correctness on the wire

Six defects, each measured in the captures of 2026-08-14, all confirmed fixed
in traffic the same day, both call directions:

- **URI parameters are serialized inside angle brackets**: `SIP.Uri.serialize/1`
  emitted them unbracketed, which RFC 3261 §20 reads as *header* parameters —
  the 200's Contact said `transport=tcp` and the caller still aimed its ACK and
  BYE at UDP. Brackets appear for any §19.1.1 uri-parameter and only those; a
  bare To carrying only a tag keeps its bare form.
- **the Contact the B2BUA stamps carries the transport that will carry the
  message, in lower case**. A Contact built with no caller-supplied one — every
  INVITE a B2BUA forwards — had no `transport` parameter at all, and
  `sip:host:5070` reads as UDP to every UA (RFC 3263 §4.1): a TCP leg told its
  peer to send the BYE to a UDP port. And `transport=TCP` upper-case, legal per
  §19.1.4, went unrecognized in the field. Both fixed in
  `build_contact_uri/2` / `add_contact_header/3`, the one place every response
  and forwarded request goes through.
- **the Contact identity crosses the B2BUA**: a relayed message lost its
  Contact userpart and display name. The identity half now crosses in both
  directions; host, port and transport remain the leg's own.
- **Route is no longer echoed into responses** (RFC 3261 Table 3 gives it no
  place in any response; Record-Route still crosses into the 2xx).
- **a dialog hangs up once**: a relayed BYE was followed 48 ms later by the
  teardown's own, which the callee could only 481. A second BYE is refused
  while one is in flight (`:already_closing`).
- **the ACK of a 2xx gets a fresh Via branch** (§17.1.1.3 makes it a
  transaction of its own); the ACK of a non-2xx keeps the INVITE's, as before.

### Keep-alives and STUN on the SIP port

- **CRLF keep-alives** (RFC 5626 §4.4.1, what Linphone sends) are recognized
  and consumed on both stream and datagram transports instead of taking the
  parse-error path.
- new **`SIP.Stun`**: STUN demultiplexed from SIP by the RFC 7983 rule (two
  zero bits + magic cookie), decoded and logged instead of blamed on the SIP
  parser. RFC 5626 §4.4.2 makes STUN the keep-alive of an outbound UDP flow, so
  a SIP port *does* receive these. We do not answer with a Binding Response
  yet; `decode/1` already returns what a responder needs.

### The registrar session

Field-validated against a Linphone re-enabling its account (2026-08-11), which
left two registrar sessions for one binding, one of them immortal. Three causes,
fixed where each belongs:

- `SIP.DialogImpl` arms the expiration timer **from the request that creates
  the dialog** — a REGISTER accepted on the first request (cached nonce, no 401
  round) used to produce a dialog with no timer at all.
- new **`SIP.Dialog.terminate/2`**: end a dialog from outside, stating why; the
  application gets the promised `{:dialog_terminated, _, reason}`.
- `Kelix.Mod.Registrar`: re-registering a contact another dialog owns hands the
  binding over and **supersedes** that dialog (`:superseded`), demonitored
  first so the death we cause does not come back as a spurious `:disconnected`.

The registrar session verbs gained context-first forms —
`challenge_registration(sip_ctx, req, params)`,
`accept_registration(sip_ctx, req, granted)` — so a script passes its context
and reads the verdict from `lasterr`, like every other DSL verb. The
positional forms stay for callers with no context.

### Authenticating calls, not only registrations

The framework half of the auth work (module half below):

- **`SIP.Msg.Ops.challenge_header/1`** is the one home of the 401 →
  `WWW-Authenticate` / 407 → `Proxy-Authenticate` mapping, which had two copies.
- new `SIP.Msg.Ops.from_username/1`, `to_username/1`, `in_dialog?/1` — the raw
  claims, deliberately not the digest-verified name (comparing that with itself
  can never fail).

## Framework corrections

- **ex_sdp 1.2**: two upstream fixes we had been compensating for locally — the
  `a=fingerprint` hash token compared case-insensitively (RFC 8122 §5), and the
  `m=` fmt list parsed as payload types for every RTP profile. The two local
  workarounds are gone; `fmtp_raw` stays (the opaque-passthrough request is not
  upstream yet).
- **the built-in scenarios are restored**: `apps/elixip2/lib/scenarios/` had
  been deleted as "redundant" with the top-level `scenarios/`, taking
  `elixipp UAC.Invite`, `elixipp UAC.Register` and `mix scenario` with it. They
  live again under `lib/built-in-scenarios/`, with the reason the two
  directories are not duplicates written into the tree.
- **the hangup that comes from the callee is covered**: every B2BUA test hung
  up from the caller's side; the callee direction (a BYE arriving on the
  outbound leg, owed on the inbound one) had no test in either suite. Both now
  cross the wire, and the relay logs name the leg
  (`relayed BYE from the outbound leg to the inbound`) — the transaction log's
  `Sent BYE <ruri>` cannot say which leg a request left on.
- diagnosed, not a defect: the PT 0 packets heading every RTP stream in the
  captures are 54-byte bare RTP headers — the media server's NAT priming, not
  media. No audio ever left as PCMU.

## Domain Specific Language changes

- new **`b2bua_challenge/2..3`**: the application builds the challenge (nonce,
  qop, algorithm — things the dialog layer's `challenge_invite` cannot know)
  and the verb sends it on the leg the matched event came from, in the header
  the code calls for. 407 is the default: a UA expects the server routing its
  calls to challenge as a proxy, and many will not retry a 401 on an INVITE.
- new **`b2bua_media_unavailable?/0`** — how a script tells "no media server"
  from a codec problem, and answers 503 rather than 488.
- `use_mediaserver` now sets `:lasterr` to `:ok` on success, so the verdict of
  `media_connect()` is readable at all; failure was already reported there.

## elixipp testing tool changes

No functional change (version bump, SBoM licensing metadata). The built-in
scenarios run by module name (`elixipp UAC.Invite`) work again — see Framework
corrections.

## kelixip

- **`User-Agent: Kelixip/1.4.0`**.
- new reference scripts, the pair the traffic validation ran on:
  [`direct-call-with-auth.exs`](../../apps/kelixip/scripts/direct-call-with-auth.exs)
  — `direct-call.exs` plus three states in front of the call: the module
  answers a verdict (`authenticate/3`), the script composes the SIP it means.
  A refused INVITE does not end the instance (the dialog outlives it and the
  next INVITE of that Call-ID must find someone alive);
  [`direct-call-with-auth-and-media.exs`](../../apps/kelixip/scripts/direct-call-with-auth-and-media.exs)
  — the same call with the media relay in the middle, `transcode: :avoid` on
  audio and video, and the 503 branch when no media server is serviceable.
- `registrar.exs` gains a `wait_auth_register` state: a challenged registration
  waits for the authenticated REGISTER in a state of its own.
- `play.exs` and `record.exs` gain `ringing` and `no_media_server` states — the
  180 commits us to a call, so it comes *after* the media server is known to
  exist. `record.exs` joins the repository (it existed only as a hand-copied
  file on the target, so every fix to it died at the next package build).
- `Kelix.Auth.challenge_www_authenticate/2` is renamed **`challenge_params/2`**:
  the params are identical for 401 and 407 and only the code decides the
  header, so a header name in the builder made call scripts read wrong. No
  alias left behind.

### kelictl

- new **`kelictl auth_db show`** (`GET /modules/auth_db/db`): the subscriber-DB
  link as it actually is — a live `SELECT 1` for the state, where it points,
  TLS or clear *with the reason*. Never the password. `down` is an answer, not
  an error: the command stays usable exactly when the base is unreachable.

### REST API changes

No change. The `mcu` codec keys (`audio_codecs`, `video_codecs`, `text_codecs`,
`video_fmtp`) announced in 1.2.1 as becoming an error are **still accepted and
ignored with a warning** — the change is deferred, not made.

### auth_db

- **it authenticates any request, not only REGISTER**: new `authenticate/3` —
  same verdict, any method, plus the identity the digest proved
  (`{:ok, %{user, realm}}`). `do_registration_auth/3` is that function applied
  to a registration, unchanged for its callers.
- new `challengeable?/1` — an initial request other than ACK, CANCEL and
  OPTIONS. ACK has no response to carry a challenge, CANCEL must be accepted
  for the transaction it cancels, OPTIONS is what liveness probing uses.
- new **identity check**: a valid digest proves who holds the password, not
  that the `From` is theirs — without the check, one subscriber calls as
  another. `[module.auth_db] identity_check` = `strict` / `warn` / `off`,
  shipped as `warn` so a trunk asserting many From identities does not turn
  into 403s on upgrade.
- a refused request logs one line naming the cause (`bad_password`,
  `unknown_user`, `bad_realm`) where nothing was logged before; the wire answer
  stays a bare 403, so nothing leaks whether the account exists.
- **the DB link tries TLS first**, whatever the config block says, and
  cleartext happens only behind `allow_insecure_db_connection = true` — the one
  gate, so "unencrypted" always means somebody confirmed it. The transport is
  decided once, at start, by probing (a throwaway connection + `SELECT 1`;
  DBConnection's pool proves nothing) — a base answering on *neither* transport
  is unreachable, not TLS-less. Connection concerns move to
  `Kelix.Mod.AuthDb.Pool`, which also fixes the MyXQL `ssl:`/`ssl_opts:`
  spelling. Verified against the real base on the dev host: TLS with no config
  change.
- new `fetch_credential/3`: the secret as `{:ha1, algorithm, hex}` — the
  backend's abstraction point
  ([evolution-auth-db.md](../design/evolution-auth-db.md)); everything above it
  is storage-agnostic.

### registrar

- **`save/2` takes the scenario context**: `save(sip_ctx, req)` reads domain
  and dialog from the context; the positional
  `save(req, domain, dialog_pid, info)` stays.
- the binding hand-over on re-registration (see *The registrar session* above)
  is the module half of the one-session-per-binding fix.

### mcu

- `call_answered/1` is a documented no-op: a conference leg arms its watchdog
  at `attach/1`, its own ACK-time step, already after the ringing.
- `xmlrpc_timeout_ms` 10 s → 2 s, restoring an invariant the pair had lost: the
  per-RPC timeout must fire before the 5 s the caller waits, or a slow server
  makes the caller EXIT where an error was owed.

### Packaging

- version 1.4.0 across the RPM spec, the deb changelog, and the shipped
  `config.toml` (whose `user_agent` example now reads `Kelixip/1.4.0`).
- `config.toml` documents the new auth_db keys: `ssl_ca_cert_file` (without it
  the DB link is encrypted but unauthenticated) and
  `allow_insecure_db_connection`.

## Documentation

- new **[CODEC-NEGOTIATION.md](../../CODEC-NEGOTIATION.md)** — how a codec is
  chosen for each leg, stated once for a reader who has not read the code:
  principles, use cases as SDP in / SDP out / what happens to the packets, and
  annexes (payload-type arithmetic, per-codec `fmtp`, total conversation with
  ITU-T F.703 / T.140 / RFC 4103 / RFC 9071, a code map, an RFC index).
  B2BUA.md's §Media, whose policy paragraph was wrong in three clauses, is
  corrected and points there.
- the rule behind the AV1 defect is written down in CLAUDE.md: **the media
  server is the source of truth about itself** — no codec table, capability
  list or port range copied on this side of the wire when the server can be
  asked; a capability that exists in code but no API can query is a server API
  hole to close, not a licence to hardcode.
- two design discussions: [integration-fail2ban.md](../design/integration-fail2ban.md)
  (what fail2ban needs, why a 401 is not a failure, the reverse-proxy trap) and
  [evolution-auth-db.md](../design/evolution-auth-db.md) (authenticating more
  than REGISTER, the two-tier Auth behaviour, checked against Diameter Cx).
- new [service-building-block.md](../design/service-building-block.md) — the
  SBB specification; README gains a "Background reading" section and a
  reworked roadmap.
- [registrar.md](../kelixip/modules/registrar.md) absorbs the registrar
  command documentation from the REST/administration pages.

## Test suite

- the JSR-309 test double now returns an fmtp verdict shaped like the real
  server's, so the bridge tests exercise the delegated-negotiation branch a
  real server takes — it is what let the PCMU misreading be reproduced with
  Linphone's own offer and answer verbatim.
- `MediaServer.Mockup.bridge/3` can rebuild the answer at bridge time
  (opt-in `rebuild_answer_on_bridge/2`): the mock modelled half the contract,
  and the half it skipped is where the stale-answer bug lived.
- the callee-side hangup is on the wire in both the signalling and the media
  suites.

## Known issues

- **Linphone Desktop 6.2.0/6.3.0 on Windows**: answering from the toast
  notification breaks the call window — no hangup, no BYE, ghost call. Not a
  kelixip bug; reported upstream as
  [linphone-desktop#1011](https://github.com/BelledonneCommunications/linphone-desktop/issues/1011).

## Dependencies

- [mediaserver](https://github.com/neutrino38/mediaserver) **newer than 1.13.0
  is required** (≥ `8ecf523`): video bridge/transcode switching, AV1, RTP
  inactivity watchdog driven from the answer, payload-type renumbering.
- **ex_sdp 1.2.0** (was 1.1.x with two local workarounds, now dropped).

## Security

- CycloneDX SBoM generation is integrated (`mix sbom.cyclonedx` from the
  umbrella root: the four apps, their transitive Hex deps and the OTP/Elixir
  runtime, 51 versioned components). Releases ship with their SBOM to comply
  with the EU Cyber Resilience Act (BSI TR-03183-2). Each app declares its
  SPDX license (`BUSL-1.1`); generation is manual at release time, documented
  in BUILD.md.
- the auth_db TLS-first link and the identity check above are security
  changes as much as module ones.
