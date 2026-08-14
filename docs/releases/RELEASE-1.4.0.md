# Release 1.4.0

B2BUA has been heavily tested against Linphone 6.2.0 UA

## Framework changes

### The B2BUA feature

- New references scenarios direct-call-with-auth.exs and direct-call-with-auth-and-media.exs
- B2BUA call between two registered UAs is now fully operational with an without media relay
- Media relay in bridge mode has been tested
- Audio and video transcoding as well.

Not tested:
- text
- SIP to WebRTC bitstream


See B2BUA.md documentation.

### Codec negotiation and transcoding

See [CODEC-NEGOTIATION.md](../../CODEC-NEGOTIATION.md) for the full rules.

- **cross-leg selection**: the codec is picked once for both legs — the first
  codec of the caller's list the callee also answers. Transcoding is not a
  decision, it is what two different selections mean.
- **per-leg codec, real transcoding**: under `transcode: :avoid` the transcoder
  bridges packet-per-packet while both legs agree and converts when they do not.
  **Validated in traffic: a VP8-only caller talking to an H.264-only callee.**
- the answer to the caller is rebuilt at bridge time and bounded to the
  intersection on a relayed media.
- **AV1** is carried in outgoing offers; H.264 `packetization-mode` absence is
  read as "no constraint" (deliberate deviation from RFC 6184).
- **NAT latching in both directions** — the outbound leg used to get one-way
  media on every NATed call.
- the media watchdog is armed **at answer**, and a media server that stops
  answering is given up on in two seconds; with **no media server at all the
  call is refused (503)** instead of being served by the test mockup.

### RTP profile negociation

This has not been tested

### Dialog, transaction and message layers

### SIP correctness on the wire

Five defects, each one measured in a capture, all confirmed fixed in traffic:

- URI parameters are serialized **inside angle brackets** (an unbracketed
  `;transport=tcp` is a header parameter per RFC 3261 §20 — the caller aimed
  its ACK and BYE at UDP); the bare form stays for a To/From carrying only a tag.
- the **Contact identity** (userpart, display name) crosses the B2BUA in both
  directions; host, port and transport remain the leg's own.
- **Route is no longer echoed into responses** (RFC 3261 gives it no place there).
- a dialog **hangs up once**: a second BYE — relayed plus teardown — is refused
  when one is already in flight.
- the ACK of a 2xx gets a **fresh Via branch** (§17.1.1.3: it is its own
  transaction); the ACK of a non-2xx keeps the INVITE's.

The `User-Agent` of the kelixip server is now **`Kelixip/1.4.0`**.

### The registrar session layer

- the `SIP.Session.Registrar` verbs have been imrpoved totake the **scenario context** 
as their first argument and be more friendly to scripts.it can act on

### Resilience

- the dialog traps exits and converts a transaction crash into a synthetic 408; the
  scenario engine catches exits so teardown always runs
- connectionless transport re-selection: a dead socket is a send failure, and UDP
  recovers from it
- a transport going down during a hunt is a **branch** failure, not the death of the
  dialog
- a leg that dies answers what it owed — its pending requests get a final response —
  before the scenario decides what to do
- `media_cleanup_ressources()` is what a scenario releases with on the way out: it
  skips dead handles and releases both legs, where `media_stop()` does not

## Framework corrections

- `address_in_dialog/2` restores **both** identities on an outbound dialog
- **mendooze: media arriving before the answer no longer loses `:ice_connected`.**
- the registrar scenarios still watched for `:tcp_closed` / `:tls_closed` /
  `:wss_closed`, replaced by one `:transport_down`: the guard matched nothing, so a
  dropped connection was recorded as a registration ending normally
- **a refused REGISTER no longer ends the registrar instance.** The dialog outlives
  the scenario and kept casting the next REGISTER to a dead process — no answer at
  all for the client until the dialog expired, up to an hour

## Domain Specific Language changes

- new **Connecting calls (B2BUA)** section in [DSL.md](../../DSL.md); the `b2bua_*`
  macros need no opt-in beyond `use SIP.Scenario`
- the `@media` attribute takes the `{:mediaserver, inbound:, outbound:, transcode:}`
  form described above
- like the other DSL verbs, the B2BUA macros rebind the scenario context in place:
  they return nothing and their verdict is read from `sip_ctx.lasterr`
- **`last_uas_req()` now covers REGISTER**

## elixipp testing tool changes

No functional change. Four reference scenarios ship with it:

- `b2bua_basic.exs` and `b2bua_media.exs` — the same call, the same states; the
  difference between the two files is what a media server costs. Worth reading as a
  pair
- `customer-service.exs` — a short number answered by hunting a list of numbers
  serially
- `webrtc-gw.exs` — a WebRTC call re-sent to a SIP phone through a media server,
  walking the offer-profile ladder to find what the phone speaks

## kelixip

- two reference scripts for the B2BUA:
  [`direct-call.exs`](../../apps/kelixip/scripts/direct-call.exs) (kamailio's
  `lookup("location"); t_relay()` done as a B2BUA — and the difference is that we
  stay in the signalling path for the whole call) and
  [`b2bua.exs`](../../apps/kelixip/scripts/b2bua.exs)
- `mcu.exs` / `mcu_adhoc.exs` also tear the call down on `:server_disconnected`
  reported by their **own** media connection, not only on the module's relay of it:
  `media_connect/0` makes the script the event sink, so both routes reach it and
  neither is guaranteed to be first

### kelictl

No change.

### REST API changes

No change. The `mcu` codec keys (`audio_codecs`, `video_codecs`, `text_codecs`,
`video_fmtp`) announced in 1.2.1 as becoming an error are **still accepted and
ignored with a warning** — the change is deferred, not made.

### Packaging

- `mcu.exs` and `mcu_adhoc.exs` now ship with **`kelixip-mod-mcu`** instead of the
  core. 

### auth_db

- **it authenticates any request, not only REGISTER**: new `authenticate/3`, same
  verdict plus the identity the digest proved. `do_registration_auth/3` is that
  function applied to a registration, unchanged for callers
- new `challengeable?/1` — an initial request other than ACK, CANCEL and OPTIONS
- new **identity check**: a valid digest proves who holds the password, not that the
  `From` is theirs. `[module.auth_db] identity_check` = `strict` / `warn` / `off`,
  shipped as `warn` (allow and log) so no legitimate deployment turns into a 403 on
  upgrade
- a refused request logs the cause (`bad_password`, `unknown_user`, `bad_realm`);
  the wire answer stays a bare `403`
- new `fetch_credential/3`: the secret as `{:ha1, algorithm, hex}` — the backend's
  abstraction point ([evolution-auth-db.md](../design/evolution-auth-db.md))

### registrar

- **`save/2` takes the scenario context**: `save(sip_ctx, req)` 
  `save(req, domain, dialog_pid, info)` form stays for callers with no context
- the facade reports to the monitor (`:db` command `registrar_save`),.
- new **`targets/2`**: where to call the AOR a request asks for, returned as a
  `%SIP.B2bua.Peer{}` 
-
- one atom per failure, each mapping to one SIP answer: `:notfound` (480),
  `:no_aor` (400), `:unavailable` (500)

### mcu

- `bridge/3` and `unbridge/2` answer `{:error, :not_supported}` / `:ok`. A

## Documentation

- new **[B2BUA.md](../../B2BUA.md)** — the scenario writer's side: the complete macro
  reference, the `%Peer{}` target form, the media modes, the offer-profile ladder,
  and the three use cases commented end to end
- the **mcu module document** was rewritten and reviewed
- [registrar.md](../kelixip/modules/registrar.md) documents `targets/2`
- design documents: `b2bua_module.md` (the *why*, with the phasing table now closed
  through P5), `b2bua_media_impl_plan.md`, `b2bua_offer_profiles_plan.md`,
  `mediagw_b2bua_jsr309.md`

## Test suite

Test suite was reviewed and several errors and flaky tests were corrected. Lots of
refactor to put common code in helper modules.

## Known issues

- **Linphone Desktop 6.2.0/6.3.0 on Windows**: answering from the toast
  notification breaks the call window — no hangup, no BYE, ghost call. Not a
  kelixip bug; reported upstream as
  [linphone-desktop#1011](https://github.com/BelledonneCommunications/linphone-desktop/issues/1011).

## Dependencies

- [mediaserver](https://github.com/neutrino38/mediaserver) **newer than 1.13.0
  is required** (≥ `8ecf523`): video bridge/transcode switching, AV1, RTP
  inactivity watchdog driven from the answer, payload-type renumbering.

## Security

CycloneDX tooling has been integrated and from now on, the release will be shipped
with its SBOM file to comply with the EU Cyber Resiliancy Act (CRA)
