# Release 1.3.0

2026-08-10 — 81 commits since 1.2.1 (2026-08-08). Theme of the release: **the
B2BUA**. A scenario can now handle an incoming call and place a second one of
its own, then bridge the two for as long as they live — with a media
server in the middle or not.

Unlike a proxy the server stays a user agent on both sides: it owns two dialogs,
it can hang either of them up, it stays in the signalling path for the whole call,
and it can meter.


## Framework changes

### The B2BUA feature

- new **`SIP.Session.B2bua`**, pulled in by `use SIP.Scenario` — one FSM drives
  **two** dialogs. The inbound leg stays the scenario's own dialog and everything
  already known keeps its meaning; the outbound leg's events arrive **tagged**
  (`{:outbound, {200, resp, trans, dlg}}`), and can be processed by the same scenario.

The module provides functions and macro to create an outbound leg (INVITE for the moment)
and relay requests and responses back and forth between call legs.

Processing request locally and answering them is also possible.

See B2BUA.md documentation.

### Where the second call goes

- new **`%SIP.B2bua.Peer{}`** struct that enables a rich forward policy settings and
  can contains a list of destination URIs

- calls policies includes
  - serial hunting
  - parallel SIP forking
  - dynamic targets
  - SRV resolution with fail-over
  - outbound proxy settings


### Media between the two legs

By default, B2BUA do not process any media. The reference scenario 
`direct-call-with-auth.exs` has been extensively tested and debugged using
Linphone.


But media relay using a Mediaserver is also supported. This enables NAT traversal but also
if requested, audio and/or video transcoding.

B2UBA module with media also supports media change (re-INVITE / UPDATE) with three
main uses cases:

- media addition or removal for total conversation: this one is handled and scenario
  propagate it between legs
- on hold / off hold
- IP address change.

A reference scenario direct-call.exs provides a good example.



### RTP profile negociation

The B2BUA provide a mecanism to negociate beween WebRTC bitstream and regular SIP
bitstream. An option enable the outbound leg to retry INVITEs and downgrade the RTP
profile as follows: `webrtc → avpf → avp`. A 488 Response code is interpreted a request
to downgrade.

### Dialog, transaction and message layers

a **client-transaction timeout is reported to the application as a synthetic 408**
  (RFC 3261 §17.1.1.2 / §8.1.3.1).

Three readings added to `SIP.Msg.Ops`: `from_username/1` / `to_username/1` (the raw
claims, where `asserted_username/1` prefers the verified digest name) and
`in_dialog?/1` (does the request carry a To tag).

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

- **DNS SRV resolution corrected.** + `srv_targets/1` that returns a peer populated with a list of URI.
- **a client transaction in `:cancelling` dropped every final response.** So a
  cancelled INVITE was never ACKed (§17.1.1.2). This was corrected.
- every branch after the first ignored the peer's `ruri: :keep` (a trunk's second
  branch was rewritten to the gateway's URI) and its `outbound_proxy`
- `address_in_dialog/2` restores **both** identities on an outbound dialog
- **mendooze: media arriving before the answer no longer loses `:ice_connected`.**
- the registrar scenarios still watched for `:tcp_closed` / `:tls_closed` /
  `:wss_closed`, replaced by one `:transport_down`: the guard matched nothing, so a
  dropped connection was recorded as a registration ending normally
- **a refused REGISTER no longer ends the registrar instance.** The dialog outlives
  the scenario and kept casting the next REGISTER to a dead process — no answer at
  all for the client until the dialog expired, up to an hour

## Domain Specific Language changes

- new **Connecting calls (B2BUA)** section in [DSL](../../FSL.md); the `b2bua_*`
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
  [`b2bua.exs`](https://github.com/neutrino38/elixip/blob/1.3.0/apps/kelixip/scripts/b2bua.exs)
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
  abstraction point ([docs/design/evolution-auth-db.md](../design/evolution-auth-db.md))

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

- new **[B2BUA](../../B2BUA.md)** — the scenario writer's side: the complete macro
  reference, the `%Peer{}` target form, the media modes, the offer-profile ladder,
  and the three use cases commented end to end
- the **mcu module document** was rewritten and reviewed
- [registrar](../kelixip/modules/registrar.md) documents `targets/2`
- design documents: `b2bua_module.md` (the *why*, with the phasing table now closed
  through P5), `b2bua_media_impl_plan.md`, `b2bua_offer_profiles_plan.md`,
  `mediagw_b2bua_jsr309.md`

## Test suite

Test suite was reviewed and several errors and flaky tests were corrected. Lots of
refactor to put common code in helper modules.

## Dependencies

- [mediaserver 1.12.2](https://github.com/neutrino38/mediaserver/releases/tag/1.12.2)
  — unchanged since 1.2.1.

## Security

CycloneDX tooling has been integrated and from now on, the release will be shipped
with its SBOM file to comply with the EU Cyber Resiliancy Act (CRA)
