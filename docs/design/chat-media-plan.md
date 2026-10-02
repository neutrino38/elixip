# chat-media-plan.md — building chat attachments

The build order of [DESIGN-CHAT-MEDIA.md](DESIGN-CHAT-MEDIA.md): photos and
voice messages in chat, the way Linphone does them. Three parts, built by
different people against one contract:

- **Part S — the server side, now**: the reference PHP file server on
  `web1`, which is the store for as long as it suffices; what kelixip must
  prove and provision;
- **Part T — the client side**: Trix (`../trix-web-client`), the web client
  written against this server;
- **Part E — the Elixir store, later**: the service of design §6, built when
  the PHP server stops being enough. Its phases are kept here so the design
  is not re-derived, and the trigger to start them is stated.

The contract between the parts is **§5 and §9 of the design**, plus the
captures Part S produces in S0. Part T needs nothing else from Part S until
its end-to-end check.

**Status (2026-10-02): planned, nothing started.** Trix's code was not read
for this plan; what it says of Trix comes from chat-basic-plan §6, checked
on 2026-09-29. The first task of Part T is to re-check it.

## 1. Scope

| In | Why it is the floor |
|---|---|
| the reference PHP server on `web1`, run for real: digest with the SIP credentials, retention, static downloads behind Apache | the store Linphone already speaks to; nothing to write to get a first exchange |
| provisioning of Linphone accounts: the store URL and CPIM | the two keys without which, respectively, nothing is sent and no receipt is ever matched (design D7) |
| proof that the relay and the Silo carry the bodies verbatim | read in the code, never captured (design §12) |
| Trix: receive and show a photo, play a voice message, send both, IMDN | the second client, and the one that shows the Linphone-side loss of a caption |
| the Elixir store, as the last part | what replaces the PHP server when quotas, control, metrics or the logging rule are needed |

| Out | Where it re-enters |
|---|---|
| the Bearer token minted by kelixip for web clients | design §8.3 — Trix does the digest until then; a one-route addition to the control API, planned when Trix's digest is measured too costly |
| thumbnails (`file-info type="thumbnail"`) | Linphone ignores them on receive and never sends them |
| object storage, a redundant store | design D6 — the schema is small enough to move when a second host exists |
| a content scanner | design §11 — a hook at the rename step of the Elixir store |
| group chats, LIME | the Flexisip conference server; not this design |

## 2. The starting point

| Piece | State |
|---|---|
| the reference PHP server | public on GitHub, not installed anywhere here; its purge mechanism and its logging were not seen (design §12) |
| `web1` | Apache running, certificate in place; nothing under `/files/` |
| kelixip relay (`SBB.Page`) and Silo | carry `Content-Type` and body verbatim, multipart with its boundary (`SIPMsgTemplate.ex:97-102`); never exercised on an `rcs-ft-http` or `message/cpim` body |
| `SIP.Msg.Ops.message_kind/1` | files `application/vnd.gsma.rcs-ft-http+xml` under `:im`, so it is stored and relayed like text |
| `apps/elixip2` | has `Req` as a dependency: an elixipp scenario can upload |
| Linphone desktop on a kelixip domain | basic chat room, no store URL, no CPIM: sends nothing, matches no receipt |
| Trix (as of 2026-09-29) | `text/plain` only, 415 with `Accept: text/plain` to anything else, 1000-byte cap, no IMDN, JsSIP with one MESSAGE per Call-ID |
| the Elixir store | does not exist; name proposed `kelifile`, repository of its own (design §6.1) |

## 3. Part S — the server side, now

### S0 — the PHP server on `web1`, for real

**Delivers** the store, installed rather than written: the reference
`flexisip-http-file-transfer-server` under `/files/` on `web1`'s Apache,
configured for production use, not as a demo:

- `DIGEST_AUTH = true`, `AUTH_NONCE_KEY` random, `AUTH_REALM` **undefined** so
  the realm is the SIP domain of the HTTP `From` (a fixed realm breaks the
  day a second domain exists), `AUTH_QUERY` pointed at the subscriber base
  under a **read-only** account, returning the HA1 and its algorithm as the
  base holds them;
- `fhft_tmp_path` on a volume sized for `fhft_maximum_file_size_in_MB` times
  the expected traffic over `fhft_validity_period`; the period **at least the
  Silo's `max_retention`** (design D8);
- the purge: since the repository does not show one, a cron job removing
  files under `tmp/` older than `fhft_validity_period`, written here and
  kept with the Apache config;
- the Apache side of design §7: `Options -Indexes`, `nosniff`,
  `Content-Disposition: attachment` on `tmp/`, the CORS headers for Trix's
  origin, `LimitRequestBody` equal to the PHP limit; `OPTIONS` not
  challenged;
- the logging rule of design §6.6 checked against what the PHP logs at
  `fhft_logLevel`: if it writes file names or URLs, the level is set so it
  does not, and this is noted in the Apache config's comments.

Two Linphone desktops provisioned with `file_transfer_server_url` and
`cpim_in_basic_chat_rooms_enabled=1` exchange one photo and one voice
message, both directions. Captured and kept under `docs/design/captures/`
of this repository: a pcap of the SIP side, Apache's access log and a
loopback capture of the HTTP side. These bytes are what Part E is diffed
against, and the answer to design §12's two first unverified points.

**Also delivers** the provisioning recipe for a Linphone account on a
kelixip domain, in `docs/kelixip/administration.md`: which keys, where they
go on desktop and on mobile, and that the desktop offers no UI for them.

**Files** `web1`'s Apache config and cron, kept in the operations
repository; `docs/kelixip/administration.md` and `docs/design/captures/`
here.

**Done when** the two desktops exchange both messages with receipts; the
realm challenged is the SIP domain; a `GET` on `/files/tmp/` lists nothing;
a file older than the period is gone the next morning; and the captures
are committed.

### S1 — kelixip: the relay, the Silo, elixipp

**Delivers** what this repository owes the design, with no change to SIP
behaviour:

- a test in `apps/kelix_modules` paging an `rcs-ft-http` body and a
  `message/cpim` body through `SBB.Page` to a Mockup device, and through
  `Kelix.Mod.Silo.store/2` then a flush, asserting the relayed body is
  **byte-identical** and the `Content-Type` unchanged, boundary included for
  a `multipart/mixed` of XML and text;
- an elixipp scenario pair, tagged `:live`: a UAC that uploads through `Req`
  (empty POST, digest, `File` part), builds the XML and pages it; a UAS that
  parses the XML, downloads and checks the size — the node's own way to
  test a store without a Linphone, usable against the PHP server today and
  the Elixir store later;
- the provisioning page of S0 in its final form.

**Files** `apps/kelix_modules/test/chat_media_relay_test.exs`,
`apps/elixip2/scenarios/uac_file_message.exs`, `uas_file_message.exs`,
`docs/kelixip/administration.md`.

**Done when** both tests are green against the PHP server, and a Linphone
desktop, offline during the upload and the MESSAGE, gets the photo at its
next REGISTER from the Silo, with the file still downloadable.

### S2 — the token mint (conditional)

**Delivers**, only if Part T measures the digest in the browser as not
acceptable (T3): the one-route token mint of design §8.3 in
`Kelix.ControlAPI`, for an authenticated subscriber. The PHP server does not
verify a Bearer token, so this phase also moves the trigger of Part E
forward: a web client that needs the token needs the Elixir store.

## 4. Part T — the client side (Trix)

Each phase lands in `trix-web-client` with its ADR when a trade-off is
taken, in the numbering Trix already uses. The decisions D1 to D13 quoted
below are Trix's, as recorded in chat-basic-plan §6. Every phase is tested
against the PHP server of S0 and a Linphone desktop.

### T0 — re-read Trix, and decide the store's address

**Delivers** the facts this plan assumes, re-checked in `src/sip/message.ts`
and `src/sip/port.ts`: `text/plain` only (D1), the 1000-byte cap (D2), no
IMDN, the 415 answer. And one decision: **where the store URL lives in
Trix**. Recommended: in `AccountConfig`, so a share link carries it to a
second device — it is not a secret, the credentials are — mirroring
Linphone's provisioning, with a default of empty meaning "attachments off".

**Done when** the ADR is written and the facts above are either confirmed or
this plan is corrected.

### T1 — receive an attachment, show it as a card

**Delivers** reception of design §9.3 steps 1-3 and 5:

- accepted on a MESSAGE: `application/vnd.gsma.rcs-ft-http+xml`,
  `multipart/mixed`, `message/cpim`, `message/external-body`, besides
  `text/plain`; the `Accept` of the 415 extended accordingly (D1 revised);
- unwrap CPIM, then multipart, then each part; the CPIM `From` is **not**
  trusted for the sender — the SIP `From` is, as D4 already says;
- the `fthttp` XML read with only `file-info[@type="file"]`; `file-name`
  percent-decoded; a voice message recognised by the strict
  `audio/wav;voice-recording=yes`; `playing-length` read as **milliseconds**;
  `until` compared to now, a past one shown as "expired";
- a card in the conversation: name, size, type icon, duration for a voice
  message, "download" and "expired" states; the 1000-byte cap (D2) applies
  to text parts only.

**Tests** the XML of design §2.2 with and without `until`, with
`am:playing-length`, with `file-key` (ignored), the `external-body` form,
and a multipart of XML and text.

**Done when** a Linphone desktop's photo and voice message, received live,
show as cards with the right name, size and duration, and a text still shows
as text.

### T2 — download and play

**Delivers** design §9.3 steps 4-6: `fetch` with `credentials: 'omit'`; the
image shown inline from a blob URL; audio **sniffed on its first four bytes**
before a decoder is chosen, played in `<audio>` with the duration from the
XML, not from the blob; a failed or 404 download shown as such, with retry.
The browser matrix for a `.mka` Opus from Linphone (Chromium, Firefox,
Safari) is measured here and written in the ADR: where `<audio>` refuses
the container, the fallback is WebCodecs or a WASM demuxer, decided on the
measurement, not before.

**Done when** the voice message from S0's capture plays in every browser
Trix supports, and a photo over 10 MB downloads without blocking the UI.

### T3 — send a photo

**Delivers** design §9.1:

- the three-request upload with `FormData` and the `File` field, `From` set
  to the account's URI, `mode: 'cors'`, `credentials: 'omit'`;
- the digest in the browser: SHA-256 through WebCrypto, MD5 through a small
  library, chosen by the challenges received; the `nc` incremented on the
  second POST. **Measured**: the cost in bytes shipped and milliseconds; if
  judged too high, S2 is requested and T6 follows;
- the XML built as §2.2, CRLF, percent-escaped name, local type;
- the MESSAGE sent as Trix sends text today (out of dialog, new Call-ID),
  with `Content-Type: application/vnd.gsma.rcs-ft-http+xml`; 200 or 202 is
  acceptance, 400 from the store is "too large", 401 is "check your
  password";
- the picker, a size limit equal to the server's, a progress indicator, and
  **one file per message** — several files are several messages, which is
  also what Linphone can show.

**Done when** a photo sent from Trix shows on a Linphone desktop and on a
second Trix.

### T4 — send a voice message

**Delivers** design §9.2: `MediaRecorder` as `audio/webm; codecs=opus`,
named `vocal_<timestamp>.mka`, duration measured in milliseconds, uploaded
with the type `audio/wav;voice-recording=yes` on the part, the XML with
`am:playing-length`; the `isComposing` with the voice `contenttype` while
recording. **Measured on a Linphone desktop**: if its player refuses the
browser's WebM, the fallback is a WAV PCM 16 kHz mono encoder in the client,
and the ADR records which container goes out.

**Done when** a voice message recorded in Trix plays on a Linphone desktop
with the right duration, and the "recording a voice message" indicator shows
there while Trix records.

### T5 — text with a photo, and IMDN

**Delivers** the two things Linphone does on receive but not on send:

- a caption with a photo as one `multipart/mixed`, XML part first then
  `text/plain; charset=UTF-8`; the UI says, once, that a Linphone sender's
  caption does not arrive (design §2.4) — a fact to display, not to
  work around;
- IMDN of design §9.4: `delivered` on receipt, `displayed` when the
  conversation is open; `message-id` from the CPIM `imdn.Message-ID` when
  present, else the Call-ID of the received MESSAGE; incoming IMDNs matched
  the same way and silently ignored when unknown; sent with
  `Priority: non-urgent`. Trix's "no de-duplication" (D3) is unchanged: an
  IMDN is not a message.

**Done when** a Linphone desktop provisioned with CPIM shows "delivered"
then "read" for a message Trix received and opened, and a Trix message to
Linphone shows the same states in Trix.

### T6 — the Bearer path (conditional)

**Delivers**, only if T3 asked for it and Part E has reached E4: the token
obtained from kelixip after registration, sent as `Authorization: Bearer` on
the first POST, refreshed before its expiry; the digest kept as the fallback
when the store answers 401 anyway.

**Done when** an upload from Trix carries no digest and the store's
`auth_failures_total` does not move.

## 5. Part E — the Elixir store, later

**When to start it.** The PHP server is kept as long as none of these is
needed: a quota per AOR, `kelifilectl`-style control (list, purge),
metrics, the logging rule enforced by code rather than by a log level, a
Bearer token for web clients (S2), or a second domain whose realm handling
the PHP server gets wrong. The first of these that is asked for starts E1.
Until then, Part E is a design with a plan, not a debt.

**What it replaces.** The same URL path on `web1` (`/files/hft`,
`/files/tmp/`), so no client is re-provisioned: Apache's `ProxyPass` turns
from the PHP handler to the loopback service, and the `Alias` points at the
new directory. Files under the PHP server's `tmp/` stay served until they
expire; nothing is migrated.

### E1 — the repository, the release, the empty endpoint

The store as a buildable, packageable, deployable service that does nothing
yet: the repository, `mix new --sup`, Elixir and OTP pinned to this
repository's versions, `Plug`, `Bandit`, `exqlite`, `jason`, `toml`;
`Store.Config` reading the TOML of design §6.5 and refusing to start on a
missing or unwritable `dir`, an empty `nonce_key`, a `public_url` that is
not `https://`; `Store.Endpoint` on `addr:port`, `Store.Router` answering
`204` to an empty `POST /files/hft`, `404` elsewhere, `OPTIONS` with the
CORS headers; `packaging/` with the OTP release, a systemd unit as user
`kelifile` with `RELEASE_DISTRIBUTION=none`, an RPM built as this
repository's `packaging/build-rpm.sh` does, `/etc/kelifile/config.toml`
shipped; `kelifilectl show`. Cohabits with kelescope: two releases, two
users, two units, no distribution, kelescope keeps its own HTTPS on 8443.

**Done when** `dnf install` on `web1` gives a unit answering 204 on the
loopback, and the RPM's version is `mix.exs`'s.

### E2 — upload, naming, metadata, XML

`Store.Upload`: the `File` part streamed to `incoming/`, `Content-Length`
checked against `max_size` **before** the body is read, renamed into `tmp/`
under the name of design §6.3; `Store.Meta`: the SQLite schema of §6.4 with
its `schema.version`, insert, by name, live bytes and count per
`(domain, aor)`; the XML with `until` in UTC and the `content-type`
**echoed with its parameters**; the AOR from the tolerant `From` parser.

**Tests** a `filename` with `/` and `..`; `.php`, `.svg`, `.JPG`;
`audio/wav;voice-recording=yes` round-tripping; one byte over the limit; a
multipart where only `File` counts; a body that stops mid-way.

**Done when** the S0 desktops, pointed at the store with
`upload_auth = "none"`, exchange both messages, and the 200 body, modulo
name and `until`, is byte-identical to the S0 capture.

### E3 — the digest, with the SIP credentials

`Store.Auth`: realm from the `From`'s domain, 400 if not in
`[auth].domains` before any database access; the stateless nonce; the two
challenges, MD5 then SHA-256; full verification; `username` against the
`From`'s user. `Store.Credentials`: a read-only pool on the subscriber base,
`MyXQL` or `Postgrex`, the query configurable; the digest functions copied
from `SIP.Auth` with their origin named. `X-SSL-Client-Verify: SUCCESS`
trusted from the loopback only. `auth_failures_total{domain}`.

**Tests** `CLRTXT`, `MD5`, `SHA-256` bases; the previous window accepted,
two windows ago refused; a wrong `username`; an unknown realm with
`Store.Credentials` never called; a replayed `nc`, accepted and said so.

**Done when** the desktops upload with no prompt under
`upload_auth = "digest"`, a wrong SIP password gets "credentials rejected",
and the 401, modulo the nonce, matches the S0 capture.

### E4 — retention, quotas, control, metrics, Bearer

`Store.Sweeper` every `sweep_interval`, reconciling rows and files both
ways; quotas per `(domain, aor)` refused with 400 **at the empty POST**, so
the client never streams a file the store will refuse; `kelifilectl list`,
`purge`, `show` with the retention and the live totals; the metrics of
design §6.7; the logging rule of §6.6 pinned by a test grepping the log for
the name and the URL; `Authorization: Bearer` verified with
`[auth].bearer_key`, never offered in a challenge.

**Done when** a `retention = "2m"` file is gone within `2m + sweep_interval`;
an AOR at quota gets 400 on the empty POST; a forged token uploads with no
digest.

### E5 — the authenticated download

`GET /files/download?target=<url>` behind E3's digest; `target` must start
with `public_url`, else 404; served with the row's `content_type`,
`Content-Disposition: attachment`, `Content-Length`.

**Done when** a desktop provisioned with `file_transfer_server_get_proxy`
downloads with its SIP credentials, and a foreign `target` is a 404.

### E6 — the switch on `web1`, and the diff

Apache's `ProxyPass` moved from the PHP handler to the loopback service, the
`Alias` to `/var/lib/kelifile/tmp`, the PHP's `tmp/` kept served until
empty; the S0 exchange replayed against the store and diffed against the
S0 captures, reduced to names, nonces and dates.

**Done when** the diff is empty but for those three; the PHP server is
removed when its `tmp/` is empty.

## 6. Decisions this plan takes

1. **The PHP server is the store until it is not enough.** It speaks the
   contract by definition, costs an afternoon, and gives the bytes Part E
   is built against. Writing the Elixir store first would have been building
   against a summary.
2. **The same URL path, so Part E is a switch, not a migration.** Clients
   are provisioned once.
3. **Quotas, when they exist, are enforced at the empty POST.** The client
   streams only after the 204; refusing there spares the upload, and the
   client reads a 400 as "too large" without having sent anything.
4. **Trix sends one file per message.** Linphone cannot do otherwise on
   send and shows one per message on receive.
5. **Measure before building the fallbacks.** The `.mka` playback in
   browsers (T2), the WebM acceptance by Linphone's player (T4) and the cost
   of the digest in the browser (T3) are each a measurement with a named
   fallback, built only on a failed measurement.
6. **The relay and the Silo gain no code.** S1 adds tests; a failing one is
   a bug fix in the message layer, not a chat-media feature.

## 7. Order, and what runs in parallel

S0 first, and alone: everything else is tested against it. S1 follows and
is the only phase touching this repository; its relay test needs no store
and can be written any time. S2 waits for T3's measurement.

Part T: T0 → T1 → T2 is reception and starts the day S0's captures exist.
T3 → T4 → T5 is emission, against the PHP server. T6 waits for S2 and E4.

Part E starts on its trigger (§5), in order E1 → E2 → E3 → E4 → E6, with E5
after E3 whenever a client is provisioned with the proxy. Its two release
points, `kelifile` 0.1.0 (E1 to E4, E6) and 0.2.0 (E5), are not on any
other part's path.

kelixip ships S1's tests and scenarios and the provisioning page in its next
minor; no SIP behaviour changes, so no kelixip release is gated on this plan.

## 8. Risks

- **The PHP server's purge and logging were not seen.** S0 adds the cron
  and checks the log; if the PHP writes file names at the level needed for
  debugging, the logging rule is not met until Part E, and S0 says so in the
  config's comments.
- **The HTTP `From` header shape.** A GRUU whose `;gr=` the PHP server
  mishandles shows up in S0 before anything copies the behaviour.
- **The subscriber base's algorithm column.** If the base holds only
  `CLRTXT` or only `SHA-256`, `AUTH_QUERY` must return what the PHP can
  verify; S0 checks it with a real REGISTER-capable account.
- **The browser's audio container.** T2's matrix may force a WASM demuxer,
  a week of work not in this plan's spine. The fallback is named; its cost
  is not.
- **Linphone mobile.** Nothing here was read in the Android or iOS
  applications. They share the SDK, so the wire format is the same; the
  provisioning path and the voice container are not verified there, and
  S0's recipe should be repeated on one mobile before the plan is called
  done.
- **CPIM provisioning is per account and invisible.** An account
  provisioned without `cpim_in_basic_chat_rooms_enabled=1` works for
  attachments and silently never matches a receipt. The provisioning page
  is the only guard; kelixip cannot tell from the wire.
