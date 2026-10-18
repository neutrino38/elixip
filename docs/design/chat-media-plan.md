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

**Status (2026-10-07):** S1's code is done, its scenario pair included,
run against the store rehearsal (`packaging/fhft/rehearsal/`); S0 is installed on `web1`
on 2026-10-07 (`.pdo1`, its SELinux contexts set by hand; `.pdo2` sets them
itself) and passed its HTTP checks against the Scaleway subscriber base — the
Linphone exchange and its captures remain; the provisioning
page is drafted (`docs/kelixip/chat-attachments.md`), to be confirmed by
S0's captures. Part T: T0 to T5 done in Trix (`9d5975a`
to `1adcbfb`, ADR 0012), checked by tests and, for the upload, against the
rehearsal; T6 not expected; T7, the video message, planned. Every live
check waits for `web1`. What this plan says of
Trix was read in its code at `ff2d8c5` (0.10.8) on 2026-10-06, and its
ADRs 0008 to 0010: CPIM, IMDN and the SHA-256 digest already exist there,
which shrinks Part T to what is specific to files.

## 1. Scope

| In | Why it is the floor |
|---|---|
| the reference PHP server on `web1`, run for real: digest with the SIP credentials, retention, static downloads behind Apache | the store Linphone already speaks to; nothing to write to get a first exchange |
| provisioning of Linphone accounts: the store URL and CPIM | the two keys without which, respectively, nothing is sent and no receipt is ever matched (design D7) |
| the relay and the Silo carrying the bodies verbatim — **a fix** for a bare multipart, a test for the rest | the Silo keeps only the first part of a multipart (§2); the rest was read in the code, never captured (design §12) |
| `deflate` on a MESSAGE that would pass 1300 octets on UDP | XML, CPIM and a caption reach that size, and a UDP-registered Linphone cannot be reached over TCP |
| Trix: receive and show a photo, play a voice message, send both, a caption; isComposing, which it lacks | the second client, and the one that shows the Linphone-side loss of a caption; its CPIM and IMDN already exist and carry files unchanged |
| Trix: a video message, recorded by default, the voice message one choice away (T7) | asked on 2026-10-07: both recorders, video the default |
| the Elixir store, as the last part | what replaces the PHP server when quotas, control, metrics or the logging rule are needed |

| Out | Where it re-enters |
|---|---|
| the Bearer token minted by kelixip for web clients | design §8.3 — Trix already computes both digests from its stored HA1s (§2), so the token is not needed for the cost of the digest; it re-enters with Part E, if ever |
| thumbnails (`file-info type="thumbnail"`) | Linphone ignores them on receive and never sends them |
| object storage, a redundant store | design D6 — the schema is small enough to move when a second host exists |
| a content scanner | design §11 — a hook at the rename step of the Elixir store |
| group chats, LIME | the Flexisip conference server; not this design |

## 2. The starting point

| Piece | State |
|---|---|
| the reference PHP server | public on GitHub, not installed anywhere here; its purge mechanism and its logging were not seen (design §12) |
| `web1` | Apache running, certificate in place; nothing under `/files/` |
| kelixip relay (`SBB.Page`) | carries `Content-Type` and body; a multipart is carried as its parsed parts and **re-serialized**, Content-Type and boundary recomputed (`SIPMsgTemplate.ex:97-102`): equivalent, not byte-identical; never exercised on an `rcs-ft-http` or `message/cpim` body |
| Silo | stores `SIP.Msg.Ops.body_string(req)` (`silo.ex:400`), which for a parsed multipart is **the first part's data alone**, under the original `multipart/…;boundary=` type: a bare multipart comes out of a flush truncated and unreadable. A single-part body, `message/cpim` included, is stored whole |
| `Content-Encoding` | decoded at parsing (`deflate`, `gzip`, `SIP.Msg.BodyCoding`); encoded only as `deflate`, only on a NOTIFY whose watcher asked for it (`SIPDialogImpl.ex:832-850`); a MESSAGE always leaves in clear, whatever its size, and nothing in the transport checks 1300 octets |
| `SIP.Msg.Ops.message_kind/1` | files `application/vnd.gsma.rcs-ft-http+xml` under `:im`, so it is stored and relayed like text |
| `apps/elixip2` | has `Req` as a dependency: an elixipp scenario can upload |
| Linphone desktop on a kelixip domain | basic chat room, no store URL, no CPIM: sends nothing, matches no receipt |
| Trix, receiving (`src/sip/message.ts`) | opens `message/cpim` (`sip/cpim.ts`), then accepts only `text/plain` in UTF-8 or US-ASCII: an `rcs-ft-http` part, in CPIM or bare, gets **415** (ADR 0009 says so); a bare `message/imdn+xml` — what a Linphone without CPIM sends — gets 415 too, since receipts are read only inside CPIM; `Accept` of the 415 is JsSIP's plus `text/plain, message/cpim` |
| Trix, sending | CPIM first with `imdn.Message-ID` = the entry's id and `Disposition-Notification: positive-delivery, display`; on a 415, the same text again in bare `text/plain`, and bare text to that correspondent for the life of the link (ADR 0009 D3); text capped at 1000 octets (D2); JsSIP, one MESSAGE per Call-ID |
| Trix, receipts (ADR 0010) | `delivered` and `displayed` read and written, in CPIM only; read receipts to contacts only (D2); none to a correspondent who refused CPIM; negative receipts read as nothing |
| Trix, credentials (`storage/store.ts`, `storage/ha1.ts`) | no password stored: `ha1` (MD5) and `ha1Sha256`, computed with **realm = SIP domain**; `ha1Sha256` empty for accounts older than its introduction; MD5 and SHA-256 in `storage/md5.ts`, `storage/sha256.ts`; JsSIP's digest grafted for SHA-256 (`sip/digest.ts`) |
| Trix, isComposing | none: no `application/im-iscomposing+xml` sent or read |
| the Elixir store | does not exist; name proposed `kelifile`, repository of its own (design §6.1) |

## 3. Part S — the server side, now

### S0 — the PHP server on `web1`, for real

**Delivers** the store, installed rather than written: the reference
`flexisip-http-file-transfer-server`, upstream commit **`524ab71`** (read on
2026-10-07, design §2.8), on `web1`'s Apache (AL9, php-fpm) under its own
name, **`files.weshwesh.eu`** — the wildcard certificate covers it, and a
name that is not the host's survives Part E moving the store elsewhere.
Configured for production use, not as a demo:

- **the subscriber base through PDO.** Upstream reads it with `mysqli`; the
  kelixip base is PostgreSQL. `packaging/fhft/common-pdo.patch` moves
  `common.php` to PDO, the driver named by `AUTH_DB_DSN`, the query and its
  contract unchanged; a **read-only** role with `SELECT` on `username`,
  `domain`, `ha1` of `subscriber`;
- `DIGEST_AUTH = true`, `AUTH_NONCE_KEY` random, `AUTH_REALM` **removed** so
  the realm is the SIP domain of the HTTP `From` (a fixed realm breaks the
  day a second domain exists);
- **one challenge.** `auth_db` holds one HA1 column hashed one way for the
  whole base, so `AUTH_QUERY` returns it as `password` and the algorithm as
  a constant (`'MD5'` or `'SHA-256'`, as `password_hash` says). The PHP
  offers only the challenges the rows allow: the 401 carries that one alone,
  and no client can pick the other;
- **the URLs**: `Alias /files` to the scripts and `Alias /files/tmp` to the
  upload directory, **statically** — the shipped config sends `tmp/`
  through `download.php`, which challenges, and a browser fetching with
  `credentials: 'omit'` cannot answer. The upload URL is
  `https://files.weshwesh.eu/files/hft.php`, `.php` included, and Part E
  serves the same path (decision 2); `download.php` is denied;
- **php-fpm**: the PHP limits in a `.user.ini` beside the scripts (the
  shipped `php_value` lines need `mod_php`), `CGIPassAuth On` so that
  `Authorization` reaches PHP; the config file loads after `php.conf` so
  the upload directory runs no script whatever its extension;
- `fhft_tmp_path` on a volume sized for `fhft_maximum_file_size_in_MB` times
  the expected traffic over `fhft_validity_period`; the period **at least the
  Silo's `max_retention`** (design D8) — both are 7 days by default;
- **the purge is upstream's** cron job (02:00, older than 7 days), installed
  as shipped; a validity changed in the config is changed there too;
- the Apache side of design §7 on `tmp/`: `Options -Indexes`, `nosniff`,
  `Content-Disposition: attachment`; CORS for `https://trix.weshwesh.eu` on
  both directories, `always` so the 401 carries it and exposes
  `WWW-Authenticate`; `OPTIONS` answered 204 by Apache, never challenged;
  `LimitRequestBody` just above the PHP limit;
- **the logging rule** of design §6.6: `fhft_logLevel` stays `DISABLED`,
  since `ERROR` and `DEBUG` both write file names and paths; said in the
  config's comments.

It is installed as an RPM under upstream's name,
`bc-flexisip-http-file-transfer-server`, built from the pinned commit with the
patch and these files (`packaging/fhft/build-rpm.sh`); upstream's own spec
installs an Apache config httpd refuses under php-fpm.

The installation is rehearsed first in containers on a development machine
— AL9, httpd, php-fpm, PostgreSQL with a `subscriber` table — with the same
files; that rehearsal is what S1's scenario pair runs against before `web1`
exists (S1).

Two Linphone desktops provisioned with `file_transfer_server_url` and
`cpim_in_basic_chat_rooms_enabled=1` exchange one photo and one voice
message, both directions. Captured and kept under `docs/design/captures/`
of this repository: a pcap of the SIP side, Apache's access log and a
loopback capture of the HTTP side. These bytes are what Part E is diffed
against, and the answer to design §12's two first unverified points.

**Also delivers** the provisioning recipe for a Linphone account on a
kelixip domain, in `docs/kelixip/chat-attachments.md`: which keys, where they
go on desktop and on mobile, and that the desktop offers no UI for them.

**Files** `packaging/fhft/` here: the spec and its build script, the PDO
patch, the Apache config, the `.user.ini`, the server config with its
secrets left as placeholders, and the rehearsal, which installs the RPM; `docs/kelixip/chat-attachments.md` and
`docs/design/captures/`.

**Done when** the two desktops exchange both messages with receipts; the
realm challenged is the SIP domain, with one algorithm; what Linphone does
with the 400 the PHP gives its authenticated empty POST is captured (design
§12); a `GET` on `/files/tmp/` lists nothing;
a file older than the period is gone the next morning; and the captures
are committed.

### S1 — kelixip: the relay, the Silo, elixipp

**Delivers** what this repository owes the design: two fixes in the
message layer and the tests that pin them.

- **the Silo stores the body as it was on the wire.** `body_string/1` is the
  body *to read* and answers the first part of a multipart; the Silo needs
  the body *to carry*. A second reading in `SIP.Msg.Ops` — the octets of the
  whole body, a multipart serialized with its parts — is what the Silo
  stores and sizes, and what its delivery sends back under the stored
  `Content-Type`. Whether the delivery re-parses it into parts or carries
  it as a string under its type is decided in the code, as long as the
  boundary in the type and the one in the body agree;
- **`deflate` past 1300 octets on UDP.** A page-mode MESSAGE — relayed by
  `SBB.Page` or delivered from the Silo — whose serialized form would pass
  1300 octets on a UDP transport leaves with its body compressed and
  `Content-Encoding: deflate` (RFC 3261 §20.12); the threshold is
  §18.1.1's, applied where TCP is not an option, a UDP-registered contact.
  Below the threshold, or on TCP, TLS or WSS, the body leaves in clear, as
  today. `deflate`, not `gzip`: Linphone decodes it, and
  `SIP.Msg.BodyCoding.encode/2` already writes it (zlib format) for the
  presence NOTIFYs, so no encoder is added — the same function, called
  from a second place. The decision lives in one place, where the outgoing
  transport of the page is known, and covers both senders. A **415**
  carrying an `Accept-Encoding` without `deflate` sends the page once more
  in clear, and that is the only retry. Still over 1300 compressed: sent
  anyway, and a warning says so;
- a test in `apps/kelix_modules` paging an `rcs-ft-http` body, a
  `message/cpim` body and a bare `multipart/mixed` of XML and text through
  `SBB.Page` to a Mockup device, and through `Kelix.Mod.Silo.store/2` then
  a flush. Asserted: the single-part bodies **byte-identical**, the
  `Content-Type` unchanged; the multipart **equivalent** — same parts, same
  part headers, same order, a boundary that matches its type — since the
  relay re-serializes it; and the Silo test fails before the first fix;
- the same paths to a UDP device with a body that crosses 1300 octets:
  compressed, decodable to the original, and in clear after a 415;
- an elixipp scenario pair, tagged `:live`: a UAC that uploads through `Req`
  (empty POST, digest, `File` part), builds the XML and pages it; a UAS that
  parses the XML, downloads and checks the size — the node's own way to
  test a store without a Linphone, usable against the PHP server today and
  the Elixir store later;
- the provisioning page of S0 in its final form.

**Done on 2026-10-06**, as built:

- `SIPMsg.body_octets/1`, public — the private helper the serializer and the
  redaction already used, a multipart of one fixed — is what the Silo stores
  and sizes; delivery needed no change, the stored type and octets go out
  as a string;
- `SIP.Msg.BodyCoding.fit_datagram/1`, called by `SIP.Transac` right after
  the Via is added, for a connectionless transport only; `send_in_clear/1`
  marks the map (the serializer skips the key) and `coding_refused?/1` reads
  the 415; `SIP.Session.Page.Relay` sends again once, on a dialog of its own,
  listening only to the current one;
- found on the way: the relay re-spelled a multipart's Content-Type as
  `multipart/mixed; boundary=…` — a `related` renamed `mixed` — because
  `page_request/2` dropped the sender's type for a list body. It now keeps
  it, and a bare multipart is relayed **byte for byte**;
- fixed after S1: the parser trimmed a part's data, so a part ending in
  whitespace (a caption ending in a space, an XML ending in CRLF) lost it
  through any relay. It now splits on the delimiter with the line break
  before it (RFC 2046 §5.1.1) and keeps the data exactly;
- tests in `apps/elixip2/test/body_coding_datagram_test.exs`,
  `sbb_page_test.exs` (relay byte for byte, compression on the wire, the
  415 retry) and `apps/kelix_modules/test/silo_test.exs` (the multipart
  through store and flush, failing before the fix).

**The scenario pair, done on 2026-10-07.** What a scenario needed became
framework, as CLAUDE.md asks of any SIP reading:

- `SIP.FileTransfer` — the `fthttp` XML read (`file-info` of type `file`
  alone, name percent-decoded, `playing-length` in milliseconds) and
  written in Linphone's shape; the upload, the empty POST sent to learn the
  challenge and the credentials put on the file POST, since the reference
  server answers 400 to an authenticated empty POST (design §2.8); the
  download;
- `SIP.Msg.Ops.file_transfer_xml/1` — the XML found bare, in CPIM, or as the
  part of a multipart, bare or in CPIM;
- `SIP.Session.FileTransfer`, used by `SIP.Scenario` — `upload_file`,
  `download_file` (one tagged event each, as `http_GET`), `send_file_page`,
  `file_info`; the credentials are the context's HA1 and algorithm, the HTTP
  `From` the account's bare URI;
- `SIPMsg.parse_challenge/1` — a `WWW-Authenticate` value read, SIP's or
  HTTP's;
- `apps/elixip2/scenarios/uac_file_message.exs` and `uas_file_message.exs`,
  defaulting to the rehearsal and its `alice@unit.test`; run through
  `elixipp`, the UAS downloaded the 380 octets the XML announced;
- `apps/elixip2/test/file_transfer_test.exs` — the XML, the four places it
  is found, and the upload against a `Req` adapter behaving as the reference
  server does, plus one `:live` upload and download against `FHFT_URL`.

**Files** `apps/elixip2/lib/framework/SIPMsg.ex`, `SIPMsgBodyCoding.ex`,
`SIPMsgTemplate.ex`, `SIPTransaction.ex`, `SIPSessionPage.ex`,
`SIPDialogImpl.ex`; `apps/kelix_modules/lib/kelix/mod/silo.ex`; the tests
above; still to come with S0: `docs/kelixip/chat-attachments.md`.

**Done when** the tests are green, the scenario pair against the PHP
server; a Linphone desktop, offline during the upload and the MESSAGE, gets
the photo at its next REGISTER from the Silo, with the file still
downloadable; and a UDP-registered Linphone desktop shows a captioned
photo from a client sending the bare multipart, which crosses 1300 octets
— the capture shows `Content-Encoding: deflate` and a 200.

### S2 — the token mint (conditional, not expected)

**Delivers**, only if T3 finds a case the digest cannot answer: the
one-route token mint of design §8.3 in `Kelix.ControlAPI`, for an
authenticated subscriber. The cost of the digest is no longer the trigger:
Trix ships MD5 and SHA-256 and keeps both HA1s (§2), so the digest costs it
nothing new. What remains possible is an account whose `ha1Sha256` is empty
facing a store that challenges with SHA-256 only. The PHP server does not
verify a Bearer token, so this phase also moves the trigger of Part E
forward: a web client that needs the token needs the Elixir store.

## 4. Part T — the client side (Trix)

Each phase lands in `trix-web-client` with its ADR when a trade-off is
taken, numbered after ADR 0011. The decisions quoted below are Trix's: D1
to D13 of ADR 0008 (as in chat-basic-plan §6), and those of ADRs 0009
(CPIM) and 0010 (IMDN). Every phase is tested against the PHP server of S0
and a Linphone desktop.

What Trix already has, and this part builds on rather than redoes: the
CPIM envelope both ways, with `imdn.Message-ID` and the 415 fallback to
bare text (ADR 0009); `delivered` and `displayed` receipts both ways, in
CPIM (ADR 0010); both HA1s and both hash functions (§2). A file message
goes through the same send path as a text: in CPIM, with the entry's id as
`imdn.Message-ID`, and receipts follow without new code on the receipt
side.

### T0 — the store's address, and the message model

**Delivers** two decisions, in one ADR:

- **where the store URL lives**: in `AccountConfig`, beside `proxy` and
  `ice` — an operator setting, carried by a share link to a second device
  (it is not a secret; the HA1s are), mirroring Linphone's provisioning;
  empty means "attachments off", and is the value of every account saved
  before it, as `ice` and the RTT transport already do;
- **what an entry is** once a message may be a file: the messaging
  machine's entry gains a kind (text, file) and, for a file, the fields of
  the XML (URL, name, type, size, `until`, duration); a file entry has an
  id like a text entry, so dedup (ADR 0009) and receipts (ADR 0010) apply
  to it unchanged.

**Done when** the ADR is written and the facts of §2 still hold at the
commit Part T starts from.

**Done on 2026-10-07** — Trix ADR 0012, from `ff2d8c5`, whose facts held.
Taken there: the store URL is an account setting `fileStore`, empty for
off, that `config.json` pins with `file_transfer_server`; the field itself
arrives with T3, since reception reads the URL from the XML. An entry
gains an optional `file`, its `text` becoming the caption. The ADR also
carries what the reference store asks of a sender (bare `From`, the 400
to an authenticated empty POST, MD5 alone), for T3.

### T1 — receive an attachment, show it as a card

**Delivers** reception of design §9.3 steps 1-3 and 5, in
`sip/message.ts` after the CPIM is opened:

- accepted, inside CPIM or bare: `application/vnd.gsma.rcs-ft-http+xml`,
  `multipart/mixed` of XML and text, `message/external-body`, besides
  `text/plain`; `ACCEPTED_BODY_TYPES_WITH_TEXT` extended accordingly, and
  ADR 0009's "a file gets 415" revised;
- a bare `message/imdn+xml` answered **200** and read like one inside CPIM:
  it is what a Linphone without CPIM sends, its id is the Call-ID of the
  relayed leg, so it matches nothing and is dropped — but it no longer
  draws a 415;
- the `fthttp` XML read with only `file-info[@type="file"]`; `file-name`
  percent-decoded; a voice message recognised by the strict
  `audio/wav;voice-recording=yes`; `playing-length` read as **milliseconds**;
  `until` compared to now, a past one shown as "expired"; the XML through
  the injected `XmlParser`, as PIDF and IMDN are;
- the CPIM `From` still not trusted for the sender — the SIP `From` is
  (ADR 0009);
- a card in the conversation: name, size, type icon, duration for a voice
  message, "download" and "expired" states; the 1000-octet cap (D2) applies
  to text only.

**Tests** the XML of design §2.2 with and without `until`, with
`am:playing-length`, with `file-key` (ignored), the `external-body` form,
a multipart of XML and text, each bare and in CPIM; a bare IMDN.

**Done when** a Linphone desktop's photo and voice message, received live,
show as cards with the right name, size and duration, a text still shows
as text, and a Linphone without CPIM gets 200 to its receipts.

**Built on 2026-10-07** (Trix `9d5975a`): `sip/fthttp.ts` reads the XML
and finds it bare, in CPIM, beside a caption or as `external-body`;
`sip/message.ts` files it and answers a bare IMDN 200; `ui/attachment.ts`
draws the card, with a plain download link until T2 — only an `http(s)`
URL becomes one, and past `until` the card says "expired". Tested on the
store rehearsal's own XML and on Linphone's as the design records it; the
live check with a Linphone desktop waits for S0.

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
- the HTTP digest from the **stored HA1s**, no password: the store's realm
  is the SIP domain (S0), which is the realm Trix's HA1s were computed
  with (`storage/ha1.ts`); MD5 or SHA-256 chosen among the challenges by
  which HA1 the account holds, SHA-256 first; `nc` incremented on the
  second POST; the response computed with `storage/md5.ts` and
  `storage/sha256.ts`. An account without `ha1Sha256` facing a SHA-256-only
  challenge says so, as `sip/digest.ts` already does for SIP; that case,
  if met on the real store, is what S2 is for;
- the XML built as §2.2, CRLF, percent-escaped name, local type;
- the MESSAGE through the existing send path, generalized from text to a
  part type: in CPIM with the entry's id, receipts requested; on a 415, the
  bare XML, as for text; 200 or 202 is acceptance; from the store, 400 is
  "too large", 401 is "check your password";
- the picker, a size limit equal to the server's, a progress indicator, and
  **one file per message** — several files are several messages, which is
  also what Linphone can show.

**Done when** a photo sent from Trix shows on a Linphone desktop and on a
second Trix, and comes back "delivered" from both.

### T4 — send a voice message, and isComposing

**Delivers** design §9.2: `MediaRecorder` as `audio/webm; codecs=opus`,
named `vocal_<timestamp>.mka`, duration measured in milliseconds, uploaded
with the type `audio/wav;voice-recording=yes` on the part, the XML with
`am:playing-length`. **Measured on a Linphone desktop**: if its player
refuses the browser's WebM, the fallback is a WAV PCM 16 kHz mono encoder in
the client, and the ADR records which container goes out.

Trix has no isComposing at all, so the "recording" indicator is new work,
done here whole rather than for voice alone: `application/im-iscomposing+xml`
sent and read as design §2.6 and §9.4 say — `active` every 60 s while typing
or recording, the voice `contenttype` while recording, `idle` after 15 s,
the peer idle after its `refresh`; a 480 from kelixip for an absent
recipient is not an error. Never in CPIM, never stored, never a receipt.

**Done when** a voice message recorded in Trix plays on a Linphone desktop
with the right duration, and the "recording a voice message" indicator shows
there while Trix records; the typing indicator works both ways.

### T5 — text with a photo

**Delivers** the caption, which Linphone shows on receive but never sends:
one `multipart/mixed`, XML part first then `text/plain; charset=UTF-8`,
**inside the CPIM envelope** like any other content — the SIP body stays a
single `message/cpim` part, which the Silo stores whole even before S1. The
bare multipart goes out only after a 415, and relies on S1's fix to survive
the Silo. The UI says, once, that a Linphone sender's caption does not
arrive (design §2.4) — a fact to display, not to work around. The text part
keeps the 1000-octet cap.

The receipts need nothing new: the entry has an id (T0), the receipt path
of ADR 0010 is unchanged. Its disposition request stays `positive-delivery,
display` — no `negative-delivery`, since ADR 0010 reads negative receipts as
nothing; design §9.4 is aligned on that.

**Done when** a captioned photo from Trix shows both on a second Trix and,
caption included, on a Linphone desktop; a Linphone desktop provisioned
with CPIM shows "delivered" then "read" for it, and Trix shows the same for
a photo from Linphone.

**T2 to T5, built on 2026-10-07** (Trix `73186c7`, `0ac46d6`, `1adcbfb`,
ADR 0012 D6 to D10), with these departures from the text above:

- T2: images and voice messages up to 10 MB are fetched as their card
  shows; an `<audio>` error turns the card into a file to save, which is
  how the browser matrix will show up — it is not measured yet. A fetch
  redraws its card alone, so playback survives other updates;
- T3: no client-side size limit and no progress bar — the store says "too
  large" with its 400, and `fetch` does not report upload progress; the
  file is kept in memory only, and one lost to a reload fails, said so;
- T5 came with T3: what is being typed when the photo is picked leaves as
  its caption, in a multipart inside the CPIM envelope;
- T4: the WAV fallback is not built — it waits for the measurement on a
  Linphone desktop.

### T6 — the Bearer path (conditional, not expected)

**Delivers**, only if S2 was built and Part E has reached E4: the token
obtained from kelixip after registration, sent as `Authorization: Bearer` on
the first POST, refreshed before its expiry; the digest kept as the fallback
when the store answers 401 anyway.

**Done when** an upload from Trix carries no digest and the store's
`auth_failures_total` does not move.

### T7 — a video message, by default

**Delivers** the recorder of T4 turned into a video recorder, the voice
message kept beside it:

- **video by default**: the record button opens the camera and the
  microphone, with a live preview while recording; "voice only" is one
  choice away and sends exactly what T4 sends today. The choice is per
  message, not a setting; a camera that is refused, absent or busy — in a
  video call, say — falls back to voice and says so;
- `MediaRecorder` on the camera stream, the container the browser offers
  in an order fixed by the measurement below (`video/mp4` H.264/AAC where
  available, else `video/webm` VP8 or VP9 with Opus), a bitrate and a
  resolution bounded (of the order of 640×480 at 1 Mb/s) and a duration
  bound (of the order of two minutes), so a message stays well inside the
  store's `fhft_maximum_file_size_in_MB`;
- **sent as an ordinary file**, not as a voice message: Linphone has a
  type for a recorded voice message (`audio/wav;voice-recording=yes`) and
  none for a recorded video, so it is named `video_<date>.<ext>`, typed
  with its real container, and carries no `playing-length` unless the
  measurement shows Linphone reads one for video;
- **received as a video**: T2's card gains the `video/*` kind, sniffed on
  its first bytes like audio (`ftyp` for MP4, EBML for WebM), played in a
  `<video controls>` within the card, and auto-fetched under the same 10 MB
  bound — a larger one waits for the button;
- the typing indicator while recording carries the video's type; what
  Linphone shows for it is part of the measurement.

**Measured, not assumed**: what a Linphone desktop does with a browser's
video file — plays it inline, hands it to the system player, or only
offers to save it — for MP4/H.264 and WebM/VP8; which container each
browser records; the size of a two-minute message at the chosen bitrate.
The container order and the bounds are set from these, and written in
the ADR.

**Done when** a video message recorded in Trix plays in a second Trix and
opens on a Linphone desktop; "voice only" still arrives on Linphone as a
voice message; a refused camera falls back to voice.

## 5. Part E — the Elixir store, later

**When to start it.** The PHP server is kept as long as none of these is
needed: a quota per AOR, `kelifilectl`-style control (list, purge),
metrics, the logging rule enforced by code rather than by a log level, a
Bearer token for web clients (S2), or a second domain whose realm handling
the PHP server gets wrong. The first of these that is asked for starts E1.
Until then, Part E is a design with a plan, not a debt.

**What it replaces.** The same URL path on `web1` (`/files/hft.php`,
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
`204` to an empty `POST /files/hft.php`, `404` elsewhere, `OPTIONS` with the
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
   browsers (T2), the WebM acceptance by Linphone's player (T4) and the
   digest algorithm the real store challenges with (T3) are each a
   measurement with a named fallback, built only on a failed measurement.
6. **The relay and the Silo gain no chat-media feature, but two fixes.**
   The Silo's truncation of a bare multipart and the absence of any size
   rule on UDP are bugs of the message layer that attachments expose; they
   are fixed there, once, for every page (S1), not worked around in a
   client.
7. **Size on UDP is solved by `deflate`, not by a cap.** A UDP-registered
   contact cannot be reached over TCP, and a caption or a CPIM envelope is
   not a reason to refuse a message. Compression is applied only past the
   1300 octets of RFC 3261 §18.1.1 and only on UDP, so every message that
   works today leaves exactly as today.
8. **Trix wraps every content in CPIM, the caption included.** The CPIM
   envelope already carries Trix's text and receipts; a file is one more
   content type inside it, and keeping the SIP body single-part keeps it
   out of the multipart paths of the relay and the Silo.

## 7. Order, and what runs in parallel

S0 first, and alone: everything else is tested against it. S1 is the only
phase touching this repository; its two fixes and their tests need no store
and **can start now**, in parallel with S0 — only its scenario pair and its
Linphone checks wait for S0. S2 waits for T3.

Part T: T0 → T1 → T2 is reception and starts the day S0's captures exist.
T3 → T4 → T5 is emission, against the PHP server; T5's fallback to a bare
multipart needs S1 deployed. T6 waits for S2 and E4. T7 follows T4 and
needs T2's player extended to video; its measurements need a Linphone
desktop, so it is built against the rehearsal and checked with S0.

Part E starts on its trigger (§5), in order E1 → E2 → E3 → E4 → E6, with E5
after E3 whenever a client is provisioned with the proxy. Its two release
points, `kelifile` 0.1.0 (E1 to E4, E6) and 0.2.0 (E5), are not on any
other part's path.

kelixip ships S1 in its next minor: the Silo fix and `deflate` on UDP **are**
SIP behaviour changes, and the release note says so — a MESSAGE over 1300
octets to a UDP contact now leaves compressed. Nothing else in this plan
gates a kelixip release.

## 8. Risks

- **Linphone receiving CPIM when not provisioned for it.** Trix sends CPIM
  first to everyone and falls back on a 415 (ADR 0009); ADR 0009's real
  validation is still pending. T3 sees it on the first file sent to an
  unprovisioned desktop.
- **The 400 to an authenticated empty POST.** With digest on, the PHP
  answers 400 where RCS describes a 204 (design §2.8). If Linphone treats
  it as a failure, attachments do not work against the reference server
  with digest, and S0 falls back to digest on the file POST alone — a
  second local patch — or to the Elixir store early.
- **The HTTP `From` header shape.** The PHP needs a bare URI; Trix must
  send one (T3). What Linphone sends is captured in S0.
- **The PDO patch is ours.** Upstream changes to `common.php` have to be
  re-applied by hand; the commit is pinned for that reason.
- **Realm = SIP domain, on both sides.** Trix's HA1s and the base's HA1s
  were computed with the SIP domain as realm, and the store challenges with
  the domain of the HTTP `From`. A deployment whose SIP realm differs from
  its domain breaks the HTTP digest for both clients; it is not one of
  ours, and the provisioning page says the two must be equal.
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
