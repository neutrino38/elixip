# DESIGN-CHAT-MEDIA.md — attachments in chat: photos and voice messages

How a chat message carries a photo or a voice message, the way Linphone does
it, and what is built to support it: a file store over HTTP, nothing new in
the SIP relay, and a client-side contract a web client can follow.

This settles the "Media" question of [DESIGN-CHAT.md](DESIGN-CHAT.md): the
content travels by **URL**, in the GSMA RCS format, not by MSRP. Everything
Linphone-side below was read in the code of `linphone-sdk`
5.6.0-alpha-69-g49190259c0 and `linphone-desktop` 6.3.0-alpha-76-gf1cb65b89;
the reference file server was read on GitHub
(`BelledonneCommunications/flexisip-http-file-transfer-server`, PHP). §12
lists what was not verified.

**Status (2026-10-02): designed, not built.** The build order is
[chat-media-plan.md](chat-media-plan.md): the reference PHP server is run
first and is the store for as long as it suffices; the Elixir store of §6
replaces it on the trigger the plan states. Every host name in this
document is a placeholder under `example.com` (RFC 2606); the production names
live in the deployment, never in a repository.

## 1. Objective and scope

A subscriber of a kelixip domain, on Linphone or on a web client, sends a
photo or a voice message to another subscriber of the domain, who may be on
either client, online or not. The recipient sees the attachment, plays the
voice message with its duration, and the sender gets the delivery receipt when
the clients support it.

In scope: the file store (upload, download, retention, quotas,
authentication), the provisioning Linphone needs, what the kelixip relay and
the Silo already do and must keep doing, and the contract a web client
implements.

Out of scope: group chats (the Flexisip conference server), end-to-end
encryption (LIME, which requires that server), MSRP, thumbnails, and media
sent *during* a call by other means than MESSAGE.

## 2. What Linphone does

A message with an attachment is **two transactions in two protocols**. The
file goes over HTTPS to a file store. The SIP MESSAGE carries a small XML
with the URL. The SIP server never sees the file.

```
Alice (Linphone)            file store (HTTPS)           kelixip (SIP)          Bob
   |  POST hft  (empty)          |                            |                  |
   |---------------------------->|                            |                  |
   |  401 Digest (if enabled)    |                            |                  |
   |<----------------------------|                            |                  |
   |  POST hft  (empty + Authorization)                       |                  |
   |---------------------------->|                            |                  |
   |  204                        |                            |                  |
   |<----------------------------|                            |                  |
   |  POST hft  multipart/form-data, field "File"             |                  |
   |---------------------------->|                            |                  |
   |  200 + XML (url, until, size)                            |                  |
   |<----------------------------|                            |                  |
   |  MESSAGE  application/vnd.gsma.rcs-ft-http+xml           |                  |
   |--------------------------------------------------------->|  MESSAGE         |
   |                                                          |----------------->|
   |  200 OK                                                  |  200 OK          |
   |<---------------------------------------------------------|<-----------------|
   |                             |  GET <url>                                    |
   |                             |<----------------------------------------------|
   |                             |  200 + bytes                                  |
   |                             |---------------------------------------------->|
   |  MESSAGE message/imdn+xml (delivered)                    |<-----------------|
   |<---------------------------------------------------------|                  |
```

### 2.1 The upload

Config key `[misc] file_transfer_server_url` (`coreapi/linphonecore.c:9119`).
Without it, nothing is sent ("no file remote URI configured",
`src/chat/modifier/file-transfer-chat-message-modifier.cpp:555`). The desktop
has **no UI field** for it and never sets it in code: it comes from the
assistant rc file, and only for `sip.linphone.org`
(`Linphone/data/assistant/use-app-sip-account.rc:35`). For any other domain
the URL must arrive by remote provisioning or by editing `linphonerc`.

The client follows RCS 5.1 §3.5.4.8.3.1 (modifier, line 87):

1. `POST <url>` with `Content-Length: 0`, headers `User-Agent` and
   `From: <local SIP address>` (`startHttpTransfer`, lines 568-570). The
   `From` may carry URI parameters (`;gr=…`). Expected: **204**. A **401**
   with `WWW-Authenticate: Digest` is answered with the SIP credentials, at
   most twice (`coreapi/authentication.c:578`).
2. On 204, `POST <url>` again, `Content-Type: multipart/form-data; boundary=…`
   (belle-sip sets `form-data` on any non-related multipart,
   `belle-sip/src/message.cc:572`), one part:
   `Content-Disposition: form-data; name="File"; filename="<name>"` and the
   part's `Content-Type` equal to the content's type **with its parameters**
   (`prepare_upload_body_handler`, lines 268-273, 316-321). The name is
   percent-escaped except alphanumerics and `-_.[]` (lines 1368-1380).
3. Expected: **200** with the XML of §2.2. Any 200 whose XML lacks
   `file-name` or `url`, and any other code, is a failure. 400 is logged as
   "probably meaning file is too large", 401 as "credentials were rejected"
   (lines 420-452).

### 2.2 The server's XML, and the one the client sends

The server answers:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<file xmlns="urn:gsma:params:xml:ns:rcs:rcs:fthttp">
  <file-info type="file">
    <file-size>184233</file-size>
    <file-name>IMG_0042.jpg</file-name>
    <content-type>image/jpeg</content-type>
    <data url="https://files.example.com/files/tmp/68de1c2a0b7f1_9f3a…c2.jpg" until="2026-10-09T10:21:45Z"/>
  </file-info>
</file>
```

The client reads only `file-info[@type="file"]`, and in it `file-size`,
`file-name`, `content-type`, `playing-length`, `data@url`, `data@until`,
`file-key`, `file-authTag` (`parseFileTransferXmlIntoContent`, lines
1248-1365). It then **rebuilds its own XML** for the MESSAGE
(`dumpFileTransferContentAsXmlString`, lines 1166-1237), CRLF line ends,
keeping the server's `url`, `until` and `file-size` and putting back its
local file name and content type, because "file transfer server removes
content type parameter" (comment, line 365):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<file xmlns="urn:gsma:params:xml:ns:rcs:rcs:fthttp" xmlns:am="urn:gsma:params:xml:ns:rcs:rcs:rram">
<file-info type="file">
<file-size>184233</file-size>
<file-name>IMG_0042.jpg</file-name>
<content-type>image/jpeg</content-type>
<data url="https://files.example.com/files/tmp/68de1c2a0b7f1_9f3a…c2.jpg" until="2026-10-09T10:21:45Z"/>
</file-info>
</file>
```

`file-key` and `file-authTag` appear only with LIME, never in a basic chat
room. One file per message: `encode` takes the first file content and stops
(lines 75-82). The older `message/external-body; access-type=URL; URL="…"`
form is still read (`createFakeFileTransferFromUrl`) but no longer produced.

### 2.3 A voice message

Not a MIME type of its own. A file whose content type is exactly

```
audio/wav;voice-recording=yes
```

(`ContentType::VoiceRecording`, `src/content/content-type.cpp:60`; strict
comparison with the parameter, `c-content.cpp:354`), plus the duration:

```xml
<am:playing-length>4320</am:playing-length>
```

in namespace `urn:gsma:params:xml:ns:rcs:rcs:rram`, in **milliseconds**
(`Recorder::getDuration`, `src/recorder/recorder.cpp:109-121`, written as is
at line 1215). RCS says seconds; Linphone writes milliseconds.

**The type lies about the container.** The desktop records Matroska with
Opus at 48 kHz (`RecorderCore.cpp:53-55` sets `MediaFileFormat::Mkv`;
`RecorderModel.cpp:84` names it `vocal_<timestamp>.mka`;
`mediastreamer2/src/voip/msmediarecorder.c:292,448`: "if mkv, opus for
audio"), and the SDK labels it `audio/wav;voice-recording=yes` regardless
(`Recorder::createContent`, lines 129-142). Linphone's own player ignores
the type and sniffs the first four bytes (`msmediaplayer.c:449-470`): `RIFF`
for WAV PCM, `1A 45 DF A3` for Matroska. While recording, the desktop sends an
`isComposing` whose `contenttype` is `audio/wav;voice-recording=yes`
(`c-chat-room.cpp:268`).

### 2.4 Text with a file: what a basic chat room drops

Against a domain that is not `sip.linphone.org`, the desktop creates a
**Basic** chat room, unencrypted (`ToolModel.cpp:711-727`: FlexisipChat
needs a conference factory URI and a LIME server URL). It puts every file
then the text **into one message** (`ChatModel::createMessage`,
`model/chat/ChatModel.cpp:221-229`). The SDK emits `multipart/mixed` only if
`canHandleMultipart()`, which in a basic room is `mMultipartAllowed`, false
by default, changed only by the C API `linphone_chat_room_allow_multipart()`
(`basic-chat-room.cpp:57-77`). The desktop never calls it. With several
contents, the SDK logs "Chat room doesn't support multipart, but has
multiple parts !" and sends **the first content only**
(`chat-message.cpp:1784-1798, 1859-1861`). "Photo + caption" loses the
caption; "three photos" loses two. Nothing on the server side can recover
them.

On **reception**, CPIM and multipart are decoded unconditionally
(`chat-message.cpp:1175-1196`). A web client may send text and photo in one
`multipart/mixed` and Linphone shows both. The asymmetry is Linphone's.

### 2.5 CPIM and IMDN in a basic chat room

`canHandleCpim()` is `mCpimAllowed || cpim_in_basic_chat_rooms_enabled`
(`basic-chat-room.cpp:61-73`). The second is a **per-account** parameter,
`[proxy] cpim_in_basic_chat_rooms_enabled`, false by default; the desktop
sets it only for `sip.linphone.org` (`use-app-sip-account.rc:25`). The
desktop's factory key `[sip] use_cpim=1` is read nowhere in the SDK.

Without CPIM:

- the body is bare, `Content-Type: application/vnd.gsma.rcs-ft-http+xml`;
- **no IMDN is requested**: the request lives only in the CPIM headers
  (`cpim-chat-message-modifier.cpp:105-144`);
- the receiver **still sends** a `delivered` IMDN, because its three flags
  default to true (`chat-message-p.h:292-294`) and `[sip] im_notif_policy`
  defaults to `all`. Its `message-id` is then the **Call-ID of the received
  MESSAGE** (`chat-room.cpp:665-680`). It goes at once, unaggregated
  (`imdn.cpp:431-436`), to the `From` URI without GRUU
  (`chat-room.cpp:332-346`), with `Priority: non-urgent`
  (`imdn-message.cpp:111`), bare XML:

```xml
<?xml version="1.0" encoding="UTF-8"?><imdn xmlns="urn:ietf:params:xml:ns:imdn"><message-id>a8f2c1d0…@192.0.2.10</message-id><datetime>2026-10-02T10:21:47Z</datetime><delivery-notification><status><delivered/></status></delivery-notification></imdn>
```

With CPIM provisioned, the body is `message/cpim`:

```
From: <sip:alice@example.com>
To: <sip:bob@example.com>
DateTime: 2026-10-02T10:21:45Z
NS: imdn <urn:ietf:params:imdn>
imdn.Message-ID: 7Kq2xP9fLm3a
imdn.Disposition-Notification: positive-delivery, negative-delivery, display

Content-Type: application/vnd.gsma.rcs-ft-http+xml

<?xml version="1.0" …
```

In an unencrypted basic room the authenticated sender is the **SIP** `From`
(`chat-message.cpp:1159-1168`); a client emitting CPIM must use the same
`From` there.

### 2.6 The MESSAGE itself

Out of dialog, no Contact (`[sip] chat_msg_with_contact` = 0), a `Date`
header, `Content-Type`, `Content-Length`, sometimes `Content-Encoding`
(`src/sal/message-op-interface.h:40-61`). The client expects and answers
**200**; it never emits 202 (`coreapi/callbacks.c:758-773`). Refusals: 415
when no part is of a supported type, 488 for `Session-mode: true` or when
encryption is mandatory, 500 with `Accept` when `Content-Type` is missing,
503 when the core is not ready. Supported types, checked **after** CPIM and
multipart are unwrapped (`linphonecore.c:9838-9847`):

```
text/plain
message/external-body
application/vnd.gsma.rcs-ft-http+xml
application/im-iscomposing+xml
message/imdn+xml
text/calendar
application/vnd.linphone.call-log+json
```

`isComposing` (RFC 3994): `application/im-iscomposing+xml`,
`Priority: non-urgent`, `Expires: 0`, `<state>active|idle</state>`,
`<contenttype>`, `<refresh>60</refresh>`; timers `[sip] composing_idle_timeout`
15 s, `composing_refresh_timeout` 60 s, `composing_remote_refresh_timeout`
120 s.

### 2.7 The download

`GET` on the URL from the XML, with `From` and `User-Agent`, no
`Authorization` unless challenged (`processAuthRequestedDownload`, lines
948-958). The client takes the size from `Content-Length` and accepts a
chunked body (`onRecvEnd`, line 756); the HTTP `Content-Type` is ignored,
the XML's is used. Any code ≥ 400 fails the download.

The client **never checks `until`**: it is parsed, stored as a property and
copied back (lines 1301-1305, 1219-1225). Expiry is the server's job alone.

With `[misc] file_transfer_server_get_proxy` set, the URL is fetched as
`<proxy>?target=<url>` (lines 1055-1061), and the proxy may challenge.

Auto-download: `[app] auto_download_incoming_files_max_size` (desktop rc:
10 MB; the UI switch writes 0 = always or -1 = never), and voice recordings
are always downloaded (`auto_download_incoming_voice_recordings`, default
true, `linphonecore.c:2065-2067`).

### 2.8 The reference file server

`flexisip-http-file-transfer-server`, PHP behind Apache, read on GitHub:

| Setting | Default | Role |
|---|---|---|
| `fhft_tmp_path` | `/var/opt/belledonne-communications/flexisip-http-file-transfer-tmp/` | files |
| `fhft_validity_period` | 7 days | written in `until` |
| `fhft_maximum_file_size_in_MB` | 256 | above: 400 |
| `fhft_extension_black_list` / `fhft_extension_fallback` | html, php, jsp… / `txt` | server-side extensions get `.txt` appended |
| `DIGEST_AUTH` | false | challenge uploads and proxied downloads |
| `AUTH_REALM` | `sip.example.org` | fixed realm; if undefined, the domain of the HTTP `From` |
| `AUTH_NONCE_KEY`, `MIN_NONCE_VALIDITY_PERIOD` | –, 10 s | nonce = HMAC-SHA256 of the time window; current and previous windows accepted |
| `AUTH_QUERY`, `AUTH_DB_*` | MySQL | returns `password` and `algorithm` (`CLRTXT`, `MD5`, `SHA-256`); in MD5 the stored value is the **SIP HA1** |

`hft.php`: empty POST → 204; otherwise `$_FILES['File']`, size checks → 400,
stored as `uniqid() . "_" . bin2hex(random 10 bytes) . ".$ext"`, URL
`<scheme>://<host>:<port><dir of hft.php>/tmp/<name>`, so the file is served
**statically** by Apache, with no authentication: the URL is the capability.
The 401 carries two challenges, MD5 and SHA-256, `qop="auth"`,
`opaque=md5(realm)`. A valid TLS client certificate
(`SSL_CLIENT_VERIFY == SUCCESS`) bypasses the digest; "the server won't
check the individual access but only certificate validity"
(`tester/message_tester.c:144-146`). `download.php` requires the
authentication, serves `Content-Type: application/octet-stream`,
`Content-Disposition: attachment`, `Content-Length`, 404 when absent.

On the client side the digest uses **the SIP credentials**, found by
username and domain of the local address, from realm to domain to username
(`_linphone_core_find_auth_info`, `authentication.c:268-300`). Nothing is
asked of the user. Bearer tokens are also understood when the server
challenges with `Bearer` (`authentication.c:591-613`), after an OIDC flow.

## 3. Decisions

**D1 — the content travels by URL, in the RCS `fthttp` format.** MSRP has
no implementation in Linphone's chat, a private format would need a gateway
that speaks `fthttp` anyway. The kelixip side of DESIGN-CHAT.md's open
question is closed by this document.

**D2 — the file store reproduces the reference contract, byte for byte where
the client is strict.** Same three-request upload, same XML, same 204/200/400
codes, same `File` field, same digest challenge shape. Linphone works with
provisioning alone, and the PHP server can be run as an **oracle** to diff
against (§10).

**D3 — the file store is a service of its own, in Elixir, on `web1` behind
Apache. Not a kelixip module.** Three reasons, the first decisive:

- *exposure*: an upload endpoint reachable by every subscriber from the
  Internet does not belong on the SIP node. kelescope is kept off the node
  for the same reason;
- *scale-out*: the node design is "independent nodes coordinated through
  the database" (DESIGN-CHAT.md, *Horizontal scale*). A file written on node
  A is unreachable from node B unless the URL pins node A, which turns a
  node outage into lost attachments. One store, one URL, settles it;
- *disk and TLS*: `web1` already has both, a public certificate and Apache.

The cost is one more release to operate. It is the same shape as kelescope:
an OTP release under `/opt`, a systemd unit, an RPM.

**D4 — Apache terminates TLS, proxies the API, and serves downloads
statically. The Elixir service does the digest itself.** Apache *could* do
the digest (`mod_auth_digest` + `mod_authn_dbd` against the subscriber base,
HA1 in the table) and the service would never see a secret. It was weighed
and not chosen: `AuthName` fixes one realm per `Location`, so a multi-domain
node needs one `Location` per domain; `mod_auth_digest` speaks MD5 only;
CORS preflights (`OPTIONS`) would be challenged unless carved out; and a
Bearer path for the web client would need a second URL. Doing the digest in
the service keeps one URL, both algorithms, a realm per `From` as the
reference does, and a Bearer alternative on the same route. The service
reads the subscriber base **read-only**, as `auth_db` does.

**D5 — downloads are capability URLs, unauthenticated, served by Apache.**
It is what Linphone expects by default and what makes the download cost the
service nothing. The name carries 160 bits of randomness, the directory is
not listable, and the file disappears at `until`. The authenticated proxy
(`/download?target=`) is provided for clients provisioned with
`file_transfer_server_get_proxy`; it is not the default.

**D6 — metadata in SQLite next to the files; the files on local disk.**
Files are local, so redundancy is a question of the host, not of a shared
database; metadata that lives on the same disk as the files cannot drift
from them. The SQL engine the Silo uses stays the Silo's. If the store ever
has to be redundant, the move is to object storage plus the shared RDBMS,
and the schema of §6.4 is small enough to migrate.

**D7 — `cpim_in_basic_chat_rooms_enabled=1` is part of the provisioning of
every Linphone account on a kelixip domain.** Without it, IMDN message-ids
are Call-IDs, and the relay draws a new Call-ID per leg (chat-basic-plan,
C3): **no receipt would ever match**. Carrying the inbound Call-ID to the
outbound legs was considered and rejected: it breaks one-transaction-per-leg
and the multi-device fan-out. With CPIM, the id is in the body and survives
the relay.

**D8 — the store's retention is at least the Silo's `max_retention`.** A
MESSAGE delivered from the Silo three days later must still point to a
file. The store does not know the Silo; the operator sets the two numbers,
and the store's `kelictl`-like `show` prints the retention so the mismatch
is visible.

## 4. Architecture

```
                  HTTPS :443                                 SIP (UDP/TCP/TLS/WSS)
  Linphone ───────────────────────┐                     ┌──────────────── kelixip node(s)
  web client ─────────────────────┤                     │                    │ relay (SBB.Page)
                                  ▼                     │                    │ Silo (SQL)
                     ┌─────────────────────────┐        │                    ▼
                     │ Apache on web1          │        │              subscriber base
                     │  /files/hft     ──proxy──┼──► Elixir file store :4010   ▲  (MySQL/PostgreSQL)
                     │  /files/download ──proxy─┼──►   ├ Plug.Router           │  read-only: HA1
                     │  /files/tmp/*  (static) │        │  ├ Auth (digest/bearer)──┘
                     │  CORS headers, mTLS opt.│        │  ├ Upload → disk + SQLite
                     └─────────────────────────┘        │  └ Sweeper (purge at `until`)
                                   ▲                    │
                                   └── reads /var/lib/<store>/tmp/ ──┘
```

Nothing connects the store to the node. The link between a MESSAGE and a
file exists only in the clients. If "was this file delivered?" is ever
asked, it is answered by crossing the store's table with the node's journal,
not by coupling them.

## 5. The HTTP contract (normative)

Base path: whatever is provisioned as `file_transfer_server_url`, here
`https://files.example.com/files/hft`.

### 5.1 `POST /files/hft` — upload

**Empty body** (`Content-Length: 0`, or no body):

- `upload_auth = "none"` → `204 No Content`;
- `upload_auth = "digest"` and no valid `Authorization` → `401` with two
  `WWW-Authenticate` headers, MD5 first then SHA-256:

  ```http
  WWW-Authenticate: Digest realm="example.com", qop="auth", algorithm=MD5, nonce="<n>", opaque="<md5(realm)>"
  WWW-Authenticate: Digest realm="example.com", qop="auth", algorithm=SHA-256, nonce="<n>", opaque="<md5(realm)>"
  ```

  `realm` is the domain of the HTTP `From` header (angle brackets, display
  name and parameters stripped), **refused with 400 when it is not a
  configured domain**. The nonce is `HMAC-SHA256(key, floor(now / window))`
  encoded in hex; the current and previous windows are valid; `window` is
  10 s by default. No nonce state is kept;
- valid `Authorization` → `204`.

**Multipart body** (`Content-Type: multipart/form-data`):

- same authentication check; the `username` of the digest must equal the
  user of the `From`;
- `Content-Length` above `max_size` → `400` **before** reading the body;
  Apache's `LimitRequestBody` is set to the same value as a second guard;
- the part named `File` is required; its `filename` is percent-decoded
  and reduced to its basename; its `Content-Type`, parameters included, is
  kept verbatim; absent → `application/octet-stream`;
- the file is written under a new name (§6.3), the metadata row inserted,
  and the answer is `200` with the XML of §2.2, `until` in UTC
  `YYYY-MM-DDTHH:MM:SSZ`, `content-type` echoed **with its parameters**;
- per-AOR quota exceeded → `400` (the one code the client reads as "too
  large");
- disk or database failure → `500`.

`Authorization: Bearer <token>` is accepted on both requests without having
been challenged (§8.3). It is never offered in the 401, so belle-sip is not
tempted to use a mode it has no token for.

### 5.2 `GET /files/tmp/<name>` — direct download

Served by Apache from the store's directory. `Content-Type` from the
extension, `Content-Length`, `Options -Indexes`,
`Access-Control-Allow-Origin` for the web client's origin(s),
`Access-Control-Expose-Headers: Content-Length, Content-Disposition`. A
purged file is a 404. No authentication.

### 5.3 `GET /files/download?target=<url>` — authenticated download

Same authentication as the upload. `target` must start with the store's own
public URL, else `404`. The file is located by the basename of `target`.
Headers as the reference: `Content-Type: application/octet-stream`,
`Content-Disposition: attachment; filename="<original name>"`,
`Content-Length`. The row's `content_type` is used instead of
`application/octet-stream` when present: the client does not read it, and a
browser does.

### 5.4 `OPTIONS` on any route

Answered `204` with the CORS headers, never challenged.

### 5.5 Errors the client sees

| Situation | Code | Why this one |
|---|---|---|
| realm not a configured domain, missing `File`, too large, over quota | 400 | the only failure code the client renders ("file too large") |
| bad credentials, after the second try | 401 | "credentials rejected", no retry |
| disk / database | 500 | "unhandled", the client gives up |

## 6. The file store service

Working name in this document: **the store**. The repository, release and
package names are chosen when it is started; `kelifile` is proposed.

### 6.1 Stack

Elixir, `Plug` + `Bandit` (both already dependencies of `apps/kelixip`, same
versions), `exqlite` for the metadata, `MyXQL` **or** `Postgrex` for the
subscriber base, `jason` for the control output. **No Phoenix**: there is no
page to render. **No dependency on `elixip2` or `kelixip`**: the digest
computation is three functions (HA1, HA2, response) and is copied, not
imported, so the store ships without the SIP stack. The copy is the
accepted duplication; the SIP side (`SIP.Auth`) is the reference when the
two disagree.

The code lives in **a repository of its own**, like kelescope (ruled
2026-10-02). A fifth umbrella app was the alternative: one CI and the
packaging already there, at the price of one more manifest in the version
rule of CLAUDE.md and a release built from a tree that also holds the SIP
stack. The separate repository keeps the store's exposure, versioning and
release cycle independent of the node's, which is what D3 asks for. It
carries its own `packaging/` in the shape of this repository's.

### 6.2 Components

| Process / module | Role |
|---|---|
| `Store.Endpoint` | starts Bandit on `addr:port`, plain HTTP: TLS is Apache's. Refuses to start if `dir` is not writable or the SQLite schema is missing |
| `Store.Router` (`Plug.Router`) | the four routes of §5, CORS, request logging **without file names** |
| `Store.Auth` (Plug) | parses `From`; digest challenge and verification; Bearer verification; attaches `{user, domain}` to the conn |
| `Store.Credentials` | `ha1(user, realm)` from the subscriber base, read-only pool, configurable query like `auth_db`'s |
| `Store.Upload` | streams the `File` part to a temp file in `dir`, renames into `tmp/`, inserts the row, renders the XML |
| `Store.Meta` | the SQLite schema and queries: insert, by name, quota per `(domain, aor)`, expired |
| `Store.Sweeper` | every `sweep_interval`, deletes expired rows and their files; counts |
| `Store.Control` | `show`, `list <domain>`, `purge <domain|aor>` over a Unix socket or a loopback HTTP route with a token, in the shape of `kelictl` |

### 6.3 File naming and layout

```
<dir>/
├── tmp/            # served by Apache at /files/tmp/
│   └── <32 hex of 16 random bytes>_<unix seconds>.<ext>
├── incoming/       # uploads in progress, renamed into tmp/ when complete
└── meta.sqlite3
```

The extension is the original's, lower-cased, limited to `[a-z0-9]{1,8}`,
and replaced by `bin` when it is on the server-side blacklist
(`html htm php phtml jsp asp aspx cgi pl py sh exe js svg`), as the reference
does with `txt`. `svg` is added: it executes script in a browser. The
timestamp in the name is for the operator reading a directory, not for the
client.

### 6.4 Metadata

```sql
CREATE TABLE files (
  name          TEXT PRIMARY KEY,   -- the file name under tmp/
  domain        TEXT NOT NULL,
  aor           TEXT NOT NULL,      -- user@domain of the uploader
  orig_name     TEXT NOT NULL,
  content_type  TEXT NOT NULL,      -- with parameters
  size          INTEGER NOT NULL,
  uploaded_at   INTEGER NOT NULL,   -- unix seconds
  until         INTEGER NOT NULL,   -- unix seconds
  user_agent    TEXT
);
CREATE INDEX files_until ON files(until);
CREATE INDEX files_aor   ON files(domain, aor);
CREATE TABLE schema (version INTEGER NOT NULL);
```

The store owns this schema and creates it at first start. The quota query
is `SUM(size)` and `COUNT(*)` per `(domain, aor)` over non-expired rows.

### 6.5 Configuration

```toml
[server]
addr           = "127.0.0.1"        # behind Apache: loopback
port           = 4010
public_url     = "https://files.example.com/files"   # prefix of every URL handed out
dir            = "/var/lib/kelifile"

[limits]
max_size_mb    = 64
retention      = "7d"               # ≥ the Silo's max_retention
sweep_interval = "10m"
quota_files    = 200                # per AOR, live files
quota_mb       = 500                # per AOR, live bytes

[auth]
upload         = "digest"           # "digest" | "none"
domains        = ["example.com"]    # accepted realms
nonce_key      = "…"                # ≥ 32 random bytes, hex
nonce_window   = 10
bearer         = "hmac"             # "none" | "hmac"; see §8.3
bearer_key     = "…"

[credentials]                       # the subscriber base, read-only
driver   = "mysql"                  # "mysql" | "postgres"
host     = "db.example.com"
database = "kelixip"
username = "kelifile_ro"
password = "…"
query    = "SELECT ha1 FROM subscriber WHERE username = ? AND domain = ?"

[control]
socket   = "/run/kelifile/control.sock"
```

`public_url` is what the client receives: it names Apache, not the service.
`[credentials]` mirrors `[module.auth_db]`'s shape so an operator who
configured one can configure the other.

### 6.6 What is logged, and what is not

The request line, the code, the size, the domain and the AOR, the
`User-Agent`. **Never the original file name, never the URL handed out.**
The URL is a capability: a log line that holds it is a copy of the key. The
same rule the node applies to message bodies (chat-basic-plan, C1b).

### 6.7 Metrics

`files_uploaded_total{domain}`, `files_bytes_live{domain}`,
`files_purged_total{domain}`, `upload_rejected_total{domain, reason}`,
`auth_failures_total{domain}`, exposed on the loopback like the node's
`[metrics]`.

## 7. Apache on `web1`

A sketch of the vhost, to be adapted to the existing one:

```apache
<VirtualHost *:443>
    ServerName files.example.com
    SSLEngine on
    # existing certificate lines

    # Optional: TLS client certificates, as the reference server accepts.
    # SSLVerifyClient optional
    # SSLOptions +StdEnvVars            # exposes SSL_CLIENT_VERIFY to the proxy
    # RequestHeader set X-SSL-Client-Verify "%{SSL_CLIENT_VERIFY}s"

    LimitRequestBody 67108864            # = [limits].max_size_mb

    ProxyPreserveHost On
    ProxyPass        /files/hft      http://127.0.0.1:4010/files/hft
    ProxyPassReverse /files/hft      http://127.0.0.1:4010/files/hft
    ProxyPass        /files/download http://127.0.0.1:4010/files/download
    ProxyPassReverse /files/download http://127.0.0.1:4010/files/download
    RequestHeader set X-Forwarded-Proto "https"

    Alias /files/tmp /var/lib/kelifile/tmp
    <Directory /var/lib/kelifile/tmp>
        Options -Indexes -ExecCGI
        Require all granted
        Header set Access-Control-Allow-Origin "https://app.example.com"
        Header set Access-Control-Expose-Headers "Content-Length, Content-Disposition"
        Header set X-Content-Type-Options "nosniff"
        Header set Content-Disposition "attachment"
    </Directory>
</VirtualHost>
```

Two traps:

- `ProxyPreserveHost On` and `X-Forwarded-Proto` are what let the service
  build nothing from the request: it uses `public_url`, so neither matters
  to the URLs, but they keep the logs honest;
- the `Alias` directory must be readable by Apache and writable by the
  service only; the service's `incoming/` must **not** be under the alias.

When the TLS client certificate option is used, the service trusts
`X-SSL-Client-Verify: SUCCESS` only from the loopback.

## 8. The kelixip side

### 8.1 The relay and the Silo: nothing new

`SIP.MsgTemplate.page_request/2` keeps the `Content-Type` and the body, a
multipart whole with its boundary (`SIPMsgTemplate.ex:97-102`), and the
Silo stores the body verbatim. `Content-Encoding` is undone at parsing and
the body leaves in clear with an unchanged `Content-Type`. `Priority` and
`Expires: 0` of IMDN and `isComposing` are outside `@page_headers`;
`Priority` is harmless, `Expires: 0` is already read as zero retention and
`:is_composing` is never stored. An IMDN for an absent recipient **is**
stored, which is wanted. To be confirmed with one capture of each body
through the relay and through a flush (§10).

### 8.2 Provisioning the Linphone accounts

Pushed by remote provisioning (an XML rc file) or written in `linphonerc`:

```ini
[misc]
file_transfer_server_url=https://files.example.com/files/hft
file_transfer_server_get_proxy=https://files.example.com/files/download   ; optional

[proxy_0]
cpim_in_basic_chat_rooms_enabled=1
```

The first line is what makes attachments possible at all; the third is D7.
The desktop has no UI for either.

### 8.3 The web client's token

A web client cannot do HTTP digest with `fetch` without computing MD5 or
SHA-256 by hand (§9.1). The store therefore accepts
`Authorization: Bearer <token>` where the token is an HMAC-signed
`<user>@<domain>:<expiry>`, minted by **kelixip** on request of an
authenticated client and verified by the store with the shared `bearer_key`.
Minting is a one-line addition to the REST control API's shape, on a route
for subscribers, not for admins; it is not designed here beyond that. Until
it exists, the web client does the digest.

## 9. A compatible web client

The client speaks SIP over WebSocket to kelixip (SIP.js or JsSIP) and HTTPS
to the store.

### 9.1 Sending a photo

1. Take the MIME type from `File.type`, the extension as a fallback.
2. Empty `POST` to the upload URL with `From: sip:<user>@<domain>` and
   `credentials: 'omit'`, `mode: 'cors'`: a cross-origin 401 does not raise
   the browser's native login dialog, and `WWW-Authenticate` is readable
   because the store exposes it.
3. On 401, compute the digest: `HA1 = H(user:realm:password)`,
   `HA2 = H(POST:<path>)`, `response = H(HA1:nonce:nc:cnonce:auth:HA2)`.
   Prefer the `SHA-256` challenge, which WebCrypto computes; MD5 needs a
   library. Replay the empty POST with
   `Authorization: Digest username="…", realm="…", nonce="…", uri="<path>", qop=auth, nc=00000001, cnonce="…", response="…", opaque="…", algorithm=SHA-256`.
   With a Bearer token (§8.3), send it on the first request instead.
4. On 204, `POST` a `FormData` with one field `File`. For a voice message,
   wrap the blob as `new File([blob], name, {type: "audio/wav;voice-recording=yes"})`
   so the parameter is on the part. Repeat the `Authorization` with `nc`
   incremented.
5. Read `data@url`, `data@until`, `file-size` from the 200.
6. Build the XML of §2.2, CRLF included, percent-escaped name, local
   content type with parameters, and `<am:playing-length>` in milliseconds
   with `xmlns:am` declared for a voice message.
7. Send an out-of-dialog MESSAGE to `sip:<recipient>@<domain>`,
   `Content-Type: application/vnd.gsma.rcs-ft-http+xml`, a `Date` header.
   200 or 202 (kelixip, recipient offline) is acceptance.
8. Text with the photo: a `multipart/mixed` with the XML part then
   `text/plain; charset=UTF-8`. Linphone shows both (§2.4). Do not expect
   the reverse.

### 9.2 Sending a voice message

1. Record with `MediaRecorder` as `audio/webm; codecs=opus`. WebM is a
   Matroska subset with the same `1A 45 DF A3` signature, and Linphone's
   player opens by signature. **Whether mediastreamer2's MKV reader accepts
   a browser-produced WebM is untested** (§12). If it fails, encode WAV PCM
   16-bit mono 16 kHz in the client, which Linphone reads for certain.
2. Name it `vocal_<timestamp>.mka` or `.wav` to match the container.
3. Measure the duration in milliseconds.
4. Upload and send as §9.1 with type `audio/wav;voice-recording=yes` and
   `<am:playing-length>`.
5. While recording, send `isComposing` `active` with
   `<contenttype>audio/wav;voice-recording=yes</contenttype>`.

### 9.3 Receiving

1. Accept the types of §2.6 plus `message/cpim` and `multipart/mixed`;
   answer 200; answer 415 to anything else.
2. Unwrap CPIM, then multipart, then each part.
3. For `application/vnd.gsma.rcs-ft-http+xml`: read only
   `file-info[@type="file"]`; a past `until` is "expired", shown without a
   GET. For `message/external-body`, read `URL=` and treat it as
   `application/binary`.
4. `GET` the URL with `credentials: 'omit'`. Use the XML's content type, not
   the HTTP one, and for audio **sniff the first four bytes** before choosing
   a decoder: a Linphone voice message is Matroska/Opus. `<audio>` plays an
   `.mka` Opus in Chromium; Firefox is to be verified (§12).
5. A voice message is a file whose `content-type` is strictly
   `audio/wav;voice-recording=yes`; show `playing-length` as milliseconds.
6. Send the `delivered` IMDN on receipt and `displayed` when the
   conversation is opened.

### 9.4 IMDN and isComposing

- IMDN: a MESSAGE `message/imdn+xml`, `Priority: non-urgent`, to the
  received `From` URI without parameters, body as §2.5. `message-id` is the
  CPIM `imdn.Message-ID` when there was one, else the Call-ID of the
  received MESSAGE. Match incoming IMDNs by the same rule; ignore, without
  error, those whose id is unknown (a Linphone without D7 sends the Call-ID
  of its own leg).
- When emitting CPIM, put the SIP `From` URI in the CPIM `From` and request
  `positive-delivery, negative-delivery, display`.
- isComposing: §2.6; `active` every 60 s while typing, `idle` with no
  `contenttype` nor `refresh` after 15 s of silence; consider the peer idle
  after its announced `refresh`, 120 s by default. kelixip answers 480 to an
  `isComposing` for an absent recipient; it is not an error.

## 10. Verification plan

1. **The oracle.** Install the reference PHP server on `web1` under
   `/files-ref/`, pointed at the subscriber base, and provision a Linphone
   desktop against it. One photo and one voice message, both directions,
   captured: this is the trace the store is diffed against. It also proves
   the provisioning path before any Elixir is written.
2. **Unit, in the store.** The digest against the three algorithms the
   subscriber base may hold; the nonce window boundary; the realm from a
   `From` with display name, brackets and `;gr=`; the 400-before-body on
   `Content-Length`; the XML with a parameterised content type; the sweeper
   on a file whose row is gone and a row whose file is gone.
3. **elixipp.** A UAC scenario that uploads through `Req` (already a
   dependency of `elixip2`), builds the XML, pages it, and a UAS scenario
   that parses it and downloads; the `:live` tag, since it needs the store.
4. **End to end with Linphone.** The same two messages as step 1 against the
   store; the desktop must show the photo, play the voice message with its
   duration, and the capture must be identical to the oracle's at the HTTP
   level except for the names.
5. **Through the relay and the Silo.** One `rcs-ft-http` and one
   `message/cpim` message to an offline recipient, delivered by a flush after
   a REGISTER: the body is byte-identical, the file still downloads.
6. **The web client.** Steps 9.1 to 9.4 against a Linphone desktop, both
   directions, including "photo + caption" from the web and the loss of the
   caption from Linphone, documented as such.

## 11. Security

- **The URL is the key.** 128 bits of randomness in the name, no directory
  listing, never logged, gone at `until`. Anyone with the URL has the file
  until then; that is the model Linphone works with, and the authenticated
  proxy exists for operators who want more.
- **Upload needs a subscriber.** The digest is the SIP one; a stolen SIP
  password already gives the attacker a phone, the store adds a disk, bounded
  by the quota.
- **Realm is validated.** A `From` naming an unknown domain is a 400, so the
  store never queries the subscriber base for a realm it does not serve.
- **The service sees HA1, read-only, under its own account**, as `auth_db`
  does; the alternative (digest in Apache) is in D4 for when that is not
  acceptable.
- **Browsers are a target of the store, not only a client.** `nosniff`,
  `Content-Disposition: attachment`, and the extension blacklist including
  `svg` and `html` keep a stored file from executing in the origin of the
  store.
- **No file content is inspected.** The store is not a scanner; a hook for
  one is a later addition at the rename step.

## 12. Not verified

- The reference PHP server was read **through an automatic summary of its
  GitHub source**, not a local checkout: constant names and the nonce
  format are from that summary. Its purge mechanism was not seen.
- The exact shape of the HTTP `From` header value (brackets, display name,
  `;gr=`) was not observed on the wire; the parser is tolerant on purpose.
- mediastreamer2's MKV reader on a browser WebM/Opus; `.mka` Opus playback
  in Firefox.
- The relay and the Silo on an `rcs-ft-http` and a `message/cpim` body: read
  in the code, not captured.
- The unit of `playing-length` on Linphone **mobile**; the SDK writes
  milliseconds and the desktop reads them as such.

## 13. Invariants

1. **The SIP relay never rewrites a chat body.** Not the XML, not the URL,
   not the boundary. A node that "fixes" an attachment is a node that breaks
   it for one of the two clients.
2. **The store hands out its URL from `public_url`, never from the request.**
   A `Host` header is attacker-controlled; a URL built from it is a capability
   handed to the wrong host.
3. **The content type is echoed with its parameters.** `voice-recording=yes`
   is the only thing that makes a voice message a voice message.
4. **The realm is a configured domain or the request is refused before any
   database access.**
5. **The store's retention is never below the Silo's `max_retention`.**
6. **Neither the original file name nor the URL ever reaches a log.**

## 14. References

| Reference | For |
|---|---|
| GSMA RCC.07 (RCS Universal Profile) §3.5.4.8 | HTTP file transfer, the `fthttp` XML |
| GSMA RCC.07, namespace `rcs:rram` | `playing-length` of an audio message |
| RFC 3428 | MESSAGE |
| RFC 3862 | CPIM |
| RFC 5438 | IMDN |
| RFC 3994 | isComposing |
| RFC 7616 | HTTP digest: the same computation as RFC 3261 §22 |
| RFC 7578 | `multipart/form-data` |
| [DESIGN-CHAT.md](DESIGN-CHAT.md), [chat-basic-plan.md](chat-basic-plan.md) | the chat function, the relay, the Silo |
| [DESIGN-AUTH.md](DESIGN-AUTH.md) | the realm and identity rules the store's digest follows |
| `BelledonneCommunications/flexisip-http-file-transfer-server` on GitHub | the reference server |
