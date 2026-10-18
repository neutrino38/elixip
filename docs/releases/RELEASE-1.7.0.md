# Release 1.7.0

2026-10-07 — since 1.6.3 (2026-10-06), which it includes. Theme: chat
attachments — photos, voice messages and files sent the way Linphone sends them.

## Chat wth attachments (RCS file transfer over HTTP)

Instant messages with attachement stored in an an HTTP **file store** is now supported.
The SIP MESSAGE has carries an RCS XML payload conformant to GSMA RCC.07. Kelixip relays
it. It is the client's responsibility to upload the attachement.

The file store URI is to be configured in the SIP UA clients.

### The file store

The store is Belledonne's `flexisip-http-file-transfer-server`
modified and  packaged in `packaging/fhft/` as
**`bc-flexisip-http-file-transfer-server`** for AL9 under php-fpm:

- a **PDO patch**, to allow uploads authenticate against the kelixip / kamalio subscriber base
  in PostgreSQL (MySQL keeps working);
- HTTP digest with the **SIP credentials**, realm = SIP domain; files served
  statically, retention 7 days (the Silo's `max_retention`);
- SELinux contexts set at install, CORS for Trix, `X-Powered-By` removed;
- `packaging/fhft/build-rpm.sh` builds it; `packaging/fhft/rehearsal/` runs it
  in containers against PostgreSQL.

The store is a separate package, independent of the kelixip release. See
[packaging/fhft/README.md](../../packaging/fhft/README.md).

## Instant messaging

- **The Silo keeps a multipart MESSAGE whole.** It stored the first part only,
  under the multipart `Content-Type`: a photo with its caption came out of a
  flush truncated and unreadable.
- Use of deflate when **A MESSAGE that would pass 1300 octets on UDP **.
- **The page relay keeps the sender's multipart type.** It re-spelled every
  multipart as `multipart/mixed`; a bare multipart is now relayed byte for byte.

## SIP stack

- **Multipart parts keep their trailing whitespace.** 

## elixipp and the framework

- **`SIP.FileTransfer`**: reads and writes the RCS fthttp XML in Linphone's
  shape, uploads with the digest answered from the SIP credentials, downloads.
- **`SIP.Session.FileTransfer`**, brought in by `SIP.Scenario`:
  `upload_file/4` and `download_file/3` (one tagged event each),
  `send_file_page/3`, `file_info/1`.
- `SIP.Msg.Ops.file_transfer_xml/1` finds the XML bare, in CPIM, or as a part
  of a multipart; `SIPMsg.parse_challenge/1` reads a `WWW-Authenticate` value.
- Example pair **`uac_file_message.exs`** / **`uas_file_message.exs`**: sends a
  file and downloads it on the receiving side, with no node.

## Upgrading

- `dnf upgrade kelixip` from 1.6.3. No configuration change; attachments need
  only the file store and the client provisioning above.
- User-Agent: `Kelixip/1.7.0`, `Elixipp-1.7.0`.
