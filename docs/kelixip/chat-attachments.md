# Chat attachments

Photos, voice messages and other files sent in chat travel the way Linphone
sends them: the file goes to an HTTP **file store**, and the SIP MESSAGE
carries an RCS XML naming it (`application/vnd.gsma.rcs-ft-http+xml`, GSMA
RCC.07 §3.5.4.8). kelixip relays and stores that MESSAGE like any other: the
file itself never crosses the SIP node.

> **Draft.** The keys and values below are read in the Linphone and reference
> server code (design §2, §8.2). They are confirmed on a real exchange by
> [chat-media-plan S0](../design/chat-media-plan.md); until then, treat this page
> as the expected configuration, not a verified one.

The design is [DESIGN-CHAT-MEDIA.md](../design/DESIGN-CHAT-MEDIA.md); the store's
installation files are in [`packaging/fhft/`](../../packaging/fhft/README.md).

## The file store

The reference store is `flexisip-http-file-transfer-server`, PHP behind Apache,
with the PDO patch of `packaging/fhft/` so that it authenticates against a
PostgreSQL subscriber base. It is served under its own name, so that the URL
clients are given survives the store moving:

| | |
|---|---|
| Upload URL (what clients are provisioned with) | `https://files.weshwesh.eu/files/hft.php` |
| Files | `https://files.weshwesh.eu/files/tmp/<random name>`, static, no authentication |
| Authentication of uploads | HTTP digest with the **SIP credentials**, realm = SIP domain |
| Retention | 7 days, the Silo's `max_retention` (a file must outlive the MESSAGE naming it) |

A file's URL is its capability: anyone who has the MESSAGE can fetch the file
until it expires. Listing the directory is refused.

## Provisioning a Linphone account

Linphone sends attachments only once it knows the store, and matches delivery
receipts only once CPIM is enabled for the account. Neither has a field in the
desktop's interface: both come from remote provisioning (an XML rc file) or
from `linphonerc`.

```ini
[misc]
file_transfer_server_url=https://files.weshwesh.eu/files/hft.php

[proxy_0]
cpim_in_basic_chat_rooms_enabled=1
```

| Key | Section | Without it |
|---|---|---|
| `file_transfer_server_url` | `[misc]` | nothing is sent: "no file remote URI configured" |
| `cpim_in_basic_chat_rooms_enabled` | the account's `[proxy_N]` | files and texts work, but no delivery or read receipt is ever matched |

`file_transfer_server_get_proxy` is not set: files are served statically, and
the authenticated download it points at is not offered.

- **Desktop**: the keys go in `linphonerc` (`~/.config/linphone/linphonerc` on
  Linux), the application closed, or in the provisioning file it is pointed at.
- **Mobile**: by remote provisioning only, the same keys in the XML rc file.

`[proxy_N]` is the account's own section: on a device with several accounts,
`cpim_in_basic_chat_rooms_enabled` is set in each one that chats through kelixip.

### What a Linphone user sees

- A photo with a caption arrives with its caption; Linphone never **sends** one —
  a photo and a text it sends are two messages.
- A voice message is recorded in Matroska/Opus and labelled
  `audio/wav;voice-recording=yes`; Linphone recognises it by that type.
- Without CPIM, the receipts Linphone sends name the Call-ID of the relayed leg,
  which matches nothing on the sender's side: messages stay "delivered to the
  server".

## Provisioning Trix

Trix reads the store URL from the account's **File server** field, or from
`config.json` for every account of a deployment:

```json
{ "file_transfer_server": "https://files.weshwesh.eu/files/hft.php" }
```

Trix sends CPIM to everyone and falls back to plain text on a 415: it needs no
receipt setting. It uploads with the HA1s it keeps, so no password is involved.
The store's CORS headers name Trix's origin (`https://trix.weshwesh.eu`).

## What kelixip does with these messages

Nothing specific. The relay (`SBB.Page`) and the Silo carry the MESSAGE as they
carry a text, CPIM envelope and multipart included, byte for byte. A MESSAGE
that would pass 1300 octets towards a UDP-registered device leaves with its body
deflated (`Content-Encoding: deflate`), and once more in clear after a 415 that
refuses the coding. Typing indicators are relayed and never stored.
