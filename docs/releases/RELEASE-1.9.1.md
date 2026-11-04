# Release 1.9.1

2026-11-04 — since 1.9.0 (2026-11-01). Theme: the correction of a captioned call
without per-domain configuration, and a backup speech-server.

## Captioned calls: the correction

### No more per-domain tables

A node that loads the `captioning` module offers the correction to every call of
`call-captioning.exs`. The `[[module.captioning.domain]]` tables are gone.

```toml
[module.captioning]
control_url = "http://127.0.0.1:9200"
public_url  = "wss://sip.example.net:9201"
```

- **A `config.toml` that still has a `[[module.captioning.domain]]` table is
  refused**: `unknown key(s): domain`, and the module does not start. Remove the
  table before the upgrade.
- **The `403 Forbidden` answer is gone.** `comp="true"` gets a token, or a `503`
  with `Retry-After` when the bounds are reached or the speech-server does not
  give one.

### The account and the language belong to the script

The script passes them to `answer/2`. Both are empty by default.

```elixir
Kelix.ModuleRegistry.facade("captioning", :answer, [req, []], @captions_only)
Kelix.ModuleRegistry.facade("captioning", :answer, [req, [account: "acme", lang: "fr"]], @captions_only)
```

| Option | Effect | Absent |
|---|---|---|
| `account:` | The label the speech-server bills the token to | The token request carries none |
| `lang:` | Added to the URL: `…/streaming/comp/<token>?lang=fr` | The client chooses |

- An invalid `account` or `lang` answers `500 Server Internal Error`, and the
  log names the option.
- A string in place of the options is the `account`. A script written for 1.9.0,
  `answer(req, "visioassistance.net")`, keeps working: that domain becomes the
  `account`.

### Backup speech-server

```toml
[module.captioning]
control_url        = "http://10.0.0.12:9200"
public_url         = "wss://speech.example.net:9201"
backup_control_url = "http://10.0.0.13:9200"
backup_public_url  = "wss://speech2.example.net:9201"
```

- The backup server is asked when the main one is unreachable, slower than
  `timeout_ms`, answers a `5xx` or an invalid response.
- After a `4xx` refusal, the backup server is not asked: the request itself is
  at fault.
- The URL handed to the client is the `public_url` of the server that gave the
  token. A token is only valid on that server.
- The two keys go together. With both servers down, the answer takes up to
  twice `timeout_ms`.
- `kelictl captioning status` shows both servers.
- Each speech-server must have this node in its `control.allow`.

### `call-captioning.exs`: authentication on the served domain

The reference script challenges the caller on the domain the call is served on.
`@realm` imposes another realm:

```elixir
@realm nil                       # the domain the call is served on
@realm "visioassistance.net"     # this realm, whatever the domain
```

It passes no `account` and no `lang`.

## Digest: the SHA-256 spelling of RFC 8760

A challenge naming `algorithm=SHA-256`, the spelling RFC 8760 defines, is
answered. It used to raise: only `SHA256` was known. Both spellings are read, in
any case. The challenges kelixip sends name `SHA-256`.

## Upgrading

1. Remove any `[[module.captioning.domain]]` table from `/etc/kelixip/config.toml`.
2. `dnf upgrade kelixip kelixip-mod-*`. Modules come from the same build: upgrade
   them together.
3. The scenario scripts are `%config(noreplace)`. A `call-captioning.exs` edited
   on the node is kept, and the 1.9.1 version lands next to it as
   `call-captioning.exs.rpmnew`. Carry your edits over to it, or keep yours: it
   still works, with its `@realm` as the `account` and as the realm.
4. `systemctl restart kelixip`.

elixipp 1.9.1-1 carries the SHA-256 spelling. Nothing else changes for it.
