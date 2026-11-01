# Release 1.9.0

2026-11-01 — since 1.8.2 (2026-10-24). Theme: the correction of the text typed
during a captioned call, and domains edited on a running node.

The correction is served by the speech-server's `comp` function. Its control
API (`POST /control/token`) is that of speech-server **1.18.0** and later
(mediaserver 1.19.1 included).

## Captioned calls: the correction

During a call placed by `call-captioning.exs`, the client sends an INFO of type
`application/captioning+xml` once the call is up:

```xml
<captioning>
  <inbound>
    <stt comp="true"/>
  </inbound>
</captioning>
```

`<stt>` confirms the captions, `comp="true"` asks for the correction of what the
user types. kelixip answers with the URL of a correction stream, carrying a
single-use token:

```xml
<captioning>
  <inbound>
    <stt comp="true" uri="wss://speech.example.net:9201/streaming/comp/<token>?lang=fr"/>
  </inbound>
</captioning>
```

| Situation | Answer |
|---|---|
| `comp="false"`, or no `comp` | `200 OK`, `comp="false"`, no `uri` |
| `comp="true"`, token obtained | `200 OK`, `comp="true"` with `uri` |
| `comp="true"`, domain without the correction | `403 Forbidden` |
| Body absent, not XML, or not a `<captioning>` document | `400 Bad Request` |
| Renewals past the bounds | `503` + `Retry-After` |
| Speech-server unreachable, slow, or refusing the token | `503` + `Retry-After` |
| Module `captioning` not configured | `200 OK`, `comp="false"`, no `uri` |

- **The captions do not depend on the INFO.** The transcription starts with the
  call, as in 1.8; the INFO confirms it and asks for the correction.
- **No answer to the INFO affects the call.** Audio and T.140 continue whatever
  the speech-server does.
- **The captioning INFO is no longer relayed to the trunk.** Any other INFO
  (DTMF, picture update…) still is.
- Only outgoing calls of the captioning client are concerned.

### New module `captioning` (`kelixip-mod-captioning`)

```toml
[module.captioning]
control_url = "http://10.0.0.12:9200"          # control API, admin network
public_url  = "wss://speech.example.net:9201"  # what the browser opens

[[module.captioning.domain]]
name       = "visioassistance.net"
correction = true
lang       = "fr"
```

- **Correction per domain**: a domain must be listed with `correction = true`.
  Its name is the `account` the speech-server bills the token to.
- **Renewals bounded per call**: `max_per_call` renewals after the first token
  (5), at least `min_interval` seconds apart (10). Past that, `503` with
  `Retry-After` (`retry_after`, 30 s).
- **Token requests bounded** by `timeout_ms` (2 s), connection included; a token
  lives `ttl` seconds (60).
- **The token is masked** in the logs, `kelictl debug` and the SIP traces: its
  first six characters followed by `…`, as the speech-server logs it.
- `kelictl captioning status` (`GET /modules/captioning/status`): effective
  configuration, tokens requested, obtained and refused by cause, request
  latency, calls holding a token.
- Metrics: `kelix_captioning_token_count{result}` and
  `kelix_captioning_token_request_duration_seconds`.

Documentation: [captioning.md](../kelixip/modules/captioning.md).

## Framework

- **`bridge/1` takes `intercept:`**, a list of `{leg, method, content_type}`.
  A matching in-dialog request is not relayed: the block returns
  `{:bridge, :request, %{leg, method, req, transaction}}`, the script answers
  it and re-enters with `bridge(resume: true)`. Only the methods of the default
  relay qualify (INFO, MESSAGE, NOTIFY, REFER…); INVITE, UPDATE, ACK and BYE
  are never handed back. Without `intercept:`, nothing changes.

  ```elixir
  bridge(args: %{media: @media, intercept: [{:caller, :INFO, "application/captioning+xml"}]})
  ```

- **`b2bua_reply_on(leg, req, code, reason, fields)`** answers on a leg named
  explicitly, `:caller` or `:callee`.
- **`SIPMsg.register_redactor(type, fun)`**: every trace of a body of that media
  type shows `fun.(body)` instead. Applied by `SIPMsg.readable/1`,
  `SIPMsg.redacted/1` and `SIPMsg.loggable/1`, hence by the journal,
  `kelictl debug` and the transport debug logs.

## Upgrading

- `dnf upgrade kelixip kelixip-mod-*` from 1.8.2, then
  `dnf install kelixip-mod-captioning` on the nodes serving the correction.
  Modules require the core at the same version.
- Add the `[module.captioning]` block to `config.toml`, and this node's address
  to the speech-server's `control.allow`. Without the block, the INFO is
  answered with the captions alone.
- **`call-captioning.exs` is `%config(noreplace)`.** If it was edited on the
  node, the 1.9.0 script lands next to it as `call-captioning.exs.rpmnew`, and
  the edited one still relays the INFO to the trunk: merge the two.
- User-Agent: `Kelixip/1.9.0`, `Elixipp-1.9.0`.

## Package 1.9.0-2: `domains.toml` moves to `/var/lib/kelixip`

The node reads its domains from `/var/lib/kelixip/domains.toml`, owned by the
`kelixip` user. The code is the code of 1.9.0-1. Only the package changes.

- **On upgrade**, the package copies `/etc/kelixip/domains.toml` to
  `/var/lib/kelixip/domains.toml`, comments included. It never overwrites a
  file already there.
- **The old file goes away.** If you had edited it, the RPM keeps it as
  `/etc/kelixip/domains.toml.rpmsave`, the deb as
  `/etc/kelixip/domains.toml.dpkg-bak`. Edit the copy in `/var/lib/kelixip`.
- **`KELIXIP_DOMAINS`** in `/etc/sysconfig/kelixip` (`/etc/default/kelixip`)
  follows when it named `/etc/kelixip/domains.toml`. Another path is kept.
- **A fresh install** starts with a file that holds no domain. The commented
  example is `/usr/share/doc/kelixip/domains.toml.example`.
- **Backups**: whatever saves `/etc/kelixip` must now also save
  `/var/lib/kelixip/domains.toml`.
- On the deb, `apt purge` removes `/var/lib/kelixip`, and the domains with it.

`dnf upgrade kelixip` from 1.9.0-1 installs 1.9.0-2: the `Release` differs, so
it is a new package, not a reinstall.

## Package 1.9.0-3: domains edited on a running node

A domain is created, edited and deleted on the running node, through `kelictl` or
the REST control API. Each command changes one element and takes effect at once: no
reload, no restart. Documentation:
[administration](../kelixip/administration.md#editing-a-domain) and
[REST API](../kelixip/rest-api.md#editing-domains).

```console
$ kelictl domain create example.com aliases=example.fr
domain example.com created (v2)

$ kelictl domain example.com call add default script=direct-call.exs
rule 1 added (v3)

$ kelictl domain example.com call add 0XXXXXXXXX script=direct-call.exs
rule 1 added (v4)
```

- **One command per element**: the domain's `max_calls`, an alias, the registrar
  block, an event package, one rule of the `call`, `chat`, `options` or SUBSCRIBE
  lists, the keepalive OPTIONS script. `kelictl domain help` lists them all.
- **Same check as at boot.** A command whose result `domains.toml` would refuse is
  refused, a script the node cannot serve included, and nothing is applied.
- **Rules are addressed by number**, as `kelictl domain show` prints them. The
  number of a rule changes when a rule is added, moved or removed before it.
  `--version N` (REST: `version`) refuses an edit when the domains changed since
  version N. `domain show` prints the version.
- **`domain delete`** stops every scenario of the domain and purges its
  registrations and presence states. It asks for no confirmation. A `domain
  reload-all` that removes a domain from the file now ends it the same way: its
  calls in progress stop.
- **Every write is logged** with who asked: the Unix user, `--admin NAME`, or the
  REST header `X-Kelix-Admin`.
- **REST**: one route per command under `/domains`. A refusal answers
  `{"error": "<reason>", "message": "…"}` with `400`, `404`, `409`, `500` or `503`.

**The file.** The node writes the domains to `/var/lib/kelixip/domains.toml`.

- **Comments disappear at the first write.** The node writes the file from its data,
  with a generated header. `[module.registrar]` is kept as it is.
- **A hand edit not yet reloaded blocks the writes**, so that a write does not erase
  it. `kelictl status` says so (`EDITED BY HAND`), as does `GET /status`
  (`domains_file_changed`). `kelictl domain reload-all` lifts the block.
- **A file the node cannot write** does not stop the node. It logs a warning at boot,
  `kelictl status` shows `domains file: …, NOT writable`, and every write is refused
  with the path, the reason and the fix.
- **One file per node.** A domain created on one node does not exist on the others.

`kelictl` exit codes: `3` for an unknown domain, alias, package or rule number, `4`
for a name that exists, a stale `--version` or a hand edit, `5` for a file the node
cannot write.

**The distribution cookie.** The package generates the cookie kelictl
authenticates with at installation. It is now made of letters and digits only. A
cookie starting with `+`, about one installation in 64, was read by the Erlang
launcher as an option: the node never started, and kelictl could not reach it. The
upgrade replaces such a cookie and keeps any other.

`dnf upgrade kelixip kelixip-mod-*` from 1.9.0-1 or 1.9.0-2 installs 1.9.0-3. Modules
come from the same build: upgrade them together.
