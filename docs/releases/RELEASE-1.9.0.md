# Release 1.9.0

2026-10-26 — since 1.8.2 (2026-10-24). Theme: the correction of the text typed
during a captioned call.

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
