# captioning

This module serves the correction of a captioned call. During a call placed by
the `call-captioning.exs` script, the caller's client sends an INFO of type
`application/captioning+xml`; the module answers it and, when the client asks
for the correction of the text it types, hands it the URL of a correction
stream on the speech-server (function `comp`), carrying a single-use token.

The captions themselves do not depend on this module: the script starts the
transcription with the call. Without the module, the INFO is answered with the
captions alone.

A node that loads the module offers the correction to every call of the script.

## Installing and activating the module

### Installing the `kelixip-mod-captioning` package

`dnf install kelixip-mod-captioning` / `apt install kelixip-mod-captioning`

### Declaring the module in config.toml

```toml
# config.toml
[module.captioning]
control_url = "http://10.0.0.12:9200"
public_url  = "wss://speech.example.net:9201"
```

With a backup speech-server:

```toml
[module.captioning]
control_url        = "http://10.0.0.12:9200"
public_url         = "wss://speech.example.net:9201"
backup_control_url = "http://10.0.0.13:9200"
backup_public_url  = "wss://speech2.example.net:9201"
```

Each speech-server must accept this node on its control API: its address goes
in the speech-server's `control.allow`.

## Parameters

| Key | Type | Default | Description |
|---|---|---|---|
| `control_url` | string | **required** | Base URL of the speech-server's control API, `http://` or `https://` |
| `public_url` | string | **required** | Base URL of the correction stream as a browser reaches it, `wss://` only |
| `backup_control_url` | string | none | Control API of the backup speech-server. Goes with `backup_public_url` |
| `backup_public_url` | string | none | Correction stream of the backup speech-server, `wss://` only. Goes with `backup_control_url` |
| `ttl` | integer | `60` | Lifetime of a token, in seconds (1 to 3600) |
| `timeout_ms` | integer | `2000` | Bound on a token request to one server, connection included (ms) |
| `max_per_call` | integer | `5` | Tokens a call may renew after its first one |
| `min_interval` | integer | `10` | Seconds between two tokens of a call |
| `retry_after` | integer | `30` | `Retry-After` of a `503`, in seconds |
| `call_timeout_ms` | integer | `5000` | Upper bound on a facade call (ms) |

A configuration error names the key at fault, and the module does not start.

## The backup speech-server

The token is asked of the main server first. The backup server is asked when the
main one is unreachable, slower than `timeout_ms`, answers a `5xx` or an invalid
response. A `4xx` refusal is not retried on the backup server.

A token is only valid on the server that minted it: the URL in the answer carries
the `public_url` of that server.

With both servers down, the answer takes up to twice `timeout_ms`.

## The INFO and its answers

The request body:

```xml
<captioning>
  <inbound>
    <stt comp="true"/>
  </inbound>
</captioning>
```

`<stt>` confirms the captions, `comp="true"` asks for the correction. An absent
`comp` is `false`. Unknown elements and attributes are ignored.

| Situation | Answer |
|---|---|
| `comp="false"`, or no `comp` | `200 OK`, `comp="false"`, no `uri` |
| `comp="true"`, token obtained | `200 OK`, `comp="true"` with `uri` |
| Body absent, not XML, or not a `<captioning>` document | `400 Bad Request` |
| `account` or `lang` given by the script is invalid | `500 Server Internal Error` |
| More than `max_per_call` renewals, or a renewal within `min_interval` | `503 Service Unavailable` + `Retry-After` |
| Speech-servers unreachable, slower than `timeout_ms`, or refusing the token | `503 Service Unavailable` + `Retry-After` |
| Module not configured | `200 OK`, `comp="false"`, no `uri` (the script's answer) |

None of these answers affects the call.

The `200 OK` body:

```xml
<captioning>
  <inbound>
    <stt comp="true" uri="wss://speech.example.net:9201/streaming/comp/<token>?lang=fr"/>
  </inbound>
</captioning>
```

The token is never written in clear by kelixip: the logs, `kelictl debug` and
the SIP traces show its first six characters followed by `…`, as the
speech-server logs it.

## Facades

### `answer/2`

```elixir
answer(req, opts) :: {code, reason, upd_fields}
```

The whole answer to the INFO `req`, in the shape `b2bua_reply_on/5` takes.

| Option | Description |
|---|---|
| `account:` | The label the speech-server bills the token to: 1 to 64 characters among `A-Z a-z 0-9 . _ -`. Absent, the token request carries none |
| `lang:` | Language of the correction (`fr`, `en`, `pt-BR`…), added to the URL. Absent, the client chooses it |

A string in place of `opts` is the `account`.

A script calls it through `Kelix.ModuleRegistry.facade/4`, with its own answer
for a node without the module:

```elixir
{code, reason, fields} =
  Kelix.ModuleRegistry.facade("captioning", :answer, [req, [lang: "fr"]], @captions_only)

b2bua_reply_on(leg, req, code, reason, fields)
```

### `parse_request/1`

```elixir
parse_request(req) :: {:ok, %{stt: boolean, comp: boolean}} | {:error, :malformed}
```

### `activate/3`

```elixir
activate(call_id, %{comp: boolean}, opts) ::
  {:ok, %{comp: false}}
  | {:ok, %{comp: true, uri: String.t()}}
  | {:error, {:bad_option, :account | :lang, value}}
  | {:error, {:busy, retry_after}}
  | {:error, {:unavailable, reason, retry_after}}
  | {:error, :down | :timeout}
```

`opts` as for `answer/2`. `reason` is `:down`, `:timeout`, `:invalid_response`
or `{:speech, status, message}`, from the last server asked.

### `response_body/1`

```elixir
response_body(%{comp: boolean} | %{comp: true, uri: String.t()}) ::
  %{contenttype: "application/captioning+xml", data: binary}
```

### `release/1`

```elixir
release(call_id | req) :: :ok
```

Forgets the renewals of a call. Called when the call ends.

### `mask/1`

```elixir
mask(text) :: String.t()
```

`text` with every token cut to its first six characters.

## Control commands

### `kelictl captioning status` — `GET /modules/captioning/status`

The effective configuration, the tokens requested, obtained and refused (by
cause), the latency of the token requests (last, max, mean, in ms) and the
number of calls holding a token.

## Metrics

| Metric | Labels | Description |
|---|---|---|
| `kelix_captioning_token_count` | `result` | Token requests by outcome: `obtained`, `busy`, `down`, `timeout`, `invalid_response`, `speech_<status>` |
| `kelix_captioning_token_request_duration_seconds` | | Duration of a token request, backup server included |

## Events

None.
