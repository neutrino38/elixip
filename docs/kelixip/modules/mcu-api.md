# mcu — REST API reference

The complete wire contract of the `mcu` module's REST surface: every endpoint, its
arguments, its payloads, its statuses. It is written to be **sufficient on its own** —
read this page and you can implement a client without reading the Elixir.

* the module itself (config keys, facades, `kelictl`, events) is [mcu.md](mcu.md);
* the core REST frontal (`/status`, `/domains`, auth config) is
  [../rest-api.md](../rest-api.md);
* the *why* of every decision is [../../design/DESIGN-MCU.md](../../design/DESIGN-MCU.md).

> **The running node is authoritative.** `GET /modules/mcu` publishes the same
> declaration this page describes — command names, methods, path templates, arguments,
> success status and per-reason error statuses (§8). A client that builds its URLs from
> that endpoint cannot drift from the server it talks to. Use this page to understand
> the surface; use the node to bind to it.

Every payload below was captured from the real frontal driving the real module, not
written by hand.

---

## 1. Transport, authentication, envelope

| | |
|---|---|
| Base URL | `http(s)://<addr>:<port>` from `[control_api]` in `config.toml` — default `127.0.0.1:8090` |
| Prefix | every endpoint on this page is under `/modules/mcu` |
| Auth | `Authorization: Bearer <token>` when `[control_api] auth = "token"` (the default); client certificate when `auth = "mtls"`; nothing when `auth = "none"` |
| Request body | `Content-Type: application/json`, on `POST` / `PUT` / `PATCH` / **`DELETE`** |
| Response body | `application/json`, always |

The API is **not** served when `[control_api] enabled` is false — there is no port to
connect to. `/metrics` and `/health` live on a different port (`[metrics]`) and are not
part of this API.

**Success** — the payload is always wrapped in `result`:

```json
{ "result": { "uid": "c-a1cfc185", "did": "8000", "conf_id": 42, "mcu": "mcu1" } }
```

`result` is an object for a single resource, an **array** for a collection, and the
string `"ok"` for a command that returns nothing.

**Failure** — a single `error` string, which is the reason code for a machine
(`not_found`, `did_in_use`, `mcu_down`…) or a human sentence for an argument the module
refused:

```json
{ "error": "not_found" }
{ "error": "max_participants must be an integer, got \"eight\"" }
```

Rule of thumb for a client: an `error` matching `^[a-z_]+$` is a **reason code** you can
switch on; anything else is a validation message meant for a human. `400` carries the
sentence form, the other statuses the code form.

Auth failures are answered by the frontal before any command runs: `401` (missing or
invalid token) or `403` (mTLS without an accepted client certificate), same
`{"error": "…"}` shape.

---

## 2. Addressing a command

Every command has **two** URLs, both dispatching to the same handler:

| Form | Example | When to use |
|---|---|---|
| Canonical (resource) | `GET /modules/mcu/conferences/c-a1cfc185/participants` | normal clients: it is a resource tree, and `Location` headers point into it |
| Flat (command id) | `POST /modules/mcu/participant.list` with `{"uid": "c-a1cfc185"}` | a client that cannot build URLs, or a generic driver over `GET /modules/mcu` |

The flat form takes the command id as one path segment and **honours the declared
method**: `GET /modules/mcu/conference.create` is a `405`, not a create.

Resolution rules the frontal applies:

* a literal segment wins over a parameter at the same position;
* a path that matches a template but not its method → `405` with an `Allow` header
  listing the methods that path does answer;
* a path that matches nothing → `404 {"error": "unknown module command"}`;
* an unloaded module → the same `404` (an unauthenticated probe enumerates nothing).

Reserved sub-resources answer `404` on purpose rather than half-working:
`…/conferences/:uid/mosaics`, `…/mixers`, `…/listeners`.

---

## 3. Argument typing — the rule that trips clients

Arguments reach the command merged from three places, in ascending precedence:

```
path  <  query string  <  JSON body
```

* a body key that **contradicts** a path parameter is refused:
  `400 {"error": "path_conflict", "detail": "uid"}`. Repeating the same value is fine.
* `GET` requests are **not** body-parsed. Anything you would put in a body must be a
  query parameter there.

**The module does not coerce types.** A query string is always a JSON *string*, so an
argument whose type is boolean, integer, object or array can only be passed in a body:

```bash
DELETE /modules/mcu/conferences/c-a1?force=true     # 400 force must be a boolean, got "true"
DELETE /modules/mcu/conferences/c-a1  -d '{"force":true}'   # 200
```

| Argument type | Query string | JSON body |
|---|---|---|
| string (`domain`, `did`, `name`, `file`, `logo`, `layout` short form, `holds`) | ✅ | ✅ |
| integer-ish path/id (`part_id`, `slot`) | ✅ (parsed from digits) | ✅ (JSON number) |
| `vad` (name **or** wire id) | ✅ (`vad=full`, `vad=2`) | ✅ (`"full"` or `2`) |
| `did` | ✅ | ✅ (a JSON number is stringified) |
| boolean (`force`, `dtmf`, `destroy_when_empty`) | ❌ | ✅ only |
| integer (`rate`, `max_participants`) | ❌ | ✅ only |
| object (`video`, `layout` wire form, `muted`) | ❌ | ✅ only |
| array (`medias`) | ❌ | ✅ only |

Two more refusals every write shares:

* an **unknown** argument is `400 {"error": "unknown argument(s): nope"}` — never a
  silent no-op;
* a **read-only** field is named as such: `400 {"error": "read-only field(s): did"}`.
  Read-only on a conference: `conf_id`, `created_at`, `participants`, `stale`, `domain`,
  `did`, `mcu`. On a participant: `name`, `state`, `medias`, `joined_at`.

---

## 4. Endpoint reference

Fourteen commands. Paths below omit the `/modules/mcu` prefix.

### 4.1 `POST /conferences` — create a conference

`conference.create` · success `201` · `Location: /modules/mcu/conferences/<uid>`

| Argument | Type | Required | Notes |
|---|---|---|---|
| `domain` | string | **yes** | the SIP domain the conference belongs to |
| `name` | string | no | free label, shown in listings |
| `did` | string | no | the number to dial. Omitted ⇒ allocated from `did_range` (lowest free). An explicit DID outside the range is honoured |
| `mcu` | string | no | `[mediaserver.pool.*]` entry to pin this conference to. Omitted ⇒ round-robin over the pool |
| `vad` | name or id | no | `none` `basic` `full` (§6.3) |
| `rate` | integer | no | one of `8000` `16000` `32000` `48000` — mixer sampling rate |
| `medias` | array of string | no | any of `"audio"` `"video"` `"text"`, non-empty. An omitted media is answered **port 0** in SDP — this is how video or text is turned off |
| `dtmf` | boolean | no | propose RFC 4733 telephone-event on audio |
| `video` | object | no | encoder profile: `size` (name or id), `fps`, `bitrate` (kbps), `intra_period`. Merged over the configured default |
| `layout` | string or object | no | mosaic / size / mode — §6.1 |
| `logo` | string | no | bare image file name under `image_dir`, drawn in every empty mosaic slot |
| `max_participants` | integer | no | per-conference cap; a further caller gets SIP `486` |
| `destroy_when_empty` | boolean | no | destroy the conference with its last participant |

Everything omitted comes from `[module.mcu]`. Request:

```json
{
  "domain": "example.com",
  "name": "Sales weekly",
  "max_participants": 8,
  "video": {"size": "vga", "fps": 25},
  "layout": "2x2 hd720p"
}
```

`201`:

```json
{
  "result": {
    "uid": "c-a1cfc185",
    "did": "8000",
    "conf_id": 42,
    "mcu": "mcu1"
  }
}
```

* `uid` (`c-` + 8 hex chars) is the identity every other endpoint takes. **Keep it**:
  it is the only key into the resource tree.
* `did` is what a phone must dial — always returned, including when the client chose it.
* `conf_id` is the media-server-side integer. It is an implementation detail that
  changes if the conference is recreated after an MCU restart: do not key on it.
* an optional `warning` string is added when the DID matches **no call rule** of that
  domain in `domains.toml` — the conference exists but nobody can dial it yet. Surface
  it; it is the single most common "my conference does not answer".

```json
{ "result": { "uid": "c-7d2e", "did": "8002", "conf_id": 43, "mcu": "mcu1",
              "warning": "DID 8002 matches no call rule on example.com: nobody can dial this conference until domains.toml routes it" } }
```

Errors:

| Reason | Status | Means |
|---|---|---|
| `did_in_use` | `400` | the DID you named is already taken on that domain |
| `no_did_available` | `409` | the allocation range is exhausted — an operator must widen `did_range` |
| `did_required` | `400` | no `did_range` configured for that domain, so `did` is mandatory |
| `unknown_mcu` | `400` | `mcu` names no pool entry |
| `no_mediaserver` | `400` | the pool is empty, or every entry is disabled |
| `mcu_down` | `503` | the chosen media server is not answering — retry later |
| `rpc_error` | `502` | the media server answered an error; the detail is in the node's log |
| *validation* | `400` | a sentence naming the field |

A `logo` that the media server cannot load is **not** an error here: it is logged and the
conference is created without it (a picture must not be why a conference does not exist).

### 4.2 `GET /conferences` — list conferences

`conference.list` · success `200`

| Argument | In | Notes |
|---|---|---|
| `domain` | query | exact match filter |
| `did` | query | exact match filter |

Both optional; no filter lists everything. No `404` — an empty result is `[]`.

```
GET /modules/mcu/conferences?domain=example.com&did=8000
```

```json
{
  "result": [
    {
      "uid": "c-a1cfc185",
      "name": "Sales weekly",
      "domain": "example.com",
      "did": "8000",
      "mcu": "mcu1",
      "conf_id": 42,
      "vad": 1,
      "rate": 32000,
      "medias": ["audio", "video", "text"],
      "dtmf": true,
      "video": {"size": 2, "fps": 25, "bitrate": 1024, "intra_period": 300},
      "layout": {"comp": 1, "size": 2, "auto": false},
      "max_participants": 8,
      "destroy_when_empty": false,
      "created_at": { "…": "timestamp object, §5.6" },
      "stale": false,
      "logo": null,
      "recording": null,
      "participants": 1
    }
  ]
}
```

⚠️ In a **listing**, `participants` is a **count**. In `conference.show` the same key
holds the **array** of participants (§4.3). A client that types this field must handle
both, keyed on the endpoint.

`stale: true` means the media server holding this conference went away: the row and its
DID survive, `conf_id` is gone, and calls to that DID are answered `503` until the server
returns (the conference is then recreated with the same `uid`).

### 4.3 `GET /conferences/:uid` — one conference and its roster

`conference.show` · success `200` · errors: `not_found` → `404`

Same object as a listing row, except `participants`, which is the full roster (the media
detail of a leg is one level down, §4.7). This is the one place a timestamp is printed in
full below; every other one has the same shape.

```json
{
  "result": {
    "uid": "c-a1cfc185",
    "name": "Sales weekly",
    "domain": "example.com",
    "did": "8000",
    "mcu": "mcu1",
    "conf_id": 42,
    "vad": 1,
    "rate": 32000,
    "medias": ["audio", "video", "text"],
    "dtmf": true,
    "video": {"size": 2, "fps": 25, "bitrate": 1024, "intra_period": 300},
    "layout": {"comp": 1, "size": 2, "auto": false},
    "max_participants": 8,
    "destroy_when_empty": false,
    "created_at": {
      "year": 2026, "month": 8, "day": 7,
      "hour": 10, "minute": 38, "second": 31,
      "microsecond": [731152, 6],
      "time_zone": "Etc/UTC", "zone_abbr": "UTC",
      "utc_offset": 0, "std_offset": 0,
      "calendar": "Elixir.Calendar.ISO"
    },
    "stale": false,
    "logo": null,
    "recording": null,
    "participants": [
      {
        "part_id": 7,
        "name": "alice@phone_example_com",
        "from": "alice@phone.example.com",
        "state": "connected",
        "joined_at": { "…": "timestamp object, §5.6" },
        "medias": {
          "audio": {"codec": "PCMA", "rec_port": 52014, "send": ["192.168.1.50", 40000], "dtmf": false}
        }
      }
    ]
  }
}
```

`recording` here is the **file name** while the mix is being recorded (`null` otherwise);
the detail is `GET …/recording` (§4.11).

### 4.4 `PUT` | `PATCH /conferences/:uid` — update a conference

`conference.update` · success `200` · both methods are the same operation (`PATCH` is the
honest verb, `PUT` is accepted for clients that only have it)

**`PUT` merges.** An omitted field is left untouched, never reset to its default. That is
the deliberate reading here, and it is what makes a one-field update safe.

| Argument | Type | Notes |
|---|---|---|
| `uid` | path | |
| `name` | string | |
| `vad` | name or id | |
| `rate` | integer | `8000` `16000` `32000` `48000` |
| `layout` | string or object | §6.1 — merged field by field over the current layout |
| `video` | object | merged field by field over the current profile. Applies to the legs that join **next**, not to the ones already encoding |
| `logo` | string | bare image name. **Cannot be unset** on a live conference (the media server has no reset): set another one, or destroy the conference |
| `max_participants` | integer | |
| `destroy_when_empty` | boolean | |

```json
{ "name": "Renamed", "layout": "auto,cif" }
```

```json
{ "result": { "uid": "c-a1cfc185", "changed": ["layout", "name"] } }
```

`changed` is the sorted list of the fields the request actually carried — the acknowledgement
of the merge. Errors: `not_found` → `404`, `mcu_down` → `503`, `rpc_error` → `502`,
read-only/unknown/validation → `400`.

A purely local change (a rename) succeeds while the media server is unreachable; anything
the mixer must hear about (`vad`, `rate`, `layout`, `video`, `logo`) needs it.

### 4.5 `DELETE /conferences/:uid` — destroy a conference

`conference.delete` · success `200`

| Argument | Type | Notes |
|---|---|---|
| `uid` | path | |
| `force` | boolean, **body only** | disconnect the participants first |

Without `force`, a conference that still holds participants is refused:

```json
{ "error": "not_empty" }
```

```json
{ "result": { "uid": "c-a1cfc185", "disconnected": 1 } }
```

Errors: `not_found` → `404`, `not_empty` → `409`, `mcu_down` → `503`,
`rpc_error` → `502`.

### 4.6 `GET /conferences/:uid/participants` — the roster

`participant.list` · success `200` · errors: `not_found` → `404` (unknown conference)

An array of the participant objects of §5.2 — including the **ringing** legs, which hold
a quota slot without being in the mix yet. An empty conference is `[]`.

### 4.7 `GET /conferences/:uid/participants/:part_id` — one leg, with statistics

`participant.show` · success `200` · errors: `not_found` → `404` (unknown conference *or*
participant)

The participant object plus the media server's own counters, asked for on each call:

```json
{
  "result": {
    "part_id": 7,
    "name": "alice@phone_example_com",
    "from": "alice@phone.example.com",
    "state": "connected",
    "joined_at": { "…": "timestamp object, §5.6" },
    "medias": {
      "audio": {"codec": "PCMA", "rec_port": 52014, "send": ["192.168.1.50", 40000], "dtmf": false}
    },
    "stats": {
      "audio": {
        "receiving": true,
        "sending": true,
        "lost_recv_packets": 0,
        "num_recv_packets": 100,
        "num_send_packets": 90,
        "total_recv_bytes": 16000,
        "total_send_bytes": 14400
      }
    }
  }
}
```

When the counters cannot be read, the call still succeeds with `stats: {}` **and** a
`stats_error` naming why (`"rpc_error"`, `"unknown_mcu"`, `"down"`, `"timeout"`) — so a
client reading zeros can always tell "no media" from "no answer". Never display zeros
without checking for `stats_error`.

### 4.8 `PUT` | `PATCH /conferences/:uid/participants/:part_id` — mute / unmute

`participant.update` · success `200`

| Argument | Type | Notes |
|---|---|---|
| `muted` | object, **body only** | per media: `{"audio": true, "video": false}`. Keys: `audio` `video` `text`; values must be booleans |

Only the medias named are touched. Request `{"muted": {"audio": true}}`:

```json
{ "result": { "part_id": 7, "changed": ["audio"] } }
```

Errors: `not_found` → `404`, `mcu_down` → `503`, `rpc_error` → `502`, and `400` for
`muted: {"foo": true}` (unknown media) or a non-boolean value.

### 4.9 `DELETE /conferences/:uid/participants/:part_id` — disconnect a leg

`participant.delete` · success `200` · errors: `not_found` → `404`

```json
{ "result": { "part_id": 7 } }
```

This asks that leg's SIP scenario to wind down — BYE, then media teardown — so the caller
sees a normal hang-up. It does **not** cut media under a live dialog, and the row does not
disappear synchronously: poll the roster if you need to observe the departure.

### 4.10 `POST /conferences/:uid/recording` — start recording the mix

`recording.start` · success `201` · `Location: /modules/mcu/conferences/<uid>/recording`

| Argument | Type | Notes |
|---|---|---|
| `file` | string | a **bare** file name ending in `.mp4` or `.flv`. No directory, no `..`, no leading dot. Omitted ⇒ `<uid>-<YYYYmmdd-HHMMSS>.mp4` |

The file is written **on the media server**, under the configured `record_dir` — a client
chooses the name, never the directory, and cannot fetch the result over this API.

```json
{ "result": { "uid": "c-a1cfc185", "file": "demo.mp4", "path": "/var/lib/kelixip/rec/demo.mp4", "mcu": "mcu1" } }
```

Errors: `not_found` → `404`, `already_recording` → `409` (one recording per conference),
`mcu_down` → `503`, `rpc_error` → `502`, and `400` for a bad name or for a node whose
`record_dir` is unset (`"record_dir is not set in [module.mcu]: there is nowhere on the
media server to write"`).

### 4.11 `GET /conferences/:uid/recording` — recording state

`recording.show` · success `200` · errors: `not_found` → `404` (unknown conference)

A conference that is not recording is **not** a `404` — it answers `recording: false`:

```json
{ "result": { "recording": false, "file": null, "path": null, "mcu": "mcu1", "started_at": null, "duration_s": null } }
```

```json
{ "result": { "recording": true, "file": "demo.mp4", "path": "/var/lib/kelixip/rec/demo.mp4",
              "mcu": "mcu1", "started_at": { "…": "§5.6" }, "duration_s": 0 } }
```

`duration_s` is computed on read (seconds since `started_at`); the media server is not
asked, so this endpoint is cheap to poll.

### 4.12 `DELETE /conferences/:uid/recording` — stop recording

`recording.stop` · success `200`

```json
{ "result": { "uid": "c-a1cfc185", "file": "demo.mp4", "duration_s": 42 } }
```

Errors: `not_found` **and** `not_recording` both → `404` (there is no recording resource
to delete either way), `mcu_down` → `503`, `rpc_error` → `502`.

### 4.13 `GET /conferences/:uid/slots` — the mosaic slot map

`slot.list` · success `200`

The only read that goes to the media server on every call: who is displayed where is the
*mixer's* state and it moves on its own at every VAD period.

```json
{
  "result": {
    "layout": {"comp": 1, "size": 2, "auto": true},
    "vad": 1,
    "logo": null,
    "slots": [
      {"slot": 0, "holds": "free", "pinned": null, "part_id": 7,    "name": "alice@phone_example_com"},
      {"slot": 1, "holds": "free", "pinned": null, "part_id": null, "name": null},
      {"slot": 2, "holds": "free", "pinned": null, "part_id": null, "name": null},
      {"slot": 3, "holds": "free", "pinned": null, "part_id": null, "name": null}
    ]
  }
}
```

Read the three columns as three different questions:

* `holds` — what the slot was **told** (`vad` `locked` `free` `part`);
* `pinned` — **whom** you pinned there (a `part_id`), `null` when nothing was pinned;
* `part_id` / `name` — who the mixer is showing **now**. On a `vad` slot this moves with
  the active speaker, which is the whole point of the endpoint.

How many slots there are depends on the mosaic, and it is the media server's own table,
not arithmetic on the name: `1x1` 1, `1+1` 2, `pip1` 2, `2x2` 4, `pip3` 4, `1+5` 6,
`3+4` 7, `1+7` 8, `3x3` 9, `2+8` 10, `4x4` 16, `1+4` 16.

Errors: `not_found` → `404`, `mcu_down` → `503`, `rpc_error` → `502`.

### 4.14 `PUT` | `PATCH /conferences/:uid/slots/:slot` — pin a slot

`slot.update` · success `200`

| Argument | Type | Required | Notes |
|---|---|---|---|
| `slot` | path (0-based) | **yes** | as the media server numbers and logs them |
| `holds` | string or integer | **yes** | see below |

`holds` takes:

| Value | Effect |
|---|---|
| `"vad"` | follow the active speaker |
| `"locked"` | show nobody |
| `"free"` | the mixer decides again (the pin stays recorded) |
| `"reset"` | free **and** forget the pin — stop replaying it after a server restart |
| a `part_id` (`7` or `"7"`) | nail that participant |
| a participant name (`"alice"` or `"alice@phone_example_com"`) | resolved against the roster |

A bare `0` or a negative number is refused: `0` is both "participant zero" and *free*, and
the names exist so that nobody has to know which. A name matching **two** legs is refused
too, naming the ids to pick from — never a coin flip.

```json
{ "result": { "slot": 0, "holds": "vad", "part_id": null } }
```

`part_id` is set only when a participant was nailed. **Pinning turns the automatic layout
off** (`layout.auto` becomes `false`): the automatic mosaic changes the composition, and a
smaller mosaic would drop the pin.

Errors: `not_found` → `404` (conference, or a name/`part_id` matching no leg),
`mcu_down` → `503`, `rpc_error` → `502`, `400` for a slot outside the mosaic or an
unreadable `holds`.

---

## 5. Object shapes

### 5.1 Conference

| Field | Type | Notes |
|---|---|---|
| `uid` | string | `c-` + 8 hex chars. The API identity |
| `name` | string \| null | free label |
| `domain` | string | |
| `did` | string | the number to dial |
| `mcu` | string | pool entry this conference is pinned to; never migrates |
| `conf_id` | integer \| null | media-server-side id; `null` while `stale` |
| `vad` | integer | wire id, §6.3 |
| `rate` | integer | Hz |
| `medias` | array of string | which `m=` sections this conference answers |
| `dtmf` | boolean | |
| `video` | object | `{size, fps, bitrate, intra_period}`, `size` a wire id |
| `layout` | object | `{comp, size, auto}`, `comp`/`size` wire ids |
| `max_participants` | integer | |
| `destroy_when_empty` | boolean | |
| `created_at` | timestamp | §5.6 |
| `stale` | boolean | its media server went away |
| `logo` | string \| null | image drawn in empty slots |
| `recording` | string \| null | the file name while recording |
| `participants` | integer **or** array | count in a listing, roster in `show` |

### 5.2 Participant

| Field | Type | Notes |
|---|---|---|
| `part_id` | integer \| null | media-server-side id; `null` on a leg that is still ringing |
| `name` | string | the leg's AOR, with dots turned into underscores (`alice@phone_example_com`) — it is a media-server-side identifier |
| `from` | string \| null | the SIP `From` as dialled (`alice@phone.example.com`) |
| `state` | string | `ringing` \| `connected` \| `leaving` |
| `joined_at` | timestamp \| null | §5.6; `null` until the leg is in the mix |
| `medias` | object | §5.3 |
| `stats` | object | `participant.show` only, §5.4 |
| `stats_error` | string | `participant.show` only, when the counters could not be read |

### 5.3 Negotiated medias

Keyed by media name, one entry per media actually negotiated on that leg:

```json
{"audio": {"codec": "PCMA", "rec_port": 52014, "send": ["192.168.1.50", 40000], "dtmf": false}}
```

* `codec` — the payload name the mixer settled on for that leg;
* `rec_port` — the port the media server receives on;
* `send` — a two-element array `[ip, port]` (a tuple on the wire, hence an array), where
  the mixer sends;
* `dtmf` — whether telephone-event was negotiated.

### 5.4 Statistics

Keyed by media name: `receiving` / `sending` (booleans), `lost_recv_packets`,
`num_recv_packets`, `num_send_packets`, `total_recv_bytes`, `total_send_bytes`. Counters
are the media server's own, cumulative since the leg joined.

### 5.5 Slot row

`slot` (integer, 0-based), `holds` (string), `pinned` (integer \| null), `part_id`
(integer \| null), `name` (string \| null) — read as three questions, §4.13.

### 5.6 Timestamps

⚠️ Timestamps are **not** ISO 8601 strings. The frontal serialises the internal
`DateTime` structurally, so every `created_at` / `joined_at` / `started_at` is an object:

```json
{
  "year": 2026, "month": 8, "day": 7,
  "hour": 10, "minute": 38, "second": 31,
  "microsecond": [731152, 6],
  "time_zone": "Etc/UTC", "zone_abbr": "UTC",
  "utc_offset": 0, "std_offset": 0,
  "calendar": "Elixir.Calendar.ISO"
}
```

It is always UTC (`time_zone: "Etc/UTC"`, both offsets `0`), and `microsecond` is
`[value, precision]`. A client reassembles it as
`YYYY-MM-DDTHH:MM:SS.ffffffZ`, or reads the fields it needs. Treat unknown keys as
additive and do not assert on the field set.

*(This shape is a wart, not a design: it is what the generic struct-to-JSON pass produces.
It is documented here because it is what the server sends today — a client must handle it.)*

---

## 6. Vocabularies

Input accepts **names**; output always carries the **wire ids**. A name is
case-insensitive; a digit string (`"6"`) is accepted wherever an id is.

### 6.1 `layout`

Two forms, both accepted everywhere `layout` is:

**Short form** — one string of tokens separated by spaces *or* commas, in **any order**
(the three vocabularies are disjoint, so order carries no meaning):

```
layout = "2x2 hd720p"     mosaic + size
layout = "auto,vga"       mode + size
layout = "1+1"            mosaic alone
layout = "cif"            size alone
layout = "manual"         stop following the participant count
```

Two rules that a client must not paper over:

* **only what is named changes** — `"vga"` keeps the current mosaic;
* **naming a mosaic implies `manual`**, unless `auto` is in the same value. On a
  conference in `auto`, a fixed mosaic would be undone by the next arrival — a command
  that appeared to work and did nothing. `"auto 2x2"` is the explicit "set it now, keep
  following".

**Wire form** — an object, taken **literally** (no implied `manual`), names allowed inside:

```json
{"layout": {"comp": 1, "size": 6, "auto": false}}
{"layout": {"comp": "2x2"}}
```

Giving two tokens of the same group (`"2x2 3x3"`) is a `400` naming both.

### 6.2 Mosaics and video sizes

| Mosaic | id | | Size | id | pixels |
|---|---|---|---|---|---|
| `1x1` | 0 | | `qcif` | 0 | 176×144 |
| `2x2` | 1 | | `cif` | 1 | 352×288 |
| `3x3` | 2 | | `vga` | 2 | 640×480 |
| `3+4` | 3 | | `pal` | 3 | 768×576 |
| `1+7` | 4 | | `hvga` | 4 | 320×240 |
| `1+5` | 5 | | `qvga` | 5 | 160×120 |
| `1+1` | 6 | | `hd720p` (`720p`) | 6 | 1280×720 |
| `pip1` | 7 | | `wqvga` | 7 | 400×240 |
| `pip3` | 8 | | `xga` | 14 | 1024×768 |
| `4x4` | 9 | | `wvga` | 15 | 800×480 |
| `1+4` | 10 | | | | |
| `2+8` | 11 | | | | |

`720p` is the one accepted alias, for `hd720p`. Note the size ids are **not** contiguous
(there is no 8–13): decode by table, never by arithmetic.

### 6.3 VAD

| Name | id | |
|---|---|---|
| `none` | 0 | no voice activity detection |
| `basic` | 1 | default |
| `full` | 2 | |

### 6.4 Medias

`"audio"`, `"video"`, `"text"` — the `m=` sections a conference answers. `text` is T.140
real-time text. A media absent from the list is answered port 0.

### 6.5 Retired arguments

`audio_codecs`, `video_codecs`, `text_codecs` and `video_fmtp` are **accepted and
ignored** on `conference.create` / `conference.update`, with a warning in the node's log:
the media server arbitrates codecs. Use `medias` to turn a media off and `dtmf` to stop
proposing telephone-event. They become a `400 unknown argument` in a future release —
a client should stop sending them now.

---

## 7. Statuses and retry semantics

| Status | When | What a client should do |
|---|---|---|
| `200` | read or write succeeded | |
| `201` | `conference.create`, `recording.start` | follow `Location` |
| `400` | unusable request: bad type, unknown or read-only argument, `did_in_use`, `unknown_mcu`, `no_mediaserver`, `did_required`, `path_conflict` | fix the request; never retry as-is |
| `401` / `403` | auth | fix the credential |
| `404` | `not_found` (conference, participant, slot's target, recording), unknown route or unloaded module | |
| `405` | that path does not answer this method | read the `Allow` header |
| `409` | `no_did_available`, `not_empty`, `already_recording` | a state conflict: change the request (widen the range, `force`, stop the running recording) |
| `502` | `rpc_error` — the media server answered an error | log it and surface it; the detail is server-side |
| `503` | `mcu_down`, or the module itself absent/wedged (`down`, `timeout`) | **retryable**: the mixer is unreachable, the request was fine |

The mapping is per command and **declared** by the module — the same declaration
`kelictl` turns into its exit code, so the two frontals cannot disagree. Read it from
`GET /modules/mcu` (`errors` per command) rather than hard-coding this table; anything not
declared falls back to `404` for `not_found`-like reasons, `503` for `down`/`timeout`,
`400` otherwise.

---

## 8. Discovery — `GET /modules/mcu`

The whole surface as data, which is what a generic client should build itself from:

```json
{
  "name": "mcu",
  "module": "Elixir.Kelix.Mod.Mcu",
  "version": "1.0",
  "exports": [["create_conference", 2], ["admit", 2], "…"],
  "commands": [
    {
      "name": "slot.update",
      "methods": ["put", "patch"],
      "path": "/conferences/:uid/slots/:slot",
      "rw": "w",
      "status": 200,
      "errors": {"not_found": 404, "mcu_down": 503, "rpc_error": 502},
      "help": "Pin a mosaic slot: the active speaker, a participant, locked or free",
      "args": [
        {"name": "uid", "required": true},
        {"name": "slot", "required": true, "help": ["slot number, 0-based — as the media server numbers and logs them", "…"]},
        {"name": "holds", "required": true, "help": ["what the slot shows: vad | locked | free | reset | <part_id> | <name>", "…"]}
      ]
    }
  ]
}
```

* `path` is relative to `/modules/mcu` and carries `:param` segments;
* `methods` are lower-case; upper-case them for the request;
* `status` is the success status (`201` on the two creations);
* `errors` maps a reason code to its HTTP status — §7;
* `args` gives the name, whether it is required, and the argument's own vocabulary as
  `help` lines (a string or an array of strings). The `help` text is written for a human
  and is the same one `kelictl mcu help <cmd>` prints;
* `render` (when present) is a **CLI** hint — table columns, detail fields, and the
  id→name label maps. A REST client can reuse `render.labels` to turn the wire ids it
  receives into names (`labels["video.size"]["6"] == "hd720p"`), which is exactly what §6
  tabulates;
* `exports` are the Elixir facade functions the module offers to *scenarios*, not
  endpoints. Ignore them in a client.

`GET /modules` returns the same for every loaded module. An unloaded `mcu` is a `404`
here, which is the fastest way for a client to check the module is installed at all.

---

## 9. Semantics a client must implement

1. **The `uid` is the address, the DID is not.** There is no `/conferences/by-did/8001`.
   A client holding only a DID does `GET /conferences?did=8001` and follows the `uid`.
2. **`PUT` merges** (§4.4). To reset a field, send its default explicitly; there is no
   `null` semantics, and `logo` cannot be unset at all on a live conference.
3. **`participants` changes type** between a listing and a `show` (§4.2).
4. **Timestamps are objects**, not strings (§5.6).
5. **Booleans, integers, objects and arrays must be in the JSON body** (§3), including on
   `DELETE`.
6. **There are no webhooks, no event stream, and no long-poll.** Node-level events
   (`conference.created`, `participant.joined`/`left`, `recording_started`/`_stopped`,
   `slot_changed`, `mediaserver.down`…) are **logged** and counted in Prometheus
   (`kelix_mcu_calls_total`, `kelix_mcu_participants`, `kelix_mcu_rpc_errors_total`); they
   are not delivered over REST. A client that needs a roster in real time **polls**
   `GET …/participants` (cheap: served from memory, no RPC). `slot.list` and
   `participant.show` do hit the media server — poll those at a human rate (1 s is fine,
   10 ms is not).
7. **A conference is pinned to one media server** and never migrates. `mcu` is chosen at
   creation only.
8. **A conference is not a call.** Creating one only allocates a room and a DID: legs
   arrive by SIP INVITE to `did@domain`, and `domains.toml` must route that DID to a
   scenario or the DID answers `404` (that is what the create `warning` is about). Joining
   a conference is not something this API can do.
9. **Nothing here fetches media.** Recordings land on the media server's filesystem; this
   API returns the `path`, and moving that file is out of scope.
10. **Slots are 0-based** and pinning turns `layout.auto` off (§4.14).

---

## 10. A worked session

```bash
TOKEN=change-me
BASE=http://127.0.0.1:8090/modules/mcu
H_AUTH="Authorization: Bearer $TOKEN"
H_JSON="Content-Type: application/json"

# 1. the module is loaded, and this is its surface
curl -s -H "$H_AUTH" $BASE | jq '.commands[].name'

# 2. create a room — an 8-seat 2x2 in VGA, DID allocated
curl -sD- -H "$H_AUTH" -H "$H_JSON" -X POST $BASE/conferences -d '{
  "domain": "example.com",
  "name": "Sales weekly",
  "max_participants": 8,
  "layout": "2x2 vga",
  "medias": ["audio", "video"]
}'
# 201, Location: /modules/mcu/conferences/c-a1cfc185
# -> {"result":{"uid":"c-a1cfc185","did":"8000","conf_id":42,"mcu":"mcu1"}}

UID=c-a1cfc185

# 3. phones dial 8000@example.com; watch the roster fill in (poll, no events)
curl -s -H "$H_AUTH" $BASE/conferences/$UID/participants | jq '.result[] | {part_id, from, state}'

# 4. show the active speaker in the top-left tile, mute a noisy leg
curl -s -H "$H_AUTH" -H "$H_JSON" -X PATCH $BASE/conferences/$UID/slots/0 -d '{"holds":"vad"}'
curl -s -H "$H_AUTH" -H "$H_JSON" -X PATCH $BASE/conferences/$UID/participants/7 \
     -d '{"muted":{"audio":true}}'

# 5. who is actually shown where, now
curl -s -H "$H_AUTH" $BASE/conferences/$UID/slots | jq '.result.slots'

# 6. record the mix, then stop it
curl -s -H "$H_AUTH" -H "$H_JSON" -X POST $BASE/conferences/$UID/recording -d '{"file":"demo.mp4"}'
curl -s -H "$H_AUTH" $BASE/conferences/$UID/recording
curl -s -H "$H_AUTH" -X DELETE $BASE/conferences/$UID/recording

# 7. hand the layout back to the module, then tear the room down
curl -s -H "$H_AUTH" -H "$H_JSON" -X PATCH $BASE/conferences/$UID -d '{"layout":"auto"}'
curl -s -H "$H_AUTH" -H "$H_JSON" -X DELETE $BASE/conferences/$UID -d '{"force":true}'
```

---

## 11. Client implementation checklist

* [ ] Base URL and token from configuration; `Authorization: Bearer` on every request.
* [ ] `Content-Type: application/json` and a JSON body on `POST` / `PUT` / `PATCH` /
      `DELETE`; query parameters only for string-typed arguments (§3).
* [ ] Unwrap `result` on success; on failure read `error` and switch on the reason code
      (§1, §7).
* [ ] Treat `503` as retryable with backoff, `409` as a state conflict, `400` as a bug in
      the request.
* [ ] Follow `Location` on `201` rather than reconstructing the URL.
* [ ] Store the `uid`; never key on `conf_id`; look a conference up by DID with the query
      filter.
* [ ] Surface the create `warning` (an unrouted DID nobody can dial).
* [ ] Decode wire ids to names with the tables of §6 (or with `render.labels` from
      `GET /modules/mcu`), and send names — they are accepted everywhere.
* [ ] Parse timestamps as the object of §5.6.
* [ ] Handle `participants` being a count in listings and an array in `show`.
* [ ] Poll for state; do not expect events. Keep `slot.list` / `participant.show` polling
      to a human rate.
* [ ] Check `stats_error` before showing statistics.
* [ ] Prefer building the surface from `GET /modules/mcu` over hard-coding paths, so a
      module upgrade does not need a client release.
