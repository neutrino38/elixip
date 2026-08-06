# mcu

The **conferencing module**: it holds the conferences, allocates their DIDs, and
drives a Medooze media server that mixes audio, video and T.140 text. An INVITE
whose R-URI user-part matches a conference DID joins that conference; the
conferences themselves are managed over `kelictl`, REST, or from a script.

Unlike `registrar` and `auth_db`, this module is **useless without a media
server**: installing the `.beam` is half of a working setup — see
[§1.1 of the guide](../../mcu_module_guide.md#11-what-must-be-true-before-a-call-can-succeed)
for the four things that must be true before a call can succeed.

> This page is the **reference** — parameters, facades, commands. The narrative
> (running a node, writing a script, debugging a call that did not work) is
> [docs/mcu_module_guide.md](../../mcu_module_guide.md), and the *why* of every
> decision and limitation is [docs/design/mcu_module.md](../../design/mcu_module.md).

## Loading

The bytecode comes from the `kelixip-mod-mcu` package (`dnf install` / `apt install`
— the name has no underscore, so it is the same on both), and the block is what
actually loads it.

The `[module.mcu]` block lives in **`config.toml`** (infrastructure, not
domain-tied). The media servers are **not** declared here: they are the
`[mediaserver.pool.*]` entries, the same block the point-to-point path uses.

```toml
# config.toml
[module.mcu]
rate             = 32000
max_participants = 20
did_range        = "8000-8099"

[mediaserver.pool.mcu1]
module = "mendooze"
url    = "http://10.0.0.12:9090"   # the media server's XML-RPC port (--http-port)
```

```elixir
import Kelix.Mod.Mcu, only: [admit: 2, attach: 1, leave: 2, media_config: 1]
```

A conference is **pinned** to the media server it was created on and never
migrates. `kelictl module reload mcu` has no in-place reload: the module is
restarted cleanly, which **drops the live conferences**.

Routing the DIDs is a separate, per-domain decision — the module allocates DIDs,
it never edits `domains.toml`, so the two can drift apart (`conference.create`
warns when they have):

```toml
# domains.toml
[[domain]]
name = "example.com"

  [[domain.call]]
  pattern = "8XXX"          # must cover the did_range above
  script  = "mcu.exs"       # joins an existing conference, else 404
```

## Parameters

Module block — `[module.mcu]` (in `config.toml`):

| Key | Type | Default | Description |
|---|---|---|---|
| `vad` | name or integer | `basic` | Voice activity detection: `none` / `basic` / `full` (or `0` / `1` / `2`) |
| `rate` | integer | `32000` | Mixer sampling rate: `8000`/`16000`/`32000`/`48000`. Participants are resampled to it — not a codec constraint |
| `medias` | list | `["audio","video","text"]` | Which `m=` sections a conference answers. An omitted media is answered **port 0** — how you turn video or text off. Codecs *inside* a media are the media server's call, not a config key |
| `dtmf` | boolean | `true` | Propose telephone-event (RFC 4733) on audio. A stream the mixer never encodes, hence a switch and not a codec |
| `max_participants` | integer | `20` | Per-conference cap; reached ⇒ the next caller gets `486` |
| `destroy_when_empty` | boolean | `false` | Destroy a conference with its last participant |
| `auto_layout` | boolean | `true` | The mosaic follows the number of video legs |
| `layout_comp` | name or integer | `2x2` | Starting mosaic — one of `1x1 2x2 3x3 3+4 1+7 1+5 1+1 pip1 pip3 4x4 1+4 2+8` (or its wire id) |
| `video_size` | name or integer | `hd720p` | Encoded size — one of `qcif cif vga pal hvga qvga hd720p wqvga xga wvga` (or its wire id) |
| `video_fps` | integer | `15` | Encoded frame rate |
| `video_bitrate` | integer | `1024` | kbps, also the cap on the answer's `b=AS:` |
| `video_intra_period` | integer | `300` | Frames between intra-frames |
| `logo_file` | string | — | Image drawn in **every empty mosaic slot**, on every conference (a bare name under `image_dir`) |
| `record_dir` | string | — | Directory the media server writes recordings into. No default: unset means `recording.start` refuses |
| `image_dir` | string | — | Directory the media server reads `logo_file` (and `logo=`) from. No default |
| `did_range` | string | — | Allocation pool for a `create` that omits `did` (`"8000-8099"`) |
| `did_ranges` | table | `{}` | Per-domain override: `{ "example.com" = "8000-8199" }` |
| `xmlrpc_timeout_ms` | integer | `10000` | Per-RPC bound towards the media server |
| `call_timeout_ms` | integer | `5000` | Upper bound on a facade call (ms) |
| `shutdown_grace_ms` | integer | `5000` | Grace given to conferences at module stop |
| `rtp_timeout_ms` | integer | `10000` | RTP inactivity watchdog — **ignored** until the server-side support of P7 (limitation L1) |
| `gc_orphans` | boolean | `true` | Sweep, at start, the conferences the media server still holds and no kelixip owns |

`vad`, `layout_comp` and `video_size` take the same names the CLI renders and the
control commands accept — one vocabulary, wherever a value enters.

**`record_dir` and `image_dir` are paths on the media server**, not on the kelixip host
(they are the same machine in a single-box deployment and will not be in production).
The module only ever appends a file name it has validated: a command can choose the
name, never the directory.

With neither `did_range` nor a `did_ranges` entry for a domain, `did` becomes
**mandatory** on create. An explicit DID is always honoured, including one
outside the range. Codec names are validated at boot *and* on every create: a
name the SDP layer cannot emit is a configuration error, never a call that fails
later. Any unknown key in the block is refused at boot.

**The media address is the media server's own setting**, not kelixip's: it
reports it on every `StartReceiving` and that is what goes in the answer's `c=`
line. Behind a NAT, `mediaserver --public-ip <ip>` is mandatory — see
[§1.2 of the guide](../../mcu_module_guide.md#12-configuration--modulemcu-in-configtoml).

## Facades

Every one of them goes through `Kelix.Module.safe_call/3`, so a wedged or absent
service is `{:error, :down | :timeout}` — an error the script answers with, never
a call that hangs. **Rescue anyway**: a module whose `.beam` was never installed
raises `UndefinedFunctionError`, and an unrescued raise leaves the caller with no
response at all.

### The call path

```elixir
admit(domain, req) ::
  {:ok, Conference.t(), participant}
  | {:error, :no_such_conference | :full | :mcu_down | :down | :timeout}
```

Resolve the DID in `req`'s R-URI under `domain`, reserve a slot, and return the
conference plus the participant handle. It reserves; it does not join the mix.
The verdicts map onto `404` / `486` / `503` / `500` — that mapping is the
**script's**, not the module's.

```elixir
attach(part)              :: :ok | {:error, term}
leave(part, reason \\ :bye) :: :ok
```

`attach/1` is what puts the leg **in the mix** (codecs, `StartSending`) and
belongs on the ACK: no RTP leaves the mixer before the call is established.
`leave/2` releases the slot and is **idempotent** by contract — it tolerates an
already-removed participant, which is why the reference script calls it from
seven places without guarding.

```elixir
media_config(conf) :: keyword    # -> appdata_set(:mediaserver_instance, …)
```

The adapter + URL of the MCU this conference is pinned to. A leg must reach the
server holding the mixer, not whatever the media pool would hand out.

### In-call

```elixir
send_fpu(part)          :: :ok | {:error, term}   # ask the MCU for an intra-frame
mute(part, media, on?)  :: :ok | {:error, term}   # media :: :audio | :video
kick(uid, part_id)      :: :ok | {:error, :not_found | term}
```

`kick/2` asks that leg's scenario to wind down (BYE + teardown); it does not cut
the media under a live dialog.

### Conference lifecycle (from a script)

```elixir
create_conference(domain, opts)        :: {:ok, Conference.t()} | {:error, atom | String.t()}
ensure_conference(domain, did, opts)   :: {:ok, Conference.t(), :created | :existing} | {:error, …}
update_conference(uid, changes)        :: {:ok, [changed_field]} | {:error, atom | String.t()}
destroy_conference(uid, opts)          :: :ok | {:error, atom}
conferences(domain)                    :: [Conference.t()]
```

`ensure_conference/3` is an **atomic get-or-create**: N simultaneous callers on
an unknown DID get one room. `owner: :caller` (the default) is the leak guard —
if the creating instance dies before anyone joins, the module destroys the
**empty** conference; a conference somebody joined survives its creator.

Options are atom-keyed keyword lists validated by exactly the same code as the
REST body, so a conference a script creates and one REST creates are
indistinguishable. `apps/kelixip/scripts/mcu_adhoc.exs` is this in full.

### Reads (no RPC, straight from ETS)

```elixir
conference(uid)        :: {:ok, Conference.t()} | :error
lookup_did(domain, did) :: {:ok, Conference.t()} | :error
mediaserver(name)      :: {:ok, map} | :error
```

## Control commands

Fourteen commands, declared once and served identically by both frontals. The
authoritative list is the running node's:

```
kelictl mcu help                  # the commands, their REST route and their args
kelictl mcu help conference.update  # one command, with each argument's own vocabulary
kelictl module list               # every loaded module, its commands and facades
```

| Command | `kelictl` | REST |
|---|---|---|
| `conference.create` | `mcu conference.create domain=example.com name=Weekly` | `POST /modules/mcu/conferences` → `201` + `Location` |
| `conference.list` | `mcu conference.list domain=example.com` | `GET /modules/mcu/conferences?domain=…&did=…` |
| `conference.show` | `mcu conference.show uid=c-3f9a` | `GET /modules/mcu/conferences/:uid` |
| `conference.update` | `mcu conference.update uid=c-3f9a layout='1+1 vga'` | `PUT`/`PATCH` `/modules/mcu/conferences/:uid` |
| `conference.delete` | `mcu conference.delete uid=c-3f9a force=true` | `DELETE /modules/mcu/conferences/:uid` |
| `participant.list` | `mcu participant.list uid=c-3f9a` | `GET …/conferences/:uid/participants` |
| `participant.show` | `mcu participant.show uid=c-3f9a part_id=7` | `GET …/participants/:part_id` |
| `participant.update` | `mcu participant.update uid=c-3f9a part_id=7 muted='{"audio":true}'` | `PUT`/`PATCH` `…/participants/:part_id` |
| `participant.delete` | `mcu participant.delete uid=c-3f9a part_id=7` | `DELETE …/participants/:part_id` |
| `recording.start` | `mcu recording.start uid=c-3f9a file=record.mp4` | `POST …/conferences/:uid/recording` → `201` |
| `recording.show` | `mcu recording.show uid=c-3f9a` | `GET …/conferences/:uid/recording` |
| `recording.stop` | `mcu recording.stop uid=c-3f9a` | `DELETE …/conferences/:uid/recording` |
| `slot.list` | `mcu slot.list uid=c-3f9a` | `GET …/conferences/:uid/slots` |
| `slot.update` | `mcu slot.update uid=c-3f9a slot=0 holds=vad` | `PUT`/`PATCH` `…/conferences/:uid/slots/:slot` |

On the CLI, arguments are `name=value` tokens — path variables are ordinary named
arguments, so the same map reaches the module either way. A value typed
`true`/`false` is a boolean, digits an integer, and a leading `{`/`[` is JSON
(`muted='{"audio":true}'`).

### Saying it in names, not in numbers

The mosaic, the video size and the VAD mode have **names**, and they are accepted
wherever a value enters — the CLI, a REST body, the config block, a script:

```bash
kelictl mcu conference.update uid=c-3f9a layout='2x2 hd720p'   # mosaic + size
kelictl mcu conference.update uid=c-3f9a layout=auto,vga       # commas: no quoting
kelictl mcu conference.update uid=c-3f9a layout=1+1            # mosaic alone
kelictl mcu conference.update uid=c-3f9a layout=cif            # size alone
kelictl mcu conference.update uid=c-3f9a layout=manual         # stop following
kelictl mcu conference.update uid=c-3f9a vad=full
kelictl mcu conference.create domain=example.com video='{"size":"vga","fps":25}'
```

`layout` takes a **mosaic**, a **size** and/or `auto`|`manual`, in **any order**,
separated by spaces or commas. The three vocabularies are disjoint, so order
carries no meaning:

| Group | Values |
|---|---|
| mosaic | `1x1` `2x2` `3x3` `3+4` `1+7` `1+5` `1+1` `pip1` `pip3` `4x4` `1+4` `2+8` |
| size | `qcif` `cif` `vga` `pal` `hvga` `qvga` `hd720p` (`720p`) `wqvga` `xga` `wvga` |
| mode | `auto` — the mosaic follows the video-leg count — or `manual` |

Two rules:

* **only what is named changes** — `layout=vga` keeps the current mosaic, like
  every other field of a `PUT` (see below);
* **naming a mosaic implies `manual`**, unless `auto` is in the same value. On a
  conference in `auto`, a fixed mosaic would otherwise be undone by the next
  arrival — a command that appeared to work and did nothing. `layout='auto 2x2'`
  is the explicit "set it now, keep following".

A typo is a `400` that prints the vocabulary, and an argument's names are in the
online help (`kelictl mcu help conference.update`). The **wire form still works
and stays literal** — `layout='{"comp":1,"size":6,"auto":false}'`, names allowed
inside it (`{"comp":"2x2"}`) — so an existing REST client needs no change and a
`PUT` body means exactly what it says.

### Recording, slots and the logo

```bash
# record the mix — the file lands on the MEDIA SERVER, under record_dir
kelictl mcu recording.start uid=c-3f9a                  # <uid>-20260803-141212.mp4
kelictl mcu recording.start uid=c-3f9a file=record.mp4
kelictl mcu recording.show  uid=c-3f9a                  # running? which file? how long?
kelictl mcu recording.stop  uid=c-3f9a

# the mosaic slot map, and what each slot must hold
kelictl mcu slot.list   uid=c-3f9a
kelictl mcu slot.update uid=c-3f9a slot=0 holds=vad     # the active speaker, here
kelictl mcu slot.update uid=c-3f9a slot=1 holds=7       # nail participant 7
kelictl mcu slot.update uid=c-3f9a slot=1 holds=alice   # …or name it
kelictl mcu slot.update uid=c-3f9a slot=2 holds=locked  # shows nobody
kelictl mcu slot.update uid=c-3f9a slot=2 holds=free    # the mixer decides again
kelictl mcu slot.update uid=c-3f9a slot=2 holds=reset   # free, and forget the pin

# the picture drawn in every EMPTY slot
kelictl mcu conference.update uid=c-3f9a logo=ives.png
```

`file` and `logo` are **bare names**, resolved under `record_dir` / `image_dir` on the
media server: a command chooses the name, never the directory. The extension decides
the container (`.mp4` or `.flv`, nothing else). One recording per conference — a second
`recording.start` is a `409`.

Slots are **0-based**, as the media server numbers and logs them, and how many there
are depends on the mosaic (`1x1` 1, `1+1` 2, `2x2` 4, `3x3` 9, `4x4` 16 …). Pinning a
slot **turns the automatic layout off**: it changes the composition, and a smaller
mosaic would drop the pin.

`slot.list` separates what was asked from what is:

```
$ kelictl mcu slot.list uid=c-3f9a2b10
Layout:  auto=false;comp=2x2;size=hd720p
Vad:     full
Logo:    ives.png
Slots:
  slot  holds  pinned  part_id  name
  0     vad    -       7        alice@phone_example_com
  1     part   9       9        bob@phone_example_com
  2     free   -       -        -
  3     free   -       -        -
```

`holds` is what the slot was **told**, `pinned` **whom** you pinned there, and
`part_id`/`name` who the mixer shows **now** — for a `vad` slot the last one moves with
the speaker, which is the whole point. An empty slot reads `free`; the logo is what is
drawn in it, not something it holds.

The logo **cannot be unset** on a live conference (the media server has no reset for
it): set another one, or destroy the conference. And the server **never reports an
unreadable image** — it answers OK whatever the picture did, so `logo` is what you
asked for, and the mix (or the media server's `mcu.log`) is what tells you it loaded.
Only a failure to reach the server is reported: on `conference.update` you get the
error, on `conference.create` it is logged and the conference is created without a logo
(a picture must not be why a conference does not exist).

Three more things worth knowing: **`PUT` merges** (an omitted field is left alone, not
reset), an **unknown or read-only field is a `400`** rather than a silent no-op,
and **the DID is not a URL** — a client holding only a DID uses
`conference.list did=8001` and follows the `uid`.

Each command declares the status of every failure it can produce, and both
frontals answer with it: `404` for a DID or participant that does not exist, `409`
for a DID already in use or a conference that is not empty, `503` when the media
server does not answer, `400` for a bad argument. `kelictl` turns the same
declaration into its exit code (`3` not found, `4` conflict, `5` unavailable, `2`
bad argument) — see
[administration.md](../administration.md#exit-codes).

On the CLI each of these renders as text, from the same declaration: a list is a
table of the columns that identify a row, and `show` is one `Label: value` per
line, with the wire integers of §3.6 spelled out (`size=hd720p`, `comp=2x2`,
`vad=basic`) — the API and the XML-RPC keep the numbers. What it prints is what it
accepts: the names above are the ones read back here.

```
$ kelictl mcu conference.list domain=example.com
name    domain       did   uid         max_participants  created_at
Weekly  example.com  8000  c-3f9a2b10  8                 2026-08-03 09:59:39Z

$ kelictl mcu conference.show uid=c-3f9a2b10
Name:               Weekly
Domain:             example.com
…
Layout:             auto=true comp=2x2 size=hd720p
Participants:
  part_id  name   from                     state      joined_at
  7        alice  alice@phone.example.com  connected  2026-08-03 10:02:11Z
```

The media detail of a leg is one level down, in `participant.show`, where the
negotiated medias and the media server's own per-media statistics each get a
block (one line per media).

`kelictl status` carries the module's own line, and `stale` is the count of
conferences whose media server went away (their DID answers `503` until it
returns, then they are recreated with the same `uid`):

```
modules:         mcu
mcu:             conferences 2, mediaservers 1/1 up, participants 5, stale 0
```

## Events

Two messages reach a **participant's scenario** and must be handled, or they rot
in its mailbox:

```elixir
{:mcu_event, :fpu_requested}        # the mixer needs a fresh intra-frame from this leg
{:mcu_event, :server_disconnected}  # the mix is gone: BYE and leave
```

`:fpu_requested` is answered with an INFO carrying RFC 5168
`picture_fast_update` (`mcu.exs` does it). A kicked leg additionally receives the
standard `{:scenario_ctl, :shutdown, :kicked}`.

Node-level events (`conference.created`, `participant.joined`,
`participant.left`, `conference.recording_started` / `_stopped`,
`conference.slot_changed`, `mediaserver.down` …) are **logged**, one line per event
carrying the conference `uid`, and counted in the Prometheus metrics
(`kelix_mcu_calls_total{result}`, `kelix_mcu_participants{mcu,conference}`,
`kelix_mcu_rpc_errors_total{method,reason}` …). They are not delivered to
scripts. See [§3.1 of the guide](../../mcu_module_guide.md#31-what-a-successful-join-looks-like).

## Examples

```toml
# config.toml
[module.mcu]
rate             = 32000
max_participants = 8
did_range        = "8000-8099"
vad              = "full"
layout_comp      = "2x2"
video_size       = "hd720p"
record_dir       = "/var/lib/kelixip/rec"    # on the media server
image_dir        = "/var/lib/kelixip/img"    # idem
logo_file        = "ives.png"                # every empty mosaic slot
medias           = ["audio", "video", "text"]
dtmf             = true

[mediaserver.pool.mcu1]
module = "mendooze"
url    = "http://10.0.0.12:9090"
```

```toml
# domains.toml
[[domain]]
name = "example.com"

  [[domain.call]]
  pattern = "8XXX"
  script  = "mcu.exs"
```

```bash
# create a room, then dial its DID from a phone on example.com
$ kelictl mcu conference.create domain=example.com name=Weekly max_participants=8
$ kelictl mcu conference.list domain=example.com
$ kelictl mcu participant.list uid=c-3f9a2b10

# pin a 2x2 in HD for a demo, then hand the layout back to the module
$ kelictl mcu conference.update uid=c-3f9a2b10 layout='2x2 hd720p'
$ kelictl mcu conference.update uid=c-3f9a2b10 layout=auto

# record a meeting for review, watching the VAD move the speaker meanwhile
$ kelictl mcu recording.start uid=c-3f9a2b10 file=demo.mp4
$ kelictl mcu slot.update uid=c-3f9a2b10 slot=0 holds=vad
$ watch -n1 kelictl mcu slot.list uid=c-3f9a2b10
$ kelictl mcu recording.stop uid=c-3f9a2b10
```

```elixir
# the join path, in a `uas(:invite)` scenario — apps/kelixip/scripts/mcu.exs in full
case Kelix.Mod.Mcu.admit(sip_ctx.domain, req) do
  {:ok, conf, part} ->
    ctx_set(:username, conf.did)                    # local identity of this leg
    appdata_set(:mcu_part, part)
    appdata_set(:media_conn_opts, mcu_participant: part)
    appdata_set(:mediaserver_instance, Kelix.Mod.Mcu.media_config(conf))
    media_connect()
    reply_invite(180, "Ringing")

  {:error, :no_such_conference} -> reply(404, "Not Found")
  {:error, :full} -> reply(486, "Busy Here")
  {:error, :mcu_down} -> reply(503, "Service Unavailable")
  {:error, _} -> reply(500, "Server Internal Error")
end
```

A script that calls this module must declare it, or it is refused at load:

```elixir
config uses_modules: [:mcu]
```
