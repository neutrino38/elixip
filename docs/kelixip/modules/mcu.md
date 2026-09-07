# Multi Conference Unit

This module provides an audio / video / text conferencing service. Each conference
is identified by a SIP number (DID) and is joined by calling it. It is an
old-style MCU, mixing the picture, the audio and the text on the server.

This module requires a medooze mediaserver up and running and configured
in the pool. See
[§1.1 of the guide](mcu_module_guide.md#11-what-must-be-true-before-a-call-can-succeed)
for the four things that must be true before a call can succeed.

**Important limitation:** for now, it is not possible to mix in a single scenario
MCU functions and regular JSR 309 media functions.

> This page is the reference: installing, configuring, the script API and the
> commands. Running and troubleshooting a node — prerequisites, the announced media
> address, metrics, reading the logs of a call that failed — is the
> [operating guide](mcu_module_guide.md). There is also a
> [design document](../../design/DESIGN-MCU.md) that lists design decisions and
> limitations. The reference call script is
> [`apps/kelixip/scripts/mcu.exs`](../../../apps/kelixip/scripts/mcu.exs).

## Installing and activating the module

### Installing the `kelixip-mod-mcu` package:

`dnf install kelixip-mod-mcu` / `apt install kelixip-mod-mcu`

### Declaring the module in config.toml

Add an `[module.mcu]` section in the `/etc/kelixip/config.toml` file.

Example:

```toml
# config.toml
[module.mcu]
rate             = 32000
max_participants = 8
did_range        = "8000-8099"
vad              = "full"
layout_comp      = "2x2"
video_size       = "hd720p"
preferred_video_codec = "H264"               # stated first in the answers
record_dir       = "/var/lib/kelixip/rec"    # on the media server
image_dir        = "/var/lib/kelixip/img"    # idem
logo_file        = "ives.png"                # every empty mosaic slot
medias           = ["audio", "video", "text"]
dtmf             = true
# the collaboration channel: closed until the kinds are declared
message_kinds    = ["hand.raised", "hand.lowered", "floor.request", "floor.grant"]
```

Every key has a default, so an empty `[module.mcu]` block is a valid one. The full
list is in [Module configuration reference](#module-configuration-reference) below.

### Check the mediaserver availability

Make sure that `/etc/kelixip/config.toml` contains at least one defined
mediaserver in the pool:

```toml
[mediaserver.pool.ms1]
module = "mendooze"
url    = "http://10.0.0.12:9090"   # the media server's XML-RPC port (--http-port)
```

If there is none, install and configure a mediaserver, then declare it here.

### Configuring a call script to handle MCU calls

The package comes with a sample script,
[`mcu.exs`](../../../apps/kelixip/scripts/mcu.exs), installed in `script_dir`. Copy
it and adapt it; then point a dial rule at it, in `/etc/kelixip/domains.toml`:

```toml
# domains.toml
[[domain]]
name = "example.com"

  [[domain.call]]
  pattern = "8XXX"          # must cover the did_range above
  script  = "mcu.exs"       # joins an existing conference, else 404
```

A second sample, [`mcu_adhoc.exs`](../../../apps/kelixip/scripts/mcu_adhoc.exs),
*creates* the conference on the first call to a free DID instead of answering `404`.

### Activating inter participant messaging

The module lets the call scripts of the participants exchange messages, as
described in a section below — advanced call scenarios use it to implement rich
features such as _raise hand_. The message kinds exchanged must be declared in
config.toml:

```toml
[module.mcu]
(...)
message_kinds    = ["hand.raised", "hand.lowered", "floor.request", "floor.grant"]
```

### Restart kelixip

`sudo systemctl restart kelixip`


## Module configuration reference

Module block — `[module.mcu]` (in `config.toml`):

| Key | Type | Default | Description |
|---|---|---|---|
| `vad` | name or integer | `basic` | Voice activity detection: `none` / `basic` / `full` (or `0` / `1` / `2`) |
| `rate` | integer | `32000` | Mixer sampling rate: `8000`/`16000`/`32000`/`48000`. Participants are resampled to it |
| `medias` | list | `["audio","video","text"]` | Which `m=` sections a conference answers. An omitted media is answered **port 0** — this is how video or text is turned off. Which codecs are accepted inside a media is the media server's decision, not a config key |
| `dtmf` | boolean | `true` | Propose telephone-event (RFC 4733) on audio |
| `max_participants` | integer | `20` | Per-conference cap; reached ⇒ the next caller gets `486` |
| `destroy_when_empty` | boolean | `false` | Destroy a conference with its last participant |
| `auto_layout` | boolean | `true` | The mosaic follows the number of video legs |
| `layout_comp` | name or integer | `2x2` | Starting mosaic — one of `1x1 2x2 3x3 3+4 1+7 1+5 1+1 pip1 pip3 4x4 1+4 2+8` (or its wire id) |
| `video_size` | name or integer | `hd720p` | Encoded size — one of `qcif cif vga pal hvga qvga hd720p wqvga xga wvga` (or its wire id). Also the size of the mosaic canvas: the two are one picture |
| `video_fps` | integer | `30` | Encoded frame rate |
| `video_bitrate` | integer | `[mediaserver] video_bitrate` (`1500`) | kbps, also the cap on the answer's `b=AS:`. Set it here to give conferences a bitrate of their own |
| `video_intra_period` | integer | `300` | Frames between intra-frames |
| `preferred_video_codec` | name | — | The video codec the answers state **first**, hence what the mixer encodes towards a leg that offered it: `H264` / `VP8` / `AV1`, or `none`. It reorders, it never adds — a codec the caller did not offer, or one the media server refused, is logged and ignored |
| `logo_file` | string | — | Image drawn in **every empty mosaic slot**, on every conference (a bare name under `image_dir`) |
| `conference_file` | string | — | File holding the conference **definitions**, on **this** host. Set it and the rooms come back after a restart (see below). Unset ⇒ no persistence |
| `record_dir` | string | — | Directory the media server writes recordings into. Unset ⇒ `recording.start` refuses |
| `image_dir` | string | — | Directory the media server reads `logo_file` (and `logo=`) from |
| `did_range` | string | — | Allocation pool for a `create` that omits `did` (`"8000-8099"`) |
| `did_ranges` | table | `{}` | Per-domain override: `{ "example.com" = "8000-8199" }` |
| `xmlrpc_timeout_ms` | integer | `10000` | Per-RPC bound towards the media server |
| `call_timeout_ms` | integer | `5000` | Upper bound on a facade call (ms) |
| `shutdown_grace_ms` | integer | `5000` | Grace given to conferences at module stop |
| `rtp_timeout_ms` | integer | `10000` | RTP inactivity watchdog, armed per media at the ACK. `0` disables it. Never armed on text, disarmed on a media the peer holds; a leg goes only when **every** watched media is silent |
| `gc_orphans` | boolean | `true` | Sweep, at start, the conferences the media server still holds and no kelixip owns |
| `message_kinds` | list | `[]` | The message kinds the collaboration channel accepts (see below). **Empty = the channel is closed** |
| `message_rate` | integer | `5` | Messages per second and per participant (burst: twice that) |
| `message_max_bytes` | integer | `1024` | Longer payloads are refused, never truncated |
| `message_queue_max` | integer | `100` | A leg whose script is that far behind is skipped rather than fed |

`vad`, `layout_comp` and `video_size` take the same names the CLI renders and the
control commands accept — one vocabulary, wherever a value enters.

**`record_dir` and `image_dir` are paths on the mediaserver host**, not on the kelixip host.

With neither `did_range` nor a `did_ranges` entry for a domain, `did` becomes
**mandatory** on create. An explicit DID is always honoured, including one
outside the range.


## Using the module in an elixip script

The MCU module is meant to be used inside an INVITE UAS scenario. The scenario
pulls in the MCU macros and declares that it needs the module:

```elixir
use SIP.Scenario
use SIP.Session.CallUAS
use Kelix.Mod.Mcu           # the admit / leave / mcu_* macros, and Mcu.SBB

uas :invite
config uses_modules: [:mcu]
```

`uses_modules` is what makes kelixip refuse to load the script when the module is
not installed, instead of failing on the first INVITE.

The module publishes two kinds of thing, and the difference is worth holding on
to: **functions and macros a script calls for a decision**, and **blocks a script
enters for a sequence**. `admit()` is a decision — it answers "may this leg
join", and the script turns that answer into a SIP response.
`Mcu.SBB.conference()` is a sequence — it holds the leg for the whole call and
comes back when something happens the script has a policy for.

The module **decides**, the script **composes the SIP response**. So the scenario
must also define the functions the macros delegate to:

| Function | Called by | What it does |
|---|---|---|
| `do_admit(sip_ctx, req, dialog_pid, domain)` | `admit/2` | maps an admission refusal onto a SIP response, returns the context |
| `do_leave(sip_ctx, reason)` | `leave/1` | releases the participant |
| `do_attach(sip_ctx)` | `attach/0` | decides which failures the call survives — only needed by a script that attaches by hand instead of taking `Mcu.SBB.conference()` |

The sample script [`mcu.exs`](../../../apps/kelixip/scripts/mcu.exs) implements
them; copy it rather than write them from scratch.


## Macros usable in a scenario

These rebind the scenario context in place, like the other FSL verbs: they return
nothing and their verdict is read from `sip_ctx.lasterr`.

### admit(req, dialog_pid)

```elixir
admit(req, dialog_pid)     # verdict in sip_ctx.lasterr
```

Processes an INVITE request and
- checks that the user part of the INVITE's R-URI matches an existing conference
  SIP number,
- reserves a seat for the participant in that conference,
- produces a verdict on whether the participant can join the conference or not.

The verdict, in `sip_ctx.lasterr`, is:
- `:ok` — admitted. The conference and the participant handle are stored in the
  scenario appdata, under `:mcu_conf` and `:mcu_part`, where `attach()` and
  `leave()` read them back;
- `{:error, :no_such_conference}` — no running conference with a DID matching the R-URI;
- `{:error, :full}` — the conference has no room for a new participant;
- `{:error, :mcu_down}`, `{:error, :down}`, `{:error, :timeout}` — a technical failure;
- `:jsr309_media_already_in_use` — this SIP session already runs a JSR 309 media
  session (the two are mutually exclusive).

The good practice is:
- to send back a `100 Trying` **before** calling `admit()`,
- call `admit()`,
- if the participant can be accepted, the scenario may check in a database or using
  an external API that this conference is open, not expired and that the participant
  has the necessary authorization. It is a good practice to send `180 Ringing` before
  those checks,
- if `admit()` returns an error verdict, send back a SIP response mapping it,
  typically `404` / `486` / `503` / `500`.

`admit()` also **wires the leg**, so a script goes straight to `media_connect()`:

| It sets | To | Because |
|---|---|---|
| `:username` | the conference's DID | the local identity of the leg — what an in-dialog request we originate puts in From/To, and what `send_BYE()` builds its URI from |
| `:media_conn_opts` | `mcu_participant:` + `nat_latch: true` | which conference the leg joins, and the fact that a leg which *answers* an offer must latch onto where the media really comes from (every handset behind a NAT writes its private address) |
| `:mediaserver_instance` | `media_config(conf)` | a conference is pinned to the MCU it was created on: the leg must reach the server holding the mixer, not whatever the media pool would hand out |

None of that is a call-flow decision, so no script has to state it. A script that
needs other connection options sets `:media_conn_opts` again after `admit()` — the
last write wins.

See the [`mcu.exs`](../../../apps/kelixip/scripts/mcu.exs) sample script for more
explanation.

### attach()

```elixir
attach()                   # verdict in sip_ctx.lasterr
```

Actually puts the participant in the mix. It is called on the ACK and works on the
participant handle `admit()` stored in the appdata.

A script that takes `Mcu.SBB.conference()` never calls this: the block owns the
ACK-time sequence, including the retransmitted ACKs that must not re-run it. The
macro stays for a script that holds the leg by hand.

### leave(reason)

```elixir
leave(reason)              # e.g. leave(:bye)
```

Removes the participant from the conference and releases its seat. It tolerates an
already-removed participant, so it can be called from every teardown path.

### mcu_accept_messages() / mcu_send(target, kind, payload, opts)

The inter participant collaboration channel — see
[Inter participant collaboration](#inter-participant-collaboration) below.


## Blocks usable in a scenario

### Mcu.SBB.conference(opts)

The leg's whole life in the mix, as one service building block. A scenario enters
it once the call is answered, and it runs on the scenario's own process, dialog
and mailbox until something happens the script has a policy for.

```elixir
state in_conference do
  Mcu.SBB.conference()

  on_events do
    # the call is whole: answer, then go back into the mix
    {:conference, :renegotiation, %{method: method}} ->
      reply_invite_with_sdp(200, media: :tc, webrtc: :if_offered)
      goto loop, "#{method} renegotiated"

    {:conference, :message, %{envelope: envelope}} ->
      Logger.info("#{envelope.kind} from #{envelope.from.part_id}")
      goto loop, "collaboration message"

    # the leg is out: released and removed, only the verdict is yours to name
    {:conference, :caller_hung_up, %{reason: reason}} -> scenario_success("BYE")
    {:conference, :cancelled, _}                     -> scenario_success("cancelled")
    {:conference, :mcu_lost, _}                      -> scenario_success("mcu lost")
    {:conference, :media_timeout, %{media: media}}   -> scenario_success("silent #{media}")
    {:conference, :attach_refused, %{reason: r}}     -> scenario_failure("not mixed")
    {:conference, :idle_timeout, _}                  -> scenario_failure("idle timeout")
  end
end
```

What the block absorbs is the SIP a conference leg owes whatever the deployment:
the ACK that puts the participant in the mix and the retransmitted copies that
must not re-run it, an INFO answered `200` whether or not it asks for a video
frame, the RFC 5168 frame requests in both directions, a BYE answered before the
slot is released, our own BYE followed by a wait for its `200`, and a leg gone
silent hung up.

What it leaves you is what a deployment actually decides. **It never composes a
response to an offer** — that is why it takes no `media:` and no `webrtc:`: your
`answering` state states the `200`, and a renegotiation comes back for you to
answer the same way, or refuse.

**Options** — one, through `args`:

| Key | Default | Meaning |
|---|---|---|
| `:idle_timeout` | `7_200_000` | the backstop against a leg that stops sending, in ms. **Idle**, not a budget: every event the block consumes re-arms it, so it is not a maximum call duration |

**What it answers.** Two families, and the difference is what state the leg is
left in. These two hand the call back **whole** — nothing answered, nothing
released — so you act and re-enter with `goto loop`:

| Outcome | Data |
|---|---|
| `:renegotiation` | `%{method: :INVITE \| :UPDATE, req, transaction, dialog}` — **unanswered** |
| `:message` | `%{envelope}` — a peer's script said something |

These mean the leg is out: the media connection is released and the participant
removed, with the reason named. You name the verdict; you free nothing.

| Outcome | Data |
|---|---|
| `:caller_hung_up` | `%{reason: :bye \| term}` — a BYE, answered, or the dialog went away |
| `:cancelled` | `%{}` — a CANCEL around the answer |
| `:mcu_lost` | `%{via: :mcu_event \| :ms_event, bye_answered: boolean}` |
| `:media_timeout` | `%{media, bye_answered: boolean}` |
| `:idle_timeout` | `%{bye_answered: boolean}` |
| `:attach_refused` | `%{reason}` — the mix refused the leg at ACK time |

**Answer the renegotiation first, then do your bookkeeping.** Between two entries
the call is up and nothing answers it, and the far end has protocol deadlines: an
unanswered re-INVITE runs at timer B. Coming back in needs no flag — the block
reads where the leg is from the appdata, so a re-INVITE's own ACK re-attaches and
an UPDATE (which has no ACK, RFC 3311) re-attaches on re-entry, while a
collaboration message re-attaches nothing.

Refusing a renegotiation with a `488` is supported and does the right thing: no
ACK follows a non-2xx, so nothing re-attaches and the leg keeps the media it had.

**`goto loop` is what re-enters the block** — it re-runs the state body, which
calls `conference()` again. Use `goto loop` rather than `stay` in these arms: only
re-running the body re-arms the idle deadline.

A script keeping the old hand-written loop still works — `attach()` and `leave()`
are still there. It is on its own for the drift, which is what the block exists
to stop.


## Functions exported by the module

Called with their full name (`Kelix.Mod.Mcu.mute(part, :audio, true)`), on the
participant or conference handle the appdata carries.

### media_config(conf)

```elixir
media_config(conf) :: keyword    # -> appdata_set(:mediaserver_instance, …)
```

The adapter + URL of the MCU this conference is pinned to. A leg must reach the
server holding the mixer, not whatever the media pool would hand out.

### In-call functions

```elixir
send_fpu(part)          :: :ok | {:error, term}   # ask the MCU for an intra-frame
mute(part, media, on?)  :: :ok | {:error, term}   # media :: :audio | :video
kick(uid, part_id)      :: :ok | {:error, :not_found | term} # ask one participant to get out of a conference
```

`kick/2` asks that leg's scenario to wind down (BYE + teardown); it does not cut
the media under a live dialog.

### Inter participant collaboration

The call scripts of the participants can send messages to each other, which is the
base for a _raise hand_ indication for instance. The script activates the feature
right after participant admission:

```elixir
# in a uas(:invite) scenario, once the leg is admitted
mcu_accept_messages()
```

Nothing is delivered to a leg that did not call it. Then it can send messages:

```elixir
mcu_send(target, kind, payload, opts \\ [])
# outcome in appdata_get(:mcu_last_send):
#   {:ok, %{delivered: n, skipped: [%{part_id: id, reason: atom}]}} | {:error, atom}
```

`kind` must be one of the `message_kinds` declared in `config.toml`, and `payload`
is a UTF-8 binary the module does not interpret. `target` can be:
- `:all` — all participants of the conference including me!
- `:others` — all _other_ participants
- `{:part_id, 7}` — a participant designated by its ID
- `{:name, "alice"}` — a participant designated by its name

What the channel guarantees, and what it does not:

* `delivered` counts the **scenarios the message was handed to** — not the phones that
  received something, and not the humans who saw it;
* order is preserved **per sender**; two participants' messages may arrive in different
  orders at different legs. `seq` lets a script notice it;
* no acknowledgement, no retry, and **no history**: a leg that joins later sees nothing
  that was sent before it arrived;
* a refusal (over the rate, unknown kind, payload too long) **never ends the call**:
  unlike `admit`/`attach`, the outcome goes to `appdata_get(:mcu_last_send)`, not to
  `lasterr`, so a following `goto` is unaffected;
* forwarding a message you received? Pass its `msg_id: envelope.msg_id` — the module
  refuses to fan the same id out twice, which is what stops a rebroadcast storm.

Outside a scenario, the same two operations are plain functions on the participant
handle:

```elixir
accept_messages(part)                        :: :ok | {:error, :no_such_participant}
send_message(part, target, kind, payload, opts \\ [])
  :: {:ok, %{delivered: n, skipped: [%{part_id: id, reason: atom}]}} | {:error, atom}
```

The script handles the incoming messages as `{:mcu_message, envelope}` events, the
envelope carrying `msg_id`, `seq`, `from`, `kind`, `payload` and `sent_at`:

A leg held by `Mcu.SBB.conference()` gets its messages as a block outcome: the
block hands the envelope back and the call is untouched, so the arm acts and
re-enters.

```elixir
on_events do
  {:conference, :message, %{envelope: %{kind: "hand.raised", from: %{display_name: who}}}} ->
    mcu_send(:others, "floor.request", who)      # or send a SIP MESSAGE, or ignore it
    goto loop, "hand raised"

  {:conference, :message, _} -> goto loop, "unsupported message ignored"
end
```

A script holding the leg by hand matches the raw `{:mcu_message, envelope}` in
every `on_events` the call goes through — a message no clause matches sits in the
mailbox for the whole call.

### Conference management

A scenario can create and manipulate conferences directly.

```elixir
create_conference(domain, opts)        :: {:ok, Conference.t()} | {:error, atom | String.t()}
ensure_conference(domain, did, opts)   :: {:ok, Conference.t(), :created | :existing} | {:error, …}
update_conference(uid, changes)        :: {:ok, [changed_field]} | {:error, atom | String.t()}
destroy_conference(uid, opts)          :: :ok | {:error, atom}
conferences(domain)                    :: [Conference.t()]
```

`ensure_conference/3` is a **get-or-create**: it creates the conference or returns
the existing one, atomically when N callers ask for the same DID simultaneously.

Options are atom-keyed keyword lists validated by exactly the same code as the
REST body, so a conference a script creates and one REST creates are
indistinguishable. The sample script
[`mcu_adhoc.exs`](../../../apps/kelixip/scripts/mcu_adhoc.exs) is this in full.

### Lookup primitives

```elixir
conference(uid)        :: {:ok, Conference.t()} | :error
lookup_did(domain, did) :: {:ok, Conference.t()} | :error
mediaserver(name)      :: {:ok, map} | :error
```


## kelictl mcu commands

Fourteen commands, available identically over `kelictl` and over REST. The
authoritative list is the running node's:

```
kelictl mcu help                  # the commands, their REST route and their args
kelictl mcu help conference.update  # one command, with each argument's own vocabulary
kelictl module list               # every loaded module, its commands and facades
```

| Command | `kelictl` |
|---|---|
| `conference.create` | `mcu conference.create domain=example.com name=Weekly` |
| `conference.list` | `mcu conference.list domain=example.com` |
| `conference.show` | `mcu conference.show uid=c-3f9a` |
| `conference.update` | `mcu conference.update uid=c-3f9a layout='1+1 vga'` |
| `conference.delete` | `mcu conference.delete uid=c-3f9a force=true` |
| `participant.list` | `mcu participant.list uid=c-3f9a` |
| `participant.show` | `mcu participant.show uid=c-3f9a part_id=7` |
| `participant.update` | `mcu participant.update uid=c-3f9a part_id=7 muted='{"audio":true}'` |
| `participant.delete` | `mcu participant.delete uid=c-3f9a part_id=7` |
| `recording.start` | `mcu recording.start uid=c-3f9a file=record.mp4` |
| `recording.show` | `mcu recording.show uid=c-3f9a` |
| `recording.stop` | `mcu recording.stop uid=c-3f9a` |
| `slot.list` | `mcu slot.list uid=c-3f9a` |
| `slot.update` | `mcu slot.update uid=c-3f9a slot=0 holds=vad` |


On the CLI, arguments are `name=value` tokens — path variables are ordinary named
arguments, so the same map reaches the module either way. A value typed
`true`/`false` is a boolean, digits an integer, and a leading `{`/`[` is JSON
(`muted='{"audio":true}'`).

A conference is **pinned** to the media server it was created on and never
migrates. `kelictl module reload mcu` has no in-place reload: the module is
restarted cleanly, which **drops the live conferences**.

### Mosaic properties

The mosaic proeprties: the video size and the VAD mode have **names**, and they are accepted
wherever a value enters — the CLI, a REST body, the config block, a script:

```bash
kelictl mcu conference.update uid=c-3f9a layout='2x2 hd720p'   # mosaic + size
kelictl mcu conference.update uid=c-3f9a layout=auto,vga       # commas: no quoting
kelictl mcu conference.update uid=c-3f9a layout=1+1            # mosaic alone
kelictl mcu conference.update uid=c-3f9a layout=cif            # size alone (encoder too)
kelictl mcu conference.update uid=c-3f9a layout=manual         # stop following
kelictl mcu conference.update uid=c-3f9a vad=full
kelictl mcu conference.create domain=example.com layout='2x2 vga' video=30fps
```

`layout` takes a **mosaic layout**, a **size** and/or `auto`|`manual`, in **any order**,
separated by spaces or commas.

| Group | Values |
|---|---|
| mosaic | `1x1` `2x2` `3x3` `3+4` `1+7` `1+5` `1+1` `pip1` `pip3` `4x4` `1+4` `2+8` |
| video size | `qcif` `cif` `vga` `pal` `hvga` `qvga` `hd720p` (`720p`) `wqvga` `xga` `wvga` |
| mode | `auto` — the mosaic adapts to the number of participants — or `manual` the mosaic layout is fixed |

Two rules:

* **only what is named changes** — `layout=vga` keeps the current mosaic other properties intact.
* **changing a mosaic layout switches it to `manual` mode**.

### The encoder profile

`video` takes the same kind of value: tokens in any order, spaces or commas, and only
what is named changes.

```bash
kelictl mcu conference.update uid=c-3f9a video='vga 30fps 1024k'
kelictl mcu conference.update uid=c-3f9a video=25fps,intra=300
kelictl mcu conference.update uid=c-3f9a video='{"fps":25}'   # the wire form still works
```

| Field | Token | Default |
|---|---|---|
| size | a size name (`vga`, `hd720p`, `720p`) | `[module.mcu] video_size` |
| frame rate | `<n>fps` | `30` |
| bitrate | `<n>k` (kbit/s) | `[module.mcu] video_bitrate` |
| intra period | `intra=<n>` (frames) | `300` |

The codec is **not** part of that profile — it is a field of its own, because it is a
preference and not a setting:

```bash
kelictl mcu conference.update uid=c-3f9a preferred_video_codec=vp8
kelictl mcu conference.update uid=c-3f9a preferred_video_codec=none   # no preference
```

The answer states that codec first, and the mixer encodes it — but only when the
caller offered it **and** the media server accepted it. Anything else keeps the
caller's own order, and the leg's log says which of the two dropped the preference.
Which codecs exist at all is the media server's answer to give, never a config key.

**The mosaic size and the encoded size are one value.** The canvas *is* the picture
the mixer encodes. Composing at one geometry and encoding at another means rescaling
between the two, and the media server does that without keeping the aspect ratio — a
VGA mosaic encoded in HD720p stretches every tile. So the two always match:

* `layout='2x2 vga'` composes **and** encodes in VGA;
* `video=hd720p` moves the canvas to HD720p;
* name both with different sizes and the **encoded** one wins; the log says so.

A new profile applies to the participants that **join next**. A participant already
in the conference keeps the profile it negotiated.

### Rooms that survive a restart

```toml
[module.mcu]
conference_file = "/var/lib/kelixip/conferences.json"
```

With that key set, every conference created through REST or `kelictl` is written to
that file and **recreated at the next start** — same `uid`, same DID, same profile.
The calls are not: a restart ends them, and the file holds rooms, not conversations.
So a restored conference shows up empty, and `stale` until its media server's control
channel is up.

A conference a **script** created for one call is deliberately *not* persisted: it was
made to serve that call. A script that wants a standing room asks for one explicitly
(`owner: :none`), and `conference.show` tells the two apart with `Persistent`.

The file is JSON, rewritten whole whenever a definition changes, and readable — you can
pre-declare a room in it before starting the node, using the same names the CLI takes:

```json
{"version": 1, "conferences": [
  {"uid": "c-standing", "domain": "example.com", "did": "8500", "name": "Salle Nord",
   "mcu": "mcu1", "vad": "full", "video": {"size": "hd720p"},
   "preferred_video_codec": "H264", "layout": {"comp": "2x2", "auto": true}}
]}
```

Two failure rules worth knowing: a file kelixip cannot parse is **left untouched** and
persistence is off for that run (the log says so — fix the file and restart, nothing is
overwritten meanwhile), and a single malformed entry costs only its own room.

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

`file` and `logo` are **bare names**, recorded under `record_dir` / `image_dir` on the
mediaserver host. Absolut path are rejected. The extension decides
the file format (`.mp4` or `.flv`, nothing else). One recording per conference — a second
`recording.start` will be reject.

Slots in a mosaic are **starting at 0**. Pinning a slot **turns the automatic layout off**.

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

The logo **cannot be unset** on a live conference: set another one, or destroy the
conference.

Failures come back as a `kelictl` exit code (`2` bad argument, `3` not found,
`4` conflict, `5` unavailable) — see
[administration.md](../administration.md#exit-codes); the HTTP status of each command
is in [mcu-api.md](mcu-api.md#7-statuses-and-retry-semantics).


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
{:mcu_event, :fpu_requested}          # the mixer needs a fresh intra-frame from this leg
{:mcu_event, :server_disconnected}    # the mix is gone: BYE and leave
{:mcu_event, :media_timeout, media}   # every watched media is silent: BYE and leave
{:mcu_event, :media_connected, media} # first validated packet of a reception cycle
```

A third one reaches a leg **only if its script asked for it** with
`mcu_accept_messages()` (see
[Inter participant collaboration](#inter-participant-collaboration)):

```elixir
{:mcu_message, envelope}            # a peer's script is saying something
```

`:fpu_requested` is answered with an INFO carrying RFC 5168 `picture_fast_update`
([`mcu.exs`](../../../apps/kelixip/scripts/mcu.exs) does it). A kicked leg
additionally receives the standard `{:scenario_ctl, :shutdown, :kicked}`.

Node-level events (`conference.created`, `participant.joined`,
`participant.left`, `conference.recording_started` / `_stopped`,
`conference.slot_changed`, `participant.message`, `mediaserver.down` …) are **logged**,
one line per event carrying the conference `uid`, and counted in the Prometheus metrics
(`kelix_mcu_calls_total{result}`, `kelix_mcu_participants{mcu,conference}`,
`kelix_mcu_rpc_errors_total{method,reason}` …). They are not delivered to
scripts. See [§3.1 of the guide](mcu_module_guide.md#31-what-a-successful-join-looks-like).

## Examples

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

## REST API

Every `kelictl mcu` command above is also an HTTP endpoint under `/modules/mcu`.
The complete wire contract — endpoints, arguments, JSON payloads, object shapes,
vocabularies and statuses — is **[mcu-api.md](mcu-api.md)**, written to be enough on
its own to implement a client:

| | |
|---|---|
| Endpoint reference | [mcu-api.md §4](mcu-api.md#4-endpoint-reference) |
| Object shapes | [mcu-api.md §5](mcu-api.md#5-object-shapes) |
| Vocabularies (`layout`, mosaics, sizes, VAD) | [mcu-api.md §6](mcu-api.md#6-vocabularies) |
| Statuses and retry semantics | [mcu-api.md §7](mcu-api.md#7-statuses-and-retry-semantics) |
| Discovery — `GET /modules/mcu` | [mcu-api.md §8](mcu-api.md#8-discovery--get-modulesmcu) |
| A worked session | [mcu-api.md §10](mcu-api.md#10-a-worked-session) |

The address, the port and the authentication of the REST frontal are core settings
(`[control_api]` in `config.toml`) and are documented in
[rest-api.md](../rest-api.md#enabling--authentication-boundary-concern).


