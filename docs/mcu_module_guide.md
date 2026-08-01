# The conferencing module — operator and developer guide

`kelixip-mod-mcu` (`Kelix.Mod.Mcu`) turns a kelixip node into a conferencing server:
an INVITE whose R-URI user-part matches a conference DID joins that conference, audio
and video are mixed by a Medooze media server, and the conferences themselves are
managed over REST, `kelictl`, or from a call script.

This is the *how*. The *why* — every decision, every limitation and what was
deliberately left out — is [docs/design/mcu_module.md](design/mcu_module.md), and the
section numbers below point into it.

Three readers are served, in order: whoever **runs** a node, whoever **writes a
script**, and whoever **debugs a call that did not work**.

---

## 1. For the operator

### 1.1 What must be true before a call can succeed

Four things, and a missing one fails in a way that looks like something else:

1. the **media server** is reachable at the configured URL (`kelictl status` says
   `mediaservers 1/1 up`);
2. a **conference exists** on the DID the caller dials (`kelictl mcu conference.list`);
3. a **dial rule** on that domain routes the DID to `mcu.exs` — the module allocates
   DIDs, it does not edit `domains.toml`, so the two can drift apart. `create` warns
   when they have;
4. the module is **loaded** (`kelictl status`, `modules:` line). Unlike `registrar` and
   `auth_db`, this module is useless without a media server: installing the `.beam` is
   half of it.

### 1.2 Configuration — `[module.mcu]` in `config.toml`

Infrastructure, so `config.toml` and not `domains.toml`; a change needs a restart
(`kelictl module reload mcu` restarts the module cleanly and **drops live
conferences** — see §5.2).

```toml
[module.mcu]
# Mixer defaults, applied to a conference created without the field.
vad                 = 1          # 0 none | 1 basic | 2 full
rate                = 32000      # 8000 | 16000 | 32000 | 48000 — see below
audio_codecs        = ["OPUS", "G722", "PCMA", "PCMU", "TELEPHONE-EVENT"]
video_codecs        = ["H264"]
max_participants    = 20
destroy_when_empty  = false
auto_layout         = true       # the mosaic follows the number of video legs
layout_comp         = 1          # starting layout (§3.6 of the design: 1 = 2x2)

# DID allocation pool, used when `create` omits `did`. An explicit DID is always
# honoured, including one outside the range. Omit both keys to make `did` mandatory.
did_range           = "8000-8099"
did_ranges          = { "example.com" = "8000-8199", "lab.example.com" = "9000-9099" }

# The inline video profile: what the mixer encodes towards every leg.
video_size          = 6          # 6 = HD720P (§3.6)
video_fps           = 15
video_bitrate       = 1024       # kbps, also the cap on the answer's b=AS:
video_intra_period  = 300

xmlrpc_timeout_ms   = 10000      # per-RPC bound
call_timeout_ms     = 5000       # facade bound (Kelix.Module.safe_call)
shutdown_grace_ms   = 5000
rtp_timeout_ms      = 10000      # ignored until the server-side watchdog of P7
gc_orphans          = true       # sweep conferences no controller owns (§9.4)

# The media servers are NOT declared here: they are the [mediaserver.pool.*] entries,
# the same block the point-to-point path uses. One control channel per `mendooze`
# entry; a conference is pinned to the one it was created on.
[mediaserver.pool.mcu1]
module = "mendooze"
url    = "http://10.0.0.12:9090"
```

**`url` is the media server's XML-RPC port** — the `--http-port` it was started with
(9090 in the IVèS deployment, *not* 8080). The module talks to `POST <url>/mcu`, a
different endpoint from the JSR-309 `/jsr309` the point-to-point adapter uses.

**The media address is the media server's own setting, not kelixip's.** It reports it
on every `StartReceiving`, and that is what goes in the answer's `c=` line and in the
ICE candidates. On the media server:

* `mediaserver --public-ip <ip>` sets it; **behind a NAT it is mandatory** — it must
  be the address reachable from the callers, which is not the one the server binds
  (it binds `0.0.0.0`);
* without the flag the server auto-detects the first non-loopback IPv4 of its host
  name, which is right on a flat network and wrong behind NAT;
* the server logs what it settled on at startup (`-RTPSession announced IP …`) and
  **refuses to start** if it cannot determine one;
* a media server too old to report the address gets its calls refused with `500` and
  a log line saying so — kelixip deliberately keeps no address to fall back on, since
  a guessed one produces a call that connects and never carries media.

**`rate` is the mixer's sampling rate, not a codec constraint.** The server accepts
8000/16000/32000/48000 and resamples every participant to its own codec rate, so a
G.711 phone in a 32 kHz conference costs nothing but the transrating. Any other value
is refused at boot.

**`audio_codecs` doubles as the DTMF switch**: `TELEPHONE-EVENT` in the list means
"offer telephone-event", it is not a codec the mixer knows. Codec names are validated
at boot *and* on every `create`, against what the SDP layer can actually emit
(`PCMU PCMA G722 OPUS` / `H264 VP8` / `T140 T140RED`) — a name it cannot emit is a
configuration error, never a call that fails later.

### 1.3 Routing the DIDs — `domains.toml`

```toml
[[domain]]
name = "example.com"

  # First match wins on the R-URI user-part. This must cover the did_range above.
  [[domain.call]]
  pattern = "8XXX"
  script  = "mcu.exs"
```

`mcu.exs` joins a conference that **already exists** and answers `404` otherwise.
Point the rule at `mcu_adhoc.exs` instead and the first caller on a DID *creates* the
room (see §2.3) — with the consequence that whoever reaches the DID can create one,
so protect the perimeter upstream.

### 1.4 The control surface

Every command exists identically over REST and `kelictl`, from one declaration.

| What | REST | `kelictl` |
|---|---|---|
| create | `POST /modules/mcu/conferences` | `kelictl mcu conference.create domain=example.com name=Weekly` |
| list | `GET /modules/mcu/conferences?domain=…&did=…` | `kelictl mcu conference.list domain=example.com` |
| show | `GET /modules/mcu/conferences/:uid` | `kelictl mcu conference.show uid=c-3f9a` |
| update | `PUT`/`PATCH` `/modules/mcu/conferences/:uid` | `kelictl mcu conference.update uid=c-3f9a layout='{"comp":6}'` |
| destroy | `DELETE /modules/mcu/conferences/:uid` | `kelictl mcu conference.delete uid=c-3f9a force=true` |
| participants | `GET /modules/mcu/conferences/:uid/participants` | `kelictl mcu participant.list uid=c-3f9a` |
| one participant | `GET …/participants/:part_id` | `kelictl mcu participant.show uid=c-3f9a part_id=7` |
| mute | `PUT`/`PATCH` `…/participants/:part_id` | `kelictl mcu participant.update uid=c-3f9a part_id=7 muted='{"audio":true}'` |
| disconnect | `DELETE …/participants/:part_id` | `kelictl mcu participant.delete uid=c-3f9a part_id=7` |

```bash
# create: 201 + Location, and the DID the caller must dial
curl -si -X POST localhost:8090/modules/mcu/conferences \
     -H 'content-type: application/json' \
     -d '{"domain":"example.com","name":"Weekly","max_participants":8}'
# HTTP/1.1 201 Created
# location: /modules/mcu/conferences/c-3f9a2b10
# {"result":{"uid":"c-3f9a2b10","did":"8000","conf_id":42,"mcu":"mcu1"}}
```

Four things worth knowing:

* **`PUT` merges.** A field you omit is left alone, never reset to its default.
  `vad`/`rate`/`layout` reach the mixer immediately; `video`, `max_participants`,
  `destroy_when_empty` and `name` are local and apply to **new** participants — a live
  encoder is not renegotiated. Lowering `max_participants` below the current count
  disconnects nobody, it refuses the next caller;
* **an unknown or read-only field is a `400`**, not a silent no-op. Mistyping
  `max_participant` tells you so;
* **the DID is not a URL.** A client that only knows the DID uses
  `GET /modules/mcu/conferences?domain=example.com&did=8001` and follows the `uid`;
* **the flat form works too** (`POST /modules/mcu/conference.create`), for a client
  that cannot build URLs. Same handler, same result. `/mosaics`, `/mixers` and
  `/listeners` are reserved and answer `404` — they are not half-implemented.

### 1.5 Reading the state

```
$ kelictl status
…
modules:         mcu
mcu:             conferences 2, mediaservers 1/1 up, participants 5, stale 0
```

`stale` counts conferences whose media server went away: their DID still answers, but
with `503` until the server comes back, at which point they are recreated
automatically with the same `uid` (§9.2).

### 1.6 Metrics

Prometheus, on the `[metrics]` port:

| Metric | Read it for |
|---|---|
| `kelix_mcu_calls_total{result}` | the funnel: `joined` versus `404` / `486` / `488` / `503` / `500`. A rising `486` means conferences are full; a rising `488` means callers offer codecs you do not accept |
| `kelix_mcu_conferences{mcu}` / `kelix_mcu_participants{mcu,conference}` | occupancy |
| `kelix_mcu_mediaserver_up{mcu}` | the module's own view of its control channel — distinct from `kelix_mediaserver_up`, which is the point-to-point *pool*'s view |
| `kelix_mcu_rpc_duration_seconds{method}` | the first place to look when calls get slow to set up: every leg's setup is a handful of these in series |
| `kelix_mcu_rpc_errors_total{method,reason}` | **any** non-zero value here deserves a look. `reason` is bounded (`mcu_error`, `timeout`, `unreachable`…); the server's own message is in the log line above |

---

## 2. For whoever writes a script

The module decides resource policy; the script decides SIP policy. It maps verdicts
onto codes and holds no policy of its own — that separation is what lets a deployment
change the SIP behaviour without touching the module.

### 2.1 The call path

```elixir
# in a `uas(:invite)` scenario — see apps/kelixip/scripts/mcu.exs in full
case Kelix.Mod.Mcu.admit(sip_ctx.domain, req) do
  {:ok, conf, part} ->
    ctx_set(:username, conf.did)                 # the local identity of this leg
    appdata_set(:mcu_part, part)
    appdata_set(:media_conn_opts, mcu_participant: part)
    appdata_set(:mediaserver_instance, Kelix.Mod.Mcu.media_config(conf))
    media_connect()
    reply_invite(180, "Ringing")

  {:error, reason} ->
    # 404 / 486 / 503 — see the table below
end
```

then, in order:

| Step | Call | What it does |
|---|---|---|
| answer | `reply_invite_with_sdp(200, media: :audio_video, webrtc: :if_offered, on_media_error: &mapper/1)` | negotiates, opens the receive plane, builds the answer |
| on the ACK | `Kelix.Mod.Mcu.attach(part)` | codecs, `StartSending`, **joins the mix** |
| teardown | `media_cleanup_ressources()` then `Kelix.Mod.Mcu.leave(part, reason)` | releases the media then the slot |

**The ACK is what puts the leg in the mix.** A caller that never ACKs holds its slot
and hears nothing — deliberately: no RTP leaves the mixer before the call is
established.

**Teardown must be idempotent, and it is**: `leave/2` tolerates an already-removed
participant, which is why the reference script calls it from seven places without
guarding. Not doing so on some path is the bug that leaves a ghost in the mix.

### 2.2 Verdicts and their SIP codes

| Verdict | Code | Meaning |
|---|---|---|
| `{:error, :no_such_conference}` | `404` | the DID designates nothing |
| `{:error, :full}` | `486` | `max_participants` reached |
| `{:error, :mcu_down}` | `503` | the conference exists, its media server does not answer |
| `{:error, :down \| :timeout}` | `500` | the module itself is wedged or absent |
| media error `:no_common_codec` | `488` | retrying is pointless |
| media error `:secure_not_supported` | `488` | a DTLS offer while the script passed `webrtc: :no` |
| media error `{:bad_offer, _}` | `400` | the SDP did not parse |
| any other media error | `500` | ours; a retry may work |

Every module call is wrapped in `safe_call/3`, so a wedged module is an error you
answer with rather than a call that hangs. **Rescue anyway**: a module that is not
installed raises `UndefinedFunctionError`, and an unrescued raise leaves the caller
with *no* response at all — worse than any code, since it retransmits into the void.

### 2.3 Owning a conference (P5b)

A script can create conferences, not just join them:

```elixir
# atomic get-or-create: N simultaneous callers on an unknown DID get ONE room
{:ok, conf, :created | :existing} =
  Kelix.Mod.Mcu.ensure_conference(domain, did,
    name: "Ad-hoc #{did}",
    owner: :caller,           # dies with this instance IF still empty
    destroy_when_empty: true  # dies with its last participant
  )

{:ok, conf}   = Kelix.Mod.Mcu.create_conference(domain, name: "Weekly", owner: :none)
{:ok, fields} = Kelix.Mod.Mcu.update_conference(conf.uid, layout: %{comp: 6})
:ok           = Kelix.Mod.Mcu.destroy_conference(conf.uid, force: true)
rooms         = Kelix.Mod.Mcu.conferences(domain)
```

`owner: :caller` (the default) is the leak guard: if the creating instance dies before
anyone joins — a caller who never ACKs, a crash, a media failure, even a `create` that
timed out — the module destroys the **empty** conference. A conference somebody joined
survives its creator, who was merely the first to arrive.

Options are atom-keyed keyword lists, validated by exactly the same code as the REST
body, so a conference a script creates and one REST creates are indistinguishable.

`apps/kelixip/scripts/mcu_adhoc.exs` is this in full. Note what it does **not** do:
the module never creates a conference by itself — no template, no implicit rule. Ad-hoc
rooms are a *script's* decision, and `mcu.exs` keeps answering `404`.

### 2.4 In-call operations

| Call | Effect |
|---|---|
| `send_fpu(part)` | asks the MCU for an intra-frame from that leg |
| `mute(part, :audio, true)` | `SetMute` — for a moderated conference |
| `kick(uid, part_id)` | asks that leg's scenario to wind down (BYE + teardown) |

Two messages arrive in a script's mailbox and must be handled, or they rot there:

* `{:mcu_event, :fpu_requested}` — the mixer needs a fresh intra-frame from this leg;
  answer with an INFO carrying RFC 5168 `picture_fast_update`;
* `{:mcu_event, :server_disconnected}` — the mix is gone; BYE and leave.

---

## 3. For whoever debugs a call

### 3.1 What a successful join looks like

Every line carries the conference `uid`, so one call can be followed end to end:

```
conference.created c-3f9a2b10: name=Weekly domain=example.com mcu=mcu1 conf_id=42 did=8000
participant.ringing c-3f9a2b10: name=alice@phone_example_com from=alice@phone.example.com did=8000
conference c-3f9a2b10: participant 7 (alice@phone_example_com) created on mcu1
participant.joined c-3f9a2b10: part_id=7 name=alice@phone_example_com medias=%{audio: "PCMA"}
participant.left c-3f9a2b10: part_id=7 reason=bye duration_ms=45120
```

`ringing` without a later `joined` is a caller who never made it into the mix. The
count of `ringing − joined` is "abandoned before answer", with no correction needed:
a **rejected** call never emits `ringing` at all.

### 3.2 The three failures that look alike from outside

The caller sees a code; only the log tells them apart.

| Symptom | Log line | Cause |
|---|---|---|
| `488` immediately | `offer refused (:no_common_codec)` | no codec in common — compare the offer's `m=` line with the conference's `codecs` |
| `488` immediately | `offer refused (:secure_not_supported)` | a DTLS/SDES offer while the script passed `webrtc: :no` |
| `503` immediately | `mediaserver.down : mcu=mcu1` earlier | the control channel is down; `kelictl status` shows `0/1 up` |
| `500` | `mcu mcu1: <Method> failed: …` | an RPC failed. The line above it names the method and the server's message |
| `500` | `mcu mcu1 returned no media IP from StartReceiving` | the media server predates the `--public-ip` work and cannot report the address to announce — upgrade it |
| `404` | `participant.rejected: reason=no_such_conference` | the DID designates nothing — `conference.list` and the dial rule |

### 3.3 Connected but no audio

The call is up and nobody hears anything. In order of likelihood:

1. **the announced address** — the answer advertises an address the caller cannot
   reach. Check the media server's startup log (`-RTPSession announced IP …`) against
   what the caller can route to, and set `mediaserver --public-ip` behind a NAT
   (§1.2). `participant.show`'s statistics settle it: `num_recv_packets` at 0 means
   nothing arrives, non-zero `num_send_packets` with silence at the far end means our
   address is wrong;
2. **no ACK** — the leg never joined the mix. `participant.list` shows `state:
   ringing`;
3. **firewall on the RTP range** — the media server's `--min-rtp-port/--max-rtp-port`.

For video specifically: if one side sees nothing, look for `h264.profile-level-id` in
the `SetRTPProperties` log — a handset that only decodes baseline needs the profile it
asked for, which is why the answerer reflects it. This is limitation L4: kelixip
decides the fmtp, so a disagreement shows up as one-way video rather than a
negotiation failure. P8 makes the server authoritative.

### 3.4 A silent leg stays forever

Known, and it is limitation L1: the MCU API has no RTP inactivity watchdog (gap G3),
so a leg whose media stops is only detected by SIP — the script's idle timeout, hours
away. Unplugging a phone leaves its slot and its mosaic tile taken. P7 adds the
server-side watchdog.

### 3.5 Conferences survive nothing

By design (limitation L5): they live in memory, and a kelixip restart loses them. The
media server's leftovers are swept at start (§9.4). Scheduled or long-lived
conferences would need persistence, which is not built.

---

## 4. Testing a node without packaging

See [BUILD.md](../BUILD.md#running-the-mcu-module-from-a-checkout). In short: in dev
the modules come from the umbrella's own `ebin`, so `module_dir` stays empty and
nothing needs installing — point `KELIXIP_CONFIG` / `KELIXIP_DOMAINS` at a TOML pair
carrying `[module.mcu]` and a dial rule, with a real `mediaserver --http-port` running.

---

## 5. Operational notes

### 5.1 One media server per conference

A conference is pinned to the MCU it was created on and never migrates (design §1.3).
That pinning is a property of the conference, not of where the servers are declared:
`create` without an `mcu` takes the `[mediaserver.pool.*]` entries in turn, `create`
with one always honours it, and either way the conference then stays put.

Two flags decide whether a server is eligible for a **new** conference:

* the pool's `enabled` — the operator's switch. Disabling a server stops new
  conferences (and new point-to-point calls) landing on it; the live ones stay, and
  naming it explicitly still works;
* the module's own `status` — `kelictl status`'s `n/m up`. This is health as seen from
  the control channel the conferences ride (`/mcu`), which is **not** what the pool
  probes for point-to-point calls (`/jsr309`). A server can legitimately be up for one
  and down for the other, which is why there are two metrics
  (`kelix_mcu_mediaserver_up` and `kelix_mediaserver_up`).

### 5.2 Reloading and restarting

* `kelictl module reload mcu` — no in-place reload: the module is restarted cleanly,
  which **drops the live conferences** (their rows, not the media server's, which the
  next start sweeps). Deliberate: pretending an MCU list can be swapped under live
  conferences would be worse than saying so;
* an **MCU restart** is handled: conferences are marked `stale`, their participants'
  scenarios are told, and the conferences are recreated with the same `uid` when the
  server returns. The calls are gone, the rooms and their DIDs are not;
* a **kelixip restart** loses the conferences; the sweep of §9.4 deletes what the media
  server still holds (`gc_orphans = true`).

### 5.3 What is not there

Read §1.2 and §12 of the design for the full list with rationale. The ones that
surprise people: no conference templates, no outbound calls (no dial-out into a
conference), no recording, no document sharing, no PIN at join time — whoever reaches
the DID enters — and only mosaic `0` / mixer `0`.
