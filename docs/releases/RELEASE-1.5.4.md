# Release 1.5.4

2026-09-10 — 14 commits since 1.5.3 (2026-09-08). Theme: **a node refuses, and
says so**. Every accumulation an unauthenticated peer could drive is now bounded,
named and configurable, and a refusal is answered instead of dropped. The push
mechanism of 1.5.3 gains its conferencing part. The build is driven by a CI.

## Hardening SIP parser

### Protection against memory exhaution attacks

Protected SIP parser against four attacks

- `Content-Length: 1000000000` causing me
- `Content-Length: lots` causing `ArgumentError` and transport crash
- `Content-Length: -5` causing body framed **truncated** and a frame desync on a shared connection
- TCP SIP messages with over 64000 bytes of headers or of body.

The bound is named and  configurable, and din bytes

- `:max_message_size` off the app env, **64 000** by default
- On a kelixip node it comes from `max_message_size` in the `[server]` section


Refusing a body means deliberately not reading the octets `Content-Length`
announced. The socket is closed intentionally.

A message that is framed correctly and is merely too big is handled diffently
and answered with a 513 response at transport level.

### 4 cases of incorrect SIP message parsing detection

Parser would raise an exception and make the transport fail when parsing non numerical header values:
- `Content-Length`,
- `Expires`,
- `Max-Forwards`,
- and the CSeq sequence number.

## MCU — added push mechanism to implement live update of conferences


| New in `Kelix.Control` | What the subscriber receives |
|---|---|
| `subscribe_conferences/1` | `{:kelix_conferences, {:upsert, conf_row}}`, `{:kelix_conferences, {:remove, uid}}` |
| `subscribe_conference/2` | `{:kelix_conference, uid, {:snapshot, %{conference:, participants:}}}`, then `{:kelix_conference, uid, :destroyed}` |
| `subscribe_conference_stats/2` | `{:kelix_conference_stats, uid, sample}`, one immediately then one per `interval_ms` |

Each has its `unsubscribe_*` counterpart, and a dying subscriber unsubscribes
itself.


- **Monitor the `owner`.** Every call returns the pid holding the subscription. A
  module restart stops the push otherwise, silently. Re-subscribe on `:DOWN`.
- **The roster is pushed whole**, in admission order. A ringing leg has no
  `part_id` yet, so there is no key a per-participant delta could name.
- **Statistics are the expensive topic.** One sweep is one RPC per connected leg,
  on the media server's own control channel. Subscribe when a panel expands, drop
  it when it collapses.

`subscribe_conferences/1` answers `owner: nil` with an empty list when the
conferencing module is not loaded — no conference can exist without it, so there is
nothing to watch and nothing to monitor. Not an error.

New module key: `stats_interval_ms` in `[module.mcu]`, **15 000** by default. `0`
disables the statistics topic entirely, which an operator has to be able to say
given what a sweep costs.

Reference: [mcu.md](../kelixip/modules/mcu.md), the module's own documentation.

## Service Building Blocks — two fixes

**A `bridge()` releases both legs on a progressive shutdown**, 

**A block shipped in a `module_dir` is usable on its first call.** 

## Build and packaging

**A GitLab CI drives the build**, on framagit, on an Alma Linux 9 runner.
push compiles and runs the tests; a **tag** additionally produces the SBoM and the
five RPMs and keeps them as artifacts. 

**bash-completion is an optional dependency** of the kelixip package, not a
required one. A server does not need a shell's completion to run.

## Upgrading

Nothing to do beyond the usual install: no configuration key changed meaning, and
none became mandatory. Two are new and both default to what 1.5.3 effectively did,
except where 1.5.3 was wrong:

| Key | Block | Default | Effect if you leave it alone |
|---|---|---|---|
| `max_message_size` | `[server]` | 64 000 | messages between 10 000 and 64 000 bytes now get through — a 4-stream WebRTC offer among them |
| `stats_interval_ms` | `[module.mcu]` | 15 000 | none until a UI subscribes to statistics |

