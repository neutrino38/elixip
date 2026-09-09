# MCU live push to an admin UI — the contract

Status: **implemented** (2026-09-09). Extends the push doctrine of
[kelixip_liveview.md](kelixip_liveview.md) to the conferencing module and closes
**L9** of [DESIGN-MCU.md](DESIGN-MCU.md) §12 ("event callbacks to an external UI are
not delivered — only logged and metered"). The consumer is kelescope
(`github.com/neutrino38/kelescope`), clustered with the node.

## Goal

Remove the refresh button from a conferencing panel. Five things arrive as a push:

1. a conference is created,
2. a conference is edited,
3. a conference is destroyed,
4. a participant comes in or goes out,
5. per-participant media statistics, every 15 s, **only while a panel is expanded**.

## Decision 0 — the same mechanism as the three existing push surfaces

Subscriber list + `send/2`, no new dependency, exposed through `Kelix.Control`.
Identical to `subscribe_monitor/1`, `subscribe_domain_counters/1` and
`subscribe_registrations/2` (kelixip_liveview.md), and to the pattern they all copy,
`Kelix.Mod.Registrar.subscribe_register_event/2`. A remote pid works transparently
once the UI is clustered with the node, and the subscriber is monitored, so a dead or
disconnected panel drops its own subscription.

Named functions in `Kelix.Control` — **not** a generic
`module_subscribe(module, topic, args, pid)`. The generic form would have exactly one
implementing module, and "no indirection layer for a single caller" is the house rule;
`Kelix.Control` already names `"registrar"` for the same reason. It is reached through
`Kelix.ModuleRegistry.facade/4`, so the core still compiles and answers "nothing to
watch" without the module (§16.12).

## Decision 1 — three topics, one per panel

| Topic | Subscribe | Pushes | Granularity |
|---|---|---|---|
| conference list | `subscribe_conferences(pid)` | one conference row, on any change to it | delta, keyed by `uid` |
| one conference | `subscribe_conference(pid, uid)` | that conference's row **and its whole roster** | snapshot per change |
| one conference's stats | `subscribe_conference_stats(pid, uid)` | every connected leg's media counters | snapshot, every `stats_interval_ms` |

Three topics and not one, for the reason `count_subs` and `detail_subs` are separate
in the registrar: the list panel must not receive a roster it does not display, and
the statistics sweep costs an RPC per leg — it must exist only while an operator is
actually looking at that conference.

A UI subscribes to the list when the conferencing page opens, adds the conference
topic when a row is expanded, adds the stats topic on the same expansion, and drops
the last two when the row collapses.

## The wire contract

### Rows are the rows the REST/CLI reads already return

A pushed conference row is exactly `Kelix.Mod.Mcu.Conference.render/1` — what
`conference.list` and `conference.show` return. A pushed participant row is exactly
`render_participant/1` — what `participant.list` returns. The same function, not a
copy: the initial `GET` and the push cannot disagree about a field, and one component
renders both. The suite asserts that equality rather than restating the shapes
(`mcu_push_test.exs`).

A roster is ordered by **admission**, oldest first — the map the participants are
held in has no order, and a table whose rows move on their own is unreadable.

### Messages

```elixir
# conference list
{:kelix_conferences, {:upsert, conf_row}}
{:kelix_conferences, {:remove, uid}}

# one conference
{:kelix_conference, uid, {:snapshot, %{conference: conf_row, participants: [part_row]}}}
{:kelix_conference, uid, :destroyed}

# one conference's statistics
{:kelix_conference_stats, uid, sample}
```

`sample`:

```elixir
%{
  at: ~U[2026-09-09 10:00:00Z],
  mcu: "mcu1",
  interval_ms: 15_000,
  participants: [
    %{
      part_id: 7,
      name: "alice@phone_example_com",
      state: :connected,
      # ms since THIS leg's previous sample; nil on its first one
      since_ms: 15_002,
      # the map `participant.show` returns, keyed by media atom, plus what only two
      # samples can say
      stats: %{
        audio: %{
          receiving: true,
          sending: true,
          num_recv_packets: 12_345,
          num_send_packets: 12_001,
          total_recv_bytes: 1_234_567,
          total_send_bytes: 1_200_000,
          lost_recv_packets: 12,
          # derived over since_ms; nil on the first sample, and nil again if a
          # counter went backwards (a recreated conference keeps its uid)
          recv_kbps: 64,
          send_kbps: 64,
          lost_recv_delta: 0
        }
      },
      # only when the sweep could not read this leg (:mcu_down, :rpc_error,
      # :unknown_mcu); `stats` is then empty
      stats_error: nil
    }
  ]
}
```

Only legs that reached the mixer are sampled: a ringing leg has no MCU-side
participant to ask about.

`stats` is keyed by **media atom** (`:audio`, `:video`, `:text`), like every other
per-media map the module hands out — a participant row's `medias` in particular, so
one consumer reads both the same way. The mapping is bounded on purpose: the name
comes off the wire, and `String.to_atom/1` on server input creates atoms nothing
frees. An unknown media name stays the string the server sent.

The derived rates are computed on this side, not by the UI: the sweep holds the
previous sample for free, every consumer wants the same arithmetic, and a UI
computing it itself would show nothing after a page reload. The counters themselves
are passed through as the media server gave them (§16.3 — what the media server knows
about itself, the media server is asked; a rate is arithmetic, not a server fact).

### Delivery guarantees

- **No gap and no duplicate on the list and conference topics.** Registering the
  subscriber and reading its snapshot happen in the *same* GenServer message, and
  everything that publishes a row goes through that process — so nothing can slip
  between the two.
- **Every message carries the whole truth** for what it names (a full row, a full
  roster, a full sample). No diffs, no sequence numbers, nothing to reconcile.
  Applying a message twice is a no-op.
- **Order is preserved per topic and per node** (plain `send/2` between two
  processes). There is no order *across* topics.
- **One node, one subscription.** A kelixip node only ever pushes its own
  conferences; a UI subscribes on each node it monitors, as it already does for the
  other three surfaces.
- A destroyed conference leaves its subscriptions in place: the subscriber has just
  been told (`:destroyed`) and unsubscribes. Until it does, the entry costs nothing —
  no event will name that uid again, and the statistics sweep finds no row and issues
  no RPC.

### Liveness — every subscribe returns its `owner`

```elixir
{:ok, %{owner: pid | nil, conferences: [conf_row]}}
{:ok, %{owner: pid, conference: conf_row, participants: [part_row]}} # | {:error, :not_found}
{:ok, %{owner: pid, interval_ms: pos_integer}}   # | {:error, :not_found | :disabled}
```

The subscriber lists live in the module's registry process. If the module is
restarted or reloaded they are gone, and nothing would tell the subscriber — a
silently dead push is precisely the bug that brings the refresh button back. So each
subscribe returns the pid holding the subscription: monitor it once, re-subscribe on
`:DOWN`.

`owner: nil` with an empty list is the answer when the conferencing module is not
loaded — there is nothing to watch and nothing to monitor. The other two topics answer
`{:error, :not_found}` in that case: no conference can exist without the module.

The three older push surfaces have the same hole and could return the same field
later; that was not a prerequisite here.

## Decision 2 — the roster is pushed whole, not per participant

A participant change pushes the conference's **entire** roster, unlike the registrar's
registration detail push, which pushes one AOR.

- A conference holds at most `max_participants` legs (20 by default, and the value is
  bounded by configuration). A registrar domain holds thousands of AORs; that
  difference is the whole reason for the difference in granularity.
- **A ringing leg has no stable public id.** `admit/2` reserves the row and its
  `part_id` is learned later (`bind_participant/4`), so `render_participant/1` reports
  `part_id: nil` until the leg reaches the mixer — there is nothing to key a
  `{:remove, key}` on. Per-participant deltas would first require giving every leg a
  public identity (a `part_uid` string, as conferences have `uid`), which the roster
  snapshot makes unnecessary.

Cost of the choice: expanding a 20-leg conference means ~20 rows per join, leave or
mute — a couple of kilobytes, to the watchers of that one conference.

## Decision 3 — the statistics sweep is its own process, gated on subscribers

`GetParticipantStatistics(confId, partId)` is per participant: there is no
conference-wide statistics RPC (`mcu/src/xmlrpcmcu.cpp`). One sweep of a watched
conference is therefore one RPC per connected leg. `Kelix.Mod.Mcu.Stats`:

- **Nothing is polled without a subscriber.** No expanded panel, no RPC, no timer
  work: `Push.watched_stats/0` is the whole work list.
- **Its own process**, last child of `Kelix.Mod.Mcu.Supervisor`. Not the registry,
  which must never sit behind a sweep while an INVITE waits on `admit/2`; and not
  `Kelix.Metrics.Poller`, although it already ticks at 15 s and is documented as the
  node's one sampling clock — it is core code that runs whether or not metrics are
  enabled, and a sweep of up to N × `xmlrpc_timeout_ms` inside it would stall the
  node's own sampling. Being last under `:rest_for_one`, its crash restarts nothing
  else, while a registry restart still takes it along — its previous samples belong to
  a roster that is gone.
- **The first sample is immediate**: a new subscription is swept on the spot (as a
  cast, so `subscribe_conference_stats/2` returns without waiting for RPCs), because
  an expanded panel showing nothing for 15 s is what an operator reads as broken.
- **A sweep never piles up**: the next tick is scheduled when the current one returns,
  so a slow media server shows as older numbers (`since_ms` says how old) instead of a
  growing queue.
- A failure is reported per leg (`stats_error`), never hidden: an operator reading
  zeros must be able to tell "no media" from "no answer" — the same rule
  `participant.show` follows, and it now shares this module's one reading of the RPC
  (`participant_statistics/2`).
- Configuration: `[module.mcu] stats_interval_ms`, default `15000`. `0` disables the
  topic, and subscribing then answers `{:error, :disabled}` rather than accepting a
  subscription that would push nothing.

**The honest cost**: the sweep shares the media server's control channel
(`Kelix.Mod.Mcu.Client`, one GenServer per MCU, RPCs serialised) with call setup. Two
operators watching two full conferences is ~40 RPCs per 15 s in front of the next
`CreateParticipant`. That is bounded by what people are actually looking at, which is
why the topic is subscription-gated rather than always on.

## Where it hooks in the module

**`Kelix.Mod.Mcu.Event.emit/3` is the single hook.** The event vocabulary is already
frozen and already emitted exactly once per observed transition, with the conference
`uid` on every line. So the fan-out (`Kelix.Mod.Mcu.Push`) is one consumer added
there, not a `broadcast_*` call at each of the twenty emission sites. The event NAME
decides what goes out:

| Event | list topic | conference topic |
|---|---|---|
| `conference.created` (including a recreate) | upsert | snapshot |
| `conference.updated`, `conference.layout_changed`, `conference.slot_changed`, `conference.recording_started`, `conference.recording_stopped` | upsert | snapshot |
| `conference.destroyed` | remove | `:destroyed` |
| `participant.ringing`, `participant.joined`, `participant.left`, `participant.muted`, `participant.media_connected`, `participant.media_timeout` | upsert (the row carries the count) | snapshot |
| `participant.rejected`, `participant.fpu_requested`, `participant.message`, `mediaserver.up`, `mediaserver.down` | — | — |

Four traps, each of which cost something to find:

1. **`conference.destroyed` is emitted *before* the `:ets.delete`** (`destroy/2`),
   the one emission that does not follow its write. A fan-out that re-read the row
   here would resurrect a destroyed conference in the UI. The name decides: destroyed
   means remove, never re-read. Every other emission follows its `:ets.insert`.
2. **Losing a media server emitted nothing per conference.** `mark_stale/1` flipped
   `stale: true` and cleared `conf_id` on every conference of that MCU silently, so
   those rows would never have been pushed — a UI would keep showing a dead room as
   healthy while its DID answers 503. Fixed at the source: `mark_stale/1` now emits
   `conference.updated` with `%{changed: [:stale], stale: true, reason: :mcu_lost}`.
   The frozen name already covered it, it fills the same hole in the logs, and
   `recreate_stale/2` already emits `conference.created` on the way back.
3. **`participant.message` publishes nothing.** It is the collaboration channel's hot
   path (§20) and changes no row; a roster render per chat message is not acceptable.
4. **`Event.emit/3` runs in many processes** — the registry, a scenario, a message
   sender. The subscriber lists therefore cannot live in the registry's GenServer
   state the way the registrar's do: they are in a `:protected` ETS table owned by
   `Kelix.Mod.Mcu` (any process reads, only the owner writes), the split the module
   already uses for its other tables. Subscribing, unsubscribing and the `:DOWN`
   cleanup stay GenServer calls.

Nothing is rendered for a topic nobody subscribed to: the roster render sits on the
call path (every ringing, joined and left), so an unwatched conference costs one
`:ets.select` and nothing more. The suite asserts that too.

## `Kelix.Control` surface

```elixir
@spec subscribe_conferences(pid) :: {:ok, %{owner: pid | nil, conferences: [map]}}
@spec unsubscribe_conferences(pid) :: :ok

@spec subscribe_conference(pid, String.t()) ::
        {:ok, %{owner: pid, conference: map, participants: [map]}} | {:error, :not_found}
@spec unsubscribe_conference(pid, String.t()) :: :ok

@spec subscribe_conference_stats(pid, String.t()) ::
        {:ok, %{owner: pid, interval_ms: pos_integer}} | {:error, :not_found | :disabled}
@spec unsubscribe_conference_stats(pid, String.t()) :: :ok
```

The module answers the snapshots itself, through the facade: unlike the registration
detail push, the core has no rendering of its own to reuse here and adds none.

## What is not here

- **An event timeline.** The frozen vocabulary could also be relayed verbatim as a
  fourth topic, which is what a "recent activity" panel and an audit view want —
  `participant.rejected` in particular is pushed by no topic above, and
  `ringing − joined` is the abandoned-call rate §11 promises a UI can read. State and
  timeline are different products, and a timeline the UI must persist is a bigger ask
  than a refresh button.
- **Per-domain filtering.** The list topic pushes every conference of the node. The
  row carries `domain`, so filtering client-side works; a server-side filter is one
  argument away if a tenancy boundary must be enforced on this side.
- **Admin tracing** on `conference.update`, `participant.delete` and `slot.update`:
  `conference.create` and `conference.delete` take an `admin` name
  (kelixip_liveview.md, 2026-09-08), and those three are just as destructive from an
  operator's seat.
- **Traffic.** The path is covered by `apps/kelix_modules/test/mcu_push_test.exs`
  (12 tests: the three topics, the destroy remove, the stale push, the unwatched
  silence, the dead subscriber, the disabled sweep, and the `Kelix.Control` pair with
  and without the module) — but it has not yet been watched by a real UI against a
  real media server.
