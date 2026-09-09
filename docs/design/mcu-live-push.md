# MCU live push to kelescope — contract proposal

Status: **proposal** (2026-09-09). Nothing here is implemented. It extends the push
doctrine of [kelixip_liveview.md](kelixip_liveview.md) to the conferencing module
and closes **L9** of [DESIGN-MCU.md](DESIGN-MCU.md) §12 ("event callbacks to an
external UI are not delivered — only logged and metered").

## Goal

Remove the refresh button from kelescope's conferencing panels. Five things must
arrive as a push:

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
once kelescope is clustered with the node, and the subscriber is monitored, so a
dead or disconnected panel drops its own subscription.

Named functions in `Kelix.Control` — **not** a generic
`module_subscribe(module, topic, args, pid)`. The generic form would have exactly
one implementing module, and "no indirection layer for a single caller" is the house
rule; `Kelix.Control` already names `"registrar"` for the same reason. It stays
reachable through `Kelix.ModuleRegistry.facade/4`, so the core still compiles
without the module and answers "nothing to watch" when it is not loaded.

## Decision 1 — three topics, one per panel

| Topic | Subscribe | Pushes | Granularity |
|---|---|---|---|
| conference list | `subscribe_conferences(pid)` | one conference row, on any change to it | delta, keyed by `uid` |
| one conference | `subscribe_conference(pid, uid)` | that conference's row **and its whole roster** | snapshot per change |
| one conference's stats | `subscribe_conference_stats(pid, uid)` | every connected leg's media counters | snapshot, every 15 s |

Three topics and not one, for the reason `count_subs` and `detail_subs` are separate
in the registrar: the list panel must not receive a roster it does not display, and
the statistics sweep costs an RPC per leg — it must exist only while an operator is
actually looking at that conference.

kelescope subscribes to the list when the conferencing page opens, adds the
conference topic when a row is expanded, adds the stats topic on the same
expansion, and drops the last two when the row is collapsed.

## The wire contract

### Rows are the rows the REST/CLI reads already return

A pushed conference row is exactly `Kelix.Mod.Mcu.Conference.render/1` — what
`conference.list` and `conference.show` return. A pushed participant row is exactly
`render_participant/1` — what `participant.list` returns. The same function, not a
copy: the initial `GET` and the push cannot disagree about a field, and kelescope
renders both with one component.

### Messages

```elixir
# conference list
{:kelix_conferences, {:upsert, conf_row}}
{:kelix_conferences, {:remove, uid}}

# one conference (uid is the canonical conference uid)
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
      name: "alice@example.com",
      state: :connected,
      # ms since THIS leg's previous sample; nil on its first one
      since_ms: 15_002,
      # the shape `participant.show` returns, plus what only two samples can say
      stats: %{
        audio: %{
          receiving: true,
          sending: true,
          num_recv_packets: 12_345,
          num_send_packets: 12_001,
          total_recv_bytes: 1_234_567,
          total_send_bytes: 1_200_000,
          lost_recv_packets: 12,
          # derived over since_ms, nil on the first sample
          recv_kbps: 64,
          send_kbps: 64,
          lost_recv_delta: 0
        }
      },
      # only when the sweep could not read this leg
      stats_error: nil
    }
  ]
}
```

The derived values are computed **here**, not by kelescope: the sweep holds the
previous sample for free, every consumer wants the same arithmetic, and a UI that
computed it itself would show nothing after a page reload. The counters themselves
are passed through as the media server gave them (§ "what the media server knows
about itself, the media server is asked") — a rate is arithmetic, not a server fact,
which is why deriving it here is not a copy of the server's state.

### Delivery guarantees

- **At-least-once, never a gap.** `subscribe_*` registers the subscriber first and
  reads the snapshot second, so a change racing the subscription arrives twice, not
  zero times.
- **Every message carries the whole truth** for what it names (a full row, a full
  roster, a full sample). No diffs, no sequence numbers, nothing to reconcile.
  Applying a message twice is a no-op.
- `{:remove, uid}` / `:destroyed` may name a conference the subscriber never saw.
  Ignore it.
- **Order is preserved per topic and per node** (plain `send/2` between two
  processes), and there is no order *across* topics.
- **One node, one subscription.** A kelixip node only ever pushes its own
  conferences; kelescope subscribes on each node it monitors, as it already does for
  the other three surfaces.

### Liveness — every subscribe returns its `owner`

```elixir
{:ok, %{owner: pid, conferences: [conf_row]}}
{:ok, %{owner: pid, conference: conf_row, participants: [part_row]}}   # | {:error, :not_found}
{:ok, %{owner: pid, interval_ms: 15_000}}                              # | {:error, :not_found}
```

The subscriber lists live in the module's registry process. If the module is
restarted or reloaded, they are gone and nothing tells the subscriber — a silently
dead push is precisely the bug that brings the refresh button back. So each
subscribe returns the pid holding the subscription: kelescope `Process.monitor`s it
once and re-subscribes on `:DOWN`. The three existing surfaces have the same hole
and could return the same field later; that is not a prerequisite here.

## Decision 2 — the roster is pushed whole, not per participant

A participant change pushes the conference's **entire** roster, unlike the
registrar's registration detail push, which pushes one AOR.

- A conference holds at most `max_participants` legs (20 by default, and the value
  is bounded by configuration). A registrar domain holds thousands of AORs; that
  difference is the whole reason for the difference in granularity.
- **A ringing leg has no stable public id.** `admit/2` reserves the row and its
  `part_id` is learned later (`bind_participant/4`), so `render_participant/1`
  reports `part_id: nil` until the leg reaches the mixer — there is nothing to key
  `{:remove, key}` on. Per-participant deltas would first require giving every leg
  a public identity (a `part_uid` string, as conferences have `uid`), which is a
  bigger change than this contract needs, and which the roster snapshot makes
  unnecessary.

Cost of the choice: expanding a 20-leg conference means ~20 rows per join, leave or
mute — a couple of kilobytes, to the watchers of that one conference.

## Decision 3 — the statistics sweep is its own process, gated on subscribers

`GetParticipantStatistics(confId, partId)` is per participant: there is no
conference-wide statistics RPC (`mcu/src/xmlrpcmcu.cpp`). One sweep of a watched
conference is therefore one RPC per connected leg.

- **Its own process** (`Kelix.Mod.Mcu.Stats`, a child of `Kelix.Mod.Mcu.Supervisor`
  after the registry, so `:rest_for_one` restarts it with the tables it reads).
  Not the registry process: a sweep must never sit in front of a `create` or an
  `admit`. Not `Kelix.Metrics.Poller` either, although it already ticks at 15 s and
  is documented as the node's one sampling clock: it is core code that runs whether
  or not metrics are enabled, and a sweep of up to N × `xmlrpc_timeout_ms` inside it
  would stall the node's own sampling.
- **Nothing is polled without a subscriber.** No subscription, no RPC, no timer
  work — the same rule the registrar's detail push applies to its render.
- **The first sample is immediate**: a new subscription is swept on the spot (in the
  sweeper, so `subscribe_conference_stats/2` still returns at once), because an
  expanded panel showing nothing for 15 s is what an operator reads as broken.
- **A sweep never piles up**: while one is running the next tick is skipped, and the
  sample says how long it actually covered (`since_ms`), so a slow MCU shows as
  older numbers rather than as a growing queue.
- Only legs with a `part_id` are swept — a ringing leg has no MCU-side participant
  to ask about. A failure is reported per leg (`stats_error`), never hidden: an
  operator reading zeros must be able to tell "no media" from "no answer", which is
  what `participant.show` already does.
- Configuration: `[module.mcu] stats_interval_ms`, default `15000`, `0` disables the
  topic (subscribing then returns `{:error, :disabled}` — never a subscription that
  pushes nothing).

**The honest cost**: the sweep shares the media server's control channel
(`Kelix.Mod.Mcu.Client`, one GenServer per MCU, RPCs serialised) with call setup.
Two operators watching two full conferences is ~40 RPCs per 15 s in front of the
next `CreateParticipant`. That is bounded by what people are actually looking at,
which is the reason the topic is subscription-gated rather than always on.

## Where it hooks in the module

**`Kelix.Mod.Mcu.Event.emit/3` is the single hook.** The event vocabulary is
already frozen and already emitted exactly once per observed transition, with the
conference `uid` on every line — its own moduledoc says adding a transport is "a
transport change and not a redesign". So the fan-out is one consumer added there,
not a `broadcast_*` call scattered over the twenty emission sites.

The fan-out re-reads the conference from ETS and renders it. Event name decides
what is pushed:

| Event | list topic | conference topic |
|---|---|---|
| `conference.created` (including a recreate) | upsert | snapshot |
| `conference.updated`, `conference.layout_changed`, `conference.slot_changed`, `conference.recording_started`, `conference.recording_stopped` | upsert | snapshot |
| `conference.destroyed` | remove | `:destroyed` |
| `participant.ringing`, `participant.joined`, `participant.left`, `participant.muted`, `participant.media_connected`, `participant.media_timeout` | upsert (the row carries the count) | snapshot |
| `participant.rejected`, `participant.fpu_requested`, `participant.message`, `mediaserver.up`, `mediaserver.down` | — | — |

Four traps, all verified against the current code:

1. **`conference.destroyed` is emitted *before* the ETS delete** (`destroy/2`), the
   one emission that does not follow its write. A fan-out that re-read the row here
   would resurrect a destroyed conference in the UI. The name decides: destroyed
   means remove, never re-read. Every other emission already follows its
   `:ets.insert`.
2. **Losing a media server emits nothing per conference.** `mark_stale/1` flips
   `stale: true` and clears `conf_id` on every conference of that MCU without
   emitting anything, so those rows would never be pushed — the panel would keep
   showing rooms as healthy while their DIDs answer 503. Fix at the source, not in
   the fan-out: `mark_stale/1` emits `conference.updated` with
   `%{changed: [:stale], stale: true, reason: :mcu_lost}`. The frozen name already
   covers it, it fills the same hole in the logs, and `recreate_stale/2` already
   emits `conference.created` on the way back.
3. **`participant.message` must push nothing.** It is the collaboration channel's
   hot path (§20) and it changes no row; a roster render per chat message is not
   acceptable.
4. **`Event.emit/3` runs in many processes** — the registry, a scenario, a message
   sender. The subscriber lists therefore cannot live in the registry's GenServer
   state the way the registrar's do: they go in a `:protected` ETS table owned by
   `Kelix.Mod.Mcu` (any process reads, only the owner writes), which is the split
   the module already uses for its other tables. `subscribe_*` / `unsubscribe_*` and
   the `:DOWN` cleanup stay GenServer calls.

## `Kelix.Control` surface

```elixir
@spec subscribe_conferences(pid) :: {:ok, %{owner: pid, conferences: [map]}}
@spec unsubscribe_conferences(pid) :: :ok

@spec subscribe_conference(pid, String.t()) ::
        {:ok, %{owner: pid, conference: map, participants: [map]}} | {:error, :not_found}
@spec unsubscribe_conference(pid, String.t()) :: :ok

@spec subscribe_conference_stats(pid, String.t()) ::
        {:ok, %{owner: pid, interval_ms: pos_integer}}
        | {:error, :not_found | :disabled}
@spec unsubscribe_conference_stats(pid, String.t()) :: :ok
```

Each one goes through `Kelix.ModuleRegistry.facade("mcu", …)` with a default that
means "nothing to watch" when the module is not loaded: `{:ok, %{owner: self(),
conferences: []}}` for the list, `{:error, :not_found}` for the other two. No
conference can exist without the module, so nothing is missed — the same argument
`subscribe_domain_counters/1` makes for the registrar half.

The snapshots come from the module's own render functions, through the facade. The
core adds no rendering of its own here — unlike the registration detail push, it has
none to reuse and none to duplicate.

## Tests this owes

In `apps/kelix_modules` (the only place both halves exist):

- one subscriber per topic sees the snapshot, then the pushes, for create / update /
  destroy / ringing / joined / left;
- an **unwatched** conference produces no roster render and no RPC — the assertion
  that the gating is real, not decorative;
- a dead subscriber is dropped by its monitor, without an `unsubscribe`;
- `conference.destroyed` pushes a remove and never a stale row (trap 1);
- a media server going down pushes every one of its conferences as `stale` (trap 2);
- a sweep whose RPC fails reports `stats_error` for that leg and keeps the others;
- `Kelix.Control`'s three functions with the module not loaded.

## Phases

1. Subscriber table + fan-out in `Event.emit/3`, the two row topics, the
   `mark_stale/1` emission, the `Kelix.Control` functions. This alone removes the
   refresh button from the list and the roster.
2. `Kelix.Mod.Mcu.Stats`, `stats_interval_ms`, the stats topic.
3. Documentation: `docs/kelixip/modules/mcu.md` gains the topics, and
   kelixip_liveview.md records the decision with its date, as it does for the other
   three.

## Open questions

- **An event timeline.** The frozen vocabulary could also be relayed verbatim as a
  fourth topic (`{:kelix_mcu_event, %Event{}}`), which is what a "recent activity"
  panel and an audit view want — `participant.rejected` in particular is pushed by
  no topic above, and `ringing − joined` is the abandoned-call rate §11 promises a
  UI can read. Not proposed here: state and timeline are different products, and a
  timeline the UI must persist is a bigger ask than a refresh button.
- **Per-domain filtering.** The list topic pushes every conference of the node; a
  multi-tenant kelescope would want one domain. The row carries `domain`, so
  filtering client-side works today; a server-side filter is one argument away if
  the tenancy boundary must be enforced on this side.
- **Admin tracing.** `conference.create` and `conference.delete` already take an
  `admin` name (kelixip_liveview.md, 2026-09-08). `conference.update`,
  `participant.delete` and `slot.update` do not, and they are just as destructive
  from an operator's seat.
