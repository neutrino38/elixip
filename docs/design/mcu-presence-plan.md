# mcu-presence-plan.md — conference rooms as presentities

**Status: implemented, MP1 to MP4 (2026-09-27).** The presence design is
[DESIGN-PRESENCE.md](DESIGN-PRESENCE.md), the MCU design
[DESIGN-MCU.md](DESIGN-MCU.md); this document is the order the link between the two
gets built in, what each phase delivers, and what proves it.

## 1. What a watcher sees

A conference room is a presentity: its resource is `sip:<did>@<domain>`, package
`presence`. A watcher subscribes to it alone or as an entry of its buddy list
(RFC 4662), exactly as it would to a user.

| The conference | The state notified |
|---|---|
| exists, live on its media server, not full | `open` |
| exists, live, `Conference.full?/1` | `open` with the RPID activity `busy` |
| exists, `stale: true` (its media server went away) | `closed` |
| does not exist | no state: `noresource` |

`busy` keeps `<basic>open</basic>`: a full room is still a reachable resource in
PIDF terms (RFC 3863), and what it is doing is what RPID (RFC 4480) carries — which
is also what Linphone reads to show "busy". Full is the quota test the admission
already applies: a ringing leg holds a slot, so the room reads `busy` exactly when
the next caller would get the `486`.

## 2. Decisions

| # | Decision | Why |
|---|---|---|
| 1 | Busy is `open` + `<rpid:busy/>` | see §1 |
| 2 | A resource with no state ends the subscription with `terminated;reason=noresource` — at subscribe time and when a pushed state becomes `nil` | a watcher waiting on an explicitly closed state for a resource that does not exist waits for nothing; this also holds for a domain with no registrar |
| 3 | The MCU is read through its existing live push, `Kelix.Mod.Mcu.subscribe_conferences/1` | the row it pushes (`domain`, `did`, `stale`, `participants`, `max_participants`) already answers the question, on every conference and participant transition, with no change to the MCU module |
| 4 | Neither `mcu` nor `presence` depends on the other; a third module, `mcu_presence`, holds the link | both are optional packages; a node with an MCU and no presence, or the reverse, must not change |
| 5 | Presence learns a **generic** reported-state source instead of a second hard-coded one | the registrar is hard-coded today (`registered`, a MapSet); an MCU next to it would be the second copy of the same mechanism |

## 3. Phases

### MP1 — presence: reported states

A module other than presence may state the presence of a resource on its own
authority.

```elixir
Kelix.Mod.Presence.report(domain, user, source :: atom, doc :: SIP.Presence.Doc.t() | nil)
  :: :ok | {:error, :down | :timeout}
```

- stored per `{resource, source}`; `nil` withdraws the source's state;
- the reporting process is monitored: when it dies, every state it reported is
  withdrawn and the watchers are pushed what follows;
- a change of the **resolved** state is pushed to the watchers, and only then.

The state of a resource becomes, in order:

1. the live document its presentity PUBLISHed;
2. a reported state (`source: :mcu` in this plan);
3. `open` while registered, from the registrar;
4. `closed` on a registrar domain for a user `auth_db` knows;
5. no state, `nil`.

The registrar keeps its own path; moving it onto `report/4` is a later, optional
phase.

**Existence.** The reference subscribe script answers `404` to a presentity
`Kelix.Mod.AuthDb.subscriber?/2` does not know, and a DID is not a subscriber. The
question "does this presentity exist" moves to the module, which owns every source:

```elixir
Kelix.Mod.Presence.exists?(sip_ctx, aor) :: boolean
# a subscriber auth_db knows, or a resource some source reports a state for
```

Control and panel: `kelictl presence list/show` and the kelescope presence panel
list a reported state with its `source` (`mcu`), as they list `registrar` today.

Proved by: unit tests of the resolution order; a reported state pushed to a
watcher; the reporter's death withdrawing its states; a PUBLISH taking precedence
over a report and the report coming back when the publication expires.

### MP2 — the reference scripts: `noresource`

`presence-subscribe.exs`:

- `authorize` asks `Kelix.Mod.Presence.exists?/2` instead of `AuthDb.subscriber?/2`;
- `subscribe`: `watch/2` answering `{:ok, nil}` ends the subscription with
  `terminate_subscription(:noresource)` instead of notifying `closed`;
- `subscribed`: a pushed `nil` ends it the same way.

A single SUBSCRIBE to a DID that is no room is therefore a `404`, as for an
unknown user; `noresource` is what a buddy-list entry gets, and what a watcher
gets when the room is destroyed under it. `presence-rls.exs` already reports a
`nil` entry as `noresource` and is unchanged.

The module doc's *State of a resource* and the `subscribed` example follow.

Proved by: the subscribe script's tests — unknown presentity `404`, state vanishing
while subscribed ends in `terminated;reason=noresource`.

### MP3 — the `mcu_presence` module

`Kelix.Mod.McuPresence`: a GenServer, no SIP function, no script.

- at start, `Kelix.Mod.Mcu.subscribe_conferences(self())`: the snapshot is mapped
  and every room reported;
- `{:kelix_conferences, {:upsert, row}}`: the document is computed (§1) and
  reported **only if it changed** — a participant joining a half-empty room
  changes no presence, and must not cost every watcher a NOTIFY;
- `{:kelix_conferences, {:remove, uid}}`: `report(…, nil)`. The message carries only
  the `uid`, so the module keeps `uid => {domain, did}`;
- it monitors the MCU module's subscription owner (returned by `subscribe`) and the
  presence module: an MCU restart is a re-subscribe and a full resync, a presence
  restart a full re-report (presence dropped every state with the old reporter).

Configuration:

```toml
[module.mcu_presence]
# every key optional
domains = ["example.com"]   # absent: every domain the MCU holds rooms on
```

`validate_config/1` refuses the block when `mcu` or `presence` is not loaded,
so a node missing one of them fails at start, not on the first SUBSCRIBE.

Control: `kelictl mcu_presence list` — the rooms reported and the state each was
given.

Proved by: unit tests of the row → document mapping; the resync after an MCU and
after a presence restart.

### MP4 — end to end, packaging, documentation

Integration test in `apps/kelix_modules` (the only app holding both halves): a
watcher on a DID, alone and through a list —

1. the room is created → `open`;
2. filled to `max_participants` → `open` + `busy`; a leg leaves → `open`;
3. its media server lost (`stale`) → `closed`; back → `open`;
4. destroyed → `terminated;reason=noresource` (alone), `noresource` entry (list).

Packaging: `kelixip-mod-mcu_presence`, requiring `kelixip-mod-mcu` and
`kelixip-mod-presence`, in both the RPM and the deb build.

Documentation: `docs/kelixip/modules/mcu_presence.md` (on the model of `mcu.md`),
a *Reported states* section in [DESIGN-PRESENCE.md](DESIGN-PRESENCE.md), and a
pointer from `presence.md` and `mcu.md`.

## 4. Out of this plan

- **Richer room state** — who speaks, how many are in, a `note` with the room's
  name. The document can carry it; nothing asks for it yet.
- **The `conference` event package** (RFC 4575) — the roster itself, for a
  participant. Its own package over the same subscription layer.
- **The registrar on `report/4`** — see MP1.
