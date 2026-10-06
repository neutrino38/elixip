# presence-composite-plan.md — the composite state of a presentity, first slice

**Status: planned 2026-09-30. PC0, PC1 and PC2 done 2026-10-01, PC3 and PC4
done 2026-10-02; decisions 1, 2 and 3 taken. The third symptom of §1 is not
fixed by composition: it stays a documented limitation (decision 3).** The presence design is
[DESIGN-PRESENCE.md](DESIGN-PRESENCE.md); this document is the order the first
slice of objective 1 — *a composite state* — gets built in, what each phase
delivers, and what proves it.

## 1. Why now

Since 2026-09-30 a presentity holds **one publication per device**, bound to the
device's connection and registration (DESIGN-PRESENCE.md,
[One publication per publisher](DESIGN-PRESENCE.md#one-publication-per-publisher)).
Between devices, what is notified is the publication whose state changed last.
That rule is honest and it is wrong in three observed ways:

| Symptom | Why |
|---|---|
| Bob sets *away* on his phone, closes it: he shows *available* again | the desk phone's publication, two hours old, is all that is left |
| A device subscribed to itself must republish what it is told, or the above happens | its own publication keeps its own old state |
| Two devices behind a proxy, on one connection, overwrite each other | they are one publisher, and one publication per publisher |

All three come from treating a presentity's state as one device's document.

## 2. The rule: tuples per device, one person

PIDF (RFC 3863) and the RFC 4479 data model already separate the two levels, and
so does `SIP.Presence.Doc`:

| Level | What it holds | Composition |
|---|---|---|
| **Tuples** | reachability per device: `open`/`closed`, contact | the **union** of the tuples of every live publication. Bob is open when one device is (`SIP.Presence.Doc.status/1` already answers the disjunction) |
| **Person** | what the user is doing: `activity`, `note` | **one** state per presentity, the last one a device expressed — and a modification with no activity expresses "none" (decision 1). It survives the departure of the device that set it, as long as one publication of the presentity remains |

What a watcher is sent is the composite document. A device subscribed to its own
presentity receives it and has nothing to republish.

## 3. Scope

In: the `presence` package; the publications of one presentity; the person facet;
the registration's place in the composite (PC4, decision pending).

Out, each its own plan: call occupancy overriding the published activity
(`on-the-phone` from `dialog_state` — today a reported state, ranked below a
publication); location; devices registered for push; partial state
(`application/pidf-diff+xml`, RFC 5262); consent (`presence.winfo`).

## 4. Phases

### PC0 — traces (prerequisite, provided by the user) — done 2026-10-01

Real PUBLISH traffic from **Trix** and **Linphone**, one AOR, both clients:

- the initial PUBLISH, a refresh, and the unPUBLISH on a clean exit;
- the user switching to *away* / *busy*, then **back to available**;
- whether each client SUBSCRIBEs to its own AOR, directly or through its list.

The question they answer: when the user goes back to available, does the client
send an empty `<dm:person>`, a `<dm:person>` with no `<rpid:activities>`, or no
`<dm:person>` at all? The first two mean "clear the person state"; the last may
only mean "this device says nothing about the person". Decision 1 is taken on
this evidence, not before. Also read: tuple ids (stable across refreshes?), and
whether a `<contact>` is carried in the tuple.

What they said (Linphone-Desktop 6.2.3, Trix on JsSIP 3.13.8):

| | Linphone 6.2.3 | Trix |
|---|---|---|
| back to available | **no** `<dm:person>` | **no** `<dm:person>` |
| busy / away | `<dm:person>` + `<rpid:activities><rpid:busy>busy</rpid:busy>` | `<dm:person>` + `<rpid:activities><rpid:busy/>` |
| modification | `SIP-If-Match` | `SIP-If-Match` |
| unPUBLISH | `Expires: 0` + `SIP-If-Match`, no body | `Expires: 0` |
| tuple id | changes on every PUBLISH | not established (one per session seen) |
| `<contact>` | the AOR | none |
| subscribes to its own AOR | no — through its RLS list | no |

Neither client ever sends an empty `<dm:person>`: "available" is said by
absence, so an absent person cannot mean "this device says nothing".

### PC1 — the model reads the field bodies — done 2026-10-01

Decision 1 makes "no person element" and "a person with no activity" mean the
same thing, which is what `SIP.Presence.Pidf.parse/1` already reads them as:
`activity: nil`, `note: nil`. The model gains nothing.

Proof: the four PC0 bodies as fixtures (`PIDF-linphone623-*.xml`,
`PIDF-trix-*.xml`), parsed and round-tripped in `pidf_test.exs`.

### PC2 — `SIP.Presence.Doc.compose/2`, pure — done 2026-10-01

In the framework, beside the model: the documents of a presentity's live
publications, in the order their state changed, plus the person state held, give
the composite document.

- Tuples: concatenated. Ids made unique per publication with a **stable**
  per-publication key — the `ruid` column of `presentity`, minted on the initial
  PUBLISH and kept across refreshes and modifications. The entity-tag is not
  stable (a new one per publication), and a tuple id that changes on every
  refresh makes a watcher redraw a device that did not move.
- Person: the held person state.
- Entity: the presentity's URI.

Proof: unit tests — one device, two devices open/closed, person set by one and
kept after it leaves, a cleared person, colliding tuple ids.

As built: `compose(person, [{key, doc}])`. `person` is the held state as a
`%Doc{}` whose `entity`, `activity` and `note` are taken and whose tuples are not;
the person facet each publication carries is ignored — which publication sets or
clears the held state is PC3's. A tuple's id is `t-<key>-<n>`, `n` its position
in its publication: the publisher's own id is dropped, since Linphone mints a new
one on every PUBLISH, and the `t-` prefix keeps it an XML `NCName` whatever the
key starts with. `ruid` is not minted yet (`nil` in every row): PC3 mints it.
Tests in `presence_doc_test.exs`, which also runs the module's doctests.

### PC3 — the collection notifies the composite

`Kelix.Mod.Presence`:

- `current_doc/2` returns `compose/2` of the live publications;
- the person state is held per resource, updated by every publication that
  expresses one (PC1), and dropped with the resource's last publication;
- watchers are pushed when the **composite** changes: a refresh, or a device
  republishing what the composite already says, costs nobody a NOTIFY (the rule
  reported states already follow);
- `kelictl presence list` shows the composite `status`/`activity`; `show` keeps
  one row per publication, with its `ruid`.

Proof: module tests for the three symptoms of §1, each failing before the phase;
the self-subscription case (Bob watching Bob, notified of his other device's
change).

As built: the `ruid` is `SIP.Publication.new_ruid/0`, minted by the collection
on the initial PUBLISH, kept by refreshes and modifications, and kept too by an
initial PUBLISH that replaces the same publisher's publication (same device,
same tuples). Every publication carrying a document sets the person state —
`activity` and `note` — and a refresh leaves it. Only `presence` documents are
composed; any other package keeps the document of the last state change. "The
composite changed" is `SIP.Presence.Doc.same_state?/2`, which ignores the tuples'
timestamps (both clients stamp every PUBLISH). The expiry sweep cannot read back
the state it replaces, so it pushes unconditionally, as before. `kelictl presence
show` gains a `ruid` column.

Proof: the first two symptoms, the union, decision 1, the silent republication
and the stable tuple ids, in `presence_test.exs` (*the composite state*); four of
them fail on the code before the phase. The third symptom is not among them —
see decision 3.

### PC4 — the registration in the composite (decision 2) — done 2026-10-02

Today a registered device that publishes nothing counts only when **nothing** is
published for the presentity. Option: each registered device without a
publication contributes an `open` tuple, so Bob is reachable on his desk phone
even while only his mobile publishes. It changes the precedence between
registration and publication, which DESIGN-PRESENCE.md states; decided before the
phase starts, and possibly dropped.

As built: the option is taken. The registrar script's report now carries the
bindings that reach a device (`Kelix.Mod.Registrar.devices/3`, which
`registered?/3` became a test of), held per resource. Each one no live
publication speaks for — told by the flow, `SIP.Publication.published_over?/2`,
as a publisher is — adds one `open` tuple offering the binding's contact, keyed
by `SIP.Msg.Ops.device_key/1` hashed (instance, else contact). A presentity that
only registers gets the same tuples, one per device, instead of a single
synthetic `open`. A registration is pushed when the composite changes, which
now includes one of several devices leaving (still open, one tuple fewer).
`kelictl presence show` lists one registrar row per device, its key as `ruid`
and its contact as `sender`.

Proof: in `presence_test.exs`, a device that publishes adds no tuple, one that
does not adds an open tuple beside a closed publication and leaves with it, the
published activity is kept beside a registered device; the tests of the former
precedence (registration ignored under a publication, a departing device
unnoticed) are rewritten to the rule.

### PC5 — documentation and field test — documentation done 2026-10-02

`DESIGN-PRESENCE.md` (the composition rule replaces "the most recent state
change"), `docs/kelixip/modules/presence.md` (Limitations: *No composition*
goes), release notes. Field test: Bob on Trix and Linphone at once — away on one,
close it, the watcher and the other device both show away; back to available,
both follow.

As built: DESIGN-PRESENCE.md gains *The composite state*; `presence.md` gains
the section of the same name and loses *No composition*; the release note is
`docs/releases/RELEASE-1.6.2.md`. The field test is pending.

## 5. Open decisions

1. **What clears the person state** — taken 2026-10-01 on the PC0 traces: a
   **modification** whose document carries no activity (no `<dm:person>`, or one
   without `<rpid:activities>`) clears it; a **refresh** (RFC 3903 §4.4, no body)
   leaves it as it is.
2. **Registration tuples** — taken 2026-10-02: with. A registered device that
   publishes nothing is one open tuple of the composite.
3. **Devices behind a proxy** — taken 2026-10-02: a documented limitation for
   now (`presence.md`, *Devices behind a proxy*), the fix deferred. Found in PC3. Composition does not fix the
   third symptom of §1: the two devices are one publisher, so the initial
   PUBLISH of the second replaces the first's publication before anything is
   composed. Telling them apart takes a reading of the PUBLISH that names the
   device beyond the flow — the bottom `Via` sent-by is the candidate — and that
   reading belongs to `SIP.Msg.Ops`. Alternatively, accept it as a documented
   limitation (it is one in `presence.md` today).
