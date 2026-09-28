# Debugging a live scenario from kelescope — implementation plan

Goal: an operator watching a kelixip node in [kelescope](https://github.com/neutrino38/kelescope)

1. turns the journal of a call **on** (and off) from the live monitor, and sees
   which calls are being journalled;
2. sees the scenarios that **ended** but whose journal is still kept, in a panel
   of their own;
3. clicks an icon and reads the journal of one scenario **in a popup**, the way
   Trix shows the log of a call ([Trix's journal popup](#b3-the-journal-popup)).

In the same step, `kelictl debug show` prints a **sngrep-like text ladder** by
default, and PlantUML with `--format-puml`.

The work splits in two:

- **Part A — the node** (this repository, and the FSL package). kelixip does
  not yet offer everything kelescope needs: [§1](#1-what-kelixip-offers-today)
  lists what exists and what is missing. Part A closes the gaps and fixes the
  contract kelescope codes against ([§4](#4-the-contract-kelescope-codes-against)).
- **Part B — kelescope**, on another machine, against that contract. It needs
  nothing from this repository but §4 and a node running Part A.

Part B can start once §4 is frozen. Its end-to-end check needs a node running
Part A.

---

## 1. What kelixip offers today

As of `feat/kelictl-debug` (FSL 0.4.0):

| Need | Today | Verdict |
|---|---|---|
| Turn a live call's journal on / off | `Kelix.Control.debug_scenario/2`, `/3` (with `admin`, logged) → `{:scenario_ctl, :journal, :on \| :off}` to the instance | **OK** |
| Live list of calls, pushed | `Kelix.Control.subscribe_monitor/1` → snapshot + `{:kelix_monitor, {:upsert, row} \| {:remove, id}}` | **OK** |
| Know which calls are journalled | nothing: the monitor row carries no such field, and `debug_scenario/2` only says the request was delivered | **Missing** (A3) |
| List of kept journals | `Kelix.Control.traces/0`, a snapshot | Partial: **no push** (A6) |
| Read one journal | `Kelix.Control.trace/1` → the rendered PlantUML documents of one instance | Partial: **text only**, no structure a popup can lay out, no SIP message bodies (A1, A2, A4) |
| Address one journal | by instance id only; an instance can leave several (`on`, `off`, `on`) | Partial: needs the trace number `n` (A5) |
| Text ladder for `kelictl` | none | **Missing** (A7) |

The gap underneath most rows: `Kelix.Traces` stores the **rendered PlantUML**,
because `FSL.Host.journal_output/3` hands the host the document and not the
events it was drawn from. A popup that lists messages, unfolds their bodies and
copies them as text, and a second text format for `kelictl`, both need the
events. The SIP message bodies Trix shows on unfold are not recorded at all:
`SIP.Scenario.SipTrace` keeps a label (`INVITE #1 +SDP`), not the message.

---

## 2. Part A — the node

### A1. FSL 0.5.0: the host receives the events

`../finite-state-language/elixir`, a minor version.

- New optional callback `c:FSL.Host.journal_output/4`:
  `(document, meta, renderer, events)`, `events` being what the document was
  rendered from, merged and ordered. `FSL.Journal.flush/0` calls `/4` when the
  host exports it, else `/3`, else writes the file. `/3` stays, documented as
  the form for a host that only keeps documents.
- Tests: `/4` preferred over `/3`; `/3` alone still works; the events handed over
  are the ones rendered (collected events included).
- CHANGELOG, `docs/design.md` §7.2, `FSL.Host` moduledoc tables.

### A2. FSL 0.5.0: a text renderer, `FSL.Diagram.Text`

A third renderer beside PlantUML and Mermaid, generic like them. It serves
`kelictl`, and `elixipp` can use it too.

A sngrep-like ladder: one column per lane (local, each peer of
`FSL.Diagram.message_lanes/1`, media when used), one line per event, time on the
left, arrows between columns, notes indented under the local column.

```
            1000                  dev71.dev.ives.fr:443/wss
            |                             |
  +0.641s   |------ INVITE #1 +SDP ------>|
  +0.756s   |<-- 407 Proxy Authenticat… --|
  +0.756s   |---------- ACK #1 ----------->|
  +0.766s   |   send_auth_INVITE          |
  +5.139s   |<--- 200 OK / 2 INVITE +SDP -|
  +5.302s   | calling -> call_answered    |
```

- Width: about 100 columns by default, an option to change it. Labels are
  truncated with `…`, never wrapped. A repetition is marked with a trailing
  `(r)`, and the arrow stays solid.
- With more than two peer lanes, the arrows span the columns in between; the
  header names every lane and its conversation (`peer1: … — Call-ID …`), as
  PlantUML's header does.
- `filename/1` → `<scenario>_<pid>.txt`.
- Tests like the PlantUML ones: untraced run, traced run, several lanes, media,
  truncation.

### A3. The monitor row says whether a call is journalled

- `SIP.FSL.Host.monitor_columns/0` gains `traced: false`.
- `journal_started/1` notes `FSL.Monitor.note(:traced, true)`, and
  `journal_output/4` notes `false`. Both run in the instance's process, so the
  row of that instance changes. This also covers a journal started by the
  `debug` flag or `--log-sequence`, not only by an operator.
- `Kelix.InstancePool`: `:traced` in `@empty_fsm` (default `false`) and
  `@fsm_keys`. The existing `{:fsl_monitor, {:updated, …}}` path already
  re-broadcasts the joined row to `subscribe_monitor/1` subscribers, so no new
  push is needed.
- `kelictl monitor`: mark a journalled row, e.g. a `●` after the id.
- elixipp's `--monitor` declares its own columns and is unaffected.

### A4. The SIP messages themselves

`SIP.Scenario.SipTrace.event/3` adds `body`: the message as text.
`SIPMsg.serialize/1` gives it for a parsed map, and a retransmission already
arrives as its wire form. The body is **clipped** at 8 KiB and flagged
`clipped: true`. Only messages of a traced dialog pay for this.

Memory: 100 traces × a few dozen messages × ~2 KiB is a few MB. A new `[debug]
max_trace_bytes` (default 1 MiB per trace) bounds a pathological call: past it,
the store keeps the head of the journal and a `cut` marker, as Trix does.

### A5. `Kelix.Traces` keeps events, and renders on demand

- `store` receives the events (via A1) and keeps `events` and `meta`, not a
  document. Keep the entry fields of today (`n`, `id`, `scenario`, `domain`,
  `script`, `pid`, `written_at`, …) plus `sip_count`.
- `render(n, :text | :plantuml)` renders through `FSL.Diagram.Text` or
  `FSL.Diagram.PlantUML`.
- `lines(n)` returns the entry normalised for a UI (shape in §4.3). This is the
  one place that turns journal events into display lines, so kelescope and any
  later UI never re-read FSL events themselves.
- Entries are addressed by `n` (unique per node run) for UIs, by instance id for
  `kelictl debug show <id>` (all of that instance's traces, oldest first).

### A6. Pushes when a journal is kept or dropped

On the model of `subscribe_monitor/1`:

- `Kelix.Control.subscribe_traces(pid)` → returns the snapshot
  (`traces/0`'s shape) and registers `pid` in the same call;
- `pid` then receives `{:kelix_traces, {:added, summary}}` when a journal is
  stored, and `{:kelix_traces, {:removed, n}}` when one expires or is evicted
  by `max_traces`;
- `unsubscribe_traces(pid)`; a dead subscriber is dropped (monitored), which
  also covers a kelescope node that disconnects;
- expiry must now push, so the sweep drops an entry on its own deadline rather
  than filtering on read only: a timer per entry, or a sweep at the earliest
  deadline.

### A7. `kelictl debug show`: text by default

```console
$ kelictl debug show 12                 # the sngrep-like ladder (FSL.Diagram.Text)
$ kelictl debug show 12 --format-puml   # PlantUML, as today
```

- `parse(["debug", "show", id | flags])`, with `--format-puml` accepted anywhere
  after `show` (`pop_flag/2`). Completion offers the flag.
- REST: `GET /traces/:id?format=text|plantuml`, default `text`, answered as
  `text/plain`. `GET /traces/:id` with `Accept: application/json` answers the
  summaries and `lines`.
- Help topic `debug`, `docs/kelixip/administration.md` (the example becomes a
  ladder), `rest-api.md`.

### A8. Control functions for kelescope

| Function | Returns |
|---|---|
| `trace_entry(n)` | `{:ok, %{summary..., lines: [line]}}` / `{:error, :not_found}` |
| `trace_render(n, :text \| :plantuml)` | `{:ok, String.t()}` / `{:error, :not_found}` |

`trace/1` (per instance id) stays for `kelictl`.

### A9. Tests and docs

- kelixip: the `traced` column set and cleared (`subscribe_monitor` sees both
  upserts); `subscribe_traces` gets `:added` on flush and `:removed` on expiry
  and on eviction; `lines/1` shape on a call against the mockup transport,
  bodies included and clipped; `--format-puml` and the default text.
- `docs/design/debug-improvments.md`, `DESIGN-FSL.md` §3.10 (`journal_output/4`,
  the `traced` column), `docs/kelixip/administration.md`.
- A release note section "kelescope shows a scenario's journal", with the
  contract of §4, as 1.5.3 and 1.6.1 did for their panels.

Order: A1 + A2 (FSL, publish 0.5.0) → A4 → A5 → A3, A6, A8 → A7 → A9.

---

## 3. Part B — kelescope

kelescope is clustered with the node and calls `Kelix.Control` directly, as it
does for the monitor, registrations, presence and conferences. Follow the
patterns already in kelescope for those panels: where it subscribes, how it
handles a node that goes away and comes back, and the confirmation popup that
asks for an operator name before `shutdown_scenario/2`.

### B1. The live monitor shows journalled calls

- Each monitor row has `traced` (§4.1). A `true` row shows a **DEBUG badge** and
  the scroll icon (B3), in the style of the existing state badges.
- Row actions:
  - **"Journal on"** when `traced` is false: confirm with an operator name (the
    same popup as Stop), then `debug_scenario(id, :on, admin)`. The badge
    appears when the pushed row says `traced: true`, not when the call
    returns: that is the proof the instance took the request.
  - **"Journal off (write now)"** when `traced` is true:
    `debug_scenario(id, :off, admin)`. The journal is then written and arrives
    as `{:kelix_traces, {:added, …}}` (B2). If the operator clicked "show"
    (B4), open it then.
- `{:error, :not_found}` means the call has ended in the meantime: say so, and
  drop the row if the `:remove` push has not arrived yet.

### B2. The "Kept journals" panel

- Subscribe with `subscribe_traces(self())` when the panel (or the node view)
  mounts; unsubscribe when it goes away. Resubscribe after a node reconnect: the
  snapshot is the truth, and a restarted node has **none** (they live in memory).
- Columns: instance id, scenario, domain, script, written at (local time),
  instance `running` / `ended`, SIP messages, **kept for** (a countdown computed
  from `expires_at`), and the scroll icon.
- `:added` inserts a row at the top; `:removed` drops it. If its popup is open,
  keep the dialog and show "no longer kept on the node".
- Empty state: "No journal kept. Turn one on from the monitor." Mention the
  retention and capacity (`limits` in the snapshot, §4.2).

### B3. The journal popup

Modelled on Trix's call log: `trix-web-client/src/ui/tracedialog.ts` and the
`.trace-*` rules of `src/ui/theme.css`. Port the look, not the code: kelescope's
stack decides the component, but the choices below are what makes it read well.

- A native `<dialog>` opened with `showModal()`. It gives Escape, focus trap,
  inert background and focus return for free. A click on the backdrop closes it
  too.
- **Header**: "Journal of `<scenario>` — instance `<id>`", then written at +
  number of SIP messages; actions **Copy**, **Download .puml**, **Close**.
  - Copy puts `trace_render(n, :text)` on the clipboard. If the clipboard is
    refused, say so on the button; the text stays selectable.
  - Download fetches `trace_render(n, :plantuml)` and saves
    `<scenario>_<id>.puml`.
- **Body**: one line per `lines` entry (§4.3), in order, monospace, left-aligned:
  - `sip`: `<details>` whose summary is `at` (`+0.641s`), the arrow (`→` out,
    `←` in, coloured like Trix: accent for out, green for in), the lane label
    when there are several lanes, and `head`. The unfolded body is `body` in a
    `<pre>`, with "(clipped)" when `clipped`. A repetition is dimmed.
  - `state`, `command`, `media`: a plain line on the soft background, as Trix's
    `fsm` lines.
  - `outcome`: green for `succeeded`, red for `failed`, neutral for `aborted`.
  - `cut`: the orange "journal truncated" line.
- Accessibility as in Trix: the arrow has an `aria-label` ("sent" /
  "received"); the content stays LTR whatever the UI direction.
- CSS to start from (Trix, `theme.css`, `.trace-dialog` … `.trace-cut`): width
  `min(780px, 92vw)`, max height `82vh`, header and body in a flex column, the
  body scrolling alone, line padding `0.32rem 1rem`, monospace `0.76rem`,
  `<pre>` indented `2.4rem` on the ground colour.

### B4. Opening the popup

- From the kept panel: the scroll icon → `trace_entry(n)` → popup.
- From a live, journalled row: nothing is written until the journal ends. The
  icon offers "Write now and show": `debug_scenario(id, :off, admin)`, then
  opens the entry whose `id` matches in the next `:added`, with a spinner while
  waiting and a timeout message after a few seconds (an instance busy outside a
  wait sees the request only at its next one).
- An instance can have several entries (on / off / on): the kept panel lists
  them all, each with its `n`.

### B5. Tests

- Rendering of each line kind from a fixed `lines` fixture: copy it from a real
  `trace_entry/1` answer once Part A is up.
- The monitor badge driven by upserts, the kept panel driven by `:added` and
  `:removed`, resubscribe after a node reconnect.
- The popup: Escape and backdrop close it, Copy and Download call the right
  renders, a removed entry keeps an open popup readable.

### B6. Done when

On a node running Part A, with a call going through it:

1. "Journal on" from the monitor: the badge appears;
2. "Write now and show": the popup opens with the INVITE… lines, bodies
   unfolding;
3. hang up with the journal on: the entry appears in the kept panel, `ended`;
4. after `[debug] trace_retention` it leaves the panel on its own;
5. `kelictl debug show <id>` on the node prints the same journal as a ladder.

---

## 4. The contract kelescope codes against

Every function below is in `Kelix.Control`, called on the kelixip node.

### 4.1 Monitor rows (existing, one field added)

`subscribe_monitor/1`, `monitor/0`, and the `{:kelix_monitor, {:upsert, row}}`
pushes: each `row` gains

```elixir
traced: boolean()   # the instance's journal is on right now
```

Turning it on and off:

```elixir
debug_scenario(id :: pos_integer, :on | :off, admin :: String.t() | nil)
  :: :ok | {:error, :not_found}
```

### 4.2 Kept journals

```elixir
subscribe_traces(pid) :: %{limits: %{trace_retention: pos_integer, max_traces: pos_integer},
                            traces: [summary]}
unsubscribe_traces(pid) :: :ok

# pushed to pid
{:kelix_traces, {:added, summary}}
{:kelix_traces, {:removed, n :: pos_integer}}

summary :: %{
  n: pos_integer,              # the journal's own number: what the calls below take
  id: pos_integer | nil,       # the instance id of the monitor, nil if unknown
  scenario: String.t(),
  domain: String.t() | nil,
  script: String.t() | nil,
  written_at: DateTime.t(),    # UTC
  expires_at: DateTime.t(),    # UTC
  running: boolean(),          # the instance still runs (journal written by :off)
  sip_count: non_neg_integer()
}
```

`traces/0` returns `[summary]`, oldest first.

### 4.3 One journal

```elixir
trace_entry(n) :: {:ok, Map.merge(summary, %{lanes: [lane], lines: [line]})}
                | {:error, :not_found}
trace_render(n, :text | :plantuml) :: {:ok, String.t()} | {:error, :not_found}

lane :: %{alias: String.t(), label: String.t(), conversation: String.t()}
        # "peer1", "dev71.dev.ives.fr:443/wss", the Call-ID

line :: %{
  at_ms: non_neg_integer(),    # since the journal started
  kind: :sip | :state | :command | :media | :outcome | :cut,
  dir: :in | :out | nil,       # :sip, and :media events from the server
  lane: String.t() | nil,      # a lane alias, for :sip
  head: String.t(),            # "INVITE #1 +SDP", "calling -> call_answered",
                               # "send_BYE", "media connected", "succeeded: 200 OK"
  body: String.t() | nil,      # the SIP message as text, for :sip
  clipped: boolean(),
  repeat: boolean(),           # a retransmission
  reply: boolean(),            # a response
  outcome: :succeeded | :failed | :aborted | nil
}
```

Every value is plain data (strings, integers, booleans, atoms, `DateTime`), so it
crosses the distribution and encodes to JSON as is. The REST frontal answers the
same shapes (`GET /traces`, `GET /traces/:n?format=…`).

---

## 5. Out of scope

- Reading a live journal **without** ending it. That would need the instance to
  hand over a copy of its journal while the SIP messages stay in the trace
  table, which is a peek mechanism of its own. B4's "write now" covers the need
  meanwhile.
- Turning the journal on for the **next** calls of a script or a domain: a
  separate design.
- Persisting journals across a restart: they are an operator's working
  material, deliberately memory only.
