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

Three decisions shape the whole plan:

- **One journal per scenario instance.** Turning it on again after an `off`
  continues the same journal; it never opens a second one. A journal is
  addressed by the instance id `kelictl monitor` prints.
- **The node keeps the journal, not a rendering of it.** `Kelix.Traces` holds the
  list of events and the run's metadata. It renders nothing.
- **Rendering belongs to the consumers.** `kelictl` draws the text ladder and the
  PlantUML, and kelescope draws its popup, each from the same stored journal.

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
| Know which calls are journalled | nothing: the monitor row has no such field, and `debug_scenario/2` only says the request was delivered | **Missing** (A4) |
| List of kept journals | `Kelix.Control.traces/0`, a snapshot | Partial: **no push** (A6) |
| Read one journal | `Kelix.Control.trace/1` → **rendered PlantUML** documents | **Wrong shape**: the node renders, and keeps no structure a popup can lay out (A1, A5) |
| One journal per instance | an instance can leave several (`on`, `off`, `on`) | **To change** (A5) |
| The SIP messages themselves | `SIP.Scenario.SipTrace` keeps a label (`INVITE #1 +SDP`), not the message | **Missing** (A2) |
| Readable bodies | received `deflate` is decoded by the parser; received **`gzip` is refused with a 415**; an **outgoing** compressed NOTIFY reaches the transaction layer already deflated | **Missing** (A3) |
| Text ladder for `kelictl` | none | **Missing** (A7) |

The gap underneath most rows: `FSL.Host.journal_output/3` hands the host a
rendered document, not the events it was rendered from.

---

## 2. Part A — the node

### A1. FSL 0.5.0: the host takes the journal before any rendering

`../finite-state-language/elixir`, a minor version.

- New optional callback `c:FSL.Host.journal_events/2`: `(events, meta) ::
  {:ok, where} | {:error, reason} | :default`. `events` are the journal's own
  events merged with those collected (`journal_collect/0`), ordered by `:at`.
- `FSL.Journal.flush/0` calls it **first**. `{:ok, _}` / `{:error, _}` end the
  flush: **nothing is rendered**. `:default` (or a host without the callback)
  falls through to what 0.4.0 does: render, then `journal_output/3`, then the
  file.
- Tests: a host taking the events renders nothing (a renderer that raises proves
  it); `:default` renders as before; the events handed over include the
  collected ones.
- CHANGELOG, `docs/design.md` §7.2, the `FSL.Host` moduledoc tables.

No renderer is added to FSL: the text ladder belongs to `kelictl` (A7).

### A2. The SIP messages themselves

`SIP.Scenario.SipTrace.event/3` adds to each `:message` event:

- `body`: the whole message as text, headers and body. It is built by the
  message layer (A3), never re-read here;
- `clipped: true` when the text is cut at 8 KiB. Only messages of a traced
  dialog pay for it.

A `[debug] max_trace_bytes` bound (default 1 MiB per journal) protects the
store from a pathological call. Past it, `Kelix.Traces` stops appending and
records a `:cut` event, as Trix does.

### A3. Bodies are shown decoded: `deflate` and `gzip`

The rule of CLAUDE.md applies: reading a message belongs to the message layer, in
one place.

- **`gzip` on receive.** `SIP.Msg.BodyCoding.decode/2` learns `gzip` (and
  `x-gzip`) with `:zlib.gunzip/1`, and `supported/0` then says
  `"deflate, gzip, identity"`. This is a protocol change and not only a debug
  one: a peer sending a gzip body gets its request processed instead of a 415.
  Test it as such.
- **Bounded inflation.** Neither format is bounded today: a small compressed body
  can inflate to any size. Inflate with a limit, the node's
  `max_message_size`, and treat going past it as `{:error, :corrupt}`, which
  answers the same 415. A compression bomb must not reach the parser.
- **The readable text of a message**, one function in the message layer, for
  instance `SIPMsg.readable/1`: the message serialized with its body **decoded**.
  - A received message is already clear, since the parser decodes it.
  - An outgoing one may carry a deflated body with its `Content-Encoding`: the
    dialog compresses a large NOTIFY. It is decoded with `BodyCoding.decode/2`
    and `SIP.Msg.Ops.body_encoding/1`.
  - A retransmission arrives as its wire form: parse it, which decodes it.
  - The `Content-Encoding` line stays in the text as it was sent. The event
    records `decoded_from: "deflate" | "gzip" | nil`, so the reader knows the
    body was compressed on the wire.
  - A body that will not decode is shown as `<N octets, <coding>, not
    decodable>`, never as raw binary.
- Tests: in and out, deflate (zlib and raw) and gzip, retransmission, the bomb
  bound, a corrupt body.

### A4. The monitor row says whether a call is journalled

- `SIP.FSL.Host.monitor_columns/0` gains `traced: false`.
- `journal_started/1` notes `FSL.Monitor.note(:traced, true)` and
  `journal_events/2` notes `false`. Both run in the instance's process. This
  covers every way a journal starts: operator, `debug` flag, `--log-sequence`.
- `Kelix.InstancePool`: `:traced` joins `@empty_fsm` (default `false`) and
  `@fsm_keys`. The existing `{:fsl_monitor, {:updated, …}}` path already
  re-broadcasts the joined row to `subscribe_monitor/1` subscribers.
- `kelictl monitor` marks a journalled row, e.g. a `●` after the id.
- elixipp's `--monitor` declares its own columns and is unaffected.

### A5. `Kelix.Traces` keeps one journal per instance, unrendered

`SIP.FSL.Host.journal_events/2` replaces its `journal_output/3`. It calls the
`{module, function}` named by `:elixip2, :sequence_output` with `(events, meta)`,
and answers `:default` when none is set, so elixipp still gets its file.
kelixip names `Kelix.Traces.store/2`.

An entry, keyed by the instance id (`meta.slot`):

```elixir
%{
  id: pos_integer,             # the monitor's instance id
  scenario: String.t(), domain: String.t() | nil, script: String.t() | nil,
  pid: pid,                    # monitored: `running` follows it
  first_written_at: DateTime.t(), last_written_at: DateTime.t(),
  meta: map,                   # FSL.Journal meta of the FIRST segment (t0 included)
  events: [event],             # the journal, oldest first (§4.3)
  bytes: non_neg_integer
}
```

- **One entry per instance.** A second flush for the same id (on, off, on, …)
  **appends** its events. The `journal off (state)` and `journal on (state)`
  notes the runner records already mark the gap, and `:at` is monotonic on the
  node, so times stay consistent against the first `t0`.
- A run with no slot (not started by the pool) is keyed by its pid and has
  `id: nil`. This is rare on a node, but it must not crash.
- **Retention** counts from `last_written_at`. **Eviction** past `max_traces`
  drops the entry written least recently. `running` comes from monitoring `pid`,
  and its change is pushed (A6).
- `Kelix.Traces` renders nothing and interprets nothing. It stores, bounds,
  expires and pushes.

### A6. Pushes when a journal is kept, grows, or goes

On the model of `subscribe_monitor/1`:

- `Kelix.Control.subscribe_traces(pid)` returns the snapshot and registers `pid`
  in the same call;
- `pid` then receives
  - `{:kelix_traces, {:upsert, summary}}` when a journal is stored or appended
    to, or its instance ends (`running` goes false);
  - `{:kelix_traces, {:remove, id}}` when it expires or is evicted;
- `unsubscribe_traces(pid)`; a dead subscriber is dropped (monitored), which
  also covers a kelescope node that disconnects;
- expiry must now push, so an entry is dropped at its own deadline, by a timer
  or by a sweep at the earliest deadline, not only filtered on read.

A summary is the entry without `events` and `meta` (§4.2). The journal itself is
fetched on demand: the push stays small, and a panel listing fifty journals
does not receive fifty of them.

### A7. `kelictl debug show`: the ladder, or PlantUML

```console
$ kelictl debug show 12                 # sngrep-like text ladder (default)
$ kelictl debug show 12 --format-puml   # PlantUML
```

Both render in `kelictl` (`Kelix.Control.CLI`, or a module beside it such as
`Kelix.Control.CLI.Ladder`), from `Kelix.Control.trace(id)`:

- **`--format-puml`**: `FSL.Diagram.PlantUML.render(events, meta)`. The package
  renderer takes the stored journal as it is.
- **The ladder**, by default: one column per lane (local; each peer of
  `FSL.Diagram.message_lanes/1`; media when used), one line per event, the time
  on the left (from `FSL.Diagram.stamp/2` or its seconds equivalent), arrows
  between the columns, and state and command notes indented under the local
  column:

  ```
              1000                  dev71.dev.ives.fr:443/wss
              |                             |
    +0.641s   |------ INVITE #1 +SDP ------>|
    +0.756s   |<-- 407 Proxy Authenticat… --|
    +0.756s   |---------- ACK #1 ---------->|
    +0.766s   |   send_auth_INVITE          |
    +5.139s   |<--- 200 OK / 2 INVITE +SDP -|
    +5.302s   | calling -> call_answered    |
  ```

  - Width about 100 columns, or the terminal's when known. Labels are truncated
    with `…`, never wrapped.
  - A retransmission is marked `(r)`. With more than two peer lanes, arrows
    span the columns in between.
  - The header names each lane and its Call-ID, as PlantUML's does.
  - The bodies are not printed; `--full` prints each message's `body` after its
    arrow line, which is what sngrep's message view gives.
- `--format-puml` is accepted anywhere after `show` (`pop_flag/2`), and
  completion offers it and `--full`.
- REST: `GET /traces/:id` answers the journal as JSON (§4.3). Rendering is not
  the node's job, so there is no `format=` there. A curl user who wants the
  ladder runs `kelictl`.
- Help topic `debug`, `docs/kelixip/administration.md` (the example becomes a
  ladder), `rest-api.md`.
- Tests: the ladder of a fixed journal (one lane, two lanes, media, truncation,
  `(r)`, `--full`), and `--format-puml` against the renderer's own output.

### A8. Tests and docs

- kelixip:
  - the `traced` column is set and cleared, and `subscribe_monitor` sees both
    upserts;
  - on/off/on gives **one** entry whose events hold both segments;
  - `subscribe_traces` gets `:upsert` on store, on append and on the instance's
    end, and `:remove` on expiry and on eviction;
  - a call against the mockup transport stores bodies, decoded and clipped.
- Docs:
  - `docs/design/debug-improvments.md`;
  - `DESIGN-FSL.md` §3.10: `journal_events/2` replaces `journal_output/3`, plus
    the `traced` column;
  - `docs/kelixip/administration.md`;
  - `docs/kelixip/installation.md`: `max_trace_bytes`, and the entry that is
    now one per instance.
- A release-note section "kelescope shows a scenario's journal", with the
  contract of §4, as 1.5.3 and 1.6.1 did for their panels. It must also name the
  **`gzip` change** (A3), which is visible to peers.

Order: A1 (FSL, publish 0.5.0) → A3 → A2 → A5 → A4, A6 → A7 → A8.

---

## 3. Part B — kelescope

kelescope is clustered with the node and calls `Kelix.Control` directly, as it
does for the monitor, registrations, presence and conferences. Follow the
patterns already in kelescope for those panels: where it subscribes, how it
handles a node that goes away and comes back, and the confirmation popup that
asks for an operator name before `shutdown_scenario/2`.

kelescope renders the journal itself. Add the hex dependency
`{:fsl, "~> 0.5", hex: :finite_state_language}` to use:

- `FSL.Diagram.message_lanes/1` for the lanes;
- `FSL.Diagram.PlantUML.render/2` for the `.puml` download;
- `FSL.Diagram.command_label/1` and `media_label/1`, rather than re-deriving
  them.

### B1. The live monitor shows journalled calls

- Each monitor row has `traced` (§4.1). A `true` row shows a **DEBUG badge** and
  the scroll icon (B3), in the style of the existing state badges.
- Row actions:
  - **"Journal on"** when `traced` is false: confirm with an operator name (the
    same popup as Stop), then `debug_scenario(id, :on, admin)`. The badge
    appears when the pushed row says `traced: true`, not when the call
    returns: that is the proof the instance took the request.
  - **"Journal off (write now)"** when `traced` is true:
    `debug_scenario(id, :off, admin)`. The journal is then stored and arrives as
    `{:kelix_traces, {:upsert, …}}` (B2).
- `{:error, :not_found}` means the call ended in the meantime: say so, and drop
  the row if the `:remove` push has not arrived yet.

### B2. The "Kept journals" panel

- Subscribe with `subscribe_traces(self())` when the panel (or the node view)
  mounts; unsubscribe when it goes away. Resubscribe after a node reconnect: the
  snapshot is the truth, and a restarted node has **none** (they live in memory).
- One row per instance.
  - Columns: instance id, scenario, domain, script, last written (local time),
    `running` / `ended`, SIP messages, **kept for** (a countdown to
    `expires_at`), and the scroll icon.
  - `:upsert` inserts or replaces the row by `id`; `:remove` drops it.
- If the popup of an entry is open:
  - on `:upsert` with a newer `last_written_at`, offer "journal updated —
    reload";
  - on `:remove`, keep the dialog and show "no longer kept on the node".
- Empty state: "No journal kept. Turn one on from the monitor." Mention the
  retention and capacity (`limits` in the snapshot, §4.2).

### B3. The journal popup

Modelled on Trix's call log: `trix-web-client/src/ui/tracedialog.ts` and the
`.trace-*` rules of `src/ui/theme.css`. Port the look, not the code: kelescope's
stack decides the component, but the choices below are what makes it read well.

- **The dialog.** A native `<dialog>` opened with `showModal()`. It gives Escape,
  focus trap, inert background and focus return for free. A click on the
  backdrop closes it too.
- **Header.** "Journal of `<scenario>` — instance `<id>`", then last written +
  number of SIP messages. Actions:
  - **Copy** puts the journal on the clipboard as text, built by kelescope as
    Trix's `traceAsText`: one line per event, time, arrow, head, then the body.
    If the clipboard is refused, say so on the button; the text stays
    selectable.
  - **Download .puml** runs `FSL.Diagram.PlantUML.render(events, meta)` and
    saves `<scenario>_<id>.puml`.
  - **Close.**
- **Body.** One line per event of `trace(id)` (§4.3), in order, monospace,
  left-aligned.
  - Time is `(at - meta.t0) / 1000` ms, shown `+0.641s`.
  - `:message`: a `<details>` whose summary is the time, the arrow (`→` for
    `dir: :out`, `←` for `:in`, coloured like Trix: accent for out, green for
    in), the lane label when there are several lanes, and `label`.
    - Unfolded, it shows `body` in a `<pre>`, with "(clipped)" when `clipped`
      and "body shown decoded (`decoded_from`)" when set.
    - `repeat` dims the line; `reply` may indent it slightly.
  - `:transition`, `:command`: a plain line on the soft background, as Trix's
    `fsm` lines. A `:command` of type `:media` and a `:transition` of type
    `:media` get the media colour.
  - `:terminal`: green for `succeeded`, red for `failed`, neutral for `aborted`.
  - `:cut`: the orange "journal truncated" line.
  - **Any other kind is skipped**, as FSL's renderers do, so a newer node does
    not break an older kelescope.
- **Accessibility**, as in Trix: the arrow has an `aria-label` ("sent" /
  "received"); the content stays LTR whatever the UI direction.
- **CSS** to start from (Trix, `theme.css`, `.trace-dialog` … `.trace-cut`):
  - dialog width `min(780px, 92vw)`, max height `82vh`;
  - header and body in a flex column, the body scrolling alone;
  - lines padded `0.32rem 1rem`, monospace `0.76rem`;
  - `<pre>` indented `2.4rem` on the ground colour.

### B4. Opening the popup

- From the kept panel: the scroll icon → `trace(id)` → popup.
- From a live, journalled row: nothing is stored until the journal is flushed.
  - The icon offers "Write now and show": `debug_scenario(id, :off, admin)`,
    then open the popup on the next `{:upsert, %{id: ^id}}`.
  - Show a spinner while waiting, and a message after a few seconds: an
    instance busy outside a wait sees the request only at its next one.
- The operator may then turn it on again: the same entry grows, and the popup
  offers to reload (B2).

### B5. Tests

- Rendering of each event kind from a fixed journal fixture. Copy it from a real
  `trace/1` answer once Part A is up: a WebRTC call with a 407, bodies
  included.
- The monitor badge driven by upserts; the kept panel driven by `:upsert` and
  `:remove`; resubscribe after a node reconnect.
- The popup:
  - Escape and backdrop close it;
  - Copy gives the text and Download gives the PlantUML of the same journal;
  - a removed entry keeps an open popup readable;
  - an unknown event kind is skipped.

### B6. Done when

On a node running Part A, with a call going through it:

1. "Journal on" from the monitor: the badge appears;
2. "Write now and show": the popup opens with the INVITE… lines, bodies
   unfolding, a compressed NOTIFY readable;
3. "Journal on" again, then hang up: the same kept row updates to `ended`, and
   its popup holds both segments;
4. after `[debug] trace_retention` the row leaves the panel on its own;
5. `kelictl debug show <id>` on the node prints the same journal as a ladder,
   and `--format-puml` as PlantUML.

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
subscribe_traces(pid) :: %{limits: %{trace_retention: pos_integer,
                                     max_traces: pos_integer,
                                     max_trace_bytes: pos_integer},
                            traces: [summary]}
unsubscribe_traces(pid) :: :ok
traces() :: [summary]          # least recently written first

# pushed to pid
{:kelix_traces, {:upsert, summary}}
{:kelix_traces, {:remove, id :: pos_integer}}

summary :: %{
  id: pos_integer,             # the monitor's instance id: one journal per instance
  scenario: String.t(),
  domain: String.t() | nil,
  script: String.t() | nil,
  first_written_at: DateTime.t(),   # UTC
  last_written_at: DateTime.t(),    # UTC
  expires_at: DateTime.t(),         # UTC, last_written_at + trace_retention
  running: boolean(),               # the instance is still alive
  sip_count: non_neg_integer(),
  bytes: non_neg_integer()
}
```

### 4.3 One journal

```elixir
trace(id) :: {:ok, Map.merge(summary, %{meta: meta, events: [event]})}
           | {:error, :not_found}

meta :: %{scenario: String.t(), pid: String.t(), slot: term, joined_in: atom | nil,
          config: keyword, t0: integer}      # FSL.Journal meta, first segment;
                                             # config has its secrets as the
                                             # scenario declared them: mask with
                                             # FSL.Diagram.mask/2 before showing

event ::                                     # FSL.Journal events, oldest first;
                                             # `at` in monotonic µs, compare to meta.t0
    %{kind: :transition, at: integer, to: atom | String.t(), event: String.t(),
      type: atom | nil}
  | %{kind: :command, at: integer, type: atom | nil, name: String.t()}
  | %{kind: :terminal, at: integer, outcome: :succeeded | :failed | :aborted,
      reason: String.t(), type: atom | nil}
  | %{kind: :message, at: integer,
      dir: :in | :out,
      lane: String.t() | nil,                # the Call-ID
      party: String.t() | nil,               # the leg tag
      peer: String.t() | nil,                # "10.0.0.1:5060/udp"
      label: String.t(),                     # "INVITE #1 +SDP", "200 OK / 1 INVITE"
      reply: boolean, repeat: boolean,
      body: String.t() | nil,                # the message as text, body decoded
      clipped: boolean,
      decoded_from: String.t() | nil,        # "deflate" | "gzip"
      method: atom | nil, code: integer | nil, reason: String.t() | nil,
      cseq: String.t() | nil, sdp: boolean}
  | %{kind: :cut, at: integer}               # max_trace_bytes reached
  # any other kind: skip it
```

Everything is plain data (strings, integers, booleans, atoms, `DateTime`), so it
crosses the distribution as is and encodes to JSON: `GET /traces` and
`GET /traces/:id` answer the same shapes.

The `config` in `meta` is the scenario's `config` block, and may hold a
password. kelescope masks it with `FSL.Diagram.mask/2`, as the renderers do,
before showing it. The node does not strip it, because `kelictl --format-puml`
relies on the renderer doing that masking.

---

## 5. Out of scope

- Reading a live journal **without** writing it out. That would need the
  instance to hand over a copy of its journal while the SIP messages stay in the
  trace table, which is a peek mechanism of its own. B4's "write now" covers the
  need meanwhile.
- Turning the journal on for the **next** calls of a script or a domain: a
  separate design.
- Persisting journals across a restart: they are an operator's working
  material, deliberately memory only.
