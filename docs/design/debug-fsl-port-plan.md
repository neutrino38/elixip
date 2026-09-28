# Carrying the SIP trace across the FSL extraction — implementation plan

Step 1 of [debug-improvments.md](debug-improvments.md) (commit `dbe4b8b`) was
written against the in-tree engine: `SIP.Scenario.Runner`,
`SIP.Scenario.SequenceJournal`, `SIP.Scenario.SequenceDiagram`. Release 1.6.1
moved that engine out of the umbrella into the hex package `finite_state_language`
(`FSL.Runner`, `FSL.Journal`, `FSL.Diagram.PlantUML`, `FSL.Diagram.Mermaid`), and
left facades under the SIP names. Merging 1.6.1 into `feat/scenario-debug`
therefore took the deletions, and half of step 1 went with them.

This plan puts it back. It does not reapply the old diff: the package must learn
something **generic**, and SIP plugs into it through `FSL.Host`, the way every
other SIP behaviour does.

## Status (2026-09-28)

- **Phase A done** on the FSL branch `feat/scenario-debug` (`09aff33`), version
  0.3.0, **not published**. One deviation from A4: the first transition
  journalled after a late start is drawn as the state entered (`third`), not as
  `second -> third` — a transition event names where the machine went, not where
  it came from, as in `dbe4b8b`.
- **B1–B6 done** on elixip `feat/scenario-debug`, against the `path:`
  dependency. `mix deps.get` with the `path:` line unlocks `:fsl`'s own
  dependencies and upgrades `req`; `mix deps.unlock fsl` before it keeps the rest
  of the lock as it was.
- **Remaining:** publish 0.3.0, switch B1 to hex, B7 (real traffic).

## 1. State after the merge

**Kept, and still wired:**

- `SIP.Scenario.SipTrace` (`apps/elixip2/lib/dsl/SIPScenarioSipTrace.ex`) — the
  ETS sink, unchanged;
- the transaction hooks: `SIP.Transac.Common.sendout_msg/2`, the two
  retransmission timers of `SIP.Trans.Timer`, the last-response resend in
  `SIP.IST` / `SIP.NIST`, the eight `{:onsipmsg, …}` clauses;
- the dialog binding, now in **one** place: `SIP.DialogImpl.bind_app/2` (1.6.1
  routes all three sites where a dialog learns its application through it).

**Lost with the deleted files** — every item below exists in `dbe4b8b`, readable
with `git show dbe4b8b -- <path>`:

| What | Was in | Why it is needed |
|---|---|---|
| `at:` (monotonic µs) on every journal event, `t0` in the metadata | `SIPScenarioSequenceJournal.ex` | the only way to interleave messages recorded by other processes |
| `SipTrace.watch/0` at journal start | same | nothing is recorded until the scenario watches itself |
| merge of `SipTrace.take/0` into the events at `flush/0`, drop at `clear/0` | same | the trace never reaches the diagram |
| `adopt_dialog/1`, `record_inbound_request/1` | same | a UAS instance's dialog and request predate its journal |
| journal start re-checked after every state | `SIPScenarioRunner.ex` | `ctx_set(:debug, true)` in a state |
| lanes per Call-ID, request/response arrows, grey retransmissions, `+Nms` stamps, commands as `hnote` when traced | `SIPScenarioSequenceDiagram.ex` | the rendering itself |
| the renderer tests | `test/sequence_diagram_test.exs` | |

**Disabled:** the end-to-end describe block of
`apps/elixip2/test/sequence_trace_test.exs` (`@describetag :skip`). The sink's
unit tests above it stay active: they do not need the journal.

The trace is inert, not broken: the table is never created, so every
transaction hook returns on its `:ets.whereis`.

`ELIXIPP.md` ("Sequence diagram") describes the target, not this state: until
phase B lands, `--log-sequence` draws the untraced diagram of 1.6.1.

## 2. The division of labour

The test for "which side" is the one the extraction applied: `:fsl` does not
depend on `:elixip2`, and `mix compile --warnings-as-errors` in the package proves
it. Anything that names a Call-ID, a CSeq, SDP, a transaction or a dialog is SIP.

| Concern | Side | Mechanism |
|---|---|---|
| timestamps, `t0` | FSL | `FSL.Journal` stamps every event it records |
| starting the journal late | FSL | `FSL.Runner` re-checks after every state |
| "events recorded elsewhere, merge them in" | FSL | new optional host callbacks (A3) |
| drawing a message exchanged with a peer, on a lane of its own | FSL | new event kind `:message` (A2), both shipped renderers |
| what a SIP message *is* — label, lane key, request or response, retransmission | SIP | `SIP.Scenario.SipTrace` builds the `:message` event |
| watching, adopting the dialog, the inbound request | SIP | `SIP.FSL.Host` answers the callbacks |

**Rejected: a SIP renderer in elixip** (`diagram_renderer/0` returning a
`SIP.Scenario.SequenceDiagram` that draws everything). It needs no new event
kind, but it duplicates ~200 lines of `FSL.Diagram.PlantUML` — lanes, notes,
masking, media — which then drift, and Mermaid gets nothing. A lane per peer
conversation is not SIP: an XMPP or Matrix binding has conversations too.

## 3. Phase A — the package (`../finite-state-language/elixir`)

Work on the FSL repository checked out next to elixip. Elixip picks it up
through a `path:` dependency during the work (B1).

### A1. Timestamps

- `FSL.Journal.start/1`: `Map.put(meta, :t0, now())`.
- Every event built by the journal gets `at: now()`, with
  `now() = System.monotonic_time(:microsecond)`.
- Update `@type event`, `@type meta`, and the event list in the `FSL.Diagram`
  moduledoc. Adding a key is compatible: a renderer that does not read `:at`
  ignores it.
- Both renderers prefix every label with `+Nms ` when the event has `:at` and the
  metadata has `:t0` (the `stamp/2` of `dbe4b8b`), and nothing otherwise.

### A2. The `:message` event kind

Shape, documented in `FSL.Diagram` next to the three existing kinds:

```elixir
%{
  kind: :message,
  at: integer(),
  dir: :in | :out,
  lane: term(),               # the conversation it belongs to (SIP: the Call-ID)
  party: String.t() | nil,    # local label of that conversation (SIP: the leg tag)
  peer: String.t() | nil,     # the far end (SIP: "10.0.0.1:5060/udp")
  label: String.t(),          # drawn as is
  reply: boolean(),           # dashed arrow
  repeat: boolean()           # dimmed arrow
}
```

Rendering, in `FSL.Diagram.PlantUML` and `FSL.Diagram.Mermaid`, after
`dbe4b8b`'s `SIPScenarioSequenceDiagram.ex`:

- **lanes:** one participant per distinct `lane`, in order of first `at`, aliased
  `peer1`, `peer2`…, labelled with the first non-nil `party` and the first non-nil
  `peer` joined by a space, else `peer N`. A header comment lists
  `alias: label — lane`. Put the lane computation in `FSL.Diagram` so the two
  renderers share it.
- **traced mode** = at least one `:message` event. Then:
  - a protocol command (a type outside the self-note set and not `:media`) is an
    `hnote` over the local lane, not an arrow to the peer;
  - a protocol transition draws no inbound arrow, only its state note.
- **untraced:** unchanged, byte for byte. The existing renderer tests must pass
  untouched — that is the compatibility proof.
- An event of a `kind` a renderer does not know is **skipped**, not a
  `FunctionClauseError`. Today `render_event/2` has no catch-all.

### A3. Host callbacks for the journal

Two optional callbacks in `FSL.Host`, added to `@optional_callbacks`:

```elixir
@doc "The journal of this run has just started, in the machine's process."
@callback journal_started(ctx :: FSL.Context.t()) :: :ok

@doc "Events recorded outside the machine's process, handed over and forgotten."
@callback journal_collect() :: [map()]
```

- `FSL.Runner` calls `journal_started/1` right after `FSL.Journal.start/1`,
  default `:ok`.
- `FSL.Journal.flush/0` calls `journal_collect/0` (default `[]`), merges the
  result with its own events with `Enum.sort_by(&Map.get(&1, :at, 0))`, then
  renders. `clear/0` calls it too and drops the result, so a run that ends
  without a flush leaves nothing in the binding's store.
- The host is resolved the way `flush/0` already resolves `diagram_renderer`:
  `FSL.Host.call(Process.get(:scenario_module), …)`.
- New public `FSL.Journal.record/1`: appends a binding-built event, stamping
  `:at` when absent, no-op when disabled. SIP uses it for the inbound request.

### A4. Starting late

In `FSL.Runner.loop/4`, after `run_state/3` returns and before the `case`:

```elixir
result = run_state(module, fun, ctx)
maybe_start_sequence_journal(module, descriptor_ctx(result) || ctx)
```

- `maybe_start_sequence_journal/2` gains `not FSL.Journal.enabled?()` as its
  first condition, so it starts once.
- `descriptor_ctx/1` returns the last element of the descriptor tuple **when it
  is a map**. `dbe4b8b` matched `%SIP.Context{}`, which cannot compile in the
  package. Check every descriptor shape `loop/4` matches: the context must be the
  last element in all of them.

### A5. Tests, docs, release

- Tests in the package:
  - an `at` on every event and a `t0` in the metadata;
  - a debug flag set in the second state starts the journal there, once;
  - both callbacks are called, collected events are merged by `at`, and
    `clear/0` drains;
  - lanes, arrows, dimmed repeats, `hnote` commands in traced mode, for both
    renderers — port the assertions of `dbe4b8b`'s `sequence_diagram_test.exs`
    to the `:message` vocabulary;
  - an unknown kind is skipped;
  - the existing untraced tests pass unchanged.
- `mix compile --warnings-as-errors`, plus whatever the package's CI runs.
- Docs: `FSL.Journal` moduledoc (the external store and the late start),
  `FSL.Diagram` (the fourth kind), `FSL.Host` (the two callbacks),
  `docs/design.md` if it describes the journal.
- If `spec/fsl-js-ts.md` covers the journal or the diagram, reconcile it, or
  record the divergence from the TypeScript side there.
- `CHANGELOG.md` and the version: **0.3.0**. It adds a behaviour surface
  (callbacks, an event kind, a public function), which is more than a 0.2.x fix
  under the package's own semver note. Publishing to hex is the maintainer's
  decision.

## 4. Phase B — elixip (`feat/scenario-debug`)

### B1. The dependency

During development, in `apps/elixip2/mix.exs`, replace
`{:fsl, "~> 0.2.1", hex: :finite_state_language}` with
`{:fsl, path: "../../../finite-state-language/elixir"}` (the spelling of
`e65c3dc`). Once 0.3.0 is published: `{:fsl, "~> 0.3.0", hex:
:finite_state_language}` and `mix deps.update fsl`. **Never let the `path:` line
reach `release/1.6.1`**: the CI and the RPM build have no sibling checkout.

### B2. `SipTrace` emits `:message`

`event/3` keeps reading the message (`describe/1`, and the one `SIPMsg.parse/2`
for a wire form) and builds the new shape:

- `lane: callid`, `party: tag && to_string(tag)`, `peer:`, `repeat: retransmit`,
  `reply: is_integer(code)`;
- `label` built here from `dbe4b8b`'s `message_label/1` and `suffixes/1`:
  `INVITE #1 +SDP`, `200 OK / 1 INVITE`, ` (retransmission)`.

The SIP detail fields (`method`, `code`, `cseq`, `sdp`) may stay in the map for
whoever reads the events; the renderers ignore them. Update `@type event` and the
moduledoc, which still names `SIP.Scenario.SequenceJournal` as the consumer.

### B3. `SIP.FSL.Host`

```elixir
@impl true
def journal_started(sip_ctx) do
  :ok = SIP.Scenario.SipTrace.watch()
  if is_pid(sip_ctx.dialogpid), do: SIP.Scenario.SipTrace.adopt(sip_ctx.dialogpid)

  # :inbound_request is where apply_run_opts/2 stores it
  case FSL.Context.appdata_get(sip_ctx, :inbound_request) do
    nil -> :ok
    req -> with %{} = ev <- SIP.Scenario.SipTrace.event(:in, req), do: FSL.Journal.record(ev)
  end

  :ok
end

@impl true
def journal_collect, do: SIP.Scenario.SipTrace.take()
```

Check the real `appdata` reader of `FSL.Context` before writing it. Go through
`SIP.Scenario.SequenceJournal.record/1` once the facade has it (B4). Add both
callbacks to the moduledoc's list — CLAUDE.md counts "eleven callbacks", which
becomes thirteen.

### B4. The facade

`SIP.Scenario.SequenceJournal` in `SIPScenarioFacades.ex`: add
`defdelegate record(event)`. Nothing else: `adopt_dialog/1` and
`record_inbound_request/1` of `dbe4b8b` are superseded by B3.

### B5. Tests

- Remove the `@describetag :skip` from `sequence_trace_test.exs`.
- Update its assertions to the package's rendering: the local alias is now
  `local`, not `elixip` (1.6.1's `FSL.Diagram.PlantUML`); arrows and notes keep
  their shape.
- Update the unit tests that read the event's fields to the `:message` shape.
- Add one UAS case: an instance spawned with `:dialog_pid` and
  `:inbound_request` draws that request as its first arrow. `dbe4b8b` never
  tested it.
- Run `mix test apps/elixip2/test/sequence_trace_test.exs` and the
  `fsl_*_test.exs` host suites, then `mix test --exclude live --exclude flaky`
  for the whole umbrella.

### B6. Documentation

- `docs/design/DESIGN-FSL.md`: a new §3.9 "`journal_started/1` and
  `journal_collect/0` — the SIP trace". It takes the substance of the §7
  paragraph written in `dbe4b8b` (the ETS table, watch/bind/adopt, why the
  transaction layer and not the transport, the cost when nobody traces),
  adapted to the callbacks. The merge dropped that paragraph because 1.6.1
  restructured the document per host callback.
- `docs/design/debug-improvments.md`: rewrite it whole. Its module table, its
  "§7" link and its construction section name the pre-extraction modules. It
  stays in French.
- `ELIXIPP.md` ("Sequence diagram"): check that the merge kept it true. The
  `elixip` alias in its example becomes `local`.
- `CLAUDE.md`: the callback count (B3).

### B7. Verification end to end

The step was never run against real traffic. After B5, and before merging into
`release/1.6.1`:

1. `cd apps/elixipp && mix escript.build`;
2. `./elixipp --log-sequence UAC.Register` against a real registrar, then a call
   with `UAC.Invite`;
3. open the `.puml` files and check: one lane per Call-ID, every message present
   with its retransmissions, the commands beside their arrows.

## 5. Order and commits

1. FSL: A1 → A5 on the package's branch, then 0.3.0 published.
2. elixip: B1 (path) → B2 → B3/B4 → B5 → B6, as intermediate commits.
3. B1 switched to hex 0.3.0, `mix.lock` updated, B7 done.
4. Merge into `release/1.6.1`.

A1 and A2 can land and be released without A3/A4: they change nothing for a
binding that does not emit `:message`.

## 6. Noticed in the merge, unrelated to this plan

`release/1.6.1` tracks a test artifact,
`apps/elixip2/SIP.Test.SequenceDiagram.SeqScenario_0.332.0.puml`. It is left as
it came.
