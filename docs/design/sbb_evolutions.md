# Service building blocks — what is not built

**Status: open.** The layer itself is done and described in
[DESIGN-SBB.md](DESIGN-SBB.md). This is what was named while building it and
deliberately left out.

## 1. A block that publishes a view, not only an outcome

A block reports its current state to the monitor and to the sequence journal,
qualified with the block it belongs to — one line of text answering "where is
this call". What it cannot do is publish a **structured view** while it runs: a
menu saying which prompt is playing and how many attempts are left, a call block
saying which target of a hunt is ringing.

The precedent is Trix's `CallView`, republished on every significant change, and
the missing consumer is what has kept this out: one line of monitor text answers
the operator's question today, and nothing reads more.

## 2. An Elixir counterpart to `fx.task`

The TypeScript dialect has `fx.task`: run an asynchronous piece of work and get
its result back as an event. The Elixir side has no such primitive — a scenario
either blocks (which an FSM must not) or hand-rolls a process and a message.

`Valet` is the mechanism underneath (`http_GET` is one facade over it) and a
block's completion deadline wants exactly that machinery. Recorded as a real gap
in the two dialects' vocabulary rather than as a feature request: naming it is
what makes it a gap.

## 3. The rest of the catalogue

`call()` and `bridge()` ship. These are the sequences that were listed as worth
packaging and are still copied per script:

- the **authentication front** of `direct-call-with-auth.exs`: three states
  (`authenticate_caller` / `wait_credentials` / retry) that any scenario gating a
  request on a digest repeats verbatim. See [DESIGN-AUTH.md](DESIGN-AUTH.md) for
  the rules such a block would enforce;
- **REGISTER challenge / accept / reject**, application-side by design and
  therefore duplicated per registrar script;
- **generic menu / prompt-and-collect** — play the choices, collect the DTMF,
  handle retries and fat-fingered input, answer `{:menu, :choice, %{key: key}}`
  or `{:menu, :disconnected, _}`. Not a B2BUA fragment at all, which is the
  point: it is the specimen that proves the event contract is service-level
  rather than SIP-level.

`queue()` — the ACD verb — is a block too, but what it needs first is the kelixip
objects it takes names for: [kelixip-b2bua.md](kelixip-b2bua.md).

## 4. The TypeScript side

`fx.sbb` and `fx.sbbReturn` are **reserved, not implemented** in the TypeScript
dialect (`fsl-typescript/spec/fsl-js-ts.md`). The names and the return contract
are agreed on both sides; the mechanism is not written. Nothing in the Elixir
implementation depends on it — the two dialects share a vocabulary, not a
runtime.

## 5. Telling a host it has not handled an outcome

`__sbb_returns__/0` says what a block can send, and the `state` macro sees both
the `sbb_fsm` call and the sibling `on_events`, so comparing the two at compile
time is reachable. It is deliberately not started: it is the first step of a much
bigger idea — introspecting a scenario for missing transitions — and that one is
its own project.

If it ever starts, it is a **warning**, never an error: a block never carries a
mandatory reaction, and letting an outcome fall through to `after` can be exactly
what the host means.
