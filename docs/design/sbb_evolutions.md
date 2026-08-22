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
- the **conference leg** of `mcu.exs` and `mcu_adhoc.exs`: `in_call`,
  `in_conference` and `hanging_up`, already copied and already drifted apart.
  Owned by the MCU module, specified in
  [mcu_module_evolutions.md](mcu_module_evolutions.md);
- **generic menu / prompt-and-collect** — play the choices, collect the DTMF,
  handle retries and fat-fingered input, answer `{:menu, :choice, %{key: key}}`
  or `{:menu, :disconnected, _}`. Not a B2BUA fragment at all, which is the
  point: it is the specimen that proves the event contract is service-level
  rather than SIP-level.

`queue()` — the ACD verb — is a block too, but what it needs first is the kelixip
objects it takes names for: [kelixip-b2bua.md](kelixip-b2bua.md).

## 4. The TypeScript side — done

`fx.sbb` and `fx.sbbReturn` shipped in `finite-state-language` 0.1.3
(`fsl-typescript/spec/fsl-js-ts.md` §8.4), so this is no longer open. Five
points the reserved contract had left unsaid were settled there, and §8.4 now
carries them: the context is shared while the scratch space is not, the host's
deadline is armed afresh rather than resumed, `fx.sbb` is the last thing a
state body does, `state` stays the host's while a block runs, and the two
compile-time checks TypeScript gets for free — the host must provide what a
block requires, and must have a clause for what it can return.

The last one is worth carrying back: it is §5 of this document, obtained at no
cost on the other dialect because assignability answers it. Elixir cannot get
it the same way, but the failure it prevents is the same one.

## 5. Telling a host it has not handled an outcome

`__sbb_returns__/0` says what a block can send, and the `state` macro sees both
the `sbb_fsm` call and the sibling `on_events`, so comparing the two at compile
time is reachable. It is deliberately not started: it is the first step of a much
bigger idea — introspecting a scenario for missing transitions — and that one is
its own project.

If it ever starts, it is a **warning**, never an error: a block never carries a
mandatory reaction, and letting an outcome fall through to `after` can be exactly
what the host means.
