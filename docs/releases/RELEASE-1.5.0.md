# Release 1.5.0

2026-08-19 — 23 commits since 1.4.1 (2026-08-18). Theme: **service building
blocks**. A scenario can enter a reusable sub-machine that runs on its own legs
and returns one event, and the first two — establishing a call, relaying an
established one — ship with the framework. The reference call scripts lost
between 36 % and 46 % of their lines.

Reference: [FSL.md](../../FSL.md#service-building-blocks-sbb) to write one,
[service-building-block.md](../design/service-building-block.md) for what the
layer must do, [service-building-block-design.md](../design/service-building-block-design.md)
for how it is built, [DESIGN-FSL.md](../design/DESIGN-FSL.md#4bis-service-building-blocks)
for the engine.

## The language

- `sbb_fsm(module, opts)` enters a service building block: the current process
  runs that FSM, on this scenario's context, dialogs and mailbox.
- `sbb_return({namespace, outcome, data})` ends a block, posting the event the
  calling state matches in its own `on_events`.
- `sbb_data_get/1` and `sbb_data_set/2` give a block a private sandbox inside the
  shared `appdata`, cleared per call unless `resume: true`.
- `use SIP.SBB` declares a block; it defines no `run/1`, so the loader can never
  mistake one for the scenario of its file.
- A block declares `@sbb_namespace` and `@sbb_returns`, and `sbb_return` refuses
  an outcome that is not declared, at compile time.
- A block is bounded by `@sbb_timeout` (32 s by default, `:infinity` allowed) and
  returns `{namespace, :timeout, %{block: module}}` when it expires.
- `scenario_failure` and `scenario_aborted` written inside a block end the whole
  stack, host included; a cooperative shutdown reaching a block still runs the
  host's `on_shutdown`.
- `sbb_fsm` is refused inside an `on_events` clause at compile time.
- A block's states show on the call's own row in `elixipp --monitor` and in the
  PlantUML journal, qualified with the block they belong to.

## The blocks that ship

Both live in `:elixip2` under `SBB.Call`; a scenario writes `use SBB.Call`.

- `call(args: %{peer: peer})` establishes the outbound leg: the INVITE, the
  provisionals, the serial hunt over the peer's targets, the caller giving up,
  the cancel race of RFC 3261 §16.7, the caller's ACK.
- It answers `:connected`, `:rejected`, `:cancelled`, `:answered_after_cancel`,
  `:caller_hung_up`, `:caller_gone`, `:media_lost`, `:timeout` or `:failed`, and
  the scenario names what each one means.
- `bridge()` relays the established call: in-dialog traffic both ways, the
  re-INVITE/UPDATE rule, the ACK a 200 owes back, the BYE and the far end's
  answer.
- It answers `:caller_hung_up`, `:callee_hung_up`, `:callee_left`,
  `:max_duration`, `:media_lost` or `:interrupted`.
- `bridge()` has no deadline and can be interrupted with `{:bridge_break,
  message}` and re-entered with `bridge(resume: true)`.
- `bridge(args: %{on_callee_hangup: :keep_caller})` hands the call back with the
  caller's leg still up when the callee goes away.
- `bridge(args: %{media: …})` answers a re-offer that only moves a peer locally
  instead of relaying it.

## Breaking changes

- `sub_fsm` is renamed `spawn_fsm`; the old spelling stays as a deprecated alias.
- The inter-FSM messages are renamed after their direction: `{:parent_msg, …}`,
  `{:child_msg, …}` and `{:child_exit, …}` replace `{:scenario_msg, …}` and
  `{:scenario_exit, …}`. A scenario still matching the old shapes is warned about
  at compile time — a message carries no alias, so the mismatch cannot be
  absorbed. See [FSL.md](../../FSL.md#sub-scenarios-sub-fsm).
- The User-Agent is `Kelixip/1.5.0` on the server and `Elixipp-1.5.0` on the tool.

## Reference scripts

- `direct-call.exs`, `direct-call-with-auth.exs` and
  `direct-call-with-auth-and-media.exs` place and relay their call with `call()`
  and `bridge()`: 230 → 124, 310 → 199 and 494 → 310 lines.
- An outcome that belongs to the call rather than to the server — the caller
  cancelling, the callee never answering, the maximum duration — is a scenario
  success.
- `b2bua.exs` is deleted: it was a copy of `direct-call.exs`.
- The scenarios of `apps/elixip2/scenarios/` deliberately keep their states, as
  the block-free path the suite regresses against.

## Documentation

- `FSL.md` gains a service-building-block section and hands "Under the hood" over
  to [DESIGN-FSL.md](../design/DESIGN-FSL.md).
- [kelixip-b2bua.md](../design/kelixip-b2bua.md) keeps `queue()` as future work;
  its FSL prerequisite and its `call()` are delivered.
- The TypeScript dialect reserves the same names
  (`fsl-typescript/spec/fsl-js-ts.md` §8.4).

## Dependencies

- unchanged from [1.4.1](RELEASE-1.4.1.md).

## Security

No change.

## Packaging

- the server identifies itself as `Kelixip/1.5.0`, the tool as `Elixipp-1.5.0`.
