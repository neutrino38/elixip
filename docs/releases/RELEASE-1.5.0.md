# Release 1.5.0

2026-08-19 — 34 commits since 1.4.1 (2026-08-18). Theme: **service building
blocks**. A scenario can enter a reusable sub-machine that runs on its own legs
and returns one event: two ship with the framework — establishing a call,
relaying an established one — and a third is published by the `auth_db` module,
which is the pattern every module will follow. The reference call scripts lost
between 45 % and 47 % of their lines.

Reference: [FSL.md](../../FSL.md#service-building-blocks-sbb) to write one,
[DESIGN-SBB.md](../design/DESIGN-SBB.md) for how the layer is built, and
[sbb_evolutions.md](../design/sbb_evolutions.md) for what is not.

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

`call()` and `bridge()` live in `:elixip2` under `SBB.Call`; a scenario writes
`use SBB.Call`.

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

## Blocks published by a module

A kelixip module now publishes two kinds of thing: functions a script calls for a
**decision**, and blocks it enters for a **sequence**. `Kelix.Mod.<Name>.SBB` is
where the second kind lives, and the pattern is
[DESIGN-SBB.md](../design/DESIGN-SBB.md#74-a-kelixip-module-publishes-its-blocks)
— `registrar` and `mcu` have the same shape waiting for them.

- `use Kelix.Mod.AuthDb` takes the module's alias and its blocks;
  `AuthDb.SBB.authenticate()` runs the whole challenge cycle on the request the
  scenario is serving: challenge, wait for the credentials, verify them,
  challenge again.
- It answers `:authenticated` (with the user and realm the digest proved),
  `:cancelled`, `:caller_gone`, `:timeout` or `:refused`.
- A rejected attempt is answered and the block keeps waiting — a 403 is one
  request's verdict, not the end of the conversation. `max_attempts` (3 by
  default, `:infinity` to restore the previous behaviour) bounds how many a
  single unauthenticated dialog can extract; only 403s count, never the 500 of a
  backend that cannot answer.
- The identity a digest proves is recorded in the session context, so the leg
  placed next asserts it — see *Security* below.
- `challenge_invite/2` takes a second form: the digest **params** the application
  composed, sent verbatim, beside the realm form that lets the dialog layer mint
  the nonce. `stale` and the algorithm the stored secret was hashed with are the
  backend's to decide and do not survive being re-derived.
- Replying on a dialog that has already died no longer fails the scenario:
  `do_reply_invite/4` catches the exit and sets `lasterr` to `:dialogterminated`,
  as the sending side already did. A caller that gives up between its INVITE and
  our 407 is ordinary traffic.

Design: [DESIGN-AUTH.md](../design/DESIGN-AUTH.md#3-the-authentication-block).

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
  and `bridge()`: 230 → 127, 310 → 164 and 494 → 276 lines.
- The two authenticated scripts gate their INVITE with
  `AuthDb.SBB.authenticate()`: the `authenticate_caller` and `wait_credentials`
  states become one state and its outcomes. Neither script names `Kelix.Auth`,
  composes a 407 or reads an `Authorization` header any more.
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
- [DESIGN-AUTH.md](../design/DESIGN-AUTH.md) gains the authentication block and
  the `P-Asserted-Identity` rule; `evolution-auth-db.md` goes back to being about
  the replaceable backend alone.
- The `auth_db` module doc documents the block beside the facades.
- The TypeScript dialect implements the same names in
  `finite-state-language` 0.1.3 (`fsl-typescript/spec/fsl-js-ts.md` §8.4), where
  they had been reserved before either side had code.

## Dependencies

- unchanged from [1.4.1](RELEASE-1.4.1.md).

## Security

- **`P-Asserted-Identity` is no longer relayed from an untrusted peer.** A
  forwarded request kept every header the B2BUA denylist did not name, this one
  included, so a caller could put `P-Asserted-Identity: <sip:boss@example.com>`
  in an INVITE and kelixip relayed it as if it had asserted it — a claim
  laundered into an assertion by the one node whose signature the header carries
  (RFC 3325 §5), on scripts with no authentication in them at all.
- An inbound one is now **always dropped** at the forward, and the only one that
  can leave is the identity an authentication verdict proved:
  `assert_identity/1` records it in `sip_ctx.asserted_identity` and
  `prepare_forwarded_request/2` re-adds it. Drop and re-add live in the same
  function, so no call site can forward a foreign assertion by forgetting an
  option.
- A request carrying `Privacy: id` is forwarded with no assertion at all
  (RFC 3325 §7): a B2BUA relaying to an arbitrary registered contact leaves the
  trust domain.
- A deployment behind a *trusted* proxy cannot yet let an inbound assertion
  through; that needs a trust-domain setting, and the safe default is the one
  that does not launder.

Design: [DESIGN-AUTH.md](../design/DESIGN-AUTH.md#4-p-asserted-identity).

## Packaging

- the server identifies itself as `Kelixip/1.5.0`, the tool as `Elixipp-1.5.0`.
