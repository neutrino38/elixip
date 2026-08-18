# Release 1.4.1

2026-08-18 — 11 commits since 1.4.0 (2026-08-14). Theme: **the scenario language
gets a name and two verbs**. `DSL.md` becomes [`FSL.md`](../../FSL.md) and the
language is the **Finite State Language (FSL)** everywhere; it gains `stay` and
`goto back`. The test transport is rebuilt around pluggable peers.

## Finite State Language changes

- new `stay` / `stay("desc")` / `stay("desc", :type)`: consume the matched event
  and wait again on the same `on_events`, without re-running the state body.
- the `after` of an `on_events` is the deadline of the whole wait: `stay` re-enters
  it with the time that is left, and never re-arms it.
- `stay` written outside an `on_events` clause is refused at compile time; one
  reaching the runner stops the scenario as a failure.
- new `goto back`: transition to the state entered before the current one.
- new `sip_ctx.laststate`, runner-owned, holds what `goto back` returns to. `goto
  loop`, an explicit self-goto and `stay` leave it untouched.
- `goto back` with no previous state stops the scenario as a failure.
- `stay` is logged and reported to `SIP.Scenario.Monitor` and to the sequence
  journal like a `goto`.
- `stay` and `back` are reserved words inside a state body.

## Reference scenarios

- `connected`, `proceeding` and `cancelling` of the eight B2BUA scenarios `stay`
  on relayed traffic, so their `after` is a call/ring budget instead of an idle
  timeout.
- `uac_invite` (×3), `uac_register` (×3), `http_get_example` and `play.exs` merge
  each send state into its wait state: nine states removed.
- `uac_register`: an unrelated final response landing in `keepalive` no longer
  sends a second OPTIONS.
- `registrar.exs`: `wait_auth_register` removed, the challenge branch returns with
  `goto back`.
- states whose `after` is an idle timeout — `mcu.exs`, `mcu_adhoc.exs`,
  `record.exs`, `uas_invite.exs`, `uas_register.exs` and `play.exs` `in_call` —
  keep `goto loop`.

## Framework corrections

No change.

## elixipp testing tool changes

No change.

## kelixip

No change.

## Documentation

- `DSL.md` renamed [`FSL.md`](../../FSL.md); every reference, code comment and
  wiki page follows.
- `FSL.md` documents `stay`, `goto back`, `sip_ctx.laststate` and when to prefer
  `goto loop` over `stay`.
- new `docs/design/moteli-reboot.md` and `apps/elixip2/priv/proto/moteli_*.proto`:
  RabbitMQ + protobuf replacing both XML-RPC control planes (design and schemas
  only).
- new `docs/design/liveview-adapter.md`: Phoenix LiveView adapter design study.
- `docs/design/improve-fsl-elixir.md`: the `stay` / `goto back` design, implemented
  in this release.

## Test suite

- `SIP.Test.Transport.UDPMockup` is replaced by `SIP.Test.Transport.Mockup` plus
  one `SIP.Test.Peer` module per simulated remote party (`Passive`, `AnsweringUAS`,
  `BusyUAS`, `NoAnswerUAS`, `ChallengingUAS`, `RegisterOK`, `Manual`).
- one probe event shape: `{:sip_mockup, {:request_sent | :response_sent, …}}`.
- `;unittest=<name>` in an R-URI selects a mockup instance of its own, so a B2BUA
  suite drives one peer per leg.
- the mockup transport module is read from `:elixip2, :unittest_transport`, so the
  library references no test module.
- `apps/elixip2/test/support` compiles in `:test` only.
- new `scenario_stay_back_test.exs`: `stay`, `goto back`, and the constant stack
  and heap of a long stay loop.
- new registrar-script test: a refresh challenged with a stale nonce.

## Known issues

- unchanged from [1.4.0](RELEASE-1.4.0.md).

## Dependencies

- unchanged from [1.4.0](RELEASE-1.4.0.md).

## Security

No change.

## Packaging

- the server identifies itself as `Kelixip/1.4.1`.
