# Design documentation

## What is built

Six documents, one per layer or artifact. Each describes what is **implemented,
tested and running**, and why it is built that way.

| Document | Covers |
|---|---|
| [DESIGN-SIPSTACK.md](DESIGN-SIPSTACK.md) | transport, message, transaction and dialog layers |
| [DESIGN-FRAMEWORK.md](DESIGN-FRAMEWORK.md) | session layer, mixins, B2BUA, media and the media-server adapters |
| [DESIGN-FSL.md](DESIGN-FSL.md) | the Finite State Language, its macros and the FSM engine |
| [DESIGN-ELIXIPP.md](DESIGN-ELIXIPP.md) | the elixipp test tool |
| [DESIGN-KELIXIP.md](DESIGN-KELIXIP.md) | the kelixip server and its module system |
| [DESIGN-MCU.md](DESIGN-MCU.md) | the conferencing module |

Each ends with an **Invariants** section: the short list of rules that must not
be broken, each one traceable to an incident that cost something.

The user-facing counterparts live at the repository root —
[FSL.md](../../FSL.md), [ELIXIPP.md](../../ELIXIPP.md),
[B2BUA.md](../../B2BUA.md), [CODEC-NEGOTIATION.md](../../CODEC-NEGOTIATION.md),
[TLS_WSS.md](../../TLS_WSS.md), [BUILD.md](../../BUILD.md) — and under
[docs/kelixip/](../kelixip/README.md) for the server.

## What is designed but not built

| Document | Subject |
|---|---|
| [kelixip_roadmap.md](kelixip_roadmap.md) | presence, `Path` generation, usrloc persistence, HA, `radius_billing` |
| [mcu_server_evolutions.md](mcu_server_evolutions.md) | media-server increments the conferencing module waits on |
| [evolution-auth-db.md](evolution-auth-db.md) | authenticating more than REGISTER, and a replaceable backend |
| [kelixip-b2bua.md](kelixip-b2bua.md) | `call()` / `queue()` above the B2BUA primitives |
| [service-building-block.md](service-building-block.md) | reusable FSM fragments |
| [integration-fail2ban.md](integration-fail2ban.md) | making kelixip trivially protectable |
| [kelixip_liveview.md](kelixip_liveview.md), [liveview-adapter.md](liveview-adapter.md) | a real-time web console over kelixip |
| [moteli-reboot.md](moteli-reboot.md) | RabbitMQ + protobuf control plane for the media servers (2.0) |

## Notes

[notes/](notes/) holds what is neither design nor plan: source studies of other
systems, and investigation records kept because the same trap will catch the
next person.
