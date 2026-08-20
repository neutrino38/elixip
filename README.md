# Elixip

**Elixip is a personal project to write a multipurpose SIP application layer.**

It provides the **Finite State Language (FSL)**, a
[domain specific language](https://elixir.hexdocs.pm/1.20.1/domain-specific-languages.html)
specialized to describe call scenarios. It is vaguely inspired by the K language developed by the N-SOFT
company as part of their Rekoll product. The scenario itself is an .exs file and takes advantage of the
Elixir syntax to provide a finite state machine (FSM) programming model. This is to me the most explicit
way to handle cleanly the asynchronous logic of programmable telecommunication.

The scenario engine itself is a framework similar to ExUnit. It sits on top of a SIP stack fully developed in Elixir.
Such call / telecom scripts are actually Elixir scripts so they can take full advantage of the SIP stack and interact
at dialog / transaction or event message level if needed. Furthermore, external libs and APIs can be easily called and used
within such scenarios as long as they comply with the asynchronous nature of finite state machines.

The framework will also provide a control interface to the
[Medooze media server](https://github.com/1760002018/medooze-media-server/tree/main/media-server)
in order to handle the media part of telecommunication over IP. A clean abstraction (Behaviour) is defined
and other media servers could easily be interfaced as well if needed.

## Background reading

The reasoning behind the project is developed in three articles:

- [Programmable telecoms, the way it should be](https://www.linkedin.com/pulse/programmable-telecoms-way-should-emmanuel-buu--emxoe/)
  — why this project exists, and the history of the ideas it builds on.
- [What a native language for telco services looks like](https://www.linkedin.com/pulse/what-native-language-telco-services-looks-like-emmanuel-buu--wujre/)
  — why a dedicated language, and what it buys over a general-purpose API.
- [Taming large state machines: Service Building Blocks](https://www.linkedin.com/pulse/taming-large-state-machines-service-building-blocks-elixip-buu--pctie/)
  — the Service Building Blocks (SBB) model, still to come.

## The roadmap

The project will provide in the long term:

- a testing tool called **elixipp**, similar to sipp, capable of running elixip scenarios to test other SIP servers.
- a mini scriptable Session Border Controller, called **borderline**, using FSL to fine-tune message handling.
- a scriptable and extensible SIP application inspired by kamailio. Called **kelixip**.

In terms of capabilities, the emphasis will be on:
- support for Total Conversation calls with any combination of audio/video/realtime text media including using the WebRTC bitstream — [how each medium's codec is chosen](CODEC-NEGOTIATION.md)
- support for SIP over UDP, TCP, TLS and WSS
- support for clustering and load sharing

## What is available, what is not.

### Framework
- Fully native Elixir SIP stack: implemented
- Support for SIP over UDP, TCP, TLS and WSS: implemented
- Media Control interface: implemented
- [Finite State Language definition](FSL.md): first version released
- SIP.Scenario Scripting Engine: done
- [Back to back user agent](B2BUA.md): first release
- [Codec negotiation across two legs](CODEC-NEGOTIATION.md), with a transcoding
  policy per media: implemented

### Testing tool: elixipp
- Interactive command elixpp for testing tools: done
- Interactive display for elixipp: done
- multple calls + max duration of test and final reporting: done
- Interface with [Medooze Media server](https://github.com/neutrino38/mediaserver): done

### Scriptable SIP server kelixip

- Loadable `.beam` [modules](docs/kelixip/modules/README.md): done,
- declarative TOML config with hot-reloadable: done
- a CLI + REST control API, and Prometheus metrics: done.
- domains/dial-plan
- digest auth (stateless nonce, HA1 via a `subscriber_db`  module)
- a multi-domain **registrar** via the registrar mocule and the `registar.exs` script
- NAT/flow for WebRTC —  a media-server pool, 
- a Total Conversation cabable **conferencing (MCU)**: done
- MCU: hardware acceleration watchdog and delegated codec negotiation: do,e
- kelixip B2BUA and call processing: in progress

## Roadmap
- FSL: [Service Building Blocks](https://www.linkedin.com/pulse/taming-large-state-machines-service-building-blocks-elixip-buu--pctie/)
  concept inspired by Jain SLEE 1.1
- kelixip and elixip `presence` support including some level of LoST support
- kelixip distributed cluster tech
- FSL: formal proof of scenario correctness
- Total Conversation call recorder
- Automated call captionning
- Push notification support

- **borderline** SBC: 
  - very good integration with fail2ban
  - liveview based management interface
  - signed and armored configuration files
  - signed beams modules and scenarios
  - anti DDOS + hardened SIP and RTP application firewall.

- kelixip 2.0:
  - domain based partitions of transaction and dialog layers
  - use of RabbitMQ as link the the mediaser
  - Wesh Wesh Mesh network with auto discovery feature
  - full IP V6 support
  - XMPP support as first class citizen
  - Matrix protocol support as first class cizizen

## The Finite State Language

Elixip provides the **Finite State Language (FSL)**, a
[domain specific language](https://elixir.hexdocs.pm/1.20.1/domain-specific-languages.html)
to describe SIP / call scenarios as finite state machines, written as `.exs` files. It covers the `config`
block, the `state` / `on_events` / `goto` / `stay` finite-state-machine model, the scenario context (`sip_ctx`),
sub-scenarios (`spawn_fsm`) and cooperative shutdown, exception handling, how the engine works under the hood,
and the `SIP.Session.*` macro helpers — for both **client (UAC)** scenarios and **server (UAS)** scenarios
(a REGISTER registrar, or a call server that answers incoming `INVITE`s with the `reply_invite*` macros).

**👉 The full FSL reference lives in [FSL.md](FSL.md).**

# elixipp: the testing tool

`elixipp` is the test tool of the project: a sipp replacement that runs FSL
scenarios as a client (UAC) or a server (UAS), and can drive a media server to
fully simulate SIP calls. It covers running scenarios from `mix` or as a
standalone escript, the built-in scenarios, the command-line options, the live
`--monitor` view, external JSON parameterisation and account files, logging and
the sequence diagram.

**👉 The full elixipp guide lives in [ELIXIPP.md](ELIXIPP.md).**

# kelixip: the application server

`kelixip` is the [productized SIP server](docs/kelixip/README.md)  built on the same stack
- 👉 TOML-declared domains, 
- 👉 script-per-function dispatch,
- 👉 [loadable modules](docs/kelixip/modules/README.md) , 
- 👉 a control CLI / [REST API](docs/kelixip/rest-api.md), 
- 👉 and Prometheus metrics.

# Design documentation

How it is built, and why. Eight documents under [`docs/design/`](docs/design/),
each covering what is implemented and running:

| Document | Covers |
|---|---|
| [DESIGN-SIPSTACK.md](docs/design/DESIGN-SIPSTACK.md) | transport, message, transaction and dialog layers |
| [DESIGN-FRAMEWORK.md](docs/design/DESIGN-FRAMEWORK.md) | session layer, mixins, B2BUA, media and the media-server adapters |
| [DESIGN-FSL.md](docs/design/DESIGN-FSL.md) | the language, its macros and the FSM engine |
| [DESIGN-ELIXIPP.md](docs/design/DESIGN-ELIXIPP.md) | the test tool |
| [DESIGN-KELIXIP.md](docs/design/DESIGN-KELIXIP.md) | the application server and its module system |
| [DESIGN-MCU.md](docs/design/DESIGN-MCU.md) | the conferencing module |
| [DESIGN-AUTH.md](docs/design/DESIGN-AUTH.md) | what kelixip challenges: which realm, which identity, 401 vs 407, which requests |
| [DESIGN-SBB.md](docs/design/DESIGN-SBB.md) | service building blocks: the engine, the return contract, `call` and `bridge` |

The other documents in that directory are designs **not yet implemented**;
[`docs/design/notes/`](docs/design/notes/) holds source studies and investigation
records.

# License

Elixip is distributed under the **Business Source License 1.1 (BSL 1.1)**, a
source-available license. See [LICENSE.md](LICENSE.md) for the full terms.

A French translation is available in [LICENSE_fr.md](LICENSE_fr.md) for
convenience; the English [LICENSE.md](LICENSE.md) is the only legally binding
version.
