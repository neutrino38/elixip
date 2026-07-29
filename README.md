# Elixip

**Elixip is a personal project to write a multipurpose SIP application layer.**

It provides a [Domain Specific Language](https://elixir.hexdocs.pm/1.20.1/domain-specific-languages.html)
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

## The roadmap

The project will provide in the long term:

- a testing tool called **elixipp**, similar to sipp, capable of running elixip scenarios to test other SIP servers.
- a mini scriptable Session Border Controller, called **borderline**, using the DSL to fine-tune message handling.
- a scriptable and extensible SIP proxy inspired by kamailio. Let's call it **kelixip** for now. If someone has a better or funnier name, let me know.

In terms of capabilities, the emphasis will be on:
- support for Total Conversation calls with any combination of audio/video/realtime text media
- support for SIP over UDP, TCP, TLS and WSS
- support of WebRTC bitstream and regular RTP bitstream using the Medooze Media Server
- support for clustering and load sharing

## What is available, what is not.

### Framework
- Fully native Elixir SIP stack: implemented
- Support for SIP over UDP, TCP, TLS and WSS: implemented
- Media Control interface: implemented
- Domain Specific Language definition: see [DSL.md](DSL.md)
- SIP.Scenario Scripting Engine: done

### Testing tool: elixipp
- Interactive command elixpp for testing tools: done
- Interactive display for elixipp: done
- multple calls + max duration of test and final reporting: done
- Interface with [Medooze Media server](https://github.com/neutrino38/mediaserver): done

### Scriptable SIP server kelixip

**kelixip**: *basic* scope delivers:
- plus loadable `.beam` modules,
- declarative TOML config with hot-reloadable
- a CLI + REST control API, and Prometheus metrics.
- domains/dial-plan
- digest auth (stateless nonce, HA1 via a `subscriber_db`  module)
- a multi-domain **registrar** via the registrar mocule and the `registar.exs` script
- NAT/flow for WebRTC —  a media-server pool, 


## Roadmap
- kelixip MCU based on Mendooze with harware acceleration
- kelixip B2BUA and call processing
- kelixip and elixip `presence` support including some level of LoST support
- kelixip distributed cluster tech: later
- **borderline** SBC: later


## The Domain Specific Language for SIP scenarios

Elixip provides a [Domain Specific Language](https://elixir.hexdocs.pm/1.20.1/domain-specific-languages.html)
to describe SIP / call scenarios as finite state machines, written as `.exs` files. It covers the `config`
block, the `state` / `on_events` / `goto` finite-state-machine model, the scenario context (`sip_ctx`),
sub-scenarios (`sub_fsm`) and cooperative shutdown, exception handling, how the engine works under the hood,
and the `SIP.Session.*` macro helpers — for both **client (UAC)** scenarios and **server (UAS)** scenarios
(a REGISTER registrar, or a call server that answers incoming `INVITE`s with the `reply_invite*` macros).

**👉 The full DSL reference now lives in [DSL.md](DSL.md).**

# elixipp: the testing tool

`elixipp` is the test tool of the project: a sipp replacement that runs DSL
scenarios as a client (UAC) or a server (UAS), and can drive a media server to
fully simulate SIP calls. It covers running scenarios from `mix` or as a
standalone escript, the built-in scenarios, the command-line options, the live
`--monitor` view, external JSON parameterisation and account files, logging and
the sequence diagram.

**👉 The full elixipp guide lives in [ELIXIPP.md](ELIXIPP.md).**

# kelixip: the application server

`kelixip` is the productized SIP server built on the same stack: TOML-declared
domains, script-per-function dispatch, loadable modules (registrar, database
auth), a control CLI/REST API and Prometheus metrics.

**👉 The operator manual lives in [docs/kelixip/README.md](docs/kelixip/README.md).**

# License

Elixip is distributed under the **Business Source License 1.1 (BSL 1.1)**, a
source-available license. See [LICENSE.md](LICENSE.md) for the full terms.

A French translation is available in [LICENSE_fr.md](LICENSE_fr.md) for
convenience; the English [LICENSE.md](LICENSE.md) is the only legally binding
version.
