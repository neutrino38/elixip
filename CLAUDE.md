# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Elixip is a SIP (Session Initiation Protocol) application server and test tool written in Elixir. The long-term goal is to build a DSL-based scripting tool for testing WebRTC call scenarios, using SIP over WSS/UDP/TCP for signaling and medooze media server for RTP media.

## Commands

```bash
# Install dependencies
mix deps.get

# Compile
mix compile

# Run all tests
mix test

# Run a specific test file
mix test test/sip_parser_test.exs

# Run a specific test by line number
mix test test/sip_parser_test.exs:42

# Run tests with verbose output
mix test --trace

# Format code
mix format
```

## Architecture

The project implements a layered SIP protocol stack. In Elixir the directory
layout under `lib/` is independent of the module names (Mix compiles every
`*.ex` recursively), so the tree below is purely organizational:

```
lib/
├── framework/   # the reusable SIP stack (transport → message → transaction →
│                #   dialog → session/context → media). See the layers below.
├── dsl/         # the scenario DSL and its FSM engine (namespace SIP.Scenario)
│   ├── SIPScenario.ex        # DSL macros: state, goto, config, on_events, …
│   ├── SIPScenarioRunner.ex  # FSM execution engine
│   └── SIPScenarioLoader.ex  # loads scenario .exs files / modules
├── elixipp/     # the standalone test tool (escript `elixipp`)
│   ├── ElixippCLI.ex         # CLI entry point + live --monitor table rendering
│   └── SIPScenarioMonitor.ex # in-memory store feeding the --monitor view
│                             #   (SIP.Scenario.Monitor; a no-op when not started)
└── mix/tasks/scenario.ex     # `mix scenario` task
```

The `dsl` layer builds on `framework` (a scenario `use SIP.Scenario` pulls in
`SIP.Session.CallUAC`, `SIP.Session.Media` and `SIP.Context`). The `elixipp`
tool drives the DSL engine; the DSL itself runs fine without the tool.

### Transport Layer (`SIP.Transport.*`)
- `SIP.Transport.UDP`, `TCP`, `TLS`, `WSS` — protocol-specific transports (outbound + inbound)
- `SIP.Transport.TCPListener`, `TLSListener`, `WSSListener` — server-side listeners; each binds a port,
  accepts connections, and spawns one transport instance per connection
- `SIP.Transport.Depack` — reassembles SIP messages from stream-based transports (TCP/TLS); **not used
  by WSS** — WebSocket frames are already message-delimited
- `SIP.Transport.Selector` — picks the appropriate transport for an outbound message
- WSS activation: inbound WSS connections use `Socket.Web.active/2` which spawns a separate reader
  process delivering `{:web, ws, data}` frames; the WSS GenServer monitors that reader so a silent
  disconnect stops the GenServer and decrements the listener connection count

### Message Layer (`SIPMsg`, `SIP.Msg.Ops`, `SIP.MsgTemplate`)
- `SIPMsg` — parses and serializes SIP messages
- `SIP.Msg.Ops` — header manipulation helpers
- `SIP.MsgTemplate` — constructs common SIP requests/responses
- `SIP.Uri` — SIP URI parsing and manipulation

### Transaction Layer (`SIP.Transac.*`, `SIP.ICT`, `SIP.IST`, `SIP.NICT`, `SIP.NIST`)
- Implements RFC 3261 transaction state machines
- `ICT`/`NICT` — INVITE/non-INVITE client transactions
- `IST`/`NIST` — INVITE/non-INVITE server transactions
- `SIP.Trans.Timer` — manages retransmission timers (A, B, D, E, F, K…)

### Dialog Layer (`SIP.Dialog`, `SIP.DialogImpl`)
- Manages call sessions (RFC 3261 dialogs)
- Processes are registered via Erlang `Registry` keyed on Call-ID / From-tag / To-tag

### Session Layer (`SIP.Session`)
- Behaviour module — applications implement callbacks for registrars and call processors
- `SIP.Session.Registrar` — registrar behaviour: `on_new_registration/3` (dialog
  pid, REGISTER, server-transaction pid) returns `{:accept, app_pid}` / `{:reject, code, reason}`;
  also exposes `check_register/1` (bounds Contact/Expires)
- `SIP.Context` — holds per-session state
- REGISTER reply logic (challenge/accept/reject) is **application-side**: it lives
  in the scenario itself (see `scenarios/uas_register.exs`), not in the framework

### UAS server scenarios (`SIP.Scenario` + `elixipp`)
- A scenario can act as a server: `uas :register` sets `__scenario_type__/0` to
  `:uas_register` (default is `:uac`)
- `elixipp` detects the type, starts `--listen PROTO:PORT` listeners (UDP only so
  far) and registers `Elixip.RegistrarUAS` (instance factory + concurrency quota →
  503) as the processing module
- `SIP.Scenario.Runner.spawn_uas_instance/2` spawns one monitored instance per
  inbound dialog (`run_instance/2` opts `:dialog_pid`, `:inbound_request`, `:parent_pid`)

### Utilities
- `SIP.NetUtils` — IP address resolution and interface enumeration
- `SIP.Auth` — SIP digest authentication
- `SIP.Resolver` — DNS/address resolution for SIP targets

### Media Layer (`MediaServer.*`)

Elixip drives a media server through the `MediaServer.Behaviour` behaviour, so
implementations are interchangeable (selected via config — see Configuration):
- `MediaServer.Mendooze` — the real adapter, driving the **Mendooze MCU** over
  its JSR309 **XML-RPC** control interface (`lib/framework/mendooze/`; design
  in `docs/mendooze_interface.md`). Events arrive over a chunked HTTP long-poll.
- `MediaServer.Mockup` — in-process stub for call-flow tests.

**Conceptual mapping — medooze → Elixir:**
```
medooze (Node.js)                  Elixir handle
─────────────────────────────────  ─────────────────────────
MediaServer process                server :: pid()
Endpoint + Transport (ICE/DTLS)    conn_ref :: reference()
Player  (file → outgoing stream)   player_ref :: reference()
Recorder (incoming stream → file)  recorder_ref :: reference()
Echo    (loopback for testing)     echo_ref :: reference()
```

**Callback groups in `MediaServer.Behaviour`:**

| Group | Callbacks |
|---|---|
| Server lifecycle | `connect/1`, `disconnect/2` |
| Peer connection  | `create_peer_connection/3`, `get_local_offer/1`, `set_remote_answer/2`, `set_remote_offer/2`, `add_remote_candidate/2`, `close_peer_connection/1` |
| Player           | `create_player/3`, `start_player/1`, `pause_player/1`, `stop_player/1` |
| Recorder         | `create_recorder/4`, `start_recorder/1`, `stop_recorder/1` |
| Echo             | `create_echo/1`, `stop_echo/1` |

**Teardown order:**
```
stop_player / stop_recorder / stop_echo
    → close_peer_connection   # closes ICE/DTLS transport
        → disconnect          # closes IPC channel to Node.js
```

**Events** — delivered as `{:ms_event, ref, event}` to the `event_sink` pid:
```elixir
# PeerConnection
{:ms_event, conn_ref, :ice_connected}
{:ms_event, conn_ref, :ice_failed}
{:ms_event, conn_ref, {:ice_candidate, candidate :: String.t()}}
{:ms_event, conn_ref, :closed}
# Player
{:ms_event, player_ref, :player_started}
{:ms_event, player_ref, :player_ended}
{:ms_event, player_ref, {:player_error, reason}}
# Recorder
{:ms_event, recorder_ref, :recorder_started}
{:ms_event, recorder_ref, {:recorder_stopped, :duration | :dtmf | :silence | :caller}}
# Server
{:ms_event, server_pid, :server_disconnected}
```

### Testing Infrastructure
- `SIP.Test.Transport.UDPMockup` — in-process fake UDP transport
- `MediaServer.Mockup` — stub media server for call flow tests
- Sample SIP messages in `test/SIP-*.txt`

## Configuration

Runtime config lives in `config/config.exs`:
- Logger writes warnings to console and info+ to `elixip.log`
- `:useragent` — the User-Agent header value (`"Elixipp-0.2"`)
- `:optionkeepaliveperiod` — OPTIONS keep-alive interval in seconds (15)

### Media server selection

The media adapter used by the config-driven `media_connect/0` DSL macro is
selected by the `:mediaserver` key:

```elixir
config :elixip2, :mediaserver,
  module: :mockup,          # :mockup | :mendooze | a MediaServer.Behaviour module
  url: "sip:localhost:8080" # passed to the adapter's connect/1
```

`:mockup` → `MediaServer.Mockup`, `:mendooze` → `MediaServer.Mendooze`. This
key is overridable **per scenario** (a `config` block key) and **per run** (an
external-JSON header key `"mediaserver": {"module": ..., "url": ...}`); the
runner routes it to the application env. Scenarios can still hardcode an
adapter with the two-arg `media_connect(module, url)`.

`MediaServer.Mendooze` accepts a `"http://host:port"` URL (default port 8080)
as well as `{host, port}`, and has its own tuning block:

```elixir
config :elixip2, MediaServer.Mendooze,
  xmlrpc_timeout_ms: 10_000,   # per-call XML-RPC timeout
  rtp_timeout_ms: 10_000,      # EndpointStartRTPTimeout inactivity watchdog
  poller_retry_ms: 1_000,      # event stream reconnect delay
  poller_max_failures: 5,      # consecutive failures before :server_disconnected
  video_bandwidth_kbps: 800    # b=AS: advertised on video (answers: min with the offer)
```

## Language & Comments Convention

- Interact with the developer in **French**
- Write all code comments, commit messages, and documentation in **English**
