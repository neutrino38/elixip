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

- Fully native Elixir SIP stack: implemented
- Support for SIP over UDP, TCP, TLS and WSS: implemented
- Media Control interface: implemented
- Domain Specific Language definition: in this README
- SIP.Scenario Scripting Engine: done
- Interactive command elixpp for testing tools: done
- Interactive display for elixipp: done
- multple calls + max duration of test and final reporting: to be done

- Interface with Medooze: to be done (priority)


- distributed cluster tech: later
- **borderline**: later
- **kelixip**: later

## The Domain Specific Language for SIP scenarios

This library defines a new [Domain Specific Language](https://elixir.hexdocs.pm/1.20.1/domain-specific-languages.html)
specialized for call and SIP related finite state machines. It is not unlike ExUnit. Call or SIP scenarios would be defined as .exs files.

Here is a "typicall" scenario where:

- an outbound call is placed
- when the call is established, the media server plays a file
- it hangs up when the file is fully played.

```Elixir
defmodule UAC.Invite do

  # use SIP.Scenario pulls in the state-machine DSL together with
  # use SIP.Session.CallUAC and use SIP.Session.Media.
  use SIP.Scenario

  @mediaservermod MediaServer.Mockup
  @domain "mydomain.com"
  @callee "sip:testcall@#{@domain}"

  # SIP identity for the scenario. The framework reads this block to build the
  # initial %SIP.Context{} (computing :ha1 from :passwd) before initial_state.
  config username:     "toto",
         authusername: "toto",
         displayname:  "La tete a toto",
         domain:       @domain,
         proxy:        "sip.mydomain.com",
         passwd:       "xxxx"
# -------------------------------------------------------------------------------
  state initial_state do
    media_connect(@mediaservermod, "sip:localhost:8080")
    goto next
  end
# -------------------------------------------------------------------------------
  state calling do
    send_INVITE(@callee, :mediaserver, timeout: 90, webrtc: :no)
    goto call_progress
  end
# -------------------------------------------------------------------------------
  state call_progress do
    on_events do
      {100, _rsp, _trans_pid, _dialog_pid} -> goto loop, "100 Trying"

      {407, rsp, _trans_pid, _dialog_pid} ->
        send_auth_INVITE(rsp, @callee, :mediaserver, timeout: 90)
        goto loop, "407 Proxy Auth Required"

      {180, _rsp, _trans_pid, _dialog_pid} -> goto loop, "180 Ringing"

      {183, rsp_183, trans_pid, _dialog_pid} ->
        process_invite_reply(rsp_183, trans_pid)
        goto loop, "183 Session Progress"

      {200, rsp_200, trans_pid, _dialog_pid} ->
        process_invite_reply(rsp_200, trans_pid)
        goto call_answered, "200 OK"

      {code, _rsp, _trans_pid, _dialog_pid} when code in 400..699 ->
        scenario_failure("Call failure with code #{code}")
    after
      30_000 -> scenario_failure("Call not answered after 30s")
    end
  end
# -------------------------------------------------------------------------------
  state call_answered do
    on_events do
      {:ms_event, _conn, :ice_connected} -> goto start_play, "media connected"
    after
      5_000 -> scenario_failure("No media received after 5s")
    end
  end
# -------------------------------------------------------------------------------
  state start_play do
    media_play("toto.mp4")
    goto next
  end
# -------------------------------------------------------------------------------
  state call_established do
    on_events do
      {:ms_event, _player, :player_started} -> goto loop, "toto.mp4: start"

      {:ms_event, _player, :player_ended} -> goto hangup_call, "toto.mp4: EOF"

      {:MESSAGE, req, _trans_pid, dialog_pid} ->
        SIP.Dialog.reply(dialog_pid, req, 200, "OK", [])
        goto loop, "MESSAGE"

      {:BYE, req, _trans_pid, dialog_pid} ->
        SIP.Dialog.reply(dialog_pid, req, 200, "OK", [])
        scenario_success("BYE")
    end
  end
# -------------------------------------------------------------------------------
  state hangup_call do
    send_BYE()

    on_events do
      {200, _bye_rsp, _trans_pid, _dialog_pid} -> scenario_success("200 OK")
    after
      4_000 -> scenario_failure("No 200 OK received for BYE")
    end
  end
end
```

### config

The config instruction declares the SIP parameters used by the scenario (username, authusername, displayname,
domain, proxy, passwd, ...). The framework reads this block to build the initial
%SIP.Context{} — computing :ha1 from :passwd — before entering initial_state.

### finite state machine description

The scenario is a description of a finite state machine. States are declared
using the keyword **state** as follows:

```Elixir
state state_name do
  <some elixir code>
  on_events do
    event1 -> goto next_state, "event 1"
    event2 -> goto another_state, "event 2"
  end
end
```

`on_events` behaves like Elixir's `receive`, but additionally infers the
*type* of the matched event from the clause pattern (`{:ms_event, …}` → `:media`,
the other SIP tuples → `:sip`) and attaches it to the following `goto`. This is
purely for display / the future sequence diagram (see the monitor section); the
plain `receive` form also works, it just leaves events untyped. An explicit type
on `goto` (`goto state, "desc", :media`) always wins.

By convention, **initial_state** is the first state executed when the FSM starts.
Such a state MUST be declared. Consider it as the main() function in the C language.

The framework defines two terminal states:
- **terminal_success_state** when the scenario is completed as expected.
- **terminal_failure_state** when the scenario encounters any kind of failure.

Those states are predeclared.

Any Elixir code may be executed when entering a state, as long as it does not invoke
blocking functions such as Process.sleep(). Waiting for events must be done through
`on_events` (or the bare `receive`) as shown below, never by busy-waiting or sleeping.
All processing should be kept asynchronous and, if possible, use Elixir events to
report progress or results.

If the synchronous Elixir code encounters an error (e.g. a file does not exist) that
prevents the scenario from running, the code is expected to call scenario_failure("reason")
to abort the scenario explicitly.

The full SIP stack is exposed on purpose in order to enable scenario writers to interact
at all possible levels. Messages can be created and sent statelessly using SIP.Msg and transport
modules. SIP transactions can be created. However, one needs to understand the possible interaction
of such custom code and the rest of the SIP stack.

For regular cases, it is advised to stick to the macros defined in the SIP.Session.* modules.

### events

Events are native Elixir messages, collected with `on_events` (a thin wrapper around
the Elixir **receive** primitive that also infers the event type). Events can be any
type but there are two sources of events to consider in SIP scenarios:

**SIP dialog events** that are sent by the SIP dialog layer:

Received SIP Requests are formatted as an event tuple:

```Elixir
{ <request type atom>, <request map>, <transaction_pid>, <dialog_pid> }
```

For example:

```Elixir
  on_events do
    { :BYE, bye_req, _trans_id, _dlg_id } -> goto next
  end
```

Received SIP Responses are formatted as an event tuple:

```Elixir
{ <response code>, <response map>, <transaction_pid>, <dialog_pid> }
```

For example:

```Elixir
  on_events do
    { 200, resp_200, trans_id, _dlg_id } -> goto next
  end
```

**Media server events** are described in the **MediaServer** module.
Those events are formatted as follow:

```Elixir
{ :ms_event, <pid of mediaserver>, <event>}
```

### transitions: the goto macro, scenario_success(), scenario_failure()

The `goto` macro triggers a state machine transition. This macro takes two arguments:
- the next state name
- a short description of the event triggering the transition (optional).

Using `goto next` triggers a transition to the **next state** declared in the scenario. `goto loop`
causes the finite state machine to reenter the same state.

The `goto` macro will:
- check that ctx_get(:lasterr) is `:ok`. If not, abort the scenario using `scenario_failure()`,
- store the name of the target state as an atom in `sip_ctx.currentstate`,
- if the logger is set to debug, log the transition as "RCV event: (old state) -> (new state)",
- transition to the target state, calling it with the modified sip_ctx (handled by the runner, not a direct recursive call). goto must be the last expression of a state body or of an `on_events` / `receive` clause.

The `scenario_success("reason")` macro must be used to terminate the scenario as successful and transition to the **terminal_success_state**.
It will log the state before the transition to the final state as an INFO log.

The `scenario_failure("reason")` macro stores the failure reason, logs it as well as the state before the transition to the final state as
an error log. `scenario_failure()` may be called by the scenario runner in case an error condition is met.

Elixir code may be added before calling goto or any other transition macro.

### The scenario context: sip_ctx

All states carry a context that stores SIP configuration information but also all information
that need to be passed around states. The main ones are:

- `sip_ctx.debug` - boolean to activate debug trace for this specific instance of scenario
- `sip_ctx.dialogpid` - PID of the SIP dialog associated with this specific instance of scenario
- `sip_ctx.lasterr` - atom that describes the last error condition detected by the code executed in the state.
- `sip_ctx.errorreason` - a string that describes the detailed reason of errors.

Except for `sip_ctx.debug`, all other sip_ctx struct members should NOT be modified manually by the scenario.
Their semantic and usage may change as this framework evolves.
The sip_ctx also provides a `sip_ctx.appdata` map that can be used as the sole way for scenario
writers to pass data around states using the `appdata_set()` and `appdata_get()` macros. This should be
the preferred way of passing data around.

```Elixir
# Storing some info into the context
appdata_set(:myproperty, "my piece of information")

# retrieving some info from the context

someinfo = appdata_get(:myproperty)

```
## Exception handling

All uncaught exceptions that are raised in the Elixir code are treated and failure
and cause the finite state machine to dump the exception in the logs and call scenario_failure()

## Under the hood of the SIP scenario DSL

Any scenario is a plain Elixir module that calls `use SIP.Scenario` (see the example
above), saved as a `.exs` file. Each **state** of the finite state machine is
an Elixir function.

The context information is stored in a variable always named **sip_ctx** which
is used by all macros from the SIP.Session.* modules and the MediaServer.*
modules. The context is updated and passed as argument to all state functions.

The `use SIP.Scenario` block generates a `run/0` entry point that starts the SIP stack
(transactions, transport selector, dialog layer, config registry), builds the initial
`%SIP.Context{}` from the `config` block and enters `initial_state`. `run/0` returns `:ok` on
`terminal_success_state` and `{:error, reason}` on `terminal_failure_state`.

The `state` macro defines an Elixir function which takes a `%SIP.Context` as sole
argument.

The `goto` macro
- checks if `sip_ctx.lasterr` is set to `:ok`. If not, it calls `scenario_failure(sip_ctx.lasterr)`
- otherwise, stores the new state name into `sip_ctx.currentstate`
- calls the function passed as first argument, passing the sip_ctx context to the new state.

If the new state argument is `next`, it determines the name of the next state to consider and
calls `goto <nextstate>, <event>`. If the new state argument is `loop`, it calls
`goto sip_ctx.currentstate, <event>`.

When transitioning to any of the terminal states, the scenario runner checks if `sip_ctx.mediaserverpid`
and `sip_ctx.mediaservermodule` are set. If yes, the scenario runner waits for the `:dialog_terminated`
event for maximum 5 seconds then calls media_cleanup_ressources() to deallocate media resources.

Then the scenario runner checks for the existence of a `cleanup` function and calls it with `sip_ctx`
as argument.

## Macro helpers

In order to avoid dealing with low level details, submodules of SIP.Session expose helper macros to be used
in scenarios. They should cover most standard cases.

All these macros operate on the implicit `sip_ctx` variable: they update it in place and store the
outcome of the operation in `sip_ctx.lasterr` (`:ok` on success, `{:error, reason}` otherwise).

### SIP.Session.RegisterUAC

This module can be used to implement a client registration scenario. It is pulled in by
`use SIP.Session.RegisterUAC`. It exposes the following helper macros:

- `send_REGISTER(expire)` — send an outbound REGISTER, creating the dialog if needed.
  `expire` is the requested registration lifetime, in seconds.
- `send_auth_REGISTER(resp_401, expire)` — resend the REGISTER authenticated against the
  `401 Unauthorized` challenge carried by `resp_401`. The credentials are taken from the
  scenario `config` (authusername / ha1).
- `send_OPTIONS()` — send an out-of-dialog OPTIONS request, typically used as a keep-alive / ping.

### SIP.Session.CallUAC

This module can be used to implement a client outbound call scenario. It is pulled in
automatically by `use SIP.Scenario`. It exposes the following helper macros:

- `send_INVITE(ruri, sdp_offer, options)` — place an outbound call to `ruri`. `sdp_offer` is
  either a raw SDP body (binary) or the atom `:mediaserver` to let the connected media server
  build the offer automatically. `options` is a keyword list:
    - `timeout:` — INVITE transaction timeout, in seconds (default 20)
    - `webrtc:` — `:no` for plain RTP, or a WebRTC flavor forwarded to the media server
- `send_auth_INVITE(resp, ruri, sdp_offer, options)` — resend the INVITE authenticated against a
  `401`/`407` challenge response `resp`. Same arguments as `send_INVITE`.
- `process_invite_reply(resp, transaction_id)` — process a `200 OK` or a `183 Session Progress`
  reply: feed the SDP answer to the media server and, for a `200 OK`, send the ACK automatically.
- `send_BYE()` — hang up the established call (send an in-dialog BYE).
- `send_ACK(transaction_id)` — send an ACK manually (normally handled by `process_invite_reply`
  for the `200 OK`).

The `send_CANCEL(transaction_id)` macro (from `SIP.Session.Common`) can be used to cancel an
INVITE that has not been answered yet.


# elixipp: the testing tool

Elixip testing tool is ment to be a sipp replacement capable of controlling a mediaserver to
fully simulate SIP calls.


## Writing and running a SIP scenario


There are two ways to run a scenario.

### Prerequisites

- **Erlang/OTP** must be installed on the machine (the BEAM runtime).
- **Elixir** is required for the `mix` mode; it is *not* required at run time for
  the standalone `elixipp` mode (the escript only needs the Erlang runtime).

### Mode 1 — with mix (development)

Use this while writing and debugging scenarios.

```bash
# fetch dependencies and compile once
mix deps.get
mix compile

# run a scenario file
mix scenario scenarios/my_call_scenario.exs
```

`mix scenario` compiles the project, loads the given `.exs`, locates the scenario
module, calls its `run/1`, logs the outcome and exits with status `0` on success
or `1` on failure (so it can be used in CI).

Without the custom task, the plain equivalent is:

```bash
mix run -e "MyCallScenario.run()" scenarios/my_call_scenario.exs
```

### Mode 2 — standalone executable of elixipp

Use this to ship a self-contained tool that runs scenarios without a mix/Elixir
install. The project builds an [escript](https://hexdocs.pm/mix/Mix.Tasks.Escript.Build.html)
named `elixipp` (configured via `escript: [main_module: Elixipp.CLI, name: "elixipp"]`
in `mix.exs`).

```bash
# build the self-contained executable once
mix escript.build          # produces ./elixipp
```

Then run scenarios directly:

```bash
./elixipp scenarios/my_call_scenario.exs   # by file path
./elixipp MyCallScenario                   # by module name (if bundled in the escript)
```

Install it on your `PATH` to call it from anywhere:

```bash
mix escript.install        # or simply: cp elixipp ~/.local/bin/
elixipp my_call_scenario.exs
```

The escript bundles the compiled BEAM modules of Elixip and its dependencies into
a single file, but it still relies on an Erlang/OTP runtime (`erl` / `escript`)
being available on the host. Like `mix scenario`, it exits with `0` on success
and `1` on failure.

### Command-line options

```bash
elixipp [OPTIONS] <scenario.exs | ModuleName>
```

| Option | Meaning | Default |
|---|---|---|
| `-m`, `--monitor` | Display a live table of the calls in progress. | off |
| `-l N`, `--limit N` | Run `N` calls simultaneously. Without `--max-run`, slots are recycled indefinitely. The live table is shown only with `--monitor`; otherwise the run is silent and prints the final summary. | `1` |
| `--max-run N` | Stop after `N` executions in total. | unlimited (`1` when neither `--limit` nor `--max-run` is set) |
| `--rate N` | Number of calls started per second. Each new call creation is spaced by `1000 / N` ms. Values greater than `100` are ignored and fall back to the default. | `10` |
| `--log-file PATH` | Log file path. | `elixipp.log` |
| `--log-level LEVEL` | File log level: `debug` \| `info` \| `warning` \| `error`. | `debug` |
| `-h`, `--help` | Show the help text. | — |

```bash
# 5 simultaneous calls, starting at most 20 new calls per second
elixipp -l 5 --rate 20 scenarios/my_call_scenario.exs
```

In live mode the following keys are available:

| Key | Action |
|---|---|
| `q` | Graceful shutdown: stop starting new calls, wait for the active ones. |
| `Ctrl+D` | Immediate stop: print the summary and halt right away. |
| `↑` / `↓` | Scroll the call table when it exceeds the terminal height. |

### Live monitor (`--monitor`)

The `--monitor` (or `-m`) flag displays a live table of the calls in progress —
one row per running scenario instance — with the scenario name, the last command
it issued, its current FSM state and the event that triggered the last transition:

```bash
elixipp --monitor scenarios/my_call_scenario.exs
```

```
╭────────────────┬────────────────┬──────────────────┬────────────────────────────╮
│Scénario        │Commande        │État              │Événement                   │
├────────────────┼────────────────┼──────────────────┼────────────────────────────┤
│UAC.Invite      │send_INVITE     │call_established  │toto.mp4: start             │
╰────────────────┴────────────────┴──────────────────┴────────────────────────────╯
```

- The **Commande** column display the last high level macro command used by the scenario.
- the **Etat** column report the current state
- the **Evènement


Transition **events** can be categorized the same way, via an optional third
argument to `goto` (`goto target, desc, type`):

```elixir
goto call_answered, "200 OK", :sip
goto start_play, "media connected", :media
```

In practice you rarely write the type by hand: using `on_events` (instead of
`receive`) infers it from the matched event pattern, so SIP events show green and
media events orange automatically. The explicit third argument is only needed to
override the inference or to type a `goto` outside an `on_events`. The event type
is stored next to the event text (also for the sequence diagram).

On a real terminal the cells are color-coded: the **Commande** and **Événement**
cells use light green for `:sip`, orange for `:media` and light blue for anything
else, and the **État** cell turns green on success and red on failure. Colors are
emitted only on a TTY — the non-interactive snapshot stays plain text.

The view is rendered with [Owl](https://hexdocs.pm/owl) (pure Elixir, bundled in
the escript). On a real terminal the table refreshes in place; on a non-interactive
device (a pipe, a CI log) it degrades to a single final snapshot. Today a single
row is shown; the table is built to hold one row per call once scenarios run in
parallel.

## Logging

Logs are written through Elixir's `Logger`. There are two distinct logging
policies depending on how a scenario is run.

### `mix scenario` and `mix test`

These use the project configuration in `config/config.exs`: warnings and above
go to the console, everything from `:debug` up is written to `elixip.log`. Change
the level or the file there. `mix scenario` starts the application before running
the scenario, so this configuration is fully applied.

### Standalone `elixipp`

A self-contained escript does not reliably apply `config/config.exs` (and never
runs `config/runtime.exs`), so `elixipp` sets up **its own logging at startup**,
overriding whatever was baked into the binary. It is driven by command-line
options:

| Option | Meaning | Default |
|---|---|---|
| `--log-file PATH`   | log file path | `elixipp.log` |
| `--log-level LEVEL` | file log level: `debug` \| `info` \| `warning` \| `error` | `debug` |

The console is kept quiet (warnings and above) since `elixipp` prints its own
success/failure line.

```bash
# default: writes elixipp.log at :debug level
elixipp scenarios/my_call_scenario.exs

# override the file and level for a single run (e.g. in CI)
elixipp --log-file ci_run.log --log-level info scenarios/my_call_scenario.exs
```

## Troubleshooting

elixipp produces a log file (`elixipp.log` by default — see [Logging](#logging)
for how to configure it).

If the scenario set the debug flag, in the initial_state:

```Elixir
# Storing some info into the context
ctx_set(:debug, true)
```

A file specific to each scenario execution (instance) will be generated. 
It will be named `<scenario_name>_<pid>.log` It will contain
the SIP configuration applied (except the password that will be masked). Then it will details every transition and action performed by the FSM. The format is a diagram
sequence text file compatible with Plant UML:

```plantuml
@startuml
participant "bob Display Name"

#Initial state
note over elixip: initial_state

# Sending a SIP request
elixip --> bob: INVITE sip_uri
# Receiving a response
elixip <-- bob: 2OO OK

# transition
note over elixip: calling -> answered 

# receiving a message
elixip <-- bob: MESSAGE

# Sending a reply
elixip --> bob: 2OO OK

# Transition
@enduml
```

## Under the hood (elixipp)

Command reporting is fed by the instrumented `SIP.Session.*` macros, which
report their name to the monitor as they run: the SIP send_* macros (`send_INVITE`,
`send_BYE`, `send_REGISTER`, …) report as type `:sip`, and the media macros
(`media_connect`, `media_play`, `media_record`, …) as type `:media`. The command
category (`:sip` / `:media` / `:http` / `:db` / …) is recorded alongside the name
to drive the future sequence-diagram output. Columns have a fixed width (long
values are truncated with an ellipsis).


Exchanges between