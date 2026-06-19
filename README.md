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

- Interface with Medooze: to be done (priority)
- SIP.Scenario Scripting Engine: to be done (priority)
- Test reporting: to be done

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
    receive do
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
    receive do
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
    receive do
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

    receive do
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
  receive do
    event1 -> goto next_state, "event 1"
    event2 -> goto another_state, "event 2"
  end
end
```

By convention, **initial_state** is the first state executed when the FSM starts.
Such a state MUST be declared. Consider it as the main() function in the C language.

The framework defines two terminal states:
- **terminal_success_state** when the scenario is completed as expected.
- **terminal_failure_state** when the scenario encounters any kind of failure.

Those states are predeclared.

Any Elixir code may be executed when entering a state, as long as it does not invoke
blocking functions such as Process.sleep(). Waiting for events must be done through the
receive primitive (see below), never by busy-waiting or sleeping. All processing should
be kept asynchronous and, if possible, use Elixir events to report progress or results.

If the synchronous Elixir code encounters an error (e.g. a file does not exist) that
prevents the scenario from running, the code is expected to call scenario_failure("reason")
to abort the scenario explicitly.

The full SIP stack is exposed on purpose in order to enable scenario writers to interact
at all possible levels. Messages can be created and sent statelessly using SIP.Msg and transport
modules. SIP transactions can be created. However, one needs to understand the possible interaction
of such custom code and the rest of the SIP stack.

For regular cases, it is advised to stick to the macros defined in the SIP.Session.* modules.

### events

Events are native Elixir events collected and received using the Elixir **receive** primitive. Events
can be any type but there are two sources of events to consider in SIP scenarios:

**SIP dialog events** that are sent by the SIP dialog layer:

Received SIP Requests are formatted as an event tuple:

```Elixir
{ <request type atom>, <request map>, <transaction_pid>, <dialog_pid> }
```

For example:

```Elixir
  receive do
    { :BYE, bye_req, _trans_id, _dlg_id } -> goto next
  end
```

Received SIP Responses are formatted as an event tuple:

```Elixir
{ <response code>, <response map>, <transaction_pid>, <dialog_pid> }
```

For example:

```Elixir
  receive do
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
- transition to the target state, calling it with the modified sip_ctx (handled by the runner, not a direct recursive call). goto must be the last expression of a state body or of a receive clause.

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
module, calls its `run/0`, logs the outcome and exits with status `0` on success
or `1` on failure (so it can be used in CI).

Without the custom task, the plain equivalent is:

```bash
mix run -e "MyCallScenario.run()" scenarios/my_call_scenario.exs
```

### Mode 2 — standalone executable (elixipp)

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

