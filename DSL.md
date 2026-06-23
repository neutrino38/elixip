# The Domain Specific Language for SIP scenarios

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

## config

The config instruction declares the SIP parameters used by the scenario (username, authusername, displayname,
domain, proxy, passwd, ...). The framework reads this block to build the initial
%SIP.Context{} — computing :ha1 from :passwd — before entering initial_state.

## finite state machine description

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

## events

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

## transitions: the goto macro, scenario_success(), scenario_failure()

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

The `scenario_aborted("reason")` macro terminates the scenario with a third, distinct outcome: `:aborted`.
It is meant for a controller-driven wind-down (a cooperative shutdown, see **Sub-scenarios** below) rather than
a genuine failure, so monitoring/tooling can tell the two apart. `run/1` returns `{:aborted, reason}` in that case
(as opposed to `:ok` for success and `{:error, reason}` for failure).

Elixir code may be added before calling goto or any other transition macro.

## Sub-scenarios (sub-FSM)

A scenario can launch **another scenario as a sub finite-state machine** and talk to it by message passing.
Because each scenario instance owns its own SIP/media mailbox (the dialog layer binds events to the running
process), a sub-scenario always runs in its **own process** — the two FSMs communicate only through explicit
messages.

```Elixir
# Parent scenario
state initial_state do
  # Load + start a child scenario, give it the local name :callee.
  # `target` is a scenario module or a path to a .exs scenario file.
  sub_fsm UAS.AutoAnswer, as: :callee, args: %{play: "ring.wav"}
  goto calling
end

state calling do
  send_INVITE("sip:bob@example.com", :mediaserver, timeout: 30)
  goto wait
end

state wait do
  on_events do
    {:scenario_msg, :callee, :ready}        -> goto talking, "callee ready"
    {:scenario_exit, :callee, :success, _r} -> scenario_success("done")
    {:scenario_exit, :callee, :failure, r}  -> scenario_failure("callee failed: #{r}")
  after
    30_000 -> scenario_failure("timeout")
  end
end

state talking do
  notify :callee, :start_media     # send an application message to the child
  goto wait
end
```

```Elixir
# Child scenario — an ordinary scenario, also runnable on its own
state initial_state do
  notify_parent :ready             # send a message back to the parent
  goto waiting
end

state waiting do
  on_events do
    {:scenario_msg, :parent, :start_media} -> goto answer, "parent asked"
  after
    30_000 -> scenario_failure("no order")
  end
end
```

**Macros**

- `sub_fsm(target, as: name, args: map)` — spawn `target` (a compiled scenario module or a `.exs` file path)
  as a monitored child. `as:` is required: it is the local name used to address the child and to tag the
  messages it sends back. `args:` (optional) is merged into the child context appdata (read it with
  `appdata_get/1`). The child handle is kept in the parent context, so it survives across states.
- `notify(child_name, payload)` — send an application message to a named child. The child receives it as
  `{:scenario_msg, :parent, payload}`.
- `notify_parent(payload)` — send an application message to the parent. The parent receives it as
  `{:scenario_msg, <our name>, payload}` (the name the parent assigned with `as:`). It is a **no-op when the
  scenario has no parent**, so the very same scenario can also be run standalone (`mix scenario`, single
  `elixipp` run).

**Messages** (matched in `on_events`)

```Elixir
{:scenario_msg, from_name, payload}            # application message between FSMs
{:scenario_exit, child_name, outcome, reason}  # a child terminated (outcome :: :success | :failure | :aborted)
{:scenario_ctl, :shutdown, reason}             # cooperative shutdown request (see below)
```

Sub-FSMs nest freely: a child may itself spawn children. When a scenario terminates, it asks each of its
live children to shut down (cooperatively, then hard-kills any straggler after 5 s) before reporting its own
exit to its parent.

### Cooperative shutdown

Any running scenario can be asked to wind down cleanly through the control message
`{:scenario_ctl, :shutdown, reason}`. This is used both by a parent tearing down its children and by `elixipp`
on a graceful stop (the `q` key), which broadcasts it to every active call.

Every `on_events` is made shutdown-aware automatically: it implicitly also matches the control message (unless
the scenario writes its own `{:scenario_ctl, …}` clause). On receipt, the scenario runs the optional
`on_shutdown` block, or — if none is declared — terminates with the `:aborted` outcome by default.

```Elixir
on_shutdown do
  # release application resources, send a BYE, ...
  scenario_aborted("controller asked to stop")
end
```

> Note: a shutdown request is only acted upon the next time the scenario reaches an `on_events`. A scenario
> stuck in a long synchronous state will not react until then; the controller hard-kills it past the grace
> period.

## The scenario context: sip_ctx

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
`terminal_success_state`, `{:error, reason}` on `terminal_failure_state`, and `{:aborted, reason}` when the
scenario was wound down by a cooperative shutdown.

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

If the scenario spawned sub-FSMs with `sub_fsm`, the runner first asks each live child to shut down
cooperatively (`{:scenario_ctl, :shutdown, …}`), waits up to 5 seconds for them to terminate and hard-kills
any straggler, then — if this scenario itself has a parent — reports its own outcome to it as
`{:scenario_exit, name, outcome, reason}`.

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
