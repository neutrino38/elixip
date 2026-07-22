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
    media_connect()   # adapter chosen by config (see "media macros" below)
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

      {:MESSAGE, req, _trans_pid, _dialog_pid} ->
        reply_request(req, 200, "OK")
        goto loop, "MESSAGE"

      {:BYE, req, _trans_pid, _dialog_pid} ->
        reply_request(req, 200, "OK")
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

**HTTP reply events** are delivered by the `http_GET` macro (see the
**HTTP.Session** helper below), one per request, tagged so several concurrent
requests can be told apart:

```Elixir
{ <tag>, {:ok, %Req.Response{}} }
{ <tag>, {:error, reason} }   # reason :: :timeout | Req exception | {:crash, r}
```

`<tag>` is whatever term you passed to `http_GET`; pick one distinctive enough
not to collide with other events matched in the same `on_events`.

## media macros

`use SIP.Scenario` pulls in `SIP.Session.Media`, which exposes the media macros:

| Macro | Effect |
|-------|--------|
| `media_connect()` | Connect the media server chosen by config (recommended) |
| `media_connect(module, url)` | Connect an explicit adapter (e.g. `MediaServer.Mockup`) |
| `media_play(file, opts \\ [])` | Play a media file to the peer |
| `media_record(file, duration_ms, opts \\ [])` | Record the peer's media to a file |
| `media_start_echo()` | Loop the peer's media back to it |
| `media_stop()` | Stop the running player / recorder / echo |
| `media_cleanup_ressources()` | Release media resources at end of call |

The zero-arg `media_connect/0` reads `config :elixip2, :mediaserver`
(`module: :mockup | :mendooze | Module, url: ...`). The adapter can therefore
be switched between the in-process **Mockup** and the real **Mendooze** MCU
without editing the scenario — set it in `config/config.exs`, in the scenario's
own `config` block, or in an external-JSON header (`"mediaserver"` key). See the
Configuration section of `CLAUDE.md` and `docs/mendooze_interface.md`.

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

### Server (UAS) scenarios — registrar

So far the scenarios above act as clients (UAC): they originate requests. A
scenario can instead act as a **server (UAS)** that *answers* inbound requests.
The first supported kind is a **REGISTER server (registrar)**.

A server scenario declares its kind with `uas :register`. The FSM enters the
initial_state once the server receives the REGISTER request. This request is
forwarded and need to be processed as a regular SIP request.


```elixir
defmodule UAS.RegisterExample do
  use SIP.Scenario

  uas :register
  config domain: "example.com"

  # The REGISTER that started this instance is already in the mailbox; jump
  # straight to the state that waits for it.
  state initial_state do
    goto next
  end

  state wait_register do
    on_events do
      {:REGISTER, req, _trans_pid, dialog_pid} ->
        # Replying to a REGISTER (challenge / accept / reject) is the application's
        # job, so these helpers are plain functions defined in the scenario itself.
        case check_registration_auth(req, dialog_pid, password: appdata_get(:password)) do
          :no_auth_header -> challenge_registration(req, dialog_pid); goto loop, "401"
          :ok             -> accept_registration(req, dialog_pid, expires: 300); goto registered, "200 OK"
          _               -> reject_registration(req, dialog_pid, 403, "Forbidden"); scenario_failure("auth")
        end
    after
      32_000 -> scenario_failure("no REGISTER received")
    end
  end

  # state registered: answer OPTIONS keepalives, REGISTER refreshes and un-REGISTER.
end
```

See [`scenarios/uas_register.exs`](scenarios/uas_register.exs) for the full scenario,
including the reply helpers and the `registered` state.

### Server (UAS) scenarios — incoming calls

A scenario can also act as a **call server (UAS)** that answers inbound `INVITE`s.
It declares its kind with `uas :invite`. When an inbound call arrives, one scenario
instance is spawned and bound to the call dialog; the `{:INVITE, …}` event is already
in its mailbox as the FSM starts.

Replying to the call is done with the `reply_invite*` macros (see
[SIP.Session.CallUAS](#sipsessioncalluas) below). The scenario **never** has to send
`100 Trying` (the INVITE server transaction emits it automatically) nor `487 Request
Terminated` on a CANCEL (also automatic); it is notified of the CANCEL and of the
final call teardown through `{:CANCEL, …}` and `{:dialog_terminated, …}` events.

```elixir
defmodule UAS.InviteExample do
  use SIP.Scenario
  use SIP.Session.CallUAS      # adds redirect_invite / challenge_invite

  uas :invite
  # Domains served (virtual-server style): the INVITE R-URI must match, otherwise
  # the call is rejected with 604. `:any` is the catch-all.
  config domains: :any

  # The {:INVITE, …} is already in the mailbox when the instance starts.
  state initial_state do
    media_connect()
    goto wait_invite
  end

  state wait_invite do
    on_events do
      {:INVITE, _req, _t, _dlg} ->
        # auto_store already stashed the request; reply macros read it back.
        reply_invite(180, "Ringing")
        goto answering, "INVITE"
    after
      32_000 -> scenario_failure("no INVITE received")
    end
  end

  state answering do
    reply_invite_with_sdp(200)          # negotiate the SDP answer + send 200 OK
    goto wait_ack
  end

  state wait_ack do
    on_events do
      {:ACK, _req, _t, _dlg}    -> goto in_call, "ACK"
      {:CANCEL, _req, _t, _dlg} -> scenario_success("caller cancelled")
    after
      10_000 -> scenario_failure("no ACK")
    end
  end

  state in_call do
    media_start_echo()
    on_events do
      {:BYE, req, _t, _dlg}       -> reply_request(req, 200); scenario_success("BYE")
      {:INVITE, _req, _t, _dlg}   -> reply_invite_with_sdp(200); goto loop, "re-INVITE"
      {:dialog_terminated, _d, _} -> scenario_success("call ended")
    after
      600_000 -> scenario_success("idle timeout")
    end
  end
end
```

The inbound offer request (initial `INVITE`, re-`INVITE` or `UPDATE`) is stored
automatically in the context by the `on_events` instrumentation, so the `reply_invite*`
macros serve it without the scenario re-passing it. Media resources are released on the
`{:dialog_terminated, …}` contract exactly as for a UAC call.


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
    - `media:` — which m-lines to offer (only used when `sdp_offer` is `:mediaserver`).
      Default `:tc` (Total Conversation = audio + video + real-time text). Accepts either a
      **kind atom** — `:audio`, `:video`, `:text`, `:audio_video`, or `:tc` /
      `:total_conversation` / `:audio_video_text` — **or an explicit list** of medias for full
      control over the set and order of m-lines, e.g. `media: [:audio, :video, :text]` or
      `media: [:audio, :text]` (audio + text, no video). List elements may themselves be kind
      atoms (expanded in place) and duplicates are dropped while order is preserved.
- `send_auth_INVITE(resp, ruri, sdp_offer, options)` — resend the INVITE authenticated against a
  `401`/`407` challenge response `resp`. Same arguments as `send_INVITE`.
- `process_invite_reply(resp, transaction_id)` — process a `200 OK` or a `183 Session Progress`
  reply: feed the SDP answer to the media server and, for a `200 OK`, send the ACK automatically.
- `send_BYE()` — hang up the established call (send an in-dialog BYE).
- `send_ACK(transaction_id)` — send an ACK manually (normally handled by `process_invite_reply`
  for the `200 OK`).

The `send_CANCEL(transaction_id)` macro (from `SIP.Session.Common`) can be used to cancel an
INVITE that has not been answered yet.

The three `reply_invite*` macros documented under **SIP.Session.CallUAS** below are actually
provided through `SIP.Session.CallUAC` (hence available in every call scenario, UAC included):
a UAC in an established dialog can receive a re-`INVITE` / `UPDATE` and must be able to answer it.

### SIP.Session.CallInDialog

Common mixin of **in-dialog request senders** and the generic in-dialog reply. It is pulled in
automatically by both `SIP.Session.CallUAC` and `SIP.Session.CallUAS`, so every call scenario has
these macros. Each sender builds the request from the scenario context and routes it through the
dialog (Call-ID, CSeq, From/To tags, remote target and route set are filled in automatically).

- `send_MESSAGE(body, opts \\ [])` — in-dialog MESSAGE. `opts[:contenttype]` (default `text/plain`).
- `send_INFO(body, opts \\ [])` — in-dialog INFO (default `application/dtmf-relay`, e.g. DTMF).
- `send_BYE(body \\ nil)` — hang up the call; the body is optional.
- `send_REFER(refer_to, opts \\ [])` — call transfer. `refer_to` is the target; `opts[:referred_by]`
  sets the `Referred-By` header.
- `send_UPDATE(sdp_or_ms, opts \\ [])` — in-dialog UPDATE carrying an offer: `:mediaserver` (offer
  built by the media server) or an explicit SDP binary, same convention as `send_INVITE`. `opts`
  accepts `:webrtc` and `:media` (same values as `send_INVITE`; default `:audio_video` here).
- `send_reINVITE(sdp_or_ms, opts \\ [])` — re-INVITE to renegotiate media (same convention and opts).
- `send_NOTIFY(event, body, opts \\ [])` — in-dialog NOTIFY (e.g. the implicit REFER subscription:
  `Event: refer`, sipfrag body).
- `send_inDialog_OPTIONS()` — in-dialog OPTIONS keep-alive.
- `reply_request(req, code, reason \\ nil, upd_fields \\ [])` — reply to an in-dialog request the
  scenario received (BYE, MESSAGE, INFO, OPTIONS, NOTIFY, REFER…). The request is passed explicitly
  (only the offer INVITE/UPDATE is auto-stored). It does **not** check the dialog state, so a test
  scenario may deliberately reply out of order.

Other messages usable in-dialog: `CANCEL` (via `SIP.Session.Common.send_CANCEL`); `PRACK` (100rel)
and in-dialog `SUBSCRIBE` are out of scope for now.

### SIP.Session.CallUAS

This module implements the **server side of an INVITE dialog** (incoming-call handling). The generic
reply macros are available in every call scenario (via `SIP.Session.CallUAC`); the redirect/challenge
macros are opt-in with `use SIP.Session.CallUAS`. All replies go through the dialog **without checking
its state** (so out-of-order test scenarios are possible).

The inbound offer request (`INVITE` / re-`INVITE` / `UPDATE`) and its server transaction are stored
in the context **automatically** — the `on_events` macro instruments every clause to stash the most
recent one — so the reply macros need not be passed the request.

- `reply_invite(code, reason \\ nil, upd_fields \\ [])` — reply to the stored request with a code that
  carries **no SDP** (100 is automatic, so typically 18x / 3xx-6xx). Raises for `183` or a `2xx`
  (those need an SDP — use the macros below), except a `2xx` answering an `UPDATE` that had no offer.
- `reply_invite_with_sdp(code, opts \\ [])` — reply `183` or `200` with an SDP answer **negotiated with
  the connected media server** (the scenario must have called `media_connect()`). A local `Contact` is
  added automatically. On a media failure the reply is `500 Media Server Error` (override with
  `opts[:on_media_error] = {code, reason}`). Other `opts`: `:reason`, `:contact`, `:webrtc`, and
  `:media` (same values as `send_INVITE`, including an explicit list; default `:audio_video`).
- `reply_invite_with_body(code, bodies, opts \\ [])` — reply with an **arbitrary body**. `bodies` is a
  raw binary (Content-Type `application/sdp`), a single `%{contenttype: ct, data: bin}` map, or a list
  of such maps. A multi-element list is serialized as a `multipart/mixed` body (boundary generated
  automatically). `opts`: `:reason`, `:contact` and any extra reply field.
- `redirect_invite(contacts, code \\ 302, reason \\ nil)` — 3xx redirect. `contacts` is a String, a
  `%SIP.Uri{}`, or a list of either (opt-in: `use SIP.Session.CallUAS`).
- `challenge_invite(realm, code \\ 407)` — reply `401`/`407` with a digest challenge, reusing the
  dialog nonce machinery (opt-in: `use SIP.Session.CallUAS`).

A scenario **never** replies `100 Trying` or the `487` after a CANCEL itself — both are automatic
(see the *incoming calls* section above).

### HTTP.Session

This module lets a scenario issue outbound **HTTP** requests (e.g. to a
provisioning / policy backend) without ever blocking the finite-state machine.
It is **opt-in**: add `use HTTP.Session` to the scenario. It exposes a single
macro:

- `http_GET(url, timeout, tag)` — fire an asynchronous HTTP GET.
    - `url` — the target URL (binary).
    - `timeout` — the **total** budget of the operation, in **milliseconds**.
    - `tag` — an atom (or any term) discriminating several concurrent requests.

Like the `SIP.Session.*` macros, `http_GET` operates on the implicit `sip_ctx`:
it sets `sip_ctx.lasterr` to `:ok` and returns the updated context, so a `goto`
may follow it directly. But unlike them it **does not** carry the result — the
request runs in the background and its outcome is delivered **later**, as a
single tagged message to the scenario mailbox, collected in `on_events`:

```Elixir
{tag, {:ok, %Req.Response{}}}
{tag, {:error, reason}}   # reason :: :timeout | Req exception | {:crash, r}
```

```Elixir
use HTTP.Session

state query_backend do
  http_GET("https://backend/api/x", 10_000, :provisioning)
  on_events do
    {:provisioning, {:ok, %Req.Response{status: 200, body: b}}} ->
      appdata_set(:data, b); goto next, "backend OK"
    {:provisioning, {:ok, %Req.Response{status: c}}} ->
      scenario_failure("backend HTTP #{c}")
    {:provisioning, {:error, :timeout}} ->
      scenario_failure("backend timeout")
    {:provisioning, {:error, r}} ->
      scenario_failure("backend error: #{inspect(r)}")
  end
end
```

**Guarantees.** `http_GET` always produces **exactly one** `{tag, …}`
message, even on timeout — so the `on_events` needs **no** `after` clause for
that case; the timeout arrives as an `{:error, :timeout}` event. Internally a
disposable *coordinator* process owns a monitored *worker* running `Req.get/2`
and arbitrates the timeout with a single `receive`/`after`. On timeout the
coordinator **kills** the worker, which cancels the in-flight request (its
pooled connection is reclaimed) so **no late reply can ever pollute a later
`on_events`**. The blocking wait lives entirely in the throwaway coordinator,
never in the scenario. See `scenarios/http_get_example.exs` for a full example
and the `HTTP.Session` module doc for the internals.
