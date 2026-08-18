# The Finite State Language (FSL)

FSL is a [domain specific language](https://elixir.hexdocs.pm/1.20.1/domain-specific-languages.html)
specialized for the finite state machines that handle calls.

> This is the **reference**: what to write in a scenario. How the language is
> built — what the macros expand to, how the engine runs them and why — is
> [docs/design/DESIGN-FSL.md](docs/design/DESIGN-FSL.md). It is not unlike ExUnit:
a call or SIP scenario is an Elixir module saved as a `.exs` file.

Here is a "typicall" scenario where:

- an outbound call is placed
- when the call is established, the media server plays a file
- it hangs up when the file is fully played.

```Elixir
defmodule UAC.Invite do

  # use SIP.Scenario pulls in FSL together with
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

    on_events do
      {100, _rsp, _trans_pid, _dialog_pid} -> stay "100 Trying"

      {407, rsp, _trans_pid, _dialog_pid} ->
        send_auth_INVITE(rsp, @callee, :mediaserver, timeout: 90)
        stay "407 Proxy Auth Required"

      {180, _rsp, _trans_pid, _dialog_pid} -> stay "180 Ringing"

      {183, rsp_183, trans_pid, _dialog_pid} ->
        process_invite_reply(rsp_183, trans_pid)
        stay "183 Session Progress"

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
      {:ms_event, _conn, :ice_connected} -> goto call_established, "media connected"
    after
      5_000 -> scenario_failure("No media received after 5s")
    end
  end
# -------------------------------------------------------------------------------
  state call_established do
    media_play("toto.mp4")

    on_events do
      {:ms_event, _player, :player_started} -> stay "toto.mp4: start"

      {:ms_event, _player, :player_ended} -> goto hangup_call, "toto.mp4: EOF"

      {:MESSAGE, req, _trans_pid, _dialog_pid} ->
        reply_request(req, 200, "OK")
        stay "MESSAGE"

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

Keys it does not recognise are kept in the context appdata, readable with
`appdata_get/1` — which is how a scenario passes its own parameters through.

One such key is read by the **kelixip** server (and ignored by `elixipp`):

```elixir
config uses_modules: [:registrar, :auth_db]
```

It names the loadable modules the script calls, so the server refuses to load the
script when one of them is not installed, instead of letting the first request die
on an undefined function. See
[docs/kelixip/modules/README.md](docs/kelixip/modules/README.md).

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

A clause may also end with `stay` instead of a `goto`: the event is consumed and the
same `on_events` waits again, without re-running the state body. See **transitions**
below. `stay` works in `on_events` only, not in a plain `receive`.

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
Configuration section of `CLAUDE.md` and `docs/design/DESIGN-FRAMEWORK.md#63-the-mendooze-adapter`.

## transitions: the goto macro, stay(), scenario_success(), scenario_failure()

The `goto` macro triggers a state machine transition. This macro takes two arguments:
- the next state name
- a short description of the event triggering the transition (optional).

Three state names are reserved and resolved by the runner instead of naming a declared state:

| Target | Effect |
|--------|--------|
| `goto next` | the **next state** declared in the scenario |
| `goto loop` | re-enter the same state, running its body again |
| `goto back` | return to the state the FSM was in **before** it entered this one |

The `goto` macro will:
- check that ctx_get(:lasterr) is `:ok`. If not, abort the scenario using `scenario_failure()`,
- store the name of the target state as an atom in `sip_ctx.currentstate`,
- if the logger is set to debug, log the transition as "RCV event: (old state) -> (new state)",
- transition to the target state, calling it with the modified sip_ctx (handled by the runner, not a direct recursive call). goto must be the last expression of a state body or of an `on_events` / `receive` clause.

### goto back

`goto back` lets a *detour* state — fetch something over HTTP, show a confirmation, answer a
challenge — return to whoever entered it, so several states can share it without it hardcoding
a return target.

```Elixir
state ask_confirmation do
  http_GET(:confirm, "https://api.example.com/confirm")
  on_events do
    {:confirm, {:ok, _rsp}} -> goto back, "confirmed"
    {:confirm, {:error, _r}} -> scenario_failure("confirmation failed")
  end
end
```

The runner keeps **one slot**, `sip_ctx.laststate`, written on every transition that actually
changes state. `goto loop`, an explicit `goto <current state>` and `stay` leave it alone: re-entering
a state is not "coming from" it.

One slot is not a stack. Two consecutive `goto back` therefore toggle between two states
(A → B, `back` → A, `back` → B). A detour that itself detours does **not** come home; write the
return target explicitly in that case.

`goto back` from `initial_state`, or from any state reached without a previous one, stops the
scenario as a failure with the reason `"goto back with no previous state"`.

### stay

`stay` consumes the matched event and goes back to waiting on the **same** `on_events`. The state
body is *not* re-executed, so its side effects — sending a request, arming a timer, allocating
media — are not replayed. This is what `goto loop` cannot do.

```Elixir
state call_established do
  media_start_echo()

  on_events do
    # answered and forgotten: we are still in the call
    {:MESSAGE, req, trans, _dlg} ->
      reply_request(req, trans, 200, "OK")
      stay "in-dialog MESSAGE"

    {:OPTIONS, req, trans, _dlg} ->
      reply_request(req, trans, 200, "OK")
      stay "keepalive"

    # this one ends the call
    {:BYE, _req, _trans, _dlg} ->
      goto hangup, "BYE"
  end
end
```

`stay` takes the same optional arguments as `goto`: a description and an event type. The transition is
logged as `(state) -> (state)` and reported to `SIP.Scenario.Monitor`, so a scenario whose whole
activity is `stay` never looks frozen in `--monitor` / `kelictl monitor`. Like `goto`, it aborts the
scenario as a failure when `sip_ctx.lasterr` is not `:ok`.

**The `after` deadline is not re-armed.** The timeout of an `on_events` is the deadline of the *wait*,
not of each event: its expression is evaluated once, when the block is entered, and a `stay` comes
back with the time that is left. A stream of consumed events can therefore never keep a state alive
past its timeout.

`stay` is only meaningful inside an `on_events` clause. Writing it anywhere else in a state body — a
plain `receive`, an `after` body, straight-line code — is refused at compile time, or stops the
scenario as a failure if the compiler could not see it.

### Choosing between `goto loop` and `stay`

Both keep the FSM in the same state, and the choice says which of two things you mean:

| | `goto loop` | `stay` |
|---|---|---|
| the state body | runs again | does not run |
| the `after` deadline | re-armed from zero | keeps counting |

So `goto loop` reads *restart this state*, and `stay` reads *I handled that one, carry on waiting*.
Pick by the meaning of the timeout:

- an **idle** timeout — « this call has gone quiet », « this leg stopped sending » — must be re-armed
  by every event, so its clauses use `goto loop`. That is what `in_call` / `in_conference` do in
  `mcu.exs`, `play.exs` and `record.exs`.
- a **budget** — « answered within 30 s », « maximum call duration », « the whole hunt » — must not be,
  so its clauses use `stay`. That is what `calling`, `proceeding` and `connected` do in the reference
  scenarios.

A state that acts on entry — sends a request, arms a timer, allocates media — and then waits, needs
`stay` for anything it consumes without leaving: `goto loop` would replay that entry action. Before
`stay` existed those states had to be split in two, one to act and one to wait; that split is no
longer a reason to write two states.

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

See [`apps/elixip2/scenarios/uas_register.exs`](apps/elixip2/scenarios/uas_register.exs) for the full scenario,
including the reply helpers and the `registered` state.

A registrar instance serves a *succession* of REGISTERs on one dialog — the unauthenticated one, the
digest replay, then every refresh — so a state must act on the last one received, not on the one that
spawned the instance. `on_events` stores it and `last_uas_req()` reads it back, in this state or any
later one; nothing has to be carried in appdata. The `SIP.Session.Registrar` verbs take the context,
so the dialog pid is not threaded through either:

```elixir
state save_registration do
  req = last_uas_req()

  case Kelix.Mod.Registrar.save(sip_ctx, req) do
    {:registered, granted} ->
      SIP.Session.Registrar.accept_registration(sip_ctx, req, granted)
      goto wait_refresh, "200 OK"
    ...
  end
end
```

[`apps/kelixip/scripts/registrar.exs`](apps/kelixip/scripts/registrar.exs) is that scenario written
against the kelixip modules, end to end.

### Server (UAS) scenarios — incoming calls

A scenario can also act as a **call server (UAS)** that answers inbound `INVITE`s.
It declares its kind with `uas :invite`. When an inbound call arrives, one scenario
instance is spawned and bound to the call dialog; the `{:INVITE, …}` event is already
in its mailbox as the FSM starts.

Replying to the call is done with the `reply_invite*` macros (see
[SIP.Session.CallUAS](#sipsessioncalluas) below). The scenario **never** has to send
`487 Request Terminated` on a CANCEL (it is automatic); it is notified of the CANCEL
and of the final call teardown through `{:CANCEL, …}` and `{:dialog_terminated, …}`
events.

The INVITE server transaction sends **no automatic `100 Trying`** — deployed behind a
proxy that answers one of its own, a second 100 is just a duplicate on the wire. A
scenario that answers slowly and wants to stop the caller's retransmissions sends it
itself with `reply_invite(100, "Trying")`; until anything is answered, the transaction
absorbs the retransmitted INVITEs.

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
  spawn_fsm UAS.AutoAnswer, as: :callee, args: %{play: "ring.wav"}
  goto calling
end

state calling do
  send_INVITE("sip:bob@example.com", :mediaserver, timeout: 30)
  goto wait
end

state wait do
  on_events do
    {:child_msg, :callee, :ready}        -> goto talking, "callee ready"
    {:child_exit, :callee, :success, _r} -> scenario_success("done")
    {:child_exit, :callee, :failure, r}  -> scenario_failure("callee failed: #{r}")
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
    {:parent_msg, :start_media} -> goto answer, "parent asked"
  after
    30_000 -> scenario_failure("no order")
  end
end
```

**Macros**

- `spawn_fsm(target, as: name, args: map)` — spawn `target` (a compiled scenario module or a `.exs` file path)
  as a monitored child. Named after `fx.spawn` of the TypeScript FSL, which spawns a child machine on the same
  contract, so the two dialects keep one name per concept. It was called `sub_fsm` up to 1.4.1; that spelling
  still works and is deprecated. `as:` is required: it is the local name used to address the child and to tag the
  messages it sends back. `args:` (optional) is merged into the child context appdata (read it with
  `appdata_get/1`). The child handle is kept in the parent context, so it survives across states.
- `notify(child_name, payload)` — send an application message to a named child. The child receives it as
  `{:parent_msg, payload}`.
- `notify_parent(payload)` — send an application message to the parent. The parent receives it as
  `{:child_msg, <our name>, payload}` (the name the parent assigned with `as:`). It is a **no-op when the
  scenario has no parent**, so the very same scenario can also be run standalone (`mix scenario`, single
  `elixipp` run).

**Messages** (matched in `on_events`)

```Elixir
{:parent_msg, payload}                       # application message, parent -> child
{:child_msg, child_name, payload}            # application message, child -> parent
{:child_exit, child_name, outcome, reason}   # a child terminated (outcome :: :success | :failure | :aborted)
{:scenario_ctl, :shutdown, reason}           # cooperative shutdown request (see below)
```

> **Renamed in 1.5.0.** These were `{:scenario_msg, from_name, payload}` — both directions, told apart by
> `from_name` — and `{:scenario_exit, …}`. The new names say the direction, and match `parent:msg` /
> `child:msg` / `child:exit` of the TypeScript FSL (see
> [docs/design/service-building-block.md](docs/design/service-building-block.md), §4.6). A message cannot
> carry a deprecated alias the way a macro can, so a scenario matching an old shape would simply never be
> woken: `on_events` reports it as a **compile-time warning** naming the replacement.

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

## Service building blocks (SBB)

Where `spawn_fsm` starts a **second machine with legs of its own**, `sbb_fsm` calls a **subroutine on the
legs you already hold**. The rule of thumb:

> `spawn_fsm` when the other machine has state of its own; `sbb_fsm` when the sequence belongs to the state
> you already hold.

A service building block packages a sequence written once — establish a call, run a menu, collect
credentials — behind a callable face. Calling one makes the current process enter the block's FSM: the block
owns the event loop, on the caller's own context, dialogs and mailbox, until it hands control back.

```Elixir
defmodule MyApp.Cancelling do
  use SIP.SBB

  @sbb_namespace :cancel          # the first element of everything it returns
  @sbb_returns [
    confirmed: "the callee answered the CANCEL with a 487 — %{}",
    answered:  "the callee picked up before the CANCEL arrived — %{code}"
  ]

  @sbb_timeout 32_000             # completion bound (timer B)

  state initial_state do
    on_events do
      {:outbound, {487, _resp, _t, _d}} -> sbb_return({:cancel, :confirmed, %{}})
      {:outbound, {200, _resp, _t, _d}} -> sbb_return({:cancel, :answered, %{code: 200}})
    end
  end
end
```

and, in a scenario:

```Elixir
state cancelling do
  sbb_fsm MyApp.Cancelling

  on_events do
    {:cancel, :confirmed, _}  -> scenario_aborted("caller cancelled, callee confirmed")
    {:cancel, :answered, _}   -> goto releasing, "callee answered after the cancellation"
    {:cancel, :timeout, _}    -> scenario_aborted("callee never concluded")
  end
end
```

**What a block returns** is always `{namespace, outcome, data}` — the namespace it declares, an outcome
atom, and a map. The shape is fixed so a block can learn to report one more thing without breaking the
scenarios that match it: a new key in `data` is invisible to whoever does not read it, where a fourth tuple
element would be a compile error everywhere. `@sbb_returns` is the vocabulary, and `sbb_return` refuses an
outcome that is not in it — at compile time, because the alternative is a host waiting on its `after` for an
event nobody will send. A bounded block gets `:timeout` in its vocabulary for free, and returns
`{namespace, :timeout, %{block: module}}` on expiry.

**Macros**

- `sbb_fsm(module, opts)` — enter `module`'s FSM. Options: `timeout:` (ms, overrides the block's
  `@sbb_timeout`), `args:` (map seeding the block's sandbox), `resume:` (`true` keeps the sandbox from a
  previous run instead of clearing it — for a block designed to be re-entered after an interruption).
  **Only valid in a state body**, never inside an `on_events` clause: that clause's deadline is absolute, so
  a block called from one would burn the host's remaining timeout while it runs. Give the block its own
  state — the compiler says so if you forget.
- `sbb_return({namespace, outcome, data})` — end the block, posting the event to the process and handing
  control back to the state that called it. This, not `scenario_success`, is how a block returns.
- `sbb_data_get(key)` / `sbb_data_set(key, value)` — the block's private sandbox. `appdata` itself is shared
  with the host, which is the point; the sandbox is what cannot collide with a host key of the same name.

**The rules that matter**

- **The block sees everything the host sees.** Same process, same mailbox, same `sip_ctx` — that is what
  separates an SBB from a sub-FSM. Its `currentstate` and `laststate` are restored on return, so `goto back`
  inside a block cannot land in a host state.
- **Terminals propagate.** `scenario_failure` and `scenario_aborted` written inside a block keep their
  ordinary meaning and tear down the whole stack, host included — the `exit()` of C. Use them for what must
  stop everything, and `sbb_return` for everything else.
- **The returned event is not privileged.** Anything the block left unconsumed is still in the mailbox and is
  matched first: arrival order, as always.
- **Every branch returns.** A block branch ends on `sbb_return` or on a terminal. One that falls through
  leaves the host waiting for an event nobody will send.
- **Blocks compose** — a block may call a block, and a terminal thrown three deep still reaches the root.
  They cannot run *concurrently*, though: one point of control, a stack of calls.
- A block has **no `run/1`**: it is not a scenario, and `SIP.Scenario.Loader` will never mistake one for the
  scenario of the `.exs` that declares it.
- **The block shows in the live view**, on the call's own row, with its states qualified —
  `MyApp.Cancelling/initial_state` rather than a call that looks frozen for thirty seconds in the last state
  its scenario declares. The scenario column keeps naming the scenario; nesting shows the innermost block.
  The row returns to the host's state when the block hands control back.

**The blocks that ship** live in `:elixip2` next to the mechanism, so a scenario and a kelixip script reach
them the same way:

| Block | `use` | Verb | Absorbs |
|---|---|---|---|
| `SBB.Call` | `use SBB.Call` | `call(args: %{peer: peer})` | forwarding the INVITE, the provisionals, the serial hunt over the peer's targets, the caller giving up, the cancel race, the ACK |

`call/1` answers `{:call, :connected, _}`, `:rejected`, `:cancelled`, `:answered_after_cancel`,
`:caller_hung_up`, `:caller_gone`, `:timeout` or `:failed` — see `SBB.Call.Establish` for what each carries.
It completes the SIP transactions it owns (a caller whose INVITE is never answered is left hanging, so the
408 is sent from inside the block) and leaves the *verdict* to the scenario: whether a refused call is a
success, whether a cancellation is an abort, and what to bill.

Specification and catalogue: [docs/design/service-building-block.md](docs/design/service-building-block.md).
Design: [docs/design/service-building-block-design.md](docs/design/service-building-block-design.md).

## The scenario context: sip_ctx

All states carry a context that stores SIP configuration information but also all information
that need to be passed around states. The main ones are:

- `sip_ctx.debug` - boolean to activate debug trace for this specific instance of scenario
- `sip_ctx.dialogpid` - PID of the SIP dialog associated with this specific instance of scenario
- `sip_ctx.lasterr` - atom that describes the last error condition detected by the code executed in the state.
- `sip_ctx.errorreason` - a string that describes the detailed reason of errors.
- `sip_ctx.currentstate` - name of the state being executed. Owned by the runner.
- `sip_ctx.laststate` - name of the state entered before this one, what `goto back` returns to. Owned by the runner.

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

## Under the hood of FSL

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
`goto sip_ctx.currentstate, <event>`. If it is `back`, it calls `goto sip_ctx.laststate, <event>`,
and fails the scenario when that slot is empty. The runner writes `sip_ctx.laststate` on every
transition where the target differs from the current state.

`on_events` compiles to a `receive` wrapped in a closure that calls itself, which is how `stay`
re-enters the wait without leaving the state function. Its `after` timeout is turned into an
absolute deadline when the block is entered, and each re-entry re-arms it with the remainder.

When transitioning to any of the terminal states, the scenario runner checks if `sip_ctx.mediaserverpid`
and `sip_ctx.mediaservermodule` are set. If yes, the scenario runner waits for the `:dialog_terminated`
event for maximum 5 seconds then calls media_cleanup_ressources() to deallocate media resources.

Then the scenario runner checks for the existence of a `cleanup` function and calls it with `sip_ctx`
as argument.

If the scenario spawned sub-FSMs with `spawn_fsm`, the runner first asks each live child to shut down
cooperatively (`{:scenario_ctl, :shutdown, …}`), waits up to 5 seconds for them to terminate and hard-kills
any straggler, then — if this scenario itself has a parent — reports its own outcome to it as
`{:child_exit, name, outcome, reason}`.

## Macro helpers

In order to avoid dealing with low level details, submodules of SIP.Session expose helper macros to be used
in scenarios. They should cover most standard cases.

All these macros operate on the implicit `sip_ctx` variable: they update it in place and store the
outcome of the operation in `sip_ctx.lasterr` (`:ok` on success, `{:error, reason}` otherwise).

### Where instrumentation lives — never in the SIP stack

Every helper reports the command it issues to `SIP.Scenario.Monitor` (`note_command/2`), which is what
feeds the `--monitor` live view and `kelictl monitor`. That reporting belongs to the **session layer**:
`SIP.Dialog` and below are a plain SIP stack and must stay unaware that scenarios are being watched, so
they record nothing. A helper notes, then calls down.

This matters when a scenario replies to an inbound request. `reply_invite*`, `reply_request` and the
`SIP.Session.Registrar` helpers already do the noting; a scenario that composes its **own** responses
must not reach for `SIP.Dialog.reply/5` directly — it would send correctly but appear frozen in the
monitor, with no `command` and a `state` that never seems to act on anything. Use instead:

```elixir
SIP.Session.reply(dialog_pid, req, code, reason, upd_fields, label \\ nil)
```

It notes `label` (default `"reply_<code>"`) then replies. It is a plain function, not a macro, because a
server scenario builds its responses in helpers that carry the dialog pid explicitly — outside a `state`
body, where the implicit `sip_ctx` of a macro is out of reach. `label` is worth passing when the response
has a meaning the bare status code does not convey (`"401 stale"`, `"423 too brief"`, `"503 store down"`).

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

The inbound request this instance is serving (`INVITE` / re-`INVITE` / `UPDATE`, and `REGISTER` for a
registrar scenario) and its server transaction are stored in the context **automatically** — the
`on_events` macro instruments every clause to stash the most recent one — so the reply macros need not
be passed the request. `last_uas_req()` reads it back in any later state, which is what lets a state
act on the request that got it there without the previous state having stashed it by hand.

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

A scenario **never** replies the `487` after a CANCEL itself — it is automatic. A `100 Trying`
is *not* automatic: send it with `reply_invite(100, "Trying")` if the scenario needs one (see the
*incoming calls* section above).

### Connecting calls (B2BUA)

`SIP.Session.B2bua` lets one scenario drive **two** dialogs: the incoming call it was started
for, and a second one it places itself. It is pulled in by `use SIP.Scenario`, so every call
scenario already has the `b2bua_*` macros.

The inbound leg stays the scenario's own dialog — `reply_invite*`, `last_uas_req()` and the rest
keep their meaning — and the outbound leg's events arrive **tagged**, `{:outbound, {200, resp,
trans, dlg}}`, so an `on_events` clause tells the two apart by shape. The relay macros are
direction-free: they act on the *other* leg, whichever the matched event came from.

```elixir
b2bua_forward(req, peer, media)   # create the outbound leg
b2bua_forward(req)                # relay a request onto the other leg
b2bua_forward_reply(resp)         # relay a response back
b2bua_reply(req, code, reason)    # answer here, relay nothing
b2bua_challenge(req, params)      # answer 407 (or 401) with a digest challenge
```

`media` is `false` (the SDP crosses verbatim) or `{:mediaserver, opts}` (both legs terminate
their media on the server, and neither side ever sees the other's SDP). Legs are wound down
automatically when the scenario ends, whatever the exit path.

`b2bua_challenge/2..3` answers the caller with a digest challenge the *application* built
(`Kelix.Auth.challenge_params/2` in kelixip): `407` + `Proxy-Authenticate` by default — what
deployed UAs expect of the server routing their calls — or `401` + `WWW-Authenticate`.

**See [B2BUA.md](B2BUA.md)** for the complete macro reference, the `%SIP.B2bua.Peer{}` target
form, the media modes, and four commented scenarios: a proxy-like direct call to a subscriber
registered on several devices, the same call with the caller authenticated, a customer service
hunting a list of numbers serially, and a WebRTC-to-SIP gateway.

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
never in the scenario. See `apps/elixip2/scenarios/http_get_example.exs` for a full example
and the `HTTP.Session` module doc for the internals.
