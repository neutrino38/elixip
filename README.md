# Elixip

**Elixip is a personal project to write a multipurpose SIP application server.**

The idea is to write a generic SIP server. Actual SIP application will be separated
processes (possibily on other nodes) and will be able to register dispatching rules
a bit like in SIP servlet.

The idea would also be to see how we can take advantages of elixir / erlang features
to implement distributed SIP processing and redundancy on several servers.

This is not intended to be a finished product . It is rather a self training project.

## Design and future roadmap

### Goal

I changed my mind and I now want to build and advanced SIP and RTP test tool using the Elixir scripting capablity.

What I want is to use the Domain Specific Language capability of elixir to create
an easy and powerful scripting tools to test WebRTC call scenario. The signaling
would be SIP over WSS or SIP over UDP or TCP and the media would be using
mendooze media server 

https://github.com/1760002018/medooze-media-server/tree/main/media-server

## Domain Specific langage for SIP scenario

This library defines a new [Domain Specific Language](https://elixir.hexdocs.pm/1.20.1/domain-specific-languages.html) specialized for call and SIP related finite state machine. It is not unlike ExUnit. Call or SIP scenario would be defined as .exs files
that would resemble this

```Elixir
defmodule MyCallScenario do

  # use SIP.Scenario pulls in the state-machine DSL together with
  # use SIP.Session.CallUAC and use SIP.Session.Media.
  use SIP.Scenario

  @mediaservermod MediaServer.Mockup
  @domain "mydomain.com"
  @callee "sip:90901@#{@domain}"

  # SIP identity for the scenario. The framework reads this block to build the
  # initial %SIP.Context{} (computing :ha1 from :passwd) before initial_state.
  config username:     "toto",
         authusername: "toto",
         displayname:  "La tete a toto",
         domain:       @domain,
         proxy:        "sip.mydomain.com",
         passwd:       "xxxx"

  state initial_state do
    media_connect(@mediaservermod, "sip:localhost:8080")
    goto next
  end

  state calling do
    send_INVITE(@callee, :mediaserver, timeout: 90, webrtc: :no)
    goto call_progress
  end

  state call_progress do
    receive do
      {100, _rsp, _trans_pid, _dialog_pid} -> goto loop

      {407, rsp, _trans_pid, _dialog_pid} ->
        send_auth_INVITE(rsp, @callee, :mediaserver, timeout: 90)
        goto loop

      {180, _rsp, _trans_pid, _dialog_pid} -> goto loop

      {183, rsp_183, trans_pid, _dialog_pid} ->
        process_invite_reply(rsp_183, trans_pid)
        goto loop

      {200, rsp_200, trans_pid, _dialog_pid} ->
        process_invite_reply(rsp_200, trans_pid)
        goto call_answered

      {code, _rsp, _trans_pid, _dialog_pid} when code in 400..699 ->
        scenario_failure("Call failure with code #{code}")
    after
      30_000 -> scenario_failure("Call not answered after 30s")
    end
  end

  state call_answered do
    receive do
      {:ms_event, _conn, :ice_connected} -> goto start_play
    after
      5_000 -> scenario_failure("No media received after 5s")
    end
  end

  state start_play do
    media_play("toto.mp4")
    goto next
  end

  state call_established do
    receive do
      {:ms_event, _player, :player_started} -> goto loop

      {:ms_event, _player, :player_ended} -> goto hangup_call

      {:MESSAGE, req, _trans_pid, dialog_pid} ->
        SIP.Dialog.reply(dialog_pid, req, 200, "OK", [])
        goto loop

      {:BYE, req, _trans_pid, dialog_pid} ->
        SIP.Dialog.reply(dialog_pid, req, 200, "OK", [])
        scenario_success()
    end
  end

  state hangup_call do
    send_BYE()

    receive do
      {200, _bye_rsp, _trans_pid, _dialog_pid} -> scenario_success()
    after
      4_000 -> scenario_failure("Not 200 OK received for BYE")
    end
  end
end
```

This framework would define the following functions or macro:

### config

Declares the SIP identity used by the scenario (username, authusername, displayname,
domain, proxy, passwd, ...). The framework reads this block to build the initial
%SIP.Context{} — computing :ha1 from :passwd — before entering initial_state.

### state

The state instruction defines a function which takes a %SIP.Context as sole argument.

### goto

This macro takes one argument, a state name. The scenario runner will 
- check the state ctx_get(:lasterr) to be :ok. If not, abort the scenario using scenario_failure()
- store the name of the target state as atom into the sip_ctx using a new member: currentstate
- if logger is set to debug, the transition is logged as "RCV event: (old state) -> (new state)"
- transition to the target state, calling it with the modified sip_ctx (handled by the runner, not a direct recursive call). goto must be the last expression of a state body or of a receive clause.


### goto next

It gets the next function listed in order of the script and call it as it would have been passed as argument to goto

### goto loop

This causes the finite state machine to reenter the same state

### initial_state

This states needs to be defined and is executed when the finite state machine starts.

### terminal_success_state

This state is predefined. It waits for the event {:dialog_terminated, _dialog_pid, _reason} for 5 seconds
and call media_cleanup_ressources() if a media server connection was created. In the future, all resources
allocated in the script should be deallocated here.

It marks the call scenario as successful

### terminal_failure_state

Same as terminal_success_state but mark de scenario run as failed.

### scenario_success()

Mark the scenario as successful and transition to terminal_success_state.
Log the state before the transtion to final state as an INFO log.

### scenario_failure("reason")

Store the failure reason, log it as well as the state before the transtion to final state as
an error log. 


## Writing and running a SIP scenario

A scenario is a plain Elixir module that `use SIP.Scenario` (see the example
above), saved as a `.exs` file. The `use SIP.Scenario` block generates a `run/0`
entry point that starts the SIP stack (transactions, transport selector, dialog
layer, config registry), builds the initial `%SIP.Context{}` from the `config`
block and enters `initial_state`. `run/0` returns `:ok` on
`terminal_success_state` and `{:error, reason}` on `terminal_failure_state`.

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