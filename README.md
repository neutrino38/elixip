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

This library defines a new [Domain Specific Langage|https://elixir.hexdocs.pm/1.20.1/domain-specific-languages.html] specialized for call and SIP related finite state machine. It is not unlike ExUnit. Call or SIP scenario would be defined as .exs files
that would resemble this

```Elixir
defmodule MyCallScenario do

  use SIP.Session.CallUAC
  use SIP.Session.Media

  @mediaservermod MediaServer.Mockup
  @username "toto"
  @authusername "toto"
  @displayname "La tete a toto"
  @domain "mydomain.com"
  @proxy "sip.mydomain.com"
  @passwd "xxxx"

  @callee "sip:90901@#{@domain}"

  state initial_state do
    media_connect(@mediaservermod, "sip:localhost:8080")

    goto next
  end

  state calling do
    send_INVITE(@callee, :mediaserver, [timeout: 90, webrtc: :no])
    goto call_progress
  end

  state call_progress
    receive do
        {100, rsp, _trans_pid, _dialog_pid} -> call_progress

        {407, rsp, _trans_pid, _dialog_pid} -> 
           send_auth_INVITE(rsp, @callee, :mediaserver, [timeout: 90])
           goto call_progress

        {180, rsp, _trans_pid, _dialog_pid} -> call_progress
        {183, rsp_183, _trans_pid, _dialog_pid} -> 
            process_invite_reply(rsp_183)
            goto call_progress

        {200, rsp_200, _trans_pid, _dialog_pid} ->
            process_invite_reply(rsp_200)
            goto call_answered
        
        {code, rsp, _trans_pid, _dialog_pid } when code in [400..699] ->
            scenario_failure "Call failure with code #{code}"
        
    after 30_000
        timeout -> scenario_failure "Call not answered after 30s"
    end
  end


  state call_answered do
    receive do
      {:ms_event, _conn, :ice_connected } -> start_play

    after 5_000
        timeout -> scenario_failure("No media received after 5s")
    end
  end

  state start_play do
    media_play("toto.mp4")
    goto next
  end

  state call_established do
    receive do
        {:ms_event, _player, :player_started} -> goto loop

        {:ms_event, _player, :player_ended} -> hangup_call

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

    after 4_000
        timeout -> scenario_failure("Not 200 OK received for BYE")     
    end
end
```

This framework would define the following functions or macro:

### state

The state instruction defines a function which takes a %SIP.Context as sole argument.

### goto

This macro takes one argument, a state (a function). It would 
- check the state ctx_get(:lasterr) to be :ok. If not, abort the scenario using scenario_failure()
- store the name of the function as atom into the sip_ctx using a new member: currentstate
- if logger is set to debug, the transition is logged as "RCV event: (old state) -> (new state)"
- call the function passed as argument and pass the modified sip_ctx


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