defmodule UAC.Invite do
  @moduledoc """
  Built-in outbound-call (UAC INVITE) scenario, compiled into the app and bundled
  into the `elixipp` escript. Run it by module name, without a `.exs` file:

      elixipp UAC.Invite
      elixipp -c ives.json UAC.Invite
      mix scenario UAC.Invite        # via the file path is also fine

  The editable, file-loadable copy lives in `scenarios/uac_invite.exs` (module
  `UAC.InviteExample`); this is the canonical bundled version.
  """
  # use SIP.Scenario pulls in the state-machine DSL together with
  # use SIP.Session.CallUAC and use SIP.Session.Media.
  use SIP.Scenario

  @mediaservermod MediaServer.Mockup

  # Standard placeholder identity — override at run time with `elixipp -c FILE`.
  @username "1000"
  @authusername "1000"
  @displayname "Test User"
  @domain "example.com"
  @proxy "sip.example.com"
  @passwd "changeme"
  @callee_num "90901"

  # SIP identity for the scenario. The framework reads this block to build the
  # initial %SIP.Context{} (computing :ha1 from :passwd) before initial_state.
  # Global keys (proxyuri / proxyusesrv) are routed by the runner to the :elixip2
  # application env — no Application.put_env needed in initial_state.
  config(
    username: @username,
    authusername: @authusername,
    displayname: @displayname,
    domain: @domain,
    passwd: @passwd,
    proxyuri: "sip:#{@proxy}:5060",
    proxyusesrv: false
  )

  # -------------------------------------------------------------------------------
  state initial_state do
    media_connect(@mediaservermod, "sip:localhost:8080")
    goto(next)
  end

  # -------------------------------------------------------------------------------
  state calling do
    send_INVITE("sip:#{@callee_num}@#{sip_ctx.domain}", :mediaserver, timeout: 90, webrtc: :no)
    goto(call_progress)
  end

  # -------------------------------------------------------------------------------
  state call_progress do
    # on_events infers the event type from each clause (here :sip), so the
    # monitor colors the transitions without an explicit type on goto.
    on_events do
      {100, _rsp, _trans_pid, _dialog_pid} ->
        goto(loop, "100 Trying")

      {407, rsp, _trans_pid, _dialog_pid} ->
        send_auth_INVITE(rsp, "sip:#{@callee_num}@#{sip_ctx.domain}", :mediaserver, timeout: 90)
        goto(loop, "407 Proxy Auth Required")

      {180, _rsp, _trans_pid, _dialog_pid} ->
        goto(loop, "180 Ringing")

      {183, rsp_183, trans_pid, _dialog_pid} ->
        process_invite_reply(rsp_183, trans_pid)
        goto(loop, "183 Session Progress")

      {200, rsp_200, trans_pid, _dialog_pid} ->
        process_invite_reply(rsp_200, trans_pid)
        goto(call_answered, "200 OK")

      {code, _rsp, _trans_pid, _dialog_pid} when code in 400..699 ->
        scenario_failure("Call failure with code #{code}")
    after
      30_000 -> scenario_failure("Call not answered after 30s")
    end
  end

  # -------------------------------------------------------------------------------
  state call_answered do
    on_events do
      {:ms_event, _conn, :ice_connected} -> goto(start_play, "media connected")
    after
      5_000 -> scenario_failure("No media received after 5s")
    end
  end

  # -------------------------------------------------------------------------------
  state start_play do
    media_play("toto.mp4")
    goto(next)
  end

  # -------------------------------------------------------------------------------
  state call_established do
    on_events do
      {:ms_event, _player, :player_started} ->
        goto(loop, "toto.mp4: start")

      {:ms_event, _player, :player_ended} ->
        goto(hangup_call, "toto.mp4: EOF")

      {:MESSAGE, req, _trans_pid, dialog_pid} ->
        SIP.Dialog.reply(dialog_pid, req, 200, "OK", [])
        goto(loop, "MESSAGE")

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
