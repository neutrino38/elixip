defmodule UAC.Invite do
  # use SIP.Scenario pulls in the state-machine DSL together with
  # use SIP.Session.CallUAC and use SIP.Session.Media.
  use SIP.Scenario

  @mediaservermod MediaServer.Mockup
  @domain "mydomain.com"
  @callee "sip:testcall@#{@domain}"

  # SIP identity for the scenario. The framework reads this block to build the
  # initial %SIP.Context{} (computing :ha1 from :passwd) before initial_state.
  config username: "toto",
         authusername: "toto",
         displayname: "La tete a toto",
         domain: @domain,
         proxy: "sip.mydomain.com",
         passwd: "xxxx"

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
      {100, _rsp, _trans_pid, _dialog_pid} ->
        goto loop, "100 Trying"

      {407, rsp, _trans_pid, _dialog_pid} ->
        send_auth_INVITE(rsp, @callee, :mediaserver, timeout: 90)
        goto loop, "407 Proxy Auth Required"

      {180, _rsp, _trans_pid, _dialog_pid} ->
        goto loop, "180 Ringing"

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
