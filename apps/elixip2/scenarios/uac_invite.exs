# Editable, file-loadable copy of the built-in UAC.Invite scenario
# (lib/built-in-scenarios/uac_invite.ex). The module is named UAC.InviteExample so it does
# not collide with the bundled UAC.Invite. Run it with:
#     elixipp apps/elixip2/scenarios/uac_invite.exs
#     mix scenario apps/elixip2/scenarios/uac_invite.exs
# or run the bundled version by name: `elixipp UAC.Invite`.
defmodule UAC.InviteExample do
  # use SIP.Scenario pulls in FSL together with
  # use SIP.Session.CallUAC and use SIP.Session.Media.
  use SIP.Scenario

  # Standard placeholder identity — override at run time with `elixipp -c FILE`.
  @username "1000"
  @authusername "1000"
  @displayname "Test User"
  @domain "example.com"
  @proxy "sip.example.com"
  @passwd "changeme"
  # @callee is NOT a module attribute here because the domain may be overridden at
  # run time by an external config file (-c FILE). Use sip_ctx.domain at runtime.
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
    # Config-driven: the media adapter (Mockup / Mendooze) and its URL come
    # from `config :elixip2, :mediaserver` — override per run with a `-c FILE`
    # JSON header `"mediaserver"` key. Defaults to the Mockup (see config.exs).
    media_connect()
    goto(next)
  end

  # -------------------------------------------------------------------------------
  state calling do
    send_INVITE("sip:#{@callee_num}@#{sip_ctx.domain}", :mediaserver, timeout: 90, webrtc: :no)

    # on_events infers the event type from each clause (here :sip), so the
    # monitor colors the transitions without an explicit type on goto.
    on_events do
      {100, _rsp, _trans_pid, _dialog_pid} ->
        stay("100 Trying")

      {407, rsp, _trans_pid, _dialog_pid} ->
        send_auth_INVITE(rsp, "sip:#{@callee_num}@#{sip_ctx.domain}", :mediaserver, timeout: 90)
        stay("407 Proxy Auth Required")

      {180, _rsp, _trans_pid, _dialog_pid} ->
        stay("180 Ringing")

      {183, rsp_183, trans_pid, _dialog_pid} ->
        process_invite_reply(rsp_183, trans_pid)
        stay("183 Session Progress")

      {200, rsp_200, trans_pid, _dialog_pid} ->
        process_invite_reply(rsp_200, trans_pid)
        goto(call_answered, "200 OK")

      {code, _rsp, _trans_pid, _dialog_pid} when code in 400..699 ->
        scenario_failure("Call failure with code #{code}")

      # The media server went away while we were still calling. There is no call
      # to salvage — the SDP we offered names a server that no longer answers —
      # so give up now rather than let the callee pick up on a dead media path.
      {:ms_event, _server, :server_disconnected} ->
        scenario_failure("media server disconnected while calling")
    after
      30_000 -> scenario_failure("Call not answered after 30s")
    end
  end

  # -------------------------------------------------------------------------------
  state call_answered do
    on_events do
      {:ms_event, _conn, :ice_connected} -> goto(call_established, "media connected")

      {:ms_event, _server, :server_disconnected} ->
        goto(hangup_call, "media server disconnected")
    after
      10_000 -> scenario_failure("No media received after 10s")
    end
  end

  # -------------------------------------------------------------------------------
  state call_established do
    media_play("/home/ebuu/mediaserver/titi.mp4")

    on_events do
      {:ms_event, _player, :player_started} ->
        stay("toto.mp4: start")

      {:ms_event, _player, :player_ended} ->
        goto(hangup_call, "toto.mp4: EOF")

      {:MESSAGE, req, _trans_pid, _dialog_pid} ->
        reply_request(req, 200, "OK")
        stay("MESSAGE")

      {:BYE, req, _trans_pid, _dialog_pid} ->
        reply_request(req, 200, "OK")
        scenario_success("BYE")

      # The media plane is gone: the call is up but there is nothing left to
      # carry it, so hang up instead of holding a silent call open. Nothing here
      # is specific to this scenario — every media scenario owes the same clause,
      # since `:server_disconnected` is delivered but not acted upon by the
      # framework (design docs/design/b2bua_module.md §14.6).
      {:ms_event, _server, :server_disconnected} ->
        goto(hangup_call, "media server disconnected")
    end
  end

  # -------------------------------------------------------------------------------
  state hangup_call do
    # Release whatever the context still holds BEFORE the BYE. This is the
    # defensive one — it skips dead handles and swallows their errors — where
    # media_stop/0 would call a server that may be the very thing that died.
    media_cleanup_ressources()
    send_BYE()

    on_events do
      {200, _bye_rsp, _trans_pid, _dialog_pid} -> scenario_success("200 OK")
    after
      4_000 -> scenario_failure("No 200 OK received for BYE")
    end
  end
end
