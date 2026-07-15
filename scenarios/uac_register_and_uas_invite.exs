# Editable, file-loadable copy of the built-in UAC.Register scenario
# (lib/scenarios/uac_register.ex). The module is named UAC.RegisterExample so it
# does not collide with the bundled UAC.Register. Run it with:
#     elixipp scenarios/uac_register.exs
#     mix scenario scenarios/uac_register.exs
# or run the bundled version by name: `elixipp UAC.Register`.
defmodule UAC.RegisterThenWaitForCall do
  use SIP.Scenario
  use SIP.Session.RegisterUAC


  # Standard placeholder identity. Real credentials are injected at run time from
  # an external JSON file (e.g. `elixipp -c ives.json scenarios/uac_register.exs`)
  # which overrides this config block. See README "Paramétrage par fichier JSON".
  @username "1000"
  @authusername "1000"
  @displayname "Test User"
  @domain "example.com"
  @proxy "sip.example.com"
  @passwd "changeme"
  @registration_expire 60
  @options_keepalive 5

  # The framework reads this block to build the initial %SIP.Context{}. Global
  # keys (proxyuri / proxyusesrv / optionkeepaliveperiod) are routed by the runner
  # to the :elixip2 application env — no need to Application.put_env by hand.
  config(
    username: @username,
    authusername: @authusername,
    displayname: @displayname,
    domain: @domain,
    passwd: @passwd,
    proxyuri: "sip:#{@proxy}:5060",
    proxyusesrv: false,
    optionkeepaliveperiod: @options_keepalive
  )

  state initial_state do
    # Count the refreshes so the test tears the registration down after one.
    appdata_set(:refreshes, 0)
    send_REGISTER(@registration_expire)
    goto next
  end

  # ---------------------------------------------------------------------------
  # Initial registration: waiting for answers

  state registering do
    on_events do
      {100, _rsp, _trans_pid, _dialog_pid} ->
        goto(loop, "100 Trying")

      {401, rsp, _trans_pid, _dialog_pid} ->
        send_auth_REGISTER(rsp, @registration_expire)
        goto(loop, "401 Unauthorized")

      {200, rsp, trans_pid, _dialog_pid} ->
        # Arms the refresh timer (:register_refresh at expire/2) and the OPTIONS
        # keepalive timer (:options_keepalive) from the granted expiration.
        process_sip_reply(rsp, trans_pid)
        SIP.Session.RegisterUAC.start_options_keepalive(sip_ctx)
        sub_fsm "scenarios/uas_invite.exs", as: :invite_uas
        goto(registered, "200 OK")

      {errcode, _rsp, _trans_pid, _dialog_pid} when errcode in 400..699 ->
        scenario_failure("REGISTER failed with #{errcode}")

      {errcode, _rsp, _trans_pid, _dialog_pid} when errcode in 300..399 ->
        scenario_failure("Unexpected REGISTER redirect #{errcode}")
    after
      5_000 ->
        scenario_failure("REGISTER timeout")
    end
  end

  # ---------------------------------------------------------------------------
  # Idle state: the refresh and keepalive timers were armed by the last
  # process_sip_reply, so here we only react to them. No manual Process.send_after.
  state registered do
    on_events do
      :register_refresh -> goto(refresh, "REGISTER refresh")
      {:scenario_ctl, :shutdown, _reason } -> scenario_aborted("UAC stopped gracefully")
      {:scenario_exit, :invite_uas, :success, _r} -> goto unregistering, "call complete"
      {:scenario_exit, :invite_uas, :failure, _r} -> goto unregistering, "call failure"
    after
      (@registration_expire + 5) * 1000 ->
        scenario_failure("No timer fired in registered state")
    end
  end

  # ---------------------------------------------------------------------------
  state refresh do
    # End the test after one refresh: tear the registration down.
    if appdata_get(:refreshes) >= 5 do
      goto(unregistering, "Max refreshes reached")
    else
      appdata_set(:refreshes, appdata_get(:refreshes) + 1)
      send_REGISTER(@registration_expire)
      goto(wait_refresh)
    end
  end

  state wait_refresh do
    on_events do
      {100, _rsp, _trans_pid, _dialog_pid} ->
        goto(loop, "100 Trying")

      {401, rsp, _trans_pid, _dialog_pid} ->
        send_auth_REGISTER(rsp, @registration_expire)
        goto(loop, "401 Unauthorized")

      {200, rsp, trans_pid, _dialog_pid} ->
        # Re-arm both the refresh and the keepalive timers.
        process_sip_reply(rsp, trans_pid)
        goto(registered, "REGISTER refreshed")

      {errcode, _rsp, _trans_pid, _dialog_pid} when errcode in 400..699 ->
        scenario_failure("REGISTER refresh failed with #{errcode}")

      {errcode, _rsp, _trans_pid, _dialog_pid} when errcode in 300..399 ->
        scenario_failure("Unexpected REGISTER redirect #{errcode}")

      {:scenario_exit, :invite_uas, :success, _r} -> goto unregistering, "call complete"

      {:scenario_exit, :invite_uas, :failure, _r} -> goto unregistering, "call failure"
    after
      5_000 ->
        scenario_failure("REGISTER refresh timeout")
    end
  end

  # ---------------------------------------------------------------------------
  state unregistering do
    send_REGISTER(0)
    goto(wait_unregister)
  end

  state wait_unregister do
    on_events do
      {100, _rsp, _trans_pid, _dialog_pid} ->
        goto(loop, "100 Trying")

      {401, rsp, _trans_pid, _dialog_pid} ->
        send_auth_REGISTER(rsp, 0)
        goto(loop, "401 Unauthorized")

      {200, rsp, trans_pid, _dialog_pid} ->
        # expire == 0: process_sip_reply cancels the keepalive timer.
        process_sip_reply(rsp, trans_pid)
        scenario_success("unREGISTER OK")

      {errcode, _rsp, _trans_pid, _dialog_pid} when errcode in 400..699 ->
        scenario_failure("unREGISTER failed with #{errcode}")

      {errcode, _rsp, _trans_pid, _dialog_pid} when errcode in 300..399 ->
        scenario_failure("Unexpected unREGISTER redirect #{errcode}")
    after
      5_000 ->
        scenario_failure("unREGISTER timeout")
    end
  end
end
