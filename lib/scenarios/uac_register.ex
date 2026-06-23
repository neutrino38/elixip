defmodule UAC.Register do
  @moduledoc """
  Built-in REGISTER scenario, compiled into the app and bundled into the
  `elixipp` escript. Run it by module name, without a `.exs` file:

      elixipp UAC.Register
      elixipp -c ives.json UAC.Register

  The editable, file-loadable copy lives in `scenarios/uac_register.exs` (module
  `UAC.RegisterExample`); this is the canonical bundled version.
  """
  use SIP.Scenario
  use SIP.Session.RegisterUAC

  # Standard placeholder identity. Real credentials are injected at run time from
  # an external JSON file (e.g. `elixipp -c ives.json UAC.Register`) which
  # overrides this config block. See README "Paramétrage par fichier JSON".
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
    goto(next)
  end

  # ---------------------------------------------------------------------------
  # Initial registration. The send and the wait live in two separate states:
  # `goto loop` re-enters the *waiting* state (which never sends), so a 401 / 100
  # does not trigger a fresh unauthenticated REGISTER. Re-sending here would
  # re-challenge and pile transactions up on the dialog. Same split as in
  # uac_invite.exs (calling -> call_progress).
  state registering do
    send_REGISTER(@registration_expire)
    goto(wait_register)
  end

  state wait_register do
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
      :options_keepalive -> goto(keepalive, "Keepalive OPTIONS")
      :register_refresh -> goto(refresh, "REGISTER refresh")
    after
      (@registration_expire + 5) * 1000 ->
        scenario_failure("No timer fired in registered state")
    end
  end

  # ---------------------------------------------------------------------------
  state keepalive do
    send_OPTIONS()

    on_events do
      {200, rsp, trans_pid, _dialog_pid} ->
        # Re-arm the next :options_keepalive timer.
        process_sip_reply(rsp, trans_pid)
        goto(registered, "OPTIONS OK")

      {errcode, _rsp, _trans_pid, _dialog_pid} when errcode in 400..699 ->
        scenario_failure("OPTIONS failed with #{errcode}")
    after
      5_000 ->
        scenario_failure("OPTIONS timeout")
    end
  end

  # ---------------------------------------------------------------------------
  state refresh do
    # End the test after one refresh: tear the registration down.
    if appdata_get(:refreshes) >= 1 do
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
