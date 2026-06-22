defmodule UAC.Register do
  use SIP.Scenario
  use SIP.Session.RegisterUAC

  @username "33970262546"
  @authusername "33970262546"
  @displayname "Test User"
  @domain "visioassistance.net"
  @proxy "sip.djanah.com"
  @passwd "TestKam1"
  @registration_expire 60
  @options_keepalive 5

  config username: @username,
         authusername: @authusername,
         displayname: @displayname,
         domain: @domain,
         proxy: @proxy,
         passwd: @passwd

  state initial_state do
    Application.put_env(:elixip2, :proxyuri, %SIP.Uri{domain: @proxy, scheme: "sip:", port: 5060})
    Application.put_env(:elixip2, :proxyusesrv, false)
    goto next
  end

  # ---------------------------------------------------------------------------
  # Initial registration. The send and the wait live in two separate states:
  # `goto loop` re-enters the *waiting* state (which never sends), so a 401 / 100
  # does not trigger a fresh unauthenticated REGISTER. Re-sending here would
  # re-challenge and pile transactions up on the dialog. Same split as in
  # uac_invite.exs (calling -> call_progress).
  state registering do
    send_REGISTER(@registration_expire)
    goto wait_register
  end

  state wait_register do
    on_events do
      {100, _rsp, _trans_pid, _dialog_pid} ->
        goto loop, "100 Trying"
      {401, rsp, _trans_pid, _dialog_pid} ->
        goto auth_registering, "401 Unauthorized"
      {200, _rsp, _trans_pid, _dialog_pid} ->
        goto registered, "200 OK"
      {errcode, _rsp, _trans_pid, _dialog_pid} when errcode in 400..699 ->
        scenario_failure("REGISTER failed with #{errcode}")
      {errcode, _rsp, _trans_pid, _dialog_pid} when errcode in 300..399 ->
        scenario_failure("Unexpected REGISTER redirect #{errcode}")
    after 5_000 ->
      scenario_failure("REGISTER timeout")
    end
  end

  state auth_registering do
    send_auth_REGISTER(@last_rsp, @registration_expire)
    goto wait_register
  end
  # ---------------------------------------------------------------------------
  state registered do
    Process.send_after(self(), :send_options, @options_keepalive * 1000)
    Process.send_after(self(), :send_register, @registration_expire * 500)
    on_events do
      :send_options -> goto keepalive, "Sending keepalive OPTIONS"
      :send_register -> goto refresh, "Sending REGISTER refresh"
    after (@registration_expire + 5) * 1000 ->
      scenario_failure("Unexpected timeout in registered state")
    end
  end

  # ---------------------------------------------------------------------------
  state keepalive do
    send_OPTIONS()
    on_events do
      {200, _rsp, _trans_pid, _dialog_pid} -> goto registered, "OPTIONS OK"
      {errcode, _rsp, _trans_pid, _dialog_pid} when errcode in 400..699 ->
        scenario_failure("OPTIONS failed with #{errcode}")
    after 5_000 ->
      scenario_failure("OPTIONS timeout")
    end
  end

  # ---------------------------------------------------------------------------
  state refresh do
    send_REGISTER(@registration_expire)
    goto wait_refresh
  end

  state wait_refresh do
    on_events do
      {100, _rsp, _trans_pid, _dialog_pid} ->
        goto loop, "100 Trying"
      {401, rsp, _trans_pid, _dialog_pid} ->
        send_auth_REGISTER(rsp, @registration_expire)
        goto loop, "401 Unauthorized"
      {200, _rsp, _trans_pid, _dialog_pid} ->
        goto refreshed, "200 OK"
      {errcode, _rsp, _trans_pid, _dialog_pid} when errcode in 400..699 ->
        scenario_failure("REGISTER refresh failed with #{errcode}")
      {errcode, _rsp, _trans_pid, _dialog_pid} when errcode in 300..399 ->
        scenario_failure("Unexpected REGISTER redirect #{errcode}")
    after 5_000 ->
      scenario_failure("REGISTER refresh timeout")
    end
  end

  # ---------------------------------------------------------------------------
  state refreshed do
    Process.send_after(self(), :send_options, @options_keepalive * 1000)
    Process.send_after(self(), :send_register, @registration_expire * 500)
    on_events do
      :send_options -> goto keepalive2, "Sending keepalive OPTIONS"
      :send_register -> goto unregistering, "Sending unREGISTER"
    after (@registration_expire + 5) * 1000 ->
      scenario_failure("Unexpected timeout in refreshed state")
    end
  end

  # ---------------------------------------------------------------------------
  state keepalive2 do
    send_OPTIONS(timeout: @options_keepalive)
    on_events do
      {200, _rsp, _trans_pid, _dialog_pid} -> goto refreshed, "OPTIONS OK"
      {errcode, _rsp, _trans_pid, _dialog_pid} when errcode in 400..699 ->
        scenario_failure("OPTIONS failed with #{errcode}")
    after 5_000 ->
      scenario_failure("OPTIONS timeout")
    end
  end

  # ---------------------------------------------------------------------------
  state unregistering do
    send_REGISTER(0)
    goto wait_unregister
  end

  state wait_unregister do
    on_events do
      {100, _rsp, _trans_pid, _dialog_pid} ->
        goto loop, "100 Trying"
      {401, rsp, _trans_pid, _dialog_pid} ->
        send_auth_REGISTER(rsp, 0)
        goto loop, "401 Unauthorized"
      {200, _rsp, _trans_pid, _dialog_pid} ->
        scenario_success("unREGISTER OK")
      {errcode, _rsp, _trans_pid, _dialog_pid} when errcode in 400..699 ->
        scenario_failure("unREGISTER failed with #{errcode}")
      {errcode, _rsp, _trans_pid, _dialog_pid} when errcode in 300..399 ->
        scenario_failure("Unexpected unREGISTER redirect #{errcode}")
    after 5_000 ->
      scenario_failure("unREGISTER timeout")
    end
  end
end
