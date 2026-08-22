# Registers, then waits for an inbound call: the REGISTER client above and the
# uas_invite.exs sub-scenario below, in one run. This is what a softphone does — be
# reachable, then answer — and it is the scenario to point a proxy at when testing
# that calls reach a registered user. Run it with:
#     elixipp -c accounts.json apps/elixip2/scenarios/uac_register_and_uas_invite.exs
#     mix scenario apps/elixip2/scenarios/uac_register_and_uas_invite.exs
# It ends when the call is over (or after 5 refreshes with no call).
defmodule UAC.RegisterThenWaitForCall do
  use SIP.Scenario
  use SIP.Session.RegisterUAC

  # Standard placeholder identity. Real credentials are injected at run time from an
  # external JSON file (`elixipp -c accounts.json …`), which overrides this config
  # block. See ELIXIPP.md, "JSON parameterisation".
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
  # Initial registration: send, then wait. A 100 or a 401 `stay`s, so the REGISTER
  # is not re-sent — the resend the challenge needs is the explicit
  # send_auth_REGISTER below. `stay` also keeps the 5 s deadline of the whole
  # registration, which `goto loop` would re-arm on every 100 Trying.

  state registering do
    send_REGISTER(@registration_expire)

    on_events do
      {100, _rsp, _trans_pid, _dialog_pid} ->
        stay("100 Trying")

      {401, rsp, _trans_pid, _dialog_pid} ->
        send_auth_REGISTER(rsp, @registration_expire)
        stay("401 Unauthorized")

      {200, rsp, trans_pid, _dialog_pid} ->
        # Arms the refresh timer (:register_refresh at expire/2) and starts the
        # OPTIONS keepalive — in the dialog layer, since this scenario has no
        # `keepalive` state of its own (the default: `options_keepalive: :dialog`).
        # It used to call start_options_keepalive/1 *as well*, which armed both
        # senders: two OPTIONS per period, and a `:options_keepalive` message that
        # no state here ever consumed, piling up in the mailbox for the whole run.
        process_sip_reply(rsp, trans_pid)
        # Named as a sibling: a sub-scenario path is resolved against the directory of
        # the file that declares it (include semantics), not against the tester's cwd.
        spawn_fsm "uas_invite.exs", as: :invite_uas
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
      {:child_exit, :invite_uas, :success, _r} -> goto(unregistering, "call complete")
      {:child_exit, :invite_uas, :failure, _r} -> goto(unregistering, "call failure")
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

      on_events do
        {100, _rsp, _trans_pid, _dialog_pid} ->
          stay("100 Trying")

        {401, rsp, _trans_pid, _dialog_pid} ->
          send_auth_REGISTER(rsp, @registration_expire)
          stay("401 Unauthorized")

        {200, rsp, trans_pid, _dialog_pid} ->
          # Re-arm both the refresh and the keepalive timers.
          process_sip_reply(rsp, trans_pid)
          goto(registered, "REGISTER refreshed")

        {errcode, _rsp, _trans_pid, _dialog_pid} when errcode in 400..699 ->
          scenario_failure("REGISTER refresh failed with #{errcode}")

        {errcode, _rsp, _trans_pid, _dialog_pid} when errcode in 300..399 ->
          scenario_failure("Unexpected REGISTER redirect #{errcode}")

        {:child_exit, :invite_uas, :success, _r} ->
          goto(unregistering, "call complete")

        {:child_exit, :invite_uas, :failure, _r} ->
          goto(unregistering, "call failure")
      after
        5_000 ->
          scenario_failure("REGISTER refresh timeout")
      end
    end
  end

  # ---------------------------------------------------------------------------
  state unregistering do
    send_REGISTER(0)

    on_events do
      {100, _rsp, _trans_pid, _dialog_pid} ->
        stay("100 Trying")

      {401, rsp, _trans_pid, _dialog_pid} ->
        send_auth_REGISTER(rsp, 0)
        stay("401 Unauthorized")

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
