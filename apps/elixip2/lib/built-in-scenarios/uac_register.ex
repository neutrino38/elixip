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
    optionkeepaliveperiod: @options_keepalive,
    # This scenario sends the OPTIONS keepalives itself, from its `keepalive`
    # state, so they show up in the monitor and the sequence diagram. The
    # dialog layer then stands down: the two senders are exclusive.
    options_keepalive: :scenario
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

      # Only a response to *our* OPTIONS condemns the run. The refresh timer fires
      # while keepalives are in flight, so the answer to a refresh REGISTER (a 401
      # challenge, normally) can land here — a response is matched on its code, not
      # on the request it answers. Reported as "OPTIONS failed with 401", it sent
      # the reader hunting for a keepalive problem that did not exist.
      {errcode, rsp, _trans_pid, _dialog_pid} when errcode in 400..699 ->
        if SIP.Msg.Ops.is_response_for?(:OPTIONS, rsp) do
          scenario_failure("OPTIONS failed with #{errcode}")
        else
          # `stay`, not `goto loop`: re-entering this state runs send_OPTIONS()
          # again, so "ignored" used to put a second OPTIONS on the wire.
          stay("#{errcode} for another request, ignored")
        end
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
