defmodule SIP.Test.ScenarioIntegration do
  @moduledoc """
  End-to-end test of a `SIP.Scenario` outbound call: INVITE → 100/180/200 → ACK
  → ICE connected → short media playback → BYE → 200, driven by the in-process
  UDP mockup transport and the mockup media server.
  """
  use ExUnit.Case

  # Outbound UAC scenario. The ";unittest=1" RURI param routes the INVITE to the
  # UDP mockup transport (see SIP.Transport.Selector). The player runs for a
  # short, test-friendly duration via the create_player opts.
  defmodule OutboundCall do
    use SIP.Scenario

    @callee "sip:testcall@mydomain.com;unittest=1"

    config username: "toto",
           authusername: "toto",
           displayname: "La tete a toto",
           domain: "mydomain.com"

    state initial_state do
      media_connect(MediaServer.Mockup, "sip:localhost:8080")
      goto next
    end

    state calling do
      send_INVITE(@callee, :mediaserver, timeout: 30, webrtc: :no)
      goto call_progress
    end

    state call_progress do
      receive do
        {100, _rsp, _trans_pid, _dialog_pid} ->
          goto loop, "100 Trying"

        {180, _rsp, _trans_pid, _dialog_pid} ->
          goto loop, "180 Ringing"

        {183, rsp, trans_pid, _dialog_pid} ->
          process_invite_reply(rsp, trans_pid)
          goto loop, "183 Session Progress"

        {200, rsp, trans_pid, _dialog_pid} ->
          process_invite_reply(rsp, trans_pid)
          goto call_answered, "200 OK"

        {code, _rsp, _trans_pid, _dialog_pid} when code in 400..699 ->
          scenario_failure("Call failure with code #{code}")
      after
        30_000 -> scenario_failure("Call not answered after 30s")
      end
    end

    state call_answered do
      receive do
        {:ms_event, _conn, :ice_connected} -> goto start_play, "media connected"
      after
        5_000 -> scenario_failure("No media after 5s")
      end
    end

    state start_play do
      media_play("toto.mp4", duration_ms: 300)
      goto next
    end

    state call_established do
      receive do
        {:ms_event, _player, :player_started} -> goto loop, "player started"
        {:ms_event, _player, :player_ended} -> goto hangup_call, "player EOF"
      after
        5_000 -> scenario_failure("No player events")
      end
    end

    state hangup_call do
      send_BYE()

      receive do
        {200, _bye_rsp, _trans_pid, _dialog_pid} -> scenario_success("200 OK for BYE")
      after
        4_000 -> scenario_failure("No 200 OK for BYE")
      end
    end
  end

  setup_all do
    :ok = SIP.Scenario.start_stack()
    Application.put_env(:elixip2, :proxyuri, %SIP.Uri{domain: "mydomain.com", scheme: "sip:", port: 5060})
    Application.put_env(:elixip2, :proxyusesrv, false)
    :ok
  end

  # Poll the transport registry until the UDP mockup transport process exists
  # (created when the scenario sends its INVITE).
  defp wait_for_transport(0), do: flunk("UDP mockup transport was never created")

  defp wait_for_transport(attempts) do
    case Registry.lookup(Registry.SIPTransport, "UDPMockup") do
      [{pid, _}] ->
        pid

      _ ->
        Process.sleep(20)
        wait_for_transport(attempts - 1)
    end
  end

  @tag timeout: 30_000
  test "outbound INVITE call with media playback runs to success" do
    parent = self()
    spawn(fn -> send(parent, {:scenario_result, OutboundCall.run(false)}) end)

    # Wait for the INVITE to create the transport, then let it be actually sent
    # (so the mockup has stored the request) before driving the answer.
    t_pid = wait_for_transport(100)
    Process.sleep(200)
    SIP.Test.Transport.UDPMockup.simulate_successful_answer(t_pid)

    assert_receive {:scenario_result, :ok}, 25_000
  end
end
