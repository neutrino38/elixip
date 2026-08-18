defmodule SIP.Test.SbbBridge do
  @moduledoc """
  `SBB.Call.bridge/1` interrupted and re-entered — the window the design of the
  layer flags as the part to be careful about.

  Between `{:bridge, :interrupted, _}` and the `bridge(resume: true)` that
  follows, the call is still up and in-dialog traffic keeps arriving. Nothing is
  lost, because the mailbox holds it; the point of this suite is that nothing is
  lost AND the resumed block answers it, because the far end has protocol
  deadlines that do not pause with the relay.
  """
  use ExUnit.Case, async: false

  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

  # A scenario that takes its call back for a moment and gives it back. The only
  # thing it does with the interruption is tell the test — a real one would play
  # a prompt or consult a backend.
  defmodule Interruptible do
    use SIP.Scenario
    use SBB.Call

    uas(:invite)

    config(peer: "sip:callee@example.com:5060;unittest=sbb_bridge")

    state initial_state do
      on_events do
        {:INVITE, req, _trans, _dlg} ->
          b2bua_reply(req, 100, "Trying")
          goto(place_call, "INVITE received")
      after
        5_000 -> scenario_failure("no INVITE")
      end
    end

    state place_call do
      call(args: %{peer: ctx_get(:peer)})

      on_events do
        {:call, :connected, _} -> goto(bridging, "call established")
        {:call, outcome, _} -> scenario_failure("not established: #{outcome}")
      end
    end

    state bridging do
      bridge()

      on_events do
        {:bridge, :interrupted, %{message: message}} ->
          send(appdata_get(:test_pid), {:interrupted, message})
          goto(resumed, "took the call back")

        {:bridge, :ended, _} ->
          scenario_success("ended without an interruption")

        {:bridge, outcome, _} ->
          scenario_failure("unexpected: #{outcome}")
      end
    end

    state resumed do
      bridge(resume: true)

      on_events do
        {:bridge, :ended, _} -> scenario_success("ended after the resume")
        {:bridge, outcome, _} -> scenario_failure("unexpected after resume: #{outcome}")
      end
    end
  end

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _config_pid} = SIP.Session.ConfigRegistry.start()
    :ok = SIP.Auth.Secret.start()
    :ok
  end

  setup do
    {:ok, stub} = SIP.Test.B2bua.InboundDialogStub.start_link(self())
    on_exit(fn -> if Process.alive?(stub), do: GenServer.stop(stub) end)
    %{stub: stub}
  end

  defp peer_uri do
    %SIP.Uri{scheme: "sip:", userpart: "callee", domain: "example.com", port: 5060}
    |> SIP.Uri.set_uri_param("unittest", "sbb_bridge")
  end

  defp inbound_invite do
    {:ok, raw} = File.read(Path.join(__DIR__, "SIP-INVITE-LVP.txt"))
    {:ok, req} = SIPMsg.parse(raw, fn _c, _m, _l, _line -> nil end)
    Map.put(req, :callid, SIP.Msg.Ops.generate_branch_value())
  end

  defp in_dialog(method, invite) do
    %{invite | method: method, body: [], contentlength: 0, cseq: [2, method]}
  end

  defp start_instance(stub, invite) do
    test_pid = self()

    spawn_monitor(fn ->
      outcome =
        SIP.Scenario.Runner.run_instance(Interruptible,
          dialog_pid: stub,
          inbound_request: invite,
          config_overrides: [peer: peer_uri(), test_pid: test_pid]
        )

      send(test_pid, {:instance_done, outcome})
    end)
  end

  # Establish the call: INVITE forwarded, answered, ACKed. Returns the INVITE so
  # in-dialog requests can be built from it.
  defp establish(stub) do
    invite = inbound_invite()
    tp = SIP.Transport.Selector.select_transport(peer_uri()).tp_pid
    :ok = Mockup.set_peer(tp, Manual)
    :ok = Mockup.attach_probe(tp)

    {instance, ref} = start_instance(stub, invite)
    send(instance, {:INVITE, invite, self(), stub})

    assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000
    Manual.simulate(tp, 200, 50)
    assert_receive {:replied, 200, _reason, _req, _fields}, 5_000

    send(instance, {:ACK, in_dialog(:ACK, invite), self(), stub})
    assert_receive {:sip_mockup, {:request_sent, :ACK, _}}, 5_000

    %{instance: instance, ref: ref, invite: invite, tp: tp}
  end

  test "a break hands the call back and resume picks it up", %{stub: stub} do
    %{instance: instance, ref: ref, invite: invite} = establish(stub)

    send(instance, {:bridge_break, :consult})
    assert_receive {:interrupted, :consult}, 5_000

    # The call was never torn down: the resumed block relays as before.
    send(instance, {:BYE, in_dialog(:BYE, invite), self(), stub})
    assert_receive {:sip_mockup, {:request_sent, :BYE, _}}, 5_000

    assert_receive {:instance_done, :ok}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end

  # The window itself. A re-INVITE arriving while the host holds the call is not
  # answered by anybody — an unanswered re-INVITE runs at timer B — so what has
  # to be true is that the resumed block finds it and relays it, rather than the
  # message being consumed by the interrupted block and lost.
  test "a re-INVITE that arrives during the interruption is relayed after the resume",
       %{stub: stub} do
    %{instance: instance, ref: ref, invite: invite} = establish(stub)

    send(instance, {:bridge_break, :consult})
    assert_receive {:interrupted, :consult}, 5_000

    # It crosses while nobody is relaying.
    send(instance, {:INVITE, in_dialog(:INVITE, invite), self(), stub})

    # The resumed block picks it out of the mailbox and forwards it: with no
    # media server the two legs are the same offer/answer, so it crosses.
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _reinvite}}, 5_000

    send(instance, {:BYE, in_dialog(:BYE, invite), self(), stub})
    assert_receive {:instance_done, :ok}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end
end
