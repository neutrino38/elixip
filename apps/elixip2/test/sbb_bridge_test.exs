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

        {:bridge, :caller_hung_up, _} ->
          send(appdata_get(:test_pid), {:ended, "ended without an interruption: caller"})
          scenario_success("ended without an interruption: caller")

        {:bridge, :callee_hung_up, _} ->
          send(appdata_get(:test_pid), {:ended, "ended without an interruption: callee"})
          scenario_success("ended without an interruption: callee")

        {:bridge, outcome, _} ->
          scenario_failure("unexpected: #{outcome}")
      end
    end

    state resumed do
      bridge(resume: true)

      on_events do
        {:bridge, :caller_hung_up, _} -> scenario_success("ended after the resume: caller")
        {:bridge, :callee_hung_up, _} -> scenario_success("ended after the resume: callee")
        {:bridge, outcome, _} -> scenario_failure("unexpected after resume: #{outcome}")
      end
    end
  end

  # The same relay, opting to keep the caller when the callee goes away. What it
  # does with the leg it keeps is a prompt in real life; here it answers the
  # caller's own BYE, which is the proof that the leg is still there.
  defmodule Surviving do
    use SIP.Scenario
    use SBB.Call

    uas(:invite)

    config(peer: "sip:callee@example.com:5060;unittest=sbb_bridge_keep")

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
      bridge(args: %{on_callee_hangup: :keep_caller})

      on_events do
        {:bridge, :callee_left, %{reason: reason}} ->
          send(appdata_get(:test_pid), {:callee_left, reason})
          goto(alone_with_caller, "callee left, caller kept")

        {:bridge, outcome, _} ->
          scenario_failure("unexpected: #{outcome}")
      end
    end

    # The caller's dialog is still up: events keep arriving on it, and a reply
    # still goes out on it.
    state alone_with_caller do
      on_events do
        {:BYE, req, _trans, _dlg} ->
          b2bua_reply(req, 200, "OK")
          scenario_success("caller hung up after the callee left")
      after
        5_000 -> scenario_failure("nothing more came from the caller")
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

  defp peer_uri(tag \\ "sbb_bridge") do
    %SIP.Uri{scheme: "sip:", userpart: "callee", domain: "example.com", port: 5060}
    |> SIP.Uri.set_uri_param("unittest", tag)
  end

  defp inbound_invite do
    {:ok, raw} = File.read(Path.join(__DIR__, "SIP-INVITE-LVP.txt"))
    {:ok, req} = SIPMsg.parse(raw, fn _c, _m, _l, _line -> nil end)
    Map.put(req, :callid, SIP.Msg.Ops.generate_branch_value())
  end

  defp in_dialog(method, invite) do
    %{invite | method: method, body: [], contentlength: 0, cseq: [2, method]}
  end

  defp start_instance(stub, invite, module \\ Interruptible, tag \\ "sbb_bridge") do
    test_pid = self()

    spawn_monitor(fn ->
      outcome =
        SIP.Scenario.Runner.run_instance(module,
          dialog_pid: stub,
          inbound_request: invite,
          config_overrides: [peer: peer_uri(tag), test_pid: test_pid]
        )

      send(test_pid, {:instance_done, outcome})
    end)
  end

  # Establish the call: INVITE forwarded, answered, ACKed. Returns the INVITE so
  # in-dialog requests can be built from it.
  defp establish(stub, module \\ Interruptible, tag \\ "sbb_bridge") do
    invite = inbound_invite()
    tp = SIP.Transport.Selector.select_transport(peer_uri(tag)).tp_pid
    :ok = Mockup.set_peer(tp, Manual)
    :ok = Mockup.attach_probe(tp)

    {instance, ref} = start_instance(stub, invite, module, tag)
    send(instance, {:INVITE, invite, self(), stub})

    assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000
    Manual.simulate(tp, 200, 50)
    assert_receive {:replied, 200, _reason, _req, _fields}, 5_000

    send(instance, {:ACK, in_dialog(:ACK, invite), self(), stub})
    assert_receive {:sip_mockup, {:request_sent, :ACK, _}}, 5_000

    %{instance: instance, ref: ref, invite: invite, tp: tp}
  end

  # Which side hung up is the outcome's name. A host reading
  # `{:bridge, :caller_hung_up, _}` knows without looking anything up — and gets
  # it wrong silently if the two are swapped, which is what these two pin.
  test "the caller's BYE is reported as the caller hanging up", %{stub: stub} do
    %{instance: instance, ref: ref, invite: invite} = establish(stub)

    send(instance, {:BYE, in_dialog(:BYE, invite), self(), stub})
    assert_receive {:sip_mockup, {:request_sent, :BYE, _}}, 5_000

    assert_receive {:instance_done, :ok}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
    assert_receive {:ended, "ended without an interruption: caller"}, 1_000
  end

  test "the callee's BYE is reported as the callee hanging up", %{stub: stub} do
    %{instance: instance, ref: ref, tp: tp} = establish(stub)

    Manual.hangup(tp)

    assert_receive {:instance_done, :ok}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
    assert_receive {:ended, "ended without an interruption: callee"}, 1_000
  end

  # ── Keeping the caller when the callee goes away ────────────────────────────

  # A relay hangs up both sides; a service does not have to. With
  # `on_callee_hangup: :keep_caller` the callee's BYE is answered and NOT relayed
  # — relaying it is what would end the caller's dialog — and the script gets the
  # call back with one leg still up.
  test "the callee's BYE does not reach the caller when the caller is kept",
       %{stub: stub} do
    %{instance: instance, ref: ref, invite: invite, tp: tp} =
      establish(stub, Surviving, "sbb_bridge_keep")

    Manual.hangup(tp)
    assert_receive {:callee_left, :bye}, 5_000

    # The one thing the option is about: the caller was not told.
    refute_receive {:sent_on_inbound, %{method: :BYE}}, 500

    # And the leg it kept still works, in both directions.
    send(instance, {:BYE, in_dialog(:BYE, invite), self(), stub})
    assert_receive {:replied, 200, _reason, _req, _fields}, 5_000

    assert_receive {:instance_done, :ok}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
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
