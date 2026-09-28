defmodule SIP.Test.FSL.StateExceptionTeardown do
  @moduledoc """
  A state that raises hangs the call up anyway.

  The teardown releases what the context says the scenario holds, and a `rescue`
  clause sees the bindings of the moment the `try` was entered — so a state that
  set the call up and *then* raised handed the teardown the context of before its
  own body: no leg to release, no media session to free. On dev71, on
  2026-09-21, that was a call left standing on both sides, a MCU session held
  until its RTP watchdog, and a caller whose BYE the orphaned dialog answered
  503.

  The three tests are the same call flow, differing only in where the scenario
  breaks: in the state that allocated, in the next one, and by an `exit` rather
  than an exception. The second is the counter-test — it passed before the fix,
  because the context the state was entered with already carried the legs — and
  it is kept so that "repair the easy case only" is not a way to a green suite.
  """
  use ExUnit.Case, async: false

  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

  # The state that allocates IS the state that breaks. `:degraded` is not a
  # property of the context, so `SIP.Context.set/3` raises — exactly what the
  # production scenario did, and with no contrivance: a `.exs` is loaded without
  # a compiler ever seeing that atom.
  defmodule RaisingWhileAllocating do
    use SIP.Scenario
    use SBB.Call

    uas(:invite)

    config(peer: "sip:callee@example.com:5060;unittest=state_exc_alloc")

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
        {:call, :connected, _} ->
          ctx_set(:degraded, [:inbound])
          goto(bridging, "call established")

        {:call, outcome, _} ->
          scenario_failure("not established: #{outcome}")
      end
    end

    state bridging do
      bridge()

      on_events do
        {:bridge, outcome, _} -> scenario_success("done: #{outcome}")
      end
    end
  end

  # The counter-test: the same break, one state later.
  defmodule RaisingOneStateLater do
    use SIP.Scenario
    use SBB.Call

    uas(:invite)

    config(peer: "sip:callee@example.com:5060;unittest=state_exc_later")

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
      ctx_set(:degraded, [:inbound])
      bridge()

      on_events do
        {:bridge, outcome, _} -> scenario_success("done: #{outcome}")
      end
    end
  end

  # Not an exception but an exit, which is what a `GenServer.call` toward a dead
  # dialog raises in the scenario's process. It is the `catch` clause of `state`,
  # and it had the same hole.
  defmodule ExitingWhileAllocating do
    use SIP.Scenario
    use SBB.Call

    uas(:invite)

    config(peer: "sip:callee@example.com:5060;unittest=state_exc_exit")

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
        {:call, :connected, _} ->
          dead = spawn(fn -> :ok end)
          ref = Process.monitor(dead)
          receive do: ({:DOWN, ^ref, :process, _, _} -> :ok)
          GenServer.call(dead, :getdialogid)
          goto(bridging, "unreachable")

        {:call, outcome, _} ->
          scenario_failure("not established: #{outcome}")
      end
    end

    state bridging do
      bridge()

      on_events do
        {:bridge, outcome, _} -> scenario_success("done: #{outcome}")
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

  defp peer_uri(tag) do
    %SIP.Uri{scheme: "sip:", userpart: "callee", domain: "example.com", port: 5060}
    |> SIP.Uri.set_uri_param("unittest", tag)
  end

  defp inbound_invite do
    {:ok, raw} = File.read(Path.join(__DIR__, "SIP-INVITE-LVP.txt"))
    {:ok, req} = SIPMsg.parse(raw, fn _c, _m, _l, _line -> nil end)
    Map.put(req, :callid, SIP.Msg.Ops.generate_branch_value())
  end

  # Establish the call — INVITE relayed, answered, ACKed — and hand back what is
  # needed to watch it being torn down.
  defp establish(stub, module, tag) do
    invite = inbound_invite()
    tp = SIP.Transport.Selector.select_transport(peer_uri(tag)).tp_pid
    :ok = Mockup.set_peer(tp, Manual)
    :ok = Mockup.attach_probe(tp)

    test_pid = self()

    {instance, ref} =
      spawn_monitor(fn ->
        outcome =
          SIP.Scenario.Runner.run_instance(module,
            dialog_pid: stub,
            inbound_request: invite,
            config_overrides: [peer: peer_uri(tag), test_pid: test_pid]
          )

        send(test_pid, {:instance_done, outcome})
      end)

    send(instance, {:INVITE, invite, self(), stub})

    assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000
    Manual.simulate(tp, 200, 50)
    assert_receive {:replied, 200, _reason, _req, _fields}, 5_000

    send(
      instance,
      {:ACK, %{invite | method: :ACK, body: [], contentlength: 0, cseq: [2, :ACK]}, self(), stub}
    )

    assert_receive {:sip_mockup, {:request_sent, :ACK, _}}, 5_000

    %{instance: instance, ref: ref, invite: invite, tp: tp}
  end

  # Both legs, and the order does not matter: what matters is that the call is
  # not left standing on either side.
  defp assert_both_legs_hung_up do
    assert_receive {:sip_mockup, {:request_sent, :BYE, _}}, 5_000
    assert_receive {:sent_on_inbound, %{method: :BYE}}, 5_000
  end

  test "a state that raises while it holds the call still hangs both legs up", %{stub: stub} do
    %{ref: ref, instance: instance} = establish(stub, RaisingWhileAllocating, "state_exc_alloc")

    assert_receive {:instance_done, {:error, _}}, 10_000
    assert_both_legs_hung_up()
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end

  test "…and so does one that raises a state later", %{stub: stub} do
    %{ref: ref, instance: instance} = establish(stub, RaisingOneStateLater, "state_exc_later")

    assert_receive {:instance_done, {:error, _}}, 10_000
    assert_both_legs_hung_up()
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end

  test "…and so does one that exits instead of raising", %{stub: stub} do
    %{ref: ref, instance: instance} = establish(stub, ExitingWhileAllocating, "state_exc_exit")

    assert_receive {:instance_done, {:error, _}}, 10_000
    assert_both_legs_hung_up()
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end
end
