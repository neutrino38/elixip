defmodule SIP.Test.B2bua.ThreeParty do
  @moduledoc """
  A call relayed across a **real** B2BUA: a caller, the scenario, and a callee,
  each on its own transport.

  What makes it possible is that the UDP mockup now serves one process per named
  peer (`;unittest=caller` / `;unittest=callee`, see
  `SIP.Test.Transport.Mockup.select_instance/1`). With the single shared
  instance the two legs overwrote each other's current request, and an answer
  meant for the callee was built from the caller's INVITE — the two directions
  answered each other.

  Unlike `b2bua_scenario_test.exs`, nothing here is stubbed: the inbound leg is a
  real dialog created by a real INVITE arriving through a transport, so this is
  what exercises the crossing end to end — the inbound server transaction, the
  outbound client transaction, and the addressing of everything the B2BUA sends
  on either side.

  Reading the assertions: each peer has a probe attached, so what the stack puts
  on that leg arrives as `{:sip_mockup, {:response_sent, code, msg}}` on the
  caller side and `{:sip_mockup, {:request_sent, method, msg}}` on the callee
  side.
  """
  use ExUnit.Case

  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

  @callee_uri "sip:bob@callee.example.com;unittest=callee"

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _} = SIP.Session.ConfigRegistry.start()
    :ok = SIP.Auth.Secret.start()

    %{
      scenario:
        SIP.Scenario.Loader.load_file!(Path.expand("../scenarios/b2bua_basic.exs", __DIR__))
    }
  end

  defp peer(name) do
    %SIP.Uri{scheme: "sip:", userpart: "x", domain: "#{name}.example.com", port: 5060}
    |> SIP.Uri.set_uri_param("unittest", name)
    |> SIP.Transport.Selector.select_transport()
  end

  # Spawn one B2BUA instance and arm the dispatcher so the next inbound INVITE is
  # handed to it — the same route a `sub_fsm` child takes.
  defp arm_b2bua(module, peer \\ @callee_uri) do
    test_pid = self()

    {pid, ref} =
      spawn_monitor(fn ->
        outcome =
          SIP.Scenario.Runner.run_instance(module, config_overrides: [peer: peer])

        send(test_pid, {:instance_done, outcome})
      end)

    {:ok, _} = SIP.Scenario.CallDispatcher.start()
    :ok = SIP.Scenario.CallDispatcher.register_waiting(pid)
    :ok = SIP.Session.ConfigRegistry.set_call_processing_module(SIP.Scenario.CallDispatcher)

    on_exit(fn -> if Process.alive?(pid), do: Process.exit(pid, :kill) end)
    {pid, ref}
  end

  defp flush_mailbox do
    receive do
      _ -> flush_mailbox()
    after
      0 -> :ok
    end
  end

  # Push an INVITE into the stack through the caller's transport, exactly as a
  # datagram off the wire would arrive.
  defp caller_invites(caller_tp) do
    {:ok, raw} = File.read(Path.join(__DIR__, "SIP-INVITE-LVP.txt"))
    {:ok, req} = SIPMsg.parse(raw, fn _c, _m, _l, _line -> nil end)

    branch = SIP.Msg.Ops.generate_branch_value()

    req =
      req
      |> Map.put(:callid, SIP.Msg.Ops.generate_branch_value())
      |> Map.put(:ruri, %SIP.Uri{req.ruri | destip: {1, 2, 3, 4}, destport: 5080})
      |> SIP.Msg.Ops.add_via({{2, 2, 2, 2}, 5090, "UDP"}, branch)

    Mockup.inject(caller_tp.tp_pid, req)
    {req, branch}
  end

  @tag timeout: 120_000
  test "a call crosses both legs: 180 and 200 to the caller, INVITE and BYE to the callee",
       %{scenario: module} do
    caller = peer("caller")
    callee = peer("callee")
    refute caller.tp_pid == callee.tp_pid

    :ok = Mockup.set_peer(caller.tp_pid, Manual)
    :ok = Mockup.attach_probe(caller.tp_pid)
    :ok = Mockup.set_peer(callee.tp_pid, Manual)
    :ok = Mockup.attach_probe(callee.tp_pid)

    {_pid, ref} = arm_b2bua(module)

    {invite, branch} = caller_invites(caller)

    # ── The B2BUA answers the caller and calls the callee ────────────────────
    # 100 Trying comes back on the caller's transport.
    assert_receive {:sip_mockup, {:response_sent, 100, _}}, 5_000

    # …and a *different* INVITE reaches the callee: its own dialog, none of the
    # caller's hop-scoped headers, one hop less.
    assert_receive {:sip_mockup, {:request_sent, :INVITE, fwd}}, 5_000
    assert fwd.callid != invite.callid
    assert fwd.ruri.userpart == "bob"
    refute Map.has_key?(fwd, :recordroute)
    assert Map.get(fwd, "Max-Forwards") in [15, "15"]

    # ── The callee rings, then answers; both reach the caller ────────────────
    Manual.simulate(callee.tp_pid, 180, 100)
    assert_receive {:sip_mockup, {:response_sent, 180, _}}, 5_000

    Manual.simulate(callee.tp_pid, 200, 100)
    assert_receive {:sip_mockup, {:response_sent, 200, _}}, 5_000

    # ── The caller confirms, then hangs up ───────────────────────────────────
    Mockup.inject(caller.tp_pid, caller_ack(invite))
    Mockup.inject(caller.tp_pid, caller_bye(invite))
    _ = branch

    # The BYE crosses to the callee, and the caller is answered 200.
    assert_receive {:sip_mockup, {:request_sent, :BYE, _}}, 5_000
    assert_receive {:sip_mockup, {:response_sent, 200, _}}, 5_000

    assert_receive {:instance_done, :ok}, 20_000
    assert_receive {:DOWN, ^ref, :process, _pid, _}, 5_000
  end

  @tag timeout: 120_000
  test "a callee that refuses is relayed to the caller with its own code",
       %{scenario: module} do
    caller = peer("caller")
    callee = peer("callee")

    :ok = Mockup.set_peer(caller.tp_pid, Manual)
    :ok = Mockup.attach_probe(caller.tp_pid)
    :ok = Mockup.set_peer(callee.tp_pid, Manual)
    :ok = Mockup.attach_probe(callee.tp_pid)

    {_pid, _ref} = arm_b2bua(module)
    caller_invites(caller)

    assert_receive {:sip_mockup, {:response_sent, 100, _}}, 5_000
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000

    Manual.simulate(callee.tp_pid, 486, 100)

    # 486, not a code of our own invention — the caller learns the callee is busy.
    assert_receive {:sip_mockup, {:response_sent, 486, _}}, 5_000
    assert_receive {:instance_done, :ok}, 20_000
  end

  # Four parties: the caller, the B2BUA and TWO callees rung at once (§3.2). The
  # scenario is the same file — parallel forking is a property of the peer, not
  # of the script, which is the whole reason the leg abstraction was kept.
  #
  # The assertion that matters is the last one. Once a branch wins, everything
  # keyed on "the attempt" must point at IT: the caller's ACK is relayed onto the
  # winning client transaction, and if it went to the branch dialled first the
  # winner would never be acknowledged and would retransmit its 200 (timer A)
  # until the call collapsed.
  @tag timeout: 120_000
  test "two callees rung at once: the first to answer takes the call, and gets the ACK",
       %{scenario: module} do
    caller = peer("caller")
    calleea = peer("calleea")
    calleeb = peer("calleeb")

    :ok = Mockup.set_peer(caller.tp_pid, Manual)
    :ok = Mockup.attach_probe(caller.tp_pid)
    :ok = Mockup.set_peer(calleea.tp_pid, Manual)
    :ok = Mockup.attach_probe(calleea.tp_pid)
    :ok = Mockup.set_peer(calleeb.tp_pid, Manual)
    :ok = Mockup.attach_probe(calleeb.tp_pid)

    # The peers are named instances shared by every test in this file, and a probe
    # event carries no test identity: an earlier test's 200 would satisfy an
    # assertion here. Start from an empty mailbox.
    flush_mailbox()

    rung = %SIP.B2bua.Peer{
      uris: [
        [
          "sip:bob@calleea.example.com;unittest=calleea",
          "sip:bob@calleeb.example.com;unittest=calleeb"
        ]
      ],
      fork: :parallel
    }

    {_pid, _ref} = arm_b2bua(module, rung)
    {invite, _branch} = caller_invites(caller)

    assert_receive {:sip_mockup, {:response_sent, 100, _}}, 5_000

    rung_domains =
      for _ <- 1..2, into: MapSet.new() do
        assert_receive {:sip_mockup, {:request_sent, :INVITE, fwd}}, 5_000
        fwd.ruri.domain
      end

    assert rung_domains == MapSet.new(["calleea.example.com", "calleeb.example.com"])

    # The second device picks up. The first is CANCELled by the dialog, and the
    # caller hears one 200 — not one per branch.
    Manual.simulate(calleeb.tp_pid, 200, 100)
    assert_receive {:sip_mockup, {:response_sent, 200, _}}, 5_000

    Mockup.inject(caller.tp_pid, caller_ack(invite))

    # Acknowledged: the winner stops retransmitting, so no second 200 reaches
    # the caller.
    refute_receive {:sip_mockup, {:response_sent, 200, _}}, 2_000
  end

  # The ACK of a 2xx is a transaction of its own and carries a FRESH branch
  # (RFC 3261 §17.1.1.3) — which is exactly what routes it past the INVITE server
  # transaction and up to the dialog, where the B2BUA is waiting for it.
  # `SIP.Msg.Ops.ack_request/4` reuses the INVITE's top Via, right for an ACK to a
  # non-2xx and wrong here: that ACK is swallowed by the IST and the scenario
  # never leaves wait_ack.
  defp caller_ack(invite) do
    branch = SIP.Msg.Ops.generate_branch_value()
    [seqno, _method] = invite.cseq

    %{
      "Max-Forwards" => "70",
      method: :ACK,
      ruri: %SIP.Uri{invite.ruri | destip: {1, 2, 3, 4}, destport: 5080},
      from: invite.from,
      to: invite.to,
      useragent: "Elixipp-test",
      callid: invite.callid,
      transid: branch,
      cseq: [seqno, :ACK],
      via: ["SIP/2.0/UDP 2.2.2.2:5090;branch=#{branch}"],
      contentlength: 0
    }
  end

  defp caller_bye(invite) do
    branch = SIP.Msg.Ops.generate_branch_value()

    %{
      "Max-Forwards" => "70",
      method: :BYE,
      ruri: %SIP.Uri{invite.ruri | destip: {1, 2, 3, 4}, destport: 5080},
      from: invite.from,
      to: invite.to,
      useragent: "Elixipp-test",
      callid: invite.callid,
      transid: branch,
      cseq: [hd(invite.cseq) + 1, :BYE],
      via: ["SIP/2.0/UDP 2.2.2.2:5090;branch=#{branch}"],
      contentlength: 0
    }
  end
end
