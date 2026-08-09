defmodule SIP.Test.B2bua.SerialFork do
  @moduledoc """
  The serial hunt (design docs/design/b2bua_module.md §3.1, §3.3): a
  `%SIP.B2bua.Peer{fork: :serial}` walks its target list, and a device that
  refuses sends the call on to the next one instead of ending it.

  The point the tests pin down is that the hunt is invisible above the dialog:
  however many targets are tried, there is still exactly ONE outbound leg, the
  correlation still points the caller at the same request, and the caller sees a
  single final response — the last one, not one per device.

  Each target is a mockup peer of its own, so "the second device answered" is a
  real second process answering.
  """
  use ExUnit.Case

  alias SIP.B2bua.{Leg, Peer, Pending}
  alias SIP.Session.B2bua

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _} = SIP.Session.ConfigRegistry.start()
    :ok
  end

  setup do
    B2bua.forget_event()
    {:ok, stub} = SIP.Test.B2bua.InboundDialogStub.start_link(self())
    on_exit(fn -> if Process.alive?(stub), do: GenServer.stop(stub) end)
    %{ctx: %SIP.Context{dialogpid: stub}}
  end

  defp target(name) do
    %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "#{name}.example.com", port: 5060}
    |> SIP.Uri.set_uri_param("unittest", name)
  end

  defp peer!(name) do
    tp = SIP.Transport.Selector.select_transport(target(name)).tp_pid
    :ok = GenServer.call(tp, :settestapp)
    tp
  end

  defp inbound_invite do
    {:ok, raw} = File.read(Path.join(__DIR__, "SIP-INVITE-LVP.txt"))
    {:ok, req} = SIPMsg.parse(raw, fn _c, _m, _l, _line -> nil end)
    Map.put(req, :callid, SIP.Msg.Ops.generate_branch_value())
  end

  defp serial_peer(names, opts \\ []) do
    struct(%Peer{uris: Enum.map(names, &target/1), fork: :serial}, opts)
  end

  # Relay a final that arrived on the leg's current initial transaction, the way
  # the scenario's `proceeding` clause does.
  defp relay_final(ctx, code) do
    tid = B2bua.outbound_leg(ctx).initial_trans
    B2bua.note_event({:outbound, {code, %{response: code}, tid, self()}})
    B2bua.do_relay_reply(ctx, %{method: false, response: code, reason: nil, body: []})
  end

  test "a device that refuses sends the call to the next one, on the same leg", %{ctx: ctx} do
    _a = peer!("srl1a")
    _b = peer!("srl1b")

    ctx = B2bua.do_create_leg(ctx, inbound_invite(), serial_peer(["srl1a", "srl1b"]), false)
    assert ctx.lasterr == :ok
    assert_receive {:invite_sent, first}, 2_000
    assert first.ruri.domain == "srl1a.example.com"

    leg_before = B2bua.outbound_leg(ctx)
    assert leg_before.untried == [target("srl1b")]

    ctx = relay_final(ctx, 486)

    # The next device is being tried…
    assert_receive {:invite_sent, second}, 2_000
    assert second.ruri.domain == "srl1b.example.com"
    assert B2bua.hunting?(ctx)

    # …and the caller has NOT been told the call failed.
    refute_receive {:replied, 486, _, _, _}, 200

    # Still one leg, still the same dialog: the hunt is invisible above it.
    leg_after = B2bua.outbound_leg(ctx)
    assert leg_after.dialogpid == leg_before.dialogpid
    assert leg_after.untried == []
    refute leg_after.initial_trans == leg_before.initial_trans

    # And the correlation followed: the caller is still waiting for an answer to
    # the same request, just from a different branch now.
    assert [{tid, %Pending{orig_leg: :inbound, method: :INVITE}}] = B2bua.pending(ctx)
    assert tid == leg_after.initial_trans
  end

  test "when every device has refused, the caller gets the last answer once", %{ctx: ctx} do
    _a = peer!("srl2a")
    _b = peer!("srl2b")

    ctx = B2bua.do_create_leg(ctx, inbound_invite(), serial_peer(["srl2a", "srl2b"]), false)
    assert_receive {:invite_sent, _first}, 2_000

    ctx = relay_final(ctx, 486)
    assert_receive {:invite_sent, _second}, 2_000
    refute_receive {:replied, _, _, _, _}, 200

    ctx = relay_final(ctx, 480)

    # The hunt is over: the caller learns of the last refusal, and of that one only.
    assert_receive {:replied, 480, _reason, _req, _fields}, 2_000
    refute B2bua.hunting?(ctx)
    assert B2bua.pending(ctx) == []
  end

  test "a 2xx ends the hunt: it is relayed and the untried targets are left alone",
       %{ctx: ctx} do
    _a = peer!("srl3a")
    b = peer!("srl3b")

    ctx = B2bua.do_create_leg(ctx, inbound_invite(), serial_peer(["srl3a", "srl3b"]), false)
    assert_receive {:invite_sent, _first}, 2_000

    ctx = relay_final(ctx, 486)
    assert_receive {:invite_sent, _second}, 2_000

    # The second device answers for real, through the wire.
    dlg = B2bua.outbound_leg(ctx).dialogpid
    GenServer.cast(b, {:simulate, 200, 100})
    assert_receive {:outbound, {200, ok_resp, tid, ^dlg}}, 3_000

    B2bua.note_event({:outbound, {200, ok_resp, tid, dlg}})
    ctx = B2bua.do_relay_reply(ctx, ok_resp)

    assert_receive {:replied, 200, _reason, _req, _fields}, 2_000
    refute B2bua.hunting?(ctx)
  end

  # 6xx is a global refusal (RFC 3261 §16.7): the user declined, and ringing
  # their other phones is precisely what they asked not to happen.
  test "a 6xx stops the hunt even with targets left", %{ctx: ctx} do
    _a = peer!("srl4a")
    _b = peer!("srl4b")

    ctx = B2bua.do_create_leg(ctx, inbound_invite(), serial_peer(["srl4a", "srl4b"]), false)
    assert_receive {:invite_sent, _first}, 2_000

    ctx = relay_final(ctx, 603)

    assert_receive {:replied, 603, _reason, _req, _fields}, 2_000
    refute_receive {:invite_sent, _second}, 300
    refute B2bua.hunting?(ctx)
  end

  # A 487 answers an INVITE *we* terminated — a branch cancelled because the
  # caller gave up. Reading it as "this device refused" made the caller's own
  # CANCEL ring the next agent: they hung up, and a second phone started ringing.
  test "a 487 never continues the hunt, targets left or not", %{ctx: ctx} do
    _a = peer!("srl8a")
    _b = peer!("srl8b")

    ctx = B2bua.do_create_leg(ctx, inbound_invite(), serial_peer(["srl8a", "srl8b"]), false)
    assert_receive {:invite_sent, _first}, 2_000
    assert B2bua.outbound_leg(ctx).untried != []

    ctx = relay_final(ctx, 487)

    refute_receive {:invite_sent, _second}, 300
    refute B2bua.hunting?(ctx)
    assert_receive {:replied, 487, _reason, _req, _fields}, 2_000
  end

  # …and not even when the peer explicitly asks for it: there is no case where
  # hunting on a 487 is what the operator meant.
  test "a peer cannot opt back into hunting on 487", %{ctx: ctx} do
    _a = peer!("srl9a")
    _b = peer!("srl9b")

    peer = serial_peer(["srl9a", "srl9b"], retry_on: [487, 486])
    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)
    assert_receive {:invite_sent, _first}, 2_000

    ctx = relay_final(ctx, 487)

    refute_receive {:invite_sent, _second}, 300
    refute B2bua.hunting?(ctx)
  end

  test "the retry-on list is a peer option", %{ctx: ctx} do
    _a = peer!("srl5a")
    _b = peer!("srl5b")

    # This peer only moves on when the device is busy; anything else is final.
    peer = serial_peer(["srl5a", "srl5b"], retry_on: [486])
    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)
    assert_receive {:invite_sent, _first}, 2_000

    ctx = relay_final(ctx, 480)

    assert_receive {:replied, 480, _reason, _req, _fields}, 2_000
    refute_receive {:invite_sent, _second}, 300
    refute B2bua.hunting?(ctx)
  end

  test "fork: :none keeps the extra targets unused", %{ctx: ctx} do
    _a = peer!("srl6a")
    _b = peer!("srl6b")

    peer = %Peer{uris: [target("srl6a"), target("srl6b")], fork: :none}
    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)
    assert_receive {:invite_sent, _first}, 2_000

    assert %Leg{untried: []} = B2bua.outbound_leg(ctx)

    ctx = relay_final(ctx, 486)
    assert_receive {:replied, 486, _reason, _req, _fields}, 2_000
    refute_receive {:invite_sent, _second}, 300
  end

  describe "progress events (§3.6)" do
    test "a hunt says nothing unless the peer asked", %{ctx: ctx} do
      _a = peer!("prg0a")
      _b = peer!("prg0b")

      ctx = B2bua.do_create_leg(ctx, inbound_invite(), serial_peer(["prg0a", "prg0b"]), false)
      assert_receive {:invite_sent, _first}, 2_000
      ctx = relay_final(ctx, 486)
      assert_receive {:invite_sent, _second}, 2_000

      refute_receive {:outbound, {:serial_attempting, _, _}}, 200
      refute_receive {:outbound, {:serial_not_reachable, _, _, _}}, 200
      _ = ctx
    end

    test "each attempt, its outcome and the end of the search are reported in order",
         %{ctx: ctx} do
      _a = peer!("prg1a")
      _b = peer!("prg1b")

      peer = serial_peer(["prg1a", "prg1b"], notify_progress: true)
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)

      # The first target is being tried…
      assert_receive {:outbound, {:serial_attempting, first, at1}}, 2_000
      assert first.domain == "prg1a.example.com"
      assert %DateTime{} = at1

      # …it is busy, and the next one is tried. The cause travels with it: a queue
      # keeps a busy agent in rotation and logs a dead phone out.
      ctx = relay_final(ctx, 486)
      assert_receive {:outbound, {:serial_not_reachable, ^first, 486, _at}}, 2_000
      assert_receive {:outbound, {:serial_attempting, second, _at}}, 2_000
      assert second.domain == "prg1b.example.com"

      # The last one refuses too: its outcome, then the search giving up.
      ctx = relay_final(ctx, 480)
      assert_receive {:outbound, {:serial_not_reachable, ^second, 480, _at}}, 2_000
      assert_receive {:outbound, {:serial_exhausted, _at}}, 2_000
      refute B2bua.hunting?(ctx)
    end

    test "an answer is reported as connected, and ends the reporting", %{ctx: ctx} do
      _a = peer!("prg2a")
      b = peer!("prg2b")

      peer = serial_peer(["prg2a", "prg2b"], notify_progress: true)
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)
      assert_receive {:outbound, {:serial_attempting, _first, _}}, 2_000

      ctx = relay_final(ctx, 486)
      assert_receive {:outbound, {:serial_attempting, second, _}}, 2_000

      dlg = B2bua.outbound_leg(ctx).dialogpid
      GenServer.cast(b, {:simulate, 200, 100})
      assert_receive {:outbound, {200, ok_resp, tid, ^dlg}}, 3_000
      B2bua.note_event({:outbound, {200, ok_resp, tid, dlg}})
      ctx = B2bua.do_relay_reply(ctx, ok_resp)

      assert_receive {:outbound, {:serial_connected, ^second, _at}}, 2_000
      refute_receive {:outbound, {:serial_exhausted, _}}, 300
      _ = ctx
    end

    # The events say which attempt, so a CDR line can be built from two of them;
    # what they must NOT do is be mistaken for traffic by a catch-all clause.
    test "they cannot be confused with the leg's traffic events", %{ctx: ctx} do
      _a = peer!("prg3a")
      peer = serial_peer(["prg3a"], notify_progress: true)
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)

      assert_receive {:outbound, evt}, 2_000

      # A traffic clause matches {code, resp, tid, dlg} or {method, req, tid, dlg}
      # — 4-tuples led by an integer or a method. A progress event is neither.
      refute match?({code, _, _, _} when is_integer(code), evt)
      refute match?({m, _, _, _} when is_atom(m) and m not in [:serial_attempting], evt)
      assert match?({:serial_attempting, _uri, _at}, evt)
      _ = ctx
    end
  end

  test "the teardown CANCELs whichever branch is in flight", %{ctx: ctx} do
    _a = peer!("srl7a")
    _b = peer!("srl7b")

    ctx = B2bua.do_create_leg(ctx, inbound_invite(), serial_peer(["srl7a", "srl7b"]), false)
    assert_receive {:invite_sent, _first}, 2_000
    ctx = relay_final(ctx, 486)
    assert_receive {:invite_sent, _second}, 2_000

    # The scenario ends while the second device is still ringing: the caller is
    # owed a final response and the device a CANCEL. The teardown reads the
    # leg's CURRENT initial transaction, so it acts on the branch in flight.
    ctx = B2bua.release_legs(ctx)

    assert_receive {:replied, 487, "Request Terminated", _req, _}, 2_000
    assert B2bua.outbound_leg(ctx) == nil
  end
end
