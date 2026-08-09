defmodule SIP.Test.B2bua.Session do
  @moduledoc """
  The B2BUA session layer (`SIP.Session.B2bua`, design docs/design/b2bua_module.md
  §3-§6): creating the outbound leg, correlating a relayed request with the
  response that comes back, and answering locally on the right leg.

  The outbound leg is driven through the in-process UDP mockup transport; the
  inbound leg is a stub dialog that records what the B2BUA replies on it.
  """
  use ExUnit.Case

  alias SIP.B2bua.{Leg, Peer, Pending}
  alias SIP.Session.B2bua

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _config_pid} = SIP.Session.ConfigRegistry.start()
    :ok
  end

  setup do
    B2bua.forget_event()
    {:ok, stub} = SIP.Test.B2bua.InboundDialogStub.start_link(self())
    on_exit(fn -> if Process.alive?(stub), do: GenServer.stop(stub) end)
    %{ctx: %SIP.Context{dialogpid: stub}, stub: stub}
  end

  defp inbound_invite() do
    {:ok, raw} = File.read(Path.join(__DIR__, "SIP-INVITE-LVP.txt"))
    {:ok, req} = SIPMsg.parse(raw, fn _c, _m, _l, _line -> nil end)
    # A distinct Call-ID per test: the dialog registry is keyed on it.
    Map.put(req, :callid, SIP.Msg.Ops.generate_branch_value())
  end

  # A peer routed through the mockup transport (the `unittest` marker wins over
  # DNS and the proxy config in SIP.Transport.Selector).
  defp mockup_peer(opts \\ []) do
    struct(%Peer{uris: [peer_target()]}, opts)
  end

  # The one target every peer in this suite points at — a mockup instance of this
  # suite's own, so no other suite's traffic reaches it (or ours theirs).
  defp peer_target do
    %SIP.Uri{scheme: "sip:", userpart: "callee", domain: "example.com", port: 5060}
    |> SIP.Uri.set_uri_param("unittest", "b2bua_session")
  end

  # Be the mockup's "test app" before anything goes out: it then tells us when it
  # holds the INVITE, and answering before that would race it.
  defp arm_peer! do
    tp_pid = SIP.Transport.Selector.select_transport(peer_target()).tp_pid
    :ok = GenServer.call(tp_pid, :settestapp)
    tp_pid
  end

  describe "current-event bookkeeping" do
    test "a tagged event names its leg and its transaction, an untagged one is inbound" do
      tid = self()

      B2bua.note_event({:outbound, {200, %{response: 200}, tid, self()}})
      assert Process.get(:scenario_event_leg) == :outbound
      assert Process.get(:scenario_event_tid) == tid

      B2bua.note_event({:BYE, %{method: :BYE}, tid, self()})
      assert Process.get(:scenario_event_leg) == :inbound

      # Media / lifecycle events carry no transaction and belong to no leg.
      B2bua.note_event({:ms_event, make_ref(), :ice_connected})
      assert Process.get(:scenario_event_leg) == :inbound
      assert Process.get(:scenario_event_tid) == nil
    end

    test "split_tag/1 does not mistake a 3-tuple event for a tagged one" do
      assert B2bua.split_tag({:outbound, {:BYE, %{}, nil, nil}}) ==
               {:outbound, {:BYE, %{}, nil, nil}}

      assert {:inbound, _} = B2bua.split_tag({:dialog_terminated, self(), :normal})
      assert {:inbound, _} = B2bua.split_tag({:ms_event, make_ref(), :closed})
    end
  end

  describe "b2bua_forward/3 — refusals" do
    test "a request that cannot create a dialog creates no leg", %{ctx: ctx} do
      ctx = B2bua.do_create_leg(ctx, %{method: :BYE}, mockup_peer(), false)
      assert {:b2bua, :not_dialog_forming, :BYE} = ctx.lasterr
      assert B2bua.outbound_leg(ctx) == nil
    end

    test "a peer with no target creates no leg", %{ctx: ctx} do
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), %Peer{uris: []}, false)
      assert {:b2bua, :no_target} = ctx.lasterr
    end

    test "the media modes of later phases are refused explicitly", %{ctx: ctx} do
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), mockup_peer(), {:mediaserver, []})
      assert {:b2bua, :media_mode_not_implemented, {:mediaserver, []}} = ctx.lasterr
    end

    test "Max-Forwards exhausted is refused as such (the scenario answers 483)", %{ctx: ctx} do
      req = Map.put(inbound_invite(), "Max-Forwards", 0)
      ctx = B2bua.do_create_leg(ctx, req, mockup_peer(), false)
      assert {:b2bua, :too_many_hops} = ctx.lasterr
    end
  end

  describe "b2bua_forward/3 — the outbound leg" do
    test "creates a tagged dialog with a Call-ID of its own", %{ctx: ctx} do
      req = inbound_invite()
      ctx = B2bua.do_create_leg(ctx, req, mockup_peer(), false)

      assert ctx.lasterr == :ok
      assert %Leg{tag: :outbound, dialogpid: dlg} = leg = B2bua.outbound_leg(ctx)
      assert is_pid(dlg)
      assert is_pid(leg.initial_trans)

      # THE anti-collision rule: reusing the inbound Call-ID/from-tag would
      # register the outbound dialog under the inbound dialog's key.
      {out_fromtag, out_callid, _totag} = GenServer.call(dlg, :getdialogid)
      assert out_callid != req.callid
      {_c, in_fromtag} = SIP.Uri.get_uri_param(req.from, "tag")
      assert out_fromtag != in_fromtag

      # The inbound leg is untouched: every existing macro keeps its meaning.
      assert ctx.dialogpid != dlg
    end

    test "records the correlation of the INVITE it forwarded", %{ctx: ctx} do
      req = inbound_invite()
      ctx = B2bua.do_create_leg(ctx, req, mockup_peer(), false)
      leg = B2bua.outbound_leg(ctx)

      assert [{tid, %Pending{orig_leg: :inbound, method: :INVITE, orig_req: orig}}] =
               B2bua.pending(ctx)

      assert tid == leg.initial_trans
      assert orig.callid == req.callid
    end

    test "a second leg is refused while the first is alive", %{ctx: ctx} do
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), mockup_peer(), false)
      assert ctx.lasterr == :ok

      ctx2 = B2bua.do_create_leg(ctx, inbound_invite(), mockup_peer(), false)
      assert {:b2bua, :outbound_leg_exists} = ctx2.lasterr
    end

    # The two questions are orthogonal: the R-URI says what the request asks
    # for, the outbound proxy says where it goes. A gateway in front of the peer
    # must not change the callee the INVITE names.
    test "a per-peer outbound proxy is where the request goes, not what it asks for",
         %{ctx: ctx} do
      gw =
        %SIP.Uri{scheme: "sip:", domain: "gw.example.com", port: 5060}
        |> SIP.Uri.set_uri_param("unittest", "b2bua_session_gw")

      gw_tp = SIP.Transport.Selector.select_transport(gw).tp_pid
      :ok = GenServer.call(gw_tp, :settestapp)

      ctx = B2bua.do_create_leg(ctx, inbound_invite(), mockup_peer(outbound_proxy: gw), false)
      assert ctx.lasterr == :ok

      # It reached the GATEWAY's transport, not the target's…
      assert_receive {:invite_sent, fwd}, 2_000
      # …while still naming the callee it was always for.
      assert fwd.ruri.userpart == "callee"
      assert fwd.ruri.domain == "example.com"
    end

    # (A proxy that cannot be resolved yields {:cannot_route_via_proxy, …}, but
    # asserting it here would be a test of ambient state rather than of this
    # code: with a global `:proxyuri` configured — which other suites do, in the
    # same VM — an unresolvable host is routed to that proxy and resolves fine.)

    # `use_srv` on a domain that publishes no SRV must keep the URI as given —
    # otherwise turning the flag on would break every peer that has no records,
    # which is most of them.
    test "use_srv on a domain with no SRV record leaves the target alone", %{ctx: ctx} do
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), mockup_peer(use_srv: true), false)

      assert ctx.lasterr == :ok
      assert B2bua.outbound_leg(ctx).target.domain == "example.com"
    end

    test "ruri: :keep preserves what the request asks for and only routes it", %{ctx: ctx} do
      req = inbound_invite()
      ctx = B2bua.do_create_leg(ctx, req, mockup_peer(ruri: :keep), false)

      assert ctx.lasterr == :ok
      assert %Leg{} = B2bua.outbound_leg(ctx)
      # The leg exists and its target is the peer, while the request kept its
      # own R-URI identity (the $ru/$du distinction of §3.1).
      assert B2bua.outbound_leg(ctx).target.userpart == "callee"
    end
  end

  describe "b2bua_forward_reply/1 — correlation" do
    setup %{ctx: ctx} do
      req = inbound_invite()
      ctx = B2bua.do_create_leg(ctx, req, mockup_peer(), false)
      assert ctx.lasterr == :ok
      leg = B2bua.outbound_leg(ctx)
      %{ctx: ctx, req: req, leg: leg, tid: leg.initial_trans}
    end

    test "a provisional is relayed on the leg its request came from and stays correlated",
         %{ctx: ctx, req: req, tid: tid} do
      B2bua.note_event({:outbound, {180, %{response: 180}, tid, self()}})

      ctx =
        B2bua.do_relay_reply(ctx, %{method: false, response: 180, reason: "Ringing", body: []})

      assert ctx.lasterr == :ok
      assert_receive {:replied, 180, "Ringing", relayed_req, _fields}
      assert relayed_req.callid == req.callid
      # Provisionals may be relayed again (goto loop): the correlation survives.
      assert [{^tid, %Pending{}}] = B2bua.pending(ctx)
    end

    test "a 2xx to the forwarded INVITE carries OUR contact and closes the correlation",
         %{ctx: ctx, tid: tid} do
      B2bua.note_event({:outbound, {200, %{response: 200}, tid, self()}})

      resp = %{
        method: false,
        response: 200,
        reason: "OK",
        body: "v=0\r\n",
        contenttype: "application/sdp",
        contact: %SIP.Uri{userpart: "callee", domain: "10.0.0.1"}
      }

      ctx = B2bua.do_relay_reply(ctx, resp)

      assert ctx.lasterr == :ok
      assert_receive {:replied, 200, "OK", _req, fields}

      # The far end's contact stayed behind; ours went out (RFC 3261 §12.1.1).
      contact = Keyword.fetch!(fields, :contact)
      assert contact.domain == "0.0.0.0"
      assert [%{data: "v=0\r\n"}] = Keyword.fetch!(fields, :body)

      assert B2bua.pending(ctx) == []
    end

    test "a response nothing correlates with is not relayed, and is not fatal", %{ctx: ctx} do
      B2bua.note_event({:outbound, {200, %{response: 200}, spawn(fn -> :ok end), self()}})

      ctx = B2bua.do_relay_reply(ctx, %{method: false, response: 200, reason: "OK", body: []})

      assert ctx.lasterr == :ok
      refute_receive {:replied, _, _, _, _}, 200
    end
  end

  describe "b2bua_reply/3 — local answers" do
    test "answers on the leg the current event came from", %{ctx: ctx} do
      req = inbound_invite()
      B2bua.note_event({:INVITE, req, self(), ctx.dialogpid})

      ctx = B2bua.do_local_reply(ctx, req, 100, "Trying", [])

      assert ctx.lasterr == :ok
      assert_receive {:replied, 100, "Trying", _req, []}
    end

    test "with no current event (an `after` clause) it answers the caller", %{ctx: ctx} do
      req = inbound_invite()
      ctx = B2bua.do_local_reply(ctx, req, 408, "Request Timeout", [])

      assert ctx.lasterr == :ok
      assert_receive {:replied, 408, "Request Timeout", _req, []}
    end
  end

  describe "release_legs/1 — automatic teardown" do
    test "a scenario that created no leg is left alone", %{ctx: ctx} do
      assert B2bua.release_legs(ctx) == ctx
    end

    test "an attempt still ringing is CANCELled and its caller told 487", %{ctx: ctx} do
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), mockup_peer(), false)
      leg = B2bua.outbound_leg(ctx)
      assert [{_tid, %Pending{}}] = B2bua.pending(ctx)

      ctx = B2bua.release_legs(ctx)

      # The caller is not left hanging on a call attempt nobody will take.
      assert_receive {:replied, 487, "Request Terminated", _req, []}

      # The attempt was cancelled rather than hung up: no BYE went out (the
      # callee never answered, so there is no session to end).
      refute_receive :BYE, 200
      refute leg == nil

      # Bookkeeping cleared, so a second pass has nothing left to do.
      assert B2bua.outbound_leg(ctx) == nil
      assert B2bua.pending(ctx) == []
      assert B2bua.release_legs(ctx) == ctx
    end

    test "an established call is hung up with a BYE", %{ctx: ctx} do
      # Be the mockup's "test app" before anything goes out: it then tells us
      # when it holds the INVITE, and answering before that would race it.
      tp_pid = SIP.Transport.Selector.select_transport(peer_target()).tp_pid
      :ok = GenServer.call(tp_pid, :settestapp)

      ctx = B2bua.do_create_leg(ctx, inbound_invite(), mockup_peer(), false)
      leg = B2bua.outbound_leg(ctx)
      dlg = leg.dialogpid
      assert_receive {:invite_sent, _fwd}, 5_000

      # Let the callee actually answer: only a 2xx makes this a session (it is
      # what teaches the dialog its remote tag and target). The scenario would
      # relay that 200 and drop the correlation; do both here. Driven one
      # response at a time rather than through a canned scenario, so this does
      # not depend on what the shared mockup instance was last used for.
      GenServer.cast(tp_pid, {:simulate, 200, 100})
      assert_receive {:outbound, {200, _rsp, _tid, ^dlg}}, 5_000
      ctx = B2bua.drop_pending(ctx, leg.initial_trans)

      ctx = B2bua.release_legs(ctx)

      assert_receive :BYE, 2_000
      # No orphan answer: nobody was waiting on a relayed request.
      refute_receive {:replied, _, _, _, _}, 200
      assert B2bua.outbound_leg(ctx) == nil
    end

    # The trap this guards: "the initial transaction is over" is NOT "the call
    # is up". An INVITE answered 486 leaves a dialog with no remote target, and
    # the BYE built for it goes out with an empty Request-URI.
    test "a call attempt that was refused is not BYEd", %{ctx: ctx} do
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), mockup_peer(), false)
      leg = B2bua.outbound_leg(ctx)

      # A final response arrived and the scenario relayed it: correlation gone,
      # but the dialog never became a session.
      ctx = B2bua.drop_pending(ctx, leg.initial_trans)

      ctx = B2bua.release_legs(ctx)

      refute_receive :BYE, 500
      assert B2bua.outbound_leg(ctx) == nil
    end

    test "a leg that already died is not a crash", %{ctx: ctx} do
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), mockup_peer(), false)
      leg = B2bua.outbound_leg(ctx)

      GenServer.stop(leg.dialogpid)
      refute Process.alive?(leg.dialogpid)

      ctx = B2bua.release_legs(ctx)
      assert B2bua.outbound_leg(ctx) == nil
    end
  end

  # ── R6: a leg that dies mid-call (design §14.4) ─────────────────────────────
  describe "note_leg_event/2 — a leg that dies" do
    # The wait this closes: the caller's INVITE is correlated with a transaction
    # on the outbound leg, so when that leg dies the answer it was waiting for is
    # never coming. It used to be answered by release_legs/1 — which runs when
    # the SCENARIO ends, not when the leg does, so a caller whose callee vanished
    # held a ringing INVITE until then.
    test "answers, at once, what the dead leg will never answer", %{ctx: ctx} do
      arm_peer!()
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), mockup_peer(), false)
      leg = B2bua.outbound_leg(ctx)
      assert_receive {:invite_sent, _fwd}, 5_000
      assert [{_tid, %Pending{orig_leg: :inbound}}] = B2bua.pending(ctx)

      ctx =
        B2bua.note_leg_event(ctx, {:outbound, {:dialog_terminated, leg.dialogpid, :transport_down}})

      # 487, because the attempt it answers is one we terminated — not 408, which
      # would say the callee was merely slow.
      assert_receive {:replied, 487, _reason, _req, _fields}, 2_000

      # …and the bookkeeping is gone with it: no leg, no correlation, nothing for
      # the teardown to try again on a dead dialog.
      assert B2bua.outbound_leg(ctx) == nil
      assert B2bua.pending(ctx) == []
      refute B2bua.hunting?(ctx)
    end

    # Symmetric, and it has to be: the correlation records where a request came
    # FROM, so what a dying leg loses is everything relayed ONTO it — whichever
    # leg that is.
    test "the inbound leg dying loses what was relayed onto it", %{ctx: ctx, stub: stub} do
      arm_peer!()
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), mockup_peer(), false)
      assert_receive {:invite_sent, _fwd}, 5_000

      # A request that came from the OUTBOUND leg, relayed onto the inbound one.
      ctx = B2bua.drop_pending(ctx, B2bua.outbound_leg(ctx).initial_trans)
      Process.put(:scenario_event_leg, :outbound)
      ctx = B2bua.do_relay_request(ctx, %{method: :MESSAGE, ruri: peer_target()})
      assert [{_tid, %Pending{orig_leg: :outbound}}] = B2bua.pending(ctx)

      ctx = B2bua.note_leg_event(ctx, {:dialog_terminated, stub, :normal})

      # Answered on the outbound leg (a MESSAGE, so 408 — no attempt to
      # terminate), and the outbound leg itself is untouched: the inbound one is
      # the scenario's own dialog, not ours to forget.
      assert B2bua.pending(ctx) == []
      assert %Leg{} = B2bua.outbound_leg(ctx)
    end

    test "an event that is not a leg death changes nothing", %{ctx: ctx} do
      arm_peer!()
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), mockup_peer(), false)
      assert_receive {:invite_sent, _fwd}, 5_000
      before = B2bua.state(ctx)

      ctx = B2bua.note_leg_event(ctx, {:outbound, {180, %{response: 180}, self(), self()}})
      assert B2bua.state(ctx) == before
    end
  end

  # ── R6: talking to a leg that is already gone ───────────────────────────────
  describe "a dialog that dies under a relay" do
    # Every b2bua_* primitive is a GenServer.call on a pid the leg map has held
    # since the leg was created. leg_alive?/1 narrows the window between the check
    # and the call; it cannot close it. The exit used to leave the scenario
    # process — R2 catches it now, but only to END the scenario, which is the
    # right last resort and the wrong ordinary answer: a B2BUA whose callee has
    # just gone should get to say 480 to its caller.
    test "relaying a request onto a dead leg sets lasterr instead of exiting", %{ctx: ctx} do
      arm_peer!()
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), mockup_peer(), false)
      leg = B2bua.outbound_leg(ctx)
      assert_receive {:invite_sent, _fwd}, 5_000

      GenServer.stop(leg.dialogpid)
      refute Process.alive?(leg.dialogpid)

      Process.put(:scenario_event_leg, :inbound)
      ctx = B2bua.do_relay_request(ctx, %{method: :MESSAGE, ruri: peer_target()})
      assert {:b2bua, :leg_dead, :MESSAGE} = ctx.lasterr
    end

    test "answering on a dead leg sets lasterr instead of exiting", %{ctx: ctx, stub: stub} do
      GenServer.stop(stub)
      refute Process.alive?(stub)

      Process.put(:scenario_event_leg, :inbound)
      ctx = B2bua.do_local_reply(ctx, %{method: :INVITE}, 486, "Busy Here", [])
      assert {:b2bua, :leg_dead, :inbound} = ctx.lasterr
    end

    # The one case where a dead leg is not an error: we were asking it to hang up.
    test "BYEing a leg that has already gone is what we wanted", %{ctx: ctx} do
      arm_peer!()
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), mockup_peer(), false)
      leg = B2bua.outbound_leg(ctx)
      assert_receive {:invite_sent, _fwd}, 5_000

      GenServer.stop(leg.dialogpid)
      ctx = B2bua.do_send_bye(ctx)
      assert ctx.lasterr == :ok
    end
  end
end
