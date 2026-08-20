defmodule SIP.Test.B2bua.Session do
  @moduledoc """
  The B2BUA session layer (`SIP.Session.B2bua`, design docs/design/DESIGN-FRAMEWORK.md#5-b2bua): creating the outbound leg, correlating a relayed request with the
  response that comes back, and answering locally on the right leg.

  The outbound leg is driven through the in-process UDP mockup transport; the
  inbound leg is a stub dialog that records what the B2BUA replies on it.
  """
  use ExUnit.Case

  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

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
    :ok = Mockup.set_peer(tp_pid, Manual)
    :ok = Mockup.attach_probe(tp_pid)
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

    # `{:rtpengine, …}` keeps its atom so a scenario that one day asks for it does
    # not change shape, and keeps refusing: it belongs to the borderline work, and
    # accepting it would produce a call with no media path.
    test "a media mode that is only reserved is refused explicitly", %{ctx: ctx} do
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), mockup_peer(), {:rtpengine, []})
      assert {:b2bua, :media_mode_not_implemented, {:rtpengine, []}} = ctx.lasterr
      assert B2bua.outbound_leg(ctx) == nil
    end

    # …whereas `{:mediaserver, …}` is understood, and fails on what is actually
    # wrong: nothing was connected to terminate the media on. Named, and not as a
    # rescued sentence — the scenario answers a 503 to this one and a 488 to a
    # codec mismatch, so it has to be able to tell them apart (2026-08-13).
    test "the media mode fails on the media, not on the mode", %{ctx: ctx} do
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), mockup_peer(), {:mediaserver, []})
      assert {:b2bua, :media_setup_failed, :no_media_server} = ctx.lasterr
      assert B2bua.media_unavailable?(ctx)
      assert B2bua.outbound_leg(ctx) == nil
    end

    # A media server that dies under a call in progress: the handle is still a
    # pid, so the setup gets as far as calling it and exits. Same verdict as
    # having none — the caller's offer was never the problem.
    test "a media server that went away reads as unavailable", %{ctx: ctx} do
      for reason <- [:no_media_server, {:media_down, :noproc}, :server_disconnected] do
        assert B2bua.media_unavailable?(%SIP.Context{
                 ctx
                 | lasterr: {:b2bua, :media_setup_failed, {:inbound, reason}}
               })
      end

      refute B2bua.media_unavailable?(%SIP.Context{
               ctx
               | lasterr: {:b2bua, :media_setup_failed, {:inbound, :no_common_codec}}
             })
    end

    test "a bad transcoding policy is refused before anything is dialled", %{ctx: ctx} do
      mode = {:mediaserver, transcode: [audio: :sometimes]}
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), mockup_peer(), mode)

      assert {:b2bua, :media_setup_failed, {:bad_transcoding_policy, :audio, :sometimes}} =
               ctx.lasterr

      assert B2bua.outbound_leg(ctx) == nil

      # A broken argument is reported as itself, before the media plane is even
      # looked at — and it is not unavailability, so it never earns a 503.
      refute B2bua.media_unavailable?(ctx)
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
      :ok = Mockup.set_peer(gw_tp, Manual)
      :ok = Mockup.attach_probe(gw_tp)

      ctx = B2bua.do_create_leg(ctx, inbound_invite(), mockup_peer(outbound_proxy: gw), false)
      assert ctx.lasterr == :ok

      # It reached the GATEWAY's transport, not the target's…
      assert_receive {:sip_mockup, {:request_sent, :INVITE, fwd}}, 2_000
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
      refute_receive {:sip_mockup, {:request_sent, :BYE, _}}, 200
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
      :ok = Mockup.set_peer(tp_pid, Manual)
      :ok = Mockup.attach_probe(tp_pid)

      ctx = B2bua.do_create_leg(ctx, inbound_invite(), mockup_peer(), false)
      leg = B2bua.outbound_leg(ctx)
      dlg = leg.dialogpid
      assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000

      # Let the callee actually answer: only a 2xx makes this a session (it is
      # what teaches the dialog its remote tag and target). The scenario would
      # relay that 200 and drop the correlation; do both here. Driven one
      # response at a time rather than through a canned scenario, so this does
      # not depend on what the shared mockup instance was last used for.
      Manual.simulate(tp_pid, 200, 100)
      assert_receive {:outbound, {200, _rsp, _tid, ^dlg}}, 5_000
      ctx = B2bua.drop_pending(ctx, leg.initial_trans)

      ctx = B2bua.release_legs(ctx)

      assert_receive {:sip_mockup, {:request_sent, :BYE, _}}, 2_000
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

      refute_receive {:sip_mockup, {:request_sent, :BYE, _}}, 500
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
      assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000
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
      assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000

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
      assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000
      before = B2bua.state(ctx)

      ctx = B2bua.note_leg_event(ctx, {:outbound, {180, %{response: 180}, self(), self()}})
      assert B2bua.state(ctx) == before
    end
  end

  # ── {:mediaserver, …}: the bodies that cross are ours ───────────────────────
  describe "the media mode" do
    setup %{ctx: ctx} do
      ctx = SIP.Session.Media.use_mediaserver(ctx, MediaServer.Mockup, "sip:localhost:8080")

      on_exit(fn ->
        if is_pid(ctx.mediaserverpid) and Process.alive?(ctx.mediaserverpid) do
          MediaServer.Mockup.disconnect(ctx.mediaserverpid, force: true)
        end
      end)

      %{ctx: ctx}
    end

    # A mockup instance of the media tests' OWN. Sharing the file's one meant a
    # previous test's dialog, still retransmitting its INVITE on timer A, could
    # overwrite the request `{:simulate, 200, …}` answers — the hazard CLAUDE.md
    # warns about, and it made this block fail once in a while.
    defp media_peer_target do
      %SIP.Uri{scheme: "sip:", userpart: "callee", domain: "example.com", port: 5060}
      |> SIP.Uri.set_uri_param("unittest", "b2bua_session_media")
    end

    defp arm_media_peer! do
      tp_pid = SIP.Transport.Selector.select_transport(media_peer_target()).tp_pid
      :ok = Mockup.set_peer(tp_pid, Manual)
      :ok = Mockup.attach_probe(tp_pid)
      tp_pid
    end

    defp media_peer, do: %Peer{uris: [media_peer_target()]}

    defp media_mode do
      {:mediaserver,
       inbound: [webrtc: :no, media: :audio],
       outbound: [webrtc: :no, media: :audio],
       transcode: [audio: :avoid, video: :avoid]}
    end

    test "the INVITE we forward carries OUR offer, not the caller's", %{ctx: ctx} do
      arm_media_peer!()
      invite = inbound_invite()
      caller_sdp = SIP.Session.extract_sdp(invite)

      ctx = B2bua.do_create_leg(ctx, invite, media_peer(), media_mode())
      assert ctx.lasterr == :ok

      assert_receive {:sip_mockup, {:request_sent, :INVITE, fwd}}, 5_000
      fwd_sdp = SIP.Session.extract_sdp(fwd)

      assert is_binary(fwd_sdp)
      assert fwd_sdp != caller_sdp
      assert fwd_sdp =~ "m=audio"

      # Both endpoints exist, and in the leg-scoped slots R1 introduced.
      assert SIP.Session.Media.media_legs(ctx) == [:inbound, :outbound]

      B2bua.release_legs(ctx)
    end

    test "the caller's answer is held back until the callee answers, then relayed", %{ctx: ctx} do
      tp_pid = arm_media_peer!()
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), media_peer(), media_mode())
      leg = B2bua.outbound_leg(ctx)
      dlg = leg.dialogpid
      assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000

      # Nothing was answered to the caller while the callee was being rung: the
      # answer exists, and waits.
      refute_receive {:replied, _code, _reason, _req, _fields}, 200
      assert %{inbound_answer: held} = B2bua.media_plan(ctx)
      assert is_binary(held)

      Manual.simulate(tp_pid, 200, 100)
      assert_receive {:outbound, {200, resp, tid, ^dlg}}, 5_000
      callee_sdp = SIP.Session.extract_sdp(resp)

      B2bua.note_event({:outbound, {200, resp, tid, self()}})
      ctx = B2bua.do_relay_reply(ctx, resp)

      # The caller gets the media server's answer — the one decided when their
      # INVITE arrived — and never sees the callee's SDP.
      assert_receive {:replied, 200, _reason, _req, fields}, 2_000
      assert [%{data: relayed}] = Keyword.fetch!(fields, :body)
      assert relayed == held
      assert relayed != callee_sdp

      # …and the two endpoints are attached, which is what makes the media flow.
      assert %{bridged: true} = B2bua.media_plan(ctx)

      B2bua.release_legs(ctx)
    end

    # The other half of the contract, and the one that was broken: `bridge/3` may
    # hand back leg A's answer REBUILT now that both legs are known — narrowed to
    # what both can carry, or its codecs reordered — and the doc of the callback
    # says a caller holding the earlier answer "must replace it with this one".
    # `complete_media/4` read the plan from its own PARAMETER instead of from the
    # context `attach_legs/3` had just written, so the rebuilt answer was computed,
    # stored, and then dropped. Nothing caught it because the mock always returned
    # a bare `:ok` (see MediaServer.Mockup.rebuild_answer_on_bridge/2).
    test "the answer rebuilt at bridge time supersedes the one held since the INVITE",
         %{ctx: ctx} do
      tp_pid = arm_media_peer!()
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), media_peer(), media_mode())
      leg = B2bua.outbound_leg(ctx)
      dlg = leg.dialogpid
      assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000

      assert %{inbound_answer: held} = B2bua.media_plan(ctx)
      assert is_binary(held)

      # The media server narrows the caller's answer to the one codec both legs
      # carry — a different body from the one held.
      rebuilt =
        "v=0\r\no=- 1 1 IN IP4 192.168.5.5\r\ns=-\r\nc=IN IP4 192.168.5.5\r\nt=0 0\r\n" <>
          "m=audio 40000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=sendrecv\r\n"

      refute rebuilt == held

      MediaServer.Mockup.rebuild_answer_on_bridge(
        SIP.Session.Media.peer_connection(ctx, :inbound),
        rebuilt
      )

      Manual.simulate(tp_pid, 200, 100)
      assert_receive {:outbound, {200, resp, tid, ^dlg}}, 5_000

      B2bua.note_event({:outbound, {200, resp, tid, self()}})
      ctx = B2bua.do_relay_reply(ctx, resp)

      assert_receive {:replied, 200, _reason, _req, fields}, 2_000
      assert [%{data: relayed}] = Keyword.fetch!(fields, :body)

      assert relayed == rebuilt,
             "the caller was answered the SDP held since the INVITE, not the rebuilt one"

      # …and the plan carries it too, so a scenario reading the plan sees what the
      # caller actually got.
      assert %{bridged: true, inbound_answer: ^rebuilt} = B2bua.media_plan(ctx)

      B2bua.release_legs(ctx)
    end

    test "an early 18x carrying SDP is relayed without it, so the hunt stays open", %{ctx: ctx} do
      tp_pid = arm_media_peer!()
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), media_peer(), media_mode())
      leg = B2bua.outbound_leg(ctx)
      dlg = leg.dialogpid
      assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000

      Manual.simulate(tp_pid, 180, 100)
      assert_receive {:outbound, {180, resp, tid, ^dlg}}, 5_000

      # Give it a body the framework has to decide about.
      resp =
        SIP.Msg.Ops.update_sip_msg(
          resp,
          {:body, [%{contenttype: "application/sdp", data: "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\n"}]}
        )

      B2bua.note_event({:outbound, {180, resp, tid, self()}})
      ctx = B2bua.do_relay_reply(ctx, resp)

      # Relayed, and stripped: with a media server the callee's early SDP is a
      # media event, not an answer to relay — and relaying one would spend the
      # caller's offer/answer on a target that has not won yet.
      assert_receive {:replied, 180, _reason, _req, fields}, 2_000
      assert Keyword.get(fields, :body) in [nil, []]

      B2bua.release_legs(ctx)
    end

    test "a 2xx whose media cannot be bridged becomes a failed attempt, not the answer", %{
      ctx: ctx
    } do
      tp_pid = arm_media_peer!()
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), media_peer(), media_mode())
      leg = B2bua.outbound_leg(ctx)
      dlg = leg.dialogpid
      assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000

      Manual.simulate(tp_pid, 200, 100)
      assert_receive {:outbound, {200, resp, tid, ^dlg}}, 5_000

      # Take the outbound endpoint away underneath: bridging can no longer work,
      # which is what a media server refusing the pair looks like from here.
      MediaServer.Mockup.close_peer_connection(SIP.Session.Media.peer_connection(ctx, :outbound))

      B2bua.note_event({:outbound, {200, resp, tid, self()}})
      ctx = B2bua.do_relay_reply(ctx, resp)

      # The caller is told the attempt failed — with a code that says "this
      # device did not work", so a hunt would move on rather than end the call.
      assert_receive {:replied, 488, _reason, _req, fields}, 2_000
      assert Keyword.get(fields, :body) in [nil, []]

      # The relay itself worked, so `lasterr` says so — truthfully. WHY there was
      # a 488 to relay is a different question, with its own reader.
      assert ctx.lasterr == :ok
      assert B2bua.media_error(ctx) != nil
      refute B2bua.media_plan(ctx).bridged

      B2bua.release_legs(ctx)
    end
  end

  # ── Calling a registered UA: the flow, not a fresh resolution ───────────────
  describe "a target that carries the flow it registered over" do
    # The last mile of the registrar case (design §3.2, §6.4). `targets/2` hands
    # back contacts stamped with the connection the REGISTER came in on, and for
    # a CONNECTED transport (TLS, TCP, WSS) that stamp is the whole point: the UA
    # is usually behind a NAT, the Contact host is a private address, and the only
    # way to reach it is the socket it is still holding open. Reopening is not an
    # option — a new connection is a different flow, from a different source port,
    # and toward a NATed client it cannot even be attempted.
    #
    # The registrar half is covered in kelix_modules; what is pinned here is that
    # the B2BUA does not lose the stamp between the peer and the wire. The target
    # below names a private address nothing could resolve, so the INVITE arriving
    # at all is the assertion.
    test "is dialled over that flow instead of being resolved afresh", %{ctx: ctx} do
      # A mockup instance of its own, and its pid taken as the "registered flow".
      flow_named =
        %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "example.com", port: 5060}
        |> SIP.Uri.set_uri_param("unittest", "b2bua_flow")

      flow_pid = SIP.Transport.Selector.select_transport(flow_named).tp_pid
      :ok = Mockup.set_peer(flow_pid, Manual)
      :ok = Mockup.attach_probe(flow_pid)

      # The contact as Kelix.Mod.Registrar.targets/2 produces it: what the device
      # announced (a private address), plus where its REGISTER really came from
      # and the transport process still holding that connection.
      target = %SIP.Uri{
        scheme: "sip:",
        userpart: "bob",
        domain: "10.0.0.9",
        port: 5060,
        destip: {10, 0, 0, 9},
        destport: 5060,
        destproto: "UDP",
        tp_module: SIP.Test.Transport.Mockup,
        tp_pid: flow_pid
      }

      ctx = B2bua.do_create_leg(ctx, inbound_invite(), %Peer{uris: [target]}, false)
      assert %Leg{} = B2bua.outbound_leg(ctx)

      # Arriving at all is the assertion: this instance is named by a `unittest`
      # marker the target does not carry, and 10.0.0.9 resolves to nothing, so
      # the stamped pid is the only thing that could have routed it here. The
      # request itself comes back off the wire and therefore parsed, which is why
      # nothing is asserted on its transport metadata — it has none by then.
      assert_receive {:sip_mockup, {:request_sent, :INVITE, fwd}}, 5_000
      assert fwd.ruri.domain == "10.0.0.9"
      assert fwd.method == :INVITE

      # Nobody is going to answer this attempt: wind it down here rather than
      # leaving a dialog retransmitting into the next test's run.
      B2bua.release_legs(ctx)
    end
  end

  # ── A relayed request whose far end never answers ───────────────────────────
  describe "a request relayed onto a leg nobody answers" do
    # What the caller must NOT get is silence. Their server transaction would sit
    # there until it gave up on its own, with nothing said. RFC 3261 §17.1.1.2
    # and §8.1.3.1: a client transaction that fails or times out is reported to
    # the TU as a 408 — and the B2BUA's job is to carry that back onto the leg
    # the request came from, on THAT request, not on the call.
    test "ends as a 408 relayed onto the leg the request came from", %{ctx: ctx} do
      tp_pid = arm_peer!()
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), mockup_peer(), false)
      leg = B2bua.outbound_leg(ctx)
      dlg = leg.dialogpid
      assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000

      # The call has to be up first: only a 2xx makes the outbound leg a session,
      # and an in-dialog request needs one. The scenario would relay that 200 and
      # drop the correlation; do both here.
      Manual.simulate(tp_pid, 200, 100)
      assert_receive {:outbound, {200, _rsp, _tid, ^dlg}}, 5_000
      ctx = B2bua.drop_pending(ctx, leg.initial_trans)

      # An in-dialog request from the caller, relayed onto the outbound leg. The
      # mockup has no answer for an INFO — it drops it, which is exactly the far
      # end this test needs.
      Process.put(:scenario_event_leg, :inbound)
      uri = %SIP.Uri{userpart: nil, domain: nil}

      info = %{
        "Max-Forwards" => "70",
        method: :INFO,
        ruri: uri,
        from: uri,
        to: uri,
        useragent: "Elixipp-test",
        callid: nil,
        cseq: [3, :INFO],
        contentlength: 0
      }

      ctx = B2bua.do_relay_request(ctx, info)

      assert {tid, %Pending{orig_leg: :inbound, method: :INFO}} =
               Enum.find(B2bua.pending(ctx), fn {_t, p} -> p.method == :INFO end)

      # Nobody answers it. Killing the client transaction reaches the same place
      # timer F would have reached, without the 32 s wait — and without touching
      # the process-global T1, which other suites read.
      Process.exit(tid, :kill)

      # The dialog synthesises the 408 and delivers it like any response, tagged
      # with the leg and carrying the transaction the correlation is keyed on.
      assert_receive {:outbound, {408, resp, ^tid, _dlg}}, 5_000

      # Which is all a scenario needs to relay it the ordinary way.
      B2bua.note_event({:outbound, {408, resp, tid, self()}})
      ctx = B2bua.do_relay_reply(ctx, resp)

      assert_receive {:replied, 408, _reason, answered, _fields}, 2_000
      assert answered.method == :INFO
      assert answered.cseq == [3, :INFO]

      # The correlation closes with it, and the call is untouched: one dead
      # in-dialog request is not a hangup.
      refute Enum.any?(B2bua.pending(ctx), fn {_t, p} -> p.method == :INFO end)
      assert %Leg{} = B2bua.outbound_leg(ctx)

      # The call is established and would stay up: end it here rather than
      # leaving a live dialog behind for the tests that follow.
      B2bua.release_legs(ctx)
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
      assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000

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
      assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000

      GenServer.stop(leg.dialogpid)
      ctx = B2bua.do_send_bye(ctx)
      assert ctx.lasterr == :ok
    end
  end
end
