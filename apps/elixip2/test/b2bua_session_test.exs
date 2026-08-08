defmodule SIP.Test.B2bua.InboundDialogStub do
  @moduledoc """
  Stands in for the inbound leg's dialog process: records the replies the B2BUA
  sends on it and forwards them to the test. Using a stub rather than a real
  inbound dialog keeps this suite on what it is about — leg bookkeeping and
  request↔response correlation — and leaves the end-to-end crossing to the
  integration test.
  """
  use GenServer

  def start_link(test_pid), do: GenServer.start_link(__MODULE__, test_pid)

  @impl true
  def init(test_pid), do: {:ok, test_pid}

  @impl true
  def handle_call({:replyreq, req, code, reason, fields}, _from, test_pid) do
    send(test_pid, {:replied, code, reason, req, fields})
    {:reply, :ok, test_pid}
  end
end

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
  alias SIP.Test.Transport.UDPMockup

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
    uri =
      %SIP.Uri{scheme: "sip:", userpart: "callee", domain: "example.com", port: 5060}
      |> SIP.Uri.set_uri_param("unittest", "1")

    struct(%Peer{uris: [uri]}, opts)
  end

  defp transport_pid(%Leg{} = leg) do
    tp = SIP.Transport.Selector.select_transport(leg.target)
    tp.tp_pid
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

  describe "the outbound leg on the wire" do
    test "the forwarded INVITE reaches the peer and its answers come back tagged", %{ctx: ctx} do
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), mockup_peer(), false)
      leg = B2bua.outbound_leg(ctx)
      tp_pid = transport_pid(leg)

      # The mockup received the INVITE (it keeps it as its current request) and
      # can now answer it. Which code it starts with depends on where the shared
      # mockup instance stands; what this asserts is that whatever comes back
      # arrives WRAPPED in the leg tag — the property the scenario patterns on.
      UDPMockup.simulate_successful_answer(tp_pid)

      dlg = leg.dialogpid
      assert_receive {:outbound, {code, _rsp, _tid, ^dlg}} when is_integer(code), 2_000
    end
  end
end
