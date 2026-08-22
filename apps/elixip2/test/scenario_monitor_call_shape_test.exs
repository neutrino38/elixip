defmodule SIP.Test.ScenarioMonitorCallShape do
  use ExUnit.Case, async: false

  @moduledoc """
  The three columns that say what SHAPE a call is, feeding `kelictl monitor` and
  `elixipp --monitor`: the media it negotiated, the media server carrying them,
  and the destination it was placed to.

  Each is written by the framework at the one point that knows the answer, so a
  scenario says nothing about any of them:

    * `medias` — the answer the two ends settled on, read by
      `SIP.Msg.Ops.media_kinds/1`. Built by us (`get_sdp_answer/3`), given to us
      (`process_sdp_answer/3`), or merely relayed by a signalling B2BUA.
    * `mediaserver` — the name the connected server is declared under, carried
      down by the per-call override; its url when nothing names it.
    * `outbound` — `%SIP.B2bua.Leg{target}`, which is the target being dialled
      and then, after a 2xx, the branch that answered.

  A row that never had any of the three keeps a standing value — `n/a`, `none` —
  rather than a blank: a registrar negotiates no media and dials nobody, and that
  is an answer.
  """

  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

  alias SIP.B2bua.Peer
  alias SIP.Session.B2bua

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _} = SIP.Session.ConfigRegistry.start()
    :ok
  end

  # An offer of audio and video, minimal but real: ExSDP has to parse it and the
  # mockup media server has to be able to answer it.
  defp offer_av do
    """
    v=0\r
    o=alice 2890844526 2890844526 IN IP4 192.168.1.10\r
    s=-\r
    c=IN IP4 192.168.1.10\r
    t=0 0\r
    m=audio 49170 RTP/AVP 0 101\r
    a=rtpmap:0 PCMU/8000\r
    a=rtpmap:101 telephone-event/8000\r
    a=sendrecv\r
    m=video 49172 RTP/AVP 96\r
    a=rtpmap:96 H264/90000\r
    a=sendrecv\r
    """
  end

  # The same, with the video declined the way an answerer declines it (RFC 3264
  # §6): the section stays, its port is 0.
  defp answer_video_declined do
    String.replace(offer_av(), "m=video 49172", "m=video 0")
  end

  # ── The reading itself ──────────────────────────────────────────────────────

  describe "SIP.Msg.Ops.media_kinds/1" do
    test "names the media a description carries, in A/V/T order" do
      assert SIP.Msg.Ops.media_kinds(offer_av()) == [:audio, :video]
    end

    test "a section at port 0 is declined, so it is not negotiated media" do
      assert SIP.Msg.Ops.media_kinds(answer_video_declined()) == [:audio]
    end

    test "nothing to read is an empty list, not a crash" do
      assert SIP.Msg.Ops.media_kinds(nil) == []
      assert SIP.Msg.Ops.media_kinds("") == []
      assert SIP.Msg.Ops.media_kinds("not an sdp at all") == []
    end
  end

  # ── The monitor row ─────────────────────────────────────────────────────────

  describe "the row of a call that has none of the three" do
    setup :monitor_slot

    test "keeps a standing value rather than a blank", %{slot: slot} do
      SIP.Scenario.Monitor.report(slot, "Some.Registrar", "alice", "registered", "REGISTER")

      assert %{medias: "n/a", mediaserver: "none", outbound: "n/a"} = row(slot)
    end
  end

  describe "medias and mediaserver, through the media layer" do
    setup :monitor_slot

    test "the answer we build names the media the two ends settled on", %{slot: slot} do
      ctx = connect_mockup()

      # The offer asks for audio and video; this leg terminates audio only, so the
      # answer the server builds declines the video. What the call carries is what
      # the answer says, and nobody had to be asked.
      {_ctx, {:ok, answer}} = SIP.Session.Media.get_sdp_answer(ctx, offer_av(), media: :audio)
      assert SIP.Msg.Ops.media_kinds(answer) == [:audio]

      assert %{medias: "A", mediaserver: "mcu1"} = row(slot)
    end

    test "an answer we are given is read the same way", %{slot: slot} do
      ctx = connect_mockup()
      {ctx, _offer} = SIP.Session.Media.get_sdp_offer(ctx, :no, :audio_video)

      ctx = SIP.Session.Media.process_sdp_answer(ctx, offer_av())
      assert SIP.Context.get(ctx, :lasterr) == :ok

      assert %{medias: "AV"} = row(slot)
    end

    test "a media server nothing names is shown by its url", %{slot: slot} do
      %SIP.Context{}
      |> SIP.Context.appdata_set(:mediaserver_instance, module: :mockup, url: "http://mcu/")
      |> SIP.Session.Media.use_mediaserver()

      assert %{mediaserver: "http://mcu/"} = row(slot)
    end
  end

  # ── outbound: the destination of a B2BUA call ───────────────────────────────

  describe "outbound, through a serial hunt" do
    setup :monitor_slot

    setup do
      B2bua.forget_event()
      {:ok, stub} = SIP.Test.B2bua.InboundDialogStub.start_link(self())
      on_exit(fn -> if Process.alive?(stub), do: GenServer.stop(stub) end)
      %{ctx: %SIP.Context{dialogpid: stub}}
    end

    test "shows the target being dialled, then the one that answered", %{ctx: ctx, slot: slot} do
      _a = peer!("shape1a")
      _b = peer!("shape1b")

      peer = %Peer{uris: [target("shape1a"), target("shape1b")], fork: :serial}
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)
      assert ctx.lasterr == :ok
      assert_receive {:sip_mockup, {:request_sent, :INVITE, _first}}, 2_000

      # The first of the destination list, while it rings.
      assert %{outbound: "sip:bob@shape1a.example.com;unittest=shape1a"} = row(slot)

      # A device that refuses hands the call to the next one, and the column
      # follows: it names the destination the call is about, not the list.
      ctx = relay_final(ctx, 486)
      assert_receive {:sip_mockup, {:request_sent, :INVITE, _second}}, 2_000
      assert %{outbound: "sip:bob@shape1b.example.com;unittest=shape1b"} = row(slot)

      # And when one answers, it stays on the one that did.
      _ctx = relay_final(ctx, 200)
      assert %{outbound: "sip:bob@shape1b.example.com;unittest=shape1b"} = row(slot)
    end

    # A signalling relay negotiates nothing of its own, so the media the two ends
    # settled on is the answer that crossed it — the one place it can be read.
    test "a signalling relay reads the media off the answer it relays", %{ctx: ctx, slot: slot} do
      _p = peer!("shape2a")

      peer = %Peer{uris: [target("shape2a")], fork: :none}
      ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)
      assert ctx.lasterr == :ok
      assert_receive {:sip_mockup, {:request_sent, :INVITE, _invite}}, 2_000
      assert %{medias: "n/a"} = row(slot)

      _ctx = relay_final(ctx, 200, offer_av())
      assert %{medias: "AV"} = row(slot)
    end
  end

  # ── Helpers ─────────────────────────────────────────────────────────────────

  defp monitor_slot(_ctx) do
    {:ok, _pid} = SIP.Scenario.Monitor.start()
    slot = System.unique_integer([:positive])
    Process.put(:scenario_slot_id, slot)
    on_exit(fn -> SIP.Scenario.Monitor.clear(slot) end)
    {:ok, slot: slot}
  end

  # The monitor is fed by casts, so give the row a moment to land.
  defp row(slot) do
    Enum.reduce_while(1..50, nil, fn _i, _acc ->
      case Enum.find(SIP.Scenario.Monitor.calls(), &(&1.slot == slot)) do
        nil -> Process.sleep(20) && {:cont, nil}
        found -> {:halt, found}
      end
    end)
  end

  defp connect_mockup do
    ctx =
      %SIP.Context{}
      |> SIP.Context.appdata_set(:mediaserver_instance,
        name: "mcu1",
        module: :mockup,
        url: "http://mcu1:8080/"
      )
      |> SIP.Session.Media.use_mediaserver()

    assert SIP.Context.get(ctx, :lasterr) == :ok
    on_exit(fn -> MediaServer.Mockup.disconnect(SIP.Context.get(ctx, :mediaserverpid), []) end)
    ctx
  end

  defp target(name) do
    %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "#{name}.example.com", port: 5060}
    |> SIP.Uri.set_uri_param("unittest", name)
  end

  defp peer!(name) do
    tp = SIP.Transport.Selector.select_transport(target(name)).tp_pid
    :ok = Mockup.set_peer(tp, Manual)
    :ok = Mockup.attach_probe(tp)
    tp
  end

  defp inbound_invite do
    {:ok, raw} = File.read(Path.join(__DIR__, "SIP-INVITE-LVP.txt"))
    {:ok, req} = SIPMsg.parse(raw, fn _c, _m, _l, _line -> nil end)
    Map.put(req, :callid, SIP.Msg.Ops.generate_branch_value())
  end

  defp relay_final(ctx, code, sdp \\ nil) do
    tid = B2bua.outbound_leg(ctx).initial_trans
    B2bua.note_event({:outbound, {code, %{response: code}, tid, self()}})
    B2bua.do_relay_reply(ctx, %{method: false, response: code, reason: nil, body: body(sdp)})
  end

  defp body(nil), do: []
  defp body(sdp), do: [%{contenttype: "application/sdp", data: sdp}]
end
