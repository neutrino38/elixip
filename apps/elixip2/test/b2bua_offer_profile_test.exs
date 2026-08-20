defmodule SIP.Test.B2bua.OfferProfile do
  @moduledoc """
  The offer-profile ladder (design docs/design/DESIGN-FRAMEWORK.md#58-offer-profiles, plan
  docs/design/DESIGN-FRAMEWORK.md#58-offer-profiles): a `%SIP.B2bua.Peer{profile:}` offers
  the callee a media profile, and a callee that refuses the BODY gets the same
  call offered one profile down before anything else is tried.

  What the tests pin down is the shape of that retry, since it is the part that
  is easy to get subtly wrong:

    * the offers really differ — `UDP/TLS/RTP/SAVPF`, then `RTP/AVPF`, then
      `RTP/AVP`;
    * each one goes out on a NEW CSeq. Two different bodies under one CSeq are
      a merged request (RFC 3261 §8.2.2.2) to a UAS whose server transaction is
      still alive, which after a just-ACKed 488 it is — answered 482;
    * it is still ONE leg, one dialog and one correlation: the caller is never
      told about any of it, and receives one final response at the end;
    * a `_required` profile has one rung, and its refusal IS the answer.

  Same harness as the other session-layer B2BUA suites: a stub inbound dialog, a
  real outbound leg on a UDP mockup peer of this file's own, and
  `MediaServer.Mockup` as the media plane.
  """
  use ExUnit.Case

  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

  alias SIP.B2bua.{Leg, Peer}
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

    ctx =
      SIP.Session.Media.use_mediaserver(
        %SIP.Context{dialogpid: stub},
        MediaServer.Mockup,
        "sip:localhost:8080"
      )

    on_exit(fn ->
      if Process.alive?(stub), do: GenServer.stop(stub)

      if is_pid(ctx.mediaserverpid) and Process.alive?(ctx.mediaserverpid) do
        MediaServer.Mockup.disconnect(ctx.mediaserverpid, force: true)
      end
    end)

    %{ctx: ctx}
  end

  # One mockup peer per test: a probe event carries no test identity, so a
  # teardown still in flight from another test lands in whichever one is running
  # (CLAUDE.md's standing warning about the shared instance).
  defp target(name) do
    %SIP.Uri{scheme: "sip:", userpart: "callee", domain: "#{name}.example.com", port: 5060}
    |> SIP.Uri.set_uri_param("unittest", "profile_#{name}")
  end

  defp arm!(name) do
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

  defp peer(names, opts) do
    struct(%Peer{uris: Enum.map(List.wrap(names), &target/1)}, opts)
  end

  # The caller is a WebRTC endpoint here, which is the case the ladder exists
  # for: the gateway terminates DTLS on the inbound leg and has to find out what
  # the callee speaks on the outbound one.
  defp media_mode do
    {:mediaserver,
     inbound: [webrtc: :if_offered, media: :audio],
     outbound: [media: :audio],
     transcode: [audio: :avoid, video: :avoid]}
  end

  # Relay a final that arrived on the leg's current initial transaction, the way
  # a scenario's `proceeding` clause does.
  defp relay_final(ctx, code) do
    tid = B2bua.outbound_leg(ctx).initial_trans
    B2bua.note_event({:outbound, {code, %{response: code}, tid, self()}})
    B2bua.do_relay_reply(ctx, %{method: false, response: code, reason: nil, body: []})
  end

  defp offered_protocols(invite) do
    invite
    |> SIP.Session.extract_sdp()
    |> String.split(["\r\n", "\n"])
    |> Enum.filter(&String.starts_with?(&1, "m="))
    |> Enum.map(fn line -> line |> String.split(" ") |> Enum.at(2) end)
  end

  defp cseq(invite), do: invite.cseq |> hd()

  # "Nothing else was offered" cannot be a `refute_receive` on a sent INVITE: the
  # client transaction of an INVITE nobody answered retransmits on timer A, and
  # the mockup announces every send. What must not arrive is a DIFFERENT request
  # — another rung of the ladder carries another CSeq, which is exactly what
  # makes it distinguishable from a retransmission here too.
  defp refute_new_offer(previous, timeout \\ 500) do
    receive do
      {:sip_mockup, {:request_sent, :INVITE, req}} ->
        assert cseq(req) == cseq(previous), "a new offer went out (CSeq #{cseq(req)})"
        refute_new_offer(previous, timeout)
    after
      timeout -> :ok
    end
  end

  test "the ladder is walked one rung at a time, each rung on a new CSeq", %{ctx: ctx} do
    tp = arm!("lad1")

    ctx =
      B2bua.do_create_leg(
        ctx,
        inbound_invite(),
        peer("lad1", profile: :webrtc_if_supported),
        media_mode()
      )

    assert ctx.lasterr == :ok

    assert_receive {:sip_mockup, {:request_sent, :INVITE, webrtc}}, 5_000
    assert offered_protocols(webrtc) == ["UDP/TLS/RTP/SAVPF"]

    leg = B2bua.outbound_leg(ctx)
    assert %Leg{profile: :webrtc, profiles_left: [:avpf, :avp]} = leg

    # "Not Acceptable Here": the body, not the device.
    ctx = relay_final(ctx, 488)

    assert_receive {:sip_mockup, {:request_sent, :INVITE, avpf}}, 5_000
    assert offered_protocols(avpf) == ["RTP/AVPF"]
    assert cseq(avpf) == cseq(webrtc) + 1
    # Same call, same leg, same target — only the offer changed.
    assert avpf.callid == webrtc.callid
    assert avpf.ruri.domain == webrtc.ruri.domain
    assert B2bua.outbound_leg(ctx).dialogpid == leg.dialogpid

    # And the caller has been told nothing at all.
    refute_receive {:replied, _code, _reason, _req, _fields}, 200

    ctx = relay_final(ctx, 488)

    assert_receive {:sip_mockup, {:request_sent, :INVITE, avp}}, 5_000
    assert offered_protocols(avp) == ["RTP/AVP"]
    assert cseq(avp) == cseq(avpf) + 1
    assert %Leg{profile: :avp, profiles_left: []} = B2bua.outbound_leg(ctx)
    assert B2bua.hunting?(ctx)

    # The bottom rung is accepted, and what the caller finally gets is the answer
    # decided when their own INVITE arrived — one profile ago, twice over.
    Manual.simulate(tp, 200, 100)
    assert_receive {:outbound, {200, resp, tid, _dlg}}, 5_000
    B2bua.note_event({:outbound, {200, resp, tid, self()}})
    ctx = B2bua.do_relay_reply(ctx, resp)

    assert_receive {:replied, 200, _reason, _req, fields}, 2_000
    assert [%{data: relayed}] = Keyword.fetch!(fields, :body)
    assert relayed == B2bua.media_plan(ctx).inbound_answer

    B2bua.release_legs(ctx)
  end

  test "a _required profile has one rung: the refusal is the answer", %{ctx: ctx} do
    _tp = arm!("lad2")

    ctx =
      B2bua.do_create_leg(
        ctx,
        inbound_invite(),
        peer("lad2", profile: :webrtc_required),
        media_mode()
      )

    assert_receive {:sip_mockup, {:request_sent, :INVITE, offer}}, 5_000
    assert offered_protocols(offer) == ["UDP/TLS/RTP/SAVPF"]
    assert %Leg{profile: :webrtc, profiles_left: []} = B2bua.outbound_leg(ctx)

    ctx = relay_final(ctx, 488)

    # Nothing else is offered, and the caller learns of the refusal.
    refute_new_offer(offer)
    assert_receive {:replied, 488, _reason, _req, _fields}, 2_000
    refute B2bua.hunting?(ctx)

    B2bua.release_legs(ctx)
  end

  test "fallback_on names the codes that mean it: a 415 walks the ladder", %{ctx: ctx} do
    _tp = arm!("lad3")

    peer = peer("lad3", profile: :avpf_if_supported, fallback_on: [415, 488])
    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, media_mode())

    assert_receive {:sip_mockup, {:request_sent, :INVITE, avpf}}, 5_000
    assert offered_protocols(avpf) == ["RTP/AVPF"]

    ctx = relay_final(ctx, 415)

    assert_receive {:sip_mockup, {:request_sent, :INVITE, avp}}, 5_000
    assert offered_protocols(avp) == ["RTP/AVP"]
    assert cseq(avp) == cseq(avpf) + 1
    refute_receive {:replied, 415, _reason, _req, _fields}, 200

    B2bua.release_legs(ctx)
  end

  test "the ladder bottoms out into the hunt, and the next target starts at the top",
       %{ctx: ctx} do
    _a = arm!("lad4a")
    _b = arm!("lad4b")

    peer = peer(["lad4a", "lad4b"], profile: :avpf_if_supported, fork: :serial)
    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, media_mode())

    assert_receive {:sip_mockup, {:request_sent, :INVITE, first}}, 5_000
    assert first.ruri.domain == "lad4a.example.com"
    assert offered_protocols(first) == ["RTP/AVPF"]

    ctx = relay_final(ctx, 488)

    assert_receive {:sip_mockup, {:request_sent, :INVITE, second}}, 5_000
    assert second.ruri.domain == "lad4a.example.com"
    assert offered_protocols(second) == ["RTP/AVP"]

    # The ladder is out of rungs, so THIS 488 is an ordinary refusal and the hunt
    # gets its usual say.
    ctx = relay_final(ctx, 488)

    assert_receive {:sip_mockup, {:request_sent, :INVITE, third}}, 5_000
    assert third.ruri.domain == "lad4b.example.com"

    # …and the second device is offered the TOP of the ladder again: what the
    # first one refused says nothing about this one, and a browser contact behind
    # a desk phone would otherwise be unreachable.
    assert offered_protocols(third) == ["RTP/AVPF"]
    assert %Leg{profile: :avpf, profiles_left: [:avp]} = B2bua.outbound_leg(ctx)
    assert B2bua.hunting?(ctx)

    B2bua.release_legs(ctx)
  end

  test "a profile asks for something a signalling relay cannot do", %{ctx: ctx} do
    ctx =
      B2bua.do_create_leg(
        ctx,
        inbound_invite(),
        peer("lad5", profile: :webrtc_if_supported),
        false
      )

    assert ctx.lasterr == {:b2bua, :profile_needs_media_server, :webrtc_if_supported}
    assert B2bua.outbound_leg(ctx) == nil
    refute_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 200
  end

  test "an unknown profile is refused where it was written", %{ctx: ctx} do
    ctx =
      B2bua.do_create_leg(ctx, inbound_invite(), peer("lad6", profile: :sctp_maybe), media_mode())

    assert ctx.lasterr == {:b2bua, :unknown_offer_profile, :sctp_maybe}
    assert B2bua.outbound_leg(ctx) == nil
  end

  test "no profile is the pre-P5 behaviour: the outbound options say it all", %{ctx: ctx} do
    _tp = arm!("lad7")

    media =
      {:mediaserver,
       inbound: [webrtc: :if_offered, media: :audio],
       outbound: [webrtc: :yes, media: :audio],
       transcode: [audio: :avoid, video: :avoid]}

    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer("lad7", []), media)

    assert_receive {:sip_mockup, {:request_sent, :INVITE, offer}}, 5_000
    assert offered_protocols(offer) == ["UDP/TLS/RTP/SAVPF"]
    assert %Leg{profile: nil, profiles_left: []} = B2bua.outbound_leg(ctx)

    # …and a 488 is just a refusal: nothing is re-offered.
    ctx = relay_final(ctx, 488)
    refute_new_offer(offer)
    assert_receive {:replied, 488, _reason, _req, _fields}, 2_000

    B2bua.release_legs(ctx)
  end
end
