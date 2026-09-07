defmodule SIP.Test.B2bua.AddrProfileHunt do
  @moduledoc """
  Step 5 of `docs/design/multi-interface.md`: one media endpoint per addressing
  profile a hunt walks through.

  The address in an offer's `c=` line is fixed when the endpoint is created, so a
  hunt that leaves a v4 target for a v6 one cannot announce the right interface
  with the endpoint it has — it needs another, exactly as an offer-profile ladder
  restart does. Both go through the same drop-and-rebuild.

  Same harness as `SIP.Test.B2bua.OfferProfile`: a stub inbound dialog, a real
  outbound leg on this file's own UDP mockup peers, `MediaServer.Mockup` as the
  media plane. The targets are marked by hand — resolution is covered by
  `SIP.Test.B2buaTargetMarking`, and what is under test here is what the hunt
  does with marks it is given.
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

  # A target on a real mockup peer, marked as if `b2bua_resolve/1` had resolved it
  # to `ip` on `side`.
  defp marked(name, ip, side) do
    %SIP.Uri{scheme: "sip:", userpart: "callee", domain: "#{name}.example.com", port: 5060}
    |> SIP.Uri.set_uri_param("unittest", "addrprof_#{name}")
    |> Map.put(:destip, ip)
    |> Map.put(:destport, 5060)
    |> Map.put(:net_side, side)
  end

  defp arm!(uri) do
    tp = SIP.Transport.Selector.select_transport(uri).tp_pid
    :ok = Mockup.set_peer(tp, Manual)
    :ok = Mockup.attach_probe(tp)
    tp
  end

  defp inbound_invite do
    {:ok, raw} = File.read(Path.join(__DIR__, "SIP-INVITE-LVP.txt"))
    {:ok, req} = SIPMsg.parse(raw, fn _c, _m, _l, _line -> nil end)
    Map.put(req, :callid, SIP.Msg.Ops.generate_branch_value())
  end

  defp media_mode do
    {:mediaserver, inbound: [media: :audio], outbound: [media: :audio]}
  end

  defp relay_final(ctx, code) do
    tid = B2bua.outbound_leg(ctx).initial_trans
    B2bua.note_event({:outbound, {code, %{response: code}, tid, self()}})
    B2bua.do_relay_reply(ctx, %{method: false, response: code, reason: nil, body: []})
  end

  defp endpoint(ctx), do: SIP.Session.Media.peer_connection(ctx, :outbound)

  @v4 {192, 0, 2, 10}
  @v6 {0x2001, 0xDB8, 0, 0, 0, 0, 0, 10}

  test "a hunt that changes family rebuilds the endpoint on the new profile",
       %{ctx: ctx} do
    a = marked("hunta", @v4, :public)
    b = marked("huntb", @v6, :public)
    _ = arm!(a)
    _ = arm!(b)

    # Pre-resolved, as b2bua_resolve/1 leaves it: two rungs of one, two profiles.
    peer = %Peer{uris: [a, b], fork: :serial, resolved: [[a], [b]]}

    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, media_mode())

    assert_receive {:sip_mockup, {:request_sent, :INVITE, first}}, 5_000
    assert first.ruri.domain == "hunta.example.com"

    # The first rung is v4, so the endpoint was placed there.
    assert %Leg{addr_profile: "publicv4"} = B2bua.outbound_leg(ctx)
    first_endpoint = endpoint(ctx)
    assert is_pid(first_endpoint)

    ctx = relay_final(ctx, 486)

    assert_receive {:sip_mockup, {:request_sent, :INVITE, second}}, 5_000
    assert second.ruri.domain == "huntb.example.com"

    # The second rung is v6: the leg says so, and the endpoint is ANOTHER one —
    # the `c=` address of the first was fixed when it was created.
    assert %Leg{addr_profile: "publicv6"} = B2bua.outbound_leg(ctx)
    second_endpoint = endpoint(ctx)
    assert is_pid(second_endpoint)
    refute second_endpoint == first_endpoint
    refute Process.alive?(first_endpoint)

    B2bua.release_legs(ctx)
  end

  test "a hunt that stays on one profile keeps its endpoint", %{ctx: ctx} do
    a = marked("keepa", @v4, :public)
    b = marked("keepb", {192, 0, 2, 11}, :public)
    _ = arm!(a)
    _ = arm!(b)

    peer = %Peer{uris: [a, b], fork: :serial, resolved: [[a], [b]]}
    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, media_mode())

    assert_receive {:sip_mockup, {:request_sent, :INVITE, _first}}, 5_000
    assert %Leg{addr_profile: "publicv4"} = B2bua.outbound_leg(ctx)
    kept = endpoint(ctx)

    ctx = relay_final(ctx, 486)

    assert_receive {:sip_mockup, {:request_sent, :INVITE, second}}, 5_000
    assert second.ruri.domain == "keepb.example.com"

    # Same profile, so nothing is rebuilt: a media endpoint torn down and made
    # again costs ports, DTLS material and a round of RPCs for no gain.
    assert %Leg{addr_profile: "publicv4"} = B2bua.outbound_leg(ctx)
    assert endpoint(ctx) == kept
    assert Process.alive?(kept)

    B2bua.release_legs(ctx)
  end

  test "one rung is one offer, so a mixed rung is rung on its first target", %{ctx: ctx} do
    # A rung is dialled in parallel with a single body — SIP.Dialog.fork_branch/3
    # takes one however many branches — so two branches cannot carry two `c=`
    # lines. This is a property of forking, not a gap: putting targets of
    # different interfaces in different rungs serves each on its own.
    a = marked("mixa", @v4, :public)
    b = marked("mixb", @v6, :public)
    _ = arm!(a)
    _ = arm!(b)

    peer = %Peer{uris: [[a, b]], fork: :parallel, resolved: [[a, b]]}
    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, media_mode())

    assert_receive {:sip_mockup, {:request_sent, :INVITE, _first}}, 5_000

    # The first of them, and the operator was told why.
    assert %Leg{addr_profile: "publicv4"} = B2bua.outbound_leg(ctx)

    B2bua.release_legs(ctx)
  end

  test "an unmarked peer leaves the endpoint alone, as before the marks existed",
       %{ctx: ctx} do
    a = marked("plaina", @v4, nil) |> Map.put(:destip, nil)
    b = marked("plainb", @v4, nil) |> Map.put(:destip, nil)
    _ = arm!(a)
    _ = arm!(b)

    peer = %Peer{uris: [a, b], fork: :serial}
    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, media_mode())

    assert_receive {:sip_mockup, {:request_sent, :INVITE, _first}}, 5_000
    assert %Leg{addr_profile: nil} = B2bua.outbound_leg(ctx)
    kept = endpoint(ctx)

    ctx = relay_final(ctx, 486)

    assert_receive {:sip_mockup, {:request_sent, :INVITE, second}}, 5_000
    assert second.ruri.domain == "plainb.example.com"
    assert %Leg{addr_profile: nil} = B2bua.outbound_leg(ctx)
    assert endpoint(ctx) == kept

    B2bua.release_legs(ctx)
  end
end
