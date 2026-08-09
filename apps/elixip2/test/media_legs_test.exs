defmodule SIP.Test.Media.Legs do
  @moduledoc """
  Leg-scoped media handles (`SIP.Session.Media`, B2BUA P3 R1 — design
  docs/design/b2bua_media_impl_plan.md).

  The mixin used to be single-slot: one peer connection, one action, one call.
  A B2BUA terminates media for BOTH of its SIP legs on one server, so the
  handles became leg-scoped — with the bare appdata keys kept as the `:inbound`
  alias, which is the part that has to keep working: every existing scenario,
  `reply_invite_with_sdp`, the MCU module and three suites read
  `:mediapeerconnectionid` directly.
  """
  use ExUnit.Case

  alias SIP.Session.Media

  setup do
    ctx = Media.use_mediaserver(%SIP.Context{}, MediaServer.Mockup, "sip:localhost:8080")

    on_exit(fn ->
      if is_pid(ctx.mediaserverpid) and Process.alive?(ctx.mediaserverpid) do
        MediaServer.Mockup.disconnect(ctx.mediaserverpid, force: true)
      end
    end)

    %{ctx: ctx}
  end

  describe "one connection per leg" do
    test "each leg gets its own, and the bare key still names the inbound one", %{ctx: ctx} do
      {ctx, offer_in} = Media.get_sdp_offer(ctx, :no, :audio)
      {ctx, offer_out} = Media.get_sdp_offer(ctx, :no, :audio, leg: :outbound)

      inbound = Media.peer_connection(ctx)
      outbound = Media.peer_connection(ctx, :outbound)

      assert is_pid(inbound) and is_pid(outbound)
      assert inbound != outbound

      # The alias, which is what makes this change invisible to everything that
      # was written before legs existed.
      assert SIP.Context.appdata_get(ctx, :mediapeerconnectionid) == inbound
      assert Media.peer_connection(ctx, :inbound) == inbound

      # Two real endpoints, not one handed out twice: distinct media ports.
      assert offer_in != offer_out

      # Creation order, which is the order the teardown releases them in.
      assert Media.media_legs(ctx) == [:inbound, :outbound]
    end

    test "asking twice for the same leg reuses its connection", %{ctx: ctx} do
      {ctx, _} = Media.get_sdp_offer(ctx, :no, :audio, leg: :outbound)
      cnx = Media.peer_connection(ctx, :outbound)

      {ctx, _} = Media.get_sdp_offer(ctx, :no, :audio, leg: :outbound)
      assert Media.peer_connection(ctx, :outbound) == cnx
      assert Media.media_legs(ctx) == [:outbound]
    end

    test "an answer can be negotiated on a named leg", %{ctx: ctx} do
      {ctx, offer} = Media.get_sdp_offer(ctx, :no, :audio)

      assert {ctx, {:ok, answer}} = Media.get_sdp_answer(ctx, offer, leg: :outbound, media: :audio)
      assert answer =~ "m=audio"
      assert Media.peer_connection(ctx, :outbound) != Media.peer_connection(ctx, :inbound)
    end
  end

  describe "one action per leg" do
    test "starting one on a leg leaves the other leg's slot free", %{ctx: ctx} do
      {ctx, _} = Media.get_sdp_offer(ctx, :no, :audio)
      {ctx, _} = Media.get_sdp_offer(ctx, :no, :audio, leg: :outbound)

      ctx = Media.start_echo(ctx, leg: :outbound)

      assert SIP.Context.appdata_get(ctx, {:mediaactionid, :outbound}) != nil
      assert SIP.Context.appdata_get(ctx, {:mediaaction, :outbound}) == :echo

      # The inbound leg is untouched — its slot is the bare key, and it is empty.
      assert SIP.Context.appdata_get(ctx, :mediaactionid) == nil

      # …so it can start one of its own, which single-slot bookkeeping refused.
      ctx = Media.start_echo(ctx)
      assert SIP.Context.appdata_get(ctx, :mediaaction) == :echo
    end

    test "stopping acts on the named leg only", %{ctx: ctx} do
      {ctx, _} = Media.get_sdp_offer(ctx, :no, :audio)
      {ctx, _} = Media.get_sdp_offer(ctx, :no, :audio, leg: :outbound)
      ctx = ctx |> Media.start_echo() |> Media.start_echo(leg: :outbound)

      ctx = Media.stop_media(ctx, leg: :outbound)

      assert SIP.Context.appdata_get(ctx, {:mediaactionid, :outbound}) == nil
      assert SIP.Context.appdata_get(ctx, :mediaactionid) != nil
    end

    test "a leg with no connection refuses an action rather than starting one elsewhere", %{
      ctx: ctx
    } do
      {ctx, _} = Media.get_sdp_offer(ctx, :no, :audio)

      assert_raise RuntimeError, ~r/leg outbound/, fn ->
        Media.start_echo(ctx, leg: :outbound)
      end
    end
  end

  describe "teardown" do
    test "releases every leg, not just the inbound one", %{ctx: ctx} do
      {ctx, _} = Media.get_sdp_offer(ctx, :no, :audio)
      {ctx, _} = Media.get_sdp_offer(ctx, :no, :audio, leg: :outbound)
      ctx = Media.start_echo(ctx, leg: :outbound)

      inbound = Media.peer_connection(ctx)
      outbound = Media.peer_connection(ctx, :outbound)
      server = ctx.mediaserverpid

      ctx = Media.media_cleanup_ressources(ctx)

      # Both connections closed server-side. The outbound one is the whole point:
      # released only because the leg list is walked, and leaked otherwise.
      refute Process.alive?(inbound)
      refute Process.alive?(outbound)
      refute Process.alive?(server)

      # …and the bookkeeping is empty, so a second call is a no-op rather than a
      # second round of calls onto dead handles.
      assert Media.peer_connection(ctx) == nil
      assert Media.peer_connection(ctx, :outbound) == nil
      assert Media.media_legs(ctx) == []
      assert ctx.mediaserverpid == nil

      assert Media.media_cleanup_ressources(ctx) == ctx
    end

    test "a context that only ever used the bare key is still released", %{ctx: ctx} do
      # What every pre-P3 scenario looks like, and what the MCU module builds by
      # hand: a connection under the bare key and no leg list at all.
      {ctx, _} = Media.get_sdp_offer(ctx, :no, :audio)
      ctx = SIP.Context.appdata_set(ctx, :medialegs, nil)
      inbound = Media.peer_connection(ctx)

      ctx = Media.media_cleanup_ressources(ctx)

      refute Process.alive?(inbound)
      assert Media.peer_connection(ctx) == nil
    end
  end
end
