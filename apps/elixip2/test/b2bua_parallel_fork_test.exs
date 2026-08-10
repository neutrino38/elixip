defmodule SIP.Test.B2bua.ParallelFork do
  @moduledoc """
  The parallel hunt (design docs/design/b2bua_module.md §3.2, §3.3, RFC 3261
  §16.6): a `%SIP.B2bua.Peer{fork: :parallel}` reads each entry of `uris` as a
  **rung** — a bare URI rung alone, a nested list rung all at once — and walks
  the rungs in order.

  What the tests pin down is what the serial suite pins down, one rung wider:
  however many devices ring at once, there is still exactly ONE outbound leg, the
  correlation still points the caller at the same request, and the caller sees a
  single final response — the best of the rung, not one per device.

  Each target is a mockup peer of its own, so "both devices rang" is two real
  processes being sent a real INVITE.
  """
  use ExUnit.Case

  alias SIP.B2bua.{Peer, Pending}
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

  # `rungs` is a list of groups of peer names: [["a", "b"], ["c"]].
  defp parallel_peer(rungs, opts \\ []) do
    uris = Enum.map(rungs, fn group -> Enum.map(group, &target/1) end)
    struct(%Peer{uris: uris, fork: :parallel}, opts)
  end

  defp invites_sent(n) do
    for _ <- 1..n, into: %{} do
      assert_receive {:invite_sent, req}, 2_000
      {req.ruri.domain, req}
    end
  end

  # An INVITE retransmits while it goes unanswered (timer A on UDP), so "that
  # device rang" is asserted on the DOMAIN and not on the next notification to
  # turn up — which may well be the previous target saying the same thing again.
  defp assert_invite_to(domain, timeout \\ 2_000) do
    assert_receive {:invite_sent, req}, timeout
    if req.ruri.domain == domain, do: req, else: assert_invite_to(domain, timeout)
  end

  defp refute_invite_to(domain, timeout \\ 400) do
    receive do
      {:invite_sent, %{ruri: %{domain: ^domain}}} -> flunk("#{domain} should not have been rung")
      {:invite_sent, _other} -> refute_invite_to(domain, timeout)
    after
      timeout -> :ok
    end
  end

  # The scenario's `proceeding` clause: take the response the leg surfaced and
  # relay it. Only what the DIALOG chose to surface ever gets here, which is the
  # whole point of the rung.
  defp relay_surfaced(ctx, code, timeout \\ 3_000) do
    dlg = B2bua.outbound_leg(ctx).dialogpid
    assert_receive {:outbound, {^code, resp, tid, ^dlg}}, timeout
    B2bua.note_event({:outbound, {code, resp, tid, dlg}})
    {B2bua.do_relay_reply(ctx, resp), tid}
  end

  test "a rung rings every device of the group, on a single leg", %{ctx: ctx} do
    _a = peer!("par1a")
    _b = peer!("par1b")

    ctx = B2bua.do_create_leg(ctx, inbound_invite(), parallel_peer([["par1a", "par1b"]]), false)
    assert ctx.lasterr == :ok

    invites = invites_sent(2)
    assert Map.keys(invites) |> Enum.sort() == ~w(par1a.example.com par1b.example.com)

    # One leg, two branches, and the caller's request relayed exactly once.
    leg = B2bua.outbound_leg(ctx)
    assert length(leg.branches) == 2
    assert [{tid, %Pending{orig_leg: :inbound, method: :INVITE}}] = B2bua.pending(ctx)
    assert tid == leg.initial_trans
    assert B2bua.hunting?(ctx)
  end

  test "one device refusing says nothing; the rung's best answer moves to the next rung",
       %{ctx: ctx} do
    a = peer!("par2a")
    b = peer!("par2b")
    _c = peer!("par2c")

    peer = parallel_peer([["par2a", "par2b"], ["par2c"]])
    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)
    _ = invites_sent(2)

    # The first device is busy while the second still rings: nothing reaches the
    # scenario, so nothing can be relayed to the caller.
    GenServer.cast(a, {:simulate, 486, 50})
    refute_receive {:outbound, {486, _, _, _}}, 500
    refute_receive {:replied, _, _, _, _}, 100

    # The second falls too. NOW the rung has an answer — the best of the two.
    GenServer.cast(b, {:simulate, 404, 50})
    {ctx, _tid} = relay_surfaced(ctx, 404)

    # …which is not relayed either: it moves the hunt to the next rung.
    assert_invite_to("par2c.example.com")
    refute_receive {:replied, _, _, _, _}, 200

    leg = B2bua.outbound_leg(ctx)
    assert leg.untried == []
    assert [{tid, %Pending{}}] = B2bua.pending(ctx)
    assert tid == leg.initial_trans
    assert B2bua.hunting?(ctx)
  end

  test "the caller is answered once, when the last rung has fallen", %{ctx: ctx} do
    a = peer!("par3a")
    b = peer!("par3b")

    ctx = B2bua.do_create_leg(ctx, inbound_invite(), parallel_peer([["par3a", "par3b"]]), false)
    _ = invites_sent(2)

    GenServer.cast(a, {:simulate, 486, 50})
    GenServer.cast(b, {:simulate, 480, 100})

    # 480 over 486 on the numbers (RFC 3261 §16.7 step 6), and one answer only.
    {ctx, _tid} = relay_surfaced(ctx, 480)
    assert_receive {:replied, 480, _reason, _req, _fields}, 2_000
    refute_receive {:replied, _, _, _, _}, 300

    refute B2bua.hunting?(ctx)
    assert B2bua.pending(ctx) == []
  end

  test "the first 2xx wins the rung and the leg follows the winner", %{ctx: ctx} do
    _a = peer!("par4a")
    b = peer!("par4b")

    peer = parallel_peer([["par4a", "par4b"], ["par4c"]])
    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)
    _ = invites_sent(2)

    first_dialled = B2bua.outbound_leg(ctx).initial_trans

    GenServer.cast(b, {:simulate, 200, 50})
    {ctx, tid} = relay_surfaced(ctx, 200)

    assert_receive {:replied, 200, _reason, _req, _fields}, 2_000

    leg = B2bua.outbound_leg(ctx)

    # The leg now IS the branch that answered — not the first one dialled, which
    # is what everything keyed on "the attempt" used to assume. The ACK of that
    # 2xx and every later in-dialog request go to the winner.
    assert leg.target.domain == "par4b.example.com"
    assert leg.initial_trans == tid
    refute tid == first_dialled
    assert leg.branches == [{tid, leg.target}]

    # And the rung that was left is dropped: someone answered.
    assert leg.untried == []
    refute B2bua.hunting?(ctx)
    refute_invite_to("par4c.example.com")
  end

  test "a 6xx from one device stops the hunt, rungs left or not", %{ctx: ctx} do
    a = peer!("par5a")
    _b = peer!("par5b")
    _c = peer!("par5c")

    peer = parallel_peer([["par5a", "par5b"], ["par5c"]])
    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)
    _ = invites_sent(2)

    # A global refusal is the user's answer, not one device's: it does not wait
    # for the sibling and it does not try the next rung.
    GenServer.cast(a, {:simulate, 603, 50})
    {ctx, _tid} = relay_surfaced(ctx, 603)

    assert_receive {:replied, 603, _reason, _req, _fields}, 2_000
    refute_invite_to("par5c.example.com")
    refute B2bua.hunting?(ctx)
  end
end
