defmodule SIP.Test.B2bua.FakeQueue do
  @moduledoc """
  A `SIP.B2bua.TargetProvider` standing in for a call queue: it hands out the
  answers a test scripts, and records every `attempt_ended/3` so the test can
  assert the reservation was released.
  """
  use GenServer
  @behaviour SIP.B2bua.TargetProvider

  def start_link(answers), do: GenServer.start_link(__MODULE__, answers)

  @doc "What was reported back, oldest first."
  def outcomes(pid), do: GenServer.call(pid, :outcomes)

  @doc "The call references the provider was asked about."
  def calls(pid), do: GenServer.call(pid, :calls)

  @impl SIP.B2bua.TargetProvider
  def next_target(server, call, req), do: GenServer.call(server, {:next, call, req})

  @impl SIP.B2bua.TargetProvider
  def attempt_ended(server, call, outcome), do: GenServer.cast(server, {:ended, call, outcome})

  @impl GenServer
  def init(answers), do: {:ok, %{answers: answers, outcomes: [], calls: []}}

  @impl GenServer
  def handle_call({:next, call, _req}, _from, state) do
    {answer, rest} =
      case state.answers do
        [a | r] -> {a, r}
        [] -> {:exhausted, []}
      end

    {:reply, answer, %{state | answers: rest, calls: [call | state.calls]}}
  end

  def handle_call(:outcomes, _from, state), do: {:reply, Enum.reverse(state.outcomes), state}
  def handle_call(:calls, _from, state), do: {:reply, Enum.reverse(state.calls), state}

  @impl GenServer
  def handle_cast({:ended, _call, outcome}, state),
    do: {:noreply, %{state | outcomes: [outcome | state.outcomes]}}
end

defmodule SIP.Test.B2bua.Provider do
  @moduledoc """
  Targets handed out by a provider rather than listed up front
  (`SIP.B2bua.TargetProvider`, design §3.4) — the call-queue case.

  What the tests pin down is the half a first sketch of the protocol
  (`get_next_target/1 -> {:ok, uri} | :no_more_targets`) has no room for: a
  caller who waits because nobody is free, and a reservation released whatever
  happens to the call.
  """
  use ExUnit.Case

  alias SIP.B2bua.{Hunt, Leg, Peer}
  alias SIP.Session.B2bua
  alias SIP.Test.B2bua.FakeQueue

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
    %SIP.Uri{scheme: "sip:", userpart: "agent", domain: "#{name}.example.com", port: 5060}
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

  defp queue_peer(answers, opts \\ []) do
    {:ok, q} = FakeQueue.start_link(answers)
    on_exit(fn -> if Process.alive?(q), do: GenServer.stop(q) end)
    peer = struct(%Peer{provider: {FakeQueue, q}, fork: :serial}, opts)
    {peer, q}
  end

  defp relay_final(ctx, code) do
    tid = B2bua.outbound_leg(ctx).initial_trans
    B2bua.note_event({:outbound, {code, %{response: code}, tid, self()}})
    B2bua.do_relay_reply(ctx, %{method: false, response: code, reason: nil, body: []})
  end

  test "the provider names the target, and the leg is built from it", %{ctx: ctx} do
    _a = peer!("prv1a")
    {peer, q} = queue_peer([{:ok, target("prv1a")}])

    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)

    assert ctx.lasterr == :ok
    assert_receive {:invite_sent, fwd}, 2_000
    assert fwd.ruri.domain == "prv1a.example.com"
    assert %Leg{} = B2bua.outbound_leg(ctx)

    # It was asked about a call reference, which is what a reservation is held
    # against — and the same one throughout.
    assert [call] = FakeQueue.calls(q)
    assert is_reference(call)
  end

  # THE difference between a queue and a list of fallbacks: nobody free is not
  # "give up", it is "the caller waits". Nothing is dialled, and nothing is
  # answered to the caller either.
  test "{:wait, ms} queues the caller instead of refusing the call", %{ctx: ctx} do
    _a = peer!("prv2a")
    {peer, _q} = queue_peer([{:wait, 5_000}, {:ok, target("prv2a")}])

    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)

    assert ctx.lasterr == :ok
    assert B2bua.outbound_leg(ctx) == nil
    refute_receive {:invite_sent, _}, 300
    refute_receive {:replied, _, _, _, _}, 200

    # …and the search is very much on, though nothing is ringing.
    assert B2bua.hunting?(ctx)
    assert %Hunt{waiting: true} = B2bua.hunt(ctx)

    # An agent frees up: the same call, now dialled.
    ctx = B2bua.do_try_next(ctx)
    assert_receive {:invite_sent, fwd}, 2_000
    assert fwd.ruri.domain == "prv2a.example.com"
    refute match?(%Hunt{waiting: true}, B2bua.hunt(ctx))
  end

  test "a refusal asks the provider for another target, on the same leg", %{ctx: ctx} do
    _a = peer!("prv3a")
    _b = peer!("prv3b")
    {peer, q} = queue_peer([{:ok, target("prv3a")}, {:ok, target("prv3b")}])

    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)
    assert_receive {:invite_sent, first}, 2_000
    leg_before = B2bua.outbound_leg(ctx)

    ctx = relay_final(ctx, 486)

    assert_receive {:invite_sent, second}, 2_000
    assert first.ruri.domain == "prv3a.example.com"
    assert second.ruri.domain == "prv3b.example.com"
    refute_receive {:replied, 486, _, _, _}, 200

    # One leg throughout, and the correlation moved with the search.
    leg_after = B2bua.outbound_leg(ctx)
    assert leg_after.dialogpid == leg_before.dialogpid
    refute leg_after.initial_trans == leg_before.initial_trans
    assert [{tid, _}] = B2bua.pending(ctx)
    assert tid == leg_after.initial_trans

    # And the provider was told why, so it can put that agent back in rotation.
    assert [{:rejected, rejected, 486}] = FakeQueue.outcomes(q)
    assert rejected.domain == "prv3a.example.com"
  end

  test "when the provider is exhausted the caller finally gets the refusal", %{ctx: ctx} do
    _a = peer!("prv4a")
    {peer, _q} = queue_peer([{:ok, target("prv4a")}])

    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)
    assert_receive {:invite_sent, _first}, 2_000

    ctx = relay_final(ctx, 480)

    assert_receive {:replied, 480, _reason, _req, _fields}, 2_000
    refute B2bua.hunting?(ctx)
  end

  test "b2bua_try_next/0 abandons the ringing target and reports it as no-answer",
       %{ctx: ctx} do
    _a = peer!("prv5a")
    _b = peer!("prv5b")
    {peer, q} = queue_peer([{:ok, target("prv5a")}, {:ok, target("prv5b")}])

    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)
    assert_receive {:invite_sent, _first}, 2_000

    # A ring timeout fires: this agent has had long enough.
    ctx = B2bua.do_try_next(ctx)

    assert_receive {:invite_sent, second}, 2_000
    assert second.ruri.domain == "prv5b.example.com"
    assert [{:no_answer, rung}] = FakeQueue.outcomes(q)
    assert rung.domain == "prv5a.example.com"
    _ = ctx
  end

  test "the ring timeout the provider asked for is readable by the scenario", %{ctx: ctx} do
    _a = peer!("prv6a")
    {peer, _q} = queue_peer([{:ok, target("prv6a"), [ring_timeout: 15_000]}])

    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)
    assert B2bua.ring_timeout(ctx) == 15_000
  end

  describe "the reservation is always released" do
    test "when the caller gives up while queued", %{ctx: ctx} do
      {peer, q} = queue_peer([{:wait, 5_000}])

      ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)
      assert B2bua.hunting?(ctx)

      ctx = B2bua.do_cancel_forward(ctx)

      assert FakeQueue.outcomes(q) == [:abandoned]
      refute B2bua.hunting?(ctx)
      assert B2bua.hunt(ctx) == nil
    end

    test "when the scenario is torn down mid-ring", %{ctx: ctx} do
      _a = peer!("prv7a")
      {peer, q} = queue_peer([{:ok, target("prv7a")}])

      ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)
      assert_receive {:invite_sent, _}, 2_000

      ctx = B2bua.release_legs(ctx)

      assert FakeQueue.outcomes(q) == [:abandoned]
      assert_receive {:replied, 487, "Request Terminated", _req, _}, 2_000
      assert B2bua.outbound_leg(ctx) == nil
    end
  end

  # A queue is shared: its trouble must not become this call's.
  test "a provider that raises ends the search without killing the call", %{ctx: ctx} do
    defmodule Exploding do
      @behaviour SIP.B2bua.TargetProvider
      def next_target(_s, _c, _r), do: raise("boom")
      def attempt_ended(_s, _c, _o), do: :ok
    end

    peer = %Peer{provider: {Exploding, self()}, fork: :serial}
    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)

    assert ctx.lasterr == :ok
    assert B2bua.outbound_leg(ctx) == nil
    refute B2bua.hunting?(ctx)
  end

  test "asking for a next target with no provider is refused, not silent", %{ctx: ctx} do
    ctx = B2bua.do_try_next(ctx)
    assert {:b2bua, :no_provider_to_ask} = ctx.lasterr
  end

  test "progress events cover the waiting state too", %{ctx: ctx} do
    _a = peer!("prv8a")
    {peer, _q} = queue_peer([{:wait, 3_000}, {:ok, target("prv8a")}], notify_progress: true)

    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)
    assert_receive {:outbound, {:serial_waiting, 3_000, at}}, 2_000
    assert %DateTime{} = at

    ctx = B2bua.do_try_next(ctx)
    assert_receive {:outbound, {:serial_attempting, uri, _at}}, 2_000
    assert uri.domain == "prv8a.example.com"
  end
end
