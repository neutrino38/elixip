defmodule Kelix.ConversationsTest do
  # One scenario per conversation, not per MESSAGE (chat-basic-plan, C3b, C3c):
  # Router.dispatch → Kelix.Conversations.key → InstancePool lookup-or-spawn.
  # The dialog layer is not in the loop: what it would do with `{:accept, pid}`
  # — send the MESSAGE there — the test does itself.
  use ExUnit.Case, async: false

  alias Kelix.{Router, InstancePool, Domains, Conversations, DialRule}

  @chatter Path.join(__DIR__, "support/scripts/chatter.exs")

  setup do
    Process.register(self(), :kelix_conversations_test)
    dom = "conv#{System.unique_integer([:positive])}.test"
    %{dom: dom}
  end

  defp snapshot(dom, rules) do
    toml =
      Enum.map_join(rules, "\n", fn rule ->
        "[[domain.chat]]\n" <>
          Enum.map_join(rule, "\n", fn
            {k, v} when is_binary(v) -> ~s(#{k} = "#{v}")
            {k, v} -> "#{k} = #{v}"
          end)
      end)

    {:ok, snap} = Domains.parse(~s([[domain]]\nname = "#{dom}"\n) <> toml)
    snap
  end

  # A MESSAGE as the transport layer hands it over: the flow it came in on is
  # stamped on its Request-URI. UDP from 192.0.2.1:`port` unless `opts` say
  # otherwise (`transport:` a module, `tp_pid:` its connection).
  defp message(from, to, dom, opts \\ []) do
    %{
      method: :MESSAGE,
      ruri: %SIP.Uri{
        userpart: to,
        domain: dom,
        destip: Keyword.get(opts, :ip, {192, 0, 2, 1}),
        destport: Keyword.get(opts, :port, 5060),
        tp_module: Keyword.get(opts, :transport, SIP.Transport.UDP),
        tp_pid: Keyword.get(opts, :tp_pid)
      },
      from: %SIP.Uri{userpart: from, domain: dom},
      to: %SIP.Uri{userpart: to, domain: dom},
      callid: "c#{System.unique_integer([:positive])}"
    }
  end

  # dispatch, then deliver as the dialog layer would
  defp deliver(snap, req) do
    assert {:accept, pid} = Router.dispatch(self(), req, snap)
    send(pid, {:MESSAGE, req, self(), self()})
    assert_receive {:chatter, ^pid, callid}, 1_000
    assert callid == req.callid
    pid
  end

  defp cleanup(pids),
    do: on_exit(fn -> Enum.each(pids, &send(&1, {:scenario_ctl, :shutdown, :test_cleanup})) end)

  defp active(dom), do: Map.get(InstancePool.stats().per_domain, dom, 0)

  # a connected transport instance, as far as the pool can tell
  defp connection(), do: spawn(fn -> receive do: (:drop -> :ok) end)

  describe "the key" do
    @rule %DialRule{default?: true, idle_timeout: 300}

    test "From, To and the flow; the direction matters" do
      a = message("alice", "bob", "d.test")

      assert {"d.test", :default, "alice@d.test", "bob@d.test", {"UDP", {192, 0, 2, 1}, 5060}} =
               Conversations.key("d.test", @rule, a)

      refute Conversations.key("d.test", @rule, a) ==
               Conversations.key("d.test", @rule, message("bob", "alice", "d.test"))
    end

    test "another port or another transport is another flow" do
      k = &Conversations.key("d.test", @rule, &1)
      a = message("alice", "bob", "d.test")

      refute k.(a) == k.(message("alice", "bob", "d.test", port: 5070))
      refute k.(a) == k.(message("alice", "bob", "d.test", transport: SIP.Transport.TCP))
    end

    test "tags, display names and host case are not part of it" do
      a = message("alice", "bob", "d.test")
      b = %{a | from: ~s("Alice" <sip:alice@D.TEST>;tag=zz), callid: "other"}
      assert Conversations.key("d.test", @rule, a) == Conversations.key("d.test", @rule, b)
    end

    test "no key: a call rule, a request with no flow, a From with no user" do
      a = message("alice", "bob", "d.test")
      assert Conversations.key("d.test", %DialRule{raw: "X."}, a) == nil
      assert Conversations.key("d.test", @rule, %{a | ruri: %SIP.Uri{userpart: "bob"}}) == nil
      assert Conversations.key("d.test", @rule, %{a | from: "<sip:d.test>"}) == nil
    end
  end

  describe "dispatch" do
    test "three MESSAGEs from Alice to the bot on one flow reach one instance, one slot",
         %{dom: dom} do
      snap = snapshot(dom, [[pattern: "mybot", script: @chatter]])

      pid = deliver(snap, message("alice", "mybot", dom))
      cleanup([pid])
      assert deliver(snap, message("alice", "mybot", dom)) == pid
      assert deliver(snap, message("alice", "mybot", dom)) == pid
      assert active(dom) == 1

      assert %{messages: 3, function: :chat} = Enum.find(InstancePool.list(), &(&1.pid == pid))

      # another user is another conversation
      other = deliver(snap, message("carol", "mybot", dom))
      cleanup([other])
      refute other == pid
    end

    # What makes routing stand for trust: the same From on another flow is not
    # handed to the conversation that authenticated it — it starts one of its own.
    test "the same From and To over another flow start another conversation", %{dom: dom} do
      snap = snapshot(dom, [[default: true, script: @chatter]])

      pid = deliver(snap, message("alice", "bob", dom))
      cleanup([pid])

      forged = deliver(snap, message("alice", "bob", dom, ip: {203, 0, 113, 9}))
      cleanup([forged])
      refute forged == pid
    end

    test "MESSAGEs of one conversation dispatched together start one instance", %{dom: dom} do
      snap = snapshot(dom, [[default: true, script: @chatter]])

      pids =
        1..8
        |> Enum.map(fn _ ->
          Task.async(fn -> Router.dispatch(self(), message("alice", "bob", dom), snap) end)
        end)
        |> Enum.map(&Task.await/1)
        |> Enum.map(fn {:accept, pid} -> pid end)
        |> Enum.uniq()

      cleanup(pids)
      assert length(pids) == 1
      assert active(dom) == 1
    end

    test "a conversation silent for idle_timeout ends and frees its slot", %{dom: dom} do
      snap = snapshot(dom, [[default: true, script: @chatter, idle_timeout: 1]])

      pid = deliver(snap, message("alice", "bob", dom))
      ref = Process.monitor(pid)
      assert active(dom) == 1

      assert_receive {:DOWN, ^ref, :process, ^pid, _}, 2_500
      assert eventually(fn -> active(dom) == 0 end)

      # the next MESSAGE starts over
      fresh = deliver(snap, message("alice", "bob", dom))
      cleanup([fresh])
      refute fresh == pid
    end

    test "a page sent out is activity too", %{dom: dom} do
      snap = snapshot(dom, [[default: true, script: @chatter, idle_timeout: 1]])

      pid = deliver(snap, message("alice", "bob", dom))
      cleanup([pid])

      # what `send_page` tells the pool, every 400 ms for 1.6 s
      for _ <- 1..4 do
        send(Process.whereis(InstancePool), {:conversation, :activity, pid})
        Process.sleep(400)
      end

      assert Process.alive?(pid)
      assert deliver(snap, message("alice", "bob", dom)) == pid
    end

    test "a connected transport dropping ends the conversation; the next flow starts over",
         %{dom: dom} do
      snap = snapshot(dom, [[default: true, script: @chatter]])
      ws = connection()
      wss = [transport: SIP.Transport.WSS, tp_pid: ws, port: 40_001]

      pid = deliver(snap, message("alice", "bob", dom, wss))
      assert deliver(snap, message("alice", "bob", dom, wss)) == pid
      ref = Process.monitor(pid)

      # chatter.exs has no clause for it: the SIP host's injected one ends it
      send(ws, :drop)
      assert_receive {:DOWN, ^ref, :process, ^pid, _}, 1_000
      assert eventually(fn -> active(dom) == 0 end)

      ws2 = connection()

      fresh =
        deliver(
          snap,
          message("alice", "bob", dom, transport: SIP.Transport.WSS, tp_pid: ws2, port: 40_002)
        )

      cleanup([fresh])
      refute fresh == pid
    end

    test "a UDP conversation watches no connection", %{dom: dom} do
      snap = snapshot(dom, [[default: true, script: @chatter]])
      pid = deliver(snap, message("alice", "bob", dom, tp_pid: connection()))
      cleanup([pid])

      inst =
        :sys.get_state(InstancePool).instances |> Map.values() |> Enum.find(&(&1.pid == pid))

      assert inst.connection_mon == nil
    end
  end

  describe "[[domain.chat]] keys" do
    test "idle_timeout is parsed, 300 by default", %{dom: dom} do
      snap =
        snapshot(dom, [
          [pattern: "mybot", script: "b.exs", idle_timeout: 60],
          [default: true, script: "p.exs"]
        ])

      [domain] = snap.domains
      assert [%DialRule{idle_timeout: 60}, %DialRule{idle_timeout: 300}] = domain.chat
    end

    test "a bad value is refused at load, a call rule takes none", %{dom: dom} do
      assert {:error, msg} =
               Domains.parse(
                 ~s([[domain]]\nname = "#{dom}"\n[[domain.chat]]\ndefault = true\n) <>
                   ~s(script = "p.exs"\nidle_timeout = 0)
               )

      assert msg =~ "idle_timeout"

      assert {:error, msg} =
               Domains.parse(
                 ~s([[domain]]\nname = "#{dom}"\n[[domain.call]]\ndefault = true\n) <>
                   ~s(script = "c.exs"\nidle_timeout = 60)
               )

      assert msg =~ "unknown key"
    end
  end

  defp eventually(fun, tries \\ 40) do
    cond do
      fun.() -> true
      tries == 0 -> false
      true -> Process.sleep(50) && eventually(fun, tries - 1)
    end
  end
end
