defmodule Kelix.ConversationsTest do
  # One scenario per conversation, not per MESSAGE (chat-basic-plan, C3b):
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

  defp message(from, to, dom, callid \\ nil) do
    %{
      method: :MESSAGE,
      ruri: %SIP.Uri{userpart: to, domain: dom},
      from: %SIP.Uri{userpart: from, domain: dom},
      to: %SIP.Uri{userpart: to, domain: dom},
      callid: callid || "c#{System.unique_integer([:positive])}"
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

  describe "the key" do
    test "pair is ordered, peers is not, to is the To alone" do
      alice_bob = message("alice", "bob", "d.test")
      bob_alice = message("bob", "alice", "d.test")
      carol_bob = message("carol", "bob", "d.test")

      pair = %DialRule{raw: "b.", conversation: :pair}
      peers = %DialRule{default?: true, conversation: :peers}
      room = %DialRule{raw: "room-.", conversation: :to}

      refute Conversations.key("d.test", pair, alice_bob) ==
               Conversations.key("d.test", pair, bob_alice)

      assert Conversations.key("d.test", peers, alice_bob) ==
               Conversations.key("d.test", peers, bob_alice)

      assert Conversations.key("d.test", room, alice_bob) ==
               Conversations.key("d.test", room, carol_bob)

      # a call rule declares no conversation
      assert Conversations.key("d.test", %DialRule{raw: "X."}, alice_bob) == nil
      # no From user: no key, an instance of its own
      assert Conversations.key("d.test", peers, %{alice_bob | from: "<sip:d.test>"}) == nil
    end

    test "the source is not part of it: tags, display names and host case are not" do
      a = message("alice", "bob", "d.test")
      b = %{a | from: ~s("Alice" <sip:alice@D.TEST>;tag=zz), callid: "other"}
      rule = %DialRule{default?: true, conversation: :peers}
      assert Conversations.key("d.test", rule, a) == Conversations.key("d.test", rule, b)
    end
  end

  describe "dispatch" do
    test "three MESSAGEs from Alice to the bot reach one instance, one slot", %{dom: dom} do
      snap = snapshot(dom, [[pattern: "mybot", script: @chatter, conversation: "pair"]])

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

    test "Bob's answer reaches the instance Alice's message started (peers)", %{dom: dom} do
      snap = snapshot(dom, [[default: true, script: @chatter]])

      pid = deliver(snap, message("alice", "bob", dom))
      cleanup([pid])
      assert deliver(snap, message("bob", "alice", dom)) == pid
    end

    test "every member of a room reaches the room's instance (to)", %{dom: dom} do
      snap = snapshot(dom, [[pattern: "room-.", script: @chatter, conversation: "to"]])

      pid = deliver(snap, message("alice", "room-1", dom))
      cleanup([pid])
      assert deliver(snap, message("bob", "room-1", dom)) == pid

      other_room = deliver(snap, message("bob", "room-2", dom))
      cleanup([other_room])
      refute other_room == pid
    end

    test "two MESSAGEs of one conversation dispatched together start one instance",
         %{dom: dom} do
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
      assert deliver(snap, message("bob", "alice", dom)) == pid
    end
  end

  describe "[[domain.chat]] keys" do
    test "conversation and idle_timeout are parsed, with their defaults", %{dom: dom} do
      snap =
        snapshot(dom, [
          [pattern: "mybot", script: "b.exs", conversation: "pair", idle_timeout: 60],
          [default: true, script: "p.exs"]
        ])

      [domain] = snap.domains

      assert [%DialRule{conversation: :pair, idle_timeout: 60}, %DialRule{} = default] =
               domain.chat

      assert default.conversation == :peers
      assert default.idle_timeout == 300
    end

    test "a bad value is refused at load, a call rule takes neither", %{dom: dom} do
      assert {:error, msg} =
               Domains.parse(
                 ~s([[domain]]\nname = "#{dom}"\n[[domain.chat]]\ndefault = true\n) <>
                   ~s(script = "p.exs"\nconversation = "room")
               )

      assert msg =~ "conversation"

      assert {:error, _} =
               Domains.parse(
                 ~s([[domain]]\nname = "#{dom}"\n[[domain.chat]]\ndefault = true\n) <>
                   ~s(script = "p.exs"\nidle_timeout = 0)
               )

      assert {:error, msg} =
               Domains.parse(
                 ~s([[domain]]\nname = "#{dom}"\n[[domain.call]]\ndefault = true\n) <>
                   ~s(script = "c.exs"\nconversation = "pair")
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
