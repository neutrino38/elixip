defmodule Kelix.Mod.ConversationTest do
  # Hibernated chat conversations (chat-basic-plan, C3d): the `conversation`
  # module on its own, then with the core — Router.dispatch → InstancePool →
  # a script that hibernates, and a MESSAGE that wakes it. Here because it is
  # the one app where both halves are present.
  use ExUnit.Case, async: false

  alias Kelix.Mod.Conversation
  alias Kelix.{Router, Domains, InstancePool}

  @bot Path.join(__DIR__, "support/scripts/hibernating_bot.exs")

  setup do
    Process.register(self(), :kelix_conversation_test)
    start_supervised!({Conversation, [default_ttl: 300, max_ttl: 3_600]})
    :ok = Kelix.ModuleRegistry.register("conversation", Conversation, %{})
    on_exit(fn -> Kelix.ModuleRegistry.unregister("conversation") end)
    :ok
  end

  @key {"d.test", :default, "alice@d.test", "bot@d.test"}

  describe "the module" do
    test "keeps a snapshot, and gives it back once" do
      assert {:ok, 60} =
               Conversation.hibernate(@key, %{script: "b.exs", resume: :x, data: %{a: 1}, ttl: 60})

      assert {:ok, %{script: "b.exs", resume: :x, data: %{a: 1}, ttl: 60}} =
               Conversation.wake(@key)

      assert Conversation.wake(@key) == :none
    end

    test "the TTL is the script's, else the default, bounded by max_ttl" do
      snap = %{script: "b.exs", resume: :x, data: %{}}
      assert {:ok, 300} = Conversation.hibernate(@key, snap)
      assert {:ok, 3_600} = Conversation.hibernate(@key, Map.put(snap, :ttl, 999_999))
    end

    test "list shows the parties and the state, never the data" do
      {:ok, _} =
        Conversation.hibernate(@key, %{script: "b.exs", resume: :x, data: %{secret: "hi"}})

      assert [row] = Conversation.list()
      assert %{from: "alice@d.test", to: "bot@d.test", resume: :x, script: "b.exs"} = row
      refute Map.has_key?(row, :data)
      refute inspect(row) =~ "hi\""
    end

    test "an expired conversation neither wakes nor survives the sweep" do
      stop_supervised!(Conversation)
      start_supervised!({Conversation, [default_ttl: 1, max_ttl: 1, sweep_ms: 200]})

      {:ok, 1} = Conversation.hibernate(@key, %{script: "b.exs", resume: :x, data: %{}})
      other = put_elem(@key, 2, "carol@d.test")
      {:ok, 1} = Conversation.hibernate(other, %{script: "b.exs", resume: :x, data: %{}})

      Process.sleep(2_100)
      assert Conversation.wake(@key) == :none
      assert Conversation.list() == []
    end

    test "validate_config" do
      assert Conversation.validate_config(%{"default_ttl" => 60, "max_ttl" => 600}) == :ok
      assert {:error, _} = Conversation.validate_config(%{"default_ttl" => 0})
      assert {:error, _} = Conversation.validate_config(%{"default_ttl" => 700, "max_ttl" => 600})
      assert {:error, _} = Conversation.validate_config(%{"ttl" => 60})
    end
  end

  describe "with the core" do
    setup do
      dom = "hib#{System.unique_integer([:positive])}.test"

      {:ok, snap} =
        Domains.parse(
          ~s([[domain]]\nname = "#{dom}"\n[[domain.chat]]\ndefault = true\nscript = "#{@bot}")
        )

      %{dom: dom, snap: snap}
    end

    test "a bot hibernates; the next MESSAGE, over another flow, wakes it where it stopped",
         %{dom: dom, snap: snap} do
      pid = deliver(snap, message(dom, "hibernate now", port: 5060))
      assert_down(pid, :normal)
      assert active(dom) == 0
      assert [%{resume: :awaiting_answer}] = Enum.filter(Conversation.list(), &(&1.domain == dom))

      woken = deliver(snap, message(dom, "the answer", port: 6000))
      assert_receive {:woken, ^woken, 2}, 1_000
      refute woken == pid
      assert Enum.filter(Conversation.list(), &(&1.domain == dom)) == []
    end

    test "a connection dropping is where a long-lived bot hibernates", %{dom: dom, snap: snap} do
      ws = spawn(fn -> receive do: (:drop -> :ok) end)

      pid =
        deliver(
          snap,
          message(dom, "hello", transport: SIP.Transport.WSS, tp_pid: ws, port: 40_100)
        )

      send(ws, :drop)
      assert_down(pid, :normal)

      woken = deliver(snap, message(dom, "back", port: 5060))
      assert_receive {:woken, ^woken, 2}, 1_000
    end

    test "hibernate refuses what would not wake: a pid in keep", %{dom: dom, snap: snap} do
      pid = deliver(snap, message(dom, "keep a pid", port: 5060))
      assert_down(pid, :normal)
      assert Enum.filter(Conversation.list(), &(&1.domain == dom)) == []
    end

    test "without the conversation module, hibernate fails and nothing wakes",
         %{dom: dom, snap: snap} do
      Kelix.ModuleRegistry.unregister("conversation")
      pid = deliver(snap, message(dom, "hibernate now", port: 5060))
      assert_down(pid, :normal)

      fresh = deliver(snap, message(dom, "the answer", port: 6000))
      on_exit(fn -> send(fresh, {:scenario_ctl, :shutdown, :test_cleanup}) end)
      refute_receive {:woken, _, _}, 300
    end
  end

  # ── helpers ─────────────────────────────────────────────────────────────────

  defp message(dom, body, opts) do
    %{
      method: :MESSAGE,
      ruri: %SIP.Uri{
        userpart: "bot",
        domain: dom,
        destip: {192, 0, 2, 1},
        destport: Keyword.fetch!(opts, :port),
        tp_module: Keyword.get(opts, :transport, SIP.Transport.UDP),
        tp_pid: Keyword.get(opts, :tp_pid)
      },
      from: %SIP.Uri{userpart: "alice", domain: dom},
      to: %SIP.Uri{userpart: "bot", domain: dom},
      callid: "c#{System.unique_integer([:positive])}",
      contenttype: "text/plain",
      body: body
    }
  end

  # dispatch, then deliver as the dialog layer would
  defp deliver(snap, req) do
    assert {:accept, pid} = Router.dispatch(self(), req, snap)
    send(pid, {:MESSAGE, req, self(), self()})
    pid
  end

  defp assert_down(pid, _reason) do
    ref = Process.monitor(pid)
    assert_receive {:DOWN, ^ref, :process, ^pid, _}, 2_000
  end

  defp active(dom) do
    Enum.reduce_while(1..40, nil, fn _, _ ->
      n = Map.get(InstancePool.stats().per_domain, dom, 0)
      if n == 0, do: {:halt, 0}, else: Process.sleep(50) && {:cont, n}
    end)
  end
end
