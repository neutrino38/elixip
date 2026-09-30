defmodule Kelix.Mod.ConversationMemoryStoreTest do
  @moduledoc "The conversation store contract on the in-memory store the rest of the suite runs on."
  use ExUnit.Case, async: true
  use Kelix.Test.ConversationStoreContract

  setup do
    {:ok, pid} = Kelix.Test.ConversationMemoryStore.start_link()
    %{store: Kelix.Test.ConversationMemoryStore, handle: pid}
  end
end

for {engine, config} <- Kelix.Test.SQL.engines() do
  defmodule Module.concat(Kelix.Mod.ConversationSQLStoreTest, Macro.camelize(to_string(engine))) do
    @moduledoc """
    The conversation store contract on #{engine}
    (KELIX_TEST_#{String.upcase(to_string(engine))}), and what only a shared
    store gives: a conversation outliving the module that set it aside.
    """
    use ExUnit.Case, async: false

    alias Kelix.Mod.Conversation

    @config config
    @conn Module.concat(__MODULE__, Conn)
    @tables ~w(conversation conversation_version)

    if @config == nil,
      do: @moduletag(skip: "KELIX_TEST_#{String.upcase(to_string(engine))} not set")

    use Kelix.Test.ConversationStoreContract

    setup_all do
      if @config,
        do: %{handle: Kelix.Test.SQL.start!(@config, @conn, "conversation", @tables)},
        else: :ok
    end

    setup context do
      if h = context[:handle], do: Kelix.Test.SQL.wipe!(h, ~w(conversation))
      %{store: Kelix.Mod.Conversation.Store.SQL}
    end

    defp start_module(h) do
      opts = [
        store: Kelix.Mod.Conversation.Store.SQL,
        handle: h,
        default_ttl: 300,
        max_ttl: 3_600
      ]

      start_supervised!(%{id: Conversation, start: {Conversation, :start_link, [opts]}})
    end

    test "a conversation hibernated before a restart wakes after it", %{handle: h} do
      start_module(h)
      snapshot = %{script: "bot.exs", resume: :awaiting_answer, data: %{step: 2}}
      assert {:ok, 300} = Conversation.hibernate(@key, snapshot)

      stop_supervised!(Conversation)
      start_module(h)

      assert {:ok, %{resume: :awaiting_answer, data: %{step: 2}, ttl: 300}} =
               Conversation.wake(@key)

      assert Conversation.wake(@key) == :none
    end

    test "two nodes woken at once: one of them gets it", %{handle: h, store: store} do
      :ok = store.put(h, @key, entry())

      results =
        1..4
        |> Enum.map(fn _ -> Task.async(fn -> store.take(h, @key, @now) end) end)
        |> Task.await_many(10_000)

      assert Enum.count(results, &match?({:ok, _}, &1)) == 1
      assert Enum.count(results, &(&1 == :none)) == 3
    end

    test "missing tables stop the module", %{handle: h} do
      mod = Kelix.DB.Pool.driver_module(h.driver)
      rename = fn from, to -> mod.query!(h.conn, "ALTER TABLE #{from} RENAME TO #{to}", []) end
      rename.("conversation_version", "conversation_version_x")

      try do
        Process.flag(:trap_exit, true)
        opts = [store: Kelix.Mod.Conversation.Store.SQL, handle: h]
        assert {:error, {:schema, :missing}} = Conversation.start_link(opts)
      after
        rename.("conversation_version_x", "conversation_version")
      end
    end
  end
end
