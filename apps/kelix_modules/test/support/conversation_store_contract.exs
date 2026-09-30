defmodule Kelix.Test.ConversationStoreContract do
  @moduledoc """
  What every `Kelix.Mod.Conversation.Store` must do: `use` it in a case whose
  setup returns `%{store: module, handle: handle}` on an empty store.
  """

  defmacro __using__(_opts) do
    quote do
      @now 1_900_000_000
      @key {"d.test", :default, "alice@d.test", "bot@d.test"}

      defp entry(overrides \\ %{}) do
        Map.merge(
          %{
            script: "/etc/kelixip/scripts/bot.exs",
            resume: :awaiting_answer,
            data: %{step: 3, cart: [{"sku-1", 2}], note: "é", flag: true},
            ttl: 600,
            expires_at: @now + 600
          },
          overrides
        )
      end

      test "the schema is there", %{store: store, handle: h} do
        assert store.check_schema(h) == :ok
      end

      test "what is put is taken back whole, once", %{store: store, handle: h} do
        assert :ok = store.put(h, @key, entry())
        assert {:ok, e} = store.take(h, @key, @now)
        assert e == entry()
        assert store.take(h, @key, @now) == :none
      end

      test "a rule name and the default rule are two keys", %{store: store, handle: h} do
        named = put_elem(@key, 1, "support")
        :ok = store.put(h, @key, entry(%{resume: :a}))
        :ok = store.put(h, named, entry(%{resume: :b}))

        assert {:ok, %{resume: :b}} = store.take(h, named, @now)
        assert {:ok, %{resume: :a}} = store.take(h, @key, @now)
      end

      test "a second put under the key replaces the first", %{store: store, handle: h} do
        :ok = store.put(h, @key, entry(%{resume: :first}))
        :ok = store.put(h, @key, entry(%{resume: :second}))
        assert {:ok, %{resume: :second}} = store.take(h, @key, @now)
        assert store.take(h, @key, @now) == :none
      end

      test "an expired entry is not taken, not listed, and swept", %{store: store, handle: h} do
        other = put_elem(@key, 2, "carol@d.test")
        :ok = store.put(h, @key, entry(%{expires_at: @now}))
        :ok = store.put(h, other, entry())

        assert store.take(h, @key, @now) == :none
        assert {:ok, [row]} = store.list(h, @now)
        assert row.from == "carol@d.test"

        assert {:ok, 1} = store.sweep(h, @now + 600)
        assert {:ok, []} = store.list(h, @now)
      end

      test "list names the parties and the state, never the data", %{store: store, handle: h} do
        :ok = store.put(h, @key, entry())
        assert {:ok, [row]} = store.list(h, @now)

        assert %{
                 domain: "d.test",
                 rule: :default,
                 from: "alice@d.test",
                 to: "bot@d.test",
                 script: "/etc/kelixip/scripts/bot.exs",
                 resume: "awaiting_answer",
                 expires_at: expires
               } = row

        assert expires == @now + 600
        refute Map.has_key?(row, :data)
      end
    end
  end
end
