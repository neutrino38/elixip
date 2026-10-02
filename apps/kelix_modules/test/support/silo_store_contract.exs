defmodule Kelix.Test.SiloStoreContract do
  @moduledoc """
  What every `Kelix.Mod.Silo.Store` must do, as tests: `use` it in a case whose
  setup returns `%{store: module, handle: handle}` on an empty store. The
  in-memory store and the SQL one run the same list, so the logic tested on the
  first holds on the second.
  """

  defmacro __using__(_opts) do
    quote do
      @now 1_900_000_000

      defp row(overrides \\ %{}) do
        Map.merge(
          %{
            domain: "example.com",
            aor: "bob",
            sender: "<sip:alice@example.com>;tag=a1",
            recipient: "<sip:bob@example.com>",
            content_type: "text/plain;charset=UTF-8",
            headers: %{"Subject" => "hello"},
            body: "Rendez-vous jeudi",
            size: 17,
            received_at: @now,
            expires_at: @now + 600,
            served: []
          },
          overrides
        )
      end

      test "the schema is there", %{store: store, handle: h} do
        assert store.check_schema(h) == :ok
      end

      test "a stored message comes back whole in a claim, body verbatim", %{
        store: store,
        handle: h
      } do
        body = "Content-type: text/plain\r\n\r\nété \x00\xff"

        {:ok, id} =
          store.insert(h, row(%{body: body, size: byte_size(body), served: ["urn:uuid:a"]}))

        assert {:ok, [m], 0} = store.claim(h, "example.com", "bob", "n1", @now, @now + 60)
        assert m.id == id
        assert m.body == body
        assert m.headers == %{"Subject" => "hello"}
        assert m.sender == "<sip:alice@example.com>;tag=a1"
        assert m.recipient == "<sip:bob@example.com>"
        assert m.content_type == "text/plain;charset=UTF-8"
        assert m.received_at == @now and m.expires_at == @now + 600
        assert m.served == ["urn:uuid:a"]
      end

      test "usage counts the AOR's live messages and their size", %{store: store, handle: h} do
        {:ok, _} = store.insert(h, row(%{size: 10}))
        {:ok, _} = store.insert(h, row(%{size: 5}))
        {:ok, _} = store.insert(h, row(%{size: 7, expires_at: @now - 1}))
        {:ok, _} = store.insert(h, row(%{aor: "carol", size: 99}))

        assert store.usage(h, "example.com", "bob", @now) == {:ok, %{count: 2, bytes: 15}}
        assert store.usage(h, "example.com", "dave", @now) == {:ok, %{count: 0, bytes: 0}}
      end

      test "a claim takes the backlog in arrival order, and a second claim nothing", %{
        store: store,
        handle: h
      } do
        ids = for n <- 1..3, do: elem(store.insert(h, row(%{body: "m#{n}"})), 1)

        assert {:ok, claimed, 0} = store.claim(h, "example.com", "bob", "n1", @now, @now + 60)
        assert Enum.map(claimed, & &1.id) == ids
        assert Enum.map(claimed, & &1.body) == ["m1", "m2", "m3"]

        assert {:ok, [], 3} = store.claim(h, "example.com", "bob", "n2", @now, @now + 60)
      end

      test "a lease that ran out frees the batch; a release frees it at once", %{
        store: store,
        handle: h
      } do
        {:ok, id} = store.insert(h, row())
        {:ok, [_], 0} = store.claim(h, "example.com", "bob", "n1", @now, @now + 60)

        assert {:ok, [%{id: ^id}], 0} =
                 store.claim(h, "example.com", "bob", "n2", @now + 60, @now + 120)

        # n1 no longer holds it: its release gives back nothing
        assert :ok = store.release(h, [id], "n1")
        assert {:ok, [], 1} = store.claim(h, "example.com", "bob", "n3", @now + 61, @now + 121)

        assert :ok = store.release(h, [id], "n2")
        assert {:ok, [_], 0} = store.claim(h, "example.com", "bob", "n3", @now + 61, @now + 121)
      end

      test "the served set grows once per device", %{store: store, handle: h} do
        {:ok, id} = store.insert(h, row())
        assert :ok = store.serve(h, id, "urn:uuid:a", @now)
        assert :ok = store.serve(h, id, "urn:uuid:a", @now + 1)
        assert :ok = store.serve(h, id, "sip:bob@10.0.0.2", @now + 2)

        {:ok, [m], 0} = store.claim(h, "example.com", "bob", "n1", @now, @now + 60)
        assert m.served == ["urn:uuid:a", "sip:bob@10.0.0.2"]
      end

      test "expired messages are neither claimed nor listed, and the sweep deletes them", %{
        store: store,
        handle: h
      } do
        {:ok, old} = store.insert(h, row(%{expires_at: @now}))
        {:ok, served} = store.insert(h, row(%{expires_at: @now, domain: "other.net"}))
        :ok = store.serve(h, served, "urn:uuid:a", @now)
        {:ok, live} = store.insert(h, row())

        assert {:ok, [%{id: ^live}]} = store.list(h, "example.com", "bob", @now)

        assert {:ok, [%{id: ^live}], 0} =
                 store.claim(h, "example.com", "bob", "n1", @now, @now + 1)

        assert {:ok, swept} = store.sweep(h, @now)

        assert Enum.sort_by(swept, & &1.domain) == [
                 %{domain: "example.com", served: false},
                 %{domain: "other.net", served: true}
               ]

        assert {:ok, []} = store.sweep(h, @now)
        refute old == live
      end

      test "list shows metadata only; purge empties the AOR", %{store: store, handle: h} do
        {:ok, id} = store.insert(h, row())
        :ok = store.serve(h, id, "urn:uuid:a", @now)
        {:ok, _} = store.insert(h, row(%{aor: "carol"}))

        assert {:ok, [meta]} = store.list(h, "example.com", "bob", @now)
        assert meta.id == id and meta.size == 17 and meta.served == ["urn:uuid:a"]
        refute Map.has_key?(meta, :body)

        assert {:ok, 1} = store.purge(h, "example.com", "bob")
        assert {:ok, []} = store.list(h, "example.com", "bob", @now)
        assert {:ok, [_]} = store.list(h, "example.com", "carol", @now)
      end

      test "stats count the live messages, their AORs, their bytes and the claimed ones", %{
        store: store,
        handle: h
      } do
        assert {:ok, %{messages: 0, aors: 0, bytes: 0, claimed: 0}} = store.stats(h, @now)

        {:ok, _} = store.insert(h, row(%{size: 10}))
        {:ok, _} = store.insert(h, row(%{size: 5}))
        {:ok, _} = store.insert(h, row(%{aor: "carol", size: 7}))
        {:ok, _} = store.insert(h, row(%{domain: "other.net", size: 1}))
        {:ok, _} = store.insert(h, row(%{aor: "dave", size: 99, expires_at: @now - 1}))
        {:ok, [_, _], 0} = store.claim(h, "example.com", "bob", "n1", @now, @now + 60)

        assert {:ok, %{messages: 4, aors: 3, bytes: 23, claimed: 2}} = store.stats(h, @now)
        assert {:ok, %{claimed: 0}} = store.stats(h, @now + 60)
      end
    end
  end
end
