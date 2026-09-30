for {engine, config} <- Kelix.Test.SQL.engines() do
  defmodule Module.concat(Kelix.Mod.SiloSQLStoreTest, Macro.camelize(to_string(engine))) do
    @moduledoc "The Silo's store contract on #{engine} (KELIX_TEST_#{String.upcase(to_string(engine))})."
    use ExUnit.Case, async: false

    @config config
    @conn Module.concat(__MODULE__, Conn)
    @tables ~w(silo_served silo_message silo_version)

    # Before the contract's tests are defined: a tag applies to the tests that follow it.
    if @config == nil,
      do: @moduletag(skip: "KELIX_TEST_#{String.upcase(to_string(engine))} not set")

    use Kelix.Test.SiloStoreContract

    # setup_all runs even for a skipped module: no engine, nothing to start.
    setup_all do
      if @config,
        do: %{handle: Kelix.Test.SQL.start!(@config, @conn, "silo", @tables)},
        else: :ok
    end

    setup context do
      if h = context[:handle], do: Kelix.Test.SQL.wipe!(h, ~w(silo_served silo_message))
      %{store: Kelix.Mod.Silo.Store.SQL}
    end

    test "a stale schema is told apart from a missing one", %{handle: h} do
      mod = Kelix.DB.Pool.driver_module(h.driver)
      mod.query!(h.conn, "UPDATE silo_version SET version = 99", [])
      assert Kelix.Mod.Silo.Store.SQL.check_schema(h) == {:error, {:stale, 99}}
      mod.query!(h.conn, "UPDATE silo_version SET version = 1", [])

      mod.query!(h.conn, "ALTER TABLE silo_version RENAME TO silo_version_x", [])
      assert Kelix.Mod.Silo.Store.SQL.check_schema(h) == {:error, :missing}
      mod.query!(h.conn, "ALTER TABLE silo_version_x RENAME TO silo_version", [])
    end

    test "two claims at the same instant: one takes the batch, the other nothing", %{
      handle: h
    } do
      store = Kelix.Mod.Silo.Store.SQL
      for n <- 1..20, do: {:ok, _} = store.insert(h, row(%{body: "m#{n}"}))

      results =
        1..4
        |> Enum.map(fn n ->
          Task.async(fn -> store.claim(h, "example.com", "bob", "node#{n}", @now, @now + 60) end)
        end)
        |> Task.await_many(10_000)

      taken = for {:ok, claimed, _busy} <- results, claimed != [], do: claimed
      assert [batch] = taken
      assert length(batch) == 20
    end
  end
end
