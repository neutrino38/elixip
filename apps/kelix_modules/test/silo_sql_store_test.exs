defmodule Kelix.Test.SiloSQL do
  @moduledoc """
  The SQL half of the Silo against a real engine, when one is named: an URL in
  `SILO_TEST_POSTGRES` or `SILO_TEST_MYSQL` (`postgres://user:pw@host:port/db`,
  `mysql://…`), on a database the test may wipe. Skipped otherwise — the same
  gate as the Mendooze E2E. The tables are recreated from the DDL the package
  ships, so what is tested is what an operator installs.
  """

  @doc "The block an URL stands for, or nil."
  def config(env) do
    case System.get_env(env) do
      nil ->
        nil

      url ->
        u = URI.parse(url)

        [user, password] =
          (String.split(u.userinfo || "", ":", parts: 2) ++ [nil]) |> Enum.take(2)

        %{
          "driver" => if(u.scheme == "mysql", do: "mysql", else: "postgres"),
          "host" => u.host,
          "port" => u.port,
          "database" => String.trim_leading(u.path || "", "/"),
          "username" => user,
          "password" => password,
          "ssl" => false,
          "allow_insecure_db_connection" => true,
          "pool_size" => 3
        }
    end
  end

  @ddl Path.expand("../../../packaging/sql/silo", __DIR__)

  @doc "Start a pool on `config` under `name`, and recreate the tables."
  def start!(config, name) do
    {:ok, _pid} = Kelix.DB.Pool.start_link(config, name: name, label: "silo-test")
    mod = Kelix.DB.Pool.driver_module(Kelix.DB.Pool.driver(config))

    for table <- ~w(silo_served silo_message silo_version),
        do: mod.query!(name, "DROP TABLE IF EXISTS #{table}", [])

    file = if config["driver"] == "mysql", do: "mysql.sql", else: "postgres.sql"

    @ddl
    |> Path.join(file)
    |> File.read!()
    |> strip_comments()
    |> String.split(";")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.each(&mod.query!(name, &1, []))

    %{conn: name, driver: Kelix.DB.Pool.driver(config), timeout: 5_000}
  end

  def wipe!(%{conn: conn} = h) do
    mod = Kelix.DB.Pool.driver_module(h.driver)
    mod.query!(conn, "DELETE FROM silo_served", [])
    mod.query!(conn, "DELETE FROM silo_message", [])
  end

  defp strip_comments(sql) do
    sql
    |> String.split("\n")
    |> Enum.reject(&String.starts_with?(String.trim(&1), "--"))
    |> Enum.join("\n")
  end
end

for {engine, env} <- [postgres: "SILO_TEST_POSTGRES", mysql: "SILO_TEST_MYSQL"] do
  defmodule Module.concat(Kelix.Mod.SiloSQLStoreTest, Macro.camelize(to_string(engine))) do
    @moduledoc "The store contract on #{engine} (#{env})."
    use ExUnit.Case, async: false

    @config Kelix.Test.SiloSQL.config(env)
    @conn Module.concat(__MODULE__, Conn)

    # Before the contract's tests are defined: a tag applies to the tests that follow it.
    if @config == nil, do: @moduletag(skip: "#{env} not set")

    use Kelix.Test.SiloStoreContract

    # setup_all runs even for a skipped module: no engine, nothing to start.
    setup_all do
      if @config, do: %{handle: Kelix.Test.SiloSQL.start!(@config, @conn)}, else: :ok
    end

    setup context do
      if h = context[:handle], do: Kelix.Test.SiloSQL.wipe!(h)
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
