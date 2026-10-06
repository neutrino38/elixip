defmodule Kelix.Test.SQL do
  @moduledoc """
  The SQL modules against a real engine, when one is named: an URL in
  `KELIX_TEST_POSTGRES` or `KELIX_TEST_MYSQL` (`postgres://user:pw@host:port/db`,
  `mysql://…`), on a database the tests may wipe. Skipped otherwise — the same
  gate as the Mendooze E2E. A module's tables are recreated from the DDL its
  package ships, so what is tested is what an operator installs.
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

  @doc "The engines to run on: `{engine, config | nil}`."
  def engines,
    do: [postgres: config("KELIX_TEST_POSTGRES"), mysql: config("KELIX_TEST_MYSQL")]

  @doc """
  Start a pool on `config` under `name`, and recreate `tables` (dropped in that
  order) from the DDL under `packaging/sql/<module>/`.
  """
  def start!(config, name, module, tables) do
    {:ok, _pid} = Kelix.DB.Pool.start_link(config, name: name, label: "silo-test")
    mod = Kelix.DB.Pool.driver_module(Kelix.DB.Pool.driver(config))

    for table <- tables, do: mod.query!(name, "DROP TABLE IF EXISTS #{table}", [])

    file = if config["driver"] == "mysql", do: "mysql.sql", else: "postgres.sql"

    Path.expand("../../../../packaging/sql/#{module}", __DIR__)
    |> Path.join(file)
    |> File.read!()
    |> strip_comments()
    |> String.split(";")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.each(&mod.query!(name, &1, []))

    Kelix.DB.SQL.handle(config, name)
  end

  @doc "Empty `tables`, in that order."
  def wipe!(%{conn: conn} = h, tables) do
    mod = Kelix.DB.Pool.driver_module(h.driver)
    Enum.each(tables, &mod.query!(conn, "DELETE FROM #{&1}", []))
  end

  defp strip_comments(sql) do
    sql
    |> String.split("\n")
    |> Enum.reject(&String.starts_with?(String.trim(&1), "--"))
    |> Enum.join("\n")
  end
end
