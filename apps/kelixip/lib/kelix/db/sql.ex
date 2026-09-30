defmodule Kelix.DB.SQL do
  @moduledoc """
  Running statements on a `Kelix.DB.Pool`, written once for MariaDB/MySQL and
  PostgreSQL: the modules that keep data in SQL (the Silo, the `conversation`
  store) share the code, never the connection.

  A handle is `%{conn: pool_name, driver: :mysql | :postgres, timeout: ms}`.
  Statements are written with `?` placeholders and numbered for PostgreSQL
  (`$1, $2…`); no statement may hold a literal `?`. `query/3` and
  `transaction/2` never raise — a base that is down is an `{:error, reason}`
  for the module to turn into its own answer; inside a transaction, `query!/4`
  raises, which rolls it back.

  A module's schema is the operator's to create; the module only checks it:
  `check_version/3` reads the one-row version table it ships.
  """

  @type handle :: %{conn: atom, driver: :mysql | :postgres, timeout: pos_integer}

  @doc "The handle a module's pool, named `conn`, is queried through."
  @spec handle(map, atom) :: handle
  def handle(config, conn),
    do: %{
      conn: conn,
      driver: Kelix.DB.Pool.driver(config),
      timeout: config["call_timeout_ms"] || Kelix.Module.default_call_timeout_ms()
    }

  @doc "Run one statement on the pool. Never raises."
  @spec query(handle, String.t(), list) :: {:ok, map} | {:error, term}
  def query(h, sql, params) do
    driver_module(h).query(h.conn, placeholders(h, sql), params, timeout: h.timeout)
  rescue
    e -> {:error, e}
  catch
    :exit, reason -> {:error, {:exit, reason}}
  end

  @doc "Run one statement on `conn`, the connection `transaction/2` hands over."
  @spec query!(handle, term, String.t(), list) :: map
  def query!(h, conn, sql, params),
    do: driver_module(h).query!(conn, placeholders(h, sql), params, timeout: h.timeout)

  @doc """
  Run `fun.(conn)` in a transaction: `{:ok, result}`, or `{:error, reason}`
  when it raised (and was rolled back) or the base did not answer.
  """
  @spec transaction(handle, (term -> term)) :: {:ok, term} | {:error, term}
  def transaction(h, fun) do
    driver_module(h).transaction(h.conn, fun, timeout: h.timeout)
  rescue
    e -> {:error, e}
  catch
    :exit, reason -> {:error, {:exit, reason}}
  end

  @doc """
  Is the schema there, at version `wanted`? Reads `SELECT version FROM table`.
  `{:error, :missing}` when the table does not exist, `{:error, {:stale,
  found}}` at another version — both the operator's to fix — and any other
  error when the base does not answer.
  """
  @spec check_version(handle, String.t(), pos_integer) ::
          :ok | {:error, :missing | {:stale, term} | term}
  def check_version(h, table, wanted) do
    case query(h, "SELECT version FROM #{table}", []) do
      {:ok, %{rows: [[^wanted]]}} ->
        :ok

      {:ok, %{rows: [[version]]}} ->
        {:error, {:stale, version}}

      {:ok, %{rows: rows}} ->
        {:error, {:stale, Enum.map(rows, &hd/1)}}

      {:error, reason} ->
        if undefined_table?(reason), do: {:error, :missing}, else: {:error, reason}
    end
  end

  @doc "`n` placeholders, for an `IN (…)` list."
  @spec marks([term]) :: String.t()
  def marks(values), do: Enum.map_join(values, ", ", fn _ -> "?" end)

  @doc "A number as the drivers hand it back (a MySQL `SUM` is a `Decimal`)."
  @spec to_int(integer | Decimal.t() | nil) :: integer
  def to_int(n) when is_integer(n), do: n
  def to_int(%Decimal{} = d), do: Decimal.to_integer(d)
  def to_int(nil), do: 0

  defp driver_module(%{driver: driver}), do: Kelix.DB.Pool.driver_module(driver)

  defp placeholders(%{driver: :mysql}, sql), do: sql

  defp placeholders(%{driver: :postgres}, sql) do
    sql
    |> String.split("?")
    |> Enum.with_index()
    |> Enum.map_join(fn
      {part, 0} -> part
      {part, i} -> "$#{i}" <> part
    end)
  end

  # ER_NO_SUCH_TABLE / undefined_table: the schema was never created.
  defp undefined_table?(%MyXQL.Error{mysql: %{code: 1146}}), do: true
  defp undefined_table?(%Postgrex.Error{postgres: %{code: :undefined_table}}), do: true
  defp undefined_table?(_), do: false
end
