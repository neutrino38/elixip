defmodule Kelix.Mod.Conversation.Store.SQL do
  @moduledoc """
  Hibernated conversations in SQL — MariaDB/MySQL or PostgreSQL, over the
  module's own `Kelix.DB.Pool` (`Kelix.Mod.Conversation.Conn`). The schema ships
  under `packaging/sql/conversation/`, at `@version`.

  A row is keyed on the SHA-256 of its key: four text columns of up to 255
  characters would exceed what MySQL accepts as a primary key, and the columns
  are kept beside it for `kelictl conversation list`. The domain's default rule
  is written as the empty string.

  The kept data is stored in the Erlang external term format — it is plain data,
  `hibernate/1` checked — and read back with `[:safe]`. A value naming an atom
  this node has not loaded yet is read without it: the table is the module's
  own, written only by `put/3`.

  `take/3` is a transaction, `SELECT … FOR UPDATE` then `DELETE`: two nodes
  woken by two MESSAGEs of the same parties at once wake the conversation once.
  """
  @behaviour Kelix.Mod.Conversation.Store

  import Kelix.DB.SQL, only: [query: 3, query!: 4, transaction: 2, to_int: 1]

  @version 1

  @doc "The schema version this code reads and writes."
  def version, do: @version

  @impl true
  def check_schema(h), do: Kelix.DB.SQL.check_version(h, "conversation_version", @version)

  @impl true
  def put(h, {domain, rule, from, to} = key, entry) do
    hash = key_hash(key)

    result =
      transaction(h, fn conn ->
        query!(h, conn, "DELETE FROM conversation WHERE key_hash = ?", [hash])

        query!(
          h,
          conn,
          "INSERT INTO conversation (key_hash, domain, chat_rule, from_aor, to_aor, script, " <>
            "resume, data, ttl, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
          [
            hash,
            domain,
            rule_text(rule),
            from,
            to,
            entry.script,
            Atom.to_string(entry.resume),
            :erlang.term_to_binary(entry.data),
            entry.ttl,
            entry.expires_at
          ]
        )
      end)

    with {:ok, _} <- result, do: :ok
  end

  @impl true
  def take(h, key, now) do
    hash = key_hash(key)

    result =
      transaction(h, fn conn ->
        rows =
          query!(
            h,
            conn,
            "SELECT script, resume, data, ttl, expires_at FROM conversation " <>
              "WHERE key_hash = ? FOR UPDATE",
            [hash]
          ).rows

        if rows != [], do: query!(h, conn, "DELETE FROM conversation WHERE key_hash = ?", [hash])
        rows
      end)

    case result do
      {:ok, [[script, resume, data, ttl, expires_at]]} ->
        if to_int(expires_at) > now do
          {:ok,
           %{
             script: script,
             resume: String.to_atom(resume),
             data: decode(data),
             ttl: to_int(ttl),
             expires_at: to_int(expires_at)
           }}
        else
          :none
        end

      {:ok, []} ->
        :none

      {:error, _} = error ->
        error
    end
  end

  @impl true
  def list(h, now) do
    sql =
      "SELECT domain, chat_rule, from_aor, to_aor, script, resume, expires_at " <>
        "FROM conversation WHERE expires_at > ? ORDER BY domain, from_aor, to_aor"

    with {:ok, %{rows: rows}} <- query(h, sql, [now]) do
      {:ok,
       for [domain, rule, from, to, script, resume, expires_at] <- rows do
         %{
           domain: domain,
           rule: rule_value(rule),
           from: from,
           to: to,
           script: script,
           resume: resume,
           expires_at: to_int(expires_at)
         }
       end}
    end
  end

  @impl true
  def stats(h, now) do
    sql = "SELECT COUNT(*), COUNT(DISTINCT domain) FROM conversation WHERE expires_at > ?"

    with {:ok, %{rows: [[count, domains]]}} <- query(h, sql, [now]) do
      {:ok, %{conversations: to_int(count), domains: to_int(domains)}}
    end
  end

  @impl true
  def sweep(h, now) do
    with {:ok, %{num_rows: n}} <-
           query(h, "DELETE FROM conversation WHERE expires_at <= ?", [now]) do
      {:ok, n}
    end
  end

  @doc false
  # Stable across nodes and releases: the parts, NUL-separated, never a term encoding.
  def key_hash({domain, rule, from, to}) do
    [domain, rule_text(rule), from, to]
    |> Enum.join(<<0>>)
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  defp rule_text(:default), do: ""
  defp rule_text(rule) when is_binary(rule), do: rule

  defp rule_value(""), do: :default
  defp rule_value(rule), do: rule

  defp decode(data) do
    :erlang.binary_to_term(data, [:safe])
  rescue
    ArgumentError -> :erlang.binary_to_term(data)
  end
end
