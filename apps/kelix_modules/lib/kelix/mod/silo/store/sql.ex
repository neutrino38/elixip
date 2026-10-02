defmodule Kelix.Mod.Silo.Store.SQL do
  @moduledoc """
  The Silo's storage in SQL — MariaDB/MySQL or PostgreSQL, over the module's own
  `Kelix.DB.Pool` (`Kelix.Mod.Silo.Conn`).

  The handle is `%{conn: pool, driver: :mysql | :postgres, timeout: ms}`. Every
  statement is written once with `?` placeholders and numbered for PostgreSQL;
  the other differences between the two engines — the key type, the body type,
  "insert unless present", how the new id comes back — are in the DDL and in
  the two clauses below that name a driver.

  ## The claim

  A short transaction, not `SKIP LOCKED` (DESIGN-CHAT.md, *Horizontal scale*):
  select the AOR's live rows nobody holds, `FOR UPDATE`; stamp `claimed_by` and
  `claimed_until` on them; commit — **before** delivering, since a lock held
  across a SIP transaction would stall every other node flushing that AOR. A
  second node claiming at the same instant blocks on the row locks, then finds
  them held and takes nothing. Plain `FOR UPDATE` is portable to every version
  of both engines.
  """
  @behaviour Kelix.Mod.Silo.Store

  alias Kelix.DB.SQL
  alias Kelix.Mod.Silo.Schema

  import Kelix.DB.SQL, only: [query: 3, query!: 4, transaction: 2, marks: 1, to_int: 1]

  @columns "id, sender, recipient, content_type, headers, body, received_at, expires_at"

  # ── Kelix.Mod.Silo.Store ─────────────────────────────────────────────────────

  @impl true
  def check_schema(h), do: SQL.check_version(h, "silo_version", Schema.version())

  @impl true
  def usage(h, domain, aor, now) do
    sql =
      "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM silo_message " <>
        "WHERE domain = ? AND aor = ? AND expires_at > ?"

    with {:ok, %{rows: [[count, bytes]]}} <- query(h, sql, [domain, aor, now]) do
      {:ok, %{count: to_int(count), bytes: to_int(bytes)}}
    end
  end

  @impl true
  def insert(h, row) do
    transaction(h, fn conn ->
      id = insert_message(h, conn, row)
      Enum.each(Enum.uniq(row.served), &insert_served!(h, conn, id, &1, row.received_at))
      id
    end)
  end

  @insert_message "INSERT INTO silo_message (domain, aor, sender, recipient, content_type, " <>
                    "headers, body, size, received_at, expires_at) " <>
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

  defp insert_message(h, conn, row) do
    params = [
      row.domain,
      row.aor,
      row.sender,
      row.recipient,
      row.content_type,
      Jason.encode!(row.headers),
      row.body,
      row.size,
      row.received_at,
      row.expires_at
    ]

    case h.driver do
      :mysql ->
        %{last_insert_id: id} = query!(h, conn, @insert_message, params)
        id

      :postgres ->
        %{rows: [[id]]} = query!(h, conn, @insert_message <> " RETURNING id", params)
        id
    end
  end

  defp insert_served!(h, conn, id, device, now) do
    sql =
      case h.driver do
        :mysql ->
          "INSERT INTO silo_served (message_id, device, served_at) VALUES (?, ?, ?) " <>
            "ON DUPLICATE KEY UPDATE served_at = served_at"

        :postgres ->
          "INSERT INTO silo_served (message_id, device, served_at) VALUES (?, ?, ?) " <>
            "ON CONFLICT (message_id, device) DO NOTHING"
      end

    query!(h, conn, sql, [id, device, now])
  end

  @impl true
  def claim(h, domain, aor, owner, now, until) do
    transaction(h, fn conn ->
      rows =
        query!(
          h,
          conn,
          "SELECT #{@columns}, claimed_until FROM silo_message " <>
            "WHERE domain = ? AND aor = ? AND expires_at > ? ORDER BY id FOR UPDATE",
          [domain, aor, now]
        ).rows

      {free, held} =
        Enum.split_with(rows, fn row -> free?(List.last(row), now) end)

      messages = Enum.map(free, &message/1)
      ids = Enum.map(messages, & &1.id)

      if ids != [] do
        query!(
          h,
          conn,
          "UPDATE silo_message SET claimed_by = ?, claimed_until = ? WHERE id IN (#{marks(ids)})",
          [owner, until | ids]
        )
      end

      served = served_sets(h, conn, ids)
      {Enum.map(messages, &%{&1 | served: Map.get(served, &1.id, [])}), length(held)}
    end)
    |> case do
      {:ok, {messages, busy}} -> {:ok, messages, busy}
      error -> error
    end
  end

  defp free?(nil, _now), do: true
  defp free?(until, now), do: to_int(until) <= now

  @impl true
  def serve(h, id, device, now) do
    case transaction(h, fn conn -> insert_served!(h, conn, id, device, now) end) do
      {:ok, _} -> :ok
      error -> error
    end
  end

  @impl true
  def release(_h, [], _owner), do: :ok

  def release(h, ids, owner) do
    sql =
      "UPDATE silo_message SET claimed_by = NULL, claimed_until = NULL " <>
        "WHERE claimed_by = ? AND id IN (#{marks(ids)})"

    with {:ok, _} <- query(h, sql, [owner | ids]), do: :ok
  end

  # One batch per transaction, so a backlog of expired rows never holds its locks
  # for long; the caller loops while batches come back full.
  @sweep_batch 500

  @impl true
  def sweep(h, now), do: sweep(h, now, [])

  defp sweep(h, now, acc) do
    result =
      transaction(h, fn conn ->
        rows =
          query!(
            h,
            conn,
            "SELECT id, domain FROM silo_message WHERE expires_at <= ? " <>
              "ORDER BY id LIMIT #{@sweep_batch} FOR UPDATE",
            [now]
          ).rows

        ids = Enum.map(rows, &hd/1)

        if ids != [] do
          served = served_sets(h, conn, ids)
          query!(h, conn, "DELETE FROM silo_served WHERE message_id IN (#{marks(ids)})", ids)
          query!(h, conn, "DELETE FROM silo_message WHERE id IN (#{marks(ids)})", ids)
          for [id, domain] <- rows, do: %{domain: domain, served: Map.has_key?(served, id)}
        else
          []
        end
      end)

    case result do
      {:ok, swept} when length(swept) == @sweep_batch -> sweep(h, now, acc ++ swept)
      {:ok, swept} -> {:ok, acc ++ swept}
      error -> error
    end
  end

  @impl true
  def list(h, domain, aor, now) do
    sql =
      "SELECT id, sender, content_type, size, received_at, expires_at FROM silo_message " <>
        "WHERE domain = ? AND aor = ? AND expires_at > ? ORDER BY id"

    with {:ok, %{rows: rows}} <- query(h, sql, [domain, aor, now]) do
      ids = Enum.map(rows, &hd/1)

      served =
        case transaction(h, &served_sets(h, &1, ids)) do
          {:ok, served} -> served
          _ -> %{}
        end

      {:ok,
       for [id, sender, ct, size, received, expires] <- rows do
         %{
           id: id,
           sender: sender,
           content_type: ct,
           size: to_int(size),
           received_at: to_int(received),
           expires_at: to_int(expires),
           served: Map.get(served, id, [])
         }
       end}
    end
  end

  @impl true
  def stats(h, now) do
    sql =
      "SELECT COUNT(*), COUNT(DISTINCT domain, aor), COALESCE(SUM(size), 0), " <>
        "COALESCE(SUM(CASE WHEN claimed_until > ? THEN 1 ELSE 0 END), 0) " <>
        "FROM silo_message WHERE expires_at > ?"

    with {:ok, %{rows: [[count, aors, bytes, claimed]]}} <-
           query(h, stats_sql(h, sql), [now, now]) do
      {:ok,
       %{
         messages: to_int(count),
         aors: to_int(aors),
         bytes: to_int(bytes),
         claimed: to_int(claimed)
       }}
    end
  end

  # `COUNT(DISTINCT a, b)` is MySQL's; PostgreSQL counts a row value.
  defp stats_sql(%{driver: :postgres}, sql),
    do: String.replace(sql, "COUNT(DISTINCT domain, aor)", "COUNT(DISTINCT (domain, aor))")

  defp stats_sql(_h, sql), do: sql

  @impl true
  def purge(h, domain, aor) do
    transaction(h, fn conn ->
      ids =
        query!(
          h,
          conn,
          "SELECT id FROM silo_message WHERE domain = ? AND aor = ? FOR UPDATE",
          [domain, aor]
        ).rows
        |> Enum.map(&hd/1)

      if ids != [] do
        query!(h, conn, "DELETE FROM silo_served WHERE message_id IN (#{marks(ids)})", ids)
        query!(h, conn, "DELETE FROM silo_message WHERE id IN (#{marks(ids)})", ids)
      end

      length(ids)
    end)
  end

  # ── internals ───────────────────────────────────────────────────────────────

  defp served_sets(_h, _conn, []), do: %{}

  defp served_sets(h, conn, ids) do
    query!(
      h,
      conn,
      "SELECT message_id, device FROM silo_served WHERE message_id IN (#{marks(ids)}) " <>
        "ORDER BY served_at",
      ids
    ).rows
    |> Enum.group_by(&hd/1, &List.last/1)
  end

  defp message([id, sender, recipient, ct, headers, body, received, expires | _]) do
    %{
      id: id,
      sender: sender,
      recipient: recipient,
      content_type: ct,
      headers: decode_headers(headers),
      body: body,
      received_at: to_int(received),
      expires_at: to_int(expires),
      served: []
    }
  end

  defp decode_headers(json) do
    case Jason.decode(json || "{}") do
      {:ok, %{} = map} -> map
      _ -> %{}
    end
  end
end
