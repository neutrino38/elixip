defmodule Kelix.Mod.Silo.Schema do
  @moduledoc """
  The Silo's tables, and the version of them this code reads.

  The module **owns** a schema and does **not** migrate it: the DDL for both
  engines ships with the package, under `/usr/share/kelixip/sql/silo/`
  (`mysql.sql`, `postgres.sql`; `packaging/sql/silo/` in the tree), and is run
  by the operator. At start the module reads `silo_version`, and refuses to
  start when the tables are absent or at another version, rather than altering
  a production database by itself (DESIGN-CHAT.md, *Horizontal scale*).

  Three tables:

    * `silo_version` — one row, the schema version;
    * `silo_message` — one row per stored message, indexed on
      `(domain, aor, id)`: a flush is one indexed query, and `id` is the arrival
      order. `claimed_by` / `claimed_until` are the lease;
    * `silo_served` — `(message_id, device)`, the devices a message was served
      to. A message is never consumed: retention and quotas reclaim it.

  Times are `BIGINT` Unix seconds rather than `DATETIME` / `TIMESTAMPTZ`: one
  column type on both engines, and no time zone for a node and its database to
  disagree on.
  """

  @version 1

  @doc "The schema version this code reads and writes."
  @spec version() :: pos_integer
  def version, do: @version

  @doc "Why the module refuses to start, in the words the log gives the operator."
  @spec refusal(term) :: String.t()
  def refusal(:missing),
    do:
      "the silo tables are missing — create them with /usr/share/kelixip/sql/silo/" <>
        "{mysql,postgres}.sql; the module never runs DDL itself"

  def refusal({:stale, found}),
    do:
      "the silo schema is at version #{inspect(found)}, this module reads version " <>
        "#{@version} — upgrade it with the DDL shipped in /usr/share/kelixip/sql/silo/"

  def refusal(other), do: "the silo schema could not be checked: #{inspect(other)}"
end
