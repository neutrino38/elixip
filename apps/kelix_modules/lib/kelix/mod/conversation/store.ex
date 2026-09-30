defmodule Kelix.Mod.Conversation.Store do
  @moduledoc """
  What the `conversation` module asks of its storage, as a behaviour
  (chat-basic-plan, C3d).

  One implementation ships: `Kelix.Mod.Conversation.Store.SQL`, so a
  conversation hibernated on one node wakes on another and survives a restart.
  The test suite adds an in-memory one behind the same callbacks.

  A key is `{domain, rule, From AOR, To AOR}` (`Kelix.Conversations.hibernation_key/1`),
  `rule` a rule name or `:default`. An entry is the snapshot `hibernate/1` set
  aside — `script`, `resume`, `data`, the granted `ttl` — and its `expires_at`,
  in wall-clock Unix seconds.
  """

  @type handle :: term
  @type key :: {String.t(), String.t() | :default, String.t(), String.t()}
  @type entry :: %{
          script: String.t(),
          resume: atom,
          data: map,
          ttl: pos_integer,
          expires_at: integer
        }

  @doc "Is the schema there, at the version this code reads? See `Kelix.DB.SQL.check_version/3`."
  @callback check_schema(handle) :: :ok | {:error, term}

  @doc "Keep `entry` under `key`, replacing what was there: it is the same two parties."
  @callback put(handle, key, entry) :: :ok | {:error, term}

  @doc """
  Take what is kept under `key`: it is no longer kept afterwards, and two nodes
  taking at once get it once. `:none` when nothing is, or when it expired by `now`.
  """
  @callback take(handle, key, now :: integer) :: {:ok, entry} | :none | {:error, term}

  @doc "What is kept and not expired by `now`: the key's parts, the script, the state, the expiry — never the data."
  @callback list(handle, now :: integer) :: {:ok, [map]} | {:error, term}

  @doc "Delete what expired by `now`. How many."
  @callback sweep(handle, now :: integer) :: {:ok, non_neg_integer} | {:error, term}
end
