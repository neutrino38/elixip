defmodule Kelix.Mod.Silo.Store do
  @moduledoc """
  What the Silo asks of its storage, as a behaviour (chat-basic-plan, C6).

  One implementation ships: `Kelix.Mod.Silo.Store.SQL`, over MariaDB/MySQL or
  PostgreSQL. The test suite adds an in-memory one behind the same callbacks, so
  the logic above storage — retention, quotas, the served set, the lease — is
  covered with no database. No in-memory Silo is shipped: a node that loses its
  messages on restart has already answered 202 to their senders.

  Every callback takes the `handle` the implementation was started with (for SQL,
  the pool and its driver). Times are wall-clock Unix seconds: what the rows
  hold, and what another node compares them against.

  ## Shapes

  A row to insert (`t:row/0`) is the message as delivery will need it — the
  identities as their header values, the Content-Type, the carried-over headers
  and the body **verbatim** — plus where it is filed (`domain`, `aor`), when it
  arrived and expires, its size, and the devices it was already served to.

  A claimed message (`t:message/0`) is the same, with its `id` and its `served`
  set. A listed one (`t:meta/0`) carries **no body**: what an operator reads
  before purging a queue is who sent what kind of content when, never the
  content (chat-basic-plan, C1b).
  """

  @type handle :: term

  @type row :: %{
          domain: String.t(),
          aor: String.t(),
          sender: String.t(),
          recipient: String.t(),
          content_type: String.t(),
          headers: %{String.t() => String.t()},
          body: binary,
          size: non_neg_integer,
          received_at: integer,
          expires_at: integer,
          served: [String.t()]
        }

  @type message :: %{
          id: integer,
          sender: String.t(),
          recipient: String.t(),
          content_type: String.t(),
          headers: %{String.t() => String.t()},
          body: binary,
          received_at: integer,
          expires_at: integer,
          served: [String.t()]
        }

  @type meta :: %{
          id: integer,
          sender: String.t(),
          content_type: String.t(),
          size: non_neg_integer,
          received_at: integer,
          expires_at: integer,
          served: [String.t()]
        }

  @doc """
  Is the schema there, at the version this code reads? `{:error, :missing}` and
  `{:error, {:stale, found}}` are the operator's to fix; any other error is the
  database not answering.
  """
  @callback check_schema(handle) :: :ok | {:error, :missing | {:stale, term} | term}

  @doc "What the AOR's live messages weigh now: their count and their total size."
  @callback usage(handle, domain :: String.t(), aor :: String.t(), now :: integer) ::
              {:ok, %{count: non_neg_integer, bytes: non_neg_integer}} | {:error, term}

  @doc "Store one message, and the devices it was already served to. Its id."
  @callback insert(handle, row) :: {:ok, integer} | {:error, term}

  @doc """
  Claim the AOR's pending backlog for `owner` until `until`, in one short
  transaction: every live message nobody holds (or whose lease has run out), in
  arrival order, each with its served set. `busy` counts the live messages
  another owner holds right now — what tells a flush that found nothing whether
  to come back.
  """
  @callback claim(
              handle,
              domain :: String.t(),
              aor :: String.t(),
              owner :: String.t(),
              now :: integer,
              until :: integer
            ) :: {:ok, [message], busy :: non_neg_integer} | {:error, term}

  @doc "Add `device` to the message's served set."
  @callback serve(handle, id :: integer, device :: String.t(), now :: integer) ::
              :ok | {:error, term}

  @doc "Give back what `owner` claimed of `ids`."
  @callback release(handle, ids :: [integer], owner :: String.t()) :: :ok | {:error, term}

  @doc """
  Delete what expired by `now`. One entry per message deleted: its domain, and
  whether any device was ever served it.
  """
  @callback sweep(handle, now :: integer) ::
              {:ok, [%{domain: String.t(), served: boolean}]} | {:error, term}

  @doc "The AOR's live messages, oldest first, metadata only."
  @callback list(handle, domain :: String.t(), aor :: String.t(), now :: integer) ::
              {:ok, [meta]} | {:error, term}

  @doc "Delete every message of the AOR. How many."
  @callback purge(handle, domain :: String.t(), aor :: String.t()) ::
              {:ok, non_neg_integer} | {:error, term}
end
