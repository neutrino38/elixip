defmodule SIP.Test.PublishCollection do
  @moduledoc """
  The in-memory collection a PUBLISH is published *into*, for as long as a test
  runs: what `Kelix.Mod.Presence` will be (P7), reduced to the two things the
  framework layer needs on the other side of the line — the entity-tag
  lifecycle, and the document per resource.

  It is here rather than inside the suite because it is the half the framework
  deliberately does **not** hold (docs/design/presence-basic-plan.md, decision
  5): one PUBLISH is one transaction, its scenario instance is gone before the
  refresh arrives, and the state therefore lives in a process of the
  application's. A stub that lived inside the instance would prove the opposite
  of what the suite is asserting.

  Rows are kept under `presentity`'s key — `{username, domain, event, etag}` —
  so what a test reads back is what a database backend would store.
  """

  use Agent

  alias SIP.Publication

  @doc "Start (or empty) the collection. Idempotent, so a test may call it in `setup`."
  @spec start() :: :ok
  def start do
    case Agent.start(fn -> %{} end, name: __MODULE__) do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> reset()
    end
  end

  @doc "Forget every published state."
  @spec reset() :: :ok
  def reset, do: Agent.update(__MODULE__, fn _rows -> %{} end)

  @doc """
  Apply one publication, the way RFC 3903 §6 has an event state compositor do it.

  Answers `{:ok, etag, expires}` — the tag the publisher must present next time
  and the lifetime granted — `{:ok, :removed}` when the state is gone, or
  `{:error, 412}` when the tag presented names no state we hold, which is the
  one verdict only the collection can reach.

  **A new entity-tag per successful publication** (§4.1): the tag identifies the
  publication, not the publisher, and a compositor that reissued the same one
  could not tell a refresh from a replay of one.
  """
  @spec publish(Publication.t()) ::
          {:ok, binary(), non_neg_integer()} | {:ok, :removed} | {:error, 412}
  def publish(%Publication{operation: :initial} = pub) do
    etag = Publication.new_etag()
    store(%{pub | etag: etag})
    {:ok, etag, Publication.remaining(pub)}
  end

  def publish(%Publication{operation: :remove} = pub) do
    case fetch(pub) do
      # A removal naming nothing — an initial PUBLISH carrying `Expires: 0`, or
      # one whose state has already lapsed. There is nothing to drop and nothing
      # to refuse: the publisher asked for no state to be kept, and none is.
      nil -> {:ok, :removed}
      stored -> drop(stored)
    end
  end

  def publish(%Publication{operation: operation} = pub) when operation in [:modify, :refresh] do
    case fetch(pub) do
      nil ->
        {:error, 412}

      stored ->
        etag = Publication.new_etag()
        # A refresh carries no body: the state is the one already held, for
        # longer. A modification carries the one that replaces it.
        body = if operation == :refresh, do: stored.body, else: pub.body
        doc = if operation == :refresh, do: stored.doc, else: pub.doc

        drop(stored)
        store(%{pub | etag: etag, body: body, doc: doc})
        {:ok, etag, Publication.remaining(pub)}
    end
  end

  @doc "The states held for one resource, as `{username, domain, event}` names it."
  @spec resource(Publication.t() | {binary(), binary(), binary()}) :: [Publication.t()]
  def resource(%Publication{} = pub), do: resource(Publication.resource(pub))

  def resource({_user, _domain, _event} = key) do
    Agent.get(__MODULE__, fn rows ->
      rows |> Map.values() |> Enum.filter(&(Publication.resource(&1) == key))
    end)
  end

  @doc "Every state held, whatever the resource."
  @spec all() :: [Publication.t()]
  def all, do: Agent.get(__MODULE__, fn rows -> Map.values(rows) end)

  defp store(%Publication{} = pub) do
    Agent.update(__MODULE__, fn rows -> Map.put(rows, Publication.key(pub), pub) end)
  end

  defp drop(%Publication{} = pub) do
    Agent.update(__MODULE__, fn rows -> Map.delete(rows, Publication.key(pub)) end)
    {:ok, :removed}
  end

  # The state the presented tag names, or nil. The key is the whole key: a tag
  # is only valid for the resource and the package it was issued for.
  defp fetch(%Publication{etag: nil}), do: nil

  defp fetch(%Publication{} = pub) do
    Agent.get(__MODULE__, fn rows -> Map.get(rows, Publication.key(pub)) end)
  end
end
