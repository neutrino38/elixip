defmodule Kelix.Test.ConversationMemoryStore do
  @moduledoc """
  Hibernated conversations in memory, **for the test suite only**: the same
  contract as `Kelix.Mod.Conversation.Store.SQL` (`conversation_store_contract.exs`
  runs on both). The handle is the pid of the Agent holding the entries.
  """
  @behaviour Kelix.Mod.Conversation.Store

  def start_link(opts \\ []) do
    schema = Keyword.get(opts, :schema, :ok)
    Agent.start_link(fn -> %{entries: %{}, schema: schema} end)
  end

  @impl true
  def check_schema(pid) do
    case Agent.get(pid, & &1.schema) do
      :ok -> :ok
      other -> {:error, other}
    end
  end

  @impl true
  def put(pid, key, entry),
    do: Agent.update(pid, fn s -> %{s | entries: Map.put(s.entries, key, entry)} end)

  @impl true
  def take(pid, key, now) do
    Agent.get_and_update(pid, fn s ->
      case Map.pop(s.entries, key) do
        {%{expires_at: at} = entry, rest} when at > now -> {{:ok, entry}, %{s | entries: rest}}
        {_none_or_expired, rest} -> {:none, %{s | entries: rest}}
      end
    end)
  end

  @impl true
  def list(pid, now) do
    rows =
      for {{domain, rule, from, to}, e} <- Agent.get(pid, & &1.entries), e.expires_at > now do
        %{
          domain: domain,
          rule: rule,
          from: from,
          to: to,
          script: e.script,
          resume: Atom.to_string(e.resume),
          expires_at: e.expires_at
        }
      end

    {:ok, Enum.sort_by(rows, &{&1.domain, &1.from, &1.to})}
  end

  @impl true
  def stats(pid, now) do
    live =
      for {{domain, _r, _f, _t}, e} <- Agent.get(pid, & &1.entries),
          e.expires_at > now,
          do: domain

    {:ok, %{conversations: length(live), domains: live |> Enum.uniq() |> length()}}
  end

  @impl true
  def sweep(pid, now) do
    Agent.get_and_update(pid, fn s ->
      {expired, kept} = Enum.split_with(s.entries, fn {_k, e} -> e.expires_at <= now end)
      {{:ok, length(expired)}, %{s | entries: Map.new(kept)}}
    end)
  end
end
