defmodule Kelix.Test.SiloMemoryStore do
  @moduledoc """
  The Silo's storage in memory, **for the test suite only** (chat-basic-plan
  C6, decision 10): the logic above storage — retention, quotas, the served
  set, the lease — runs on it with no database. The handle is the pid of the
  Agent holding the rows.

  It honours the same contract as `Kelix.Mod.Silo.Store.SQL`, and the contract
  suite (`silo_store_contract.exs`) runs on both.
  """
  @behaviour Kelix.Mod.Silo.Store

  def start_link(opts \\ []) do
    schema = Keyword.get(opts, :schema, :ok)
    Agent.start_link(fn -> %{next: 1, messages: %{}, served: %{}, schema: schema} end)
  end

  @doc "Make the next calls fail as a database that does not answer would."
  def set_down(pid, down?), do: Agent.update(pid, &Map.put(&1, :down, down?))

  @impl true
  def check_schema(pid) do
    case Agent.get(pid, & &1.schema) do
      :ok -> :ok
      other -> {:error, other}
    end
  end

  @impl true
  def usage(pid, domain, aor, now) do
    guarded(pid, fn s ->
      live = live(s, domain, aor, now)
      {:ok, %{count: length(live), bytes: Enum.sum(Enum.map(live, & &1.size))}}
    end)
  end

  @impl true
  def insert(pid, row) do
    guarded_update(pid, fn s ->
      id = s.next

      message =
        row |> Map.delete(:served) |> Map.merge(%{id: id, claimed_by: nil, claimed_until: nil})

      s = %{
        s
        | next: id + 1,
          messages: Map.put(s.messages, id, message),
          served: Map.put(s.served, id, Enum.uniq(row.served))
      }

      {{:ok, id}, s}
    end)
  end

  @impl true
  def claim(pid, domain, aor, owner, now, until) do
    guarded_update(pid, fn s ->
      {free, held} =
        s
        |> live(domain, aor, now)
        |> Enum.split_with(&(&1.claimed_until == nil or &1.claimed_until <= now))

      messages =
        Enum.reduce(free, s.messages, fn m, acc ->
          Map.put(acc, m.id, %{m | claimed_by: owner, claimed_until: until})
        end)

      claimed = Enum.map(free, &(&1 |> view() |> Map.put(:served, Map.get(s.served, &1.id, []))))
      {{:ok, claimed, length(held)}, %{s | messages: messages}}
    end)
  end

  @impl true
  def serve(pid, id, device, _now) do
    guarded_update(pid, fn s ->
      served = Map.update(s.served, id, [device], &Enum.uniq(&1 ++ [device]))
      {:ok, %{s | served: served}}
    end)
  end

  @impl true
  def release(pid, ids, owner) do
    guarded_update(pid, fn s ->
      messages =
        Enum.reduce(ids, s.messages, fn id, acc ->
          case acc do
            %{^id => %{claimed_by: ^owner} = m} ->
              Map.put(acc, id, %{m | claimed_by: nil, claimed_until: nil})

            _ ->
              acc
          end
        end)

      {:ok, %{s | messages: messages}}
    end)
  end

  @impl true
  def sweep(pid, now) do
    guarded_update(pid, fn s ->
      expired = for {id, m} <- s.messages, m.expires_at <= now, do: {id, m}
      ids = Enum.map(expired, &elem(&1, 0))

      swept =
        for {id, m} <- Enum.sort(expired),
            do: %{domain: m.domain, served: Map.get(s.served, id, []) != []}

      {{:ok, swept}, %{s | messages: Map.drop(s.messages, ids), served: Map.drop(s.served, ids)}}
    end)
  end

  @impl true
  def list(pid, domain, aor, now) do
    guarded(pid, fn s ->
      {:ok,
       for m <- live(s, domain, aor, now) do
         m
         |> Map.take([:id, :sender, :content_type, :size, :received_at, :expires_at])
         |> Map.put(:served, Map.get(s.served, m.id, []))
       end}
    end)
  end

  @impl true
  def stats(pid, now) do
    guarded(pid, fn s ->
      live = s.messages |> Map.values() |> Enum.filter(&(&1.expires_at > now))

      {:ok,
       %{
         messages: length(live),
         aors: live |> Enum.map(&{&1.domain, &1.aor}) |> Enum.uniq() |> length(),
         bytes: live |> Enum.map(& &1.size) |> Enum.sum(),
         claimed: Enum.count(live, &(&1.claimed_until != nil and &1.claimed_until > now))
       }}
    end)
  end

  @impl true
  def purge(pid, domain, aor) do
    guarded_update(pid, fn s ->
      ids = for {id, m} <- s.messages, m.domain == domain and m.aor == aor, do: id

      {{:ok, length(ids)},
       %{s | messages: Map.drop(s.messages, ids), served: Map.drop(s.served, ids)}}
    end)
  end

  defp live(s, domain, aor, now) do
    s.messages
    |> Map.values()
    |> Enum.filter(&(&1.domain == domain and &1.aor == aor and &1.expires_at > now))
    |> Enum.sort_by(& &1.id)
  end

  defp view(m),
    do:
      Map.take(m, [
        :id,
        :sender,
        :recipient,
        :content_type,
        :headers,
        :body,
        :received_at,
        :expires_at
      ])

  defp guarded(pid, fun) do
    Agent.get(pid, fn s -> if Map.get(s, :down), do: {:error, :down}, else: fun.(s) end)
  end

  defp guarded_update(pid, fun) do
    Agent.get_and_update(pid, fn s ->
      if Map.get(s, :down), do: {{:error, :down}, s}, else: fun.(s)
    end)
  end
end
