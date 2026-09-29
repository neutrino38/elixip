defmodule Kelix.Mod.Conversation do
  @moduledoc """
  Hibernated chat conversations (chat-basic-plan, C3d): what a chat script set
  aside with `hibernate/1`, kept until the next MESSAGE between the same two
  parties wakes it, or until its TTL runs out.

  A conversation is set aside **by the node**, not by the script: the instance
  asks `Kelix.InstancePool`, which knows its key, and the pool calls
  `hibernate/2` here. Waking is the pool's too — a MESSAGE that finds no live
  instance asks `wake/1` before spawning one. The key is
  `{domain, rule, From AOR, To AOR}` (`Kelix.Conversations.hibernation_key/1`):
  without the flow, since a conversation set aside outlives the one it came in
  on.

  A snapshot is `%{script, resume, data, ttl}`: the script it belongs to, the
  state to resume in, the appdata it kept (plain data, checked by `hibernate/1`)
  and the TTL it asked for.

  ## Configuration

      [module.conversation]
      default_ttl = 86400      # seconds, when the script names none
      max_ttl     = 604800     # the cap, whoever asks

  The granted TTL is the script's, bounded by `max_ttl`. A sweep deletes what
  expired; `wake/1` never returns an expired snapshot either.

  ## Storage

  In memory (ETS, owned by this module's process) until `Kelix.DB.Pool` lands
  (chat-basic-plan, C5): a restart loses what was hibernated. The SQL store —
  a conversation hibernated on one node waking on another — comes with C5,
  behind the same two facades.

  `kelictl conversation list` shows what is set aside — its parties, the state
  it resumes in, when it expires — never the data it kept.
  """
  use GenServer
  @behaviour Kelix.Module
  require Logger

  @table __MODULE__
  @default_ttl 86_400
  @max_ttl 604_800
  @sweep_ms 60_000
  @config_keys ~w(module default_ttl max_ttl)

  @type key :: {String.t(), String.t() | :default, String.t(), String.t()}
  @type snapshot :: %{
          required(:script) => String.t(),
          required(:resume) => atom,
          required(:data) => map,
          optional(:ttl) => pos_integer | nil
        }

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  # ── Kelix.Module behaviour ───────────────────────────────────────────────────

  @impl Kelix.Module
  def child_spec(_name, config),
    do: %{id: __MODULE__, start: {__MODULE__, :start_link, [ttls(config)]}}

  @impl Kelix.Module
  def validate_config(config) when is_map(config) do
    with :ok <- reject_unknown_keys(config),
         :ok <- pos_int(config, "default_ttl"),
         :ok <- pos_int(config, "max_ttl") do
      opts = ttls(config)

      if opts[:default_ttl] > opts[:max_ttl],
        do: {:error, "default_ttl must not exceed max_ttl"},
        else: :ok
    end
  end

  def validate_config(_), do: {:error, "block must be a table"}

  @impl Kelix.Module
  def reload(_name, config), do: GenServer.call(__MODULE__, {:reload, ttls(config)})

  @impl Kelix.Module
  def describe(), do: %{version: "1.0", exports: [hibernate: 2, wake: 1]}

  @impl Kelix.Module
  def describe_control() do
    [
      %{
        name: "list",
        rest: {:get, "/conversations"},
        rw: :r,
        args: [],
        render: %{kind: :table, columns: ~w(domain rule from to script resume expires_in)},
        help: "The hibernated chat conversations — never the data they kept"
      }
    ]
  end

  @impl Kelix.Module
  def handle_control("list", _args), do: {:ok, list()}
  def handle_control(command, _args), do: {:error, {:unknown_command, command}}

  # ── Facades ──────────────────────────────────────────────────────────────────

  @doc """
  Keep `snapshot` under `key`. `{:ok, granted_ttl}` — the TTL asked for, else
  `default_ttl`, bounded by `max_ttl` — or `{:error, reason}`. A conversation
  already hibernated under `key` is replaced: it is the same two parties.
  """
  @spec hibernate(key, snapshot) :: {:ok, pos_integer} | {:error, term}
  def hibernate({_d, _r, _f, _t} = key, %{script: _, resume: resume, data: data} = snapshot)
      when is_atom(resume) and is_map(data),
      do: Kelix.Module.safe_call(__MODULE__, {:hibernate, key, snapshot})

  @doc """
  Take the conversation hibernated under `key`: `{:ok, snapshot}`, and it is no
  longer kept, or `:none`.
  """
  @spec wake(key) :: {:ok, snapshot} | :none
  def wake({_d, _r, _f, _t} = key) do
    case Kelix.Module.safe_call(__MODULE__, {:wake, key}) do
      {:ok, snapshot} -> {:ok, snapshot}
      _none_or_down -> :none
    end
  end

  @doc "What is hibernated, one row per conversation (`kelictl conversation list`)."
  @spec list() :: [map] | {:error, :down | :timeout}
  def list(), do: Kelix.Module.safe_call(__MODULE__, :list)

  # ── GenServer ────────────────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    table = :ets.new(@table, [:set, :private])
    schedule_sweep(Keyword.get(opts, :sweep_ms, @sweep_ms))

    {:ok,
     %{
       table: table,
       default_ttl: Keyword.get(opts, :default_ttl, @default_ttl),
       max_ttl: Keyword.get(opts, :max_ttl, @max_ttl),
       sweep_ms: Keyword.get(opts, :sweep_ms, @sweep_ms)
     }}
  end

  @impl true
  def handle_call({:hibernate, key, snapshot}, _from, state) do
    ttl = min(Map.get(snapshot, :ttl) || state.default_ttl, state.max_ttl)
    entry = snapshot |> Map.put(:ttl, ttl) |> Map.put(:expires_at, now() + ttl)
    :ets.insert(state.table, {key, entry})
    {:reply, {:ok, ttl}, state}
  end

  def handle_call({:wake, key}, _from, state) do
    now = now()

    case :ets.take(state.table, key) do
      [{^key, %{expires_at: at} = entry}] when at > now ->
        {:reply, {:ok, Map.delete(entry, :expires_at)}, state}

      _none_or_expired ->
        {:reply, :none, state}
    end
  end

  def handle_call(:list, _from, state) do
    now = now()

    rows =
      for {{domain, rule, from, to}, entry} <- :ets.tab2list(state.table),
          entry.expires_at > now do
        %{
          domain: domain,
          rule: rule,
          from: from,
          to: to,
          script: entry.script,
          resume: entry.resume,
          expires_in: entry.expires_at - now
        }
      end

    {:reply, Enum.sort_by(rows, &{&1.domain, &1.from, &1.to}), state}
  end

  def handle_call({:reload, opts}, _from, state),
    do: {:reply, :ok, %{state | default_ttl: opts[:default_ttl], max_ttl: opts[:max_ttl]}}

  @impl true
  def handle_info(:sweep, state) do
    now = now()

    swept =
      :ets.select_delete(state.table, [
        {{:_, %{expires_at: :"$1"}}, [{:"=<", :"$1", now}], [true]}
      ])

    if swept > 0,
      do: Logger.info(module: __MODULE__, message: "#{swept} hibernated conversation(s) expired")

    schedule_sweep(state.sweep_ms)
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ── internals ────────────────────────────────────────────────────────────────

  defp schedule_sweep(ms), do: Process.send_after(self(), :sweep, ms)

  # Wall-clock seconds, not monotonic: what the SQL store will write, and what a
  # conversation hibernated before a restart will be compared against.
  defp now(), do: System.os_time(:second)

  defp ttls(config),
    do: [
      default_ttl: Map.get(config, "default_ttl", @default_ttl),
      max_ttl: Map.get(config, "max_ttl", @max_ttl)
    ]

  defp reject_unknown_keys(config) do
    case Map.keys(config) -- @config_keys do
      [] -> :ok
      extra -> {:error, "unknown key(s): #{Enum.join(Enum.sort(extra), ", ")}"}
    end
  end

  defp pos_int(config, key) do
    case Map.get(config, key) do
      nil -> :ok
      n when is_integer(n) and n > 0 -> :ok
      _ -> {:error, "#{key} must be a positive integer (seconds)"}
    end
  end
end
