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

  ## Storage

  SQL — MariaDB/MySQL or PostgreSQL — over a `Kelix.DB.Pool` of the module's own
  (`Kelix.Mod.Conversation.Conn`), so a conversation hibernated on one node
  wakes on another and survives a restart. The schema is the operator's to
  create (`packaging/sql/conversation/`); the module refuses to start without
  it, and answers as if nothing were kept while its base does not answer.

  ## Configuration

      [module.conversation]
      driver      = "postgres"
      host        = "db.example.net"
      database    = "kelixip"
      username    = "conversation"
      default_ttl = 86400      # seconds, when the script names none
      max_ttl     = 604800     # the cap, whoever asks

  The link keys are `Kelix.DB.Pool`'s, read over `[database]`. The granted TTL
  is the script's, bounded by `max_ttl`. A sweep deletes what expired;
  `wake/1` never returns an expired snapshot either.

  `kelictl conversation list` shows what is set aside — its parties, the state
  it resumes in, when it expires — never the data it kept. `kelictl
  conversation show` shows the database link, how many conversations are set
  aside, and what this node hibernated, woke and swept since it started.
  """
  use GenServer
  @behaviour Kelix.Module
  require Logger

  @conn Kelix.Mod.Conversation.Conn
  @default_ttl 86_400
  @max_ttl 604_800
  @sweep_ms 60_000
  @recheck_ms 5_000
  @config_keys ~w(module default_ttl max_ttl) ++ Kelix.DB.Pool.link_keys()
  @counters [:hibernated, :woken, :expired]

  @type key :: Kelix.Mod.Conversation.Store.key()
  @type snapshot :: %{
          required(:script) => String.t(),
          required(:resume) => atom,
          required(:data) => map,
          optional(:ttl) => pos_integer | nil
        }

  # ── Kelix.Module behaviour ───────────────────────────────────────────────────

  @doc """
  The module's tree: its pool, then the service holding the schema verdict and
  the TTLs (`:rest_for_one`: the service checks the schema through the pool).
  """
  @impl Kelix.Module
  def child_spec(_name, config) do
    config = Kelix.DB.Pool.with_defaults(config)

    service =
      [store: Kelix.Mod.Conversation.Store.SQL, handle: Kelix.DB.SQL.handle(config, @conn)] ++
        ttls(config)

    %{
      id: __MODULE__,
      type: :supervisor,
      start:
        {Supervisor, :start_link,
         [
           [
             Kelix.DB.Pool.child_spec(config, name: @conn, label: "conversation"),
             %{id: __MODULE__, start: {__MODULE__, :start_link, [service]}}
           ],
           [strategy: :rest_for_one, name: Kelix.Mod.Conversation.Supervisor]
         ]}
    }
  end

  @impl Kelix.Module
  def validate_config(config) when is_map(config) do
    config = Kelix.DB.Pool.with_defaults(config)

    with :ok <- reject_unknown_keys(config),
         :ok <- Kelix.DB.Pool.validate(config, "conversation"),
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
  def describe(), do: %{version: "2.0", exports: [hibernate: 2, wake: 1]}

  @impl Kelix.Module
  def describe_control() do
    [
      %{
        name: "show",
        rest: {:get, "/db"},
        rw: :r,
        args: [],
        render: %{
          kind: :detail,
          fields: ~w(state schema host port database username driver tls certificate transport
                     pool_size query_timeout_ms error conversations domains default_ttl max_ttl
                     since_start)
        },
        help:
          "The conversation store's database link — does it answer, where, encrypted? — " <>
            "how many conversations are set aside, and what this node did since it started"
      },
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
  def handle_control("list", _args) do
    case list() do
      rows when is_list(rows) -> {:ok, rows}
      {:error, _} = error -> error
    end
  end

  # `show` never fails on a base that is down: "down, and here is why" is its
  # answer, and the counters of this node are there whatever the base says.
  def handle_control("show", _args) do
    link = Kelix.DB.Pool.describe(@conn, @conn, "conversation", &held/0, show_timeout())

    case Kelix.Module.safe_call(__MODULE__, :status) do
      %{} = status -> {:ok, Map.merge(link, status)}
      {:error, _} -> {:ok, link}
    end
  end

  def handle_control(command, _args), do: {:error, {:unknown_command, command}}

  defp held() do
    with {:ok, ctx} <- context(), do: ctx.store.stats(ctx.handle, now())
  end

  defp show_timeout(),
    do: Kelix.ModuleRegistry.call_timeout(__MODULE__, Kelix.Module.default_call_timeout_ms())

  # ── Facades ──────────────────────────────────────────────────────────────────

  @doc """
  Keep `snapshot` under `key`. `{:ok, granted_ttl}` — the TTL asked for, else
  `default_ttl`, bounded by `max_ttl` — or `{:error, reason}`. A conversation
  already hibernated under `key` is replaced: it is the same two parties.
  """
  @spec hibernate(key, snapshot) :: {:ok, pos_integer} | {:error, term}
  def hibernate({_d, _r, _f, _t} = key, %{script: script, resume: resume, data: data} = snapshot)
      when is_atom(resume) and is_map(data) do
    with {:ok, ctx} <- context() do
      ttl = min(Map.get(snapshot, :ttl) || ctx.default_ttl, ctx.max_ttl)
      entry = %{script: script, resume: resume, data: data, ttl: ttl, expires_at: now() + ttl}

      case ctx.store.put(ctx.handle, key, entry) do
        :ok ->
          count(:hibernated)
          {:ok, ttl}

        {:error, reason} ->
          Logger.warning(
            module: __MODULE__,
            message: "conversation: not hibernated, the store failed: #{short(reason)}"
          )

          {:error, :down}
      end
    end
  end

  @doc """
  Take the conversation hibernated under `key`: `{:ok, snapshot}`, and it is no
  longer kept, or `:none` — also when the module or its base does not answer,
  in which case the MESSAGE starts a new conversation.
  """
  @spec wake(key) :: {:ok, snapshot} | :none
  def wake({_d, _r, _f, _t} = key) do
    with {:ok, ctx} <- context(),
         {:ok, entry} <- ctx.store.take(ctx.handle, key, now()) do
      count(:woken)
      {:ok, Map.delete(entry, :expires_at)}
    else
      {:error, reason} when reason not in [:down, :timeout] ->
        Logger.warning(
          module: __MODULE__,
          message: "conversation: could not be woken, the store failed: #{short(reason)}"
        )

        :none

      _none_or_down ->
        :none
    end
  end

  @doc "What is hibernated, one row per conversation (`kelictl conversation list`)."
  @spec list() :: [map] | {:error, :down | :timeout}
  def list() do
    now = now()

    with {:ok, ctx} <- context() do
      case ctx.store.list(ctx.handle, now) do
        {:ok, rows} ->
          for row <- rows do
            row |> Map.delete(:expires_at) |> Map.put(:expires_in, row.expires_at - now)
          end

        {:error, _} ->
          {:error, :down}
      end
    end
  end

  defp context(), do: Kelix.Module.safe_call(__MODULE__, :context)

  defp count(key), do: GenServer.cast(__MODULE__, {:count, key, 1})

  # ── GenServer ────────────────────────────────────────────────────────────────

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(opts) do
    state = %{
      store: Keyword.fetch!(opts, :store),
      handle: Keyword.fetch!(opts, :handle),
      default_ttl: Keyword.get(opts, :default_ttl, @default_ttl),
      max_ttl: Keyword.get(opts, :max_ttl, @max_ttl),
      sweep_ms: Keyword.get(opts, :sweep_ms, @sweep_ms),
      schema: :unchecked,
      counters: Map.new(@counters, &{&1, 0})
    }

    case check_schema(state) do
      {:stop, reason} ->
        {:stop, reason}

      state ->
        Process.send_after(self(), :sweep, state.sweep_ms)
        {:ok, state}
    end
  end

  # Absent or stale tables stop the module: the operator has DDL to run. A base
  # that does not answer does not — it is checked again until it does.
  defp check_schema(state) do
    case state.store.check_schema(state.handle) do
      :ok ->
        %{state | schema: :ok}

      {:error, reason} when reason == :missing or elem(reason, 0) == :stale ->
        Logger.error(
          module: __MODULE__,
          message:
            "conversation: the schema is #{if reason == :missing, do: "missing", else: "stale"} " <>
              "(#{inspect(reason)}) — create or upgrade it with the DDL in " <>
              "/usr/share/kelixip/sql/conversation/; the module never runs DDL itself"
        )

        {:stop, {:schema, reason}}

      {:error, reason} ->
        Logger.error(
          module: __MODULE__,
          message: "conversation: the database does not answer (#{short(reason)}) — retrying"
        )

        Process.send_after(self(), :recheck, @recheck_ms)
        %{state | schema: :unchecked}
    end
  end

  @impl true
  def handle_call(:context, _from, %{schema: :ok} = state),
    do: {:reply, {:ok, Map.take(state, [:store, :handle, :default_ttl, :max_ttl])}, state}

  def handle_call(:context, _from, state), do: {:reply, {:error, :down}, state}

  def handle_call(:status, _from, state) do
    {:reply,
     %{
       schema: state.schema,
       default_ttl: state.default_ttl,
       max_ttl: state.max_ttl,
       since_start: state.counters
     }, state}
  end

  def handle_call({:reload, opts}, _from, state),
    do: {:reply, :ok, %{state | default_ttl: opts[:default_ttl], max_ttl: opts[:max_ttl]}}

  @impl true
  def handle_cast({:count, key, n}, state), do: {:noreply, bump(state, key, n)}

  @impl true
  def handle_info(:recheck, %{schema: :unchecked} = state) do
    case check_schema(state) do
      {:stop, reason} -> {:stop, reason, state}
      state -> {:noreply, state}
    end
  end

  def handle_info(:sweep, state) do
    state =
      if state.schema == :ok do
        case state.store.sweep(state.handle, now()) do
          {:ok, 0} ->
            state

          {:ok, swept} ->
            Logger.info(
              module: __MODULE__,
              message: "#{swept} hibernated conversation(s) expired"
            )

            bump(state, :expired, swept)

          {:error, reason} ->
            Logger.warning(
              module: __MODULE__,
              message: "conversation: sweep failed: #{short(reason)}"
            )

            state
        end
      else
        state
      end

    Process.send_after(self(), :sweep, state.sweep_ms)
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  defp bump(state, key, n), do: %{state | counters: Map.update!(state.counters, key, &(&1 + n))}

  # ── internals ────────────────────────────────────────────────────────────────

  # Wall-clock seconds, not monotonic: what the rows hold, and what a
  # conversation hibernated on another node, or before a restart, is compared
  # against.
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

  defp short(reason), do: reason |> inspect() |> String.slice(0, 200)
end
