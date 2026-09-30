defmodule Kelix.Mod.Silo do
  @moduledoc """
  Store-and-forward for page-mode messages (chat-basic-plan C6, design in
  DESIGN-CHAT.md, *The Silo module*): a MESSAGE no device took is stored, and
  delivered when one of the recipient's devices registers.

      # in the chat script, once the relay found nobody
      case Kelix.Mod.Silo.store(sip_ctx, req, served: served) do
        {:stored, _} -> reply_message(202)
        {:error, :quota} -> reply_message(486)
        {:error, _down} -> reply_message(503)
      end

      # in the registrar script, after the 200 OK
      Kelix.Mod.Silo.flush(sip_ctx, req)

  The Silo does not know the registrar, and the registrar does not know the
  Silo: the registrar script sequences them, after its 200 OK, since a MESSAGE
  pushed while the client is still completing its registration is lost.

  ## Storage

  SQL only — MariaDB/MySQL or PostgreSQL — over a `Kelix.DB.Pool` of the
  module's own (`Kelix.Mod.Silo.Conn`), on an account of its own. The database
  is the only copy: no cache in front of it, a flush is one indexed query. The
  schema is the operator's to create (`Kelix.Mod.Silo.Schema`); the module
  refuses to start without it.

  ## Configuration

      [module.silo]
      driver    = "postgres"
      host      = "db.example.net"
      database  = "kelixip_silo"
      username  = "silo"
      pool_size = 5
      lease     = 300           # seconds a flush holds an AOR's backlog

      [module.silo.defaults]
      retention     = 259200    # 3 days, when neither sender nor script says
      max_retention = 604800    # the cap, whoever asks
      max_messages  = 200       # per AOR
      max_bytes     = 1048576   # per AOR

  The link keys are `Kelix.DB.Pool`'s, read over `[database]`.
  """
  use GenServer
  @behaviour Kelix.Module
  require Logger

  alias Kelix.Mod.Silo.{Delivery, Schema, Sweep}

  @conn Kelix.Mod.Silo.Conn
  @tasks Kelix.Mod.Silo.Tasks

  @defaults %{
    retention: 259_200,
    max_retention: 604_800,
    max_messages: 200,
    max_bytes: 1_048_576
  }
  @default_lease 300
  @page_timeout 32
  @sweep_ms 60_000
  @recheck_ms 5_000
  @retry_ms 1_000

  @config_keys ~w(module defaults lease) ++ Kelix.DB.Pool.link_keys()
  @default_keys ~w(retention max_retention max_messages max_bytes)

  @counters [
    :stored,
    :delivered,
    :accepted,
    :refused,
    :unreachable,
    :expired,
    :expired_undelivered
  ]

  # ── Kelix.Module behaviour ───────────────────────────────────────────────────

  @doc """
  The module's tree: its pool, the task supervisor its flushes run under, and
  the service holding the schema verdict and the counters — in that order,
  `:rest_for_one`, since each needs the one before it.
  """
  @impl Kelix.Module
  def child_spec(_name, config) do
    config = Kelix.DB.Pool.with_defaults(config)

    %{
      id: __MODULE__,
      type: :supervisor,
      start: {Kelix.Mod.Silo.Supervisor, :start_link, [config, service_opts(config)]}
    }
  end

  @doc false
  def service_opts(config) do
    [
      store: Kelix.Mod.Silo.Store.SQL,
      handle: Kelix.DB.SQL.handle(config, @conn),
      defaults: defaults(config),
      lease: config["lease"] || @default_lease
    ]
  end

  @impl Kelix.Module
  def validate_config(config) when is_map(config) do
    config = Kelix.DB.Pool.with_defaults(config)

    with :ok <- unknown_keys(config, @config_keys, "[module.silo]"),
         :ok <- Kelix.DB.Pool.validate(config, "silo"),
         :ok <- pos_int(config, "lease"),
         :ok <- validate_defaults(Map.get(config, "defaults", %{})) do
      d = defaults(config)

      if d.retention > d.max_retention,
        do: {:error, "defaults.retention must not exceed defaults.max_retention"},
        else: :ok
    end
  end

  def validate_config(_), do: {:error, "block must be a table"}

  defp validate_defaults(%{} = d) do
    with :ok <- unknown_keys(d, @default_keys, "[module.silo.defaults]") do
      Enum.reduce_while(@default_keys, :ok, fn key, :ok ->
        case pos_int(d, key) do
          :ok -> {:cont, :ok}
          error -> {:halt, error}
        end
      end)
    end
  end

  defp validate_defaults(_), do: {:error, "[module.silo.defaults] must be a table"}

  @impl Kelix.Module
  def describe(), do: %{version: "1.0", exports: [store: 2, store: 3, flush: 2]}

  @impl Kelix.Module
  def describe_control() do
    [
      %{
        name: "list",
        rest: {:get, "/messages/:aor"},
        rw: :r,
        args: [%{name: "aor", required: true, help: "user@domain"}],
        render: %{
          kind: :table,
          columns: ~w(id sender content_type size received expires_in served)
        },
        help:
          "The messages stored for an AOR — who sent what kind of content when, never the content"
      },
      %{
        name: "purge",
        rest: {:delete, "/messages/:aor"},
        rw: :w,
        args: [%{name: "aor", required: true, help: "user@domain"}],
        render: %{kind: :detail, fields: ~w(aor purged)},
        help: "Delete every message stored for an AOR"
      }
    ]
  end

  @impl Kelix.Module
  def handle_control(command, args) when command in ["list", "purge"] do
    with {:ok, domain, aor} <- parse_aor(control_arg(args, "aor")),
         {:ok, ctx} <- context() do
      control(command, ctx, domain, aor)
    end
  end

  def handle_control(command, _args), do: {:error, {:unknown_command, command}}

  defp control("list", ctx, domain, aor) do
    now = now()

    case ctx.store.list(ctx.handle, domain, aor, now) do
      {:ok, rows} ->
        {:ok,
         for row <- rows do
           %{
             id: row.id,
             sender: row.sender,
             content_type: row.content_type,
             size: row.size,
             received: DateTime.to_iso8601(DateTime.from_unix!(row.received_at)),
             expires_in: row.expires_at - now,
             served: Enum.join(row.served, " ")
           }
         end}

      {:error, _} ->
        {:error, :down}
    end
  end

  defp control("purge", ctx, domain, aor) do
    case ctx.store.purge(ctx.handle, domain, aor) do
      {:ok, n} ->
        Logger.info(
          module: __MODULE__,
          message: "silo: #{n} message(s) purged for #{aor}@#{domain}"
        )

        {:ok, %{aor: "#{aor}@#{domain}", purged: n}}

      {:error, _} ->
        {:error, :down}
    end
  end

  # REST merges the path parameter at the top level; kelictl hands it positionally.
  defp control_arg(args, name) do
    case args do
      %{^name => value} -> value
      %{"args" => [value | _]} -> value
      _ -> nil
    end
  end

  defp parse_aor(aor) when is_binary(aor) do
    case String.split(aor, "@") do
      [user, host] when user != "" and host != "" ->
        {:ok, Kelix.Domains.nominal(String.downcase(host)), String.downcase(user)}

      _ ->
        {:error, "the AOR must read user@domain, got #{inspect(aor)}"}
    end
  end

  defp parse_aor(_), do: {:error, "an AOR is required (user@domain)"}

  # ── Facades ──────────────────────────────────────────────────────────────────

  @doc """
  Store the MESSAGE `req` for its recipient — the user of its Request-URI, on
  the script's domain.

  Options: `:served`, the device keys that already have it (the `served` of
  `SBB.Page`'s outcome), which a flush will not serve again; `:retention`, in
  seconds.

  The retention is the sender's (`SIP.Msg.Ops.content_expires/1`: the lifetime
  it gave the content), else the script's `:retention`, else the module
  default — bounded by `max_retention`. The body is stored verbatim, CPIM
  wrapper included.

    * `{:stored, %{id: id, expires_in: seconds}}`;
    * `{:error, :quota}` — the AOR is over `max_messages` or `max_bytes`: the
      script picks the code;
    * `{:error, :expired}` — the sender gave the content no lifetime
      (`Expires: 0`): nothing to keep;
    * `{:error, :no_aor}` — the Request-URI names no user;
    * `{:error, :down}` — the module or its database does not answer.
  """
  @spec store(%SIP.Context{}, map, keyword) ::
          {:stored, %{id: integer, expires_in: non_neg_integer}}
          | {:error, :quota | :expired | :no_aor | :down}
  def store(%SIP.Context{} = sip_ctx, req, opts \\ []) when is_map(req) do
    SIP.Scenario.Monitor.note_command(:db, "silo_store")

    with {:ok, ctx} <- context(),
         {:ok, aor} <- recipient(req),
         {:ok, retention} <- granted_retention(req, opts, ctx.defaults) do
      domain = Kelix.Domains.nominal(sip_ctx.domain)
      now = now()
      row = row(req, domain, aor, now, retention, Keyword.get(opts, :served, []))

      with {:ok, usage} <- ctx.store.usage(ctx.handle, domain, aor, now),
           :ok <- within_quota(usage, row.size, ctx.defaults),
           {:ok, id} <- ctx.store.insert(ctx.handle, row) do
        count(:stored)
        {:stored, %{id: id, expires_in: retention}}
      else
        {:error, :quota} ->
          {:error, :quota}

        {:error, reason} ->
          Logger.warning(
            module: __MODULE__,
            message: "silo: store for #{aor}@#{domain} failed: #{short(reason)}"
          )

          {:error, :down}
      end
    end
  end

  @doc """
  Deliver what is stored for the AOR a REGISTER binds, to the devices it binds
  (`SIP.Msg.Ops.register_targets/1`), over the flow it came on. Call it after
  the 200 OK: `:ok` means the flush has **started**, in a task of the module's
  own; delivery is not the registrar's time. `{:error, :down}` when the module
  does not answer.

  A REGISTER binding nothing — an un-registration — flushes nothing.
  """
  @spec flush(%SIP.Context{}, map) :: :ok | {:error, :down}
  def flush(%SIP.Context{} = sip_ctx, req) when is_map(req) do
    SIP.Scenario.Monitor.note_command(:db, "silo_flush")

    with [_ | _] = targets <- SIP.Msg.Ops.register_targets(req),
         {user, _host} when is_binary(user) <- SIP.Msg.Ops.header_aor(req, :to),
         {:ok, ctx} <- context() do
      domain = Kelix.Domains.nominal(sip_ctx.domain)
      aor = String.downcase(user)
      delivery = delivery_ctx(ctx)

      case Task.Supervisor.start_child(@tasks, fn ->
             Delivery.run(delivery, domain, aor, targets)
           end) do
        {:ok, _pid} -> :ok
        _ -> {:error, :down}
      end
    else
      {:error, :down} = down -> down
      _nothing_to_flush -> :ok
    end
  end

  @doc """
  What `kelictl status` shows of the module: whether the schema was verified,
  and what this node did since it started — stored, delivered (a device's
  2xx), accepted (a device's 202), refused, unreachable, expired, and expired
  with no delivery at all.
  """
  @spec status() :: map | {:error, :down | :timeout}
  def status(), do: Kelix.Module.safe_call(__MODULE__, :status)

  @doc false
  @spec granted_retention(map, keyword, map) :: {:ok, pos_integer} | {:error, :expired}
  def granted_retention(req, opts, defaults) do
    asked =
      SIP.Msg.Ops.content_expires(req) || Keyword.get(opts, :retention) || defaults.retention

    case min(asked, defaults.max_retention) do
      0 -> {:error, :expired}
      granted -> {:ok, granted}
    end
  end

  @doc false
  @spec within_quota(%{count: integer, bytes: integer}, integer, map) :: :ok | {:error, :quota}
  def within_quota(%{count: count, bytes: bytes}, size, defaults) do
    if count + 1 > defaults.max_messages or bytes + size > defaults.max_bytes,
      do: {:error, :quota},
      else: :ok
  end

  defp recipient(req) do
    case SIP.Msg.Ops.target_aor(req) do
      user when is_binary(user) and user != "" -> {:ok, String.downcase(user)}
      _ -> {:error, :no_aor}
    end
  end

  # The message as delivery will rebuild it: the identities as header values,
  # the Content-Type, the carried-over headers, the body verbatim.
  defp row(req, domain, aor, now, retention, served) do
    body = SIP.Msg.Ops.body_string(req) || ""

    %{
      domain: domain,
      aor: aor,
      sender: header_text(req.from),
      recipient: header_text(req.to),
      content_type: to_string(Map.get(req, :contenttype) || "text/plain"),
      headers: Map.new(SIP.MsgTemplate.page_headers(req), fn {k, v} -> {k, to_string(v)} end),
      body: body,
      size: byte_size(body),
      received_at: now,
      expires_at: now + retention,
      served: served
    }
  end

  defp header_text(%SIP.Uri{} = uri), do: SIP.Uri.serialize(uri)
  defp header_text(value), do: to_string(value)

  defp context(), do: Kelix.Module.safe_call(__MODULE__, :context)

  defp delivery_ctx(ctx) do
    server = Process.whereis(__MODULE__)

    %{
      store: ctx.store,
      handle: ctx.handle,
      owner: ctx.owner,
      lease: ctx.lease,
      page_timeout: ctx.page_timeout,
      retry_ms: ctx.retry_ms,
      report: fn verdict -> if server, do: GenServer.cast(server, {:count, verdict}) end
    }
  end

  defp count(key), do: GenServer.cast(__MODULE__, {:count, key})

  # ── GenServer ────────────────────────────────────────────────────────────────

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(opts) do
    state = %{
      store: Keyword.fetch!(opts, :store),
      handle: Keyword.fetch!(opts, :handle),
      defaults: Keyword.get(opts, :defaults, @defaults),
      lease: Keyword.get(opts, :lease, @default_lease),
      page_timeout: Keyword.get(opts, :page_timeout, @page_timeout),
      retry_ms: Keyword.get(opts, :retry_ms, @retry_ms),
      sweep_ms: Keyword.get(opts, :sweep_ms, @sweep_ms),
      owner: owner(),
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

  # Absent or stale tables stop the module: the operator has DDL to run. A
  # database that does not answer does not — it is checked again until it does,
  # and the facades answer `:down` meanwhile.
  defp check_schema(state) do
    case state.store.check_schema(state.handle) do
      :ok ->
        if state.schema != :ok,
          do:
            Logger.info(
              module: __MODULE__,
              message: "silo: schema version #{Schema.version()} found"
            )

        %{state | schema: :ok}

      {:error, reason} ->
        if operator_fix?(reason) do
          Logger.error(module: __MODULE__, message: "silo: " <> Schema.refusal(reason))
          {:stop, {:schema, reason}}
        else
          unreachable(state, reason)
        end
    end
  end

  defp operator_fix?(:missing), do: true
  defp operator_fix?({:stale, _}), do: true
  defp operator_fix?(_), do: false

  defp unreachable(state, reason) do
    Logger.error(
      module: __MODULE__,
      message: "silo: the database does not answer (#{short(reason)}) — retrying"
    )

    Process.send_after(self(), :recheck, @recheck_ms)
    %{state | schema: :unchecked}
  end

  @impl true
  def handle_call(:context, _from, %{schema: :ok} = state) do
    {:reply,
     {:ok,
      Map.take(state, [:store, :handle, :defaults, :owner, :lease, :page_timeout, :retry_ms])},
     state}
  end

  def handle_call(:context, _from, state), do: {:reply, {:error, :down}, state}

  def handle_call(:status, _from, state),
    do: {:reply, Map.put(state.counters, :schema, state.schema), state}

  @impl true
  def handle_cast({:count, key}, state), do: {:noreply, bump(state, key, 1)}

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
        case Sweep.run(state.store, state.handle, now()) do
          {:ok, %{expired: n, undelivered: u}} ->
            state |> bump(:expired, n) |> bump(:expired_undelivered, u)

          {:error, reason} ->
            Logger.warning(module: __MODULE__, message: "silo: sweep failed: #{short(reason)}")
            state
        end
      else
        state
      end

    Process.send_after(self(), :sweep, state.sweep_ms)
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  defp bump(state, key, n) when is_map_key(state.counters, key),
    do: %{state | counters: Map.update!(state.counters, key, &(&1 + n))}

  defp bump(state, _key, _n), do: state

  # ── internals ────────────────────────────────────────────────────────────────

  # What this node's claims carry: the host and the OS process, so a lease left
  # by a node that restarted is not mistaken for its successor's.
  defp owner() do
    {:ok, host} = :inet.gethostname()
    "#{host}:#{System.pid()}"
  end

  defp defaults(config) do
    d = Map.get(config, "defaults", %{})

    for {key, default} <- @defaults, into: %{} do
      {key, Map.get(d, Atom.to_string(key), default)}
    end
  end

  defp unknown_keys(map, allowed, where) do
    case Map.keys(map) -- allowed do
      [] -> :ok
      extra -> {:error, "#{where}: unknown key(s): #{Enum.join(Enum.sort(extra), ", ")}"}
    end
  end

  defp pos_int(map, key) do
    case Map.get(map, key) do
      nil -> :ok
      n when is_integer(n) and n > 0 -> :ok
      _ -> {:error, "#{key} must be a positive integer"}
    end
  end

  defp short(reason), do: reason |> inspect() |> String.slice(0, 200)

  defp now, do: System.os_time(:second)
end

defmodule Kelix.Mod.Silo.Supervisor do
  @moduledoc """
  What `Kelix.Mod.Silo.child_spec/2` starts: the pool, the flushes' task
  supervisor, and the service. `:rest_for_one`: the service checks the schema
  through the pool, and the flushes read the service's context.
  """
  use Supervisor

  @spec start_link(map, keyword) :: Supervisor.on_start()
  def start_link(config, service_opts),
    do: Supervisor.start_link(__MODULE__, {config, service_opts}, name: __MODULE__)

  @impl true
  def init({config, service_opts}) do
    children = [
      Kelix.DB.Pool.child_spec(config, name: Kelix.Mod.Silo.Conn, label: "silo"),
      {Task.Supervisor, name: Kelix.Mod.Silo.Tasks},
      %{id: Kelix.Mod.Silo, start: {Kelix.Mod.Silo, :start_link, [service_opts]}}
    ]

    Supervisor.init(children, strategy: :rest_for_one)
  end
end
