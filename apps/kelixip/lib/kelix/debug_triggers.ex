defmodule Kelix.DebugTriggers do
  @moduledoc """
  Debug triggers: rules that journal the next runs of a script
  (debug-triggers-plan.md).

  A rule is attached to one script served by one domain — **one rule per
  `{domain, script}`**, a new one replacing the old — and says: journal the next
  `count` runs, for the next `duration`, optionally only the runs whose starting
  request matches **one** filter:

  - `caller` — a user part of `From` or of `P-Asserted-Identity`
    (`SIP.Msg.Ops.caller_users/1`);
  - `callee` — the user part of `To` or of the Request-URI
    (`SIP.Msg.Ops.callee_users/1`);
  - `source` — the address the request came from, an IP or a CIDR prefix
    (`SIP.Msg.Ops.source_ip/1`).

  User parts are compared case-insensitively, nothing else is normalised. A run
  with no request (`kelictl run`) only matches a rule without filter.

  A rule ends when its last run is claimed (`:exhausted`) or when its window
  closes (`:expired`), whichever comes first, and is then removed. It is also
  removed by an operator (`:removed`) and when its domain stops serving its
  script (`:orphan`, `prune/1`).

  **The pool asks, the store decides.** `claim/3` is called by
  `Kelix.InstancePool` once a slot and the script are secured: it answers
  `{:journal, rule}` and counts the run, or `:no`. The rules are mirrored in a
  protected ETS table, so a pair without a rule costs one lookup in the caller's
  process; only a matching run reaches the server, which re-checks and counts it,
  so N runs are N runs under concurrency.

  **Kept in a state file**, `debug_triggers.json` next to `domains.toml`
  (`:kelixip, :debug_triggers_path` overrides it), rewritten atomically on every
  change: set, remove, claim, end. A rule of a month survives a restart; one
  that expired while the node was down is dropped at boot. `set/4` and
  `remove/3` fail if the file cannot be written, and change nothing; a claim or
  an end that cannot be written is logged and kept in memory — a call is never
  refused because of a debug rule. Without a `domains.toml` path (tests, a
  checkout) the rules live in memory only.

  **Pushes.** `subscribe/1` returns `%{rules: [rule]}` and then sends
  `{:kelix_debug_triggers, {:upsert, rule}}` on every set and claim, and
  `{:kelix_debug_triggers, {:remove, {domain, script}, reason}}` when a rule ends.

  Every rule handed out carries `seconds_left`, computed when it is handed out.
  """
  use GenServer
  require Logger

  alias SIP.Msg.Ops
  alias SIP.NetUtils

  @typedoc "A filter: none, or exactly one criterion."
  @type filter :: nil | %{caller: String.t()} | %{callee: String.t()} | %{source: String.t()}

  @typedoc "A rule as every reader receives it."
  @type rule :: %{
          domain: String.t(),
          script: String.t(),
          total: pos_integer,
          remaining: pos_integer,
          filter: filter,
          created_at: DateTime.t(),
          expires_at: DateTime.t(),
          created_by: String.t() | nil,
          seconds_left: non_neg_integer
        }

  @type end_reason :: :exhausted | :expired | :removed | :orphan

  # Decision 3: a duration, not a calendar. A month is 30 days.
  @units %{"m" => 60, "h" => 3_600, "d" => 86_400, "mo" => 2_592_000}
  @max_duration 12 * 2_592_000

  # `Process.send_after/3` takes at most 2^32 - 1 ms (~49 days): a long rule is
  # looked at once a day until its end is near.
  @max_timer_ms 86_400_000

  @file_version 1

  # ── API ──────────────────────────────────────────────────────────────────────

  @doc """
  Options: `name:` (default `#{inspect(__MODULE__)}`, `nil` for an unregistered
  store a test drives by pid), `path:` (the state file; default from the app env,
  `nil` for memory only), `max_runs:` (default `[debug] max_traces`),
  `snapshot:` (a 0-arity function answering the `Kelix.Domains` snapshot).
  """
  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts \\ []) do
    case Keyword.get(opts, :name, __MODULE__) do
      nil -> GenServer.start_link(__MODULE__, opts)
      name -> GenServer.start_link(__MODULE__, opts, name: name)
    end
  end

  @doc """
  Set the rule of `{domain, script}`, replacing any. `spec` holds `:count` (runs,
  1 to `[debug] max_traces`), `:duration` (`"30m"`, `"2h"`, `"7d"`, `"3mo"`, or
  seconds; 12 months at most) and an optional `:filter` (`%{caller: "1001"}`,
  `%{callee: …}`, `%{source: "10.1.0.0/16"}`; string keys accepted).

  The domain must exist (its canonical name) and serve the script. `admin` is
  recorded as `created_by`.
  """
  @spec set(String.t(), String.t(), map | keyword, String.t() | nil, GenServer.server()) ::
          {:ok, rule} | {:error, term}
  def set(domain, script, spec, admin \\ nil, server \\ __MODULE__)
      when is_binary(domain) and is_binary(script),
      do: GenServer.call(server, {:set, domain, script, Map.new(spec), admin})

  @doc "Remove the rule of `{domain, script}`."
  @spec remove(String.t(), String.t(), String.t() | nil, GenServer.server()) ::
          :ok | {:error, :not_found | {:write_failed, term}}
  def remove(domain, script, admin \\ nil, server \\ __MODULE__),
    do: GenServer.call(server, {:remove, domain, script, admin})

  @doc "The rule of `{domain, script}`."
  @spec get(String.t(), String.t(), GenServer.server()) :: {:ok, rule} | {:error, :not_found}
  def get(domain, script, server \\ __MODULE__),
    do: GenServer.call(server, {:get, domain, script})

  @doc "Every rule, the one ending first first."
  @spec list(GenServer.server()) :: [rule]
  def list(server \\ __MODULE__), do: GenServer.call(server, :list)

  @doc """
  Called by the pool for a run about to start: `{:journal, rule}` — the run is
  counted, `rule` is what is left of it — or `:no`. `request` is the request that
  starts the run, `nil` for a run no request started.

  Never raises and never blocks on a missing store: a debug rule cannot refuse a
  call.
  """
  @spec claim(String.t(), String.t(), map | nil, GenServer.server()) :: {:journal, rule} | :no
  def claim(domain, script, request, server \\ __MODULE__)

  def claim(domain, script, request, server) when is_atom(server) do
    case lookup(server, {domain, script}) do
      [{_key, rule, matcher}] ->
        if live?(rule, now_ms()) and matches?(matcher, request),
          do: call_claim(server, domain, script, request),
          else: :no

      _none ->
        :no
    end
  end

  def claim(domain, script, request, server),
    do: call_claim(server, domain, script, request)

  @doc """
  Remove the rules whose domain no longer exists or no longer serves their script
  (decision 5) — called after every snapshot `Kelix.Domains` accepts. Answers the
  keys removed.
  """
  @spec prune(Kelix.Domains.t(), GenServer.server()) :: [{String.t(), String.t()}]
  def prune(snapshot, server \\ __MODULE__), do: GenServer.call(server, {:prune, snapshot})

  @doc """
  Subscribe `pid`: returns `%{rules: [rule]}` and registers `pid` in the same
  call. `pid` is monitored and dropped when it dies.
  """
  @spec subscribe(pid, GenServer.server()) :: %{rules: [rule]}
  def subscribe(pid, server \\ __MODULE__), do: GenServer.call(server, {:subscribe, pid})

  @doc "Stop a subscription started by `subscribe/1`."
  @spec unsubscribe(pid, GenServer.server()) :: :ok
  def unsubscribe(pid, server \\ __MODULE__), do: GenServer.call(server, {:unsubscribe, pid})

  @doc """
  A duration as seconds: `"30m"`, `"2h"`, `"7d"`, `"3mo"` (a month is 30 days),
  or a positive integer of seconds. 12 months at most.
  """
  @spec parse_duration(String.t() | pos_integer) :: {:ok, pos_integer} | {:error, term}
  def parse_duration(seconds) when is_integer(seconds) and seconds > 0 do
    if seconds <= @max_duration,
      do: {:ok, seconds},
      else: {:error, {:bad_duration, seconds}}
  end

  def parse_duration(text) when is_binary(text) do
    with [_, n, unit] <- Regex.run(~r/^\s*(\d+)\s*(mo|m|h|d)\s*$/i, text),
         {n, ""} when n > 0 <- Integer.parse(n) do
      parse_duration(n * Map.fetch!(@units, String.downcase(unit)))
    else
      {:error, _} = err -> err
      _ -> {:error, {:bad_duration, text}}
    end
  end

  def parse_duration(other), do: {:error, {:bad_duration, other}}

  @doc "Where the rules are kept on this node, `nil` for memory only."
  @spec default_path() :: String.t() | nil
  def default_path() do
    case Application.get_env(:kelixip, :debug_triggers_path) do
      nil ->
        case Application.get_env(:kelixip, :domains_path) do
          nil -> nil
          domains -> Path.join(Path.dirname(domains), "debug_triggers.json")
        end

      path ->
        path
    end
  end

  # ── server ──────────────────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    table =
      case Keyword.get(opts, :name, __MODULE__) do
        nil -> :ets.new(__MODULE__, [:set, :protected, read_concurrency: true])
        name -> :ets.new(name, [:set, :protected, :named_table, read_concurrency: true])
      end

    state = %{
      table: table,
      path: Keyword.get_lazy(opts, :path, &default_path/0),
      max_runs: Keyword.get_lazy(opts, :max_runs, &default_max_runs/0),
      snapshot: Keyword.get(opts, :snapshot, &Kelix.Domains.current/0),
      rules: %{},
      timers: %{},
      subscribers: %{}
    }

    {:ok, load(state)}
  end

  @impl true
  def handle_call({:set, domain, script, spec, admin}, _from, state) do
    with :ok <- check_target(state, domain, script),
         {:ok, count} <- check_count(Map.get(spec, :count), state.max_runs),
         {:ok, seconds} <- parse_duration(Map.get(spec, :duration)),
         {:ok, filter} <- check_filter(Map.get(spec, :filter)) do
      now = DateTime.utc_now() |> DateTime.truncate(:second)

      rule = %{
        domain: domain,
        script: script,
        total: count,
        remaining: count,
        filter: filter,
        created_at: now,
        expires_at: DateTime.add(now, seconds, :second),
        created_by: admin
      }

      key = {domain, script}
      next = Map.put(state.rules, key, rule)

      case persist(state, next) do
        :ok ->
          state = state |> put_rule(key, rule) |> arm(key, rule)
          push(state, {:upsert, view(rule)})

          Logger.info(
            module: __MODULE__,
            message:
              "debug trigger #{domain}/#{script} set by admin=#{admin || "unknown"}: " <>
                "#{count} runs until #{DateTime.to_iso8601(rule.expires_at)}" <>
                filter_text(filter)
          )

          {:reply, {:ok, view(rule)}, state}

        {:error, _} = err ->
          {:reply, err, state}
      end
    else
      {:error, _} = err -> {:reply, err, state}
    end
  end

  def handle_call({:remove, domain, script, admin}, _from, state) do
    key = {domain, script}

    case Map.fetch(state.rules, key) do
      :error ->
        {:reply, {:error, :not_found}, state}

      {:ok, _rule} ->
        case persist(state, Map.delete(state.rules, key)) do
          :ok ->
            Logger.info(
              module: __MODULE__,
              message: "debug trigger #{domain}/#{script} removed by admin=#{admin || "unknown"}"
            )

            {:reply, :ok, drop_rule(state, key, :removed)}

          {:error, _} = err ->
            {:reply, err, state}
        end
    end
  end

  def handle_call({:get, domain, script}, _from, state) do
    reply =
      case Map.fetch(state.rules, {domain, script}) do
        {:ok, rule} -> {:ok, view(rule)}
        :error -> {:error, :not_found}
      end

    {:reply, reply, state}
  end

  def handle_call(:list, _from, state), do: {:reply, views(state), state}

  def handle_call({:claim, domain, script, request}, _from, state) do
    key = {domain, script}
    now = now_ms()

    case :ets.lookup(state.table, key) do
      [{^key, rule, matcher}] ->
        cond do
          not live?(rule, now) ->
            {:reply, :no, end_rule(state, key, :expired)}

          not matches?(matcher, request) ->
            {:reply, :no, state}

          rule.remaining <= 1 ->
            rule = %{rule | remaining: 0}
            {:reply, {:journal, view(rule)}, end_rule(state, key, :exhausted)}

          true ->
            rule = %{rule | remaining: rule.remaining - 1}
            state = put_rule(state, key, rule)
            persist_logged(state)
            push(state, {:upsert, view(rule)})
            {:reply, {:journal, view(rule)}, state}
        end

      [] ->
        {:reply, :no, state}
    end
  end

  def handle_call({:prune, snapshot}, _from, state) do
    orphans =
      for {{domain, script} = key, _rule} <- state.rules,
          script not in (Kelix.Domains.scripts_of(snapshot, domain) || []),
          do: key

    state =
      Enum.reduce(orphans, state, fn {domain, script} = key, acc ->
        Logger.info(
          module: __MODULE__,
          message:
            "debug trigger #{domain}/#{script} removed: the domain no longer serves the script"
        )

        drop_rule(acc, key, :orphan)
      end)

    if orphans != [], do: persist_logged(state)

    {:reply, orphans, state}
  end

  def handle_call({:subscribe, pid}, _from, state) do
    subscribers =
      if Map.has_key?(state.subscribers, pid),
        do: state.subscribers,
        else: Map.put(state.subscribers, pid, Process.monitor(pid))

    {:reply, %{rules: views(state)}, %{state | subscribers: subscribers}}
  end

  def handle_call({:unsubscribe, pid}, _from, state) do
    case Map.pop(state.subscribers, pid) do
      {nil, _} ->
        {:reply, :ok, state}

      {ref, subscribers} ->
        Process.demonitor(ref, [:flush])
        {:reply, :ok, %{state | subscribers: subscribers}}
    end
  end

  @impl true
  # Only the timer armed last for this key: a replaced rule has another.
  def handle_info({:expire, key, token}, state) do
    with ^token <- Map.get(state.timers, key),
         {:ok, rule} <- Map.fetch(state.rules, key) do
      if live?(rule, now_ms()),
        do: {:noreply, arm(state, key, rule)},
        else: {:noreply, end_rule(state, key, :expired)}
    else
      _stale -> {:noreply, state}
    end
  end

  def handle_info({:DOWN, ref, :process, pid, _reason}, state) do
    case Map.pop(state.subscribers, pid) do
      {^ref, subscribers} -> {:noreply, %{state | subscribers: subscribers}}
      _other -> {:noreply, state}
    end
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ── rules ───────────────────────────────────────────────────────────────────

  defp put_rule(state, key, rule) do
    :ets.insert(state.table, {key, rule, matcher(rule.filter)})
    %{state | rules: Map.put(state.rules, key, rule)}
  end

  # Removes and tells; the caller persists (or already has).
  defp drop_rule(state, key, reason) do
    :ets.delete(state.table, key)
    push(state, {:remove, key, reason})
    %{state | rules: Map.delete(state.rules, key), timers: Map.delete(state.timers, key)}
  end

  # A rule that ended by itself: logged, removed, persisted.
  defp end_rule(state, {domain, script} = key, reason) do
    Logger.info(
      module: __MODULE__,
      message: "debug trigger #{domain}/#{script} ended: #{reason}"
    )

    state = drop_rule(state, key, reason)
    persist_logged(state)
    state
  end

  defp arm(state, key, rule) do
    token = make_ref()
    ms = rule.expires_at |> DateTime.diff(DateTime.utc_now(), :millisecond) |> max(0)
    Process.send_after(self(), {:expire, key, token}, min(ms, @max_timer_ms))
    %{state | timers: Map.put(state.timers, key, token)}
  end

  defp live?(rule, now_ms),
    do: DateTime.to_unix(rule.expires_at, :millisecond) > now_ms

  defp now_ms, do: System.os_time(:millisecond)

  defp lookup(table, key) do
    :ets.lookup(table, key)
  rescue
    ArgumentError -> []
  end

  defp call_claim(server, domain, script, request) do
    GenServer.call(server, {:claim, domain, script, request})
  catch
    :exit, _ -> :no
  end

  # ── matching ────────────────────────────────────────────────────────────────

  defp matcher(nil), do: :any
  defp matcher(%{caller: user}), do: {:caller, String.downcase(user)}
  defp matcher(%{callee: user}), do: {:callee, String.downcase(user)}

  defp matcher(%{source: text}) do
    {:ok, prefix} = parse_source(text)
    {:source, prefix}
  end

  defp matches?(:any, _request), do: true
  defp matches?(_filtered, nil), do: false

  defp matches?({:caller, user}, request),
    do: Enum.any?(Ops.caller_users(request), &(String.downcase(&1) == user))

  defp matches?({:callee, user}, request),
    do: Enum.any?(Ops.callee_users(request), &(String.downcase(&1) == user))

  defp matches?({:source, prefix}, request) do
    case Ops.source_ip(request) do
      nil -> false
      ip -> NetUtils.in_prefix?(ip, prefix)
    end
  end

  # ── validation ──────────────────────────────────────────────────────────────

  defp check_target(state, domain, script) do
    snapshot = state.snapshot.()

    case Kelix.Domains.scripts_of(snapshot, domain) do
      nil -> {:error, {:unknown_domain, domain}}
      scripts -> if script in scripts, do: :ok, else: {:error, {:unknown_script, script}}
    end
  catch
    :exit, _ -> {:error, :domains_unavailable}
  end

  # Decision 4: more triggered journals than the store keeps would evict the
  # first ones before anybody reads them.
  defp check_count(n, max) when is_integer(n) and n >= 1 and n <= max, do: {:ok, n}
  defp check_count(n, max), do: {:error, {:bad_count, n, max}}

  defp check_filter(nil), do: {:ok, nil}
  defp check_filter(filter) when filter == %{}, do: {:ok, nil}

  defp check_filter(%{} = filter) when map_size(filter) == 1 do
    [{key, value}] = Map.to_list(filter)

    with {:ok, key} <- filter_key(key),
         {:ok, value} <- filter_value(key, value) do
      {:ok, %{key => value}}
    else
      _ -> {:error, {:bad_filter, filter}}
    end
  end

  defp check_filter(filter), do: {:error, {:bad_filter, filter}}

  defp filter_key(key) when key in [:caller, :callee, :source], do: {:ok, key}
  defp filter_key("caller"), do: {:ok, :caller}
  defp filter_key("callee"), do: {:ok, :callee}
  defp filter_key("source"), do: {:ok, :source}
  defp filter_key(_), do: :error

  defp filter_value(key, value) when is_binary(value) do
    value = String.trim(value)

    cond do
      value == "" -> :error
      key == :source -> with {:ok, _} <- parse_source(value), do: {:ok, value}
      true -> {:ok, value}
    end
  end

  defp filter_value(_key, _value), do: :error

  # An address alone is the network of that one address.
  defp parse_source(text) do
    if String.contains?(text, "/") do
      NetUtils.parse_prefix(text)
    else
      case NetUtils.parse_address(text) do
        {:ok, ip} -> {:ok, {ip, tuple_size(ip) * if(tuple_size(ip) == 4, do: 8, else: 16)}}
        _ -> {:error, :badprefix}
      end
    end
  end

  defp filter_text(nil), do: ""
  defp filter_text(filter), do: ", " <> Enum.map_join(filter, &"#{elem(&1, 0)}=#{elem(&1, 1)}")

  # ── views ───────────────────────────────────────────────────────────────────

  defp view(rule) do
    left = DateTime.diff(rule.expires_at, DateTime.utc_now(), :second)
    Map.put(rule, :seconds_left, max(left, 0))
  end

  defp views(state) do
    state.rules
    |> Map.values()
    |> Enum.sort_by(&DateTime.to_unix(&1.expires_at))
    |> Enum.map(&view/1)
  end

  defp push(state, msg) do
    for pid <- Map.keys(state.subscribers), do: send(pid, {:kelix_debug_triggers, msg})
    :ok
  end

  defp default_max_runs() do
    Kelix.Config.current().debug.max_traces
  catch
    :exit, _ -> %Kelix.Config{}.debug.max_traces
  end

  # ── the state file ──────────────────────────────────────────────────────────

  defp persist(%{path: nil}, _rules), do: :ok

  defp persist(%{path: path}, rules) do
    doc = %{
      "version" => @file_version,
      "rules" =>
        rules
        |> Map.values()
        |> Enum.sort_by(&{&1.domain, &1.script})
        |> Enum.map(&encode_rule/1)
    }

    tmp = path <> ".tmp"

    with {:ok, text} <- Jason.encode(doc, pretty: true),
         :ok <- File.write(tmp, text),
         :ok <- File.chmod(tmp, 0o640),
         :ok <- File.rename(tmp, path) do
      :ok
    else
      {:error, reason} ->
        File.rm(tmp)
        {:error, {:write_failed, %{path: path, reason: reason}}}
    end
  end

  defp persist_logged(state) do
    case persist(state, state.rules) do
      :ok ->
        :ok

      {:error, reason} ->
        Logger.error(
          module: __MODULE__,
          message: "debug triggers not written, kept in memory: #{inspect(reason)}"
        )
    end
  end

  defp encode_rule(rule) do
    %{
      "domain" => rule.domain,
      "script" => rule.script,
      "total" => rule.total,
      "remaining" => rule.remaining,
      "filter" => rule.filter && Map.new(rule.filter, fn {k, v} -> {Atom.to_string(k), v} end),
      "created_at" => DateTime.to_iso8601(rule.created_at),
      "expires_at" => DateTime.to_iso8601(rule.expires_at),
      "created_by" => rule.created_by
    }
  end

  defp load(%{path: nil} = state), do: state

  defp load(%{path: path} = state) do
    case File.read(path) do
      {:ok, text} ->
        case decode(text) do
          {:ok, rules} ->
            restore(state, rules)

          {:error, reason} ->
            aside = path <> ".corrupt"
            _ = File.rename(path, aside)

            Logger.error(
              module: __MODULE__,
              message:
                "#{path} unreadable (#{inspect(reason)}): moved to #{aside}, " <>
                  "starting without debug triggers"
            )

            state
        end

      {:error, :enoent} ->
        state

      {:error, reason} ->
        Logger.error(
          module: __MODULE__,
          message:
            "cannot read #{path} (#{:file.format_error(reason)}): " <>
              "starting without debug triggers"
        )

        state
    end
  end

  defp restore(state, rules) do
    now = now_ms()
    {live, expired} = Enum.split_with(rules, &live?(&1, now))

    for rule <- expired do
      Logger.info(
        module: __MODULE__,
        message: "debug trigger #{rule.domain}/#{rule.script} expired while the node was down"
      )
    end

    state =
      Enum.reduce(live, state, fn rule, acc ->
        key = {rule.domain, rule.script}
        acc |> put_rule(key, rule) |> arm(key, rule)
      end)

    if expired != [], do: persist_logged(state)
    state
  end

  defp decode(text) do
    with {:ok, %{"version" => @file_version, "rules" => rules}} when is_list(rules) <-
           Jason.decode(text),
         {:ok, rules} <- decode_rules(rules) do
      {:ok, rules}
    else
      {:ok, _other} -> {:error, :unknown_format}
      {:error, _} = err -> err
    end
  end

  defp decode_rules(rules) do
    Enum.reduce_while(rules, {:ok, []}, fn raw, {:ok, acc} ->
      case decode_rule(raw) do
        {:ok, rule} -> {:cont, {:ok, [rule | acc]}}
        :error -> {:halt, {:error, {:bad_rule, raw}}}
      end
    end)
    |> case do
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      err -> err
    end
  end

  defp decode_rule(%{
         "domain" => domain,
         "script" => script,
         "total" => total,
         "remaining" => remaining,
         "filter" => filter,
         "created_at" => created_at,
         "expires_at" => expires_at,
         "created_by" => created_by
       })
       when is_binary(domain) and is_binary(script) and is_integer(total) and
              is_integer(remaining) and remaining >= 1 do
    with {:ok, filter} <- check_filter(filter),
         {:ok, created_at, _} <- DateTime.from_iso8601(created_at),
         {:ok, expires_at, _} <- DateTime.from_iso8601(expires_at) do
      {:ok,
       %{
         domain: domain,
         script: script,
         total: total,
         remaining: remaining,
         filter: filter,
         created_at: created_at,
         expires_at: expires_at,
         created_by: created_by
       }}
    else
      _ -> :error
    end
  end

  defp decode_rule(_raw), do: :error
end
