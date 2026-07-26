defmodule Kelix.Domains do
  @moduledoc """
  Holds the current `domains.toml` snapshot and swaps it **atomically** on reload
  (design `docs/kelixip_basic_design.md` §3.2, §9.2).

  The whole file is parsed and validated into a fresh `%Kelix.Domains{}` *off to
  the side*; only if everything validates is it swapped in. One bad element ⇒ the
  reload is rejected and the current config stays intact — never a half-applied
  config. Reads (`current/0`) always see one consistent version.

  This module is both the supervised GenServer and the snapshot struct it holds:
    * `version`  — bumped on each successful reload
    * `domains`  — ordered `[%Kelix.Domain{}]`
    * `index`    — `name` + each alias (lower-cased) → `%Kelix.Domain{}` for O(1) lookup
    * `modules`  — raw `[module.*]` blocks (carried for the module system, P5)
  """
  use GenServer
  require Logger

  alias Kelix.{Domain, DialRule, DialPlan}

  @type t :: %__MODULE__{
          version: non_neg_integer,
          domains: [Domain.t()],
          index: %{optional(String.t()) => Domain.t()},
          modules: %{optional(String.t()) => map}
        }

  defstruct version: 0, domains: [], index: %{}, modules: %{}

  @allowed_top_keys ~w(domain module)
  @registrar_keys %{
    "script" => :string,
    "default_expires" => :pos_integer,
    "min_expires" => :pos_integer,
    "keepalive_period" => :pos_integer
  }
  @presence_keys %{"script" => :string}

  # ── GenServer API ────────────────────────────────────────────────────────────

  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc "The current snapshot (`%Kelix.Domains{}`)."
  @spec current() :: t
  def current(), do: GenServer.call(__MODULE__, :current)

  @doc """
  Atomically reload `domains.toml` from `path`. Returns `:ok` on success (the new
  version is swapped in) or `{:error, reason}` (current version kept intact).
  """
  @spec reload(Path.t()) :: :ok | {:error, term}
  def reload(path), do: GenServer.call(__MODULE__, {:reload, path})

  @doc "Resolve a host (R-URI/To host) to its domain, or nil. `name` + aliases, case-insensitive."
  @spec lookup(t, String.t()) :: Domain.t() | nil
  def lookup(%__MODULE__{index: index}, host) when is_binary(host),
    do: Map.get(index, String.downcase(host))

  # ── GenServer callbacks ──────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    case Keyword.get(opts, :path) do
      nil ->
        # P0/P1: boot with an empty config; the path is wired later.
        {:ok, %__MODULE__{}}

      path ->
        case load_path(path, 1) do
          {:ok, snapshot} -> {:ok, snapshot}
          {:error, reason} -> {:stop, {:invalid_domains, reason}}
        end
    end
  end

  @impl true
  def handle_call(:current, _from, state), do: {:reply, state, state}

  def handle_call({:reload, path}, _from, state) do
    case load_path(path, state.version + 1) do
      {:ok, snapshot} ->
        Logger.info(module: __MODULE__, message: "domains.toml reloaded (v#{snapshot.version}, #{length(snapshot.domains)} domains)")
        {:reply, :ok, snapshot}

      {:error, reason} = err ->
        Logger.error(module: __MODULE__, message: "domains.toml reload rejected: #{inspect(reason)} — keeping v#{state.version}")
        {:reply, err, state}
    end
  end

  defp load_path(path, version) do
    with {:ok, content} <- read_file(path),
         {:ok, snapshot} <- parse(content) do
      {:ok, %{snapshot | version: version}}
    end
  end

  defp read_file(path) do
    case File.read(path) do
      {:ok, content} -> {:ok, content}
      {:error, reason} -> {:error, "cannot read #{path}: #{:file.format_error(reason)}"}
    end
  end

  # ── Pure parse + validation (testable without the GenServer) ─────────────────

  @doc """
  Parse + validate a `domains.toml` string into a `%Kelix.Domains{}` (version 0).
  Returns `{:ok, snapshot}` or `{:error, message}` with a clear reason.
  """
  @spec parse(String.t()) :: {:ok, t} | {:error, String.t()}
  def parse(content) when is_binary(content) do
    with {:ok, map} <- decode(content),
         :ok <- check_top_keys(map),
         {:ok, domains} <- parse_domains(Map.get(map, "domain", [])),
         {:ok, index} <- build_index(domains) do
      {:ok, %__MODULE__{version: 0, domains: domains, index: index, modules: Map.get(map, "module", %{})}}
    end
  end

  defp decode(content) do
    case Toml.decode(content) do
      {:ok, map} -> {:ok, map}
      {:error, reason} -> {:error, "invalid TOML: #{inspect(reason)}"}
    end
  end

  defp check_top_keys(map) do
    case Map.keys(map) -- @allowed_top_keys do
      [] -> :ok
      extra -> {:error, "unknown top-level key(s): #{Enum.join(extra, ", ")}"}
    end
  end

  defp parse_domains(list) when is_list(list) do
    reduce_while_ok(list, fn dm -> parse_domain(dm) end)
  end

  defp parse_domains(_), do: {:error, "`domain` must be an array of tables ([[domain]])"}

  defp parse_domain(%{} = dm) do
    with {:ok, name} <- req_string(dm, "name", "domain"),
         {:ok, aliases} <- opt_string_list(dm, "aliases", name),
         {:ok, max_calls} <- opt_pos_integer(dm, "max_calls", name),
         {:ok, registrar} <- opt_fn_block(dm, "registrar", @registrar_keys, name),
         {:ok, presence} <- opt_fn_block(dm, "presence", @presence_keys, name),
         {:ok, dial_plan} <- parse_dial_plan(Map.get(dm, "call", []), name),
         :ok <- check_domain_keys(dm, name) do
      {:ok,
       %Domain{
         name: name,
         aliases: aliases,
         max_calls: max_calls,
         registrar: registrar,
         presence: presence,
         dial_plan: dial_plan
       }}
    end
  end

  defp parse_domain(_), do: {:error, "each [[domain]] must be a table"}

  @domain_keys ~w(name aliases max_calls registrar presence call)
  defp check_domain_keys(dm, name) do
    case Map.keys(dm) -- @domain_keys do
      [] -> :ok
      extra -> {:error, "domain #{inspect(name)}: unknown key(s): #{Enum.join(extra, ", ")}"}
    end
  end

  # ── dial-plan (ordered; first-match-wins; one catch-all, last) ───────────────

  defp parse_dial_plan(rules, domain) when is_list(rules) do
    with {:ok, parsed} <- reduce_while_ok(rules, fn r -> parse_rule(r, domain) end),
         :ok <- validate_catch_all(parsed, domain) do
      {:ok, parsed}
    end
  end

  defp parse_dial_plan(_, domain), do: {:error, "domain #{inspect(domain)}: `call` must be an array of tables"}

  defp parse_rule(%{"default" => true} = r, domain) do
    with {:ok, script} <- req_string(r, "script", "call rule (domain #{domain})"),
         :ok <- reject_keys(r, ~w(default script), "default call rule (domain #{domain})") do
      {:ok, %DialRule{default?: true, script: script}}
    end
  end

  defp parse_rule(%{"pattern" => pattern} = r, domain) when is_binary(pattern) do
    with {:ok, script} <- req_string(r, "script", "call rule (domain #{domain})"),
         :ok <- reject_keys(r, ~w(pattern script), "call rule (domain #{domain})"),
         {:ok, matcher} <- compile_pattern(pattern, domain) do
      {:ok, %DialRule{matcher: matcher, raw: pattern, script: script}}
    end
  end

  defp parse_rule(_, domain),
    do: {:error, "domain #{inspect(domain)}: each [[domain.call]] needs `pattern = \"...\"` or `default = true`"}

  defp compile_pattern(pattern, domain) do
    case DialPlan.compile(pattern) do
      {:ok, matcher} -> {:ok, matcher}
      {:error, reason} -> {:error, "domain #{inspect(domain)}: bad pattern #{inspect(pattern)} (#{inspect(reason)})"}
    end
  end

  defp validate_catch_all(rules, domain) do
    case Enum.split_while(rules, &(not &1.default?)) do
      {_before, []} -> :ok
      {_before, [_default]} -> :ok
      {_before, [_default | _after]} -> {:error, "domain #{inspect(domain)}: the catch-all (default = true) must be the last call rule"}
    end
  end

  # ── index (name + aliases -> domain; collisions rejected) ────────────────────

  defp build_index(domains) do
    Enum.reduce_while(domains, {:ok, %{}}, fn d, {:ok, acc} ->
      keys = [d.name | d.aliases] |> Enum.map(&String.downcase/1)

      case Enum.find(keys, &Map.has_key?(acc, &1)) do
        nil -> {:cont, {:ok, Enum.reduce(keys, acc, &Map.put(&2, &1, d))}}
        dup -> {:halt, {:error, "domain name/alias #{inspect(dup)} is used by more than one domain"}}
      end
    end)
  end

  # ── small validators ─────────────────────────────────────────────────────────

  defp req_string(map, key, ctx) do
    case Map.get(map, key) do
      v when is_binary(v) and v != "" -> {:ok, v}
      nil -> {:error, "#{ctx}: missing required `#{key}`"}
      _ -> {:error, "#{ctx}: `#{key}` must be a non-empty string"}
    end
  end

  defp opt_string_list(map, key, ctx) do
    case Map.get(map, key) do
      nil -> {:ok, []}
      list when is_list(list) ->
        if Enum.all?(list, &is_binary/1),
          do: {:ok, list},
          else: {:error, "domain #{inspect(ctx)}: `#{key}` must be a list of strings"}

      _ -> {:error, "domain #{inspect(ctx)}: `#{key}` must be a list of strings"}
    end
  end

  defp opt_pos_integer(map, key, ctx) do
    case Map.get(map, key) do
      nil -> {:ok, nil}
      v when is_integer(v) and v > 0 -> {:ok, v}
      _ -> {:error, "domain #{inspect(ctx)}: `#{key}` must be a positive integer"}
    end
  end

  # a function block ([domain.registrar] / [domain.presence]): present = enabled
  defp opt_fn_block(map, key, allowed, domain) do
    case Map.get(map, key) do
      nil ->
        {:ok, nil}

      %{} = block ->
        ctx = "domain #{domain} [domain.#{key}]"

        with :ok <- reject_keys(block, Map.keys(allowed), ctx),
             {:ok, _} <- req_string(block, "script", ctx),
             {:ok, cfg} <- pick_typed(block, allowed, ctx) do
          {:ok, cfg}
        end

      _ ->
        {:error, "domain #{domain}: [domain.#{key}] must be a table"}
    end
  end

  # build an atom-keyed config map from a whitelist (no String.to_atom on input)
  defp pick_typed(block, allowed, ctx) do
    Enum.reduce_while(allowed, {:ok, %{}}, fn {key, type}, {:ok, acc} ->
      case Map.get(block, key) do
        nil -> {:cont, {:ok, acc}}
        v ->
          case check_type(v, type) do
            :ok -> {:cont, {:ok, Map.put(acc, known_atom(key), v)}}
            :error -> {:halt, {:error, "#{ctx}: `#{key}` must be #{type}"}}
          end
      end
    end)
  end

  defp check_type(v, :string) when is_binary(v), do: :ok
  defp check_type(v, :pos_integer) when is_integer(v) and v > 0, do: :ok
  defp check_type(_, _), do: :error

  # whitelist -> atom (compile-time-known keys only; never String.to_atom on input)
  defp known_atom("script"), do: :script
  defp known_atom("default_expires"), do: :default_expires
  defp known_atom("min_expires"), do: :min_expires
  defp known_atom("keepalive_period"), do: :keepalive_period

  defp reject_keys(map, allowed, ctx) do
    case Map.keys(map) -- allowed do
      [] -> :ok
      extra -> {:error, "#{ctx}: unknown key(s): #{Enum.join(extra, ", ")}"}
    end
  end

  # reduce a list, stopping at the first {:error, _}
  defp reduce_while_ok(list, fun) do
    result =
      Enum.reduce_while(list, {:ok, []}, fn item, {:ok, acc} ->
        case fun.(item) do
          {:ok, parsed} -> {:cont, {:ok, [parsed | acc]}}
          {:error, _} = err -> {:halt, err}
        end
      end)

    with {:ok, acc} <- result, do: {:ok, Enum.reverse(acc)}
  end
end
