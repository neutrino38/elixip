defmodule Kelix.ScriptRegistry do
  @moduledoc """
  Loads scenario scripts, enforces the **load-time contract** (design §5.3) and
  tracks **versions** with reference counting (§5.1, §16 #3).

  Contract — a script is refused (with a clear error) unless it is a valid
  scenario (`__scenario_type__/0`) **and** handles cooperative shutdown
  explicitly (`__state___shutdown__/1`, i.e. an `on_shutdown` block). elixip makes
  every scenario shutdown-aware by default but that default is abrupt; kelixip
  forbids it — every served script must prove it drains cleanly.

  Versioning — each load compiles the `.exs` under a **version-suffixed module
  name** (`Foo` → `Foo.V<n>`), so several versions coexist as distinct BEAM
  modules (the BEAM only keeps current+old per name, insufficient when a reload
  happens while a long call still runs on a superseded version). In-flight
  instances keep their version; new spawns get the current one; an old version is
  purged when its last instance ends (refcount 0). No in-flight state migration.

  Script names are resolved relative to `script_dir` (config §3.1 / §4). Reads
  never mutate the framework — `current/1` loads on demand and caches.
  """
  use GenServer
  require Logger

  # entry:    %{module: mod, version: n, refcount: r, path: p}   (current version)
  # draining: %{{name, version} => %{module: mod, refcount: r}}  (superseded, still in use)
  defstruct script_dir: ".", scripts: %{}, draining: %{}

  # ── API ──────────────────────────────────────────────────────────────────────

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc "Current version's module for `name`, loading + contract-checking on first use."
  @spec current(String.t()) :: {:ok, module} | {:error, term}
  def current(name), do: GenServer.call(__MODULE__, {:current, name})

  @doc "Force a (re)load of `name` as a new version. `:ok` (swapped) / `{:error, reason}` (kept)."
  @spec reload(String.t()) :: :ok | {:error, term}
  def reload(name), do: GenServer.call(__MODULE__, {:reload, name})

  @doc "Reserve the current version for a new instance; returns its module (refcount++)."
  @spec checkout(String.t()) :: {:ok, module, pos_integer} | {:error, term}
  def checkout(name), do: GenServer.call(__MODULE__, {:checkout, name})

  @doc "Release a version when an instance ends (refcount--; purge an old version at 0)."
  @spec checkin(String.t(), pos_integer) :: :ok
  def checkin(name, version), do: GenServer.cast(__MODULE__, {:checkin, name, version})

  # ── GenServer ────────────────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    script_dir = Keyword.get(opts, :script_dir) || script_dir_from_config()
    {:ok, %__MODULE__{script_dir: script_dir}}
  end

  defp script_dir_from_config do
    case Process.whereis(Kelix.Config) do
      nil -> "."
      _ -> Kelix.Config.current().script_dir
    end
  end

  @impl true
  def handle_call({:current, name}, _from, state) do
    case ensure_loaded(name, state) do
      {:ok, entry, state2} -> {:reply, {:ok, entry.module}, state2}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:reload, name}, _from, state) do
    case do_reload(name, state) do
      {:ok, state2} -> {:reply, :ok, state2}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:checkout, name}, _from, state) do
    case ensure_loaded(name, state) do
      {:ok, entry, state2} ->
        entry2 = %{entry | refcount: entry.refcount + 1}
        state3 = put_in(state2.scripts[name], entry2)
        {:reply, {:ok, entry2.module, entry2.version}, state3}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_cast({:checkin, name, version}, state) do
    {:noreply, release(state, name, version)}
  end

  # ── loading / versioning ─────────────────────────────────────────────────────

  defp ensure_loaded(name, state) do
    case Map.get(state.scripts, name) do
      %{} = entry -> {:ok, entry, state}
      nil -> load_new(name, 1, state)
    end
  end

  defp do_reload(name, state) do
    version = (get_in(state.scripts, [name, :version]) || 0) + 1

    case compile_checked(path_of(state, name), version) do
      {:ok, mod} ->
        old = Map.get(state.scripts, name)
        entry = %{module: mod, version: version, refcount: 0, path: path_of(state, name)}
        state2 = put_in(state.scripts[name], entry)

        Logger.info(
          module: __MODULE__,
          message: "script #{name} loaded as v#{version} (#{inspect(mod)})"
        )

        {:ok, retire(state2, name, old)}

      {:error, _} = err ->
        err
    end
  end

  defp load_new(name, version, state) do
    case compile_checked(path_of(state, name), version) do
      {:ok, mod} ->
        entry = %{module: mod, version: version, refcount: 0, path: path_of(state, name)}
        state2 = put_in(state.scripts[name], entry)
        {:ok, entry, state2}

      {:error, _} = err ->
        err
    end
  end

  # move a superseded version to `draining` (purge now if unused)
  defp retire(state, _name, nil), do: state
  defp retire(state, _name, %{refcount: 0, module: mod}), do: purge(state, mod)

  defp retire(state, name, %{version: v, refcount: r, module: mod}),
    do: put_in(state.draining[{name, v}], %{module: mod, refcount: r})

  defp release(state, name, version) do
    case Map.get(state.scripts, name) do
      %{version: ^version, refcount: r} = entry when r > 0 ->
        put_in(state.scripts[name], %{entry | refcount: r - 1})

      _ ->
        # a draining (superseded) version — decrement and purge at 0
        decrement_draining(state, {name, version})
    end
  end

  defp decrement_draining(state, key) do
    case Map.get(state.draining, key) do
      nil ->
        state

      %{refcount: 1, module: mod} ->
        purge(%{state | draining: Map.delete(state.draining, key)}, mod)

      %{refcount: r} = d ->
        put_in(state.draining[key], %{d | refcount: r - 1})
    end
  end

  defp purge(state, mod) do
    :code.purge(mod)
    :code.delete(mod)
    Logger.debug(module: __MODULE__, message: "purged #{inspect(mod)}")
    state
  end

  # A name is resolved relative to script_dir; an absolute path is used as-is
  # (config never uses absolute script names, but tests do).
  defp path_of(state, name) do
    if Path.type(name) == :absolute, do: name, else: Path.join(state.script_dir, name)
  end

  # ── compile with a version-suffixed module name + contract check ─────────────

  @spec compile_checked(Path.t(), pos_integer) :: {:ok, module} | {:error, term}
  def compile_checked(path, version) do
    with {:ok, source} <- read(path),
         {:ok, ast} <- to_ast(source, path),
         {:ok, modules} <- compile(suffix_modules(ast, version), path),
         {:ok, mod} <- pick_scenario(modules, path),
         :ok <- contract_check(mod, path) do
      {:ok, mod}
    end
  end

  defp read(path) do
    case File.read(path) do
      {:ok, s} -> {:ok, s}
      {:error, reason} -> {:error, "cannot read #{path}: #{:file.format_error(reason)}"}
    end
  end

  defp to_ast(source, path) do
    case Code.string_to_quoted(source, file: path) do
      {:ok, ast} -> {:ok, ast}
      {:error, {_meta, msg, tok}} -> {:error, "#{path}: syntax error: #{msg}#{tok}"}
    end
  end

  # append `.V<version>` to every top-level defmodule name
  defp suffix_modules({:__block__, m, exprs}, v),
    do: {:__block__, m, Enum.map(exprs, &suffix_one(&1, v))}

  defp suffix_modules(expr, v), do: suffix_one(expr, v)

  defp suffix_one({:defmodule, m, [{:__aliases__, am, parts}, body]}, v),
    do: {:defmodule, m, [{:__aliases__, am, parts ++ [String.to_atom("V#{v}")]}, body]}

  defp suffix_one(other, _v), do: other

  defp compile(ast, path) do
    {:ok, Code.compile_quoted(ast, path) |> Enum.map(&elem(&1, 0))}
  rescue
    e -> {:error, "#{path}: compile error: #{Exception.message(e)}"}
  end

  defp pick_scenario(modules, path) do
    case Enum.find(modules, &scenario_module?/1) do
      nil -> {:error, "#{path} defines no scenario module"}
      mod -> {:ok, mod}
    end
  end

  defp scenario_module?(mod) do
    Code.ensure_loaded?(mod) and function_exported?(mod, :run, 1) and
      function_exported?(mod, :__scenario_states__, 0)
  end

  defp contract_check(mod, path) do
    cond do
      not function_exported?(mod, :__scenario_type__, 0) ->
        {:error, "#{path} is not a valid kelixip scenario (no __scenario_type__/0)"}

      not function_exported?(mod, :__state___shutdown__, 1) ->
        {:error,
         "#{path} does not handle cooperative shutdown (missing `on_shutdown` block): refused"}

      true ->
        check_declared_modules(mod, path)
    end
  end

  @doc """
  Refuse a script whose declared `uses_modules` are not loaded (design §16 #14).

  A script names the modules it calls in its `config` block:

      config domain: "example.com", uses_modules: [:registrar, :auth_db]

  and this checks them against `Kelix.ModuleRegistry` at load. Without the
  declaration the dependency is written nowhere and cannot be inferred — a custom
  registrar script may legitimately need no `registrar` module — so the mismatch
  could only ever be a boot *warning*, and the first request to that domain died
  inside the instance. Declaring turns it into a load error, caught before any
  request arrives.

  Silent when a script declares nothing: the declaration is opt-in, and every
  scenario written before it stays loadable.
  """
  @spec check_declared_modules(module, Path.t()) :: :ok | {:error, String.t()}
  def check_declared_modules(mod, path) do
    loaded = Map.keys(Kelix.ModuleRegistry.all())

    case Enum.reject(declared_modules(mod), &(&1 in loaded)) do
      [] ->
        :ok

      missing ->
        {:error,
         "#{path} declares uses_modules #{inspect(missing)}, which " <>
           "#{if length(missing) == 1, do: "is", else: "are"} not loaded " <>
           "(no [module.<name>] block, or no .beam in module_dir); loaded: " <>
           "#{inspect(Enum.sort(loaded))}"}
    end
  end

  defp declared_modules(mod) do
    if function_exported?(mod, :__scenario_config__, 0) do
      mod.__scenario_config__()
      |> Keyword.get(:uses_modules, [])
      |> List.wrap()
      |> Enum.map(&to_string/1)
    else
      []
    end
  end
end
