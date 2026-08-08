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

  Because the module name comes from the *file*, two scripts that declare the
  same `defmodule` compile to the same versioned module and silently overwrite
  each other — the dial plan routes to two names, one body runs. So the contract
  also covers **module ownership**: a script is refused when it declares a module
  another loaded script already owns (`check_module_ownership/3`).

  Script names are resolved relative to `script_dir` (config §3.1 / §4). Reads
  never mutate the framework — `current/1` loads on demand and caches.
  """
  use GenServer
  require Logger

  # entry:    %{module: mod, version: n, refcount: r, path: p, stamp: s, bases: [m]}
  #           (current version; `bases` = the UNsuffixed module names the file defines)
  # draining: %{{name, version} => %{module: mod, refcount: r}}  (superseded, still in use)
  defstruct script_dir: ".", scripts: %{}, draining: %{}

  # Compiling a handful of scenarios is not a 5 s job on a loaded box.
  @validate_timeout 60_000

  # ── API ──────────────────────────────────────────────────────────────────────

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc "Current version's module for `name`, loading + contract-checking on first use."
  @spec current(String.t()) :: {:ok, module} | {:error, term}
  def current(name), do: GenServer.call(__MODULE__, {:current, name})

  @doc "Force a (re)load of `name` as a new version. `:ok` (swapped) / `{:error, reason}` (kept)."
  @spec reload(String.t()) :: :ok | {:error, term}
  def reload(name), do: GenServer.call(__MODULE__, {:reload, name})

  @doc """
  Contract-check every script in `names` **against the disk** (§5.3): a name never
  loaded is loaded now, a name whose file changed since it was loaded is reloaded as
  a new version, an unchanged one is already proven (its module passed the contract
  when it was loaded).

  Returns `:ok`, or `{:error, [{name, reason}]}` listing **every** offender — an
  operator fixing a config wants all of them, not the first. Nothing is rolled back
  on failure: a script that does compile stays loaded at its new version, exactly
  the publication `reload/1` would have done.

  This is what lets `kelictl domain reload-all` refuse a `domains.toml` whose
  scripts are missing, uncompilable or not shutdown-aware (§3.2) instead of
  discovering it one inbound call at a time — the failure mode this exists to kill.
  """
  @spec validate([String.t()]) :: :ok | {:error, [{String.t(), term}]}
  def validate(names) when is_list(names),
    do: GenServer.call(__MODULE__, {:validate, Enum.uniq(names)}, @validate_timeout)

  @doc """
  The live version of every loaded script (`%{name => version}`) — what the reload
  report shows an operator, so "the reload went through" is a version they can check.
  """
  @spec versions() :: %{optional(String.t()) => pos_integer}
  def versions(), do: GenServer.call(__MODULE__, :versions)

  @doc """
  The live **module** behind every loaded script, and whether it still matches the
  file: `%{name => %{module:, version:, path:, stale:}}`.

  What `versions/0` reports is not enough to answer "what actually runs": the module
  name comes from the script's `defmodule`, not from its file name. Ownership is now
  enforced at load (`check_module_ownership/3`), but the mapping stays worth showing
  — `kelictl domain show` prints it next to each dial-plan rule, so an operator reads
  the compiled truth rather than inferring it from the file name.

  `stale` compares the stamp taken at load with the file **right now** (the same
  reading `ensure_fresh/2` uses to decide a recompile), so it answers the other half
  of the question — "is what runs still what I edited?":

    * `false` — the loaded version was compiled from the file as it stands;
    * `:changed` — the file was edited since; a `reload` would pick that up;
    * `:missing` — the file is gone (the loaded version keeps serving);
    * `:unknown` — it could not be stat'ed at load, so there is nothing to compare.

  This is a read, not a reload: it never swaps anything in.
  """
  @spec loaded() :: %{
          optional(String.t()) => %{
            module: module,
            version: pos_integer,
            path: Path.t(),
            stale: false | :changed | :missing | :unknown
          }
        }
  def loaded(), do: GenServer.call(__MODULE__, :loaded)

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

  def handle_call(:versions, _from, state) do
    {:reply, Map.new(state.scripts, fn {name, entry} -> {name, entry.version} end), state}
  end

  def handle_call(:loaded, _from, state) do
    loaded =
      Map.new(state.scripts, fn {name, e} ->
        {name,
         %{module: e.module, version: e.version, path: e.path, stale: staleness(e.stamp, e.path)}}
      end)

    {:reply, loaded, state}
  end

  def handle_call({:validate, names}, _from, state) do
    {state2, failures} =
      Enum.reduce(names, {state, []}, fn name, {st, failures} ->
        case ensure_fresh(name, st) do
          {:ok, _entry, st2} -> {st2, failures}
          {:error, reason} -> {st, [{name, reason} | failures]}
        end
      end)

    reply = if failures == [], do: :ok, else: {:error, Enum.reverse(failures)}
    {:reply, reply, state2}
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

  # `validate/1`'s reading of "loaded" — the *file*, not what we happen to hold.
  # An unchanged file needs nothing (its module already passed the contract); a
  # changed one is recompiled as a new version, so an operator who edits a script
  # and reloads the domains gets that edit checked, and served. A file that cannot
  # be stat'ed has no stamp, so it recompiles — i.e. it fails loudly, which is right.
  defp ensure_fresh(name, state) do
    case Map.get(state.scripts, name) do
      %{stamp: stamp} = entry when not is_nil(stamp) ->
        if stamp == stamp_of(path_of(state, name)),
          do: {:ok, entry, state},
          else: reload_entry(name, state)

      %{} ->
        reload_entry(name, state)

      nil ->
        load_new(name, 1, state)
    end
  end

  defp reload_entry(name, state) do
    with {:ok, state2} <- do_reload(name, state),
         do: {:ok, Map.fetch!(state2.scripts, name), state2}
  end

  defp do_reload(name, state) do
    version = (get_in(state.scripts, [name, :version]) || 0) + 1

    case compile_entry(state, name, version) do
      {:ok, entry} ->
        old = Map.get(state.scripts, name)
        state2 = put_in(state.scripts[name], entry)

        Logger.info(
          module: __MODULE__,
          message: "script #{name} loaded as v#{version} (#{inspect(entry.module)})"
        )

        {:ok, retire(state2, name, old)}

      {:error, _} = err ->
        err
    end
  end

  defp load_new(name, version, state) do
    case compile_entry(state, name, version) do
      {:ok, entry} ->
        state2 = put_in(state.scripts[name], entry)
        {:ok, entry, state2}

      {:error, _} = err ->
        err
    end
  end

  # The stamp is sampled *before* the compile: should the file change while we are
  # compiling it, what we record is the older stamp, so the next `validate/1`
  # recompiles. The other order would file the new file's stamp against the old code.
  defp compile_entry(state, name, version) do
    path = path_of(state, name)
    stamp = stamp_of(path)

    with {:ok, mod, bases} <- compile_all(path, version, owned_bases(state, name)) do
      {:ok, %{module: mod, version: version, refcount: 0, path: path, stamp: stamp, bases: bases}}
    end
  end

  # The modules owned by the OTHER loaded scripts (`base module => script name`).
  # `name` itself is excluded: reloading a script — including one whose module was
  # just renamed — re-declares its own modules, which is the normal case, not a clash.
  # Draining versions need no entry: they are older versions of a name already here,
  # so they own nothing their current entry does not.
  defp owned_bases(state, name) do
    for {other, %{bases: bases}} <- state.scripts,
        other != name,
        base <- bases,
        into: %{},
        do: {base, other}
  end

  # What "the file changed" means for `ensure_fresh/2`: mtime **and** size. Posix
  # mtime has a one-second granularity, so mtime alone misses an edit saved in the
  # same second as the previous load — size catches most of those.
  defp stamp_of(path) do
    case File.stat(path, time: :posix) do
      {:ok, %File.Stat{mtime: mtime, size: size}} -> {mtime, size}
      {:error, _} -> nil
    end
  end

  # `loaded/0`'s read of the same comparison `ensure_fresh/2` acts on — the stamp
  # taken when this version was compiled, against the file right now. It answers, and
  # only answers: is the code in memory still the code on disk?
  defp staleness(nil, _path), do: :unknown

  defp staleness(recorded, path) do
    case stamp_of(path) do
      nil -> :missing
      ^recorded -> false
      _other -> :changed
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
    with {:ok, mod, _bases} <- compile_all(path, version, %{}), do: {:ok, mod}
  end

  # The ownership check runs on the AST, BEFORE `compile/2`: compiling is what
  # overwrites the other script's module, so a check made afterwards would report
  # damage it had already done.
  @spec compile_all(Path.t(), pos_integer, %{module => String.t()}) ::
          {:ok, module, [module]} | {:error, term}
  defp compile_all(path, version, owned) do
    with {:ok, source} <- read(path),
         {:ok, ast} <- to_ast(source, path),
         bases = declared_bases(ast),
         :ok <- check_module_ownership(bases, owned, path),
         {:ok, modules} <- compile(suffix_modules(ast, version), path),
         {:ok, mod} <- pick_scenario(modules, path),
         :ok <- contract_check(mod, path) do
      {:ok, mod, bases}
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

  # The module names `suffix_modules/2` is about to version — the same shapes, read
  # instead of rewritten, so the guard covers exactly what the compile will define
  # (a file's helper modules clobber just as thoroughly as its scenario module).
  # A computed alias (`defmodule :"#{x}"`) yields no static name and is skipped:
  # unnameable here, and no scenario writes one.
  defp declared_bases({:__block__, _, exprs}), do: Enum.flat_map(exprs, &declared_one/1)
  defp declared_bases(expr), do: declared_one(expr)

  defp declared_one({:defmodule, _, [{:__aliases__, _, parts}, _body]}) do
    if Enum.all?(parts, &is_atom/1), do: [Module.concat(parts)], else: []
  end

  defp declared_one(_other), do: []

  @doc """
  Refuse a script that declares a module another loaded script already owns.

  Without it the collision is silent and total: `record.exs` and `play.exs` both
  saying `defmodule UAS.InviteExample` compile to the same `UAS.InviteExample.V1`,
  the second load overwrites the first, and both dial-plan entries then run the
  same body — visible only in the media the call produces. Worse, retiring either
  one purges the module both point at.

  `owned` maps a base module name to the script that owns it.
  """
  @spec check_module_ownership([module], %{module => String.t()}, Path.t()) ::
          :ok | {:error, String.t()}
  def check_module_ownership(bases, owned, path) do
    case Enum.filter(bases, &Map.has_key?(owned, &1)) do
      [] ->
        :ok

      clashing ->
        details =
          Enum.map_join(clashing, ", ", &"#{inspect(&1)} (owned by #{Map.fetch!(owned, &1)})")

        {:error,
         "#{path} defines #{details}; two scripts cannot share a module name — " <>
           "rename the module in one of them"}
    end
  end

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
