defmodule Kelix.ModuleSupervisor do
  @moduledoc """
  Supervises one child per loaded `[module.<name>]` block (design §8.1). Strategy
  `:one_for_one` — a module crash never takes its siblings down.

  Config sources (§6.1/§8.1): every module's block is read from `config.toml`
  (`Kelix.Config.modules`) **except `registrar`**, whose block lives in
  `domains.toml` (`Kelix.Domains.modules`) so it is hot-reloadable alongside the
  domains it serves. `registrar` is therefore ignored if it appears in
  `config.toml`.

  For each block: resolve the module (`Kelix.Mod.<Camelize(name)>` by default, or
  an explicit `module = "..."` key), run `validate_config/1` — an invalid block is
  logged and skipped, never aborting boot nor touching the others — then record it
  in `Kelix.ModuleRegistry`, publish its `describe_control/0` into
  `Kelix.Control.Registry`, and start `child_spec/2` under this supervisor.

  **Where the code comes from.** No module is compiled into the core release: it is
  function-agnostic (§16.12), and each provided module (`registrar`, `auth_db`)
  ships as its own package dropping `Elixir.Kelix.Mod.<Name>.beam` into
  `server.module_dir`. This supervisor puts that directory on the code path before
  resolving anything, so `Code.ensure_loaded?/1` finds it; a configured module whose
  `.beam` is not installed is logged and skipped like any other bad block. In
  dev/test the modules come from the umbrella's own `ebin` (already on the path),
  so `module_dir` is simply empty there.

  Tests may bypass the config sources with `start_link(modules: %{name => block})`,
  and point the loader elsewhere with `start_link(module_dir: "…")`.
  """
  use Supervisor
  require Logger

  @spec start_link(keyword) :: Supervisor.on_start()
  def start_link(opts \\ []),
    do: Supervisor.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  @impl true
  def init(opts) do
    add_module_dir(Keyword.get(opts, :module_dir, module_dir_from_config()))
    blocks = Keyword.get(opts, :modules) || gather_blocks()

    children =
      blocks
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.flat_map(fn {name, config} -> prepare(name, config) end)

    warn_missing_function_modules()
    Supervisor.init(children, strategy: :one_for_one)
  end

  @doc """
  Reload one module's config at runtime (`kelictl module reload <name>`, §8.1).
  Re-reads its block from the config sources, `validate_config/1` first (an invalid
  block is rejected, the running service untouched), then `reload/2` if the module
  exports it, else a clean child restart; re-registers metadata + control surface.
  """
  @spec reload(String.t()) :: :ok | {:error, term}
  def reload(name) when is_binary(name) do
    case Map.get(gather_blocks(), name) do
      nil ->
        {:error, :not_configured}

      config ->
        add_module_dir(module_dir_from_config())

        with {:ok, module} <- ok_or_error(resolve_module(name, config)),
             :ok <- ok_or_error(validate(module, name, config)) do
          reload_code(module)
          apply_reload(name, module, config)
        end
    end
  end

  # {:skip, reason} (boot's "log & skip") becomes {:error, reason} for reload
  defp ok_or_error({:skip, reason}), do: {:error, reason}
  defp ok_or_error(other), do: other

  defp apply_reload(name, module, config) do
    name_atom = String.to_atom(name)

    outcome =
      if function_exported?(module, :reload, 2),
        do: module.reload(name_atom, config),
        else: restart_child(module.child_spec(name_atom, config))

    case outcome do
      :ok ->
        register(name, module, config)
        :ok

      other ->
        other
    end
  end

  defp restart_child(spec) do
    id = spec_id(spec)
    _ = Supervisor.terminate_child(__MODULE__, id)
    _ = Supervisor.delete_child(__MODULE__, id)

    case Supervisor.start_child(__MODULE__, spec) do
      {:ok, _pid} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp spec_id(%{id: id}), do: id
  defp spec_id(spec) when is_tuple(spec), do: elem(spec, 0)

  # ── dynamic code loading from module_dir (§8.3, §12.1) ───────────────────────

  @doc """
  Put `module_dir` on the code path so the `.beam` files installed there become
  loadable. Idempotent (the code server keeps one entry per path). Returns `:ok`
  whatever happens: a missing directory is normal — a deployment that installs no
  module, or a dev/test run where the modules come from the build path.
  """
  @spec add_module_dir(String.t() | nil) :: :ok
  def add_module_dir(nil), do: :ok

  def add_module_dir(dir) when is_binary(dir) do
    path = String.to_charlist(dir)

    cond do
      path in :code.get_path() ->
        :ok

      File.dir?(dir) ->
        true = :code.add_pathz(path)
        Logger.info(module: __MODULE__, message: "module_dir #{dir} added to the code path")
        :ok

      true ->
        Logger.debug(
          module: __MODULE__,
          message: "module_dir #{dir} does not exist; only already-loaded modules can be used"
        )

        :ok
    end
  end

  defp module_dir_from_config() do
    if Process.whereis(Kelix.Config), do: Kelix.Config.current().module_dir
  end

  @doc """
  Make `module` usable, loading it **and the beams it is implemented with** from the
  code path if needed.

  `Code.ensure_loaded?/1` is **not enough in a release**: the code server then runs
  in *embedded* mode, where it never searches the code path — it answers
  `{:error, :embedded}` for anything not already loaded, and an undefined-function
  call does not trigger an implicit load either. Loading code installed after boot
  is therefore an explicit act: try the implicit path first (dev/test, interactive
  mode), then `:code.load_file/1`, which searches the path in both modes.

  The same reasoning applies one step further, and that step is what the `mcu` module
  first tripped on: a module of any size is spread over several beams
  (`Kelix.Mod.Mcu` calls `Kelix.Mod.Mcu.Config`, `.Client`, `.Conference`…), and in
  embedded mode the *first call* to a companion raises `UndefinedFunctionError`
  instead of loading it — a crash at boot, in `validate_config/1`, before anything
  is running. So the **companions are loaded too**: every beam sharing the module's
  namespace prefix, taken from the directory the module itself came from. A load
  failure there is logged and tolerated — a stale or half-installed companion must
  not be reported as "this module is fine".

  The registrar never hit this: its only companion is a struct, i.e. a compiled
  literal that is never called.

  Consequence worth knowing when writing scripts: a script that calls a module's
  facade needs that module **configured** (`[module.<name>]`) — that block is what
  gets it loaded. There is no lazy loading to fall back on in a release.
  """
  @spec ensure_loaded(module) :: boolean
  def ensure_loaded(module) when is_atom(module) do
    if load_one(module) do
      Enum.each(companions(module), &load_one/1)
      true
    else
      false
    end
  end

  defp load_one(module) do
    Code.ensure_loaded?(module) or
      case :code.load_file(module) do
        {:module, ^module} ->
          true

        {:error, reason} ->
          Logger.warning(
            module: __MODULE__,
            message: "could not load #{inspect(module)}: #{inspect(reason)}"
          )

          false
      end
  end

  # The beams sharing `module`'s namespace, found next to its own beam rather than by
  # asking the config: what a module is implemented with is decided by what was
  # *installed*, and `:code.which/1` names the very file the module was loaded from —
  # so this keeps working for a module that came from the build path in dev.
  defp companions(module) do
    with path when is_list(path) <- :code.which(module),
         dir = Path.dirname(List.to_string(path)),
         prefix = Atom.to_string(module) do
      dir
      |> Path.join(prefix <> ".*.beam")
      |> Path.wildcard()
      |> Enum.map(&String.to_atom(Path.basename(&1, ".beam")))
    else
      # :non_existing (defined in a test, never on disk), :preloaded, :cover_compiled
      _ -> []
    end
  end

  # function → the modules its reference script needs. `registrar` needs two: the
  # usrloc store AND the authentication backend — a registrar with no `auth_db`
  # loaded fails exactly as hard as one with no `registrar`, and forgetting the
  # auth half is the easier mistake of the two (nothing is named after it).
  @function_modules %{registrar: ["registrar", "auth_db"], presence: ["presence"]}

  @doc """
  Warn when a domain enables a SIP function whose module(s) are **not** loaded.
  Since no module ships inside the core (§16.12), a deployment that enables
  `registrar` without installing `kelixip-mod-registrar` is now a real (and easy)
  mistake — and a costly one: the function's script raises on its first facade call,
  the instance dies, and the request goes **unanswered** rather than refused.

  A warning, not an error: a script is free to serve a function without a given
  module (its own store, another backend). Turning it into the load-time config
  error §3.2 calls for would need scripts to *declare* the modules they use — see
  the open item in §16.
  """
  @spec warn_missing_function_modules() :: :ok
  def warn_missing_function_modules() do
    loaded = Map.keys(Kelix.ModuleRegistry.all())

    for {function, module_names} <- @function_modules,
        module_name <- module_names,
        module_name not in loaded,
        domain <- domains_enabling(function) do
      Logger.warning(
        module: __MODULE__,
        message:
          "domain #{domain} enables #{function} but no #{inspect(module_name)} module is " <>
            "loaded (module_dir): its script will fail unless it needs none"
      )
    end

    :ok
  end

  defp domains_enabling(function) do
    if Process.whereis(Kelix.Domains) do
      for domain <- Kelix.Domains.current().domains,
          Map.get(domain, function) != nil,
          do: domain.name
    else
      []
    end
  end

  # Re-read a module's `.beam` from disk so `kelictl module reload <name>` picks up
  # a newly installed version, not just a config change. `:nofile` is expected and
  # fine for a module that has no `.beam` of its own (defined in a test, or part of
  # a release's own code): there is simply nothing to re-read.
  #
  # The companions are re-read too, and for a sharper reason than at load time: a
  # package installs `Mcu.beam` and `Mcu.Config.beam` together, so reloading only the
  # named one would run new code against a stale companion — a mismatch harder to
  # diagnose than an outright failure to load. Collected *before* the purge, since
  # `:code.which/1` cannot name the file of a module that is no longer loaded.
  #
  # Note (§16.2): this replaces the *code*; a service that implements `reload/2`
  # keeps its state and adopts the new code on its next fully-qualified call, while
  # one without it is restarted cleanly just below. Full `code_change`-style state
  # migration is out of basic scope.
  defp reload_code(module) do
    Enum.each([module | companions(module)], &purge_and_load/1)
    :ok
  end

  defp purge_and_load(module) do
    :code.purge(module)

    case :code.load_file(module) do
      {:module, ^module} ->
        Logger.info(module: __MODULE__, message: "reloaded #{inspect(module)} code from disk")

      {:error, :nofile} ->
        :ok

      {:error, reason} ->
        Logger.warning(
          module: __MODULE__,
          message: "could not reload #{inspect(module)} code: #{inspect(reason)}"
        )
    end

    :ok
  end

  # ── block gathering (config.toml + registrar from domains.toml) ──────────────

  defp gather_blocks(), do: block_sources(current(Kelix.Config), current(Kelix.Domains))

  @doc """
  Merge the two config sources into the `%{name => block}` set to start: every
  module from `config.toml` **except** `registrar`, plus `registrar` from
  `domains.toml` (§6.1/§8.1) — so a stray `[module.registrar]` in `config.toml`
  is ignored.
  """
  @spec block_sources(map, map) :: map
  def block_sources(config_modules, domain_modules) do
    config_modules
    |> Map.delete("registrar")
    |> Map.merge(Map.take(domain_modules, ["registrar"]))
  end

  # read the `.modules` field of a started Config/Domains GenServer, else %{}
  defp current(mod) do
    if Process.whereis(mod), do: Map.get(mod.current(), :modules, %{}), else: %{}
  end

  # ── per-module preparation: resolve → validate → register → child spec ───────

  # returns a (possibly empty) list of child specs to add under the supervisor
  defp prepare(name, config) when is_map(config) do
    with {:ok, module} <- resolve_module(name, config),
         :ok <- validate(module, name, config) do
      register(name, module, config)
      [module.child_spec(String.to_atom(name), config)]
    else
      {:skip, reason} ->
        Logger.error(
          module: __MODULE__,
          message: "module #{inspect(name)} not started: #{reason}"
        )

        []
    end
  end

  defp prepare(name, _config) do
    Logger.error(
      module: __MODULE__,
      message: "module #{inspect(name)} not started: block must be a table"
    )

    []
  end

  defp resolve_module(name, config) do
    module =
      case Map.get(config, "module") do
        m when is_binary(m) and m != "" -> Module.concat([m])
        _ -> Module.concat(Kelix.Mod, Macro.camelize(name))
      end

    cond do
      not ensure_loaded(module) ->
        {:skip, "module #{inspect(module)} is not installed (no .beam in module_dir?)"}

      not function_exported?(module, :child_spec, 2) ->
        {:skip, "#{inspect(module)} does not implement the Kelix.Module behaviour"}

      true ->
        {:ok, module}
    end
  end

  defp validate(module, name, config) do
    case module.validate_config(config) do
      :ok -> :ok
      {:error, reason} -> {:skip, "invalid [module.#{name}] config: #{inspect(reason)}"}
    end
  end

  defp register(name, module, config) do
    Kelix.ModuleRegistry.register(name, module, config)

    # A refused command set (ambiguous templates, FW-4) is a declaration bug in the
    # module: log it and keep the module running — its facades and config are fine,
    # only its control surface is unavailable.
    if function_exported?(module, :describe_control, 0) do
      case Kelix.Control.Registry.register(name, module.describe_control()) do
        {:error, reason} ->
          Logger.error(
            module: __MODULE__,
            message: "module #{inspect(name)} has no control surface: #{inspect(reason)}"
          )

        _ ->
          :ok
      end
    end

    Logger.info(
      module: __MODULE__,
      message: "module #{inspect(name)} loaded (#{inspect(module)})"
    )
  end
end
