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

  Tests may bypass the config sources with `start_link(modules: %{name => block})`.
  """
  use Supervisor
  require Logger

  @spec start_link(keyword) :: Supervisor.on_start()
  def start_link(opts \\ []),
    do: Supervisor.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  @impl true
  def init(opts) do
    blocks = Keyword.get(opts, :modules) || gather_blocks()

    children =
      blocks
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.flat_map(fn {name, config} -> prepare(name, config) end)

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
        with {:ok, module} <- ok_or_error(resolve_module(name, config)),
             :ok <- ok_or_error(validate(module, name, config)) do
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
      not Code.ensure_loaded?(module) ->
        {:skip, "module #{inspect(module)} is not loaded"}

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

    if function_exported?(module, :describe_control, 0),
      do: Kelix.Control.Registry.register(name, module.describe_control())

    Logger.info(
      module: __MODULE__,
      message: "module #{inspect(name)} loaded (#{inspect(module)})"
    )
  end
end
