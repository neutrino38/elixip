defmodule Kelix.ModuleRegistry do
  @moduledoc """
  The in-memory catalogue of loaded modules (design §8.1). `Kelix.ModuleSupervisor`
  records one entry per started `[module.<name>]` block; facades and the control
  layer read it back.

  An entry is `name => %{module: module, config: map}` — no pid: the service is
  a supervised process resolved by its registered name at call time (single
  instance, §8.2). Held in a supervised `Agent`; every read tolerates the Agent
  being absent (returns empty / the default) so a facade in a bare test still works.
  """
  use Agent

  @type entry :: %{module: module, config: map}

  @spec start_link(keyword) :: Agent.on_start()
  def start_link(_opts \\ []), do: Agent.start_link(fn -> %{} end, name: __MODULE__)

  @doc "Record a loaded module under `name` (called by the ModuleSupervisor)."
  @spec register(String.t(), module, map) :: :ok
  def register(name, module, config) when is_binary(name) and is_atom(module) do
    Agent.update(__MODULE__, &Map.put(&1, name, %{module: module, config: config}))
  end

  @doc "Drop a module's entry (stop / reload)."
  @spec unregister(String.t()) :: :ok
  def unregister(name) when is_binary(name) do
    if alive?(), do: Agent.update(__MODULE__, &Map.delete(&1, name)), else: :ok
  end

  @doc "All loaded modules as `%{name => entry}` (empty if the registry is down)."
  @spec all() :: %{optional(String.t()) => entry}
  def all(), do: if(alive?(), do: Agent.get(__MODULE__, & &1), else: %{})

  @doc "The entry for `name` (by TOML name), or nil."
  @spec lookup(String.t()) :: entry | nil
  def lookup(name) when is_binary(name), do: Map.get(all(), name)

  @doc """
  Call a loaded module's **facade by its configured name**.

  This is how the core reaches a module, and the only way it can: no module is
  compiled into the core release (§16.12), so `Kelix.Control` must never name
  `Kelix.Mod.…` at compile time — that would both fail to compile without the
  module present and defeat the whole point of loading it from `module_dir`.

  Returns `default` when the module is not loaded, does not export the function, or
  raises/exits — the control layer answers a value, never crashes its caller.
  """
  @spec facade(String.t(), atom, [term], term) :: term
  def facade(name, fun, args, default) when is_binary(name) and is_atom(fun) and is_list(args) do
    case lookup(name) do
      %{module: module} ->
        if function_exported?(module, fun, length(args)) do
          try do
            apply(module, fun, args)
          catch
            _kind, _reason -> default
          end
        else
          default
        end

      nil ->
        default
    end
  end

  @doc """
  The `call_timeout_ms` configured for a module, or `default`. `ref` is either the
  TOML name or the service module (facades pass their `__MODULE__`).
  """
  @spec call_timeout(String.t() | module, pos_integer) :: pos_integer
  def call_timeout(ref, default) do
    case find_entry(ref) do
      %{config: config} -> to_pos_int(Map.get(config, "call_timeout_ms"), default)
      nil -> default
    end
  end

  # ── internals ────────────────────────────────────────────────────────────────

  defp find_entry(name) when is_binary(name), do: lookup(name)

  defp find_entry(module) when is_atom(module) do
    all() |> Map.values() |> Enum.find(&(&1.module == module))
  end

  defp to_pos_int(v, _default) when is_integer(v) and v > 0, do: v
  defp to_pos_int(_v, default), do: default

  defp alive?(), do: Process.whereis(__MODULE__) != nil
end
