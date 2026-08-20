defmodule Kelix.Control.Registry do
  @moduledoc """
  Central registry of the **module-contributed** control commands (design §8.1,
  §10). At module start `Kelix.ModuleSupervisor` reads each module's
  `describe_control/0` and registers the entries here, keyed by module name;
  they are deregistered on stop/reload.

  Both control frontals iterate this registry (parity by construction, §10):
  `Kelix.ControlAPI` mounts the `/modules/<name>/…` routes and `kelictl` generates
  the `<name> <cmd>` sub-commands. The frontals land in P7; this phase provides
  the registry and its population.

  Held in a supervised `Agent`; reads tolerate it being absent.

  Registration is also where a **conflicting command set is refused** (FW-4,
  `docs/design/DESIGN-MCU.md`): two commands whose path templates no request
  could tell apart would make dispatch depend on iteration order, so the module's
  whole surface is rejected here instead — a declaration bug, caught once at start,
  rather than a request-time coin flip.
  """
  use Agent
  require Logger

  @type command :: Kelix.Module.control_command()

  @spec start_link(keyword) :: Agent.on_start()
  def start_link(_opts \\ []), do: Agent.start_link(fn -> %{} end, name: __MODULE__)

  @doc """
  Register a module's declared commands (no-op for an empty list).

  `{:error, {:ambiguous_templates, a, b}}` when two commands declare templates that
  cannot be told apart; nothing is registered in that case.
  """
  @spec register(String.t(), [command]) :: :ok | {:error, term}
  def register(_name, []), do: :ok

  def register(name, commands) when is_binary(name) and is_list(commands) do
    case Kelix.Control.Route.check_conflicts(commands) do
      :ok ->
        if alive?(), do: Agent.update(__MODULE__, &Map.put(&1, name, commands)), else: :ok

      {:error, reason} ->
        Logger.error(
          module: __MODULE__,
          message:
            "module #{inspect(name)} declares an unroutable command set: #{inspect(reason)}"
        )

        {:error, reason}
    end
  end

  @doc "Drop a module's commands (stop / reload)."
  @spec deregister(String.t()) :: :ok
  def deregister(name) when is_binary(name) do
    if alive?(), do: Agent.update(__MODULE__, &Map.delete(&1, name)), else: :ok
  end

  @doc "The commands declared by `name`, or `[]`."
  @spec commands_for(String.t()) :: [command]
  def commands_for(name) when is_binary(name), do: Map.get(all(), name, [])

  @doc "Every module's commands as `%{name => [command]}` (empty if the registry is down)."
  @spec all() :: %{optional(String.t()) => [command]}
  def all(), do: if(alive?(), do: Agent.get(__MODULE__, & &1), else: %{})

  defp alive?(), do: Process.whereis(__MODULE__) != nil
end
