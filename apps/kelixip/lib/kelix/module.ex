defmodule Kelix.Module do
  @moduledoc """
  The loadable-module contract (design `docs/design/kelixip_basic_design.md` §8, spec §5).

  A module is a **stateful OTP service** (a connection pool, a store …) **plus
  stateless facades** imported by scripts. `Kelix.ModuleSupervisor` starts one
  child per `[module.<name>]` block; the `<name>` is the registered name used by
  facade resolution (`Kelix.ModuleRegistry`).

  Three ways to plug in (like Kamailio modules): **config** (`[module.<name>]`),
  **REST** (`/modules/<name>/…`) and **CLI** (`kelictl <name> <cmd>`). The REST +
  CLI surface is declared **once** via `describe_control/0` and both frontals
  derive from it (parity by construction) — see `Kelix.Control.Registry`.

  This module is both the behaviour and the home of `safe_call/3`, the helper the
  facades route their `GenServer.call` through so a facade never blocks the
  scenario instance nor raises: a down service yields `{:error, :down}` and a slow
  one `{:error, :timeout}` (spec §5.2), leaving the instance in control of the SIP
  response.
  """

  @typedoc "A REST+CLI command a module contributes (declared once, both frontals derive from it)."
  @type control_command :: %{
          name: String.t(),
          args: [%{name: String.t(), required: boolean}],
          rest: {:get | :post | :delete, String.t()},
          rw: :r | :w,
          help: String.t()
        }

  # Validate the [module.<name>] block BEFORE starting/reconfiguring anything. An
  # invalid config is rejected without touching a running service.
  @callback validate_config(config :: map) :: :ok | {:error, reason :: term}

  # child_spec placed under Kelix.ModuleSupervisor. `name` = TOML key (the
  # registered name used by facade resolution). `config` = the [module.<name>] map.
  @callback child_spec(name :: atom, config :: map) :: Supervisor.child_spec()

  # Metadata: version + functions exported to scenarios.
  @callback describe() :: %{version: String.t(), exports: [{atom, arity :: non_neg_integer}]}

  # Hot reload — OPTIONAL. Present ⇒ in-place reconfiguration (keeps resources up).
  # Absent ⇒ the supervisor restarts the child cleanly.
  @callback reload(name :: atom, config :: map) :: :ok | {:error, term}

  # Control surface (REST + CLI) — OPTIONAL. Registered into Kelix.Control.Registry
  # by the ModuleSupervisor at start, deregistered on stop/reload (§8.1, §10).
  @callback describe_control() :: [control_command]

  # Run a declared command. NEVER checks auth — that is enforced at the frontal
  # boundary (§10), keeping the module logic pure.
  @callback handle_control(name :: String.t(), args :: map) :: {:ok, term} | {:error, term}

  @optional_callbacks reload: 2, describe_control: 0, handle_control: 2

  @default_call_timeout_ms 5_000

  @doc """
  Call a module's service on behalf of a facade, **without blocking or raising**.

  `server` is the service's registered name (for the provided modules, the module
  itself). Returns the service reply, or `{:error, :down}` if it is not running,
  or `{:error, :timeout}` if it does not answer within the bound. The timeout is
  `opts[:timeout]`, else the module's `call_timeout_ms` (from `Kelix.ModuleRegistry`),
  else #{@default_call_timeout_ms} ms.
  """
  @spec safe_call(GenServer.server(), term, keyword) :: term | {:error, :down | :timeout}
  def safe_call(server, request, opts \\ []) do
    timeout =
      Keyword.get(opts, :timeout) ||
        Kelix.ModuleRegistry.call_timeout(server, @default_call_timeout_ms)

    case whereis(server) do
      nil ->
        {:error, :down}

      pid ->
        try do
          GenServer.call(pid, request, timeout)
        catch
          :exit, _ -> {:error, :timeout}
        end
    end
  end

  @doc "The default facade-call timeout (ms) applied when nothing overrides it."
  @spec default_call_timeout_ms() :: pos_integer
  def default_call_timeout_ms(), do: @default_call_timeout_ms

  # a registered name resolves via the process registry; a bare pid passes through
  defp whereis(pid) when is_pid(pid), do: if(Process.alive?(pid), do: pid)
  defp whereis(name) when is_atom(name), do: Process.whereis(name)
  defp whereis({:global, _} = ref), do: GenServer.whereis(ref)
  defp whereis({:via, _, _} = ref), do: GenServer.whereis(ref)
end
