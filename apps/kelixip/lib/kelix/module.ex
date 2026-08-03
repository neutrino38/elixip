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

  @typedoc "An HTTP method a control command may declare."
  @type control_method :: :get | :post | :put | :patch | :delete

  @typedoc """
  A REST+CLI command a module contributes (declared once, both frontals derive
  from it).

  `rest` is `{method | [method], path_template}`; the template is **relative to
  `/modules/<name>`** and may contain `:param` segments
  (`"/conferences/:uid/participants"`). A method list is what lets one declaration
  answer both `PUT` and `PATCH`. Path params are merged into the args map handed to
  `handle_control/2`, so a command receives `%{"uid" => …}` identically from REST
  and from `kelictl` (design `docs/design/mcu_module.md` §8.3.4, FW-4).

  The three optional keys let the REST frontal **derive** its HTTP concerns from
  the declaration, so `handle_control/2` keeps returning plain domain results and
  the same function serves `kelictl` unchanged:

    * `status:` — success status (default `200`, e.g. `201` on a creation);
    * `location:` — `Location:` template, rendered from the result map
      (`"/conferences/:uid"` needs the result to carry `uid`);
    * `errors:` — `%{reason_atom => status}`, consulted before the default
      404/400 mapping (that is how a module gets a `409`).

  A command that declares none of them, with a single-segment template, behaves
  exactly as it did before FW-4.

  `render:` — OPTIONAL — is how a command tells the **CLI** what its result should
  look like, keeping `kelictl` module-agnostic (the REST frontal ignores it, JSON
  is already structured). `kind: :table` renders a list of maps as a table of the
  named `columns:`; `kind: :detail` renders one map as `Label: value` lines, the
  declared `fields:` first. `labels:` maps a dotted field path to `%{"raw" =>
  "human"}` value names (`"video.size" => %{"6" => "hd720p"}`) — everything is
  strings so the hint survives both the RPC and the JSON encoding of `GET /modules`.

  In a `:detail` view a field holding a list of maps becomes an indented table and
  one holding a map of maps an indented block, since neither fits a line. `nested:`
  picks the columns of such a table (`%{"participants" => %{columns: [...]}}`);
  without it they are derived from the rows, so a module gets a readable block
  whether or not it declares one.
  """
  @type control_command :: %{
          required(:name) => String.t(),
          required(:args) => [%{name: String.t(), required: boolean}],
          required(:rest) => {control_method | [control_method], String.t()},
          required(:rw) => :r | :w,
          required(:help) => String.t(),
          optional(:status) => 100..599,
          optional(:location) => String.t(),
          optional(:errors) => %{optional(atom) => 100..599},
          optional(:render) => %{
            required(:kind) => :table | :detail,
            optional(:columns) => [String.t()],
            optional(:fields) => [String.t()],
            optional(:labels) => %{optional(String.t()) => %{optional(String.t()) => String.t()}},
            optional(:nested) => %{optional(String.t()) => %{optional(:columns) => [String.t()]}}
          }
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
