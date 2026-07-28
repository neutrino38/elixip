defmodule Kelix.Control do
  @moduledoc """
  The control layer — the **single source of truth** for every administrative
  operation (design §10.1). Both frontals call into here and hold no business
  logic: `kelictl` (`Kelix.Control.CLI`, over Erlang RPC) and the REST API (P8).

  Every function delegates to an existing surface (`InstancePool`, `Domains`,
  `ScriptRegistry`, `MediaPool`, `Mod.Registrar`, …) and tolerates a surface being
  down (returns a value, never crashes the caller).

  Auth is a **frontal** concern (§10.3): neither this module nor a module's
  `handle_control/2` inspects credentials — they assume an authenticated caller.
  """
  require Logger

  @log_levels %{"debug" => :debug, "info" => :info, "warning" => :warning, "error" => :error}

  # ── read verbs ────────────────────────────────────────────────────────────────

  @doc "Uptime, counters, media-pool and node state (`kelictl status`)."
  @spec status() :: map
  def status() do
    %{
      node: node(),
      uptime_ms: uptime_ms(),
      instances: safe(fn -> Kelix.InstancePool.stats() end, %{}),
      listeners: safe(fn -> Kelix.Listener.Supervisor.status() end, []),
      media_pool: safe(fn -> Kelix.MediaPool.status() end, []),
      modules: Map.keys(safe(fn -> Kelix.ModuleRegistry.all() end, %{})),
      domains_version: safe(fn -> Kelix.Domains.current().version end, 0)
    }
  end

  @doc """
  Scenarios in progress (`kelictl monitor`).

  Joins the two views that each hold half the answer, on the instance id:

    * `Kelix.InstancePool.list/0` — **which** instances exist (`id`, `domain`,
      `function`, `script`, `pid`). The `id` is what `shutdown_scenario/1`
      (`kelictl stop <id>`) takes, and no other command exposes it.
    * `SIP.Scenario.Monitor` — **where each FSM is**: current `state`, the `event`
      that got it there, the last `command` it issued, and the `account` it serves.
      Reading the FSM state is the whole point of a DSL-driven server; without it
      the formalism is invisible from the outside.

  Rows the pool does not know about (a `sub_fsm` child, keyed `{id, name}`) are not
  surfaced: the server spawns none today (`:uas_register` is not supported as a
  sub-FSM). A missing monitor row degrades to empty FSM columns, never an error.
  """
  @spec monitor() :: [map]
  def monitor() do
    fsm = safe(fn -> Map.new(SIP.Scenario.Monitor.calls(), &{&1.slot, &1}) end, %{})

    for row <- safe(fn -> Kelix.InstancePool.list() end, []) do
      Map.merge(row, fsm_fields(Map.get(fsm, row.id)))
    end
  end

  @empty_fsm %{scenario: "", state: "", event: "", command: "", account: ""}

  defp fsm_fields(nil), do: @empty_fsm

  defp fsm_fields(entry),
    do: Map.merge(@empty_fsm, Map.take(entry, [:scenario, :state, :event, :command, :account]))

  @doc """
  Current registrations (`kelictl regs [aor]`). `aor` filters by user-part, and by
  domain when given as `"user@domain"`; `nil` lists every domain. Returns rows
  `%{domain, aor, contacts}` where each contact is `%{uri, expires_at}`.
  """
  @spec registrations(String.t() | nil) :: [map]
  def registrations(aor \\ nil) do
    {user, dom} = if aor, do: split_aor(aor), else: {nil, nil}

    for d <- domain_names(),
        is_nil(dom) or d == dom,
        {a, contacts} <- registrations_for(d),
        is_nil(user) or a == user do
      %{domain: d, aor: a, contacts: Enum.map(contacts, &render_contact/1)}
    end
  end

  # ── write verbs ───────────────────────────────────────────────────────────────

  @doc """
  Remove a registration (`kelictl unregister <aor> [contact]`). `aor` may be
  `"user@domain"` (that domain) or `"user"` (every domain). `contact` is a
  contact-URI string or `:all`. `:ok` if anything was removed, else `:notfound`.
  """
  @spec unregister(String.t(), String.t() | :all) :: :ok | :notfound
  def unregister(aor, contact \\ :all) do
    {user, dom} = split_aor(aor)
    targets = if dom, do: [dom], else: domain_names()
    # via the registry: the registrar is a loadable module, absent from the core
    results =
      Enum.map(
        targets,
        &Kelix.ModuleRegistry.facade("registrar", :remove, [&1, user, contact], :notfound)
      )

    if Enum.any?(results, &(&1 == :ok)), do: :ok, else: :notfound
  end

  @doc "Cooperatively shut down one scenario by id (`kelictl stop <id>`)."
  @spec shutdown_scenario(pos_integer) :: :ok | {:error, :not_found}
  def shutdown_scenario(id) when is_integer(id), do: Kelix.InstancePool.shutdown(id)

  @doc """
  Reload one or more scenario scripts by name (`kelictl reload-script <name…>`).
  Returns `%{name => :ok | {:error, reason}}`. `notify?` is accepted for parity
  with the spec (in-progress-instance notification is a roadmap refinement).
  """
  @spec reload_script([String.t()], boolean) :: %{optional(String.t()) => :ok | {:error, term}}
  def reload_script(names, _notify? \\ false) when is_list(names) do
    Map.new(names, fn name -> {name, Kelix.ScriptRegistry.reload(name)} end)
  end

  @doc "Hot-reload `domains.toml` (`kelictl reload-domains`). Path from the boot env."
  @spec reload_domains() :: :ok | {:error, term}
  def reload_domains() do
    case Application.get_env(:kelixip, :domains_path) do
      nil ->
        {:error, :no_domains_path}

      path ->
        with :ok <- Kelix.Domains.reload(path) do
          # a freshly enabled domain may need a module nobody installed (§8.3)
          Kelix.ModuleSupervisor.warn_missing_function_modules()
        end
    end
  end

  @doc "Reload a module's config (`kelictl module reload <name>`)."
  @spec module_reload(String.t()) :: :ok | {:error, term}
  def module_reload(name) when is_binary(name), do: Kelix.ModuleSupervisor.reload(name)

  @doc "Enable/disable a media server in the pool (`kelictl mcu <name> on|off`)."
  @spec mediaserver_toggle(String.t(), boolean) :: :ok | {:error, :unknown}
  def mediaserver_toggle(name, on?) when is_boolean(on?), do: Kelix.MediaPool.toggle(name, on?)

  @doc "Set the runtime log level (`kelictl log-level <lvl>`)."
  @spec set_log_level(String.t() | atom) :: :ok | {:error, :invalid_level}
  def set_log_level(level) do
    case @log_levels[to_string(level)] do
      nil -> {:error, :invalid_level}
      lvl -> Logger.configure(level: lvl)
    end
  end

  @doc """
  Drain running scenarios then stop the node (`kelictl graceful-shutdown`). The
  final `System.stop/0` is suppressed when `:kelixip, :graceful_stop` is `false`
  (tests), so the drain can be exercised without killing the VM.
  """
  @spec graceful_shutdown() :: :ok
  def graceful_shutdown() do
    Kelix.InstancePool.shutdown_all(:graceful_shutdown)

    if Application.get_env(:kelixip, :graceful_stop, true) do
      Task.start(fn ->
        Process.sleep(Application.get_env(:kelixip, :graceful_grace_ms, 2_000))
        System.stop(0)
      end)
    end

    :ok
  end

  # ── module-contributed commands (§8.1) ────────────────────────────────────────

  @doc """
  Run a module-contributed command (`kelictl <module> <cmd> <args>`). Resolves the
  module by its registered name and delegates to its `handle_control/2` (which
  never checks auth — that is the frontal's job).
  """
  @spec module_command(String.t(), String.t(), map) :: {:ok, term} | {:error, term}
  def module_command(module_name, cmd, args) when is_binary(module_name) and is_binary(cmd) do
    case Kelix.ModuleRegistry.lookup(module_name) do
      %{module: module} ->
        if function_exported?(module, :handle_control, 2),
          do: module.handle_control(cmd, args),
          else: {:error, :no_command_surface}

      nil ->
        {:error, :unknown_module}
    end
  end

  # ── helpers ───────────────────────────────────────────────────────────────────

  defp uptime_ms(), do: elem(:erlang.statistics(:wall_clock), 0)

  defp domain_names() do
    safe(fn -> Enum.map(Kelix.Domains.current().domains, & &1.name) end, [])
  end

  defp registrations_for(domain) do
    case Kelix.ModuleRegistry.facade("registrar", :all, [domain], %{}) do
      m when is_map(m) -> m
      _ -> %{}
    end
  end

  # Matched structurally, not as `%Kelix.Mod.Registrar.Contact{}`: the core cannot
  # reference a loadable module's struct at compile time (§16.12).
  defp render_contact(%{contact: uri, expires_at: at}) do
    %{uri: uri_string(uri), expires_at: at}
  end

  defp uri_string(%SIP.Uri{} = uri) do
    case SIP.Uri.serialize(uri) do
      {:ok, s} -> s
      _ -> inspect(uri)
    end
  end

  defp uri_string(other), do: inspect(other)

  # "user@domain" -> {"user", "domain"}; "user" -> {"user", nil}
  defp split_aor(aor) do
    case String.split(aor, "@", parts: 2) do
      [user, domain] -> {String.downcase(user), String.downcase(domain)}
      [user] -> {String.downcase(user), nil}
    end
  end

  # run `fun`, returning `default` if the surface is down / raises / exits
  defp safe(fun, default) do
    fun.()
  rescue
    _ -> default
  catch
    _, _ -> default
  end
end
