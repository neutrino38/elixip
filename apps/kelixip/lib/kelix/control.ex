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
      # Whether this node still tells upstream it takes traffic. A draining node looks
      # healthy in every other line here while answering 503 to the OPTIONS pings, so
      # it has to be visible: it is the difference between "nobody calls us" and
      # "we asked nobody to call us".
      draining: draining?(),
      options_allow: Kelix.Options.allow(),
      instances: safe(fn -> Kelix.InstancePool.stats() end, %{}),
      listeners: safe(fn -> Kelix.Listener.Supervisor.status() end, []),
      media_pool: safe(fn -> Kelix.MediaPool.status() end, []),
      modules: Map.keys(safe(fn -> Kelix.ModuleRegistry.all() end, %{})),
      # What each loaded module says about itself right now (conferences and
      # participants, for the conferencing module). Generic: a module that exports
      # `status/0` contributes a line, one that does not is simply absent — the core
      # names no module here.
      module_status: module_status(),
      domains_version: safe(fn -> Kelix.Domains.current().version end, 0)
    }
  end

  defp module_status() do
    for {name, _entry} <- safe(fn -> Kelix.ModuleRegistry.all() end, %{}),
        summary = Kelix.ModuleRegistry.facade(name, :status, [], nil),
        is_map(summary),
        into: %{},
        do: {name, summary}
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

  @doc """
  The served domains and their properties (`kelictl domain list`), in
  `domains.toml` order — which is significant, the dial-plan is first-match-wins.

  Each row is what `domain/1` returns for that domain: the configured properties
  plus the live counters (active calls, registrations), so the list and the detail
  view never disagree about a field.
  """
  @spec domains() :: [map]
  def domains() do
    snapshot = current_domains()
    active = active_calls()

    Enum.map(snapshot.domains, &describe_domain(&1, active))
  end

  @doc """
  One domain and its properties (`kelictl domain show <domain>`). `name` is
  matched the way inbound traffic is — against the domain name *and* its aliases,
  case-insensitively — so `show` answers for whatever host an operator saw on the
  wire. `{:error, :not_found}` if no domain serves that host.

  The returned map is the configuration (`aliases`, `max_calls`, the enabled
  functions with their scripts and tuning, the ordered dial-plan) plus the live
  counters for that domain.
  """
  @spec domain(String.t()) :: {:ok, map} | {:error, :not_found}
  def domain(name) when is_binary(name) do
    case Kelix.Domains.lookup(current_domains(), name) do
      nil -> {:error, :not_found}
      d -> {:ok, describe_domain(d, active_calls())}
    end
  end

  # A domain as both frontals show it. `function_enabled?/2` is asked rather than
  # re-derived here: "a function block present = enabled" is the router's reading
  # of domains.toml, and the operator must be told exactly what the router will do.
  defp describe_domain(%Kelix.Domain{} = d, active) do
    %{
      name: d.name,
      aliases: d.aliases,
      max_calls: d.max_calls,
      functions:
        for(f <- [:registrar, :calls, :presence], Kelix.Router.function_enabled?(d, f), do: f),
      registrar: d.registrar,
      presence: d.presence,
      dial_plan: Enum.map(d.dial_plan, &render_rule/1),
      active_calls: Map.get(active, d.name, 0),
      registrations: map_size(registrations_for(d.name))
    }
  end

  defp render_rule(%Kelix.DialRule{default?: true, script: script}),
    do: %{pattern: nil, default: true, script: script}

  defp render_rule(%Kelix.DialRule{raw: raw, script: script}),
    do: %{pattern: raw, default: false, script: script}

  @doc """
  The media servers of the pool and their state (`kelictl mediaserver list`), in
  `config.toml` order — which is significant, the pool is round-robin.

  Each row is what `mediaserver/1` returns for that entry, so the list and the
  detail view never disagree about a field.
  """
  @spec mediaservers() :: [map]
  def mediaservers() do
    modules = loaded_modules()

    Enum.map(pool_entries(), &describe_mediaserver(&1, modules))
  end

  @doc """
  One media server and its state (`kelictl mediaserver show <name>`), by its
  `[mediaserver.pool.<name>]` name. `{:error, :not_found}` if the pool has no such
  entry — the pool is the node's only declaration of a media server (§9).
  """
  @spec mediaserver(String.t()) :: {:ok, map} | {:error, :not_found}
  def mediaserver(name) when is_binary(name) do
    case Enum.find(pool_entries(), &(&1.name == name)) do
      nil -> {:error, :not_found}
      entry -> {:ok, describe_mediaserver(entry, loaded_modules())}
    end
  end

  # The configured entry (name/adapter/url), the operator switch (`enabled`), the
  # pool's own probe (`healthy`) and what each module driving media servers says
  # about this one.
  defp describe_mediaserver(entry, modules) do
    %{
      name: entry.name,
      module: entry.module,
      url: entry.url,
      enabled: entry.enabled,
      healthy: Map.get(entry, :healthy, true),
      modules: module_mediaserver_views(modules, entry.name)
    }
  end

  # `healthy` is the pool's probe of the point-to-point adapter's channel; the mcu
  # module holds a *different* channel to the same server and has its own view of it
  # (§9). A server can be up on one and down on the other, so both are reported.
  # Generic: a module exporting `mediaserver/1` contributes an entry, one that does
  # not is simply absent — the core names no module here.
  defp module_mediaserver_views(modules, name) do
    for m <- modules,
        {:ok, view} <- [Kelix.ModuleRegistry.facade(m, :mediaserver, [name], :error)],
        is_map(view),
        into: %{},
        do: {m, printable(view)}
  end

  # A module's view keeps its own shape — minus the values that mean nothing outside
  # the node (the pid of its control channel, a monitor ref): both frontals render
  # this, and neither a CLI line nor a JSON body has any use for `#PID<0.123.0>`.
  defp printable(view), do: for({k, v} <- view, printable?(v), into: %{}, do: {k, v})

  defp printable?(v), do: not (is_pid(v) or is_reference(v) or is_port(v) or is_function(v))

  defp pool_entries(), do: safe(fn -> Kelix.MediaPool.status() end, [])

  defp loaded_modules(), do: Map.keys(safe(fn -> Kelix.ModuleRegistry.all() end, %{}))

  defp current_domains(), do: safe(fn -> Kelix.Domains.current() end, %Kelix.Domains{})

  defp active_calls() do
    safe(fn -> Map.get(Kelix.InstancePool.stats(), :per_domain, %{}) end, %{})
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

  @doc "Hot-reload `domains.toml` (`kelictl domain reload-all`). Path from the boot env."
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

  @doc "Enable/disable a media server in the pool (`kelictl mediaserver enable|disable <name>`)."
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

  # ── drain ─────────────────────────────────────────────────────────────────────

  @doc """
  Leave the upstream rotation without touching what is in flight (`kelictl drain`).

  While draining, `Kelix.Options` answers **503** to the OPTIONS liveness pings, which
  is how an upstream proxy or load balancer learns to stop sending new traffic here.
  Registrations and calls already established keep working: nothing is torn down.

  This is the missing half of a graceful stop. `graceful_shutdown/0` used to tear the
  instances down immediately, while upstream — having no signal — kept sending new
  REGISTERs and INVITEs into a node that was dying.
  """
  @spec drain() :: :ok
  def drain() do
    Application.put_env(:kelixip, :draining, true)
    Logger.warning("Node draining: OPTIONS now answered 503, no new traffic expected.")
    :ok
  end

  @doc "Return to service (`kelictl undrain`): OPTIONS are answered 200 again."
  @spec undrain() :: :ok
  def undrain() do
    Application.put_env(:kelixip, :draining, false)
    Logger.warning("Node back in service: OPTIONS answered 200.")
    :ok
  end

  @doc "Whether the node is draining (read by `Kelix.Options` on every ping)."
  @spec draining?() :: boolean()
  def draining?(), do: Application.get_env(:kelixip, :draining, false)

  @doc """
  Drain, let upstream notice, then stop the node (`kelictl graceful-shutdown`).

  The drain comes first and is held for `[server] drain_wait_ms` (default 5 s, i.e.
  longer than a typical OPTIONS interval) so upstream takes this node out of rotation
  *before* the instances go away. Set it to 0 to stop immediately, as this function
  used to.

  The final `System.stop/0` is suppressed when `:kelixip, :graceful_stop` is `false`
  (tests), so the sequence can be exercised without killing the VM.
  """
  @spec graceful_shutdown() :: :ok
  def graceful_shutdown() do
    drain()
    wait = Application.get_env(:kelixip, :drain_wait_ms, 5_000)

    finish = fn ->
      if wait > 0, do: Process.sleep(wait)
      Kelix.InstancePool.shutdown_all(:graceful_shutdown)

      if Application.get_env(:kelixip, :graceful_stop, true) do
        Process.sleep(Application.get_env(:kelixip, :graceful_grace_ms, 2_000))
        System.stop(0)
      end
    end

    # Don't hold the caller (a kelictl RPC) for the whole drain window: it would time
    # out and leave the operator thinking the command failed.
    if wait > 0 or Application.get_env(:kelixip, :graceful_stop, true) do
      Task.start(finish)
    else
      finish.()
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
