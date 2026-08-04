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
  Every served domain and its registrations (`kelictl registration list`), in
  `domains.toml` order.

  **One entry per served domain**, `%{domain, registrations}`, including a domain
  nobody is registered in — "served, empty" and "not served at all" are different
  answers and an operator is usually asking which of the two it is. Registrations
  are keyed per domain in the store (§6.1), so this is the shape they have.
  """
  @spec registrations() :: [map]
  def registrations(), do: Enum.map(domain_names(), &domain_registrations/1)

  @doc """
  One domain's registrations (`kelictl registration list <domain>`).

  `domain` is matched the way inbound traffic is — name **and** aliases,
  case-insensitively — so the host an operator saw on the wire is a valid argument.
  `{:error, :not_found}` if no domain serves that host, which is *not* the same
  answer as a served domain with nothing registered in it.

  Returns the same `%{domain, registrations}` entry `registrations/0` lists, so the
  two views cannot disagree about a field.
  """
  @spec registrations(String.t()) :: {:ok, map} | {:error, :not_found}
  def registrations(domain) when is_binary(domain) do
    with {:ok, name} <- resolve_domain(domain), do: {:ok, domain_registrations(name)}
  end

  @doc """
  One AOR and its bindings (`kelictl registration show <domain> <aor>`).

  An AOR is only unique **within a domain** (§6.1), so the domain is part of the
  address, not a filter on it. `aor` is the user-part, or the full `"user@domain"`
  an operator copied out of a log — in which case its domain part must resolve to
  `domain`, rather than being silently ignored.

  Returns the row `registrations/1` holds for that AOR; `{:error, :not_found}` for
  an unserved domain as much as for an unregistered AOR — neither is something the
  operator can act on, and telling them apart would enumerate the served domains.
  """
  @spec registration(String.t(), String.t()) :: {:ok, map} | {:error, :not_found}
  def registration(domain, aor) when is_binary(domain) and is_binary(aor) do
    with {:ok, name} <- resolve_domain(domain),
         {:ok, user} <- aor_user(aor, name),
         [_ | _] = contacts <- Map.get(registrations_for(name), user, :not_registered) do
      {:ok, registration_row(name, user, contacts)}
    else
      _ -> {:error, :not_found}
    end
  end

  defp domain_registrations(name) do
    %{
      domain: name,
      # sorted: the store is an ETS table, whose enumeration order is arbitrary and
      # would reshuffle the list between two otherwise identical calls
      registrations:
        for(
          {aor, contacts} <- Enum.sort(registrations_for(name)),
          do: registration_row(name, aor, contacts)
        )
    }
  end

  defp registration_row(domain, aor, contacts),
    do: %{domain: domain, aor: aor, contacts: Enum.map(contacts, &render_contact/1)}

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
  Remove a registration (`kelictl registration remove <domain> <aor> [contact]`).

  `domain` and `aor` are read exactly as `registration/2` reads them; `contact` is a
  contact-URI string, or `:all` to drop the whole AOR. `:ok` if anything was
  removed, else `:notfound` — including for an unserved domain, since nothing was
  removed either way.

  Dropping a binding is destructive and per-domain by nature: there is deliberately
  no form that removes `"alice"` from *every* domain at once.
  """
  @spec unregister(String.t(), String.t(), String.t() | :all) :: :ok | :notfound
  def unregister(domain, aor, contact \\ :all) do
    with {:ok, name} <- resolve_domain(domain),
         {:ok, user} <- aor_user(aor, name) do
      # via the registry: the registrar is a loadable module, absent from the core
      Kelix.ModuleRegistry.facade("registrar", :remove, [name, user, contact], :notfound)
    else
      _ -> :notfound
    end
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

  @doc """
  Set the runtime log level (`kelictl log-level <lvl>`).

  Goes through `Kelix.Config.set_level/1` rather than `Logger.configure/1`: the
  primary level alone leaves each sink on its own compiled-in level (console at
  `:warning`, the file backend at `:info`), so `log-level debug` answered `:ok`
  while no debug line ever reached the console or `elixip.log`.
  """
  @spec set_log_level(String.t() | atom) :: :ok | {:error, :invalid_level}
  def set_log_level(level) do
    case @log_levels[to_string(level)] do
      nil -> {:error, :invalid_level}
      lvl -> Kelix.Config.set_level(lvl)
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
  What each loaded module contributes (`kelictl module list`, `GET /modules`).

  One entry per `[module.<name>]` block that started, carrying the two surfaces a
  module exposes and neither of which was discoverable at runtime (FW-5,
  `docs/design/mcu_module.md` §8.3.6): the **control commands** it declared into
  `Kelix.Control.Registry` (what an operator can run) and the **facade functions**
  it exports to scenario scripts (what a script can call, from `describe/0`).

  Generic by construction: the core names no module: a module without
  `describe_control/0` simply lists no command, one without `describe/0` no version
  and no export.
  """
  @spec module_commands() :: %{optional(String.t()) => map}
  def module_commands() do
    for {name, %{module: module}} <- safe(fn -> Kelix.ModuleRegistry.all() end, %{}), into: %{} do
      described = Kelix.ModuleRegistry.facade(name, :describe, [], %{})

      {name,
       %{
         module: module,
         version: Map.get(described, :version),
         exports: Map.get(described, :exports, []),
         commands:
           safe(fn -> Kelix.Control.Registry.commands_for(name) end, [])
           |> Enum.map(&described_command/1)
       }}
    end
  end

  # A declaration read once, here, so both frontals render the same thing: the
  # `rest:` tuple becomes an explicit method list + path template (through
  # `Kelix.Control.Route`, which owns the defaults an incomplete declaration falls
  # back to), and the optional keys get theirs. A frontal formats; it does not
  # interpret.
  defp described_command(cmd) do
    described = %{
      name: cmd.name,
      methods: Kelix.Control.Route.methods(cmd),
      path: Kelix.Control.Route.template(cmd),
      args: Enum.map(Map.get(cmd, :args, []), &described_arg/1),
      rw: Map.get(cmd, :rw, :w),
      help: Map.get(cmd, :help, ""),
      status: Map.get(cmd, :status, 200),
      errors: Map.get(cmd, :errors, %{})
    }

    # only when declared: most commands have none, and the CLI is its only reader
    case Map.get(cmd, :render) do
      nil -> described
      render -> Map.put(described, :render, render)
    end
  end

  # An argument's own help travels when it is declared — a value with a vocabulary
  # (a mosaic name, an enum, a compact syntax) explains itself where it is used,
  # rather than in prose the operator has to go and find.
  defp described_arg(arg) do
    described = %{name: arg.name, required: Map.get(arg, :required, false)}

    case Map.get(arg, :help) do
      nil -> described
      help -> Map.put(described, :help, help)
    end
  end

  @doc """
  One module's surface (`kelictl <module> help`, `GET /modules/<name>`), or
  `{:error, :unknown_module}` when no `[module.<name>]` block is loaded.
  """
  @spec module_commands(String.t()) :: {:ok, map} | {:error, :unknown_module}
  def module_commands(name) when is_binary(name) do
    case Map.fetch(module_commands(), name) do
      {:ok, entry} -> {:ok, Map.put(entry, :name, name)}
      :error -> {:error, :unknown_module}
    end
  end

  @doc """
  The status `<module> <cmd>` declares for `reason` (FW-5).

  What `kelictl` classifies a failed module command by: it holds the result but not
  the declaration, which lives here. Same function the REST frontal answers with, so
  a reason a module declared `409` is a conflict on both frontals or on neither.

  An unknown module, or a command name the module never declared, gets the default
  mapping — an ad-hoc command still fails with a usable code.
  """
  @spec command_error_status(String.t(), String.t(), term) :: 100..599
  def command_error_status(module_name, cmd, reason)
      when is_binary(module_name) and is_binary(cmd) do
    declared =
      safe(fn -> Kelix.Control.Registry.commands_for(module_name) end, [])
      |> Enum.find(%{}, &(&1.name == cmd))

    Kelix.Control.Route.error_status(declared, reason)
  end

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
  # reference a loadable module's struct at compile time (§16.12) — hence `Map.get`
  # for the optional fields too.
  #
  # `expires_in` is derived here rather than left to each frontal: "how long has
  # this binding left" is the operator question, and an absolute UTC timestamp is
  # not an answer to it. `source` is where the REGISTER *actually* came from, which
  # behind a NAT is not what the contact URI says — the difference is the usual
  # reason a call to a registered phone never arrives.
  defp render_contact(%{contact: uri, expires_at: at} = binding) do
    %{
      uri: uri_string(uri),
      expires_at: at,
      expires_in: expires_in(at),
      source: source_string(Map.get(binding, :received)),
      transport: transport_string(Map.get(binding, :flow_module)),
      instance: Map.get(binding, :instance),
      reg_id: Map.get(binding, :reg_id),
      methods: Map.get(binding, :methods)
    }
  end

  defp expires_in(%DateTime{} = at), do: max(DateTime.diff(at, DateTime.utc_now()), 0)
  defp expires_in(_at), do: nil

  defp source_string({proto, ip, port}) when is_tuple(ip) do
    case :inet.ntoa(ip) do
      {:error, _} -> nil
      addr -> "#{proto} #{addr}:#{port}"
    end
  end

  defp source_string(_received), do: nil

  # The transport the binding is reachable over, named the way the stack names it
  # (`SIP.Transport.UDP.transport_str/0`) rather than by guessing from the module.
  defp transport_string(module) when is_atom(module) and not is_nil(module) do
    if Code.ensure_loaded?(module) and function_exported?(module, :transport_str, 0),
      do: module.transport_str(),
      else: nil
  end

  defp transport_string(_module), do: nil

  defp uri_string(%SIP.Uri{} = uri) do
    case SIP.Uri.serialize(uri) do
      {:ok, s} -> s
      _ -> inspect(uri)
    end
  end

  defp uri_string(other), do: inspect(other)

  # A host an operator saw on the wire is a valid argument: resolved through the
  # router's own reading (`Kelix.Domains.lookup/2` — name + aliases, case-insensitive),
  # and answered with the *canonical* name, which is what the registrar keys on.
  defp resolve_domain(name) do
    case Kelix.Domains.lookup(current_domains(), name) do
      nil -> {:error, :not_found}
      d -> {:ok, d.name}
    end
  end

  # `alice`, or the `alice@example.com` an operator copied out of a log. A domain
  # part naming *another* domain is refused rather than dropped:
  # `show example.com bob@other.example.net` must not answer for example.com's bob.
  defp aor_user(aor, domain) do
    case String.split(aor, "@", parts: 2) do
      [user] ->
        {:ok, String.downcase(user)}

      [user, dom] ->
        case resolve_domain(dom) do
          {:ok, ^domain} -> {:ok, String.downcase(user)}
          _ -> {:error, :not_found}
        end
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
