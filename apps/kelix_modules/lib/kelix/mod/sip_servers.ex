defmodule Kelix.Mod.SipServers do
  @moduledoc """
  The remote SIP servers a domain talks to — application servers, proxies and
  trunks (design `docs/design/sip-server-specs.md`).

  A server belongs to one domain, named by slug, and is unique there by its own
  slug. Its definition lives in this module's persistence file, fed by kelictl and
  the API; neither `config.toml` nor `domains.toml` describes one.

  ## Configuration

      [module.sip_servers]
      server_file = "/var/lib/kelixip/sip_servers.json"

  Without `server_file` the servers live in memory only and a restart forgets
  them, which the module says at start.

  ## Control

      kelictl sip_servers server.create domain=example.com slug=acd \\
        type=sip-application primary_uri=sip:10.0.0.5:5060
      kelictl sip_servers server.list [domain]
      kelictl sip_servers server.show example.com acd
      kelictl sip_servers server.update example.com acd backup_uri=sip:10.0.0.6
      kelictl sip_servers server.delete example.com acd
      kelictl sip_servers aor.add example.com partner-pbx alice@partner.net
      kelictl sip_servers aor.rm example.com partner-pbx alice@partner.net
      kelictl sip_servers aor.list example.com partner-pbx

  A trunk password is given as `auth_password=` with `auth_username` and
  `auth_realm`, and is never stored nor shown: only its HA1 is kept.
  """
  use GenServer
  @behaviour Kelix.Module
  require Logger

  alias Kelix.Mod.SipServers.{Link, Resolution, Route, Server, Store}

  @links Kelix.Mod.SipServers.Links

  # Read by the facades straight from the script's process: recognising where a
  # request comes from must not queue behind a kelictl command.
  @servers_table :kelix_sip_servers
  @addr_table :kelix_sip_servers_addr

  # How often a resolution is redone: its TTL, within these bounds; and how soon
  # after a failure.
  @min_refresh_s 30
  @max_refresh_s 3_600
  @retry_ms 60_000

  @config_keys ~w(module server_file keepalive_interval)

  # ── Kelix.Module behaviour ───────────────────────────────────────────────────

  @impl Kelix.Module
  def child_spec(_name, config) do
    %{id: __MODULE__, type: :supervisor, start: {__MODULE__, :start_tree, [config]}}
  end

  @doc false
  # The server processes first, the service after them, `:rest_for_one`: the
  # service starts the processes, and one that outlived it would answer for a
  # server it no longer knows.
  def start_tree(config) do
    Supervisor.start_link(
      [
        {DynamicSupervisor, name: @links, strategy: :one_for_one},
        %{id: :service, start: {__MODULE__, :start_link, [config]}}
      ],
      strategy: :rest_for_one
    )
  end

  @impl Kelix.Module
  def validate_config(config) when is_map(config) do
    case Map.keys(config) -- @config_keys do
      [] ->
        with :ok <- server_file(Map.get(config, "server_file")) do
          case Map.get(config, "keepalive_interval") do
            nil ->
              :ok

            n when is_integer(n) and n > 0 ->
              :ok

            other ->
              {:error, "keepalive_interval must be a positive integer, got #{inspect(other)}"}
          end
        end

      unknown ->
        {:error, "[module.sip_servers]: unknown key(s) #{Enum.join(unknown, ", ")}"}
    end
  end

  def validate_config(_), do: {:error, "block must be a table"}

  defp server_file(nil), do: :ok
  defp server_file(path) when is_binary(path) and path != "", do: :ok
  defp server_file(other), do: {:error, "server_file must be a path, got #{inspect(other)}"}

  @impl Kelix.Module
  def describe(),
    do: %{version: "1.0", exports: [matches_server: 2, find_server: 2, forward: 3]}

  @server_path "/servers/:domain/:slug"

  @impl Kelix.Module
  def describe_control() do
    server_args =
      for f <- Server.fields(),
          f not in ["domain", "slug", "aors"],
          do: %{name: f, required: false}

    key_args = [%{name: "domain", required: true}, %{name: "slug", required: true}]
    conflicts = %{exists: 409, address_in_use: 409, ext_domain_in_use: 409}

    [
      %{
        name: "server.create",
        rest: {:post, "/servers"},
        status: 201,
        location: @server_path,
        errors: Map.put(conflicts, :unknown_domain, 400),
        rw: :w,
        args: key_args ++ type_arg(server_args),
        help: "Declare a SIP server of a domain"
      },
      %{
        name: "server.list",
        rest: {:get, "/servers"},
        rw: :r,
        args: [%{name: "domain", required: false}],
        render: %{kind: :table, columns: ~w(domain slug type primary_uri backup_uri ha_mode)},
        help: "List the SIP servers, optionally of one domain"
      },
      %{
        name: "server.show",
        rest: {:get, @server_path},
        errors: %{not_found: 404},
        rw: :r,
        args: key_args,
        render: %{
          kind: :detail,
          fields: ~w(domain slug type primary_uri backup_uri use_dns_srv send_keepalive
               initiate_connection ha_mode ext_domain ext_domain_aliases probe_remote_aors
               probe_interval aors register_expires register_retry auth_username auth_realm auth)
        },
        help: "Show one SIP server (never its credentials)"
      },
      %{
        name: "server.update",
        rest: {[:put, :patch], @server_path},
        errors: Map.put(conflicts, :not_found, 404),
        rw: :w,
        args: key_args ++ server_args,
        help: "Change a SIP server; the fields not given are kept"
      },
      %{
        name: "server.delete",
        rest: {:delete, @server_path},
        errors: %{not_found: 404},
        rw: :w,
        args: key_args,
        help: "Delete a SIP server"
      },
      %{
        name: "aor.add",
        rest: {:post, @server_path <> "/aors"},
        errors: %{not_found: 404},
        rw: :w,
        args: key_args ++ [%{name: "aor", required: true, help: "user@domain"}],
        help: "Attach a remote AOR to a sip-proxy server"
      },
      %{
        name: "aor.rm",
        rest: {:delete, @server_path <> "/aors/:aor"},
        errors: %{not_found: 404},
        rw: :w,
        args: key_args ++ [%{name: "aor", required: true, help: "user@domain"}],
        help: "Detach a remote AOR from a sip-proxy server"
      },
      %{
        name: "aor.list",
        rest: {:get, @server_path <> "/aors"},
        errors: %{not_found: 404},
        rw: :r,
        args: key_args,
        render: %{kind: :table, columns: ~w(aor)},
        help: "The remote AORs attached to a sip-proxy server"
      }
    ]
  end

  defp type_arg(args) do
    Enum.map(args, fn
      %{name: "type"} = a -> Map.put(a, :help, Enum.join(Server.types(), " | "))
      a -> a
    end)
  end

  @impl Kelix.Module
  def handle_control(command, args) when is_map(args) do
    Kelix.Module.safe_call(__MODULE__, {:control, command, Map.delete(args, "args")})
  end

  # ── facades ──────────────────────────────────────────────────────────────────

  @doc """
  Which of the domain's servers `req` comes from: `{slug, %SIP.B2bua.Peer{}}`, the
  peer being where that server is answered, or `:no_match`.

  A server is recognised by the source address and transport of the request,
  compared with what its URIs resolved to — never by the source port, which a
  connected transport picks at random. An address two servers of the domain have
  come to share answers `:no_match`.

  Recognising is not trusting: what the request is worth (reject it, challenge
  it, accept it, keep its P-Asserted-Identity) is the script's decision.

      case Kelix.Mod.SipServers.matches_server(sip_ctx, req) do
        {_slug, _peer} -> trust_asserted_identity(req)
        :no_match -> ...
      end
  """
  @spec matches_server(%SIP.Context{} | String.t(), map()) ::
          {String.t(), %SIP.B2bua.Peer{}} | :no_match
  def matches_server(ctx_or_domain, req) when is_map(req) do
    domain = domain_of(ctx_or_domain)

    with {transport, ip, _port} <- SIP.Msg.Ops.source_flow(req),
         [{_, entries}] when is_list(entries) <- lookup(@addr_table, {domain, ip}),
         {slug, _t} <- Enum.find(entries, fn {_slug, t} -> t == transport end),
         [{_, server, link}] <- lookup(@servers_table, {domain, slug}) do
      # Any request from the server is proof of life.
      if is_pid(link), do: Link.seen(link, transport, ip)
      {slug, Route.peer(server, link)}
    else
      _ -> :no_match
    end
  end

  @doc """
  The server a request is addressed to, from the host of its Request-URI: a
  `sip-proxy` by its `ext_domain` and aliases, a `sip-application` by the host of
  its URIs. The slug to hand to `forward/3`, or `:no_match`; a trunk is never
  found this way.
  """
  @spec find_server(%SIP.Context{} | String.t(), map()) :: String.t() | :no_match
  def find_server(ctx_or_domain, req) when is_map(req) do
    domain = domain_of(ctx_or_domain)

    with %SIP.Uri{domain: host} when is_binary(host) <- Map.get(req, :ruri),
         host = String.downcase(host),
         %Server{slug: slug} <-
           Enum.find(servers_of(domain), &(&1.type != "sip-trunk" and host in Server.claims(&1))) do
      slug
    else
      _ -> :no_match
    end
  end

  @doc """
  `{newreq, %SIP.B2bua.Peer{}}` to forward `req` to the server `slug` of the
  domain — the request as that server expects it, and the peer to hand to
  `b2bua_forward`. `{:error, :not_found}` for an unknown server, `{:error,
  :not_resolved}` for a trunk whose addresses are not known yet (see
  `Kelix.Mod.SipServers.Route`).
  """
  @spec forward(%SIP.Context{} | String.t(), map(), String.t()) ::
          {map(), %SIP.B2bua.Peer{}} | {:error, term}
  def forward(ctx_or_domain, req, slug) when is_map(req) and is_binary(slug) do
    case Kelix.Module.safe_call(
           __MODULE__,
           {:forward, domain_of(ctx_or_domain), String.downcase(slug)}
         ) do
      {:ok, server, resolved, turn, link} -> Route.forward(req, server, resolved, turn, link)
      {:error, _} = error -> error
    end
  end

  @doc "The servers of `domain`, or every server when `domain` is nil."
  @spec servers(String.t() | nil) :: [Server.t()] | {:error, :down | :timeout}
  def servers(domain \\ nil), do: Kelix.Module.safe_call(__MODULE__, {:servers, domain})

  defp domain_of(%SIP.Context{domain: domain}), do: domain_of(domain)
  defp domain_of(domain) when is_binary(domain), do: String.downcase(domain)
  defp domain_of(_), do: nil

  defp servers_of(domain) do
    for {{d, _slug}, server, _link} <- table(@servers_table), d == domain, do: server
  end

  defp lookup(table, key) do
    :ets.lookup(table, key)
  rescue
    ArgumentError -> []
  end

  defp table(table) do
    :ets.tab2list(table)
  rescue
    ArgumentError -> []
  end

  # ── service ──────────────────────────────────────────────────────────────────

  def start_link(config), do: GenServer.start_link(__MODULE__, config, name: __MODULE__)

  @impl GenServer
  def init(config) do
    :ets.new(@servers_table, [:named_table, :protected, read_concurrency: true])
    :ets.new(@addr_table, [:named_table, :protected, read_concurrency: true])
    {file, servers} = restore(Map.get(config, "server_file"))

    # A service restarted under a live tree finds the processes of its previous
    # life: they answer for state it no longer holds.
    for {_, pid, _, _} <- DynamicSupervisor.which_children(@links),
        is_pid(pid),
        do: DynamicSupervisor.terminate_child(@links, pid)

    state = %{
      file: file,
      interval: Map.get(config, "keepalive_interval", 30),
      links: %{},
      servers: %{},
      resolved: %{},
      gen: %{},
      turns: %{},
      conflicts: MapSet.new()
    }

    {:ok, sync(state, %{state | servers: servers})}
  end

  @impl GenServer
  def handle_call({:servers, domain}, _from, state) do
    {:reply, list(state, domain && String.downcase(domain)), state}
  end

  def handle_call({:control, command, args}, _from, state) do
    case control(command, args, state) do
      {:ok, result, new_state} -> {:reply, {:ok, result}, state |> sync(new_state) |> persist()}
      {:ok, result} -> {:reply, {:ok, result}, state}
      {:error, _} = error -> {:reply, error, state}
    end
  end

  def handle_call({:forward, domain, slug}, _from, state) do
    case Map.get(state.servers, {domain, slug}) do
      %Server{} = server ->
        key = {domain, slug}
        turn = Map.get(state.turns, key, 0)
        resolved = state.resolved |> Map.get(key, %{}) |> Map.get(:targets, %{})

        {:reply, {:ok, server, resolved, turn, Map.get(state.links, key)},
         %{state | turns: Map.put(state.turns, key, turn + 1)}}

      nil ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl GenServer
  def handle_info({:resolved, key, gen, result}, state) do
    if Map.get(state.gen, key) == gen and Map.has_key?(state.servers, key) do
      {:noreply, state |> apply_resolution(key, gen, result) |> rebuild_index()}
    else
      {:noreply, state}
    end
  end

  def handle_info({:refresh, key, gen}, state) do
    if Map.get(state.gen, key) == gen and Map.has_key?(state.servers, key),
      do: {:noreply, resolve(state, key)},
      else: {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ── commands ─────────────────────────────────────────────────────────────────

  defp control("server.create", args, state) do
    with {:ok, server} <- Server.build(args),
         :ok <- known_domain(server.domain),
         :ok <- absent(state, server),
         :ok <- no_conflict(state, server) do
      log("created", server)
      {:ok, Server.public(server), put(state, server)}
    end
  end

  defp control("server.list", args, state) do
    domain = args["domain"] && String.downcase(args["domain"])
    {:ok, Enum.map(list(state, domain), &Server.public/1)}
  end

  defp control("server.show", args, state) do
    with {:ok, server} <- fetch(state, args) do
      {:ok, Map.put(Server.public(server), :reachability, reachability(state, server))}
    end
  end

  defp control("server.update", args, state) do
    with {:ok, current} <- fetch(state, args),
         {:ok, server} <- Server.build(Map.drop(args, ["domain", "slug"]), current),
         :ok <- no_conflict(state, server) do
      log("updated", server)
      {:ok, Server.public(server), put(state, server)}
    end
  end

  defp control("server.delete", args, state) do
    with {:ok, server} <- fetch(state, args) do
      log("deleted", server)

      {:ok, %{domain: server.domain, slug: server.slug, deleted: true},
       %{state | servers: Map.delete(state.servers, key(server))}}
    end
  end

  defp control("aor.list", args, state) do
    with {:ok, server} <- fetch(state, args),
         :ok <- proxy(server) do
      {:ok, Enum.map(server.aors, &%{aor: &1})}
    end
  end

  defp control(command, args, state) when command in ["aor.add", "aor.rm"] do
    with {:ok, server} <- fetch(state, args),
         :ok <- proxy(server),
         {:ok, aor} <- aor(args["aor"]) do
      aors =
        if command == "aor.add",
          do: Enum.uniq(server.aors ++ [aor]),
          else: List.delete(server.aors, aor)

      server = %Server{server | aors: aors}
      {:ok, %{domain: server.domain, slug: server.slug, aors: aors}, put(state, server)}
    end
  end

  defp control(command, _args, _state), do: {:error, {:unknown_command, command}}

  # ── rules ────────────────────────────────────────────────────────────────────

  # A server names its domain; one the node does not serve would never be
  # reached. Without the domain table (a unit test) there is nothing to check.
  defp known_domain(domain) do
    if Process.whereis(Kelix.Domains) do
      nominal = Kelix.Domains.nominal(domain)

      if Enum.any?(Kelix.Domains.current().domains, &(&1.name == nominal)),
        do: :ok,
        else: {:error, :unknown_domain}
    else
      :ok
    end
  end

  defp absent(state, server) do
    if Map.has_key?(state.servers, key(server)), do: {:error, :exists}, else: :ok
  end

  # Within a domain: at most one sip-proxy per remote domain, and no host or
  # address claimed by two servers — or matches_server/1 and find_server/1 could
  # not tell them apart.
  defp no_conflict(state, server) do
    others =
      for {k, s} <- state.servers, k != key(server), s.domain == server.domain, do: s

    cond do
      server.type == "sip-proxy" and
          Enum.any?(others, &(&1.type == "sip-proxy" and &1.ext_domain == server.ext_domain)) ->
        {:error, :ext_domain_in_use}

      Enum.any?(others, &overlaps?(&1, server)) ->
        {:error, :address_in_use}

      true ->
        :ok
    end
  end

  defp overlaps?(a, b), do: Server.claims(a) -- Server.claims(b) != Server.claims(a)

  defp proxy(%Server{type: "sip-proxy"}), do: :ok

  defp proxy(%Server{type: type}),
    do: {:error, "remote AORs belong to a sip-proxy, not a #{type}"}

  defp aor(value) when is_binary(value) do
    case String.split(String.trim(value), "@") do
      [user, host] when user != "" and host != "" ->
        {:ok, String.downcase(value |> String.trim())}

      _ ->
        {:error, "aor must be user@domain, got #{inspect(value)}"}
    end
  end

  defp aor(value), do: {:error, "aor must be user@domain, got #{inspect(value)}"}

  # ── state ────────────────────────────────────────────────────────────────────

  defp key(%Server{domain: d, slug: s}), do: {d, s}

  defp fetch(state, args) do
    with d when is_binary(d) <- args["domain"],
         s when is_binary(s) <- args["slug"],
         %Server{} = server <- Map.get(state.servers, {String.downcase(d), String.downcase(s)}) do
      {:ok, server}
    else
      _ -> {:error, :not_found}
    end
  end

  defp put(state, server), do: %{state | servers: Map.put(state.servers, key(server), server)}

  defp list(state, domain) do
    state.servers
    |> Map.values()
    |> Enum.filter(&(is_nil(domain) or &1.domain == domain))
    |> Enum.sort_by(&{&1.domain, &1.slug})
  end

  defp log(what, server) do
    Logger.info(
      module: __MODULE__,
      message: "sip server #{server.slug}@#{server.domain} (#{server.type}) #{what}"
    )
  end

  # ── tables and resolution ────────────────────────────────────────────────────

  # Bring the tables in line with a new set of servers: a server added or changed
  # is written and resolved again, a server gone is dropped with its addresses.
  defp sync(old, new) do
    gone = Map.keys(old.servers) -- Map.keys(new.servers)
    changed = for {k, s} <- new.servers, Map.get(old.servers, k) != s, do: k

    Enum.each(gone, &:ets.delete(@servers_table, &1))

    for key <- gone,
        pid = Map.get(new.links, key),
        is_pid(pid),
        do: DynamicSupervisor.terminate_child(@links, pid)

    new = %{
      new
      | resolved: Map.drop(new.resolved, gone),
        gen: Map.drop(new.gen, gone),
        turns: Map.drop(new.turns, gone),
        links: Map.drop(new.links, gone)
    }

    new = Enum.reduce(changed, new, &link/2)

    changed |> Enum.reduce(new, &resolve(&2, &1)) |> rebuild_index()
  end

  # Off the service's process: a DNS answer can take seconds, and kelictl must not
  # wait for it. The generation discards an answer overtaken by a newer question.
  defp resolve(state, key) do
    gen = make_ref()
    server = Map.fetch!(state.servers, key)
    owner = self()
    resolver = resolver()
    Task.start(fn -> send(owner, {:resolved, key, gen, resolver.resolve(server)}) end)
    %{state | gen: Map.put(state.gen, key, gen)}
  end

  defp resolver(), do: Application.get_env(:kelix_modules, :sip_servers_resolver, Resolution)

  defp apply_resolution(state, key, gen, {:ok, targets, ttl}) do
    unless ttl == :infinity do
      delay = ttl |> max(@min_refresh_s) |> min(@max_refresh_s)
      Process.send_after(self(), {:refresh, key, gen}, delay * 1000)
    end

    state = %{state | resolved: Map.put(state.resolved, key, %{targets: targets})}

    if pid = Map.get(state.links, key),
      do: Link.update(pid, Map.fetch!(state.servers, key), targets)

    state
  end

  # A failed resolution keeps the last answer — an address that worked is a better
  # guess than none — and asks again soon.
  defp apply_resolution(state, {domain, slug} = key, gen, {:error, reason}) do
    Logger.warning(
      module: __MODULE__,
      message: "sip server #{slug}@#{domain}: resolution failed (#{inspect(reason)}), retrying"
    )

    Process.send_after(self(), {:refresh, key, gen}, @retry_ms)
    state
  end

  # The server's process: started with the server, told of every change to it, and
  # what the table row hands to the facades.
  defp link(key, state) do
    server = Map.fetch!(state.servers, key)
    targets = state.resolved |> Map.get(key, %{}) |> Map.get(:targets, %{})

    pid =
      case Map.get(state.links, key) do
        pid when is_pid(pid) ->
          Link.update(pid, server, targets)
          pid

        nil ->
          opts = [server: server, resolved: targets, interval: state.interval]
          spec = Supervisor.child_spec({Link, opts}, restart: :temporary)

          case DynamicSupervisor.start_child(@links, spec) do
            {:ok, pid} -> pid
            _ -> nil
          end
      end

    :ets.insert(@servers_table, {key, server, pid})
    %{state | links: Map.put(state.links, key, pid)}
  end

  defp reachability(state, server) do
    case Map.get(state.links, {server.domain, server.slug}) do
      pid when is_pid(pid) ->
        try do
          Map.new(Link.states(pid), fn {uri, st} -> {uri, Atom.to_string(st)} end)
        catch
          :exit, _ -> %{}
        end

      _ ->
        %{}
    end
  end

  # `{domain, ip} => [{slug, transport}]`, or `:ambiguous` when two servers of a
  # domain resolved to one address: matches_server/2 then recognises neither, and
  # the alarm names both — once, when the overlap appears.
  defp rebuild_index(state) do
    pairs =
      for {{domain, slug}, %{targets: targets}} <- state.resolved,
          {_uri, addrs} <- targets,
          {transport, ip, _port} <- addrs,
          uniq: true,
          do: {{domain, ip}, {slug, transport}}

    index = Enum.group_by(pairs, &elem(&1, 0), &elem(&1, 1))

    conflicts =
      for {{domain, ip}, entries} <- index,
          slugs = entries |> Enum.map(&elem(&1, 0)) |> Enum.uniq() |> Enum.sort(),
          length(slugs) > 1,
          into: MapSet.new(),
          do: {domain, ip, slugs}

    for {domain, ip, slugs} <- MapSet.difference(conflicts, state.conflicts) do
      Logger.error(
        module: __MODULE__,
        message:
          "sip servers #{Enum.join(slugs, ", ")} of #{domain} resolve to the same address " <>
            "#{:inet.ntoa(ip)}: requests from it are recognised as neither"
      )
    end

    ambiguous = MapSet.new(conflicts, fn {domain, ip, _} -> {domain, ip} end)

    :ets.delete_all_objects(@addr_table)

    for {addr, entries} <- index do
      :ets.insert(@addr_table, {addr, if(addr in ambiguous, do: :ambiguous, else: entries)})
    end

    %{state | conflicts: conflicts}
  end

  # ── persistence ──────────────────────────────────────────────────────────────

  # The path to write to, or nil when there is nothing to write: no file, or one
  # that could not be read — overwriting an unreadable file with an empty set is
  # how an operator loses every trunk to a stray byte.
  defp restore(nil) do
    Logger.warning(
      module: __MODULE__,
      message: "no server_file: SIP servers live in memory only, a restart forgets them"
    )

    {nil, %{}}
  end

  defp restore(path) do
    case Store.load(path) do
      {:ok, servers} ->
        Logger.info(
          module: __MODULE__,
          message: "#{length(servers)} SIP server(s) restored from #{path}"
        )

        {path, Enum.reduce(servers, %{}, &restore_server/2)}

      {:error, reason} ->
        Logger.error(
          module: __MODULE__,
          message:
            "#{path} could not be read (#{inspect(reason)}): its servers are NOT restored " <>
              "and the file is left untouched — fix it and restart"
        )

        {nil, %{}}
    end
  end

  # A hand-edited file can declare a server twice; the second is refused rather
  # than allowed to shadow the first.
  defp restore_server(server, acc) do
    if Map.has_key?(acc, key(server)) do
      Logger.error(
        module: __MODULE__,
        message: "server #{server.slug}@#{server.domain} appears twice; second ignored"
      )

      acc
    else
      Map.put(acc, key(server), server)
    end
  end

  # Never fatal: a server that is defined is worth more than a file that is up to
  # date, so a failed write is logged and the command still succeeds.
  defp persist(%{file: nil} = state), do: state

  defp persist(%{file: path} = state) do
    case Store.save(path, list(state, nil)) do
      :ok ->
        state

      {:error, reason} ->
        Logger.error(
          module: __MODULE__,
          message:
            "could not write the SIP servers to #{path} (#{inspect(reason)}): " <>
              "they are live, but a restart will not bring them back"
        )

        state
    end
  end
end
