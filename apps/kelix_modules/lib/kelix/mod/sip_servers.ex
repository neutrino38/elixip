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

  alias Kelix.Mod.SipServers.{Server, Store}

  @config_keys ~w(module server_file)

  # ── Kelix.Module behaviour ───────────────────────────────────────────────────

  @impl Kelix.Module
  def child_spec(_name, config) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, [config]}}
  end

  @impl Kelix.Module
  def validate_config(config) when is_map(config) do
    case Map.keys(config) -- @config_keys do
      [] ->
        case Map.get(config, "server_file") do
          nil -> :ok
          path when is_binary(path) and path != "" -> :ok
          other -> {:error, "server_file must be a path, got #{inspect(other)}"}
        end

      unknown ->
        {:error, "[module.sip_servers]: unknown key(s) #{Enum.join(unknown, ", ")}"}
    end
  end

  def validate_config(_), do: {:error, "block must be a table"}

  @impl Kelix.Module
  def describe(), do: %{version: "1.0", exports: []}

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

  @doc "The servers of `domain`, or every server when `domain` is nil."
  @spec servers(String.t() | nil) :: [Server.t()] | {:error, :down | :timeout}
  def servers(domain \\ nil), do: Kelix.Module.safe_call(__MODULE__, {:servers, domain})

  # ── service ──────────────────────────────────────────────────────────────────

  def start_link(config), do: GenServer.start_link(__MODULE__, config, name: __MODULE__)

  @impl GenServer
  def init(config) do
    {file, servers} = restore(Map.get(config, "server_file"))
    {:ok, %{file: file, servers: servers}}
  end

  @impl GenServer
  def handle_call({:servers, domain}, _from, state) do
    {:reply, list(state, domain && String.downcase(domain)), state}
  end

  def handle_call({:control, command, args}, _from, state) do
    case control(command, args, state) do
      {:ok, result, state} -> {:reply, {:ok, result}, persist(state)}
      {:ok, result} -> {:reply, {:ok, result}, state}
      {:error, _} = error -> {:reply, error, state}
    end
  end

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
    with {:ok, server} <- fetch(state, args), do: {:ok, Server.public(server)}
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
