defmodule Kelix.Mod.SipServers.Server do
  @moduledoc """
  One remote SIP server a domain talks to: an application server, a proxy or a
  trunk (design `docs/design/sip-server-specs.md`).

  A definition, never a runtime state: reachability, registration and resolved
  addresses live in the server's process, not here, and never reach the file.

  `build/2` is the single reading of what an operator typed, from kelictl (every
  value a string) or from the API (JSON values), for a creation as for a partial
  update — so the two frontals, and the file, cannot disagree on what a field
  means.
  """

  alias SIP.Auth

  @types ~w(sip-application sip-proxy sip-trunk)
  @ha_modes ~w(failover loadsharing)

  # The algorithms a trunk password is hashed for at entry: the remote side picks
  # one in its challenge, and the password is not kept to compute another later.
  @ha1_algorithms ["MD5", "SHA-256"]

  # Which fields belong to which type. A field set on a type that does not use it
  # is refused rather than ignored: it is a misunderstanding worth saying.
  @proxy_only ~w(ext_domain_aliases probe_remote_aors probe_interval aors)
  @trunk_only ~w(register register_expires register_retry auth_username auth_realm auth_password)
  @ext_domain_types ~w(sip-proxy sip-trunk)

  @fields ~w(domain slug type primary_uri backup_uri tertiary_uri source_networks use_dns_srv
             send_keepalive initiate_connection ha_mode ext_domain ext_domain_aliases
             probe_remote_aors probe_interval aors register register_expires register_retry
             auth_username auth_realm auth_password)

  @roles [primary_uri: "primary", backup_uri: "backup", tertiary_uri: "tertiary"]

  @type t :: %__MODULE__{}

  defstruct domain: nil,
            slug: nil,
            type: nil,
            primary_uri: nil,
            backup_uri: nil,
            tertiary_uri: nil,
            source_networks: [],
            use_dns_srv: false,
            send_keepalive: true,
            initiate_connection: true,
            ha_mode: "failover",
            ext_domain: nil,
            ext_domain_aliases: [],
            probe_remote_aors: false,
            probe_interval: 60,
            aors: [],
            register: true,
            register_expires: 600,
            register_retry: 30,
            auth_username: nil,
            auth_realm: nil,
            auth_ha1: []

  @doc "The argument names `build/2` reads, for the control declarations."
  def fields(), do: @fields

  @doc "The server types."
  def types(), do: @types

  @doc "Does a field apply to a server of `type`?"
  @spec applies?(String.t(), String.t()) :: boolean()
  def applies?(type, key) do
    not ((key in @proxy_only and type != "sip-proxy") or
           (key in @trunk_only and type != "sip-trunk") or
           (key == "ext_domain" and type not in @ext_domain_types))
  end

  @doc """
  A server from `args` laid over `base` (a creation starts from the defaults, an
  update from the server as it stands). `{:ok, server}` or `{:error, message}`.

  The password is never stored: with `auth_username` and `auth_realm` it becomes
  one HA1 per algorithm. Changing the user or the realm without it is refused,
  since the HA1 already stored was computed for the old ones.
  """
  @spec build(map(), t()) :: {:ok, t()} | {:error, String.t()}
  def build(args, %__MODULE__{} = base \\ %__MODULE__{}) when is_map(args) do
    with {:ok, s} <- put_string(base, args, "domain", &String.downcase/1),
         {:ok, s} <- put_string(s, args, "slug", &String.downcase/1),
         {:ok, s} <- put_enum(s, args, "type", @types),
         {:ok, s} <- put_uri(s, args, "primary_uri"),
         {:ok, s} <- put_uri(s, args, "backup_uri"),
         {:ok, s} <- put_uri(s, args, "tertiary_uri"),
         {:ok, s} <- put_networks(s, args, "source_networks"),
         {:ok, s} <- put_bool(s, args, "use_dns_srv"),
         {:ok, s} <- put_bool(s, args, "send_keepalive"),
         {:ok, s} <- put_bool(s, args, "initiate_connection"),
         {:ok, s} <- put_enum(s, args, "ha_mode", @ha_modes),
         {:ok, s} <- put_string(s, args, "ext_domain", &String.downcase/1),
         {:ok, s} <- put_list(s, args, "ext_domain_aliases", &String.downcase/1),
         {:ok, s} <- put_bool(s, args, "probe_remote_aors"),
         {:ok, s} <- put_pos_int(s, args, "probe_interval"),
         {:ok, s} <- put_list(s, args, "aors", &String.downcase/1),
         {:ok, s} <- put_bool(s, args, "register"),
         {:ok, s} <- put_pos_int(s, args, "register_expires"),
         {:ok, s} <- put_pos_int(s, args, "register_retry"),
         {:ok, s} <- put_string(s, args, "auth_username", & &1),
         {:ok, s} <- put_string(s, args, "auth_realm", & &1),
         {:ok, s} <- put_password(s, base, args),
         :ok <- check_required(s),
         :ok <- check_slug(s.slug),
         :ok <- check_type_fields(s, args),
         :ok <- check_userpart(s) do
      {:ok, s}
    end
  end

  @doc "The server's URIs in the order they are tried: primary, backup, tertiary."
  @spec uris(t()) :: [String.t()]
  def uris(%__MODULE__{} = s), do: for({_role, uri} <- roles(s), do: uri)

  @doc "The server's URIs with their role, in the order they are tried."
  @spec roles(t()) :: [{String.t(), String.t()}]
  def roles(%__MODULE__{} = s) do
    for {field, role} <- @roles, uri = Map.get(s, field), uri != nil, do: {role, uri}
  end

  @doc """
  Whether a request from `ip` over `transport` falls in one of the server's
  `source_networks`. The transport must be one its URIs name: a network widens
  the addresses a server may come from, not what it speaks.
  """
  @spec from_network?(t(), String.t(), :inet.ip_address()) :: boolean()
  def from_network?(%__MODULE__{source_networks: []}, _transport, _ip), do: false

  def from_network?(%__MODULE__{} = s, transport, ip) do
    transport in transports(s) and
      Enum.any?(s.source_networks, fn text ->
        {:ok, prefix} = SIP.NetUtils.parse_prefix(text)
        SIP.NetUtils.in_prefix?(ip, prefix)
      end)
  end

  @doc "Do the `source_networks` of two servers overlap?"
  @spec networks_overlap?(t(), t()) :: boolean()
  def networks_overlap?(%__MODULE__{} = a, %__MODULE__{} = b) do
    prefixes = fn s ->
      for text <- s.source_networks, do: elem(SIP.NetUtils.parse_prefix(text), 1)
    end

    Enum.any?(prefixes.(a), fn {addr_a, _} = pa ->
      Enum.any?(prefixes.(b), fn {addr_b, _} = pb ->
        SIP.NetUtils.in_prefix?(addr_a, pb) or SIP.NetUtils.in_prefix?(addr_b, pa)
      end)
    end)
  end

  defp transports(s) do
    for uri <- uris(s), uniq: true do
      {:ok, parsed} = parse_uri(uri)
      SIP.Uri.get_transport(parsed) || "UDP"
    end
  end

  @doc """
  The host names and addresses this server claims within its domain: the hosts
  of its URIs, plus a proxy's remote domain and aliases. Two servers of a domain
  never share one — that is what keeps `matches_server/1` and `find_server/1`
  unambiguous.
  """
  @spec claims(t()) :: [String.t()]
  def claims(%__MODULE__{} = s) do
    hosts = for uri <- uris(s), do: uri_host(uri)

    proxy =
      if s.type == "sip-proxy",
        do: Enum.reject([s.ext_domain | s.ext_domain_aliases], &is_nil/1),
        else: []

    Enum.uniq(hosts ++ proxy)
  end

  @doc """
  What `show` and `list` display: everything but the HA1, plus `uris`, the URIs
  with their role in the order they are tried.
  """
  @spec public(t()) :: map()
  def public(%__MODULE__{} = s) do
    s
    |> Map.from_struct()
    |> Map.delete(:auth_ha1)
    |> Map.put(:auth, if(s.auth_ha1 == [], do: "none", else: "set"))
    |> Map.put(:uris, for({role, uri} <- roles(s), do: %{role: role, uri: uri}))
  end

  # ── fields ──────────────────────────────────────────────────────────────────

  # A key absent leaves the field as it was; a key present with an empty value
  # clears an optional field (`backup_uri=` drops the backup).
  defp fetch(args, key) do
    case Map.fetch(args, key) do
      {:ok, value} -> {:ok, value}
      :error -> :absent
    end
  end

  defp put_string(s, args, key, norm) do
    case fetch(args, key) do
      :absent -> {:ok, s}
      {:ok, v} when v in [nil, ""] -> {:ok, Map.put(s, field(key), nil)}
      {:ok, v} when is_binary(v) -> {:ok, Map.put(s, field(key), norm.(String.trim(v)))}
      {:ok, v} -> {:error, "#{key} must be a string, got #{inspect(v)}"}
      error -> error
    end
  end

  defp put_enum(s, args, key, allowed) do
    case fetch(args, key) do
      :absent -> {:ok, s}
      {:ok, v} when is_binary(v) -> enum(s, key, String.downcase(v), allowed)
      {:ok, v} -> {:error, "#{key} must be one of #{Enum.join(allowed, ", ")}, got #{inspect(v)}"}
      error -> error
    end
  end

  defp enum(s, key, v, allowed) do
    if v in allowed,
      do: {:ok, Map.put(s, field(key), v)},
      else: {:error, "#{key} must be one of #{Enum.join(allowed, ", ")}, got #{inspect(v)}"}
  end

  defp put_uri(s, args, key) do
    case fetch(args, key) do
      :absent ->
        {:ok, s}

      {:ok, v} when v in [nil, ""] ->
        {:ok, Map.put(s, field(key), nil)}

      {:ok, v} when is_binary(v) ->
        case parse_uri(v) do
          {:ok, _uri} -> {:ok, Map.put(s, field(key), String.trim(v))}
          :error -> {:error, "#{key}: #{inspect(v)} is not a sip: or sips: URI"}
        end

      {:ok, v} ->
        {:error, "#{key} must be a URI string, got #{inspect(v)}"}

      error ->
        error
    end
  end

  defp put_bool(s, args, key) do
    case fetch(args, key) do
      :absent -> {:ok, s}
      {:ok, v} when is_boolean(v) -> {:ok, Map.put(s, field(key), v)}
      {:ok, "true"} -> {:ok, Map.put(s, field(key), true)}
      {:ok, "false"} -> {:ok, Map.put(s, field(key), false)}
      {:ok, v} -> {:error, "#{key} must be true or false, got #{inspect(v)}"}
      error -> error
    end
  end

  defp put_pos_int(s, args, key) do
    case fetch(args, key) do
      :absent ->
        {:ok, s}

      {:ok, v} when is_integer(v) and v > 0 ->
        {:ok, Map.put(s, field(key), v)}

      {:ok, v} when is_binary(v) ->
        case Integer.parse(v) do
          {n, ""} when n > 0 -> {:ok, Map.put(s, field(key), n)}
          _ -> {:error, "#{key} must be a positive integer, got #{inspect(v)}"}
        end

      {:ok, v} ->
        {:error, "#{key} must be a positive integer, got #{inspect(v)}"}

      error ->
        error
    end
  end

  # A list from the API, a comma-separated string from kelictl.
  defp put_list(s, args, key, norm) do
    case fetch(args, key) do
      :absent ->
        {:ok, s}

      {:ok, v} when v in [nil, ""] ->
        {:ok, Map.put(s, field(key), [])}

      {:ok, v} when is_binary(v) ->
        {:ok, Map.put(s, field(key), split(v, norm))}

      {:ok, v} when is_list(v) ->
        if Enum.all?(v, &is_binary/1),
          do:
            {:ok, Map.put(s, field(key), v |> Enum.map(&norm.(String.trim(&1))) |> Enum.uniq())},
          else: {:error, "#{key} must be a list of strings, got #{inspect(v)}"}

      {:ok, v} ->
        {:error, "#{key} must be a list, got #{inspect(v)}"}

      error ->
        error
    end
  end

  defp split(v, norm) do
    v
    |> String.split(",", trim: true)
    |> Enum.map(&norm.(String.trim(&1)))
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  # CIDR prefixes, each kept as the operator wrote it once it parses.
  defp put_networks(s, args, key) do
    with {:ok, s} <- put_list(s, args, key, & &1) do
      case Enum.reject(Map.get(s, field(key)), &match?({:ok, _}, SIP.NetUtils.parse_prefix(&1))) do
        [] -> {:ok, s}
        [bad | _] -> {:error, "#{key}: #{inspect(bad)} is not a CIDR network (a.b.c.d/n)"}
      end
    end
  end

  defp put_password(s, base, args) do
    case fetch(args, "auth_password") do
      {:ok, pass} when is_binary(pass) and pass != "" ->
        if is_nil(s.auth_username) or is_nil(s.auth_realm),
          do: {:error, "auth_password needs auth_username and auth_realm"},
          else: {:ok, %{s | auth_ha1: ha1s(s.auth_username, s.auth_realm, pass)}}

      {:ok, v} when v in [nil, ""] ->
        {:ok, %{s | auth_ha1: []}}

      {:ok, v} ->
        {:error, "auth_password must be a string, got #{inspect(v)}"}

      :absent ->
        # The stored HA1 hashes the user and the realm: either one changing
        # without the password would leave an HA1 that can only answer wrong.
        if s.auth_ha1 != [] and
             (s.auth_username != base.auth_username or s.auth_realm != base.auth_realm),
           do: {:error, "changing auth_username or auth_realm needs auth_password again"},
           else: {:ok, s}

      error ->
        error
    end
  end

  defp ha1s(user, realm, pass) do
    for algorithm <- @ha1_algorithms,
        do: %{algorithm: algorithm, hex: Auth.compute_ha1(algorithm, user, realm, pass)}
  end

  # ── checks ──────────────────────────────────────────────────────────────────

  defp check_required(s) do
    missing = for f <- [:domain, :slug, :type, :primary_uri], is_nil(Map.get(s, f)), do: f

    case missing do
      [] -> :ok
      _ -> {:error, "missing #{Enum.join(missing, ", ")}"}
    end
  end

  @slug ~r/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/

  defp check_slug(slug) do
    if Regex.match?(@slug, slug),
      do: :ok,
      else: {:error, "slug #{inspect(slug)} must be a hostname (letters, digits, - and .)"}
  end

  # Checked on the arguments AND on the result: a field given for a type that does
  # not use it, even at its default value, and one an update would leave set after
  # the type changed.
  defp check_type_fields(s, args) do
    defaults = %__MODULE__{}

    misplaced =
      if(s.type == "sip-proxy", do: [], else: @proxy_only) ++
        if(s.type == "sip-trunk", do: [], else: @trunk_only) ++
        if s.type in @ext_domain_types, do: [], else: ["ext_domain"]

    given? = fn key -> Map.get(args, key) not in [nil, ""] end

    changed? = fn key ->
      key != "auth_password" and Map.get(s, field(key)) != Map.get(defaults, field(key))
    end

    set = for key <- misplaced, given?.(key) or changed?.(key), do: key

    set =
      if s.type != "sip-trunk" and s.auth_ha1 != [] and "auth_password" not in set,
        do: set ++ ["auth_password"],
        else: set

    case set do
      [] -> :ok
      _ -> {:error, "#{Enum.join(set, ", ")} do(es) not apply to a #{s.type} server"}
    end
  end

  # An application server is a host, a trunk is an account on one.
  defp check_userpart(%__MODULE__{type: type} = s) do
    for uri <- uris(s), reduce: :ok do
      :ok ->
        {:ok, parsed} = parse_uri(uri)

        case {type, parsed.userpart} do
          {"sip-application", u} when u not in [nil, ""] ->
            {:error, "#{uri}: a sip-application URI has no user part"}

          {"sip-trunk", u} when u in [nil, ""] ->
            {:error, "#{uri}: a sip-trunk URI carries the account's user part"}

          _ ->
            :ok
        end

      error ->
        error
    end
  end

  defp parse_uri(v) do
    case SIP.Uri.parse(String.trim(v)) do
      {:ok, %SIP.Uri{scheme: scheme, domain: domain} = uri}
      when scheme in ["sip:", "sips:"] and is_binary(domain) and domain != "" ->
        {:ok, uri}

      _ ->
        :error
    end
  end

  defp uri_host(uri) do
    {:ok, parsed} = parse_uri(uri)
    String.downcase(parsed.domain)
  end

  defp field(key), do: String.to_existing_atom(key)
end
