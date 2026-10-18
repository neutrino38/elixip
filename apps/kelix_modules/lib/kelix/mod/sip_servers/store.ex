defmodule Kelix.Mod.SipServers.Store do
  @moduledoc """
  The server definitions on disk: the module's source of truth, fed by kelictl and
  the API (design `docs/design/sip-server-specs.md`), on the model of
  `Kelix.Mod.Mcu.Store`.

  One JSON file, read once at start and rewritten whole on every change. Servers
  are declared neither in `config.toml` nor in `domains.toml`.

  **Mode 0600.** A trunk's HA1 is hashed, not encrypted, and it is
  password-equivalent for its realm: the file is protected as if it held the
  password.

  **Atomic on write** — a sibling `.tmp` then a rename in the same directory — so a
  node killed mid-save loses the last change and never the file.

  Reading is **tolerant per row and strict per file**: a malformed server is skipped
  with its name logged, while a file that does not parse at all disables
  persistence for the run rather than being overwritten. A row is read through
  `Kelix.Mod.SipServers.Server.build/2`, the same reading kelictl and the API go
  through, so a hand-edited entry means what it means there.
  """

  require Logger

  alias Kelix.Mod.SipServers.Server

  # Bumped when the shape changes in a way an older node cannot read. A file from a
  # newer version is refused whole.
  @version 1

  @doc """
  The servers a file holds. `{:ok, []}` when it does not exist yet; `{:error, reason}`
  when it exists and cannot be read or parsed.
  """
  @spec load(Path.t()) :: {:ok, [Server.t()]} | {:error, term}
  def load(path) do
    case File.read(path) do
      {:ok, body} -> decode_file(body, path)
      {:error, :enoent} -> {:ok, []}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "Write `servers` as the whole content of `path`, mode 0600."
  @spec save(Path.t(), [Server.t()]) :: :ok | {:error, term}
  def save(path, servers) do
    document = %{"version" => @version, "servers" => Enum.map(servers, &encode/1)}
    tmp = path <> ".tmp"

    with {:ok, body} <- Jason.encode(document, pretty: true),
         :ok <- File.write(tmp, [body, "\n"]),
         :ok <- File.chmod(tmp, 0o600),
         :ok <- File.rename(tmp, path) do
      :ok
    else
      {:error, reason} -> {:error, reason}
    end
  end

  # Field by field: a field added to the struct is absent from the file until
  # someone decides it belongs there.
  defp encode(%Server{} = s) do
    %{
      "domain" => s.domain,
      "slug" => s.slug,
      "type" => s.type,
      "primary_uri" => s.primary_uri,
      "backup_uri" => s.backup_uri,
      "tertiary_uri" => s.tertiary_uri,
      "source_networks" => s.source_networks,
      "use_dns_srv" => s.use_dns_srv,
      "send_keepalive" => s.send_keepalive,
      "initiate_connection" => s.initiate_connection,
      "use_fqdn_contact" => s.use_fqdn_contact,
      "ha_mode" => s.ha_mode,
      "ext_domain" => s.ext_domain,
      "ext_domain_aliases" => s.ext_domain_aliases,
      "probe_remote_aors" => s.probe_remote_aors,
      "probe_interval" => s.probe_interval,
      "aors" => s.aors,
      "register" => s.register,
      "register_expires" => s.register_expires,
      "register_retry" => s.register_retry,
      "auth_username" => s.auth_username,
      "auth_realm" => s.auth_realm,
      "auth_ha1" => Enum.map(s.auth_ha1, &%{"algorithm" => &1.algorithm, "hex" => &1.hex})
    }
    |> Map.reject(fn {k, v} -> is_nil(v) or not Server.applies?(s.type, k) end)
  end

  defp decode_file(body, path) do
    case Jason.decode(body) do
      {:ok, %{"servers" => rows} = document} when is_list(rows) ->
        with :ok <- check_version(Map.get(document, "version")) do
          {:ok, decode_rows(rows, path)}
        end

      {:ok, other} ->
        {:error, {:bad_document, other}}

      {:error, %Jason.DecodeError{} = err} ->
        {:error, err}
    end
  end

  defp check_version(version) when is_integer(version) and version <= @version, do: :ok
  defp check_version(other), do: {:error, {:unsupported_version, other}}

  defp decode_rows(rows, path) do
    Enum.flat_map(rows, fn row ->
      case decode(row) do
        {:ok, server} ->
          [server]

        {:error, reason} ->
          Logger.error(
            module: __MODULE__,
            message:
              "#{path}: server #{inspect(name_of(row))} was not restored (#{reason}); " <>
                "the other definitions are loaded — fix the entry or delete it"
          )

          []
      end
    end)
  end

  defp name_of(%{} = row), do: "#{row["slug"]}@#{row["domain"]}"
  defp name_of(_row), do: nil

  defp decode(%{} = row) do
    with {:ok, ha1} <- decode_ha1(Map.get(row, "auth_ha1", [])),
         {:ok, server} <- Server.build(Map.drop(row, ["auth_ha1", "auth_password"])),
         :ok <- ha1_belongs(server, ha1) do
      {:ok, %Server{server | auth_ha1: ha1}}
    end
  end

  defp decode(_row), do: {:error, "not a JSON object"}

  defp ha1_belongs(_server, []), do: :ok

  defp ha1_belongs(%Server{type: "sip-trunk", auth_username: u, auth_realm: r}, _)
       when is_binary(u) and is_binary(r),
       do: :ok

  defp ha1_belongs(_server, _ha1),
    do: {:error, "auth_ha1 needs a sip-trunk with auth_username and auth_realm"}

  defp decode_ha1(list) when is_list(list) do
    Enum.reduce_while(list, {:ok, []}, fn
      %{"algorithm" => algorithm, "hex" => hex}, {:ok, acc}
      when is_binary(algorithm) and is_binary(hex) ->
        case SIP.Auth.canonical_algorithm(algorithm) do
          nil -> {:halt, {:error, "auth_ha1: unknown algorithm #{inspect(algorithm)}"}}
          canonical -> {:cont, {:ok, acc ++ [%{algorithm: canonical, hex: hex}]}}
        end

      other, _acc ->
        {:halt, {:error, "auth_ha1: #{inspect(other)} is not {algorithm, hex}"}}
    end)
  end

  defp decode_ha1(other), do: {:error, "auth_ha1 must be a list, got #{inspect(other)}"}
end
