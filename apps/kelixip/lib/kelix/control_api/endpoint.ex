defmodule Kelix.ControlAPI.Endpoint do
  @moduledoc """
  Supervised entry point that starts the Bandit HTTP(S) server for the REST
  control frontal (`Kelix.ControlAPI`), gated on `[control_api].enabled` (§10.3).

  It reads its settings from the `:kelixip` app env (populated by `Kelix.Config`
  at boot), so it must be ordered **after** `Kelix.Config` in the supervision
  tree. When disabled — or when no `[control_api]` block is configured — it
  returns `:ignore`, i.e. no server is started.

  Transport by auth mode: `token`/`none` bind plain HTTP on `addr` (loopback by
  default); `mtls` binds HTTPS with `verify_peer` + `fail_if_no_peer_cert`, so the
  TLS layer rejects certless clients before the request reaches the router.
  """
  require Logger

  @spec child_spec(term) :: Supervisor.child_spec()
  def child_spec(_opts) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, []}, type: :supervisor}
  end

  @spec start_link() :: Supervisor.on_start() | :ignore
  def start_link() do
    case Application.get_env(:kelixip, :control_api, %{}) do
      %{enabled: true} = cfg -> start_server(cfg)
      _ -> :ignore
    end
  end

  defp start_server(cfg) do
    case bandit_opts(cfg) do
      {:ok, opts} ->
        Logger.info(
          module: __MODULE__,
          message: "REST control API on #{cfg.addr}:#{cfg.port} (auth=#{cfg.auth})"
        )

        Bandit.start_link(opts)

      {:error, reason} ->
        Logger.error(module: __MODULE__, message: "control API not started: #{inspect(reason)}")
        {:error, reason}
    end
  end

  # Assemble the Bandit options, resolving the bind address and (for mtls) the TLS
  # material. A bad `addr` aborts rather than binding somewhere unexpected.
  defp bandit_opts(cfg) do
    with {:ok, ip} <- parse_addr(cfg.addr) do
      base = [plug: Kelix.ControlAPI, port: cfg.port]

      case cfg.auth do
        "mtls" -> {:ok, base ++ [scheme: :https, thousand_island_options: tls_options(cfg, ip)]}
        _ -> {:ok, base ++ [ip: ip]}
      end
    end
  end

  defp tls_options(cfg, ip) do
    [
      transport_options: [
        ip: ip,
        certfile: cfg.cert,
        keyfile: cfg.key,
        cacertfile: cfg.cacert,
        verify: :verify_peer,
        fail_if_no_peer_cert: true
      ]
    ]
  end

  defp parse_addr(addr) do
    case :inet.parse_address(String.to_charlist(addr)) do
      {:ok, ip} -> {:ok, ip}
      {:error, _} -> {:error, {:bad_addr, addr}}
    end
  end
end
