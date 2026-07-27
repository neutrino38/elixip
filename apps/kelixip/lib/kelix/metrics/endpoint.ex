defmodule Kelix.Metrics.Endpoint do
  @moduledoc """
  Bandit HTTP server for the metrics/health surface (`Kelix.Metrics.Router`),
  bound to `[metrics].addr:port` (loopback by default, §11). Started only as a
  child of the `Kelix.Metrics` supervisor, which itself runs only when metrics are
  enabled — so no separate gating is needed here.
  """
  require Logger

  @spec child_spec(map) :: Supervisor.child_spec()
  def child_spec(cfg) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, [cfg]}}
  end

  @spec start_link(map) :: Supervisor.on_start() | {:error, term}
  def start_link(cfg) do
    case parse_addr(cfg.addr) do
      {:ok, ip} ->
        Logger.info(module: __MODULE__, message: "metrics/health on #{cfg.addr}:#{cfg.port}")
        Bandit.start_link(plug: Kelix.Metrics.Router, ip: ip, port: cfg.port)

      {:error, reason} ->
        Logger.error(
          module: __MODULE__,
          message: "metrics endpoint not started: #{inspect(reason)}"
        )

        {:error, reason}
    end
  end

  defp parse_addr(addr) do
    case :inet.parse_address(String.to_charlist(addr)) do
      {:ok, ip} -> {:ok, ip}
      {:error, _} -> {:error, {:bad_addr, addr}}
    end
  end
end
