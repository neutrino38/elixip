defmodule Kelix.Metrics.Router do
  @moduledoc """
  The `[metrics]` HTTP surface (design §11): `GET /metrics` (Prometheus text) and
  `GET /health` (liveness + readiness for systemd / orchestrators). No auth —
  loopback-bound, scraped by a local Prometheus.

  Readiness = the node is up **and** the config surfaces are loaded
  (`Kelix.Config` + `Kelix.Domains` alive); a `200` means ready, `503` not yet.
  """
  use Plug.Router

  plug(:match)
  plug(:dispatch)

  get "/metrics" do
    conn
    |> put_resp_content_type("text/plain")
    |> send_resp(200, Kelix.Metrics.scrape())
  end

  get "/health" do
    {status, body} = health()

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end

  match _ do
    send_resp(conn, 404, "not found")
  end

  # liveness is implicit (this process answered); readiness checks the config
  # surfaces are up
  defp health() do
    ready = alive?(Kelix.Config) and alive?(Kelix.Domains)
    status = if ready, do: 200, else: 503
    {status, %{status: if(ready, do: "ok", else: "not_ready"), live: true, ready: ready}}
  end

  defp alive?(name), do: Process.whereis(name) != nil
end
