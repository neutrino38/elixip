defmodule Kelix.ControlAPI.Auth do
  @moduledoc """
  Auth middleware for the REST control frontal (design §10.3). **Auth is a
  boundary concern**: this plug validates the credential *before* the router
  dispatches to `Kelix.Control` / a module's `handle_control/2`, neither of which
  ever inspects credentials.

  Settings come from `[control_api]` (pushed to the `:kelixip` app env by
  `Kelix.Config`), so one source drives both the boot-time child-spec gating and
  this per-request check:

    * `auth = "token"` (default) — a `Authorization: Bearer <token>` header, compared
      to the configured admin token in constant time (`Plug.Crypto.secure_compare/2`).
    * `auth = "mtls"` — the TLS layer already verifies the client certificate
      (`verify_peer` + `fail_if_no_peer_cert`); this plug confirms one was presented.
    * `auth = "none"` — trusted local, no credential (still loopback-bound by `addr`).

  A rejected request gets `401` (token) / `403` (mtls) with a JSON body and the
  pipeline is halted. **Basic model = one admin token** (all commands, all
  domains); per-domain RBAC is roadmap (spec §10).
  """
  @behaviour Plug
  import Plug.Conn

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    case Application.get_env(:kelixip, :control_api, %{}) do
      %{auth: "token", token: token} -> check_token(conn, token)
      %{auth: "mtls"} -> check_mtls(conn)
      %{auth: "none"} -> conn
      # No/empty control_api config reaching an already-started API: deny by
      # default rather than fail open.
      _ -> deny(conn, 401, "unauthorized")
    end
  end

  # ── token ────────────────────────────────────────────────────────────────────

  defp check_token(conn, token) when is_binary(token) and token != "" do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> presented] ->
        if Plug.Crypto.secure_compare(presented, token),
          do: conn,
          else: deny(conn, 401, "invalid token")

      _ ->
        deny(conn, 401, "missing bearer token")
    end
  end

  # misconfigured (token auth without a token): fail closed
  defp check_token(conn, _), do: deny(conn, 401, "unauthorized")

  # ── mtls ─────────────────────────────────────────────────────────────────────

  defp check_mtls(conn) do
    case get_peer_data(conn) do
      %{ssl_cert: cert} when is_binary(cert) -> conn
      _ -> deny(conn, 403, "client certificate required")
    end
  end

  # ── rejection ────────────────────────────────────────────────────────────────

  defp deny(conn, status, message) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(%{error: message}))
    |> halt()
  end
end
