defmodule Kelix.Router do
  @moduledoc """
  Declarative dispatch of an out-of-dialog request (design §2.1, §4).

  Three steps: **domain** (R-URI host, else To host → `name`/`aliases`) →
  **function** (method → registrar/calls/presence, must be enabled) → **script**
  (the function's script, or the dial-plan first-match for `calls`). No global
  routing script — runtime-data routing lives inside the selected script.

  `resolve/2` is the pure decision (this module's heart); quota and instance
  spawning (§4.1 steps 4-5) are layered on top by the ConfigRegistry callbacks
  (added next), which call `Kelix.Domains.current/0` then `resolve/2`.
  """

  @behaviour SIP.Session.Registrar
  require Logger

  alias Kelix.{Domains, Domain, DialRule, InstancePool}

  @type function_kind :: :registrar | :calls | :presence
  @type route :: %{domain: Domain.t(), function: function_kind, script: String.t()}
  @type reject :: {:reject, 404 | 405, String.t()}

  # method → SIP function (spec §2.1 table)
  @method_function %{
    REGISTER: :registrar,
    INVITE: :calls,
    SUBSCRIBE: :presence,
    PUBLISH: :presence,
    MESSAGE: :presence
  }

  # ── processing-module callbacks (registered in SIP.Session.ConfigRegistry) ───

  @impl SIP.Session.Registrar
  def on_new_registration(dialog_id, registerreq, _transaction_id),
    do: dispatch(dialog_id, registerreq)

  @impl SIP.Session.Registrar
  def on_registration_expired(_dialog_id, _app_pid), do: :ok

  @doc """
  Full dispatch of an out-of-dialog request: resolve (this module) then reserve a
  slot + spawn via `Kelix.InstancePool`. Returns `{:accept, pid}` or
  `{:reject, code, reason}` (404/405 from routing, 503 quota, 500 script load).
  """
  @spec dispatch(pid | nil, map, Domains.t() | nil) ::
          {:accept, pid} | {:reject, integer, String.t()}
  def dispatch(dialog_id, req, domains \\ nil) do
    case resolve(domains || Domains.current(), req) do
      {:reject, code, reason} ->
        # routing reject (404 no-domain / 405 method): label by host + method
        Kelix.Metrics.Emit.dispatch_rejected(
          req_host(req) || "unknown",
          method_function(req),
          code
        )

        {:reject, code, reason}

      {:route, %{domain: domain, function: function, script: script}} ->
        route = %{
          domain: domain.name,
          function: function,
          script: script,
          max_calls: domain.max_calls
        }

        emit_accept(
          InstancePool.accept(route, dialog_id, req, overrides_for(domain)),
          domain.name,
          function
        )
    end
  end

  # single dispatch-metric funnel: label the InstancePool outcome (accepted, or
  # 503 quota / 500 load reject) by the resolved domain + function
  defp emit_accept({:accept, _pid} = ok, domain, function) do
    Kelix.Metrics.Emit.dispatch_accepted(domain, function)
    ok
  end

  defp emit_accept({:reject, code, _reason} = rej, domain, function) do
    Kelix.Metrics.Emit.dispatch_rejected(domain, function, code)
    rej
  end

  # method → function label for a routing reject (SUBSCRIBE/PUBLISH/… → :presence)
  defp method_function(req), do: Map.get(@method_function, Map.get(req, :method), :unknown)

  # Config overrides injected into every spawned instance: the domain name (so the
  # script no longer hardcodes it — migration §14) and, when a media pool is up, the
  # per-call MCU it selected (§9). The `:mediaserver_instance` key lands in the
  # instance's context appdata and is preferred by `media_connect/0` over the global
  # media env, so concurrent calls don't race on a shared adapter config.
  defp overrides_for(%Domain{name: name}) do
    case media_override() do
      nil -> [domain: name]
      cfg -> [domain: name, mediaserver_instance: cfg]
    end
  end

  # ask the pool for an MCU; nil when there is no pool or none is serviceable (the
  # instance then falls back to the global :mediaserver config).
  defp media_override() do
    with pid when is_pid(pid) <- Process.whereis(Kelix.MediaPool),
         {:ok, %{module: module, url: url}} <- Kelix.MediaPool.checkout() do
      [module: module, url: url]
    else
      _ -> nil
    end
  end

  @doc """
  Resolve a request against a domains snapshot.

  Returns `{:route, %{domain, function, script}}`, or a `{:reject, code, reason}`:
  `404` (no domain / no dial-plan match), `405` (method's function not enabled).
  """
  @spec resolve(Domains.t(), map) :: {:route, route} | reject
  def resolve(%Domains{} = domains, req) when is_map(req) do
    with {:ok, domain} <- match_domain(domains, req),
         {:ok, function} <- function_for(req, domain),
         {:ok, script} <- pick_script(domain, function, req) do
      {:route, %{domain: domain, function: function, script: script}}
    end
  end

  # ── 1. domain (R-URI host, else To host) ─────────────────────────────────────

  defp match_domain(domains, req) do
    host = req_host(req)

    case host && Domains.lookup(domains, host) do
      %Domain{} = d -> {:ok, d}
      _ -> {:reject, 404, "Not Found"}
    end
  end

  defp req_host(req) do
    ruri_host(Map.get(req, :ruri)) || ruri_host(Map.get(req, :to))
  end

  defp ruri_host(%SIP.Uri{domain: d}) when is_binary(d), do: d
  defp ruri_host(_), do: nil

  # ── 2. function (method → function, must be enabled on the domain) ────────────

  defp function_for(req, domain) do
    case Map.get(@method_function, Map.get(req, :method)) do
      nil ->
        {:reject, 405, "Method Not Allowed"}

      function ->
        if function_enabled?(domain, function),
          do: {:ok, function},
          else: {:reject, 405, "Method Not Allowed"}
    end
  end

  @doc "Is `function` enabled on `domain`? (a function block present = enabled)"
  @spec function_enabled?(Domain.t(), function_kind) :: boolean
  def function_enabled?(%Domain{registrar: r}, :registrar), do: not is_nil(r)
  def function_enabled?(%Domain{presence: p}, :presence), do: not is_nil(p)
  def function_enabled?(%Domain{dial_plan: dp}, :calls), do: dp != []

  # ── 3. script (function script, or dial-plan first-match for calls) ──────────

  defp pick_script(%Domain{registrar: %{script: s}}, :registrar, _req), do: {:ok, s}
  defp pick_script(%Domain{presence: %{script: s}}, :presence, _req), do: {:ok, s}

  defp pick_script(%Domain{dial_plan: rules}, :calls, req) do
    user = ruri_user(req)

    case Enum.find(rules, &DialRule.matches?(&1, user || "")) do
      %DialRule{script: s} -> {:ok, s}
      nil -> {:reject, 404, "Not Found"}
    end
  end

  defp ruri_user(req) do
    case Map.get(req, :ruri) do
      %SIP.Uri{userpart: u} -> u
      _ -> nil
    end
  end

  @doc "The functions enabled on a domain, for an `Allow` header (405 responses)."
  @spec enabled_methods(Domain.t()) :: [atom]
  def enabled_methods(%Domain{} = d) do
    for {method, function} <- @method_function, function_enabled?(d, function), do: method
  end
end
