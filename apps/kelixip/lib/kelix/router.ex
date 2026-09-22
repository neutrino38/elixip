defmodule Kelix.Router do
  @moduledoc """
  Declarative dispatch of an out-of-dialog request (design §2.1, §4).

  Three steps: **domain** (R-URI host, else To host → `name`/`aliases`) →
  **function** (method → registrar/calls/presence, must be enabled) → **script**
  (the function's script, the dial-plan first-match for `calls`, or the
  `[[domain.presence]]` block naming the request's event package). No global
  routing script — runtime-data routing lives inside the selected script.

  Step 3 is where the **489 Bad Event** is raised, before any script runs: a
  script serving one package must never have to check that the SUBSCRIBE or the
  PUBLISH concerns it (DESIGN-PRESENCE.md, *the Router reads `Event`*). The
  refusal carries the domain's `Allow-Events`, so the watcher learns which
  packages it could have asked for.

  `resolve/2` is the pure decision (this module's heart); quota and instance
  spawning (§4.1 steps 4-5) are layered on top by the ConfigRegistry callbacks
  (added next), which call `Kelix.Domains.current/0` then `resolve/2`.
  """

  @behaviour SIP.Session.Registrar
  @behaviour SIP.Session.Call
  @behaviour SIP.Session.Presence
  require Logger

  alias Kelix.{Domains, Domain, DialRule, PresenceBlock, InstancePool}

  @type function_kind :: :registrar | :calls | :presence
  @type route :: %{
          domain: Domain.t(),
          function: function_kind,
          script: String.t(),
          event_package: String.t() | nil
        }
  @type reject ::
          {:reject, 404 | 405 | 489, String.t()} | {:reject, 405 | 489, String.t(), list}

  # method → SIP function (spec §2.1 table)
  #
  # MESSAGE is deliberately absent: it carries no `Event`, so it cannot name one of
  # the `[[domain.presence]]` blocks, and page-mode chat is a function of its own
  # with its own dispatch (DESIGN-CHAT.md, *chat is a function of its own*). Until
  # those blocks exist an out-of-dialog MESSAGE is answered 405 — which is what a
  # node serving no chat should say, rather than handing it to a subscription
  # script that has no clause for it.
  @method_function %{
    REGISTER: :registrar,
    INVITE: :calls,
    SUBSCRIBE: :presence,
    PUBLISH: :presence
  }

  # ── supervision-tree entry (§2.1) ────────────────────────────────────────────

  # The router is stateless — it runs no process. It still takes a place in the
  # tree so the wiring happens **in boot order**: registered as the processing
  # module here, before `Kelix.Listener.Supervisor` (the next child) accepts the
  # first request. `:ignore` = nothing to supervise.
  @spec child_spec(term) :: Supervisor.child_spec()
  def child_spec(_opts) do
    %{id: __MODULE__, start: {__MODULE__, :register_processing_modules, []}, type: :worker}
  end

  @doc """
  Register the router as the processing module for every implemented SIP function.
  Always `:ignore`.
  """
  @spec register_processing_modules() :: :ignore
  def register_processing_modules() do
    :ok = SIP.Session.ConfigRegistry.set_registration_processing_module(__MODULE__)
    # Inbound calls go through the very same resolve → quota → spawn path as
    # REGISTER; only the callback the dialog layer invokes differs. Without this
    # registration the framework answers an INVITE 500 ("no call server defined")
    # however complete the domain's dial plan is.
    :ok = SIP.Session.ConfigRegistry.set_call_processing_module(__MODULE__)
    # Out-of-dialog OPTIONS do not go through the dial-plan: they are answered
    # directly by Kelix.Options (200 with our Allow, or 503 while draining). Without
    # a module registered the framework answers 500, which upstream reads as "node
    # broken" — so this registration is what makes kelixip pingable at all.
    :ok = SIP.Session.ConfigRegistry.set_options_processing_module(Kelix.Options)
    # SUBSCRIBE and PUBLISH take the same resolve → quota → spawn path; what
    # differs is the step-3 reading of `Event`. Without this registration the
    # framework answers 500 to a SUBSCRIBE, whatever the domain declares.
    :ok = SIP.Session.ConfigRegistry.set_presence_processing_module(__MODULE__)
    :ignore
  end

  # ── processing-module callbacks (registered in SIP.Session.ConfigRegistry) ───

  @impl SIP.Session.Registrar
  def on_new_registration(dialog_id, registerreq, _transaction_id),
    do: dispatch(dialog_id, registerreq)

  @impl SIP.Session.Registrar
  def on_registration_expired(_dialog_id, _app_pid), do: :ok

  @impl SIP.Session.Call
  def on_new_call(dialog_id, invitereq, _transaction_id),
    do: dispatch(dialog_id, invitereq)

  # The instance is monitored by `Kelix.InstancePool`, which frees its slot on
  # `:DOWN`; there is nothing left for the dialog layer to tell us here.
  @impl SIP.Session.Call
  def on_call_end(_dialog_id, _app_pid), do: :ok

  @impl SIP.Session.Presence
  def on_new_subscribe(dialog_id, subreq, _transaction_id), do: dispatch(dialog_id, subreq)

  @impl SIP.Session.Presence
  def on_new_publish(dialog_id, pubreq, _transaction_id), do: dispatch(dialog_id, pubreq)

  # Same as `on_call_end/2`: the instance's slot is freed by the pool's monitor,
  # and the scenario has already been handed its own `{:subscription_terminated, …}`.
  @impl SIP.Session.Presence
  def on_subscription_expired(_dialog_id, _app_pid), do: :ok

  # An out-of-dialog MESSAGE goes through the same resolution as every other
  # request, and `@method_function` maps it to nothing: the answer is 405 with the
  # `Allow` this node advertises. It is routed here, not answered here, so the day
  # `[[domain.chat]]` lands the block decides and this callback does not change.
  #
  # Not having it at all was a crash, not a refusal: `SIP.Session.ConfigRegistry`
  # called an `@optional_callbacks` function that did not exist, `SIP.DialogImpl.init/1`
  # died on the `:undef`, and the sender got nothing to read. Linphone's typing
  # indicator is an out-of-dialog MESSAGE, so it happened on the first chat window
  # anyone opened.
  @impl SIP.Session.Presence
  def on_message(dialog_id, msgreq, _transaction_id), do: dispatch(dialog_id, msgreq)

  @doc """
  Full dispatch of an out-of-dialog request: resolve (this module) then reserve a
  slot + spawn via `Kelix.InstancePool`. Returns `{:accept, pid}` or
  `{:reject, code, reason}` (404 from routing, 503 quota, 500 script load) — or
  `{:reject, code, reason, fields}` when the refusal carries a header of its own,
  which the dialog layer puts on the response: `Allow` on a 405 (RFC 3261
  §21.4.6), the domain's `Allow-Events` on a 489.
  """
  @spec dispatch(pid | nil, map, Domains.t() | nil) ::
          {:accept, pid} | {:reject, integer, String.t()} | {:reject, integer, String.t(), list}
  def dispatch(dialog_id, req, domains \\ nil) do
    case resolve(domains || Domains.current(), req) do
      {:reject, code, reason} ->
        reject_metric(req, code)
        {:reject, code, reason}

      {:reject, code, reason, fields} ->
        reject_metric(req, code)
        {:reject, code, reason, fields}

      {:route, %{domain: domain, function: function, script: script}} ->
        # The routing decision itself, before the quota and the spawn: without it
        # the only script name in the log is the one the operator *believes* is
        # served, and a dial-plan mismatch is invisible until someone reads the
        # media the call actually produced.
        Logger.info(
          module: __MODULE__,
          message:
            "dial-plan: #{Map.get(req, :method)} #{ruri_user(req) || "-"}@#{domain.name} " <>
              "-> #{function} script #{script}"
        )

        route = %{
          domain: domain.name,
          function: function,
          script: script,
          max_calls: domain.max_calls
        }

        emit_accept(
          InstancePool.accept(route, dialog_id, req, overrides_for(domain, req)),
          domain.name,
          function
        )
    end
  end

  # routing reject (404 no-domain / 405 method / 489 event package): label by host
  # + method, since no domain or no block was resolved to label it by.
  defp reject_metric(req, code),
    do:
      Kelix.Metrics.Emit.dispatch_rejected(req_host(req) || "unknown", method_function(req), code)

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
  #
  # A presence instance also gets the **event package** its block declares, for the
  # same reason it gets the domain: the script is the domain's, the package is the
  # block's, and a script hardcoding either serves one deployment.
  defp overrides_for(%Domain{name: name} = domain, req) do
    base =
      case media_override() do
        nil -> [domain: name]
        cfg -> [domain: name, mediaserver_instance: cfg]
      end

    case presence_block(domain, req) do
      %PresenceBlock{event_package: package} -> [{:event_package, package} | base]
      _ -> base
    end
  end

  # Ask the pool for an MCU. Three outcomes, and the middle one used to be lost in
  # the other two:
  #
  #   * an MCU              → its module and url, for this call only
  #   * NO POOL AT ALL      → `nil`: fall back to the global `:mediaserver` config.
  #     That is a pool-less deployment, and the standalone `elixipp` tool, both of
  #     which legitimately name their media server in configuration.
  #   * a pool that has NOTHING serviceable → `[module: :unavailable]`, which
  #     `media_connect/0` refuses to connect to.
  #
  # The last case returned `nil` too, so the instance fell back to the global
  # config — which defaults to `module: :mockup`. A production server that lost its
  # media server therefore routed real traffic to a TEST STUB: the call signalled
  # perfectly, `Scenario … succeeded` was logged, and neither party saw or heard
  # anything. Observed 2026-08-13, with the media server alive but wedged (its
  # accept queue full, so probes timed out rather than being refused).
  #
  # A pool that answered "nothing" is information, not an absence of it. Falling
  # back to configuration at that point overrides a live measurement with a static
  # guess, and the guess is a stub.
  #
  # Public for one reason: this three-way distinction IS the fix, and the defect it
  # replaces lived for months in wiring that no test could reach. Not part of the
  # supported API.
  @doc """
  A media server carrying every addressing profile this call needs, as
  `media_connect/0` asks for it once `b2bua_resolve/1` has resolved the targets
  (step 5 of docs/design/multi-interface.md).

  Declared to the framework as `:elixip2, :mediaserver_selector` — the framework
  cannot reach `Kelix.MediaPool`, which is a kelixip surface, so the selection is
  injected rather than called.

  Same three outcomes as `media_override/1`, and the middle one matters more
  here: a pool with no server carrying the needed interface answers
  `module: :unavailable`, and the call is refused instead of placing its media
  where the peer cannot reach it.
  """
  @spec media_for_profiles([{:ipv4 | :ipv6, :internal | :public}]) :: keyword()
  def media_for_profiles(profiles), do: media_override(Kelix.MediaPool, profiles)

  @doc false
  @spec media_override(GenServer.server(), [{:ipv4 | :ipv6, :internal | :public}]) ::
          keyword() | nil
  def media_override(pool \\ Kelix.MediaPool, profiles \\ []) do
    case Process.whereis(pool) do
      nil ->
        nil

      _pid ->
        case Kelix.MediaPool.checkout(pool, profiles) do
          {:ok, %{name: name, module: module, url: url}} ->
            # `name:` is inert for `media_connect/0` — it reads `:module` and `:url` —
            # and it is what the monitor's `mediaserver` column shows: an operator
            # reading `kelictl monitor` next to `kelictl mediaserver list` needs the
            # same word in both, not a url on one side and a name on the other.
            [name: name, module: module, url: url]

          {:error, reason} ->
            # Loud on purpose: this is the whole media plane being unavailable, and
            # the silence around it is what made the failure above take an evening
            # to find. The pool's own health verdict is not otherwise logged, and
            # `mediaserver.down` belongs to the MCU module, which a B2BUA call does
            # not go through.
            Logger.error(
              module: __MODULE__,
              message:
                "no serviceable media server in the pool (#{inspect(reason)}): " <>
                  "calls needing media will be refused. " <>
                  "Pool status: #{inspect(safe_pool_status(pool))}"
            )

            [module: :unavailable]
        end
    end
  end

  # Status for the log line above, defensively: a pool that is mid-restart must not
  # turn a refusal into a crash.
  defp safe_pool_status(pool) do
    Kelix.MediaPool.status(pool)
  rescue
    _ -> :unavailable
  catch
    _, _ -> :unavailable
  end

  @doc """
  Resolve a request against a domains snapshot.

  Returns `{:route, %{domain, function, script}}`, or a `{:reject, code, reason}`:
  `404` (no domain / no dial-plan match), `405` (method's function not enabled, or
  no script declared for it on the package asked for). An event package the domain
  does not serve is `{:reject, 489, reason, [{"Allow-Events", …}]}` — the one
  refusal that carries a header of its own.
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
      %Domain{} = d ->
        {:ok, d}

      _ ->
        log_reject(
          req,
          if(host,
            do: "domain #{host} not declared in domains.toml",
            else: "no domain in the Request-URI nor in the To header"
          )
        )

        {:reject, 404, "Not Found"}
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
        log_reject(req, "method #{Map.get(req, :method)} is not routable out of dialog")
        method_not_allowed()

      function ->
        if function_enabled?(domain, function) do
          {:ok, function}
        else
          log_reject(req, not_configured(function, domain))
          method_not_allowed()
        end
    end
  end

  # RFC 3261 §21.4.6 makes `Allow` mandatory on a 405: a refusal that does not say
  # what IS allowed leaves the sender to find out by trying. The list is
  # `Kelix.Options`', the one this node already advertises on OPTIONS, so a UA
  # reading the two reads one answer.
  defp method_not_allowed(),
    do: {:reject, 405, "Method Not Allowed", [{"Allow", Kelix.Options.allow()}]}

  defp not_configured(:registrar, %Domain{name: name}),
    do:
      "registrar not configured in domains.toml for domain #{name} (no [domain.registrar] block)"

  defp not_configured(:presence, %Domain{name: name}),
    do:
      "presence not configured in domains.toml for domain #{name} " <>
        "(no [[domain.presence]] block)"

  defp not_configured(:calls, %Domain{name: name}),
    do: "no call rule declared in domains.toml for domain #{name} (no [[domain.call]] block)"

  @doc "Is `function` enabled on `domain`? (a function block present = enabled)"
  @spec function_enabled?(Domain.t(), function_kind) :: boolean
  def function_enabled?(%Domain{registrar: r}, :registrar), do: not is_nil(r)
  def function_enabled?(%Domain{presence: p}, :presence), do: p != []
  def function_enabled?(%Domain{dial_plan: dp}, :calls), do: dp != []

  # ── 3. script (function script, dial-plan first-match, or presence block) ────

  defp pick_script(%Domain{registrar: %{script: s}}, :registrar, _req), do: {:ok, s}

  # The event package decides, not the method: one domain serves as many packages
  # as it declares blocks, and which of them this request is about is written in
  # its `Event` header. Read through `SIP.Msg.Ops` like every other header
  # (CLAUDE.md, *Message Layer*) — a second reading here is how two answers to one
  # question start, and the instance's own `accept_subscription/1` is the first.
  defp pick_script(%Domain{} = domain, :presence, req) do
    method = Map.get(req, :method)

    case presence_block(domain, req) do
      %PresenceBlock{} = block ->
        case PresenceBlock.script_for(block, method) do
          script when is_binary(script) ->
            {:ok, script}

          nil ->
            # The package is served, this method on it is not: a `dialog` block
            # with no `publish` script is subscribed to and published by nobody.
            log_reject(
              req,
              "event package #{inspect(block.event_package)} is served on domain " <>
                "#{domain.name}, but no #{method} script is declared for it"
            )

            method_not_allowed()
        end

      nil ->
        refuse_event_package(domain, req)
    end
  end

  defp pick_script(%Domain{dial_plan: rules, name: name}, :calls, req) do
    user = ruri_user(req)

    case Enum.find(rules, &DialRule.matches?(&1, user || "")) do
      %DialRule{script: s} ->
        {:ok, s}

      nil ->
        log_reject(
          req,
          "destination #{req_uri_str(req)} does not match any call rule declared " <>
            "in domain #{name} (#{length(rules)} [[domain.call]] rule(s) tried)"
        )

        {:reject, 404, "Not Found"}
    end
  end

  defp ruri_user(req) do
    case Map.get(req, :ruri) do
      %SIP.Uri{userpart: u} -> u
      _ -> nil
    end
  end

  # ── the event package a presence request names ───────────────────────────────

  @doc """
  The `[[domain.presence]]` block serving `req`'s event package, or nil.

  Public because the module facing the collection asks the same question of a
  request it is handed, and asking it twice is how two answers to one question
  start. A request with no `Event` header matches no block: the package is what
  says which state is being asked for, so its absence is the same answer as a
  package this domain does not serve (RFC 6665 §8.2.1).
  """
  @spec presence_block(Domain.t(), map) :: PresenceBlock.t() | nil
  def presence_block(%Domain{presence: blocks}, req) do
    case SIP.Msg.Ops.event_package(req) do
      {name, _id} -> Enum.find(blocks, &(&1.event_package == name))
      nil -> nil
    end
  end

  @doc """
  The packages a domain serves, as the `Allow-Events` header value — the answer to
  "which ones could I have asked for".

  A property of the domain, never of the node (plan decision 3): two domains on
  one node may serve different packages, so it is composed here and put on the
  responses that already know their domain — the 489 below, and the 2xx the
  notifier scenario sends.
  """
  @spec allow_events(Domain.t()) :: String.t()
  def allow_events(%Domain{} = domain),
    do: SIP.Msg.Ops.allow_events(Domains.event_packages(domain))

  # 489 Bad Event, raised before any script runs, carrying what this domain does
  # serve. Without `Allow-Events` the watcher is told "not that one" and has no way
  # to find out which — RFC 6665 §4.4.7 makes the header the actionable half of the
  # refusal, as `Min-Expires` is for a 423.
  defp refuse_event_package(%Domain{} = domain, req) do
    asked =
      case SIP.Msg.Ops.event_package(req) do
        {name, _id} -> inspect(name)
        nil -> "(no Event header)"
      end

    log_reject(
      req,
      "event package #{asked} is not served on domain #{domain.name} " <>
        "(declared: #{allow_events(domain)})"
    )

    {:reject, 489, "Bad Event", [{"Allow-Events", allow_events(domain)}]}
  end

  # ── why a request was refused, in the operator's words ───────────────────────

  # Every routing reject used to leave nothing but a metric, so "kelixip answers
  # 404 to my INVITE" could not be told from "kelixip answers 404 to my REGISTER
  # for want of a [domain.registrar] block" without reading domains.toml next to a
  # capture. The line names the request AND the domains.toml block that is missing.
  defp log_reject(req, cause) do
    Logger.info(
      module: __MODULE__,
      message: "#{Map.get(req, :method)} #{req_uri_str(req)} rejected: #{cause}"
    )
  end

  # The R-URI as it arrived, else the To URI (the host fallback of `req_host/1`).
  # `serialize_ruri/1` needs a host: a request with neither is already rejected by
  # step 1, and must not crash the line that says so.
  defp req_uri_str(req) do
    case Map.get(req, :ruri) || Map.get(req, :to) do
      %SIP.Uri{domain: d} = uri when is_binary(d) or is_tuple(d) ->
        {:ok, str} = SIP.Uri.serialize_ruri(uri)
        str

      _ ->
        "(no URI)"
    end
  end

  @doc "The functions enabled on a domain, for an `Allow` header (405 responses)."
  @spec enabled_methods(Domain.t()) :: [atom]
  def enabled_methods(%Domain{} = d) do
    for {method, function} <- @method_function, function_enabled?(d, function), do: method
  end
end
