defmodule Kelix.Mod.SipServers.Link do
  @moduledoc """
  One server's process: whether each of its URIs is reachable (lot L3 of
  `docs/design/sip-server-specs.md`).

  It is the `trunk_pid` of the peers built for the server, answering the B2BUA's
  `{:reachable?, uri}` before a target is tried — so a hunt skips a URI known to be
  down instead of waiting for its timeout.

  What makes a URI `:up` or `:down`:

    * **OPTIONS** sent every `keepalive_interval` seconds when `send_keepalive` is
      set. Any final response says the server is there, whatever its code, except
      `503` (it is there, and says it takes no traffic). No answer, or no transport
      to send it on, is `:down`.
    * **Any request received from the server** (`matches_server/2` recognised it):
      proof of life, which brings a `:down` URI back up without waiting for the next
      probe.

  A URI never probed and never heard from is `:unknown`, and counts as reachable:
  a missing liveness source must not make a working server unreachable.

  For a `sip-trunk` it is also (lot L4):

    * the **`credentials`** of its peers, answering the B2BUA's `{:authorize, code,
      challenge, method, digest_uri}` from the stored HA1
      (`Kelix.Mod.SipServers.Credentials`) — a challenge for a realm other than
      `auth_realm` is refused and raises an alarm naming both;
    * the **registration** of the account: a REGISTER to the primary URI (the
      backup after a failure), answered challenges, a refresh before the granted
      lifetime ends, a retry every `register_retry` seconds, doubled after each
      consecutive failure up to an hour, and an un-REGISTER when the server is
      deleted or the node stops.
  """
  use GenServer
  require Logger

  alias Kelix.Mod.SipServers.{Credentials, Server}

  @type state_name :: :unknown | :up | :down

  @default_interval_s 30
  @options_timeout_s 32
  @register_timeout_s 32
  @max_retry_s 3_600

  # ── API ─────────────────────────────────────────────────────────────────────

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc "The server changed (definition or resolution): probe what it is now."
  def update(pid, %Server{} = server, resolved),
    do: GenServer.cast(pid, {:update, server, resolved})

  @doc "A request from `ip` over `transport` was recognised as this server's."
  def seen(pid, transport, ip), do: GenServer.cast(pid, {:seen, transport, ip})

  @doc "`%{uri => :unknown | :up | :down}`."
  def states(pid), do: GenServer.call(pid, :states)

  @doc "A trunk's registration, as `server.show` reports it; `nil` for another type."
  def registration(pid), do: GenServer.call(pid, :registration)

  # ── GenServer ───────────────────────────────────────────────────────────────

  @impl GenServer
  def init(opts) do
    # So a trunk can say goodbye (an un-REGISTER) when it is stopped.
    Process.flag(:trap_exit, true)
    server = Keyword.fetch!(opts, :server)

    state = %{
      server: server,
      resolved: Keyword.get(opts, :resolved, %{}),
      interval_ms: Keyword.get(opts, :interval, @default_interval_s) * 1000,
      states: initial_states(server, %{}),
      probes: %{},
      timer: nil,
      reg: new_registration(server)
    }

    {:ok, state |> schedule(0) |> register_soon(0)}
  end

  @impl GenServer
  def terminate(_reason, state) do
    if state.reg && state.reg.state == :registered, do: send_register(state, 0)
    :ok
  end

  @impl GenServer
  def handle_call({:reachable?, target}, _from, state) do
    reply =
      case uri_of(state, target) do
        nil -> true
        uri -> Map.get(state.states, uri) != :down
      end

    {:reply, reply, state}
  end

  def handle_call(:states, _from, state), do: {:reply, state.states, state}

  def handle_call(:registration, _from, %{reg: nil} = state), do: {:reply, nil, state}

  def handle_call(:registration, _from, %{reg: reg} = state) do
    {:reply, %{state: Atom.to_string(reg.state), error: reg.error}, state}
  end

  def handle_call({:authorize, code, challenge, method, digest_uri}, _from, state)
      when code in [401, 407] do
    {:reply, authorize(state, challenge, method, digest_uri), state}
  end

  @impl GenServer
  def handle_cast({:update, server, resolved}, state) do
    restart = server != state.server

    state = %{
      state
      | server: server,
        resolved: resolved,
        states: initial_states(server, state.states)
    }

    # A changed definition is registered again from scratch: the account, the
    # realm or the registrar may be what changed.
    state =
      if restart,
        do: %{schedule(state, 0) | reg: new_registration(server)} |> register_soon(0),
        else: state

    {:noreply, state}
  end

  def handle_cast({:seen, transport, ip}, state) do
    uris =
      for {uri, addrs} <- state.resolved,
          Enum.any?(addrs, fn {t, a, _port} -> t == transport and a == ip end),
          do: uri

    {:noreply, Enum.reduce(uris, state, &set(&2, &1, :up, "a request was received from it"))}
  end

  @impl GenServer
  def handle_info(:probe, state) do
    state = %{state | timer: nil}

    state =
      if state.server.send_keepalive,
        do: Enum.reduce(uris(state.server), state, &probe(&2, &1)),
        else: state

    {:noreply, schedule(state, state.interval_ms)}
  end

  def handle_info(:register, %{reg: nil} = state), do: {:noreply, state}

  def handle_info(:register, state) do
    state = %{state | reg: %{state.reg | timer: nil}}
    {:noreply, send_register(state, state.server.register_expires)}
  end

  def handle_info({:response, %{response: code} = resp, tid}, %{reg: %{tid: tid}} = state)
      when is_integer(code) and code >= 200 do
    {:noreply, registered(state, resp)}
  end

  def handle_info({:transaction_timeout, _timer, tid, _req, _module}, %{reg: %{tid: tid}} = state) do
    {:noreply, register_failed(state, "REGISTER not answered")}
  end

  def handle_info({:response, %{response: code}, tid}, state)
      when is_integer(code) and code >= 200 do
    case Map.pop(state.probes, tid) do
      {nil, _} ->
        {:noreply, state}

      {uri, probes} ->
        state = %{state | probes: probes}

        if code == 503,
          do: {:noreply, set(state, uri, :down, "OPTIONS answered 503")},
          else: {:noreply, set(state, uri, :up, "OPTIONS answered #{code}")}
    end
  end

  def handle_info({:transaction_timeout, _timer, tid, _req, _module}, state) do
    case Map.pop(state.probes, tid) do
      {nil, _} ->
        {:noreply, state}

      {uri, probes} ->
        {:noreply, set(%{state | probes: probes}, uri, :down, "OPTIONS not answered")}
    end
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ── credentials ─────────────────────────────────────────────────────────────

  defp authorize(state, challenge, method, digest_uri) do
    case Credentials.authorize(state.server, challenge, method, digest_uri) do
      {:ok, _params} = ok ->
        ok

      {:error, {:realm_mismatch, expected, received}} = error ->
        Logger.error(
          module: __MODULE__,
          message:
            "sip server #{name(state)}: challenged for realm #{inspect(received)}, but its " <>
              "credentials were entered for #{inspect(expected)} — enter the password " <>
              "again with auth_realm=#{received}"
        )

        error

      error ->
        Logger.warning(
          module: __MODULE__,
          message: "sip server #{name(state)}: cannot answer the challenge (#{inspect(error)})"
        )

        error
    end
  end

  # ── registration (sip-trunk) ────────────────────────────────────────────────

  defp new_registration(%Server{type: "sip-trunk"}) do
    %{
      state: :unregistered,
      callid: SIP.Msg.Ops.generate_branch_value(),
      tag: SIP.Msg.Ops.generate_from_or_to_tag(),
      cseq: 0,
      target: 0,
      tid: nil,
      sent: nil,
      expires: nil,
      auth_tried: false,
      failures: 0,
      timer: nil,
      error: nil
    }
  end

  defp new_registration(_server), do: nil

  defp register_soon(%{reg: nil} = state, _ms), do: state

  defp register_soon(%{reg: reg} = state, ms) do
    if reg.timer, do: Process.cancel_timer(reg.timer)
    %{state | reg: %{reg | timer: Process.send_after(self(), :register, ms)}}
  end

  defp send_register(state, expires, auth \\ nil) do
    reg = %{state.reg | cseq: state.reg.cseq + 1, expires: expires}
    msg = register_msg(state.server, reg, state.resolved, expires, auth)

    case SIP.Transac.start_uac_transaction(msg, @register_timeout_s) do
      {:ok, tid, sent} ->
        reg = %{reg | tid: tid, sent: sent, auth_tried: auth != nil}
        reg = if reg.state == :registered, do: reg, else: %{reg | state: :registering}
        %{state | reg: reg}

      other ->
        register_failed(%{state | reg: reg}, "REGISTER could not be sent (#{inspect(other)})")
    end
  end

  defp registered(state, %{response: code} = resp) when code in 200..299 do
    reg = state.reg
    granted = SIP.Msg.Ops.granted_expires(resp, reg.sent.contact, reg.expires)

    if reg.state != :registered and reg.expires > 0 do
      Logger.info(
        module: __MODULE__,
        message: "sip server #{name(state)}: registered for #{granted} s"
      )
    end

    reg = %{reg | tid: nil, auth_tried: false, failures: 0, error: nil}

    if reg.expires == 0 do
      %{state | reg: %{reg | state: :unregistered}}
    else
      # Refreshed ahead of the end, as RFC 3261 §10.2.4 leaves it to the client.
      refresh = max(div(granted * 3, 4), 1)
      register_soon(%{state | reg: %{reg | state: :registered}}, refresh * 1000)
    end
  end

  defp registered(state, %{response: code} = resp) when code in [401, 407] do
    challenge =
      if code == 401,
        do: Map.get(resp, :wwwauthenticate),
        else: Map.get(resp, :proxyauthenticate)

    cond do
      state.reg.auth_tried ->
        register_failed(state, "credentials refused (#{code} again)")

      not is_map(challenge) ->
        register_failed(state, "#{code} without a challenge")

      true ->
        {:ok, digest_uri} = SIP.Uri.serialize_ruri(state.reg.sent.ruri)

        case authorize(state, challenge, :REGISTER, digest_uri) do
          {:ok, params} ->
            header = if code == 401, do: :authorization, else: :proxyauthorization
            send_register(state, state.reg.expires, {header, params})

          {:error, reason} ->
            register_failed(state, "cannot answer the challenge (#{inspect(reason)})")
        end
    end
  end

  defp registered(state, %{response: code}),
    do: register_failed(state, "REGISTER answered #{code}")

  # Retry later, on the next URI, waiting twice as long after each consecutive
  # failure — a registrar refusing us is not helped by being asked every second.
  defp register_failed(state, why) do
    reg = state.reg
    uris = uris(state.server)

    if reg.state != :failed or reg.error != why do
      Logger.warning(
        module: __MODULE__,
        message: "sip server #{name(state)}: registration failed (#{why})"
      )
    end

    delay = min(state.server.register_retry * Integer.pow(2, min(reg.failures, 12)), @max_retry_s)

    reg = %{
      reg
      | state: :failed,
        tid: nil,
        auth_tried: false,
        failures: reg.failures + 1,
        target: rem(reg.target + 1, max(length(uris), 1)),
        error: why
    }

    register_soon(%{state | reg: reg}, delay * 1000)
  end

  # REGISTER sip:<registrar> with the account as From and To. With an
  # `ext_domain`, the registrar is named by it and reached where the trunk's URI
  # resolved, as a call is (`Kelix.Mod.SipServers.Route`).
  defp register_msg(server, reg, resolved, expires, auth) do
    uri = Enum.at(uris(server), reg.target) || server.primary_uri
    {:ok, parsed} = SIP.Uri.parse(uri)
    account = parsed.userpart
    host = server.ext_domain || parsed.domain

    ruri =
      case {server.ext_domain, Map.get(resolved, uri, [])} do
        {nil, _} ->
          %SIP.Uri{parsed | userpart: nil}

        {ext, [{transport, ip, port} | _]} ->
          %SIP.Uri{
            scheme: parsed.scheme,
            domain: ext,
            destip: ip,
            destport: port,
            destproto: transport
          }

        {ext, []} ->
          %SIP.Uri{parsed | userpart: nil, domain: ext}
      end

    aor = %SIP.Uri{scheme: "sip:", userpart: account, domain: host}

    msg = %{
      "Max-Forwards" => "70",
      method: :REGISTER,
      ruri: ruri,
      from: %SIP.Uri{aor | hparams: %{"tag" => reg.tag}},
      to: aor,
      contact: %SIP.Uri{
        scheme: "sip:",
        userpart: account,
        domain: "0.0.0.0",
        hparams: %{"expires" => Integer.to_string(expires)}
      },
      callid: reg.callid,
      cseq: [reg.cseq, :REGISTER],
      useragent: Application.get_env(:elixip2, :useragent, "Elixipp/0.1"),
      contentlength: 0
    }

    case auth do
      {header, params} -> Map.put(msg, header, params)
      nil -> msg
    end
  end

  defp name(state), do: "#{state.server.slug}@#{state.server.domain}"

  # ── probing ─────────────────────────────────────────────────────────────────

  defp probe(state, uri) do
    case SIP.Transac.start_uac_transaction(options(state.server, uri), @options_timeout_s) do
      {:ok, tid, _sent} ->
        %{state | probes: Map.put(state.probes, tid, uri)}

      other ->
        set(state, uri, :down, "OPTIONS could not be sent (#{inspect(other)})")
    end
  end

  # An out-of-dialog OPTIONS (RFC 3261 §11): its own Call-ID and From tag, nothing
  # that would open a dialog.
  defp options(server, uri) do
    {:ok, target} = SIP.Uri.parse(uri)
    target = %SIP.Uri{target | userpart: nil}

    %{
      "Max-Forwards" => "70",
      "Accept" => "application/sdp",
      method: :OPTIONS,
      ruri: target,
      from: %SIP.Uri{
        scheme: "sip:",
        userpart: "kelixip",
        domain: server.domain,
        hparams: %{"tag" => SIP.Msg.Ops.generate_from_or_to_tag()}
      },
      to: target,
      callid: SIP.Msg.Ops.generate_branch_value(),
      cseq: [1, :OPTIONS],
      useragent: Application.get_env(:elixip2, :useragent, "Elixipp/0.1"),
      contentlength: 0
    }
  end

  defp schedule(state, ms) do
    if state.timer, do: Process.cancel_timer(state.timer)
    %{state | timer: Process.send_after(self(), :probe, ms)}
  end

  # ── states ──────────────────────────────────────────────────────────────────

  defp uris(server), do: Enum.reject([server.primary_uri, server.backup_uri], &is_nil/1)

  # A URI kept keeps its state; a new one starts unknown.
  defp initial_states(server, old) do
    Map.new(uris(server), fn uri -> {uri, Map.get(old, uri, :unknown)} end)
  end

  defp set(state, uri, new, why) do
    case Map.fetch(state.states, uri) do
      {:ok, ^new} ->
        state

      {:ok, old} ->
        level = if new == :down, do: :warning, else: :info

        Logger.log(level,
          module: __MODULE__,
          message: "sip server #{name(state)}: #{uri} #{old} -> #{new} (#{why})"
        )

        %{state | states: Map.put(state.states, uri, new)}

      :error ->
        state
    end
  end

  # Which of the server's URIs a B2BUA target stands for: the one it is sent to
  # (its resolved destination), else the one naming the same host.
  defp uri_of(state, %SIP.Uri{} = target) do
    by_address =
      if is_tuple(target.destip) do
        Enum.find_value(state.resolved, fn {uri, addrs} ->
          Enum.any?(addrs, fn {_t, ip, _p} -> ip == target.destip end) && uri
        end)
      end

    by_address || by_host(state, target.domain)
  end

  defp uri_of(state, target) when is_binary(target) do
    case SIP.Uri.parse(target) do
      {:ok, parsed} -> uri_of(state, parsed)
      _ -> nil
    end
  end

  defp uri_of(_state, _target), do: nil

  defp by_host(state, host) when is_binary(host) do
    host = String.downcase(host)

    Enum.find(uris(state.server), fn uri ->
      {:ok, parsed} = SIP.Uri.parse(uri)
      String.downcase(parsed.domain) == host
    end)
  end

  defp by_host(_state, _host), do: nil
end
