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
    * the **registration** of the account, unless `register` is false (a trunk that
      only answers the challenges of its calls): a REGISTER to the primary URI (the
      backup after a failure), answered challenges, a refresh before the granted
      lifetime ends, a retry every `register_retry` seconds, doubled after each
      consecutive failure up to an hour, and an un-REGISTER when the server is
      deleted or the node stops.

  For a `sip-proxy` with `probe_remote_aors` it probes the remote AORs attached
  to it (lot L5): one OPTIONS per AOR and `probe_interval`, the Request-URI the AOR
  itself, sent to the proxy (as a `ruri: :keep` peer is) — so the proxy relays it
  to the registered contact or answers for it. The probes are spread over the
  interval, not sent as a burst. A 2xx is `:open`, any other answer or none is
  `:closed`, and the state is reported to `Kelix.Mod.Presence` for the user part of
  the AOR on the server's domain (source `:sip_servers`): a remote AOR then has a
  presence as a local one does. An AOR no longer probed has its state withdrawn.
  """
  use GenServer
  require Logger

  alias Kelix.Mod.SipServers.{Credentials, Server}

  @type state_name :: :unknown | :up | :down

  @default_interval_s 30
  @options_timeout_s 32
  @register_timeout_s 32
  # How often a probe or a REGISTER due at boot looks again for the listeners.
  @listen_wait_ms 200
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

  @doc """
  Whether `target`, one of the server's URIs, is worth trying — the question the
  B2BUA asks before a forwarded attempt (`{:reachable?, uri}`), with its answer to
  silence: no reply, or no process, counts as reachable.
  """
  @spec reachable?(pid(), %SIP.Uri{}) :: boolean()
  def reachable?(pid, target) do
    GenServer.call(pid, {:reachable?, target}) != false
  catch
    :exit, _ -> true
  end

  @doc "`%{aor => :unknown | :open | :closed}` of a proxy's probed remote AORs."
  def aor_states(pid), do: GenServer.call(pid, :aor_states)

  @doc "A trunk's registration, as `server.show` reports it; `nil` for another type."
  def registration(pid), do: GenServer.call(pid, :registration)

  @doc "An INVITE from the server (`:in`) or sent to it (`:out`), for the metrics."
  def count_call(pid, direction) when direction in [:in, :out],
    do: GenServer.cast(pid, {:count_call, direction})

  @doc """
  Everything this process knows about its server, as the service shows and pushes
  it: `reachability`, `registration`, the remote AORs' states (`aor_states`),
  `metrics` and the active `alarms`.
  """
  def status(pid), do: GenServer.call(pid, :status)

  # ── GenServer ───────────────────────────────────────────────────────────────

  @impl GenServer
  def init(opts) do
    # So a trunk can say goodbye (an un-REGISTER) when it is stopped.
    Process.flag(:trap_exit, true)
    server = Keyword.fetch!(opts, :server)

    state = %{
      owner: Keyword.get(opts, :owner),
      published: nil,
      flush: nil,
      metrics: new_metrics(),
      alarms: %{},
      server: server,
      resolved: Keyword.get(opts, :resolved, %{}),
      interval_ms: Keyword.get(opts, :interval, @default_interval_s) * 1000,
      states: initial_states(server, %{}),
      probes: %{},
      timer: nil,
      reg: new_registration(server),
      aors: %{
        states: aor_states_for(server, %{}),
        probes: %{},
        timer: nil,
        next: 0,
        reported: %{},
        presence: nil
      }
    }

    {:ok, state |> schedule(0) |> register_soon(0) |> schedule_aor() |> publish()}
  end

  @impl GenServer
  def handle_call(:status, _from, state), do: {:reply, current_status(state), state}

  def handle_call(msg, from, state), do: msg |> call(from, state) |> published()

  @impl GenServer
  def handle_cast(msg, state), do: msg |> cast(state) |> published()

  @impl GenServer
  def handle_info(:flush_status, state), do: {:noreply, send_status(%{state | flush: nil})}

  # Nothing goes out before the listeners own their sockets: a datagram sent at
  # boot, ahead of them, takes the udp listener's registry name and aborts the
  # node's start (Kelix.Listener.Supervisor.listening?/0). Each timer is re-armed
  # where it is kept, so a definition change can still cancel it.
  def handle_info(msg, state) when msg in [:probe, :register, :probe_aor] do
    if Kelix.Listener.Supervisor.listening?(),
      do: msg |> info(state) |> published(),
      else: {:noreply, rearm(msg, state)}
  end

  def handle_info(msg, state), do: msg |> info(state) |> published()

  @impl GenServer
  def terminate(_reason, state) do
    _ = unregister(state)
    :ok
  end

  defp call({:reachable?, target}, _from, state) do
    reply =
      case uri_of(state, target) do
        nil -> true
        uri -> Map.get(state.states, uri) != :down
      end

    {:reply, reply, state}
  end

  defp call(:states, _from, state), do: {:reply, state.states, state}

  defp call(:aor_states, _from, state), do: {:reply, state.aors.states, state}

  defp call(:registration, _from, %{reg: nil} = state), do: {:reply, nil, state}

  defp call(:registration, _from, %{reg: reg} = state) do
    {:reply, %{state: Atom.to_string(reg.state), error: reg.error}, state}
  end

  defp call({:authorize, code, challenge, method, digest_uri}, _from, state)
       when code in [401, 407] do
    {:reply, authorize(state, challenge, method, digest_uri), state}
  end

  defp cast({:update, server, resolved}, state) do
    restart = server != state.server
    newly_resolved = resolved != state.resolved

    # The binding made under the old definition is dropped first: it would
    # otherwise outlive a trunk told to stop registering, or to use another account.
    state = if restart, do: unregister(state), else: state

    # A new definition is a new chance: the password re-entered for the realm the
    # remote side asked is what clears its alarm.
    state = if restart, do: %{state | alarms: %{}}, else: state

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

    # Whatever waited for an address goes now.
    state =
      if newly_resolved and not restart,
        do: state |> schedule(0) |> register_if_waiting(),
        else: state

    {:noreply, if(restart, do: update_aors(state), else: state)}
  end

  defp cast({:seen, transport, ip}, state) do
    uris =
      for {uri, addrs} <- state.resolved,
          Enum.any?(addrs, fn {t, a, _port} -> t == transport and a == ip end),
          do: uri

    {:noreply, Enum.reduce(uris, state, &set(&2, &1, :up, "a request was received from it"))}
  end

  defp cast({:count_call, direction}, state) do
    key = if direction == :in, do: :calls_in, else: :calls_out
    {:noreply, update_in(state.metrics[key], &(&1 + 1))}
  end

  defp cast({:call_result, _target, code}, state) do
    metrics =
      case code do
        code when code in 200..299 ->
          Map.update!(state.metrics, :answered, &(&1 + 1))

        code ->
          Map.update!(
            state.metrics,
            :failures,
            &Map.update(&1, to_string(code), 1, fn n -> n + 1 end)
          )
      end

    {:noreply, %{state | metrics: metrics}}
  end

  defp info(:probe, state) do
    state = %{state | timer: nil}

    state =
      if state.server.send_keepalive,
        do: Enum.reduce(Server.uris(state.server), state, &probe(&2, &1)),
        else: state

    {:noreply, schedule(state, state.interval_ms)}
  end

  defp info(:register, %{reg: nil} = state), do: {:noreply, state}

  defp info(:register, state) do
    state = %{state | reg: %{state.reg | timer: nil}}
    {:noreply, send_register(state, state.server.register_expires)}
  end

  defp info({:response, %{response: code} = resp, tid}, %{reg: %{tid: tid}} = state)
       when is_integer(code) and code >= 200 do
    {:noreply, registered(state, resp)}
  end

  defp info({:transaction_timeout, _timer, tid, _req, _module}, %{reg: %{tid: tid}} = state) do
    {:noreply, register_failed(state, "REGISTER not answered")}
  end

  defp info(:probe_aor, state) do
    state = put_in(state.aors.timer, nil)
    {:noreply, state |> probe_next_aor() |> schedule_aor()}
  end

  defp info({:DOWN, ref, :process, _pid, _reason}, %{aors: %{presence: ref}} = state) do
    # What we reported went with it: report again on the next probe.
    {:noreply, %{state | aors: %{state.aors | presence: nil, reported: %{}}}}
  end

  defp info({:response, %{response: code}, tid}, state)
       when is_integer(code) and code >= 200 and is_map_key(state.aors.probes, tid) do
    {aor, probes} = Map.pop(state.aors.probes, tid)
    status = if code in 200..299, do: :open, else: :closed
    {:noreply, aor_result(put_in(state.aors.probes, probes), aor, status)}
  end

  defp info({:transaction_timeout, _timer, tid, _req, _module}, state)
       when is_map_key(state.aors.probes, tid) do
    {aor, probes} = Map.pop(state.aors.probes, tid)
    {:noreply, aor_result(put_in(state.aors.probes, probes), aor, :closed)}
  end

  defp info({:response, %{response: code}, tid}, state)
       when is_integer(code) and code >= 200 do
    case Map.pop(state.probes, tid) do
      {nil, _} ->
        {:noreply, state}

      {{uri, sent_at}, probes} ->
        state = %{state | probes: probes} |> rtt(now_ms() - sent_at)

        if code == 503,
          do: {:noreply, set(state, uri, :down, "OPTIONS answered 503")},
          else: {:noreply, set(state, uri, :up, "OPTIONS answered #{code}")}
    end
  end

  defp info({:transaction_timeout, _timer, tid, _req, _module}, state) do
    case Map.pop(state.probes, tid) do
      {nil, _} ->
        {:noreply, state}

      {{uri, _sent_at}, probes} ->
        {:noreply, set(%{state | probes: probes}, uri, :down, "OPTIONS not answered")}
    end
  end

  defp info({:alarm, kind, alarm}, state),
    do: {:noreply, %{state | alarms: Map.put(state.alarms, kind, alarm)}}

  defp info(_msg, state), do: {:noreply, state}

  # ── status ──────────────────────────────────────────────────────────────────

  defp published({:noreply, state}), do: {:noreply, publish(state)}
  defp published({:reply, reply, state}), do: {:reply, reply, publish(state)}

  # Sent to the service when it changed: at once for a state, at most once a
  # second for the metrics alone — a busy trunk changes them on every call.
  defp publish(state) do
    status = current_status(state)

    cond do
      status == state.published ->
        state

      state.published != nil and
          Map.delete(status, :metrics) == Map.delete(state.published, :metrics) ->
        if state.flush,
          do: state,
          else: %{state | flush: Process.send_after(self(), :flush_status, 1_000)}

      true ->
        if state.flush, do: Process.cancel_timer(state.flush)
        send_status(%{state | flush: nil})
    end
  end

  defp send_status(state) do
    status = current_status(state)
    if is_pid(state.owner), do: send(state.owner, {:link_status, key(state), self(), status})
    %{state | published: status}
  end

  defp key(state), do: {state.server.domain, state.server.slug}

  defp current_status(state) do
    %{
      reachability: Map.new(state.states, fn {uri, st} -> {uri, Atom.to_string(st)} end),
      registration:
        state.reg && %{state: Atom.to_string(state.reg.state), error: state.reg.error},
      aor_states: Map.new(state.aors.states, fn {aor, st} -> {aor, Atom.to_string(st)} end),
      metrics: render_metrics(state.metrics),
      alarms: state.alarms |> Map.values() |> Enum.map(&Map.put(&1, :server, state.server.slug))
    }
  end

  defp new_metrics(),
    do: %{
      calls_in: 0,
      calls_out: 0,
      answered: 0,
      failures: %{},
      rtt_last: nil,
      rtt_sum: 0,
      rtt_n: 0
    }

  defp rtt(state, ms) do
    m = state.metrics
    %{state | metrics: %{m | rtt_last: ms, rtt_sum: m.rtt_sum + ms, rtt_n: m.rtt_n + 1}}
  end

  defp render_metrics(m) do
    %{
      calls_in: m.calls_in,
      calls_out: m.calls_out,
      answered: m.answered,
      failures: m.failures,
      options_rtt_ms: %{
        last: m.rtt_last,
        mean: if(m.rtt_n > 0, do: div(m.rtt_sum, m.rtt_n))
      }
    }
  end

  defp now_ms(), do: System.monotonic_time(:millisecond)

  # ── credentials ─────────────────────────────────────────────────────────────

  defp authorize(state, challenge, method, digest_uri) do
    case Credentials.authorize(state.server, challenge, method, digest_uri) do
      {:ok, _params} = ok ->
        ok

      {:error, {:realm_mismatch, expected, received}} = error ->
        send(
          self(),
          {:alarm, :realm_mismatch,
           %{kind: "realm_mismatch", expected: expected, received: received}}
        )

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

  defp new_registration(%Server{type: "sip-trunk", register: true}) do
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
      error: nil,
      waiting: false
    }
  end

  defp new_registration(_server), do: nil

  defp unregister(%{reg: %{state: :registered, timer: timer}} = state) do
    if timer, do: Process.cancel_timer(timer)
    send_register(state, 0)
  end

  defp unregister(state), do: state

  defp register_if_waiting(%{reg: %{waiting: true}} = state), do: register_soon(state, 0)
  defp register_if_waiting(state), do: state

  defp register_soon(%{reg: nil} = state, _ms), do: state

  defp register_soon(%{reg: reg} = state, ms) do
    if reg.timer, do: Process.cancel_timer(reg.timer)
    %{state | reg: %{reg | timer: Process.send_after(self(), :register, ms)}}
  end

  defp send_register(state, expires, auth \\ nil) do
    reg = %{state.reg | cseq: state.reg.cseq + 1, expires: expires}

    case register_msg(state, reg, expires, auth) do
      # not resolved yet: registered when it is (register_if_waiting/1)
      nil -> %{state | reg: %{state.reg | waiting: true}}
      msg -> start_register(state, reg, msg, auth)
    end
  end

  defp start_register(state, reg, msg, auth) do
    reg = %{reg | waiting: false}

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
    uris = Server.uris(state.server)

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
  defp register_msg(state, reg, expires, auth) do
    server = state.server
    uri = Enum.at(Server.uris(server), reg.target) || server.primary_uri
    {:ok, parsed} = SIP.Uri.parse(uri)

    target = Server.at_ext_domain(server, %SIP.Uri{parsed | userpart: nil})

    case stamp_resolved(state, uri, target) do
      nil -> nil
      ruri -> register_msg(server, parsed, ruri, reg, expires, auth)
    end
  end

  defp register_msg(server, parsed, ruri, reg, expires, auth) do
    account = parsed.userpart
    host = server.ext_domain || parsed.domain

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

  # With an `ext_domain`, the OPTIONS asks for that domain and is sent where `uri`
  # resolved, as a REGISTER and a call are.
  defp probe(state, uri) do
    {:ok, parsed} = SIP.Uri.parse(uri)
    target = Server.at_ext_domain(state.server, %SIP.Uri{parsed | userpart: nil})

    case stamp_resolved(state, uri, target) do
      # not resolved yet: probed when it is
      nil ->
        state

      ruri ->
        case SIP.Transac.start_uac_transaction(
               options_msg(state.server, parsed, ruri, target),
               @options_timeout_s
             ) do
          {:ok, tid, _sent} ->
            %{state | probes: Map.put(state.probes, tid, {uri, now_ms()})}

          other ->
            set(state, uri, :down, "OPTIONS could not be sent (#{inspect(other)})")
        end
    end
  end

  # Where `uri` resolved, stamped on `target`. This process never resolves a name
  # itself: a DNS lookup here would hold up every `{:reachable?, _}` the B2BUA
  # asks meanwhile, and every `server.show`. `nil` until the service's resolution
  # has landed (`update/3`).
  defp stamp_resolved(state, uri, %SIP.Uri{} = target) do
    case Map.get(state.resolved, uri, []) do
      [{transport, ip, port} | _] ->
        %SIP.Uri{
          target
          | destip: ip,
            destport: port,
            destproto: transport,
            contact_host: Server.contact_host(state.server)
        }

      [] ->
        nil
    end
  end

  # An out-of-dialog OPTIONS (RFC 3261 §11): its own Call-ID and From tag, nothing
  # that would open a dialog.
  defp options_msg(server, parsed, ruri, to) do
    from = options_from(server, parsed)

    msg = %{
      "Max-Forwards" => "70",
      "Accept" => "application/sdp",
      method: :OPTIONS,
      ruri: ruri,
      from: %SIP.Uri{from | hparams: %{"tag" => SIP.Msg.Ops.generate_from_or_to_tag()}},
      to: to,
      callid: SIP.Msg.Ops.generate_branch_value(),
      cseq: [1, :OPTIONS],
      useragent: Application.get_env(:elixip2, :useragent, "Elixipp/0.1"),
      contentlength: 0
    }

    case options_contact(server, from) do
      nil -> msg
      contact -> Map.put(msg, :contact, contact)
    end
  end

  # The Contact carries the From's user part: a Contact without one crashes the
  # modified Kamailio in front of some servers. The transport keeps it and stamps
  # the address, port and transport (SIP.Transport.add_contact_header/3), as for a
  # REGISTER. A server that knows us by name (`use_fqdn_contact`) gets the bare
  # host, as before.
  defp options_contact(%Server{use_fqdn_contact: true}, _from), do: nil

  defp options_contact(_server, %SIP.Uri{userpart: user}),
    do: %SIP.Uri{scheme: "sip:", userpart: user, domain: "0.0.0.0"}

  # A trunk's keepalive comes from its account, as its REGISTER and its calls do:
  # an operator SBC may drop an OPTIONS from a user it does not know. Another
  # server, or a trunk URI naming no account, gets the node's own name.
  defp options_from(%Server{type: "sip-trunk"} = server, %SIP.Uri{userpart: account} = parsed)
       when account not in [nil, ""],
       do: %SIP.Uri{scheme: "sip:", userpart: account, domain: server.ext_domain || parsed.domain}

  defp options_from(server, _parsed),
    do: %SIP.Uri{scheme: "sip:", userpart: "kelixip", domain: server.domain}

  defp rearm(:probe, state), do: schedule(state, @listen_wait_ms)
  defp rearm(:register, state), do: register_soon(state, @listen_wait_ms)

  defp rearm(:probe_aor, state) do
    timer = Process.send_after(self(), :probe_aor, @listen_wait_ms)
    %{state | aors: %{state.aors | timer: timer}}
  end

  defp schedule(state, ms) do
    if state.timer, do: Process.cancel_timer(state.timer)
    %{state | timer: Process.send_after(self(), :probe, ms)}
  end

  # ── remote AORs (sip-proxy) ─────────────────────────────────────────────────

  defp probes_aors?(%Server{type: "sip-proxy", probe_remote_aors: true, aors: [_ | _]}),
    do: true

  defp probes_aors?(_server), do: false

  # An AOR kept keeps its state; a new one starts unknown.
  defp aor_states_for(server, old) do
    if probes_aors?(server),
      do: Map.new(server.aors, fn aor -> {aor, Map.get(old, aor, :unknown)} end),
      else: %{}
  end

  # The AORs changed, or the probing did: what is no longer probed is withdrawn
  # from presence, and the round starts over.
  defp update_aors(state) do
    aors = state.aors
    states = aor_states_for(state.server, aors.states)

    state =
      Enum.reduce(Map.keys(aors.reported), state, fn aor, state ->
        if Map.has_key?(states, aor), do: state, else: report_aor(state, aor, nil)
      end)

    %{state | aors: %{state.aors | states: states, next: 0}} |> schedule_aor()
  end

  # One AOR per tick, a tick every `probe_interval / N` (±10 %): N AORs make N
  # OPTIONS per interval towards the proxy, spread instead of a burst.
  defp schedule_aor(state) do
    aors = state.aors
    if aors.timer, do: Process.cancel_timer(aors.timer)

    timer =
      case map_size(aors.states) do
        0 ->
          nil

        n ->
          tick = div(state.server.probe_interval * 1000, n)
          jitter = div(tick, 10)
          delay = max(tick - jitter + :rand.uniform(2 * jitter + 1) - 1, 50)
          Process.send_after(self(), :probe_aor, delay)
      end

    %{state | aors: %{aors | timer: timer}}
  end

  defp probe_next_aor(state) do
    aors = state.server.aors |> Enum.filter(&Map.has_key?(state.aors.states, &1))

    case aors do
      [] ->
        state

      list ->
        aor = Enum.at(list, rem(state.aors.next, length(list)))
        state = put_in(state.aors.next, state.aors.next + 1)
        probe_aor(state, aor)
    end
  end

  defp probe_aor(state, aor) do
    {:ok, target} = SIP.Uri.parse("sip:" <> aor)

    case proxy_hop(state) do
      # the proxy is down: nothing reaches the AOR either
      :down ->
        aor_result(state, aor, :closed)

      # not resolved yet: probed on a later round
      nil ->
        state

      via ->
        ruri = %SIP.Uri{
          SIP.Session.B2bua.stamp_destination(target, via)
          | contact_host: Server.contact_host(state.server)
        }

        case SIP.Transac.start_uac_transaction(
               options_msg(state.server, target, ruri, target),
               @options_timeout_s
             ) do
          {:ok, tid, _sent} -> put_in(state.aors.probes[tid], aor)
          _ -> aor_result(state, aor, :closed)
        end
    end
  end

  # The proxy URI to go through: the first one not known to be down, where it
  # resolved. `:down` when every one is, `nil` while none is resolved yet.
  defp proxy_hop(state) do
    case Enum.reject(Server.uris(state.server), &(Map.get(state.states, &1) == :down)) do
      [] ->
        :down

      up ->
        Enum.find_value(up, fn uri ->
          {:ok, parsed} = SIP.Uri.parse(uri)

          with %SIP.Uri{} = stamped <- stamp_resolved(state, uri, parsed),
               %SIP.Uri{} = hop <- SIP.Transport.Selector.select_transport(stamped) do
            hop
          else
            _ -> nil
          end
        end)
    end
  end

  defp aor_result(state, aor, status) do
    case Map.fetch(state.aors.states, aor) do
      {:ok, old} ->
        if old != status do
          Logger.info(
            module: __MODULE__,
            message: "sip server #{name(state)}: remote AOR #{aor} #{old} -> #{status}"
          )
        end

        state = put_in(state.aors.states[aor], status)

        if Map.get(state.aors.reported, aor) == status,
          do: state,
          else: report_aor(state, aor, status)

      # removed while its probe was in flight
      :error ->
        state
    end
  end

  # The presence of `user` on the server's domain, on our own authority. A
  # presence module that is not there is not an error: the state is reported
  # again on the next probe, once it is.
  defp report_aor(state, aor, status) do
    [user | _] = String.split(aor, "@")
    doc = if status, do: SIP.Presence.Doc.new("sip:#{user}@#{state.server.domain}", status)

    case Kelix.Mod.Presence.report(state.server.domain, user, :sip_servers, doc) do
      :ok ->
        reported =
          if status,
            do: Map.put(state.aors.reported, aor, status),
            else: Map.delete(state.aors.reported, aor)

        %{state | aors: %{state.aors | reported: reported}} |> watch_presence()

      {:error, _} ->
        state
    end
  end

  defp watch_presence(%{aors: %{presence: nil}} = state) do
    case Process.whereis(Kelix.Mod.Presence) do
      nil -> state
      pid -> put_in(state.aors.presence, Process.monitor(pid))
    end
  end

  defp watch_presence(state), do: state

  # ── states ──────────────────────────────────────────────────────────────────

  # A URI kept keeps its state; a new one starts unknown.
  defp initial_states(server, old) do
    Map.new(Server.uris(server), fn uri -> {uri, Map.get(old, uri, :unknown)} end)
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

    Enum.find(Server.uris(state.server), fn uri ->
      {:ok, parsed} = SIP.Uri.parse(uri)
      String.downcase(parsed.domain) == host
    end)
  end

  defp by_host(_state, _host), do: nil
end
