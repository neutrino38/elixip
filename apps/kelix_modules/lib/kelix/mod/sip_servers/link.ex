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
  """
  use GenServer
  require Logger

  alias Kelix.Mod.SipServers.Server

  @type state_name :: :unknown | :up | :down

  @default_interval_s 30
  @options_timeout_s 32

  # ── API ─────────────────────────────────────────────────────────────────────

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc "The server changed (definition or resolution): probe what it is now."
  def update(pid, %Server{} = server, resolved),
    do: GenServer.cast(pid, {:update, server, resolved})

  @doc "A request from `ip` over `transport` was recognised as this server's."
  def seen(pid, transport, ip), do: GenServer.cast(pid, {:seen, transport, ip})

  @doc "`%{uri => :unknown | :up | :down}`."
  def states(pid), do: GenServer.call(pid, :states)

  # ── GenServer ───────────────────────────────────────────────────────────────

  @impl GenServer
  def init(opts) do
    server = Keyword.fetch!(opts, :server)

    state = %{
      server: server,
      resolved: Keyword.get(opts, :resolved, %{}),
      interval_ms: Keyword.get(opts, :interval, @default_interval_s) * 1000,
      states: initial_states(server, %{}),
      probes: %{},
      timer: nil
    }

    {:ok, schedule(state, 0)}
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

  @impl GenServer
  def handle_cast({:update, server, resolved}, state) do
    restart = server != state.server

    state = %{
      state
      | server: server,
        resolved: resolved,
        states: initial_states(server, state.states)
    }

    {:noreply, if(restart, do: schedule(state, 0), else: state)}
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
          message:
            "sip server #{state.server.slug}@#{state.server.domain}: #{uri} #{old} -> #{new} (#{why})"
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
