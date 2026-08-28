defmodule MediaServer.Mendooze do
  @moduledoc """
  Server lifecycle GenServer of the Mendooze JSR309 adapter.

  One instance per media server connection. On `connect/1` it creates the
  server-side event queue (`EventQueueCreate`), starts the
  `MediaServer.Mendooze.EventPoller` on the returned source path, and then
  acts as the event router: the poller sends it decoded events, and the
  session tag carried by every event selects the destination
  `MediaServer.Mendooze.Conn` process from the registry.

  This module is the `MediaServer.Behaviour` facade: peer connections and
  their sub-resources (player, recorder, echo) are implemented by
  `MediaServer.Mendooze.Conn` and delegated to from here.

  Configuration (`config :elixip2, MediaServer.Mendooze`):
  `:xmlrpc_timeout_ms` (see `XmlRpc`), `:poller_retry_ms`,
  `:poller_max_failures` (see `EventPoller`), `:rtp_timeout_ms`
  (RTP inactivity watchdog, see `Conn`).
  """

  use GenServer
  @behaviour MediaServer.Behaviour
  require Logger

  alias MediaServer.Mendooze.{Conn, EventPoller, XmlRpc}

  # The media server's self-description, on the same host and port as the XML-RPC
  # control interface (XmlRpc's @jsr309_path is its sibling).
  @status_path "/status/general"

  # ── MediaServer.Behaviour subset ────────────────────────────────────────────

  @doc """
  Connect to a Mendooze media server: `{host, http_port}` of the JSR309
  XML-RPC interface. Returns `{:ok, server_pid}` or `{:error, reason}`.
  """
  @impl MediaServer.Behaviour
  @spec connect(MediaServer.server_addr() | String.t()) :: {:ok, pid()} | {:error, term()}
  def connect(addr), do: connect(addr, [])

  @doc """
  Same as `connect/1` with options.

  `:purpose` — `:call` (default) or `:health_check`. A health check is the pool
  keepalive probe (`Kelix.MediaPool`), which connects and disconnects on every
  cycle: its event-queue lifecycle is then logged at `:debug` and stamped
  `keepalive`, so the probe does not flood the log with queue churn.
  """
  @spec connect(MediaServer.server_addr() | String.t(), keyword()) ::
          {:ok, pid()} | {:error, term()}
  def connect({host, port}, opts) do
    case GenServer.start(__MODULE__, {"http://#{host}:#{port}", opts}) do
      {:ok, pid} -> {:ok, pid}
      {:error, {:connect_failed, reason}} -> {:error, reason}
      {:error, reason} -> {:error, reason}
    end
  end

  # URL form used by scenarios (media_connect) and the MENDOOZE_URL env var:
  # "http://host:port", "http://host" or "host:port"; default port 8080.
  def connect(url, opts) when is_binary(url) do
    case parse_url(url) do
      {:ok, host, port} -> connect({host, port}, opts)
      {:error, _} = err -> err
    end
  end

  @default_http_port 8080

  defp parse_url(url) do
    hostport = String.replace_prefix(url, "http://", "") |> String.trim_trailing("/")

    case String.split(hostport, ":", parts: 2) do
      [host, port_str] ->
        case Integer.parse(port_str) do
          {port, ""} when port in 1..65_535 -> {:ok, host, port}
          _ -> {:error, {:bad_url, url}}
        end

      [host] when host != "" ->
        {:ok, host, @default_http_port}

      _ ->
        {:error, {:bad_url, url}}
    end
  end

  @doc """
  Delete the event queue, stop the poller and terminate. With `force: true`,
  any peer connection still registered is closed first; without it, callers
  are expected to have closed their connections already (teardown order).
  """
  @impl MediaServer.Behaviour
  @spec disconnect(pid(), keyword()) :: :ok
  def disconnect(server, opts \\ []) do
    GenServer.call(server, {:disconnect, Keyword.get(opts, :force, false)})
  catch
    # already stopped — disconnect is idempotent
    :exit, _ -> :ok
  end

  # ── Peer connections ────────────────────────────────────────────────────────

  @doc """
  Create a peer connection, or — with `bridge_with:` — a second endpoint inside
  the media session that connection already owns.

  The distinction is not an optimisation. `EndpointAttachToEndpoint` takes a
  single session id, so two endpoints are connectable only inside one
  `MediaSession`: where the endpoint lives has to be decided when it is created,
  and `bridge/3` cannot repair it afterwards.
  """
  @impl MediaServer.Behaviour
  @spec create_peer_connection(pid(), pid(), MediaServer.conn_opts()) ::
          {:ok, MediaServer.conn_ref()} | {:error, term()}
  def create_peer_connection(server, event_sink, opts \\ []) do
    case Keyword.get(opts, :bridge_with) do
      nil -> Conn.start(server, event_sink, opts)
      sibling -> Conn.add_leg(sibling, opts)
    end
  end

  @impl MediaServer.Behaviour
  def get_local_offer(conn), do: Conn.get_local_offer(conn)

  @impl MediaServer.Behaviour
  def set_remote_answer(conn, sdp), do: Conn.set_remote_answer(conn, sdp)

  @impl MediaServer.Behaviour
  def set_remote_offer(conn, sdp), do: Conn.set_remote_offer(conn, sdp)

  @impl MediaServer.Behaviour
  def add_remote_candidate(conn, candidate), do: Conn.add_remote_candidate(conn, candidate)

  @impl MediaServer.Behaviour
  def call_answered(conn), do: Conn.call_answered(conn)

  @impl MediaServer.Behaviour
  @spec close_peer_connection(pid()) :: :ok
  def close_peer_connection(conn), do: Conn.close(conn)

  # ── Bridge ──────────────────────────────────────────────────────────────────

  @impl MediaServer.Behaviour
  def bridge(a, b, opts), do: Conn.bridge(a, b, opts)

  @impl MediaServer.Behaviour
  def unbridge(a, b), do: Conn.unbridge(a, b)

  # ── Players ─────────────────────────────────────────────────────────────────

  @impl MediaServer.Behaviour
  def create_player(conn, file_path, opts \\ []), do: Conn.create_player(conn, file_path, opts)

  @impl MediaServer.Behaviour
  def start_player(player), do: Conn.player_cmd(player, :start)

  @impl MediaServer.Behaviour
  def pause_player(player), do: Conn.player_cmd(player, :pause)

  @impl MediaServer.Behaviour
  def stop_player(player), do: Conn.player_cmd(player, :stop)

  # ── Recorders ───────────────────────────────────────────────────────────────

  @impl MediaServer.Behaviour
  def create_recorder(conn, file_path, duration_ms, opts \\ []),
    do: Conn.create_recorder(conn, file_path, duration_ms, opts)

  @impl MediaServer.Behaviour
  def start_recorder(recorder), do: Conn.recorder_cmd(recorder, :start)

  @impl MediaServer.Behaviour
  def stop_recorder(recorder), do: Conn.recorder_cmd(recorder, :stop)

  # ── Echo ────────────────────────────────────────────────────────────────────

  @impl MediaServer.Behaviour
  def create_echo(conn), do: Conn.create_echo(conn)

  @impl MediaServer.Behaviour
  def stop_echo(echo), do: Conn.stop_echo(echo)

  # ── Internal API for Conn processes ─────────────────────────────────────────

  @doc false
  def register_conn(server, sess_tag, event_sink),
    do: GenServer.call(server, {:register_conn, sess_tag, self(), event_sink})

  @doc false
  def unregister_conn(server, sess_tag),
    do: GenServer.cast(server, {:unregister_conn, sess_tag})

  @doc false
  # RPC coordinates for Conn processes:
  # %{base_url: ..., queue_id: ..., network_profiles: ...}
  def rpc_info(server), do: GenServer.call(server, :rpc_info)

  @doc """
  The addressing profiles this media server carries, read from it when the
  connection was made (`GetNetworkProfiles`, xmlrpc_jsr309_api.md §6.7 ter).

  `%{"publicv6" => %{available: true, announced: "2001:db8::12", bind: "",
  default: false}, …}` — the four profiles, available or not — or `:unsupported`
  for a server whose API predates the call.

  Asked, never configured. A profile list written on this side is a copy of what
  the server knows about itself, and a copy drifts; the same rule already deleted
  the MCU module's codec configuration.
  """
  @spec network_profiles(pid()) :: %{String.t() => map()} | :unsupported
  def network_profiles(server), do: rpc_info(server).network_profiles

  @doc """
  Everything this media server says about itself, read from it when the
  connection was made (`GET /status/general`, mediaserver
  `docs/reference/status-http.md`).

  The decoded JSON body, keys as strings:

      %{"server" => %{"version" => "1.14.0", "uptimeSecs" => 274_353, ...},
        "capabilities" => %{"audio" => %{"decode" => [...], "encode" => [...]},
                            "video" => %{...},
                            "text" => %{"rfc4103" => true, "rfc8865" => true, ...},
                            "hardware" => %{"vaapi" => false}},
        "security" => %{"modes" => ["none", "sdes-srtp", "dtls-srtp"], ...},
        "network" => %{"profiles" => [...], "rtpPortRange" => %{...}, ...},
        "load" => %{"conferences" => 1, ...}}

  `:unsupported` for a server whose binary predates the endpoint, or that
  answered something other than a JSON object.

  Same rule as `network_profiles/1`: asked, never configured. In particular
  `capabilities.video.encode` and `capabilities.video.decode` are **different
  lists** — the server decodes codecs it cannot encode — and the offer we build
  must read the one matching its direction.
  """
  @spec server_status(pid()) :: map() | :unsupported
  def server_status(server), do: rpc_info(server).server_status

  # ── GenServer callbacks ─────────────────────────────────────────────────────

  @impl true
  def init({base_url, opts}) do
    purpose = Keyword.get(opts, :purpose, :call)

    # The synchronous XML-RPC calls run on httpc's default profile. Raise its
    # per-host session pool so many concurrent peer connections (each issuing
    # several RPCs) don't serialize over the default of 2 connections. The
    # event-stream long-poll lives on its own profile (see EventPoller).
    :httpc.set_options(max_sessions: 100)

    case XmlRpc.call(base_url, "EventQueueCreate") do
      {:ok, [queue_id | rest]} when is_integer(queue_id) and queue_id >= 0 ->
        source_path = source_path(queue_id, rest)
        cfg = Application.get_env(:elixip2, __MODULE__, [])

        {:ok, poller} =
          EventPoller.start_link(
            base_url: base_url,
            source_path: source_path,
            sink: self(),
            purpose: purpose,
            retry_ms: Keyword.get(cfg, :poller_retry_ms, 1_000),
            max_failures: Keyword.get(cfg, :poller_max_failures, 5)
          )

        log_connected(purpose, base_url, queue_id)

        {:ok,
         %{
           base_url: base_url,
           queue_id: queue_id,
           source_path: source_path,
           poller: poller,
           purpose: purpose,
           # What the server says it can announce, read once here. The pool's
           # keepalive probe opens and closes a connection every 30 s, so this
           # re-reads itself: a media server restarted with other addresses is
           # described by its own answer, never by what we remember of it.
           network_profiles: read_network_profiles(base_url, purpose),
           # Same read-every-probe discipline as network_profiles above, and for
           # the same reason: a media server upgraded to another codec set is
           # described by its own answer, never by what we remember of it.
           server_status: read_server_status(base_url, purpose),
           # sess_tag => %{pid: conn_pid, sink: event_sink_pid}
           conns: %{}
         }}

      {:ok, other} ->
        {:stop, {:connect_failed, {:unexpected_return, other}}}

      {:error, reason} ->
        {:stop, {:connect_failed, reason}}
    end
  end

  def init(base_url) when is_binary(base_url), do: init({base_url, []})

  # A pool keepalive probe creates and deletes a queue on every cycle: log that
  # churn at :debug, and say what it is, so it is not read as call activity.
  defp log_connected(:health_check, base_url, queue_id),
    do: Logger.debug("Mendooze: keepalive probe on #{base_url}, event queue #{queue_id}")

  defp log_connected(_purpose, base_url, queue_id),
    do: Logger.info("Mendooze: connected to #{base_url}, event queue #{queue_id}")

  # The four profiles, keyed by name. `:unsupported` covers every way a server can
  # fail to answer — an older binary faults on the unknown method, an unreachable
  # one has already failed EventQueueCreate above — and it means exactly what a
  # controller that never heard of profiles obtains: every leg goes out with no
  # profile, and the server applies its own default.
  defp read_network_profiles(base_url, purpose) do
    case XmlRpc.call(base_url, "GetNetworkProfiles") do
      {:ok, profiles} when is_list(profiles) ->
        case Map.new(Enum.flat_map(profiles, &decode_profile/1)) do
          empty when empty == %{} -> unsupported(purpose, base_url, "the answer names no profile")
          decoded -> log_profiles(purpose, base_url, decoded)
        end

      {:ok, _other} ->
        unsupported(purpose, base_url, "the answer is not a list of profiles")

      {:error, reason} ->
        unsupported(purpose, base_url, "#{inspect(reason)}")
    end
  end

  defp decode_profile(%{"name" => name} = p) when is_binary(name) do
    [
      {name,
       %{
         available: p["available"] == true,
         announced: to_string(p["announced"] || ""),
         bind: to_string(p["bind"] || ""),
         default: p["default"] == true
       }}
    ]
  end

  defp decode_profile(_), do: []

  # Said out loud: it also means a server carrying two addresses is about to be
  # driven through one of them only.
  defp unsupported(:health_check, _base_url, _why), do: :unsupported

  defp unsupported(_purpose, base_url, why) do
    Logger.info(
      "Mendooze: #{base_url} states no addressing profiles (#{why}) — " <>
        "legs will use the server's default"
    )

    :unsupported
  end

  defp log_profiles(:health_check, _base_url, decoded), do: decoded

  defp log_profiles(_purpose, base_url, decoded) do
    available =
      decoded
      |> Enum.filter(fn {_n, p} -> p.available end)
      |> Enum.map_join(", ", fn {n, p} -> "#{n}=#{p.announced}#{if p.default, do: " (default)"}" end)

    Logger.info("Mendooze: #{base_url} announces #{if available == "", do: "no profile", else: available}")
    decoded
  end

  # `GET /status/general` — the media server's own description of itself. Not
  # XML-RPC: the endpoint is plain HTTP + JSON, on the same host and port as the
  # control interface (mediaserver docs/reference/status-http.md).
  #
  # `Accept: application/json` is explicit rather than left to the default: the
  # endpoint also serves a human-readable text rendering, and which one it picks
  # without the header is a rule we should not depend on.
  #
  # Every failure collapses to `:unsupported` — an older binary answers 404, an
  # unreachable one has already failed EventQueueCreate above — and it means what
  # a controller that never heard of the endpoint obtains: nothing is known, and
  # nothing on this side may pretend otherwise.
  defp read_server_status(base_url, purpose) do
    url = String.to_charlist(base_url <> @status_path)
    timeout = status_timeout()
    http_opts = [timeout: timeout, connect_timeout: timeout]
    headers = [{~c"accept", ~c"application/json"}]

    case :httpc.request(:get, {url, headers}, http_opts, body_format: :binary) do
      {:ok, {{_, 200, _}, _headers, body}} ->
        decode_server_status(body, purpose, base_url)

      {:ok, {{_, status, _}, _headers, _body}} ->
        unsupported_status(purpose, base_url, "HTTP #{status}")

      {:error, reason} ->
        unsupported_status(purpose, base_url, "#{inspect(reason)}")
    end
  end

  defp decode_server_status(body, purpose, base_url) do
    case Jason.decode(body) do
      {:ok, %{} = status} -> log_status(purpose, base_url, status)
      {:ok, _other} -> unsupported_status(purpose, base_url, "the answer is not a JSON object")
      {:error, reason} -> unsupported_status(purpose, base_url, "#{inspect(reason)}")
    end
  end

  defp unsupported_status(:health_check, _base_url, _why), do: :unsupported

  defp unsupported_status(_purpose, base_url, why) do
    Logger.info(
      "Mendooze: #{base_url} does not describe itself (#{why}) — " <>
        "its version and capabilities stay unknown to this node"
    )

    :unsupported
  end

  defp log_status(:health_check, _base_url, status), do: status

  defp log_status(_purpose, base_url, status) do
    version = get_in(status, ["server", "version"]) || "?"
    audio = get_in(status, ["capabilities", "audio", "encode"]) || []
    video = get_in(status, ["capabilities", "video", "encode"]) || []

    Logger.info(
      "Mendooze: #{base_url} is mediaserver #{version}, can emit " <>
        "audio [#{Enum.join(audio, " ")}] video [#{Enum.join(video, " ")}]"
    )

    status
  end

  defp status_timeout do
    Application.get_env(:elixip2, __MODULE__, [])
    |> Keyword.get(:status_timeout_ms, 5_000)
  end

  # Older servers return only [queueId]; the documented fallback path applies.
  defp source_path(_queue_id, [path | _]) when is_binary(path), do: path
  defp source_path(queue_id, _), do: "/events/jsr309/#{queue_id}"

  @impl true
  def handle_call({:disconnect, force}, _from, state) do
    if force do
      Enum.each(state.conns, fn {tag, %{pid: pid}} ->
        Logger.warning("Mendooze: force disconnect, closing leftover session #{tag}")

        try do
          GenServer.stop(pid, :shutdown)
        catch
          :exit, _ -> :ok
        end
      end)
    end

    # Stop the poller *before* deleting the queue. The other order is a race the
    # server loses: deleting the queue closes the stream, the poller sees the
    # end-of-stream and schedules its 1 s reconnect, and if the RPC round-trip
    # takes longer than that the retry GETs a queue that no longer exists —
    # "unexpected response: 404 Not Found" in the log, once in a while.
    Process.unlink(state.poller)
    Process.exit(state.poller, :shutdown)

    case XmlRpc.call(state.base_url, "EventQueueDelete", [state.queue_id]) do
      {:ok, _} -> :ok
      # the server may already be gone; disconnect must still succeed
      {:error, reason} -> Logger.warning("Mendooze: EventQueueDelete failed: #{inspect(reason)}")
    end

    {:stop, :normal, :ok, state}
  end

  def handle_call({:register_conn, sess_tag, conn_pid, event_sink}, _from, state) do
    Process.monitor(conn_pid)
    conns = Map.put(state.conns, sess_tag, %{pid: conn_pid, sink: event_sink})
    {:reply, :ok, %{state | conns: conns}}
  end

  def handle_call(:rpc_info, _from, state) do
    {:reply,
     %{
       base_url: state.base_url,
       queue_id: state.queue_id,
       network_profiles: state.network_profiles,
       server_status: state.server_status
     }, state}
  end

  @impl true
  def handle_cast({:unregister_conn, sess_tag}, state) do
    {:noreply, %{state | conns: Map.delete(state.conns, sess_tag)}}
  end

  @impl true
  def handle_info({:mendooze_event, event}, state) do
    sess_tag = elem(event, 1)

    case Map.get(state.conns, sess_tag) do
      %{pid: pid} ->
        send(pid, {:mendooze_event, event})

      nil ->
        # late events after a session teardown are expected
        Logger.debug("Mendooze: dropping event for unknown session #{sess_tag}")
    end

    {:noreply, state}
  end

  def handle_info({:mendooze_poller_down}, state) do
    Logger.error("Mendooze: media server #{state.base_url} unreachable")

    state.conns
    |> Enum.map(fn {_tag, %{sink: sink}} -> sink end)
    |> Enum.uniq()
    |> Enum.each(&send(&1, {:ms_event, self(), :server_disconnected}))

    {:noreply, state}
  end

  def handle_info({:DOWN, _ref, :process, pid, _reason}, state) do
    conns = state.conns |> Enum.reject(fn {_tag, %{pid: p}} -> p == pid end) |> Map.new()
    {:noreply, %{state | conns: conns}}
  end
end
