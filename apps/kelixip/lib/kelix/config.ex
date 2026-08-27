defmodule Kelix.Config do
  @moduledoc """
  Parses and holds `config.toml` — the **infrastructure** config (design §3.1).

  Loaded once at boot, read-only afterwards (not hot-reloadable — a change means
  a restart, spec §3). Any validation error aborts boot with a clear message
  (fail fast; systemd then sees a failed start).

  It also translates the infra keys the lower framework already reads into the
  `:elixip2` application env (so those layers need no change) — today
  `server.user_agent → :useragent` and `mediaserver.video_bitrate →
  MediaServer.Mendooze[:video_bandwidth_kbps]`. The other sections (listeners,
  media pool, modules, control API, metrics) are validated and **held** in the
  struct for the phases that consume them (listeners/P?, media pool/P6,
  modules/P5, control/P7).
  """
  use GenServer
  require Logger

  @type listener :: %{
          proto: :udp | :tcp | :tls | :wss,
          addr: String.t() | nil,
          port: pos_integer,
          cert: String.t() | nil,
          key: String.t() | nil
        }

  @typedoc """
  One `[mediaserver.pool.<name>]` entry, decoded (design §9).

  Decoded **here** rather than by each consumer: `Kelix.MediaPool` selects a server
  per point-to-point call and the mcu module opens one control channel per server,
  and both must see the same list — a media server declared once, read one way.
  `module` keeps the `:mockup` / `:mendooze` shorthand the adapters understand.
  """
  @type pool_entry :: %{
          name: String.t(),
          module: :mockup | :mendooze | module,
          url: String.t(),
          enabled: boolean
        }

  @type t :: %__MODULE__{
          node_name: String.t(),
          script_dir: String.t(),
          module_dir: String.t(),
          user_agent: String.t(),
          max_calls: pos_integer | nil,
          log: map,
          listen: [listener],
          mediaserver_pool: [pool_entry],
          mediaserver_video_bitrate: pos_integer,
          mediaserver_bitrate_feedback: [:remb | :tmmbr],
          mediaserver_transport_cc: boolean,
          modules: map,
          control_api: map,
          metrics: map
        }

  @default_video_bitrate_kbps 1500
  # The bitrate-feedback dialects the answer may confirm, as `[mediaserver]
  # bitrate_feedback` names them: "none", "tmmbr", "goog-remb" or both, in any
  # order. What a peer never offered is still never answered — this only narrows.
  @bitrate_feedback_dialects %{"tmmbr" => :tmmbr, "goog-remb" => :remb}
  @default_bitrate_feedback [:remb, :tmmbr]

  defstruct node_name: "kelixip@127.0.0.1",
            script_dir: "/usr/share/kelixip",
            module_dir: "/usr/lib/kelixip/modules",
            user_agent: "Kelixip/1.5.1",
            max_calls: nil,
            log: %{target: "stdout", facility: "local0", level: "info"},
            listen: [],
            # The OUTBOUND TLS/WSS leg's policy: whether the certificate a peer we
            # DIAL presents is checked, and against which authority. Node-wide,
            # because it is about who we are willing to talk to, not about one
            # socket. `[[listen]] cert`/`key` is the inbound side and stays there.
            tls: %{verify: false, ca: nil},
            mediaserver_pool: [],
            # The node's video encoding bitrate (kb/s): what a leg is encoded at and
            # the cap on the `b=AS:` it is answered with. One statement for both
            # media paths — the point-to-point adapter reads it from the app env,
            # the mcu module takes it as the default of its own `video_bitrate`.
            mediaserver_video_bitrate: @default_video_bitrate_kbps,
            # Which bitrate-feedback dialects the answer may confirm. Narrowing the
            # list is what an OPEN-LOOP rate-control measurement needs: with nothing
            # leaving towards the peer, the source keeps emitting at its own rate and
            # the incoming bitrate stops depending on what the media server
            # estimates — the only setting under which its recovery time measures its
            # own estimator instead of the loop it forms with the browser's
            # congestion control. Naming a single dialect isolates one of the two
            # paths. Empty leaves the call with no congestion control from us at all,
            # so production wants both.
            mediaserver_bitrate_feedback: @default_bitrate_feedback,
            # Whether the SDP negotiates transport-wide congestion control on video
            # (RFC 8285 extmap + `a=rtcp-fb transport-cc`), which is what feeds the
            # media server's SENDER-side bandwidth estimator. Off by default, and the
            # default moves only once the recipe of
            # `docs/design/kelixip-transport-wide-cc.md` §6 has run: the server does
            # not yet emit fmt 15 reports for what it RECEIVES, so a peer that
            # negotiates the extension gets nothing back for its own outgoing stream
            # and falls back on RR losses plus the REMB/TMMBR we keep sending.
            mediaserver_transport_cc: false,
            modules: %{},
            control_api: %{},
            metrics: %{}

  @protos %{"udp" => :udp, "tcp" => :tcp, "tls" => :tls, "wss" => :wss}
  @log_levels ~w(debug info warning error)
  @log_targets ~w(syslog stdout)
  @auth_modes ~w(token mtls none)

  # ── API ──────────────────────────────────────────────────────────────────────

  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc "The loaded infra config (`%Kelix.Config{}`)."
  @spec current() :: t
  def current(), do: GenServer.call(__MODULE__, :current)

  @impl true
  def init(opts) do
    case Keyword.get(opts, :path) do
      nil ->
        # P0/P1: boot with defaults (empty config); the path is wired later.
        cfg = %__MODULE__{}
        apply_app_env(cfg)
        {:ok, cfg}

      path ->
        with {:ok, content} <- read_file(path),
             {:ok, cfg} <- parse(content) do
          apply_app_env(cfg)
          # Only when a real config file was loaded: with no file we must not
          # override the level the host (dev config / tests) already set.
          apply_logger(cfg)

          Logger.info(
            module: __MODULE__,
            message: "config.toml loaded (#{length(cfg.listen)} listeners)"
          )

          {:ok, cfg}
        else
          {:error, reason} -> {:stop, {:invalid_config, abort(path, reason)}}
        end
    end
  end

  # Fail fast *visibly*: a release that dies during boot flushes no Logger output,
  # so the operator would see only "Runtime terminating during boot". Write the
  # reason on stderr — systemd/journald then records why the start failed.
  defp abort(path, reason) do
    IO.puts(:stderr, "kelixip: invalid configuration in #{path}: #{reason}")
    reason
  end

  @impl true
  def handle_call(:current, _from, state), do: {:reply, state, state}

  # ── infra -> :elixip2 app env ────────────────────────────────────────────────

  @doc "Push the framework-facing infra keys into the :elixip2 application env."
  @spec apply_app_env(t) :: :ok
  def apply_app_env(%__MODULE__{} = cfg) do
    Application.put_env(:elixip2, :useragent, cfg.user_agent)
    # `[tls]` reaches the outbound leg here: SIP.Transport.ImplHelpers reads both
    # keys when it dials a TLS or WSS peer.
    Application.put_env(:elixip2, :tls_verify, cfg.tls.verify)

    case cfg.tls.ca do
      nil -> Application.delete_env(:elixip2, :tls_cacertfile)
      path -> Application.put_env(:elixip2, :tls_cacertfile, path)
    end

    # `[mediaserver] video_bitrate` reaches the point-to-point media path here: the
    # Medooze adapter reads `:video_bandwidth_kbps` off its own tuning block for
    # every leg it encodes and answers. Merged, not replaced — the block also holds
    # the timeouts config/config.exs sets.
    # `[mediaserver] bitrate_feedback` rides the same block: the adapter reads it
    # when it decides which rtcp-fb types the answer confirms. So does
    # `transport_cc` — read by the shared SDP layer, so both the point-to-point
    # adapter and the mcu module negotiate the same thing.
    Application.put_env(
      :elixip2,
      MediaServer.Mendooze,
      Application.get_env(:elixip2, MediaServer.Mendooze, [])
      |> Keyword.put(:video_bandwidth_kbps, cfg.mediaserver_video_bitrate)
      |> Keyword.put(:bitrate_feedback, cfg.mediaserver_bitrate_feedback)
      |> Keyword.put(:transport_cc, cfg.mediaserver_transport_cc)
    )

    # The REST frontal (Kelix.ControlAPI.Auth) reads its settings from the app
    # env so both the boot-time child-spec gating and the per-request auth check
    # share one source (and tests can override it).
    Application.put_env(:kelixip, :control_api, cfg.control_api)
    # Same pattern for the metrics/health frontal (Kelix.Metrics.Endpoint, §11).
    Application.put_env(:kelixip, :metrics, cfg.metrics)
    :ok
  end

  @doc """
  Apply `[log]` to the running Logger: the target, then the level.

  `syslog` adds the `Kelix.Log.Syslog` sink under the configured facility;
  anything else removes it. stdout/journald is always live either way — systemd
  captures it — so `syslog` adds a sink rather than replacing one.

  Order matters: the target is applied first so a freshly added sink is included
  when the level is pushed down.
  """
  @spec apply_logger(t) :: :ok
  def apply_logger(%__MODULE__{log: log}) do
    # `level` is validated against @log_levels, so the atom always exists.
    level = String.to_existing_atom(log.level)

    if log.target == "syslog",
      do: Kelix.Log.Syslog.enable(log.facility),
      else: Kelix.Log.Syslog.disable()

    set_level(level)
  end

  @doc """
  Set the log level everywhere: the primary level **and** every sink.

  `Logger.configure(level:)` alone only sets the *primary* level — what is allowed
  to enter the logger. Every sink then filters again on its own level, and the
  compiled-in defaults cap them (console at `:warning`, the file backend at
  `:info`), so raising the primary level to `:debug` changes nothing an operator
  can see. This is the one place that pushes a level down to the sinks, shared by
  `[log].level` at boot/reload and `kelictl log-level` at runtime.

  `:ssl_handler` is deliberately left alone: it is OTP's TLS logger, and putting
  it at debug buries the SIP trace under handshake internals.
  """
  @spec set_level(Logger.level()) :: :ok
  def set_level(level) when is_atom(level) do
    Logger.configure(level: level)
    apply_sink_levels(level)
  end

  defp apply_sink_levels(level) do
    for handler <- :logger.get_handler_ids(), handler not in [:ssl_handler, Logger] do
      :logger.update_handler_config(handler, :level, level)
    end

    # Legacy Elixir backends (this repo ships LoggerFileBackend) live behind a
    # gen_event manager rather than an OTP handler.
    if Process.whereis(Logger) do
      for backend <- :gen_event.which_handlers(Logger), backend != Logger.Backends.Config do
        Logger.configure_backend(backend, level: level)
      end
    end

    :ok
  rescue
    e ->
      Logger.warning(
        module: __MODULE__,
        message: "could not apply [log].level to every sink: #{Exception.message(e)}"
      )

      :ok
  end

  # ── pure parse + validation ──────────────────────────────────────────────────

  @spec parse(String.t()) :: {:ok, t} | {:error, String.t()}
  def parse(content) when is_binary(content) do
    with {:ok, map} <- decode(content),
         :ok <-
           reject_keys(
             map,
             ~w(server log listen mediaserver module control_api metrics tls),
             "config"
           ),
         {:ok, server} <- parse_server(Map.get(map, "server", %{})),
         {:ok, log} <- parse_log(Map.get(map, "log", %{})),
         {:ok, listen} <- parse_listeners(Map.get(map, "listen", [])),
         {:ok, control_api} <- parse_control_api(Map.get(map, "control_api")),
         {:ok, metrics} <- parse_metrics(Map.get(map, "metrics")),
         {:ok, tls} <- parse_tls(Map.get(map, "tls")),
         {:ok, mediaserver} <- parse_mediaserver(Map.get(map, "mediaserver")) do
      {:ok,
       %__MODULE__{
         node_name: server.node_name,
         script_dir: server.script_dir,
         module_dir: server.module_dir,
         user_agent: server.user_agent,
         max_calls: server.max_calls,
         log: log,
         listen: listen,
         mediaserver_pool: mediaserver.pool,
         mediaserver_video_bitrate: mediaserver.video_bitrate,
         mediaserver_bitrate_feedback: mediaserver.bitrate_feedback,
         mediaserver_transport_cc: mediaserver.transport_cc,
         modules: Map.get(map, "module", %{}),
         control_api: control_api,
         metrics: metrics,
         tls: tls
       }}
    end
  end

  defp parse_server(%{} = s) do
    defaults = %__MODULE__{}

    with :ok <-
           reject_keys(s, ~w(node_name script_dir module_dir user_agent max_calls), "[server]"),
         {:ok, node_name} <- opt_string(s, "node_name", defaults.node_name, "[server]"),
         {:ok, script_dir} <- opt_string(s, "script_dir", defaults.script_dir, "[server]"),
         {:ok, module_dir} <- opt_string(s, "module_dir", defaults.module_dir, "[server]"),
         {:ok, user_agent} <- opt_string(s, "user_agent", defaults.user_agent, "[server]"),
         {:ok, max_calls} <- opt_pos_integer(s, "max_calls", "[server]") do
      {:ok,
       %{
         node_name: node_name,
         script_dir: script_dir,
         module_dir: module_dir,
         user_agent: user_agent,
         max_calls: max_calls
       }}
    end
  end

  defp parse_server(_), do: {:error, "[server] must be a table"}

  defp parse_log(%{} = l) do
    with :ok <- reject_keys(l, ~w(target facility level), "[log]"),
         {:ok, target} <- opt_enum(l, "target", @log_targets, "stdout", "[log]"),
         {:ok, facility} <-
           opt_enum(l, "facility", Kelix.Log.Syslog.facilities(), "local0", "[log]"),
         {:ok, level} <- opt_enum(l, "level", @log_levels, "info", "[log]") do
      {:ok, %{target: target, facility: facility, level: level}}
    end
  end

  defp parse_log(_), do: {:error, "[log] must be a table"}

  # [control_api] — the REST frontal (design §10.3). Absent ⇒ disabled. Present ⇒
  # enabled by default, loopback + token; `auth = "token"` requires a non-empty
  # token; `mtls`/`none` need none. Validated at boot so a bad config fails fast.
  defp parse_control_api(nil), do: {:ok, %{enabled: false}}

  defp parse_control_api(%{} = c) do
    with :ok <- reject_keys(c, ~w(enabled addr port auth token cert key cacert), "[control_api]"),
         {:ok, enabled} <- opt_bool(c, "enabled", true, "[control_api]"),
         {:ok, addr} <- opt_string(c, "addr", "127.0.0.1", "[control_api]"),
         {:ok, port} <- opt_port(c, "port", 8090, "[control_api]"),
         {:ok, auth} <- opt_enum(c, "auth", @auth_modes, "token", "[control_api]"),
         {:ok, token} <- control_api_token(c, auth),
         {:ok, tls} <- control_api_tls(c, auth) do
      {:ok, Map.merge(%{enabled: enabled, addr: addr, port: port, auth: auth, token: token}, tls)}
    end
  end

  defp parse_control_api(_), do: {:error, "[control_api] must be a table"}

  # token is required (non-empty) for auth = "token"; ignored for mtls/none
  defp control_api_token(c, "token"), do: req_string(c, "token", "[control_api] token auth")
  defp control_api_token(_c, _auth), do: {:ok, nil}

  # mtls needs the server cert/key plus the CA that signs accepted client certs;
  # the other modes run over plain HTTP (loopback-bound), so certs are forbidden
  defp control_api_tls(c, "mtls") do
    with {:ok, cert} <- req_string(c, "cert", "[control_api] mtls"),
         {:ok, key} <- req_string(c, "key", "[control_api] mtls"),
         {:ok, cacert} <- req_string(c, "cacert", "[control_api] mtls") do
      {:ok, %{cert: cert, key: key, cacert: cacert}}
    end
  end

  defp control_api_tls(c, _auth) do
    case {Map.get(c, "cert"), Map.get(c, "key"), Map.get(c, "cacert")} do
      {nil, nil, nil} -> {:ok, %{}}
      _ -> {:error, "[control_api]: `cert`/`key`/`cacert` only apply to mtls auth"}
    end
  end

  # [metrics] — the Prometheus /metrics + /health frontal (design §11). Absent ⇒
  # disabled. Present ⇒ enabled by default, loopback (a separate port from the
  # control API). No auth: loopback-bound, scraped by a local Prometheus.
  defp parse_metrics(nil), do: {:ok, %{enabled: false}}

  defp parse_metrics(%{} = m) do
    with :ok <- reject_keys(m, ~w(enabled addr port), "[metrics]"),
         {:ok, enabled} <- opt_bool(m, "enabled", true, "[metrics]"),
         {:ok, addr} <- opt_string(m, "addr", "127.0.0.1", "[metrics]"),
         {:ok, port} <- opt_port(m, "port", 9095, "[metrics]") do
      {:ok, %{enabled: enabled, addr: addr, port: port}}
    end
  end

  defp parse_metrics(_), do: {:error, "[metrics] must be a table"}

  # Absent means no checking. Verifying a peer presumes an authority both sides
  # agreed on, which is an interconnect decision and not something a node takes on
  # its own — turning it on is the same deliberate act as putting a client
  # certificate on the wire. It is nonetheless the half that gives the other its
  # worth: a listener demanding a client certificate while this side checks nothing
  # is theatre.
  defp parse_tls(nil), do: {:ok, %__MODULE__{}.tls}

  defp parse_tls(%{} = t) do
    with :ok <- reject_keys(t, ~w(verify ca), "[tls]"),
         {:ok, verify} <- opt_bool(t, "verify", false, "[tls]"),
         {:ok, ca} <- opt_readable_file(t, "ca", "[tls]") do
      {:ok, %{verify: verify, ca: ca}}
    end
  end

  defp parse_tls(_), do: {:error, "[tls] must be a table"}

  # A CA that cannot be read is a configuration error, not a runtime surprise: the
  # alternative is every outbound TLS leg failing at handshake time with an alert
  # that says nothing about the path being wrong.
  defp opt_readable_file(map, key, ctx) do
    case Map.get(map, key) do
      nil ->
        {:ok, nil}

      path when is_binary(path) ->
        if File.regular?(path),
          do: {:ok, path},
          else: {:error, "#{ctx}: `#{key}` is not a readable file: #{path}"}

      other ->
        {:error, "#{ctx}: `#{key}` must be a string, got #{inspect(other)}"}
    end
  end

  defp parse_listeners(list) when is_list(list) do
    reduce_while_ok(list, &parse_listener/1)
  end

  defp parse_listeners(_), do: {:error, "`listen` must be an array of tables ([[listen]])"}

  defp parse_listener(%{} = l) do
    with :ok <- reject_keys(l, ~w(proto addr port cert key), "[[listen]]"),
         {:ok, proto} <- req_proto(l),
         {:ok, addr} <- opt_bind_addr(l),
         {:ok, port} <- req_pos_integer(l, "port", "[[listen]]"),
         {:ok, cert, key} <- listener_certs(l, proto) do
      {:ok, %{proto: proto, addr: addr, port: port, cert: cert, key: key}}
    end
  end

  defp parse_listener(_), do: {:error, "each [[listen]] must be a table"}

  # `addr` states a family, and a wildcard states one too: "0.0.0.0" is every
  # IPv4 interface, "::" every IPv6 one. **Absent** is the only spelling that
  # names no family — it is `nil` here, and the listener supervisor expands it
  # into one socket per family the host carries.
  #
  # nil rather than a default of "0.0.0.0": that string is an IPv4 address, and
  # an operator who writes it is asking for IPv4. Only silence can mean both.
  defp opt_bind_addr(l) do
    case Map.get(l, "addr") do
      nil ->
        {:ok, nil}

      addr when is_binary(addr) ->
        case :inet.parse_address(String.to_charlist(addr)) do
          {:ok, _ip} -> {:ok, addr}
          {:error, _} -> {:error, "[[listen]]: `addr` must be an IP address, got #{inspect(addr)}"}
        end

      other ->
        {:error, "[[listen]]: `addr` must be a string, got #{inspect(other)}"}
    end
  end

  defp req_proto(l) do
    case Map.get(l, "proto") do
      p when is_binary(p) ->
        case Map.get(@protos, p) do
          nil -> {:error, "[[listen]]: unknown proto #{inspect(p)} (udp|tcp|tls|wss)"}
          atom -> {:ok, atom}
        end

      nil ->
        {:error, "[[listen]]: missing required `proto`"}

      _ ->
        {:error, "[[listen]]: `proto` must be a string"}
    end
  end

  # tls/wss need cert+key; udp/tcp must not carry them
  defp listener_certs(l, proto) when proto in [:tls, :wss] do
    with {:ok, cert} <- req_string(l, "cert", "[[listen]] #{proto}"),
         {:ok, key} <- req_string(l, "key", "[[listen]] #{proto}") do
      {:ok, cert, key}
    end
  end

  defp listener_certs(l, _proto) do
    case {Map.get(l, "cert"), Map.get(l, "key")} do
      {nil, nil} -> {:ok, nil, nil}
      _ -> {:error, "[[listen]]: `cert`/`key` only apply to tls/wss listeners"}
    end
  end

  # ── [mediaserver] + [mediaserver.pool.*] (§9) ────────────────────────────────

  # The whole `[mediaserver]` section: the pool plus the node's media policy — video
  # bitrate, which bitrate-feedback dialects the answer confirms, and whether
  # transport-wide congestion control is negotiated. A sibling key is a typo worth
  # naming rather than ignoring.
  defp parse_mediaserver(nil),
    do:
      {:ok,
       %{
         pool: [],
         video_bitrate: @default_video_bitrate_kbps,
         bitrate_feedback: @default_bitrate_feedback,
         transport_cc: false
       }}

  defp parse_mediaserver(%{} = m) do
    with :ok <-
           reject_keys(m, ~w(pool video_bitrate bitrate_feedback transport_cc), "[mediaserver]"),
         {:ok, bitrate} <- opt_pos_integer(m, "video_bitrate", "[mediaserver]"),
         {:ok, feedback} <-
           parse_bitrate_feedback(Map.get(m, "bitrate_feedback")),
         {:ok, transport_cc} <- opt_bool(m, "transport_cc", false, "[mediaserver]"),
         {:ok, pool} <- parse_pool(Map.get(m, "pool")) do
      {:ok,
       %{
         pool: pool,
         video_bitrate: bitrate || @default_video_bitrate_kbps,
         bitrate_feedback: feedback,
         transport_cc: transport_cc
       }}
    end
  end

  defp parse_mediaserver(_), do: {:error, "[mediaserver] must be a table"}

  # "none" | "tmmbr" | "goog-remb" | "goog-remb, tmmbr" — a comma-separated list,
  # order and spacing free because this is hand-written config. "none" says the list
  # is empty and cannot be combined with a dialect: asking for none of one thing and
  # some of another is a typo, not an intent.
  defp parse_bitrate_feedback(nil), do: {:ok, @default_bitrate_feedback}

  defp parse_bitrate_feedback(v) when is_binary(v) do
    names = v |> String.split(",") |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == ""))

    cond do
      names == [] ->
        {:error, bitrate_feedback_error()}

      "none" in names and names != ["none"] ->
        {:error, "[mediaserver]: `bitrate_feedback` cannot combine `none` with a dialect"}

      names == ["none"] ->
        {:ok, []}

      Enum.all?(names, &Map.has_key?(@bitrate_feedback_dialects, &1)) ->
        {:ok, names |> Enum.map(&@bitrate_feedback_dialects[&1]) |> Enum.uniq()}

      true ->
        {:error, bitrate_feedback_error()}
    end
  end

  defp parse_bitrate_feedback(_),
    do: {:error, "[mediaserver]: `bitrate_feedback` must be a string"}

  defp bitrate_feedback_error do
    "[mediaserver]: `bitrate_feedback` must be `none` or a comma-separated list of " <>
      Enum.join(Map.keys(@bitrate_feedback_dialects), ", ")
  end

  defp parse_pool(nil), do: {:ok, []}

  # Name order, not TOML order: it is what makes the round-robin sequence (and the
  # boot log of the mcu module) reproducible from the file alone.
  defp parse_pool(%{} = pool) do
    pool
    |> Enum.sort_by(&elem(&1, 0))
    |> reduce_while_ok(fn {name, attrs} -> parse_pool_entry(name, attrs) end)
  end

  defp parse_pool(_),
    do: {:error, "`mediaserver.pool` must be a table of [mediaserver.pool.<name>] blocks"}

  defp parse_pool_entry(name, %{} = attrs) do
    ctx = "[mediaserver.pool.#{name}]"

    with :ok <- reject_keys(attrs, ~w(module url enabled), ctx),
         {:ok, module} <- pool_module(attrs, ctx),
         {:ok, url} <- req_string(attrs, "url", ctx),
         {:ok, enabled} <- opt_bool(attrs, "enabled", true, ctx) do
      {:ok, %{name: name, module: module, url: url, enabled: enabled}}
    end
  end

  defp parse_pool_entry(name, _attrs),
    do: {:error, "[mediaserver.pool.#{name}] must be a table"}

  # `mockup`/`mendooze` stay atoms — the adapters resolve the shorthand — and
  # anything else is taken as a `MediaServer.Behaviour` module name. Its existence
  # is not checked here: a module shipped in `module_dir` is loaded after this.
  defp pool_module(attrs, ctx) do
    case Map.get(attrs, "module") do
      "mockup" -> {:ok, :mockup}
      "mendooze" -> {:ok, :mendooze}
      m when is_binary(m) and m != "" -> {:ok, Module.concat([m])}
      nil -> {:error, "#{ctx}: missing required `module` (mockup|mendooze|<module name>)"}
      _ -> {:error, "#{ctx}: `module` must be a string"}
    end
  end

  # ── helpers ──────────────────────────────────────────────────────────────────

  defp decode(content) do
    case Toml.decode(content) do
      {:ok, map} -> {:ok, map}
      {:error, reason} -> {:error, "invalid TOML: #{inspect(reason)}"}
    end
  end

  defp read_file(path) do
    case File.read(path) do
      {:ok, content} -> {:ok, content}
      {:error, reason} -> {:error, "cannot read #{path}: #{:file.format_error(reason)}"}
    end
  end

  defp opt_string(map, key, default, ctx) do
    case Map.get(map, key) do
      nil -> {:ok, default}
      v when is_binary(v) -> {:ok, v}
      _ -> {:error, "#{ctx}: `#{key}` must be a string"}
    end
  end

  defp req_string(map, key, ctx) do
    case Map.get(map, key) do
      v when is_binary(v) and v != "" -> {:ok, v}
      nil -> {:error, "#{ctx}: missing required `#{key}`"}
      _ -> {:error, "#{ctx}: `#{key}` must be a non-empty string"}
    end
  end

  # A bind address, validated here so a typo fails the boot with a clear message
  # rather than crashing Kelix.Listener.Supervisor when it converts it.
  defp opt_enum(map, key, allowed, default, ctx) do
    case Map.get(map, key) do
      nil ->
        {:ok, default}

      v when is_binary(v) ->
        if v in allowed,
          do: {:ok, v},
          else: {:error, "#{ctx}: `#{key}` must be one of #{Enum.join(allowed, "|")}"}

      _ ->
        {:error, "#{ctx}: `#{key}` must be a string"}
    end
  end

  defp opt_bool(map, key, default, ctx) do
    case Map.get(map, key) do
      nil -> {:ok, default}
      v when is_boolean(v) -> {:ok, v}
      _ -> {:error, "#{ctx}: `#{key}` must be a boolean"}
    end
  end

  # a valid TCP port (1..65535) with a default
  defp opt_port(map, key, default, ctx) do
    case Map.get(map, key) do
      nil -> {:ok, default}
      v when is_integer(v) and v > 0 and v < 65_536 -> {:ok, v}
      _ -> {:error, "#{ctx}: `#{key}` must be a port (1..65535)"}
    end
  end

  defp opt_pos_integer(map, key, ctx) do
    case Map.get(map, key) do
      nil -> {:ok, nil}
      v when is_integer(v) and v > 0 -> {:ok, v}
      _ -> {:error, "#{ctx}: `#{key}` must be a positive integer"}
    end
  end

  defp req_pos_integer(map, key, ctx) do
    case Map.get(map, key) do
      v when is_integer(v) and v > 0 -> {:ok, v}
      nil -> {:error, "#{ctx}: missing required `#{key}`"}
      _ -> {:error, "#{ctx}: `#{key}` must be a positive integer"}
    end
  end

  defp reject_keys(map, allowed, ctx) do
    case Map.keys(map) -- allowed do
      [] -> :ok
      extra -> {:error, "#{ctx}: unknown key(s): #{Enum.join(extra, ", ")}"}
    end
  end

  defp reduce_while_ok(list, fun) do
    result =
      Enum.reduce_while(list, {:ok, []}, fn item, {:ok, acc} ->
        case fun.(item) do
          {:ok, parsed} -> {:cont, {:ok, [parsed | acc]}}
          {:error, _} = err -> {:halt, err}
        end
      end)

    with {:ok, acc} <- result, do: {:ok, Enum.reverse(acc)}
  end
end
