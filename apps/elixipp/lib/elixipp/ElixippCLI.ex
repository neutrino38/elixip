defmodule Elixipp.CLI do
  @moduledoc """
  Entry point of the standalone `elixipp` executable (built with `mix escript.build`).

      elixipp scenarios/my_call.exs
      elixipp UAC.Invite                       # built-in scenario, no file needed
      elixipp --monitor -l 5 scenarios/my_call.exs
      elixipp --monitor -l 5 --max-run 100 scenarios/my_call.exs

  ## Scenarios

  The argument is either a path to a scenario `.exs` file or the name of a
  **built-in** scenario module bundled into the escript: `UAC.Invite` and
  `UAC.Register`. Built-ins need no file on the host, so the standalone tool can
  run them anywhere.

  ## Options

    * `--monitor` / `-m`   — live table of calls in progress
    * `--limit N` / `-l N` — run N calls simultaneously (implies --monitor)
    * `--max-run N`        — stop after N total executions (`0` = unlimited;
      default: unlimited, except a bare run which does a single one)
    * `--rate N`           — calls started per second (default: 2, max: 100)
    * `--config FILE` / `-c` — JSON file parameterizing the scenario (header +
      N accounts). Overrides the scenario `config` block; accounts are picked
      round-robin across runs. In server (UAS) mode there is no run counter to
      cycle on: the header and the first account are shared by every instance.

  ## Keys (interactive/live mode)

    * `q`       — graceful shutdown: no new calls, wait for active ones
    * `Ctrl+D`  — immediate stop (prints the summary, then halts)
    * `↑ / ↓`   — scroll the call table when it exceeds the terminal height

  ## Logging

    * `--log-file PATH`   — log file path (default `elixipp.log`)
    * `--log-level LEVEL` — file log level: `debug` | `info` | `warning` | `error`
    * `--log-sequence`    — write a PlantUML sequence diagram (`<scenario>_<pid>.puml`)
      per scenario instance. Single-call only (rejected with `--limit > 1`).
  """
  require Logger

  # These all end on System.halt/1 (the tool's exit paths), so Dialyzer's
  # "no local return" is expected — suppress it for them only.
  @dialyzer {:no_return,
             [
               server_monitor_halt: 1,
               run_parallel: 7,
               handle_force_quit: 1,
               abort: 2,
               print_help: 0
             ]}

  @default_log_file "elixipp.log"
  @default_log_level :info

  # Call creation rate (calls per second) and its hard ceiling.
  @default_rate 2

  @max_rate 100

  # Grace period (ms) after a graceful stop before still-running calls that did
  # not honour the cooperative shutdown request are hard-killed.
  @shutdown_grace_ms 5_000

  # Concurrent instances a server (UAS) scenario accepts when --limit is not given.
  # Requests beyond it are rejected with 503, so the client-mode default of 1 made a
  # registrar refuse every phone but the first.
  @default_server_limit 50

  # Table columns: {header, monitor_key, fixed_cell_width}
  @columns [
    {"Scénario", :scenario, 16},
    {"Compte", :account, 16},
    {"Commande", :command, 16},
    {"État", :state, 18},
    {"Événement", :event, 28}
  ]

  # Rows to reserve for the counter line, border, and status bar.
  @ui_overhead 6

  @spec main([String.t()]) :: no_return()
  def main(argv) do
    {opts, rest, _} =
      OptionParser.parse(argv,
        strict: [
          monitor: :boolean,
          limit: :integer,
          max_run: :integer,
          rate: :float,
          config: :string,
          log_file: :string,
          log_level: :string,
          log_sequence: :boolean,
          listen: :keep,
          local_port: :integer,
          local_addr: :string,
          tls_cert: :string,
          tls_key: :string,
          help: :boolean
        ],
        aliases: [m: :monitor, l: :limit, c: :config, h: :help]
      )

    setup_logging(opts[:log_file], opts[:log_level])

    if opts[:help], do: print_help()

    arg =
      case rest do
        [a | _] ->
          a

        [] ->
          abort(
            "usage: elixipp [--monitor] [-l N] [--max-run N] [--rate N] [--log-file PATH] [--log-level LEVEL] <scenario.exs | ModuleName>",
            2
          )
      end

    module = resolve_module(arg)
    ext_config = load_config(opts[:config])
    scenario_type = SIP.Scenario.Loader.scenario_type(module)

    # `--limit` caps concurrent scenario instances. A client run defaults to a
    # single one-shot call; a server accepts @default_server_limit registrations or
    # calls, because the alternative is a test registrar that answers the second
    # phone with a 503 for no reason the operator can see.
    limit =
      opts[:limit] ||
        if scenario_type == :uac, do: 1, else: @default_server_limit

    # Optional local UDP bind overrides (so a UAC can run on a host that already
    # has a UAS bound to 5060 — see the two-process REGISTER recipe in the README).
    apply_local_udp_opts(opts)
    apply_tls_opts(opts)

    # --log-sequence writes one PlantUML file per scenario instance, so it only makes
    # sense when a single instance runs at a time — server mode included, where it
    # used to be accepted and then silently ignored (the flag never reached the app
    # env, because this check sat *after* the server-mode branch below).
    case validate_log_sequence(opts, limit) do
      :ok ->
        if Keyword.get(opts, :log_sequence, false),
          do: Application.put_env(:elixip2, :log_sequence, true)

      {:error, msg} ->
        abort(msg, 2)
    end

    # A server (UAS) scenario is driven by inbound requests, not by an outbound
    # spawn loop: switch to server mode and never return.
    case scenario_type do
      :uac -> :ok
      type -> run_server_mode(module, type, opts, limit, ext_config)
    end

    # Client mode without --local-port: bind a random free UDP port (>= 5000)
    # instead of the transport's 5060 default, so a UAC can always start even
    # when another SIP process already owns 5060 on this host.
    unless opts[:local_port] do
      port = random_free_port(:udp)
      Application.put_env(:elixip2, :udp_local_port, port)
      Logger.info("elixipp: no --local-port given, using random free UDP port #{port}")
    end

    # When neither --limit nor --max-run is given, default to a single one-shot
    # run (--limit 1 --max-run 1). As soon as either is set, --max-run stays
    # unlimited unless explicitly provided.
    max_run =
      case {opts[:limit], opts[:max_run]} do
        {nil, nil} -> 1
        {_, max} -> resolve_max_run(max)
      end

    if limit < 1, do: abort("--limit must be >= 1", 2)
    if max_run != nil and max_run < 0, do: abort("--max-run must be >= 0", 2)

    rate = resolve_rate(opts[:rate])
    spawn_interval_ms = round(1000 / rate)

    # The live/snapshot call table is shown only when --monitor is explicitly
    # requested. Parallel execution (-l N or a multi-run --max-run) still works
    # without it — it just runs silently and prints the final summary.
    monitor? = opts[:monitor] || false
    parallel? = monitor? or limit > 1 or max_run == nil or max_run > 1

    if parallel? do
      run_parallel(module, limit, max_run, spawn_interval_ms, rate, monitor?, ext_config)
    else
      # Single one-shot run: bootstrap the stack ourselves so we can inject the
      # external-config overrides for the first account (index 0).
      SIP.Scenario.Runner.bootstrap_stack()
      overrides = SIP.Scenario.ExternalConfig.overrides_for(ext_config, 0)

      case SIP.Scenario.Runner.run_instance(module, config_overrides: overrides) do
        :ok ->
          IO.puts("Scenario #{inspect(module)} succeeded.")
          System.halt(0)

        {:aborted, reason} ->
          IO.puts("Scenario #{inspect(module)} aborted: #{inspect(reason)}")
          System.halt(0)

        {:error, reason} ->
          IO.puts(:stderr, "Scenario #{inspect(module)} failed: #{inspect(reason)}")
          System.halt(1)
      end
    end
  end

  # ── Server (UAS) mode ─────────────────────────────────────────────────────

  @default_listen {:udp, :all, 5060}

  # Run elixipp as a SIP server: bring up the stack and the configured listeners,
  # register the scenario as the registration processing module, then block until
  # the operator stops the tool. `limit` caps the number of concurrent scenario
  # instances (REGISTER beyond it are rejected with 503). Never returns.
  @spec run_server_mode(module(), atom(), keyword(), pos_integer(), term()) :: no_return()
  defp run_server_mode(module, kind, opts, limit, ext_config)
       when kind in [:uas_register, :uas_invite],
       do: start_uas_server(module, kind, opts, limit, ext_config)

  defp run_server_mode(_module, type, _opts, _limit, _ext_config) do
    abort("Type de scénario serveur non supporté : #{inspect(type)}", 2)
  end

  # Shared bring-up for both UAS server kinds: bind the UDP socket, bootstrap the
  # stack, start the ScenarioUAS factory, register it as the registration or call
  # processing module, start the listeners and enter the (monitored or plain)
  # server loop. Never returns.
  @spec start_uas_server(
          module(),
          :uas_register | :uas_invite,
          keyword(),
          pos_integer(),
          term()
        ) :: no_return()
  defp start_uas_server(module, kind, opts, limit, ext_config) do
    listeners = parse_listeners(opts)
    max_run = resolve_max_run(opts[:max_run])

    # Bind the UDP socket to the first UDP listener's address/port (one socket per
    # host for now — see phase 7). Done before bootstrap so the transport binds it.
    case Enum.find(listeners, fn {proto, _a, _p} -> proto == :udp end) do
      {:udp, addr, port} ->
        Application.put_env(:elixip2, :udp_local_port, port)
        if addr != :all, do: Application.put_env(:elixip2, :udp_local_addr, addr)

      _ ->
        :ok
    end

    SIP.Scenario.Runner.bootstrap_stack()

    {:ok, _pid} =
      Elixip.ScenarioUAS.start_link(
        scenario_module: module,
        max_instances: limit,
        max_run: max_run,
        scenario_overrides: server_scenario_overrides(ext_config)
      )

    :ok =
      case kind do
        :uas_register ->
          SIP.Session.ConfigRegistry.set_registration_processing_module(Elixip.ScenarioUAS)

        :uas_invite ->
          SIP.Session.ConfigRegistry.set_call_processing_module(Elixip.ScenarioUAS)
      end

    started = start_listeners(listeners)
    check_listeners!(started)

    # --monitor wires the same live call table as the UAC parallel mode. Without
    # it (or on a non-interactive stdin) we fall back to the plain text loop.
    if opts[:monitor] do
      run_server_monitored(module, kind, limit, max_run, started)
    else
      print_server_header(module, kind, limit, started)
      server_loop(module, max_run)
    end
  end

  # External-config overrides handed to *every* UAS instance. A server scenario is
  # not driven by a spawn loop, so there is no run counter to cycle accounts on:
  # the header keys and the first account are shared by all instances. This is what
  # makes a real digest check reachable — the reference registrar scenario reads its
  # `password` from these overrides (scenarios/uas_register.exs).
  @doc false
  @spec server_scenario_overrides(term()) :: keyword()
  def server_scenario_overrides(nil), do: []

  def server_scenario_overrides(ext_config) do
    case SIP.Scenario.ExternalConfig.account_count(ext_config) do
      n when n > 1 ->
        IO.puts(
          :stderr,
          "elixipp: mode serveur — #{n} comptes déclarés dans --config, seul le premier est utilisé " <>
            "(un UAS partage les mêmes identifiants entre toutes ses instances)."
        )

      _ ->
        :ok
    end

    ext_config
    |> SIP.Scenario.ExternalConfig.overrides_for(0)
    |> as_server_credential()
  end

  # In a client run the account password is *our own* credential: the context
  # turns `:passwd` into the ha1 of our identity (SIP.Context.set/3) and keeps no
  # clear text. A server needs the opposite — the shared secret to verify an
  # incoming client's digest against — so it is handed over as `:password`, an
  # application key that lands in the context appdata, where the reference
  # registrar reads it (`appdata_get(:password)` in scenarios/uas_register.exs).
  defp as_server_credential(overrides) do
    case Keyword.pop(overrides, :passwd) do
      {nil, rest} -> rest
      {passwd, rest} -> Keyword.put(rest, :password, passwd)
    end
  end

  # A "server" whose listeners all failed answers nothing: say why on stderr and
  # exit non-zero instead of parking forever on sockets that were never bound
  # (kelixip does the same at boot — see Kelix.Listener.Supervisor). A partial
  # failure is reported but lets the run continue on the listeners that are up.
  @spec check_listeners!([{tuple(), :ok | {:error, term()}}]) :: :ok
  defp check_listeners!(started) do
    {verdict, messages} = listener_report(started)
    Enum.each(messages, &IO.puts(:stderr, &1))

    if verdict == :fatal do
      abort("elixipp: aucun listener n'a pu être démarré, le serveur ne répondrait à rien.", 2)
    end

    :ok
  end

  @doc """
  Turn the listener start results into `{verdict, messages}`: one operator-readable
  message per failed listener, and `:fatal` when **every** listener failed (the
  caller then aborts — a server with no socket is not a server).
  """
  @spec listener_report([{tuple(), :ok | {:error, term()}}]) ::
          {:ok | :fatal, [String.t()]}
  def listener_report(started) do
    failed = Enum.reject(started, fn {_listener, status} -> status == :ok end)

    messages =
      Enum.map(failed, fn {{proto, addr, port}, status} ->
        reason = with {:error, r} <- status, do: r

        "elixipp: écoute #{proto} sur #{format_addr(addr)}:#{port} impossible — #{bind_error(reason)}"
      end)

    verdict = if failed != [] and length(failed) == length(started), do: :fatal, else: :ok

    {verdict, messages}
  end

  defp bind_error(:eaddrinuse),
    do: "port déjà utilisé (un autre SIP tourne dessus ? essayez un autre --listen)"

  defp bind_error(:eacces),
    do: "permission refusée (port < 1024 : lancez en root, ou donnez CAP_NET_BIND_SERVICE)"

  defp bind_error(:eaddrnotavail), do: "adresse locale inexistante sur cette machine"

  defp bind_error(:enoent),
    do: "fichier introuvable — certificat/clé TLS manquants ? (tls_certfile / tls_keyfile)"

  defp bind_error(reason), do: inspect(reason)

  defp print_server_header(module, kind, limit, started) do
    IO.puts("elixipp — mode serveur #{server_kind_label(kind)} (#{inspect(module)})")
    IO.puts("  instances max : #{limit}")
    IO.puts("  listeners     : #{format_listeners(started)}")
    IO.puts("  (tapez 'q' puis Entrée pour arrêter)")
  end

  defp server_kind_label(:uas_register), do: "UAS Register"
  defp server_kind_label(:uas_invite), do: "UAS Invite (call server)"

  # Live monitored server loop: bring up Owl + the monitor, render the call table
  # in a live block and react to the keyboard (q / Ctrl+D / arrows). On a
  # non-interactive stdin the live table is impossible, so we degrade to the plain
  # text server loop. Never returns.
  @spec run_server_monitored(module(), atom(), pos_integer(), non_neg_integer() | nil, list()) ::
          no_return()
  defp run_server_monitored(module, kind, limit, max_run, started) do
    {:ok, _} = Application.ensure_all_started(:owl)
    {:ok, _} = SIP.Scenario.Monitor.start()

    if match?({:ok, _}, :io.rows()) do
      raw? = setup_raw_terminal(true)

      Owl.LiveScreen.add_block(:display,
        state: {0, :none},
        render: fn {scroll, shutdown} ->
          render_server_block(scroll, shutdown, module, limit, started)
        end
      )

      start_input_reader(self())

      server_monitor_loop(%{
        scroll_offset: 0,
        raw?: raw?,
        shutdown: :none,
        module: module,
        max_run: max_run
      })
    else
      print_server_header(module, kind, limit, started)
      server_loop(module, max_run)
    end
  end

  @spec server_monitor_loop(map()) :: no_return()
  defp server_monitor_loop(state) do
    receive do
      :graceful_stop when state.shutdown == :none ->
        Elixip.ScenarioUAS.shutdown_all(:elixipp_graceful)
        state = %{state | shutdown: :graceful}
        Owl.LiveScreen.update(:display, {state.scroll_offset, state.shutdown})
        # Same deadline as the UAC path: an instance that does not honour the
        # cooperative shutdown must not leave the operator with only Ctrl+D.
        Process.send_after(self(), :shutdown_deadline, @shutdown_grace_ms)

        # If no instance was active, exit right away.
        if Elixip.ScenarioUAS.stats().active == 0 do
          server_monitor_halt(state)
        else
          server_monitor_loop(state)
        end

      :shutdown_deadline ->
        active = Elixip.ScenarioUAS.stats().active

        if active > 0 do
          Owl.LiveScreen.flush()

          IO.puts(
            "\r\n#{active} instance(s) n'ont pas honoré l'arrêt coopératif en " <>
              "#{div(@shutdown_grace_ms, 1000)}s — arrêt forcé."
          )
        end

        server_monitor_halt(state)

      :graceful_stop ->
        # Already draining — ignore.
        server_monitor_loop(state)

      :force_quit ->
        server_monitor_halt(state)

      :arrow_up ->
        state = %{state | scroll_offset: max(0, state.scroll_offset - 1)}
        Owl.LiveScreen.update(:display, {state.scroll_offset, state.shutdown})
        server_monitor_loop(state)

      :arrow_down ->
        total = length(SIP.Scenario.Monitor.calls())
        max_scroll = max(0, total - visible_rows())
        state = %{state | scroll_offset: min(max_scroll, state.scroll_offset + 1)}
        Owl.LiveScreen.update(:display, {state.scroll_offset, state.shutdown})
        server_monitor_loop(state)

      _ ->
        server_monitor_loop(state)
    after
      500 ->
        Owl.LiveScreen.update(:display, {state.scroll_offset, state.shutdown})
        stats = Elixip.ScenarioUAS.stats()

        # Auto-halt when max_run instances have all completed naturally.
        # RegistrarUAS already refuses new registrations once total_started >= max_run,
        # so no shutdown_all is needed here — that would abort running instances early.
        state =
          if is_integer(state.max_run) and stats.total_started >= state.max_run and
               stats.active == 0 and state.shutdown == :none do
            %{state | shutdown: :graceful}
          else
            state
          end

        if state.shutdown == :graceful and stats.active == 0 do
          server_monitor_halt(state)
        else
          server_monitor_loop(state)
        end
    end
  end

  defp server_monitor_halt(state) do
    Owl.LiveScreen.update(:display, {state.scroll_offset, state.shutdown})
    Owl.LiveScreen.flush()
    restore_terminal(state.raw?)
    IO.puts("\r\nServeur arrêté.")
    print_uas_summary(state.module)
    System.halt(0)
  end

  # Wait for the active instances to wind down after a cooperative shutdown request —
  # but not forever. An instance stuck outside its on_events (or one that ignores
  # {:scenario_ctl, :shutdown, _}) used to hold the tool hostage with no way out but
  # Ctrl+D; the UAC path has always armed the same deadline.
  defp drain_uas_instances(remaining \\ @shutdown_grace_ms)

  defp drain_uas_instances(remaining) when remaining <= 0 do
    case Elixip.ScenarioUAS.stats().active do
      0 ->
        :ok

      active ->
        IO.puts(
          "#{active} instance(s) n'ont pas honoré l'arrêt coopératif en " <>
            "#{div(@shutdown_grace_ms, 1000)}s — arrêt forcé."
        )
    end
  end

  defp drain_uas_instances(remaining) do
    if Elixip.ScenarioUAS.stats().active > 0 do
      Process.sleep(200)
      drain_uas_instances(remaining - 200)
    else
      :ok
    end
  end

  defp print_uas_summary(module) do
    %{
      total_started: total,
      total_succeeded: succ,
      total_aborted: aborted,
      total_failed: failed,
      total_rejected_quota: rejected_quota,
      total_rejected_domain: rejected_domain
    } = Elixip.ScenarioUAS.stats()

    IO.puts("══ Résumé ══════════════════")
    IO.puts("  Scénario    : #{inspect(module)}")
    IO.puts("  Total       : #{total}")
    IO.puts("  Succès      : #{succ}")
    IO.puts("  Interrompus : #{aborted}")
    IO.puts("  Échecs      : #{failed}")

    # Rejections were counted but never shown: a run whose requests were all turned
    # away read as "Total : 0", with nothing saying the tool had answered 503 or 604.
    if rejected_quota > 0,
      do: IO.puts("  Refusés 503 : #{rejected_quota} (quota d'instances atteint, voir -l)")

    if rejected_domain > 0,
      do: IO.puts("  Refusés 604 : #{rejected_domain} (domaine non servi, voir config domains:)")

    IO.puts("════════════════════════════")
  end

  defp render_server_block(scroll, shutdown, module, limit, started) do
    [
      render_server_counters(shutdown, module, limit, started),
      "\n",
      render_table(scroll, true)
    ]
  end

  defp render_server_counters(shutdown, module, limit, started) do
    active = length(SIP.Scenario.Monitor.calls())

    hint =
      case shutdown do
        :none -> "  [q+Entrée: arrêt propre | Ctrl+D: immédiat | ↑↓: défile]"
        :graceful -> "  [arrêt en cours… | Ctrl+D: forcer]"
      end

    line =
      "  Serveur UAS #{inspect(module)}" <>
        "  |  Instances: #{active}/#{limit}" <>
        "  |  Listeners: #{format_listeners(started)}" <>
        hint

    Owl.Data.tag(line, :cyan)
  end

  # Parse repeated --listen options ("proto:port") into {proto, :all, port}
  # triplets. Falls back to the default UDP:5060 listener when none is given.
  @spec parse_listeners(keyword()) :: [{atom(), :all | tuple(), pos_integer()}]
  defp parse_listeners(opts) do
    case Keyword.get_values(opts, :listen) do
      [] -> [@default_listen]
      specs -> Enum.map(specs, &parse_listen_spec/1)
    end
  end

  defp parse_listen_spec(spec) do
    case String.split(spec, ":") do
      # No port given: draw a random free one (>= 5000) for the protocol's
      # socket family (tls/wss listen on TCP sockets).
      [proto] ->
        proto = parse_proto(proto)
        {proto, :all, random_free_port(listen_sock_proto(proto))}

      [proto, port] ->
        {parse_proto(proto), :all, parse_port(port)}

      [proto, addr, port] ->
        {parse_proto(proto), parse_addr(addr), parse_port(port)}

      _ ->
        abort(
          "--listen invalide : #{inspect(spec)} (attendu proto, proto:port ou proto:addr:port)",
          2
        )
    end
  end

  defp listen_sock_proto(:udp), do: :udp
  defp listen_sock_proto(_tcp_based), do: :tcp

  defp parse_addr(addr) do
    case SIP.NetUtils.parse_address(addr) do
      {:ok, ip} -> ip
      _ -> abort("--listen : adresse IP invalide #{inspect(addr)}", 2)
    end
  end

  # Apply --local-port / --local-addr to the application env (read by the UDP
  # transport when it binds its socket).
  defp apply_local_udp_opts(opts) do
    if port = opts[:local_port], do: Application.put_env(:elixip2, :udp_local_port, port)

    case opts[:local_addr] do
      nil -> :ok
      addr -> Application.put_env(:elixip2, :udp_local_addr, parse_addr(addr))
    end
  end

  # X.509 certificate and key used by the TLS and WSS listeners (they share both).
  #
  # The transports read them from the :elixip2 application env, which a standalone
  # escript has no way to write: config/config.exs is baked in at build time and
  # config/runtime.exs is never evaluated (and now holds kelixip's :prod settings
  # only). Telling a tester to "set tls_certfile in config/runtime.exs" — as the help
  # and the guide did — could not work. `ELIXIPP_TLS_CERT` / `ELIXIPP_TLS_KEY` are
  # honoured too, for a run driven from a script or a systemd unit.
  defp apply_tls_opts(opts) do
    cert = opts[:tls_cert] || System.get_env("ELIXIPP_TLS_CERT")
    key = opts[:tls_key] || System.get_env("ELIXIPP_TLS_KEY")

    # One without the other is a mistake worth catching now rather than as an
    # unexplained handshake failure on the first inbound connection.
    cond do
      cert && !key ->
        abort("--tls-cert donné sans --tls-key : les deux sont requis.", 2)

      key && !cert ->
        abort("--tls-key donné sans --tls-cert : les deux sont requis.", 2)

      cert && key ->
        Application.put_env(:elixip2, :tls_certfile, check_readable!(cert, "--tls-cert"))
        Application.put_env(:elixip2, :tls_keyfile, check_readable!(key, "--tls-key"))

      true ->
        :ok
    end
  end

  # Fail now, with the path and the option name, rather than inside a TLS handshake.
  defp check_readable!(path, opt) do
    case File.stat(path) do
      {:ok, %File.Stat{type: :regular}} ->
        path

      {:ok, _other} ->
        abort("#{opt} : #{path} n'est pas un fichier.", 2)

      {:error, reason} ->
        abort("#{opt} : #{path} illisible (#{:file.format_error(reason)}).", 2)
    end
  end

  # Draw a random free local port (>= 5000) for the given socket protocol, or
  # abort when none can be found.
  defp random_free_port(sock_proto) do
    case SIP.NetUtils.pick_free_port(sock_proto) do
      {:ok, port} ->
        port

      {:error, :nofreeport} ->
        abort("Impossible de trouver un port #{sock_proto} local libre (>= 5000)", 2)
    end
  end

  defp parse_proto(proto) do
    case String.downcase(proto) do
      p when p in ["udp", "tcp", "tls", "wss"] -> String.to_atom(p)
      _ -> abort("--listen : protocole inconnu #{inspect(proto)} (udp|tcp|tls|wss)", 2)
    end
  end

  defp parse_port(port) do
    case Integer.parse(port) do
      {n, ""} when n > 0 and n <= 65535 -> n
      _ -> abort("--listen : port invalide #{inspect(port)}", 2)
    end
  end

  # Start the configured listeners. UDP, TCP, TLS, and WSS are all wired.
  # UDP reuses the bidirectional SIP.Transport.UDP instance.
  defp start_listeners(listeners) do
    Enum.map(listeners, fn
      {:udp, addr, port} = l ->
        case GenServer.start(SIP.Transport.UDP, {addr, port}) do
          {:ok, _pid} -> {l, :ok}
          {:error, reason} -> {l, {:error, reason}}
        end

      {:tcp, addr, port} = l ->
        case SIP.Transport.TCPListener.start({addr, port}) do
          {:ok, _pid} -> {l, :ok}
          {:error, reason} -> {l, {:error, reason}}
        end

      {:tls, addr, port} = l ->
        case SIP.Transport.TLSListener.start({addr, port}) do
          {:ok, _pid} -> {l, :ok}
          {:error, reason} -> {l, {:error, reason}}
        end

      {:wss, addr, port} = l ->
        case SIP.Transport.WSSListener.start({addr, port}) do
          {:ok, _pid} -> {l, :ok}
          {:error, reason} -> {l, {:error, reason}}
        end
    end)
  end

  defp format_listeners(started) do
    started
    |> Enum.map(fn {{proto, addr, port}, status} ->
      "#{proto}:#{format_addr(addr)}:#{port} (#{inspect(status)})"
    end)
    |> Enum.join(", ")
  end

  defp format_addr(:all), do: "*"

  defp format_addr(addr) when is_tuple(addr) do
    case :inet.ntoa(addr) do
      {:error, _} -> inspect(addr)
      str -> to_string(str)
    end
  end

  defp format_addr(addr), do: to_string(addr)

  # Block the main process until the operator types 'q' (or stdin reaches EOF on a
  # non-interactive run, in which case we simply park forever).
  # When max_run is set, a background task polls RegistrarUAS and halts once all
  # started instances have completed.
  @spec server_loop(module(), non_neg_integer() | nil) :: no_return()
  defp server_loop(module, max_run) do
    if is_integer(max_run) do
      Task.start(fn -> max_run_watcher(max_run, module) end)
    end

    server_loop_io(module)
  end

  defp server_loop_io(module) do
    case IO.gets("") do
      :eof ->
        Process.sleep(:infinity)

      {:error, _} ->
        Process.sleep(:infinity)

      line when is_binary(line) ->
        if String.trim(line) == "q" do
          IO.puts("Arrêt propre en cours — attente des instances actives…")
          Elixip.ScenarioUAS.shutdown_all(:elixipp_graceful)
          drain_uas_instances()
          IO.puts("Serveur arrêté.")
          print_uas_summary(module)
          System.halt(0)
        else
          server_loop_io(module)
        end
    end
  end

  defp max_run_watcher(max_run, module) do
    Process.sleep(500)
    stats = Elixip.ScenarioUAS.stats()

    # Wait until all started instances have completed naturally.
    # RegistrarUAS already refuses new registrations once total_started >= max_run.
    if stats.total_started >= max_run and stats.active == 0 do
      IO.puts("\nMax-run #{max_run} atteint — arrêt du serveur.")
      print_uas_summary(module)
      System.halt(0)
    else
      max_run_watcher(max_run, module)
    end
  end

  # Load and validate the external JSON config, aborting with a clear message on
  # any error. Returns nil when no --config was given.
  defp load_config(nil), do: nil

  defp load_config(path) do
    SIP.Scenario.ExternalConfig.load!(path)
  rescue
    e -> abort(Exception.message(e), 2)
  end

  # ── Parallel / monitored execution ──────────────────────────────────────────

  # Resolve the call creation rate (calls/s). Values <= 0 or above @max_rate
  # are ignored and fall back to the default rate.
  @doc false
  # --log-sequence requires a single simultaneous call (--limit 1): one PlantUML
  # file is written per instance, which would interleave/clobber across parallel
  # calls. Returns :ok or {:error, message}.
  @spec validate_log_sequence(keyword(), integer()) :: :ok | {:error, String.t()}
  def validate_log_sequence(opts, limit) do
    if Keyword.get(opts, :log_sequence, false) and limit > 1 do
      {:error, "--log-sequence n'est utilisable qu'avec un seul appel simultané (--limit 1)"}
    else
      :ok
    end
  end

  @doc """
  Normalise the `--max-run` value: `0` means **no limit**, which the run loops
  express as `nil`.

  Without this, `--max-run 0` — documented as "walk through every account", and the
  only way to recycle slots indefinitely with an explicit flag — made
  `can_start?/1` compare `total_started < 0` and start nothing at all (a run
  reporting `Total : 0`).
  """
  @spec resolve_max_run(integer() | nil) :: pos_integer() | nil
  def resolve_max_run(0), do: nil
  def resolve_max_run(max_run), do: max_run

  defp resolve_rate(nil), do: @default_rate

  defp resolve_rate(rate) when rate > 0 and rate <= @max_rate, do: rate

  defp resolve_rate(rate) do
    IO.puts(
      :stderr,
      "--rate #{rate} ignoré (autorisé : 0 < rate <= #{@max_rate}), utilisation de #{@default_rate}"
    )

    @default_rate
  end

  defp run_parallel(module, limit, max_run, spawn_interval_ms, rate, monitor?, ext_config) do
    {:ok, _} = Application.ensure_all_started(:owl)
    {:ok, _} = SIP.Scenario.Monitor.start()
    SIP.Scenario.Runner.bootstrap_stack()

    # Keyboard control (q / Ctrl+D) needs an interactive terminal; the live table
    # additionally needs --monitor. On a piped/non-tty stdin we read nothing, so
    # an immediate EOF can't be mistaken for Ctrl+D.
    interactive? = match?({:ok, _}, :io.rows())
    live? = monitor? and interactive?
    raw? = setup_raw_terminal(live?)

    if live? do
      Owl.LiveScreen.add_block(:display,
        state: initial_block_state(),
        render: fn bs -> render_block(bs, limit, max_run) end
      )
    end

    state = %{
      module: module,
      ext_config: ext_config,
      limit: limit,
      max_run: max_run,
      rate: rate,
      spawn_interval_ms: spawn_interval_ms,
      # monotonic ms of the last spawn, nil before the first
      last_spawn: nil,
      monitor?: monitor?,
      live?: live?,
      raw?: raw?,
      # slot_id => {pid, mon_ref}
      slots: %{},
      total_started: 0,
      total_succeeded: 0,
      total_aborted: 0,
      total_failed: 0,
      scroll_offset: 0,
      # :none | :graceful
      shutdown: :none
    }

    if interactive?, do: start_input_reader(self())

    state =
      Enum.reduce(1..limit, state, fn slot_id, acc ->
        if can_start?(acc), do: spawn_slot(acc, slot_id), else: acc
      end)

    state = parallel_loop(state)

    cond do
      live? ->
        # The live block already holds the final table; flushing leaves one copy
        # on screen. Printing render_table_plain on top would duplicate it.
        Owl.LiveScreen.update(:display, block_state(state))
        Owl.LiveScreen.flush()
        restore_terminal(raw?)

      monitor? ->
        # --monitor without an interactive terminal (piped / CI): final snapshot.
        restore_terminal(raw?)
        IO.puts("")
        IO.puts(render_table_plain(state))

      true ->
        # No --monitor: run silently, no table at all.
        restore_terminal(raw?)
    end

    print_summary(state)
    System.halt(if state.total_failed > 0, do: 1, else: 0)
  end

  # ── Slot lifecycle ───────────────────────────────────────────────────────────

  defp spawn_slot(state, slot_id) do
    state = throttle(state)
    SIP.Scenario.Monitor.clear(slot_id)
    parent = self()

    # Pick the account on the monotonic spawn counter (not slot_id, which is
    # recycled): accounts cycle round-robin across successive runs. [] when no
    # --config, so run_instance behaves exactly as before.
    overrides = SIP.Scenario.ExternalConfig.overrides_for(state.ext_config, state.total_started)

    {pid, mon_ref} =
      spawn_monitor(fn ->
        Process.put(:scenario_slot_id, slot_id)
        result = SIP.Scenario.Runner.run_instance(state.module, config_overrides: overrides)
        send(parent, {:slot_done, slot_id, result})
      end)

    %{
      state
      | slots: Map.put(state.slots, slot_id, {pid, mon_ref}),
        total_started: state.total_started + 1
    }
  end

  # Enforce the minimum delay between two call creations (1000 / rate ms).
  # Sleeps only for the remaining time so an idle gap doesn't add latency.
  defp throttle(%{last_spawn: nil} = state) do
    %{state | last_spawn: System.monotonic_time(:millisecond)}
  end

  defp throttle(%{last_spawn: last, spawn_interval_ms: interval} = state) do
    wait = interval - (System.monotonic_time(:millisecond) - last)
    if wait > 0, do: Process.sleep(wait)
    %{state | last_spawn: System.monotonic_time(:millisecond)}
  end

  defp can_start?(state) do
    state.shutdown == :none and
      (state.max_run == nil or state.total_started < state.max_run)
  end

  defp maybe_spawn_next(state, freed_slot_id) do
    if can_start?(state), do: spawn_slot(state, freed_slot_id), else: state
  end

  # ── Main receive loop ────────────────────────────────────────────────────────

  defp parallel_loop(state) do
    if done?(state) do
      state
    else
      receive do
        {:slot_done, slot_id, result} ->
          state = handle_slot_done(state, slot_id, result)
          push_display(state)
          parallel_loop(state)

        {:DOWN, mon_ref, :process, _pid, reason} when reason != :normal ->
          state = handle_slot_crash(state, mon_ref, reason)
          push_display(state)
          parallel_loop(state)

        # Normal exit: already handled by :slot_done — ignore the :DOWN.
        {:DOWN, _mon_ref, :process, _pid, :normal} ->
          parallel_loop(state)

        :graceful_stop ->
          handle_graceful_stop(state)

        :force_quit ->
          handle_force_quit(state)

        :shutdown_deadline ->
          # Grace period elapsed after a graceful stop: hard-kill any leftover.
          Enum.each(state.slots, fn {_sid, {pid, _ref}} -> Process.exit(pid, :kill) end)
          parallel_loop(state)

        :arrow_up ->
          state = %{state | scroll_offset: max(0, state.scroll_offset - 1)}
          push_display(state)
          parallel_loop(state)

        :arrow_down ->
          state = scroll_down(state)
          push_display(state)
          parallel_loop(state)
      after
        200 ->
          push_display(state)
          parallel_loop(state)
      end
    end
  end

  # Done when all slots are empty AND we will never start new ones.
  defp done?(%{slots: slots} = state) do
    slots == %{} and (state.shutdown != :none or not can_start?(state))
  end

  defp handle_slot_done(state, slot_id, result) do
    state = %{state | slots: Map.delete(state.slots, slot_id)}

    state =
      case result do
        :ok -> %{state | total_succeeded: state.total_succeeded + 1}
        {:aborted, _} -> %{state | total_aborted: state.total_aborted + 1}
        {:error, _} -> %{state | total_failed: state.total_failed + 1}
      end

    maybe_spawn_next(state, slot_id)
  end

  defp handle_slot_crash(state, mon_ref, reason) do
    case Enum.find(state.slots, fn {_sid, {_pid, mref}} -> mref == mon_ref end) do
      {slot_id, _} ->
        Logger.warning("Slot #{slot_id} crashed: #{inspect(reason)}")

        state = %{
          state
          | slots: Map.delete(state.slots, slot_id),
            total_failed: state.total_failed + 1
        }

        maybe_spawn_next(state, slot_id)

      nil ->
        state
    end
  end

  # 'q' requests a graceful shutdown: stop starting new calls and wait for the
  # active ones. Immediate stop is Ctrl+D — SIGINT (Ctrl+C) cannot be trapped by
  # the Erlang runtime, so it is not used here.
  defp handle_graceful_stop(state) do
    case state.shutdown do
      :none ->
        IO.write(
          "\r\n[q] Arrêt propre — plus de nouveaux appels, demande d'arrêt aux actifs (Ctrl+D pour forcer).\r\n"
        )

        # Ask every active call to wind down cooperatively, and arm a deadline to
        # hard-kill any that ignores the request (e.g. stuck outside on_events).
        Enum.each(state.slots, fn {_sid, {pid, _ref}} ->
          send(pid, {:scenario_ctl, :shutdown, :elixipp_graceful})
        end)

        Process.send_after(self(), :shutdown_deadline, @shutdown_grace_ms)
        state = %{state | shutdown: :graceful}
        push_display(state)
        if done?(state), do: state, else: parallel_loop(state)

      _ ->
        # Already shutting down gracefully — nothing more to do.
        if done?(state), do: state, else: parallel_loop(state)
    end
  end

  # Ctrl+D (or EOF / Ctrl+C in raw mode): stop everything right now, whatever is
  # still in flight, and print the summary before halting.
  defp handle_force_quit(state) do
    IO.write("\r\n[Ctrl+D] Arrêt immédiat.\r\n")
    restore_terminal(state.raw?)
    print_summary(state)
    System.halt(1)
  end

  defp scroll_down(state) do
    max_scroll = max(0, state.limit - visible_rows())
    %{state | scroll_offset: min(max_scroll, state.scroll_offset + 1)}
  end

  # ── Display ──────────────────────────────────────────────────────────────────

  defp push_display(%{live?: true} = state) do
    Owl.LiveScreen.update(:display, block_state(state))
  end

  defp push_display(_state), do: :ok

  defp initial_block_state, do: {0, 0, 0, 0, 0, 0, :none}

  defp block_state(state) do
    {state.scroll_offset, map_size(state.slots), state.total_started, state.total_succeeded,
     state.total_aborted, state.total_failed, state.shutdown}
  end

  defp render_block({scroll, active, total, succ, aborted, fail, shutdown}, limit, max_run) do
    [
      render_counters(active, total, succ, aborted, fail, limit, max_run, shutdown),
      "\n",
      render_table(scroll, true)
    ]
  end

  defp render_table_plain(_state) do
    case SIP.Scenario.Monitor.calls() do
      [] ->
        "(aucun appel)"

      calls ->
        calls
        |> Enum.map(&display_row(&1, false))
        |> Owl.Table.new(border_style: :solid_rounded, sort_columns: &column_order/2)
        |> Owl.Data.to_chardata()
        |> IO.chardata_to_string()
    end
  end

  defp render_table(scroll, colorize?) do
    max_vis = visible_rows()
    calls = SIP.Scenario.Monitor.calls()
    total = length(calls)
    visible = Enum.slice(calls, scroll, max_vis)

    case visible do
      [] ->
        "(aucun appel actif)"

      rows ->
        table =
          rows
          |> Enum.map(&display_row(&1, colorize?))
          |> Owl.Table.new(border_style: :solid_rounded, sort_columns: &column_order/2)

        if total > max_vis do
          [table, "\n  ↑↓  lignes #{scroll + 1}–#{min(scroll + max_vis, total)}/#{total}"]
        else
          table
        end
    end
  end

  defp render_counters(active, total, succ, aborted, fail, limit, max_run, shutdown) do
    max_str = if max_run, do: "/#{max_run}", else: ""

    shutdown_hint =
      case shutdown do
        :none -> "  [q: arrêt propre | Ctrl+D: immédiat]"
        _ -> "  [Ctrl+D: arrêt immédiat]"
      end

    line =
      "  Actifs: #{active}/#{limit}" <>
        "  |  Succès: #{succ}" <>
        "  |  Interrompus: #{aborted}" <>
        "  |  Échecs: #{fail}" <>
        "  |  Total: #{total}#{max_str}" <>
        shutdown_hint

    Owl.Data.tag(line, :cyan)
  end

  defp print_summary(state) do
    IO.puts("══ Résumé ══════════════════")
    IO.puts("  Scénario : #{inspect(state.module)}")
    IO.puts("  Rate     : #{state.rate} appels/s")
    IO.puts("  Total    : #{state.total_started}")
    IO.puts("  Succès   : #{state.total_succeeded}")
    IO.puts("  Interrompus : #{state.total_aborted}")
    IO.puts("  Échecs   : #{state.total_failed}")
    IO.puts("════════════════════════════")
  end

  defp visible_rows do
    case :io.rows() do
      {:ok, rows} -> max(5, rows - @ui_overhead)
      _ -> 20
    end
  end

  # ── Input reader (q = graceful, Ctrl+D = immediate, arrow keys) ───────────────

  defp start_input_reader(parent) do
    spawn(fn -> input_loop(parent, :standard_io) end)
  end

  defp input_loop(parent, io) do
    case read_byte(io) do
      :eof ->
        # Ctrl+D (EOF in cooked mode) or a closed stdin → immediate stop. No loop:
        # we force-quit, and looping would spin on a persistently-closed stream.
        send(parent, :force_quit)

      <<4>> ->
        # Ctrl+D (EOT) in raw mode → immediate stop.
        send(parent, :force_quit)

      <<3>> ->
        # Ctrl+C in raw mode → immediate stop.
        send(parent, :force_quit)

      <<c>> when c in [?q, ?Q] ->
        # 'q' → graceful shutdown (no new calls, wait for the active ones).
        send(parent, :graceful_stop)
        input_loop(parent, io)

      <<27>> ->
        # ESC prefix: read the rest of the ANSI sequence
        case {read_byte(io), read_byte(io)} do
          {<<"[">>, <<"A">>} -> send(parent, :arrow_up)
          {<<"[">>, <<"B">>} -> send(parent, :arrow_down)
          _ -> :ok
        end

        input_loop(parent, io)

      _ ->
        input_loop(parent, io)
    end
  end

  defp read_byte(io) do
    case :file.read(io, 1) do
      {:ok, byte} -> byte
      :eof -> :eof
      {:error, _} -> :eof
    end
  end

  # ── Raw terminal setup / teardown ────────────────────────────────────────────

  # Redirect from /dev/tty: System.cmd gives the spawned stty its own stdin pipe,
  # not our terminal, so a bare `stty raw` is a no-op and Ctrl+D keeps arriving
  # as EOF instead of byte 4. `</dev/tty` makes stty act on the real terminal.
  defp setup_raw_terminal(true) do
    case System.cmd("sh", ["-c", "stty raw -echo </dev/tty"], stderr_to_stdout: true) do
      {_, 0} -> true
      _ -> false
    end
  end

  defp setup_raw_terminal(false), do: false

  defp restore_terminal(true),
    do: System.cmd("sh", ["-c", "stty sane </dev/tty"], stderr_to_stdout: true)

  defp restore_terminal(false), do: :ok

  # ── Row rendering ─────────────────────────────────────────────────────────────

  defp display_row(call, colorize?) do
    Map.new(@columns, fn {header, key, width} ->
      {header, cell(call, key, width, colorize?)}
    end)
  end

  # Indent a sub-FSM's name under its parent scenario row.
  defp scenario_cell(call) do
    case Map.get(call, :depth, 0) do
      0 -> call.scenario
      depth -> String.duplicate("  ", depth - 1) <> "└ " <> call.scenario
    end
  end

  defp cell(call, :command, width, true),
    do: Owl.Data.tag(fit(call[:command], width), color_for(call[:command_type]))

  defp cell(call, :event, width, true),
    do: Owl.Data.tag(fit(call[:event], width), color_for(call[:event_type]))

  defp cell(call, :state, width, true) do
    case state_color(call[:state]) do
      nil -> fit_state(call[:state], width)
      color -> Owl.Data.tag(fit_state(call[:state], width), color)
    end
  end

  defp cell(call, :scenario, width, _colorize?), do: fit(scenario_cell(call), width)

  defp cell(call, key, width, _colorize?), do: fit(Map.get(call, key, ""), width)

  defp state_color("succeeded"), do: :green
  defp state_color("failed"), do: :red
  defp state_color(_), do: nil

  defp color_for(:sip), do: :light_green
  defp color_for(:media), do: IO.ANSI.color(214)
  defp color_for(_), do: :light_blue

  # A service building block reports its states qualified (`MyApp.Cancelling/waiting`),
  # so the state cell is the one place a value regularly overflows. When it does,
  # the HEAD goes rather than the tail: the state name is what says where the call
  # is, and the block stays recognisable from its last segments.
  @doc false
  # Public for the test: the arithmetic is one character away from cutting the
  # state name it exists to preserve.
  def fit_state(value, width) do
    s = to_string(value)

    if String.contains?(s, "/") and String.length(s) > width do
      "…" <> String.slice(s, -(width - 1)..-1//1)
    else
      fit(s, width)
    end
  end

  defp fit(value, width) do
    s = to_string(value)

    if String.length(s) > width do
      String.slice(s, 0, width - 1) <> "…"
    else
      String.pad_trailing(s, width)
    end
  end

  defp column_order(a, b), do: column_rank(a) <= column_rank(b)

  defp column_rank(header) do
    Enum.find_index(@columns, fn {h, _key, _width} -> h == header end) || length(@columns)
  end

  # ── Module resolution ─────────────────────────────────────────────────────────

  defp resolve_module(arg) do
    if String.ends_with?(arg, ".exs") do
      # The path is the tester's: taken as given, relative to the current directory.
      # (A `spawn_fsm` inside a scenario is the one exception — it names a file next to
      # the scenario that declares it.)
      unless File.exists?(arg),
        do: abort("Scénario introuvable : #{Path.expand(arg)}", 2)

      SIP.Scenario.Loader.load_file!(arg)
    else
      SIP.Scenario.Loader.load_module!(arg)
    end
  end

  # ── Logging setup ─────────────────────────────────────────────────────────────

  defp setup_logging(log_file, log_level) do
    _ = Application.ensure_all_started(:logger)
    _ = Application.ensure_all_started(:logger_file_backend)

    log_file = log_file || @default_log_file
    file_level = parse_level(log_level)

    Logger.configure(level: file_level)

    # config/config.exs is baked into the escript, and it declares its own file
    # sink ({LoggerFileBackend, :file_log} → elixip.log). Left in place, every line
    # lands in a second file the tool never mentions, at a level --log-level does
    # not control. elixipp owns its file logging (--log-file / --log-level), so
    # drop that backend before installing ours.
    _ = Logger.remove_backend({LoggerFileBackend, :file_log})

    backend = {LoggerFileBackend, :elixipp_log}
    Logger.add_backend(backend)

    Logger.configure_backend(backend,
      path: log_file,
      level: file_level,
      format: "$time [$level] $message\n",
      metadata: [:module, :pid]
    )

    quiet_console()
    :ok
  end

  defp quiet_console do
    try do
      Logger.configure_backend(:console, level: :warning)
    catch
      _, _ -> :ok
    end

    try do
      :logger.set_handler_config(:default, :level, :warning)
    catch
      _, _ -> :ok
    end

    :ok
  end

  defp parse_level(nil), do: @default_log_level

  defp parse_level(value) do
    case String.downcase(value) do
      "debug" ->
        :debug

      "info" ->
        :info

      "warn" ->
        :warning

      "warning" ->
        :warning

      "error" ->
        :error

      other ->
        IO.puts(:stderr, "Unknown --log-level #{inspect(other)}, using #{@default_log_level}")
        @default_log_level
    end
  end

  defp abort(message, code) do
    IO.puts(:stderr, message)
    System.halt(code)
  end

  defp print_help do
    IO.puts("""
    elixipp — outil de test de scénarios SIP

    USAGE
      elixipp [OPTIONS] <scenario.exs | NomDeModule>

    EXEMPLES
      Le chemin du scénario est celui que vous donnez, relatif au répertoire courant.
      Les scénarios d'exemple du dépôt sont dans apps/elixip2/scenarios/.

      elixipp mon_scenario.exs                    # depuis un fichier
      elixipp UAC.Invite                          # scénario intégré (sans fichier)
      elixipp UAC.Register                        # scénario intégré (sans fichier)
      elixipp -m mon_scenario.exs                 # affichage live d'un appel
      elixipp -l 5 mon_scenario.exs               # 5 appels en continu
      elixipp -l 5 --max-run 100 mon_scenario.exs # 5 simultanés, 100 au total
      elixipp -l 5 --rate 20 mon_scenario.exs     # 5 simultanés, 20 appels/s max
      elixipp -c comptes.json uac_register.exs    # paramétré par un fichier JSON
      elixipp -c comptes.json --max-run 0 uac_register.exs   # balaye tous les comptes
      elixipp --listen udp:5060 uas_register.exs  # serveur registrar UAS (UDP)
      elixipp -l 200 --listen udp:5060 uas_register.exs      # serveur, 200 abonnés max
      elixipp --listen tls:5061 --tls-cert cert.pem --tls-key key.pem uas_register.exs
      elixipp --listen wss:5065 --tls-cert cert.pem --tls-key key.pem uas_register.exs
      elixipp --listen udp:5060 uas_invite.exs    # serveur d'appels (répond aux INVITE)
      elixipp -l 20 --listen udp:5060 uas_invite.exs         # 20 appels simultanés max

    OPTIONS
      -m, --monitor      Affiche un tableau live des appels en cours.
      -l, --limit N      Lance N appels simultanés (mode client).
                         Sans --max-run, les slots sont recyclés indéfiniment.
                         En mode serveur : nombre d'instances simultanées
                         acceptées, au-delà les requêtes reçoivent un 503.
                         Défaut : 1 en client, #{@default_server_limit} en serveur.
      --max-run N        Arrête après N exécutions au total.
                         0 = illimité (les slots sont recyclés sans fin).
      -c, --config FILE  Fichier JSON paramétrant le scénario : entête (domain,
                         proxyuri, proxyusesrv, optionkeepaliveperiod,
                         mediaserver) + N comptes {username, password, domain}.
                         Surcharge le bloc config du scénario. Les comptes sont
                         tirés en round-robin sur les exécutions (avec --limit 1,
                         utilisez --max-run pour tous les parcourir).
                         En mode serveur, l'entête et le PREMIER compte sont
                         partagés par toutes les instances : c'est ainsi qu'on
                         donne au registrar le mot de passe à vérifier.
      --rate N           Nombre d'appels créés par seconde (défaut : #{@default_rate}, max : #{@max_rate}).
                         Espace la création de chaque nouvel appel de 1000/N ms.
                         Les valeurs > 100 sont ignorées (retour au défaut).
      --listen PROTO:PORT  (mode serveur) Écoute les requêtes entrantes sur ce
      --listen PROTO:ADDR:PORT  protocole/port (ADDR optionnel pour fixer l'IP
                         locale annoncée). Répétable. Protocoles : udp, tcp,
                         tls, wss. TLS et WSS nécessitent un certificat, voir
                         --tls-cert / --tls-key.
                         Sans PORT (--listen udp), un port libre est tiré au
                         hasard (>= 5000). Défaut si absent : udp:5060.
      --tls-cert FILE    Certificat X.509 (PEM) présenté par les listeners TLS
      --tls-key FILE     et WSS, et sa clé privée. Les deux vont ensemble.
                         Variables d'environnement équivalentes :
                         ELIXIPP_TLS_CERT / ELIXIPP_TLS_KEY.
                         Défaut : certs/certificate.pem et certs/private_key.pem
                         (relatifs au répertoire courant).
      --local-port PORT  (mode client) Port UDP local à utiliser pour émettre.
                         Sans cette option, un port UDP libre est tiré au hasard
                         (>= 5000), ce qui permet de lancer un UAC sur une machine
                         qui héberge déjà un UAS sur 5060.
      --local-addr ADDR  (mode client) IP locale annoncée dans Via/Contact.
      --log-file PATH    Chemin du fichier de log (défaut : elixipp.log).
      --log-level LEVEL  Niveau : debug | info | warning | error (défaut : info).
      --log-sequence     Écrit un diagramme de séquence PlantUML par instance de
                         scénario (<scenario>_<pid>.puml). Réservé à une seule
                         instance simultanée (refusé avec --limit > 1, en mode
                         client comme serveur). Équivaut à activer le flag debug
                         du scénario (ctx_set(:debug, true)).
      -h, --help         Affiche cette aide.

    Sans --limit ni --max-run, comportement équivalent à --limit 1 --max-run 1
    (un seul appel, une seule exécution).

    SCÉNARIOS
      L'argument est soit un chemin vers un fichier .exs, soit le nom d'un
      scénario intégré (compilé dans l'exécutable) : UAC.Invite, UAC.Register.
      Les scénarios intégrés ne nécessitent aucun fichier sur la machine.
      Dans un scénario, un sous-scénario (spawn_fsm "autre.exs") est cherché à
      côté du fichier qui le déclare, pas dans le répertoire courant.

    TOUCHES (mode live)
      q                  Arrêt propre : plus de nouveaux appels, attend les actifs.
      Ctrl+D             Arrêt immédiat (affiche le résumé puis quitte).
      ↑ / ↓              Défile le tableau quand il dépasse la hauteur du terminal.

    Code de sortie : 0 si aucun échec, 1 sinon.
    """)

    System.halt(0)
  end
end
