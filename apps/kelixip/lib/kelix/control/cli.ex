defmodule Kelix.Control.CLI do
  @moduledoc """
  `kelictl` — the thin CLI frontal onto `Kelix.Control` (design §10.2). It runs no
  SIP stack: it resolves the running node + cookie and does
  `:rpc.call(node, Kelix.Control, fun, args)`, then renders the result as text.

  Shipped inside the `kelixip` release and driven by the `bin/kelictl` overlay,
  which forwards `argv` to `main/1`. Business logic lives in `Kelix.Control`, so
  parity with the REST frontal (P8) is automatic — a command is one `Kelix.Control`
  function plus a thin parse/render clause here.

  `run/2` (parse → dispatch → `{exit_code, text}`) is the testable core; `main/1`
  prints the text and halts. Dispatch is local when the target is this node (so
  tests need no distribution) and `:rpc.call` otherwise.
  """

  @default_node "kelixip@127.0.0.1"

  @doc "Release entry point: run `argv`, print the output, halt with the exit code."
  @spec main([String.t()]) :: no_return
  def main(argv) do
    {code, output} = run(argv)
    IO.puts(output)
    System.halt(code)
  end

  @doc """
  Entry point for the `bin/kelictl` overlay, which runs `kelixip rpc` so this
  executes **inside** the live node: split the arg string, run against the local
  node, and print the text. (`rpc` redirects IO back to the operator's terminal.)
  """
  @spec rpc_main(String.t()) :: :ok
  def rpc_main(arg_string) when is_binary(arg_string) do
    {_code, output} = run(OptionParser.split(arg_string), node())
    IO.puts(output)
  end

  @doc "Parse + dispatch `argv` against `node`, returning `{exit_code, text}`."
  @spec run([String.t()], node) :: {non_neg_integer, String.t()}
  def run(argv, target \\ resolve_node()) do
    case parse(argv) do
      {:ok, tag, fun, args} -> render(tag, call(target, fun, args))
      {:error, msg} -> {2, msg}
    end
  end

  # ── parsing (argv → {tag, Kelix.Control fun, args}) ──────────────────────────

  defp parse(["status"]), do: {:ok, :status, :status, []}
  defp parse(["monitor"]), do: {:ok, :monitor, :monitor, []}
  defp parse(["registration", "list"]), do: {:ok, :regs, :registrations, []}
  defp parse(["registration", "list", domain]), do: {:ok, :reg_domain, :registrations, [domain]}

  defp parse(["registration", "show", domain, aor]),
    do: {:ok, :registration, :registration, [domain, aor]}

  defp parse(["registration", "remove", domain, aor]),
    do: {:ok, :ok, :unregister, [domain, aor, :all]}

  defp parse(["registration", "remove", domain, aor, contact]),
    do: {:ok, :ok, :unregister, [domain, aor, contact]}

  defp parse(["registration" | _]), do: {:error, usage_registration()}

  defp parse(["domain", "list"]), do: {:ok, :domains, :domains, []}
  defp parse(["domain", "show", name]), do: {:ok, :domain, :domain, [name]}
  defp parse(["domain", "reload-all"]), do: {:ok, :ok, :reload_domains, []}
  # `domain` is a core noun, so it never reaches the module dispatch below: a
  # mistyped sub-command gets the domain usage rather than "unknown module".
  defp parse(["domain" | _]), do: {:error, usage_domain()}

  defp parse(["mediaserver", "list"]), do: {:ok, :mediaservers, :mediaservers, []}
  defp parse(["mediaserver", "show", name]), do: {:ok, :mediaserver, :mediaserver, [name]}

  defp parse(["mediaserver", onoff, name]) when onoff in ["enable", "disable"],
    do: {:ok, :ok, :mediaserver_toggle, [name, onoff == "enable"]}

  # `mediaserver` is a core noun too — and the pool entry it names is not the `mcu`
  # module, which owns its own command namespace (`kelictl mcu conference.list`).
  defp parse(["mediaserver" | _]), do: {:error, usage_mediaserver()}

  defp parse(["module", "list"]), do: {:ok, :module_list, :module_commands, []}
  defp parse(["module", "reload", name]), do: {:ok, :ok, :module_reload, [name]}
  # `module` is a core noun, like `domain` above: a mistyped sub-command gets this
  # usage instead of being taken for a module named "module".
  defp parse(["module" | _]), do: {:error, usage_module()}

  defp parse(["log-level", lvl]), do: {:ok, :ok, :set_log_level, [lvl]}
  defp parse(["graceful-shutdown"]), do: {:ok, :ok, :graceful_shutdown, []}
  defp parse(["drain"]), do: {:ok, :ok, :drain, []}
  defp parse(["undrain"]), do: {:ok, :ok, :undrain, []}

  defp parse(["stop", id]) do
    case Integer.parse(id) do
      {n, ""} -> {:ok, :ok, :shutdown_scenario, [n]}
      _ -> {:error, "stop: <id> must be an integer"}
    end
  end

  defp parse(["reload-script" | rest]) do
    {notify?, names} = pop_flag(rest, "--notify")

    if names == [],
      do: {:error, "reload-script: needs at least one script name"},
      else: {:ok, :map, :reload_script, [names, notify?]}
  end

  # `<module> help` is answered by the CLI from Kelix.Control.Registry (FW-5,
  # `docs/design/mcu_module.md` §8.3.6): a module declares its command set once and
  # gets its usage for free — nothing to write, nothing to keep in sync. `help` is
  # therefore reserved on a module namespace; a module that declares a command of
  # that name keeps it reachable over REST.
  defp parse([module, "help"]), do: {:ok, {:module_help, module}, :module_commands, [module]}

  # module-contributed command: <module> <cmd> [args…]
  defp parse([module, cmd | rest]),
    do: {:ok, {:module, module}, :module_command, [module, cmd, %{"args" => rest}]}

  defp parse(_), do: {:error, usage()}

  defp pop_flag(args, flag), do: {flag in args, Enum.reject(args, &(&1 == flag))}

  # ── dispatch (local when targeting this node, else RPC) ──────────────────────

  defp call(target, fun, args) do
    cond do
      target == node() -> apply(Kelix.Control, fun, args)
      true -> rpc(target, fun, args)
    end
  rescue
    e -> {:error, {:exception, Exception.message(e)}}
  end

  defp rpc(target, fun, args) do
    case :rpc.call(target, Kelix.Control, fun, args) do
      {:badrpc, reason} -> {:error, {:unreachable, reason}}
      other -> other
    end
  end

  # ── rendering ({tag, result} → {exit_code, text}) ────────────────────────────

  # `<module> <cmd>` is also where an unrecognised built-in lands (a mistyped or
  # over-qualified command such as `kelictl domains graceful-shutdown`), so name
  # what was not found and show the usage rather than a bare :unknown_module.
  defp render({:module, name}, {:error, :unknown_module}),
    do: {1, "error: \"#{name}\" is neither a kelictl command nor a loaded module\n\n" <> usage()}

  defp render({:module_help, name}, {:error, :unknown_module}),
    do: {1, "error: no module named \"#{name}\" is loaded (kelictl module list)"}

  defp render(:domain, {:error, :not_found}), do: {1, "no such domain"}
  defp render(:reg_domain, {:error, :not_found}), do: {1, "no such domain"}
  defp render(:registration, {:error, :not_found}), do: {1, "no such registration"}
  defp render(:mediaserver, {:error, :not_found}), do: {1, "no such media server"}

  defp render(_tag, {:error, reason}), do: {1, "error: #{inspect(reason)}"}

  defp render(:status, %{} = s) do
    lines =
      [
        "node:            #{s.node}",
        "uptime:          #{format_uptime(s.uptime_ms)}",
        "active calls:    #{Map.get(s.instances, :active, 0)}",
        "listeners:       #{format_listeners(Map.get(s, :listeners, []))}",
        "domains version: #{s.domains_version}",
        "modules:         #{Enum.join(s.modules, ", ")}",
        "media pool:      #{format_pool(s.media_pool)}"
      ] ++ module_status_lines(Map.get(s, :module_status, %{}))

    {0, Enum.join(lines, "\n")}
  end

  defp render(:monitor, []), do: {0, "no scenario in progress"}

  defp render(:monitor, rows) when is_list(rows) do
    {0,
     table(
       ["id", "domain", "function", "account", "state", "event", "command"],
       rows,
       &[
         to_string(&1.id),
         &1.domain,
         to_string(&1.function),
         dash(&1.account),
         dash(&1.state),
         dash(&1.event),
         dash(&1.command)
       ]
     )}
  end

  defp render(:regs, []), do: {0, "no domain served"}

  # One section per served domain, in domains.toml order: registrations are keyed
  # per domain in the store, and a domain with none is still worth a line — "served,
  # empty" and "not served" are what the operator is trying to tell apart.
  defp render(:regs, entries) when is_list(entries),
    do: {0, Enum.map_join(entries, "\n\n", &domain_registrations_block/1)}

  defp render(:reg_domain, {:ok, entry}), do: {0, domain_registrations_block(entry)}

  # One numbered paragraph per binding. Absent fields are omitted rather than
  # dashed: `instance` / `reg-id` / `methods` are what a given handset chose to
  # send, and a column of dashes says nothing.
  defp render(:registration, {:ok, row}), do: {0, registration_block(row)}

  defp render(:domains, []), do: {0, "no domain served"}

  defp render(:domains, rows) when is_list(rows) do
    {0,
     table(
       ["domain", "aliases", "functions", "calls", "regs", "max"],
       rows,
       &[
         &1.name,
         dash(Enum.join(&1.aliases, ", ")),
         dash(Enum.join(&1.functions, ", ")),
         to_string(&1.active_calls),
         to_string(&1.registrations),
         if(&1.max_calls, do: to_string(&1.max_calls), else: "-")
       ]
     )}
  end

  defp render(:domain, {:ok, d}) do
    lines =
      [
        "domain:        #{d.name}",
        "aliases:       #{dash(Enum.join(d.aliases, ", "))}",
        "max calls:     #{if d.max_calls, do: d.max_calls, else: "unlimited"}",
        "active calls:  #{d.active_calls}",
        "registrations: #{d.registrations}",
        "registrar:     #{format_function(d.registrar)}",
        "presence:      #{format_function(d.presence)}",
        if(d.dial_plan == [], do: "dial-plan:     (disabled)", else: "dial-plan:")
      ] ++ format_dial_plan(d.dial_plan)

    {0, Enum.join(lines, "\n")}
  end

  defp render(:mediaservers, []), do: {0, "no media server in the pool"}

  defp render(:mediaservers, rows) when is_list(rows) do
    {0,
     table(
       ["server", "adapter", "url", "enabled", "health", "modules"],
       rows,
       &[
         &1.name,
         to_string(&1.module),
         &1.url,
         if(&1.enabled, do: "on", else: "off"),
         if(&1.healthy, do: "up", else: "down"),
         format_module_views(&1.modules)
       ]
     )}
  end

  defp render(:mediaserver, {:ok, m}) do
    lines =
      [
        "media server: #{m.name}",
        "adapter:      #{m.module}",
        "url:          #{m.url}",
        "enabled:      #{if m.enabled, do: "on", else: "off"}",
        # Named for what it is: this is the pool's own probe of the adapter channel,
        # not the health a conference rides — the module lines below carry that one.
        "health:       #{if m.healthy, do: "up", else: "down"} (pool probe)"
      ] ++ module_view_lines(m.modules)

    {0, Enum.join(lines, "\n")}
  end

  defp render(:module_list, modules) when modules == %{}, do: {0, "no module loaded"}

  defp render(:module_list, modules) when is_map(modules) do
    rows = Enum.sort_by(modules, &elem(&1, 0))

    {0,
     table(
       ["module", "version", "implementation", "commands", "exports"],
       rows,
       fn {name, m} ->
         [
           name,
           dash(m.version),
           inspect(m.module),
           to_string(length(m.commands)),
           to_string(length(m.exports))
         ]
       end
     ) <> "\n\nkelictl <module> help lists what a module contributes"}
  end

  defp render({:module_help, name}, {:ok, m}) do
    {0, Enum.join(module_help_lines(name, m), "\n")}
  end

  defp render(:map, result) when is_map(result) do
    {exit_map(result), Enum.map_join(result, "\n", fn {k, v} -> "#{k}: #{fmt(v)}" end)}
  end

  defp render({:module, _name}, {:ok, value}), do: {0, fmt(value)}
  defp render(:ok, :ok), do: {0, "ok"}
  defp render(:ok, :notfound), do: {1, "not found"}
  defp render(_tag, other), do: {0, fmt(other)}

  # The whole surface of one module, rendered from its own declaration: the commands
  # an operator can run (with their REST route, so the two frontals are visibly the
  # same thing) and the facades a script imports.
  defp module_help_lines(name, m) do
    header = "#{name}#{if m.version, do: " #{m.version}", else: ""} (#{inspect(m.module)})"

    commands =
      case m.commands do
        [] ->
          ["", "commands: none — this module contributes no control command"]

        cmds ->
          width = cmds |> Enum.map(&String.length(&1.name)) |> Enum.max()
          ["", "commands:"] ++ Enum.flat_map(cmds, &command_lines(&1, name, width))
      end

    exports =
      case m.exports do
        [] -> []
        list -> ["", "facades (import #{inspect(m.module)}):", "  " <> format_exports(list)]
      end

    [header] ++ commands ++ exports
  end

  # `*` marks a required argument — the CLI form is `name=value` tokens, so the arg
  # names are the whole calling convention. The REST route is shown next to it because
  # both frontals come from this one declaration (§10).
  defp command_lines(cmd, module_name, width) do
    [
      "  #{String.pad_trailing(cmd.name, width)}  " <>
        "[#{format_methods(cmd)} /modules/#{module_name}#{cmd.path}]",
      "      args: #{format_command_args(cmd)}",
      "      #{cmd.help}"
    ]
  end

  defp format_methods(cmd),
    do: Enum.map_join(cmd.methods, "|", &String.upcase(to_string(&1)))

  defp format_command_args(%{args: []}), do: "(none)"

  defp format_command_args(%{args: args}) do
    Enum.map_join(args, " ", fn a ->
      if Map.get(a, :required, false), do: "#{a.name}*", else: a.name
    end)
  end

  defp format_exports(exports) do
    Enum.map_join(exports, ", ", fn
      {fun, arity} -> "#{fun}/#{arity}"
      other -> inspect(other)
    end)
  end

  # A function block: absent = the function is not served on this domain. Present,
  # it is the script plus whatever tuning the domain overrode.
  defp format_function(nil), do: "(disabled)"

  defp format_function(cfg) when is_map(cfg) do
    Enum.map_join(Enum.sort(cfg), " ", fn {k, v} -> "#{k}=#{v}" end)
  end

  # Numbered, because the dial-plan is first-match-wins: the position *is* the
  # semantics, and "which rule caught this call" is the usual question.
  defp format_dial_plan(rules) do
    patterns = Enum.map(rules, &(&1.pattern || "(default)"))
    width = patterns |> Enum.map(&String.length/1) |> Enum.max(fn -> 0 end)

    patterns
    |> Enum.zip(rules)
    |> Enum.with_index(1)
    |> Enum.map(fn {{pattern, r}, i} ->
      "  #{i}. #{String.pad_trailing(pattern, width)} -> #{r.script}"
    end)
  end

  defp domain_registrations_block(%{domain: domain, registrations: []}),
    do: "#{domain}\n  (no registration)"

  defp domain_registrations_block(%{domain: domain, registrations: rows}) do
    body =
      table(
        ["aor", "contacts", "expires", "bindings"],
        rows,
        &[
          &1.aor,
          to_string(length(&1.contacts)),
          # the soonest, i.e. when this AOR starts losing a way to be reached
          dash(format_expires(soonest_expiry(&1.contacts))),
          Enum.map_join(&1.contacts, ", ", fn c -> c.uri end)
        ]
      )

    domain <> "\n" <> indent(body)
  end

  defp indent(text), do: text |> String.split("\n") |> Enum.map_join("\n", &("  " <> &1))

  defp registration_block(row) do
    header = ["aor:          #{row.aor}@#{row.domain}", "contacts:     #{length(row.contacts)}"]

    Enum.join(header ++ Enum.flat_map(Enum.with_index(row.contacts, 1), &contact_lines/1), "\n")
  end

  defp contact_lines({c, i}) do
    ["  #{i}. #{c.uri}"] ++
      for {label, value} <- [
            {"expires", format_expiry(c)},
            {"source", c.source},
            {"transport", c.transport},
            {"instance", c.instance},
            {"reg-id", c.reg_id},
            {"methods", c.methods}
          ],
          value not in [nil, ""],
          do: "     " <> String.pad_trailing(label <> ":", 11) <> to_string(value)
  end

  # "in 5m40s (2026-08-02T12:34:56Z)": the remaining time is the operator question,
  # the absolute instant is what a log line will carry.
  defp format_expiry(%{expires_in: nil, expires_at: nil}), do: nil
  defp format_expiry(%{expires_in: nil, expires_at: at}), do: to_string(at)
  defp format_expiry(%{expires_in: 0}), do: "expired"

  defp format_expiry(%{expires_in: secs, expires_at: at}),
    do: "in #{format_expires(secs)}#{if at, do: " (#{at})", else: ""}"

  defp soonest_expiry([]), do: nil

  defp soonest_expiry(contacts) do
    contacts |> Enum.map(& &1.expires_in) |> Enum.reject(&is_nil/1) |> Enum.min(fn -> nil end)
  end

  defp format_expires(nil), do: nil
  defp format_expires(0), do: "expired"
  defp format_expires(s) when s < 3600, do: "#{div(s, 60)}m#{rem(s, 60)}s"
  defp format_expires(s), do: "#{div(s, 3600)}h#{rem(div(s, 60), 60)}m"

  # What a module driving this media server says about it. In the list only its
  # `status` fits a column (`mcu=up`); `show` prints the whole view, one line per
  # module. Rendered from whatever the module returned, so a new one needs no CLI
  # change.
  defp format_module_views(views) when views == %{}, do: "-"

  defp format_module_views(views) do
    Enum.map_join(Enum.sort(views), ", ", fn {name, view} ->
      case Map.get(view, :status) do
        nil -> to_string(name)
        status -> "#{name}=#{status}"
      end
    end)
  end

  defp module_view_lines(views) do
    for {name, view} <- Enum.sort(views),
        do: String.pad_trailing("#{name}:", 14) <> format_summary(view)
  end

  # One line per module that reports state of its own (`mcu: 2 conferences, …`).
  # Rendered from whatever the module returned, so a new module needs no CLI change.
  defp module_status_lines(status) when is_map(status) do
    for {name, summary} <- Enum.sort_by(status, &elem(&1, 0)) do
      String.pad_trailing("#{name}:", 17) <> format_summary(summary)
    end
  end

  defp module_status_lines(_status), do: []

  defp format_summary(summary) when is_map(summary) do
    Enum.map_join(summary, ", ", fn {k, v} -> "#{k} #{fmt(v)}" end)
  end

  defp format_summary(other), do: fmt(other)

  defp exit_map(result), do: if(Enum.all?(result, fn {_k, v} -> v == :ok end), do: 0, else: 1)

  defp fmt(:ok), do: "ok"
  defp fmt({:error, reason}), do: "error: #{inspect(reason)}"
  defp fmt(v) when is_binary(v), do: v
  defp fmt(v), do: inspect(v)

  # An empty FSM cell reads as a missing column; a dash reads as "nothing yet".
  defp dash(""), do: "-"
  defp dash(nil), do: "-"
  defp dash(v), do: to_string(v)

  # Column-aligned, because an unpadded 7-column FSM table is unreadable in a
  # terminal. Widths come from the content, so a narrow table stays narrow.
  defp table(headers, rows, to_cells) do
    cells = [headers | Enum.map(rows, to_cells)]

    widths =
      cells
      |> Enum.zip_with(fn column -> Enum.map(column, &String.length/1) |> Enum.max() end)

    cells
    |> Enum.map_join("\n", fn row ->
      row
      |> Enum.zip(widths)
      |> Enum.map_join("  ", fn {cell, w} -> String.pad_trailing(cell, w) end)
      |> String.trim_trailing()
    end)
  end

  defp format_uptime(ms) do
    s = div(ms, 1000)
    "#{div(s, 3600)}h#{rem(div(s, 60), 60)}m#{rem(s, 60)}s"
  end

  defp format_pool([]), do: "(empty)"

  defp format_pool(entries) do
    Enum.map_join(entries, ", ", fn e ->
      "#{e.name}=#{if e.enabled, do: "on", else: "off"}/#{if e.healthy, do: "up", else: "down"}"
    end)
  end

  defp format_listeners([]), do: "(none)"

  defp format_listeners(entries) do
    Enum.map_join(entries, ", ", fn l ->
      "#{l.proto}:#{l.addr}:#{l.port}#{if l.up, do: "", else: " (down)"}"
    end)
  end

  # ── node resolution ──────────────────────────────────────────────────────────

  defp resolve_node() do
    (System.get_env("KELIX_NODE") || @default_node) |> String.to_atom()
  end

  defp usage() do
    """
    usage: kelictl <command> [args]

      status                          uptime, counters, pool, node state
      monitor                         scenarios in progress
      registration list [domain]      registrations, per domain
      registration show <domain> <aor>  one AOR and its bindings, in detail
      registration remove <domain> <aor> [contact]  drop a registration
      domain list                     served domains + their properties
      domain show <domain>            one domain in detail (name or alias)
      domain reload-all               hot-reload domains.toml
      mediaserver list                the media-server pool + its state
      mediaserver show <name>         one media server in detail
      mediaserver enable|disable <name>  take a media server in/out of the pool
      stop <id>                       shut down one scenario
      reload-script [--notify] <name…>  reload scenario script(s)
      module list                     loaded modules, their commands and facades
      module reload <name>            reload a module's config
      log-level <lvl>                 set the runtime log level
      drain                           answer 503 to OPTIONS: leave the
                                      upstream rotation, keep serving
                                      what is already in flight
      undrain                         back in service (OPTIONS -> 200)
      graceful-shutdown               drain, let upstream notice, then stop
      <module> help                   the commands a module contributes
      <module> <cmd> [args…]          a module-contributed command
    """
  end

  defp usage_module(), do: "usage: kelictl module list | module reload <name>"

  defp usage_registration() do
    "usage: kelictl registration list [domain] | registration show <domain> <aor> | " <>
      "registration remove <domain> <aor> [contact]"
  end

  defp usage_domain(),
    do: "usage: kelictl domain list | domain show <domain> | domain reload-all"

  defp usage_mediaserver() do
    "usage: kelictl mediaserver list | mediaserver show <name> | " <>
      "mediaserver enable|disable <name>"
  end
end
