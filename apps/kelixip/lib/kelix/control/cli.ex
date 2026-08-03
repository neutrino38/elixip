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

  ## Exit codes

  | Code | Means |
  |---|---|
  | `0` | ok |
  | `1` | the command failed, unclassified |
  | `2` | usage, or an argument the command refused (a declared `400`) |
  | `3` | no such object (a declared `404`) |
  | `4` | conflict: it already exists, or is not empty (a declared `409`) |
  | `5` | unavailable: the node, the module or its backend did not answer (a declared `5xx`) |

  `3`/`4`/`5` come from the failing command's **own declaration** (`errors:` in its
  `describe_control/0` entry, read through `Kelix.Control.Route.error_status/2`), so
  the class an operator scripts against is the same one the REST frontal answers with
  — FW-5, `docs/design/mcu_module.md` §8.3.6.
  """

  @default_node "kelixip@127.0.0.1"

  @exit_not_found 3
  @exit_conflict 4
  @exit_unavailable 5

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
      # A module command's rendering may be declared by the module itself (the
      # `render:` hint, §8.3.6); resolving it needs the target node, so this one
      # cannot go through the pure render/2.
      {:ok, {:module, module, cmd}, fun, args} ->
        render_module(module, cmd, call(target, fun, args), target)

      {:ok, tag, fun, args} ->
        render(tag, call(target, fun, args))

      {:error, msg} ->
        {2, msg}
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
  defp parse([module, "help"]), do: {:ok, {:module_help, module, nil}, :module_commands, [module]}

  # `<module> help <cmd>` narrows it to one command, with its arguments' own help —
  # a module's full surface plus every vocabulary would be a screenful to scroll.
  defp parse([module, "help", cmd]),
    do: {:ok, {:module_help, module, cmd}, :module_commands, [module]}

  # module-contributed command: <module> <cmd> [args…]
  defp parse([module, cmd | rest]),
    do: {:ok, {:module, module, cmd}, :module_command, [module, cmd, %{"args" => rest}]}

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

  defp render({:module_help, name, _cmd}, {:error, :unknown_module}),
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

  defp render({:module_help, name, nil}, {:ok, m}) do
    {0, Enum.join(module_help_lines(name, m), "\n")}
  end

  defp render({:module_help, name, cmd}, {:ok, m}) do
    case Enum.find(m.commands, &(&1.name == cmd)) do
      nil ->
        {2,
         "error: module \"#{name}\" declares no command \"#{cmd}\" " <>
           "(kelictl #{name} help lists them)"}

      command ->
        {0, Enum.join(command_lines(command, name, String.length(command.name)), "\n")}
    end
  end

  defp render(:map, result) when is_map(result) do
    {exit_map(result), Enum.map_join(result, "\n", fn {k, v} -> "#{k}: #{fmt(v)}" end)}
  end

  defp render(:ok, :ok), do: {0, "ok"}
  defp render(:ok, :notfound), do: {1, "not found"}
  defp render(_tag, other), do: {0, fmt(other)}

  # ── module-command rendering (declaration-driven, design §8.3.6) ──────────────

  # `<module> <cmd>` is also where an unrecognised built-in lands (a mistyped or
  # over-qualified command such as `kelictl domains graceful-shutdown`), so name
  # what was not found and show the usage rather than a bare :unknown_module.
  defp render_module(name, _cmd, {:error, :unknown_module}, _target),
    do: {1, "error: \"#{name}\" is neither a kelictl command nor a loaded module\n\n" <> usage()}

  # The CLI's own failures, not a module verdict: the node did not answer, or the call
  # raised inside it. Nothing the operator's arguments can fix, and asking the registry
  # to classify it would fail the same way — so they are `unavailable` outright.
  defp render_module(_name, _cmd, {:error, {kind, _detail} = reason}, _target)
       when kind in [:unreachable, :exception],
       do: {@exit_unavailable, "error: #{inspect(reason)}"}

  # A failed command exits with the class the module **declared** for that reason
  # (FW-5): a provisioning script can tell "fix the command" from "it is not there"
  # from "it already exists" from "try again later" without parsing the message, and
  # the class is the same one the REST frontal answers with. One extra call, on the
  # failure path only.
  defp render_module(name, cmd, {:error, reason}, target),
    do:
      {exit_class(call(target, :command_error_status, [name, cmd, reason])),
       "error: #{inspect(reason)}"}

  # A command may declare what its result should look like (`render:` in its
  # describe_control/0 entry): a table with named columns for a list, a labelled
  # detail view for a map. No declaration → the raw term, as before. The hint comes
  # from the target's registry, so the CLI stays module-agnostic — it formats what
  # the module declared, it never interprets.
  defp render_module(name, cmd, {:ok, value}, target),
    do: {0, render_hinted(value, render_hint(target, name, cmd))}

  defp render_module(_name, _cmd, other, _target), do: {0, fmt(other)}

  # The declared status, classified into the exit codes kelictl already uses. `2` keeps
  # its meaning — a usage error and a refused argument are the same thing to whoever
  # has to fix the command line — and each of the others is a case an operator acts on
  # differently. A status no class claims stays the generic `1`.
  defp exit_class(status) when status in 200..299, do: 0
  defp exit_class(status) when status in [400, 422], do: 2
  defp exit_class(404), do: @exit_not_found
  defp exit_class(409), do: @exit_conflict
  defp exit_class(status) when status in 500..599, do: @exit_unavailable
  defp exit_class(_status), do: 1

  defp render_hint(target, module, cmd) do
    case call(target, :module_commands, [module]) do
      {:ok, %{commands: commands}} ->
        Enum.find_value(commands, fn c -> c.name == cmd && Map.get(c, :render) end)

      _ ->
        nil
    end
  end

  defp render_hinted(value, nil), do: fmt(value)

  defp render_hinted([], %{kind: :table}), do: "(none)"

  defp render_hinted(rows, %{kind: :table} = hint) when is_list(rows) do
    labels = Map.get(hint, :labels, %{})
    table_of(rows, Map.get(hint, :columns) || derived_columns(rows), labels, [])
  end

  defp render_hinted(map, %{kind: :detail} = hint) when is_map(map) do
    labels = Map.get(hint, :labels, %{})
    nested = Map.get(hint, :nested, %{})
    fields = detail_fields(map, Map.get(hint, :fields, []))
    width = fields |> Enum.map(&String.length(humanize(&1))) |> Enum.max(fn -> 0 end)

    Enum.map_join(fields, "\n", fn name ->
      label = String.pad_trailing(humanize(name) <> ":", width + 2)

      case field_layout(field(map, name), [name], labels, Map.get(nested, name, %{})) do
        {:block, text} -> String.trim_trailing(label) <> "\n" <> indent(text)
        {:inline, text} -> label <> text
      end
    end)
  end

  defp render_hinted(value, _hint), do: fmt(value)

  # How one field of a detail view is laid out. A value that cannot honestly fit a
  # line gets a block of its own under the label — that is the whole difference
  # between a readable roster and an inspected term. Everything else stays inline, so
  # the common case is still one field per line.
  defp field_layout(value, path, labels, nested) do
    cond do
      # a list of uniform maps (the participants of a conference) reads as a table,
      # for the same reason `conference.list` does
      rows?(value) ->
        columns = Map.get(nested, :columns) || derived_columns(value)
        {:block, table_of(value, columns, labels, path)}

      # a map keyed by something that is *data* (per-media negotiation, per-media
      # statistics): one line per key, which a single k=v line cannot show
      map_of_maps?(value) ->
        {:block, keyed_block(value, path, labels)}

      true ->
        {:inline, detail_value(value, path, labels)}
    end
  end

  # `path` prefixes the label lookup, so a nested table's columns are declared the
  # way every other field is — `"participants.state"`.
  defp table_of(rows, columns, labels, path) do
    table(columns, rows, fn row ->
      Enum.map(columns, &dash(cell(field(row, &1), path ++ [&1], labels)))
    end)
  end

  # Columns a hint did not declare: every key the rows carry, sorted. A module gets a
  # readable table without declaring one; declaring `columns:` is how it says *which*
  # fields, and in what order.
  defp derived_columns(rows) do
    rows
    |> Enum.flat_map(fn row -> Enum.map(row, fn {k, _v} -> to_string(k) end) end)
    |> Enum.uniq()
    |> Enum.sort()
  end

  # One line per key, the keys aligned. The outer key is data (a media name), so it
  # is **not** part of the label path: `"medias.codec"` is declared once, not once
  # per media.
  defp keyed_block(map, path, labels) do
    entries = Enum.sort_by(map, fn {k, _v} -> to_string(k) end)
    width = entries |> Enum.map(fn {k, _v} -> String.length(to_string(k)) end) |> Enum.max()

    Enum.map_join(entries, "\n", fn {k, v} ->
      String.pad_trailing(to_string(k), width) <> "  " <> detail_value(v, path, labels)
    end)
  end

  defp rows?([_ | _] = list), do: Enum.all?(list, &(is_map(&1) and not is_struct(&1)))
  defp rows?(_value), do: false

  defp map_of_maps?(%{} = map) when not is_struct(map) do
    map_size(map) > 0 and Enum.all?(map, fn {_k, v} -> is_map(v) and not is_struct(v) end)
  end

  defp map_of_maps?(_value), do: false

  # Declared order first — that is the hint's whole point — then whatever else the
  # result carries (a module may merge extra keys, e.g. participant statistics).
  defp detail_fields(map, declared) do
    all = map |> Map.keys() |> Enum.map(&to_string/1)
    declared = Enum.filter(declared, &(&1 in all))
    declared ++ Enum.sort(all -- declared)
  end

  # Result maps are atom-keyed but the hint travels as strings (it must survive
  # both the RPC and the JSON of GET /modules): match on the printed name rather
  # than minting atoms on the CLI side.
  defp field(map, name) do
    case Enum.find(map, fn {k, _v} -> to_string(k) == name end) do
      {_k, v} -> v
      nil -> nil
    end
  end

  defp detail_value([], _path, _labels), do: "(none)"

  defp detail_value(list, path, labels) when is_list(list),
    do: Enum.map_join(list, ", ", &sub_value(&1, path, labels))

  defp detail_value(%DateTime{} = dt, path, labels), do: dash(scalar(dt, path, labels))

  # a nested map (video, layout, codecs…) fits one line as k=v pairs
  defp detail_value(%{} = map, path, labels) when not is_struct(map) do
    map
    |> Enum.sort_by(fn {k, _v} -> to_string(k) end)
    |> Enum.map_join(" ", fn {k, v} ->
      "#{k}=#{sub_value(v, path ++ [to_string(k)], labels)}"
    end)
  end

  defp detail_value(value, path, labels), do: dash(scalar(value, path, labels))

  # A table cell is one line by construction, so a value that would block is
  # compacted instead: `;` between the entries of a map, `,` between the items of a
  # list. Nothing here may emit a newline.
  defp cell([], _path, _labels), do: nil

  defp cell(%DateTime{} = dt, path, labels), do: scalar(dt, path, labels)

  defp cell(%{} = map, path, labels) when not is_struct(map) do
    map
    |> Enum.sort_by(fn {k, _v} -> to_string(k) end)
    |> Enum.map_join(";", fn {k, v} -> "#{k}=#{sub_value(v, path ++ [to_string(k)], labels)}" end)
  end

  defp cell(list, path, labels) when is_list(list),
    do: Enum.map_join(list, ",", &sub_value(&1, path, labels))

  defp cell(value, path, labels), do: scalar(value, path, labels)

  defp sub_value(list, path, labels) when is_list(list),
    do: Enum.map_join(list, ",", &sub_value(&1, path, labels))

  defp sub_value(%DateTime{} = dt, path, labels), do: scalar(dt, path, labels)

  # One level deeper than an inline k=v pair: parenthesised, or the inner pairs would
  # read as belonging to the enclosing map.
  defp sub_value(%{} = map, path, labels) when not is_struct(map),
    do: "(" <> detail_value(map, path, labels) <> ")"

  defp sub_value(value, path, labels), do: scalar(value, path, labels)

  # One displayable value. An enum integer gets the human name its command declared
  # (`labels: %{"video.size" => %{"6" => "hd720p"}}`); a timestamp loses its
  # microseconds — the operator reads `hd720p`, the API keeps the 6.
  defp scalar(nil, _path, _labels), do: nil

  defp scalar(%DateTime{} = dt, _path, _labels),
    do: dt |> DateTime.truncate(:second) |> to_string()

  defp scalar(value, path, labels) when is_binary(value) or is_atom(value) or is_number(value) do
    case Map.get(labels, Enum.join(path, ".")) do
      nil -> to_string(value)
      names -> Map.get(names, to_string(value), to_string(value))
    end
  end

  # A positional aggregate — an address pair, say. Shown as its elements rather than
  # as Elixir syntax; it is deliberately *not* rendered as `host:port`, since what the
  # positions mean is the module's knowledge and not the CLI's.
  defp scalar(value, path, labels) when is_tuple(value) do
    "(" <> (value |> Tuple.to_list() |> Enum.map_join(", ", &scalar(&1, path, labels))) <> ")"
  end

  defp scalar(value, _path, _labels), do: inspect(value)

  defp humanize(name), do: name |> String.replace("_", " ") |> String.capitalize()

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
    ] ++ arg_help_lines(cmd)
  end

  # An argument whose value has a vocabulary of its own declares it (`help:` in its
  # entry, one line or several): a mosaic name, an enum, a compact syntax. Printed
  # under the command, indented below the argument's name — the CLI knows nothing
  # about what it is showing, which is the point (§8.3.7).
  defp arg_help_lines(%{args: args}) when is_list(args) do
    Enum.flat_map(args, fn arg ->
      case List.wrap(Map.get(arg, :help)) do
        [] ->
          []

        [first | rest] ->
          pad = String.duplicate(" ", String.length(arg.name) + 8)
          ["      #{arg.name}: #{first}" | Enum.map(rest, &(pad <> &1))]
      end
    end)
  end

  defp arg_help_lines(_cmd), do: []

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
      <module> help [<cmd>]           the commands a module contributes, or
                                      one of them with its arguments' help
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
