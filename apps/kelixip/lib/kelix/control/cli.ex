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
  defp parse(["regs"]), do: {:ok, :regs, :registrations, [nil]}
  defp parse(["regs", aor]), do: {:ok, :regs, :registrations, [aor]}
  defp parse(["unregister", aor]), do: {:ok, :ok, :unregister, [aor, :all]}
  defp parse(["unregister", aor, contact]), do: {:ok, :ok, :unregister, [aor, contact]}
  defp parse(["reload-domains"]), do: {:ok, :ok, :reload_domains, []}
  defp parse(["module", "reload", name]), do: {:ok, :ok, :module_reload, [name]}

  defp parse(["mcu", name, onoff]) when onoff in ["on", "off"],
    do: {:ok, :ok, :mediaserver_toggle, [name, onoff == "on"]}

  defp parse(["log-level", lvl]), do: {:ok, :ok, :set_log_level, [lvl]}
  defp parse(["graceful-shutdown"]), do: {:ok, :ok, :graceful_shutdown, []}

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

  # module-contributed command: <module> <cmd> [args…]
  defp parse([module, cmd | rest]),
    do: {:ok, :module, :module_command, [module, cmd, %{"args" => rest}]}

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

  defp render(_tag, {:error, reason}), do: {1, "error: #{inspect(reason)}"}

  defp render(:status, %{} = s) do
    lines = [
      "node:            #{s.node}",
      "uptime:          #{format_uptime(s.uptime_ms)}",
      "active calls:    #{Map.get(s.instances, :active, 0)}",
      "listeners:       #{format_listeners(Map.get(s, :listeners, []))}",
      "domains version: #{s.domains_version}",
      "modules:         #{Enum.join(s.modules, ", ")}",
      "media pool:      #{format_pool(s.media_pool)}"
    ]

    {0, Enum.join(lines, "\n")}
  end

  defp render(:monitor, rows) when is_list(rows) do
    {0,
     table(
       ["scenario", "account", "state", "command"],
       rows,
       &[&1.scenario, &1.account, &1.state, &1.command]
     )}
  end

  defp render(:regs, rows) when is_list(rows) do
    if rows == [] do
      {0, "no registrations"}
    else
      {0,
       Enum.map_join(rows, "\n", fn r ->
         contacts = Enum.map_join(r.contacts, ", ", & &1.uri)
         "#{r.aor}@#{r.domain} -> #{contacts}"
       end)}
    end
  end

  defp render(:map, result) when is_map(result) do
    {exit_map(result), Enum.map_join(result, "\n", fn {k, v} -> "#{k}: #{fmt(v)}" end)}
  end

  defp render(:module, {:ok, value}), do: {0, fmt(value)}
  defp render(:ok, :ok), do: {0, "ok"}
  defp render(:ok, :notfound), do: {1, "not found"}
  defp render(_tag, other), do: {0, fmt(other)}

  defp exit_map(result), do: if(Enum.all?(result, fn {_k, v} -> v == :ok end), do: 0, else: 1)

  defp fmt(:ok), do: "ok"
  defp fmt({:error, reason}), do: "error: #{inspect(reason)}"
  defp fmt(v) when is_binary(v), do: v
  defp fmt(v), do: inspect(v)

  defp table(headers, rows, to_cells) do
    Enum.join([Enum.join(headers, "  ") | Enum.map(rows, &Enum.join(to_cells.(&1), "  "))], "\n")
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
      regs [aor]                      list registrations
      unregister <aor> [contact]      remove a registration
      stop <id>                       shut down one scenario
      reload-script [--notify] <name…>  reload scenario script(s)
      reload-domains                  hot-reload domains.toml
      module reload <name>            reload a module's config
      mcu <name> on|off               enable/disable a media server
      log-level <lvl>                 set the runtime log level
      graceful-shutdown               drain scenarios then stop
      <module> <cmd> [args…]          a module-contributed command
    """
  end
end
