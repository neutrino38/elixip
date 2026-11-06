defmodule Kelix.ControlAPI do
  @moduledoc """
  REST control frontal (design §10.3) — a `Plug.Router` served by Bandit, one
  endpoint per `Kelix.Control` verb (table §10.1) plus the module-contributed
  `/modules/<name>/<cmd>` commands (§8.1, from `Kelix.Control.Registry`).

  **Parity by construction**: every route is a thin translation onto a
  `Kelix.Control` function — the same layer `kelictl` calls — so the two frontals
  never diverge. This module holds no business logic and no auth: the credential
  is checked upstream by `Kelix.ControlAPI.Auth` (§10.3).

  | Verb | Route |
  |---|---|
  | `status/0` | `GET /status` |
  | `monitor/0` | `GET /scenarios` |
  | `registrations/0` | `GET /registrations` |
  | `registrations/1` | `GET /domains/:domain/registrations` |
  | `registration/2` | `GET /domains/:domain/registrations/:aor` |
  | `domains/0` | `GET /domains` |
  | `domain/1` | `GET /domains/:name` |
  | `mediaservers/0` | `GET /mediaservers` |
  | `mediaserver/1` | `GET /mediaservers/:name` |
  | `unregister/3` | `DELETE /domains/:domain/registrations/:aor[?contact=]` |
  | `shutdown_scenario/1` | `POST /scenarios/:id/shutdown` |
  | `debug_scenario/2` | `POST /scenarios/:id/debug` (body `{"enabled": bool}`) |
  | `traces/0` | `GET /traces` |
  | `debug_triggers/1` | `GET /debug/triggers[?domain=]` |
  | `debug_trigger/2` | `GET /debug/triggers/:domain/:script` |
  | `set_debug_trigger/4` | `PUT /debug/triggers/:domain/:script` (body `{"count", "duration", "filter"}`) |
  | `remove_debug_trigger/3` | `DELETE /debug/triggers/:domain/:script` → `204` |
  | `trace/1` | `GET /traces/:id` (the journal, unrendered, secrets masked) |
  | `reload_script/2` | `POST /scripts/reload[?notify=1]` (body `{"names": […]}`) |
  | `run_script/3` | `POST /scripts/:name/run` (body `{"domain": …, "args": {…}}`) → `202` |
  | `reload_domains/0` | `POST /domains/reload` |
  | `create_domain/3` … `delete_domain/2` | `POST` / `PATCH` / `PUT` / `DELETE /domains/…` (`docs/kelixip/rest-api.md`) |
  | `reload_all/0` | `POST /reload-all` |
  | `module_reload/1` | `POST /modules/:name/reload` |
  | `mediaserver_toggle/2` | `POST /mediaservers/:name` (body `{"enabled": bool}`) |
  | `set_log_level/1` | `PUT /log/level` (body `{"level": …}`) |
  | `graceful_shutdown/0` | `POST /graceful-shutdown` |
  | `drain/0` / `undrain/0` | `POST /drain` / `POST /undrain` |
  | `module_command/3` | `<METHOD> /modules/:name/*path` (declared template, body/query/path = args) |

  ## Module commands: nested resources (FW-4)

  A module's commands are resolved against the **path templates** they declare in
  `describe_control/0` (`Kelix.Control.Route`), so a module can expose a real
  resource tree (`/modules/mcu/conferences/:uid/participants`) instead of flat
  verbs. Resolution is **most-literal-first**, and an ambiguous pair is refused at
  registration time rather than arbitrated here.

  Args reaching `handle_control/2` are merged **path < query < body** — a body key
  colliding with a path param is a `400 path_conflict`, never a silent divergence
  between the URL and the effect. Success status, `Location:` and error statuses are
  **derived** from the declaration (`status:` / `location:` / `errors:`); the module
  itself never manipulates HTTP, which is what keeps `kelictl` parity free.

  The flat form (`<METHOD> /modules/<name>/<command.id>`) is **kept**: every command
  id is a valid single-segment path, so a client that cannot build URLs — and every
  command written before FW-4 — still reaches the same `handle_control/2` clause
  (design `docs/design/DESIGN-MCU.md`).
  """
  use Plug.Router
  require Logger

  alias Kelix.Control
  alias Kelix.Control.Route

  plug(Kelix.ControlAPI.Auth)
  plug(:match)

  plug(Plug.Parsers,
    parsers: [:json],
    pass: ["application/json"],
    json_decoder: Jason
  )

  plug(:dispatch)

  # ── read verbs ────────────────────────────────────────────────────────────────

  get "/status" do
    json(conn, 200, Control.status())
  end

  get "/traces" do
    json(conn, 200, Enum.map(Control.traces(), &trace_json/1))
  end

  get "/traces/:id" do
    case Integer.parse(id) do
      {n, ""} ->
        case Control.trace(n) do
          {:ok, trace} -> json(conn, 200, trace_json(trace))
          {:error, :not_found} -> json(conn, 404, %{error: "not found"})
        end

      _ ->
        json(conn, 400, %{error: "id must be an integer"})
    end
  end

  get "/scenarios" do
    json(conn, 200, Control.monitor())
  end

  # The cross-domain view: one entry per served domain, each with its registrations.
  # A single domain is `GET /domains/:domain/registrations` below.
  get "/registrations" do
    json(conn, 200, Control.registrations())
  end

  get "/domains" do
    json(conn, 200, Control.domains())
  end

  # Registrations are a **sub-resource of the domain**: an AOR is only unique within
  # one (§6.1), so the domain belongs in the path rather than in the AOR string. An
  # AOR contains no slash (a user-part, optionally `user@domain`), so it is one
  # segment; `DELETE` on the same path is the removal below.
  get "/domains/:domain/registrations" do
    case Control.registrations(domain) do
      {:ok, entry} -> json(conn, 200, entry)
      {:error, :not_found} -> json(conn, 404, %{error: "not found"})
    end
  end

  get "/domains/:domain/registrations/:aor" do
    case Control.registration(domain, aor) do
      {:ok, row} -> json(conn, 200, row)
      {:error, :not_found} -> json(conn, 404, %{error: "not found"})
    end
  end

  # Declared before `POST /domains/reload` is irrelevant (the method differs), but
  # it does mean `GET /domains/reload` answers 404 "not found" — there is no
  # domain by that name, which is the honest answer.
  get "/domains/:name" do
    case Control.domain(name) do
      {:ok, domain} -> json(conn, 200, domain)
      {:error, :not_found} -> json(conn, 404, %{error: "not found"})
    end
  end

  get "/mediaservers" do
    json(conn, 200, Control.mediaservers())
  end

  get "/mediaservers/:name" do
    case Control.mediaserver(name) do
      {:ok, mediaserver} -> json(conn, 200, mediaserver)
      {:error, :not_found} -> json(conn, 404, %{error: "not found"})
    end
  end

  # What the loaded modules contribute (FW-5): the command declarations a client can
  # build its URLs from, instead of being handed the list out of band. Declared before
  # `match "/modules/:name/*path"` below, whose glob would otherwise swallow
  # `GET /modules/mcu` and answer 404 — the same reason `GET /domains/:name` precedes
  # the domain write verbs.
  get "/modules" do
    json(conn, 200, Control.module_commands())
  end

  get "/modules/:name" do
    case Control.module_commands(name) do
      {:ok, entry} -> json(conn, 200, entry)
      {:error, :unknown_module} -> json(conn, 404, %{error: "not found"})
    end
  end

  # ── write verbs ───────────────────────────────────────────────────────────────

  delete "/domains/:domain/registrations/:aor" do
    contact =
      case conn.query_params["contact"] do
        nil -> :all
        "" -> :all
        c -> c
      end

    respond(conn, Control.unregister(domain, aor, contact))
  end

  post "/scenarios/:id/shutdown" do
    case Integer.parse(id) do
      {n, ""} -> respond(conn, Control.shutdown_scenario(n))
      _ -> json(conn, 400, %{error: "id must be an integer"})
    end
  end

  post "/scenarios/:id/debug" do
    case {Integer.parse(id), conn.body_params["enabled"]} do
      {{n, ""}, enabled} when is_boolean(enabled) ->
        case Control.debug_scenario(n, if(enabled, do: :on, else: :off)) do
          {:error, :journal_written} -> json(conn, 409, %{error: "journal already written"})
          result -> respond(conn, result)
        end

      {{_n, ""}, _other} ->
        json(conn, 400, %{error: "body must be {\"enabled\": true | false}"})

      _ ->
        json(conn, 400, %{error: "id must be an integer"})
    end
  end

  # ── debug triggers (debug-triggers-plan.md) ──────────────────────────────────
  #
  # A script name may hold a `/` (a sub-directory of script_dir), hence the glob:
  # everything after the domain is the script.

  get "/debug/triggers" do
    conn = fetch_query_params(conn)
    rules = Control.debug_triggers(presence(conn.query_params["domain"]))
    json(conn, 200, Enum.map(rules, &trigger_json/1))
  end

  get "/debug/triggers/:domain/*script" do
    case Control.debug_trigger(domain, Enum.join(script, "/")) do
      {:ok, rule} -> json(conn, 200, trigger_json(rule))
      {:error, reason} -> trigger_error(conn, reason)
    end
  end

  put "/debug/triggers/:domain/*script" do
    script = Enum.join(script, "/")

    case Control.set_debug_trigger(domain, script, body_map(conn), actor: admin_header(conn)) do
      {:ok, rule} -> json(conn, 200, %{result: trigger_json(rule)})
      {:error, reason} -> trigger_error(conn, reason)
    end
  end

  delete "/debug/triggers/:domain/*script" do
    script = Enum.join(script, "/")

    case Control.remove_debug_trigger(domain, script, actor: admin_header(conn)) do
      :ok -> send_resp(conn, 204, "")
      {:error, reason} -> trigger_error(conn, reason)
    end
  end

  post "/scripts/reload" do
    case conn.body_params["names"] do
      names when is_list(names) and names != [] ->
        notify? = conn.query_params["notify"] in ["1", "true"]
        json(conn, 200, Control.reload_script(names, notify?))

      _ ->
        json(conn, 400, %{error: ~s(body must be {"names": ["…"]})})
    end
  end

  # A script run on demand: `202` with the instance id, which is what `/scenarios`
  # lists and `/scenarios/:id/shutdown` stops — the instance runs on after the
  # response, and how it ends is the monitor's to show.
  post "/scripts/:name/run" do
    case {conn.body_params["domain"], Map.get(conn.body_params, "args", %{})} do
      {domain, args} when is_binary(domain) and is_map(args) ->
        case Control.run_script(name, domain, args) do
          {:ok, %{id: id}} ->
            json(conn, 202, %{result: %{id: id}})

          {:error, :not_found} ->
            json(conn, 404, %{error: "no domain #{domain}"})

          {:error, :bad_script_name} ->
            json(conn, 400, %{error: "a script name, not a path"})

          {:error, {:script, reason}} ->
            json(conn, 422, %{error: "script #{name} does not load: #{error_message(reason)}"})

          {:error, {:rejected, code, reason}} ->
            json(conn, code, %{error: reason})
        end

      _ ->
        json(conn, 400, %{error: ~s(body must be {"domain": "…", "args": {…}}, args optional)})
    end
  end

  post "/domains/reload" do
    respond(conn, Control.reload_domains())
  end

  # The umbrella reload (`kelictl reload-all`, `systemctl reload`): the report is the
  # body either way, so a client sees per-stage what was applied and what was not — a
  # bare 400 with no detail would be unusable here.
  post "/reload-all" do
    report = Control.reload_all()
    json(conn, if(Control.reload_ok?(report), do: 200, else: 400), report)
  end

  post "/modules/:name/reload" do
    respond(conn, Control.module_reload(name))
  end

  post "/mediaservers/:name" do
    case conn.body_params["enabled"] do
      on? when is_boolean(on?) -> respond(conn, Control.mediaserver_toggle(name, on?))
      _ -> json(conn, 400, %{error: ~s(body must be {"enabled": true|false})})
    end
  end

  put "/log/level" do
    case conn.body_params["level"] do
      lvl when is_binary(lvl) -> respond(conn, Control.set_log_level(lvl))
      _ -> json(conn, 400, %{error: ~s(body must be {"level": "debug|info|warning|error"})})
    end
  end

  post "/graceful-shutdown" do
    Control.graceful_shutdown()
    json(conn, 202, %{result: "draining"})
  end

  # Leave / rejoin the upstream rotation without touching what is in flight: while
  # draining, the OPTIONS liveness ping is answered 503 (see Kelix.Options).
  post "/drain" do
    Control.drain()
    json(conn, 200, %{result: "draining"})
  end

  post "/undrain" do
    Control.undrain()
    json(conn, 200, %{result: "in_service"})
  end

  # ── domain edits (docs/design/dynamic-domains-plan.md §5) ─────────────────────
  #
  # One route per `kelictl domain …` command. Every one runs through `domain_edit/3`,
  # which reads `version` and `X-Kelix-Admin` and maps the answer.

  post "/domains" do
    domain_edit(conn, fn result, _body -> "/domains/#{result.name}" end, fn body, opts ->
      with {:ok, name, attrs} <- take_arg(body, "name"),
           do: Control.create_domain(name, attrs, opts)
    end)
  end

  delete "/domains/:d" do
    domain_edit(conn, fn _body, opts ->
      with {:ok, result} <- Control.delete_domain(d, opts),
           do: {:ok, Map.update!(result, :purged, &purge_json/1)}
    end)
  end

  patch "/domains/:d" do
    domain_edit(conn, fn body, opts -> Control.set_domain(d, body, opts) end)
  end

  post "/domains/:d/aliases" do
    location = fn _result, body -> "/domains/#{d}/aliases/#{body["host"]}" end

    domain_edit(conn, location, fn body, opts ->
      with {:ok, host} <- only_arg(body, "host"), do: Control.add_alias(d, host, opts)
    end)
  end

  delete "/domains/:d/aliases/:host" do
    domain_edit(conn, fn _body, opts -> Control.remove_alias(d, host, opts) end)
  end

  patch "/domains/:d/registrar" do
    domain_edit(conn, fn body, opts -> Control.set_registrar(d, body, opts) end)
  end

  delete "/domains/:d/registrar" do
    domain_edit(conn, fn _body, opts -> Control.remove_registrar(d, opts) end)
  end

  post "/domains/:d/presence" do
    location = fn _result, body -> "/domains/#{d}/presence/#{body["package"]}" end

    domain_edit(conn, location, fn body, opts ->
      with {:ok, package, attrs} <- take_arg(body, "package"),
           do: Control.add_presence(d, package, attrs, opts)
    end)
  end

  patch "/domains/:d/presence/:package" do
    domain_edit(conn, fn body, opts -> Control.set_presence(d, package, body, opts) end)
  end

  delete "/domains/:d/presence/:package" do
    domain_edit(conn, fn _body, opts -> Control.remove_presence(d, package, opts) end)
  end

  # Declared before the rule routes, whose `:n` would take `keepalive` for a number.
  put "/domains/:d/options/keepalive" do
    domain_edit(conn, fn body, opts ->
      with {:ok, script} <- only_arg(body, "script"), do: Control.set_keepalive(d, script, opts)
    end)
  end

  delete "/domains/:d/options/keepalive" do
    domain_edit(conn, fn _body, opts -> Control.remove_keepalive(d, opts) end)
  end

  post "/domains/:d/presence/:package/subscribe" do
    add_rule(conn, d, {:subscribe, package}, "presence/#{package}/subscribe")
  end

  patch "/domains/:d/presence/:package/subscribe/:n" do
    domain_edit(conn, fn body, opts ->
      Control.update_rule(d, {:subscribe, package}, n, body, opts)
    end)
  end

  post "/domains/:d/presence/:package/subscribe/:n/move" do
    move_rule(conn, d, {:subscribe, package}, n)
  end

  delete "/domains/:d/presence/:package/subscribe/:n" do
    domain_edit(conn, fn _body, opts ->
      Control.remove_rule(d, {:subscribe, package}, n, opts)
    end)
  end

  post "/domains/:d/:list" when list in ["calls", "chat", "options"] do
    add_rule(conn, d, rule_list(list), list)
  end

  patch "/domains/:d/:list/:n" when list in ["calls", "chat", "options"] do
    domain_edit(conn, fn body, opts -> Control.update_rule(d, rule_list(list), n, body, opts) end)
  end

  post "/domains/:d/:list/:n/move" when list in ["calls", "chat", "options"] do
    move_rule(conn, d, rule_list(list), n)
  end

  delete "/domains/:d/:list/:n" when list in ["calls", "chat", "options"] do
    domain_edit(conn, fn _body, opts -> Control.remove_rule(d, rule_list(list), n, opts) end)
  end

  # ── module-contributed commands (§8.1, FW-4) ───────────────────────────────────
  #
  # Everything under `/modules/<name>/` that is not the fixed config-reload route
  # above: the rest-path is resolved against the module's declared templates (and
  # its flat command ids). Declared *after* `POST /modules/:name/reload`, so config
  # reload keeps winning over a hypothetical `reload` command.
  match "/modules/:name/*path" do
    dispatch_module(conn, name, path)
  end

  match _ do
    json(conn, 404, %{error: "not found"})
  end

  # ── module dispatch ───────────────────────────────────────────────────────────

  defp dispatch_module(conn, name, path) do
    commands = Kelix.Control.Registry.commands_for(name)

    case resolve(commands, path, conn.method) do
      {:ok, command, path_params} ->
        run_command(conn, name, command, path_params)

      {:method_not_allowed, allowed} ->
        conn
        |> put_resp_header("allow", allow_header(allowed))
        |> json(405, %{error: "method not allowed"})

      :error ->
        # a module or path we do not serve: 404 either way, so an unauthenticated
        # probe (auth runs first) enumerates nothing
        json(conn, 404, %{error: "unknown module command"})
    end
  end

  # Resolve a rest-path against the declared commands: flat form first (a command
  # id is always a valid single-segment path), then the path templates,
  # most-literal-first. Method mismatch on an otherwise matching path is a 405.
  defp resolve(commands, path, method) do
    matches =
      commands
      |> Enum.flat_map(&candidates(&1, path))
      |> Enum.sort_by(fn {rank, _command, _params} -> rank end)

    case Enum.filter(matches, fn {_r, c, _p} -> method in http_methods(c) end) do
      [{_rank, command, params} | _] ->
        {:ok, command, params}

      [] ->
        case matches do
          [] ->
            :error

          _ ->
            {:method_not_allowed, Enum.flat_map(matches, fn {_r, c, _p} -> http_methods(c) end)}
        end
    end
  end

  # {sort_rank, command, path_params} for every way `path` reaches `command`
  defp candidates(command, path) do
    flat = if path == [command.name], do: [{{0, []}, command, %{}}], else: []

    segments = Route.segments(Route.template(command))

    templated =
      case Route.match(segments, path) do
        {:ok, params} -> [{{1, Route.specificity(segments)}, command, params}]
        :error -> []
      end

    flat ++ templated
  end

  defp http_methods(command),
    do: Enum.map(Route.methods(command), &String.upcase(to_string(&1)))

  defp allow_header(methods), do: methods |> Enum.uniq() |> Enum.join(", ")

  # Merge the args (path < query < body) and hand the command to the control layer,
  # then derive the HTTP answer from the declaration.
  defp run_command(conn, name, command, path_params) do
    conn = fetch_query_params(conn)

    case merge_args(path_params, conn.query_params, body_map(conn)) do
      {:ok, args} ->
        respond_command(conn, name, command, Control.module_command(name, command.name, args))

      {:error, key} ->
        json(conn, 400, %{error: "path_conflict", detail: key})
    end
  end

  # Precedence is ascending path < query < body (§8.3.4 item 3). A body that tries
  # to *change* a path param is refused: the URL and the effect must not diverge.
  defp merge_args(path_params, query_params, body) do
    conflict =
      Enum.find(path_params, fn {key, value} ->
        case Map.fetch(body, key) do
          {:ok, other} -> to_string(other) != to_string(value)
          :error -> false
        end
      end)

    case conflict do
      {key, _value} -> {:error, key}
      nil -> {:ok, path_params |> Map.merge(query_params) |> Map.merge(body)}
    end
  end

  # the parsed JSON body as a plain map (%{} for an unfetched/absent body)
  defp body_map(%{body_params: %Plug.Conn.Unfetched{}}), do: %{}
  defp body_map(%{body_params: params}) when is_map(params), do: params
  defp body_map(_), do: %{}

  # ── domain edit helpers ───────────────────────────────────────────────────────

  # `fun` gets the command's JSON arguments, without `version`, and the opts every
  # `Kelix.Control` domain edit takes; it answers that edit's result, or `{:bad,
  # message}` for a body without what the route needs. With `location`, a success is
  # a creation: `201` and a `Location:` built from the result and the body.
  defp domain_edit(conn, location \\ nil, fun) do
    body = conn |> body_map() |> Map.delete("version")

    with {:ok, opts} <- edit_opts(conn),
         {:ok, result} <- fun.(body, opts) do
      case location do
        nil ->
          json(conn, 200, %{result: result})

        location ->
          conn
          |> put_resp_header("location", location.(result, body))
          |> json(201, %{result: result})
      end
    else
      {:bad, message} -> json(conn, 400, %{error: "invalid", message: message})
      {:error, reason} -> domain_error(conn, reason)
    end
  end

  # `version` from the body or the query string, the admin from `X-Kelix-Admin`.
  defp edit_opts(conn) do
    conn = fetch_query_params(conn)
    actor = conn |> get_req_header("x-kelix-admin") |> List.first()

    case Map.get(body_map(conn), "version", conn.query_params["version"]) do
      nil ->
        {:ok, [actor: actor]}

      v when is_integer(v) and v > 0 ->
        {:ok, [actor: actor, version: v]}

      v when is_binary(v) ->
        case Integer.parse(v) do
          {n, ""} when n > 0 -> {:ok, [actor: actor, version: n]}
          _ -> {:bad, "`version` must be a positive integer"}
        end

      _ ->
        {:bad, "`version` must be a positive integer"}
    end
  end

  # The argument a route names in its body, and the others, for the command.
  defp take_arg(body, key) do
    case Map.pop(body, key) do
      {value, rest} when is_binary(value) and value != "" -> {:ok, value, rest}
      _ -> {:bad, "the body needs `#{key}`, a non-empty string"}
    end
  end

  # A route whose body holds one argument and nothing else.
  defp only_arg(body, key) do
    case take_arg(body, key) do
      {:ok, value, rest} when rest == %{} ->
        {:ok, value}

      {:ok, _value, rest} ->
        {:bad, "unknown argument(s): #{rest |> Map.keys() |> Enum.sort() |> Enum.join(", ")}"}

      bad ->
        bad
    end
  end

  # `pattern` is a dial pattern or `default`, as `<rule>` in `kelictl … add <rule>`;
  # the answer's `at` is the number the rule took.
  defp add_rule(conn, d, list, segment) do
    location = fn result, _body -> "/domains/#{d}/#{segment}/#{result.at}" end

    domain_edit(conn, location, fn body, opts ->
      with {:ok, pattern, attrs} <- take_arg(body, "pattern"),
           do: Control.add_rule(d, list, pattern, attrs, opts)
    end)
  end

  defp move_rule(conn, d, list, n) do
    domain_edit(conn, fn body, opts ->
      case Map.keys(body) -- ["to"] do
        [] -> Control.move_rule(d, list, n, body["to"], opts)
        extra -> {:bad, "unknown argument(s): #{extra |> Enum.sort() |> Enum.join(", ")}"}
      end
    end)
  end

  defp rule_list("calls"), do: :call
  defp rule_list("chat"), do: :chat
  defp rule_list("options"), do: :options

  defp purge_json(purged) do
    Map.new(purged, fn
      {module, {:ok, n}} -> {module, %{purged: n}}
      {module, {:error, reason}} -> {module, %{error: inspect(reason)}}
      {module, other} -> {module, other}
    end)
  end

  # The statuses of §5; `error` is the reason a client tests, `message` what it shows.
  defp domain_error(conn, :not_found),
    do:
      domain_error(
        conn,
        404,
        :not_found,
        "no such domain, or no such alias, block, package or rule in it"
      )

  defp domain_error(conn, :exists), do: domain_error(conn, 409, :exists, "it already exists")

  defp domain_error(conn, :conflict),
    do:
      domain_error(
        conn,
        409,
        :conflict,
        "the domains changed since the version given, or while the command ran: read " <>
          "them again (GET /domains/<domain>) and send the command again. Nothing was applied."
      )

  defp domain_error(conn, :file_changed),
    do:
      domain_error(
        conn,
        409,
        :file_changed,
        "domains.toml was edited by hand and not reloaded, and a write would erase that " <>
          "edit: POST /domains/reload first. Nothing was applied."
      )

  defp domain_error(conn, {:invalid, message}), do: domain_error(conn, 400, :invalid, message)
  defp domain_error(conn, {:scripts, message}), do: domain_error(conn, 400, :scripts, message)

  defp domain_error(conn, {:read_only, %{path: path, reason: reason, user: user}}) do
    json(conn, 503, %{
      error: "read_only",
      message:
        "the node cannot write #{path} (#{file_reason(reason)}, running as #{user}): give " <>
          "the file and its directory to #{user}, or point KELIXIP_DOMAINS to " <>
          "/var/lib/kelixip/domains.toml. Nothing was applied.",
      path: path,
      reason: to_string(reason),
      user: user
    })
  end

  defp domain_error(conn, {:write_failed, %{path: path, reason: reason}}),
    do:
      domain_error(
        conn,
        500,
        :write_failed,
        "writing #{path} failed (#{file_reason(reason)}). Nothing was applied."
      )

  defp domain_error(conn, :no_domains_path),
    do:
      domain_error(
        conn,
        503,
        :no_domains_path,
        "this node reads no domains.toml (KELIXIP_DOMAINS is not set)"
      )

  defp domain_error(conn, other), do: domain_error(conn, 500, :error, inspect(other))

  defp file_reason(reason) when is_atom(reason), do: "#{:file.format_error(reason)}, #{reason}"
  defp file_reason(reason), do: inspect(reason)

  defp domain_error(conn, status, error, message),
    do: json(conn, status, %{error: error, message: message})

  # ── declared status / Location / errors (§8.3.4 item 4) ────────────────────────

  defp respond_command(conn, name, command, {:ok, value}),
    do: created_or_ok(conn, name, command, value)

  defp respond_command(conn, name, command, :ok),
    do: created_or_ok(conn, name, command, "ok")

  defp respond_command(conn, _name, command, {:error, reason}),
    do: json(conn, Route.error_status(command, reason), %{error: error_message(reason)})

  # anything else (a bare map / term) keeps the pre-FW-4 behaviour
  defp respond_command(conn, _name, _command, other), do: respond(conn, other)

  defp created_or_ok(conn, name, command, value) do
    conn
    |> put_location(name, Map.get(command, :location), value)
    |> json(Map.get(command, :status, 200), %{result: jsonable(value)})
  end

  defp put_location(conn, _name, nil, _value), do: conn

  defp put_location(conn, name, template, value) when is_map(value) do
    case Route.render(template, value) do
      {:ok, path} -> put_resp_header(conn, "location", "/modules/#{name}#{path}")
      # the result does not carry the params the template names: no header rather
      # than one pointing nowhere
      :error -> conn
    end
  end

  defp put_location(conn, _name, _template, _value), do: conn

  # The status for a reason is `Kelix.Control.Route.error_status/2` — shared with the
  # CLI's exit-code mapping, so one declaration drives both frontals.

  defp error_message(reason) when is_atom(reason), do: to_string(reason)
  defp error_message(reason) when is_binary(reason), do: reason
  defp error_message(reason), do: inspect(reason)

  # ── response mapping ──────────────────────────────────────────────────────────

  # translate a Kelix.Control result into an HTTP status + JSON body
  defp respond(conn, :ok), do: json(conn, 200, %{result: "ok"})
  defp respond(conn, :notfound), do: json(conn, 404, %{error: "not found"})
  defp respond(conn, {:ok, value}), do: json(conn, 200, %{result: jsonable(value)})

  defp respond(conn, {:error, reason}) when reason in [:not_found, :unknown, :unknown_module],
    do: json(conn, 404, %{error: to_string(reason)})

  defp respond(conn, {:error, reason}), do: json(conn, 400, %{error: to_string(reason)})
  # a per-name result map (reload_script): the status is the aggregate outcome
  defp respond(conn, %{} = map), do: json(conn, 200, jsonable(map))
  defp respond(conn, other), do: json(conn, 200, jsonable(other))

  # A debug trigger as JSON: times in ISO 8601 (`jsonable/1` would turn a
  # DateTime into the map of its fields).
  defp trigger_json(rule) do
    rule
    |> Map.update!(:created_at, &DateTime.to_iso8601/1)
    |> Map.update!(:expires_at, &DateTime.to_iso8601/1)
  end

  defp trigger_error(conn, reason) do
    {class, message} = Control.debug_trigger_error(reason)
    status = %{not_found: 404, invalid: 400, unavailable: 503}[class]
    json(conn, status, %{error: to_string(class), message: message})
  end

  defp admin_header(conn), do: conn |> get_req_header("x-kelix-admin") |> List.first()

  defp presence(nil), do: nil
  defp presence(""), do: nil
  defp presence(value), do: value

  # A kept journal as JSON: times in ISO 8601, and the `config` of its metadata
  # masked as the renderers mask it — a REST client is not trusted to.
  defp trace_json(entry) do
    entry
    |> Map.update!(:written_at, &DateTime.to_iso8601/1)
    |> Map.update!(:expires_at, &DateTime.to_iso8601/1)
    |> Map.update(:meta, nil, &mask_meta/1)
  end

  defp mask_meta(meta) do
    Map.update(meta, :config, [], fn config ->
      Map.new(config, fn {key, value} ->
        # mask/2 answers "****" for a secret and inspect/1 of anything else:
        # only the verdict is taken, the other values stay as they were.
        {key, if(FSL.Diagram.mask(key, value) == "****", do: "****", else: value)}
      end)
    end)
  end

  defp json(conn, status, data) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(jsonable(data)))
  end

  # Make an arbitrary Kelix.Control result JSON-encodable: atoms (bar the JSON
  # literals) → strings, tuples → lists, structs → plain maps. Keeps the frontal
  # tolerant of whatever a module's handle_control/2 returns.
  defp jsonable(v) when is_atom(v) and v not in [nil, true, false], do: to_string(v)
  defp jsonable(v) when is_tuple(v), do: v |> Tuple.to_list() |> Enum.map(&jsonable/1)
  defp jsonable(%_{} = struct), do: struct |> Map.from_struct() |> jsonable()
  defp jsonable(%{} = map), do: Map.new(map, fn {k, v} -> {jsonable_key(k), jsonable(v)} end)
  defp jsonable(list) when is_list(list), do: Enum.map(list, &jsonable/1)
  # A monitor row carries its instance's pid: meaningful inside the node, and a
  # crash of the whole response for Jason, which encodes no pid. GET /scenarios
  # answered 500 whenever a scenario was running — that is, whenever it had
  # something to say. Such a term travels as the text an operator reads in logs.
  defp jsonable(v) when is_pid(v) or is_reference(v) or is_port(v) or is_function(v),
    do: inspect(v)

  defp jsonable(v), do: v

  defp jsonable_key(k) when is_atom(k) and k not in [nil, true, false], do: to_string(k)
  defp jsonable_key(k), do: k
end
