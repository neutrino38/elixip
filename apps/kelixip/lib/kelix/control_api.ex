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
  | `reload_script/2` | `POST /scripts/reload[?notify=1]` (body `{"names": […]}`) |
  | `reload_domains/0` | `POST /domains/reload` |
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
  (design `docs/design/mcu_module.md` §8.3.5).
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

  post "/scripts/reload" do
    case conn.body_params["names"] do
      names when is_list(names) and names != [] ->
        notify? = conn.query_params["notify"] in ["1", "true"]
        json(conn, 200, Control.reload_script(names, notify?))

      _ ->
        json(conn, 400, %{error: ~s(body must be {"names": ["…"]})})
    end
  end

  post "/domains/reload" do
    respond(conn, Control.reload_domains())
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
  defp jsonable(v), do: v

  defp jsonable_key(k) when is_atom(k) and k not in [nil, true, false], do: to_string(k)
  defp jsonable_key(k), do: k
end
