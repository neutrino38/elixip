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
  | `registrations/1` | `GET /registrations[?aor=]` |
  | `unregister/2` | `DELETE /registrations/:aor[?contact=]` |
  | `shutdown_scenario/1` | `POST /scenarios/:id/shutdown` |
  | `reload_script/2` | `POST /scripts/reload[?notify=1]` (body `{"names": […]}`) |
  | `reload_domains/0` | `POST /domains/reload` |
  | `module_reload/1` | `POST /modules/:name/reload` |
  | `mediaserver_toggle/2` | `POST /mediaservers/:name` (body `{"enabled": bool}`) |
  | `set_log_level/1` | `PUT /log/level` (body `{"level": …}`) |
  | `graceful_shutdown/0` | `POST /graceful-shutdown` |
  | `drain/0` / `undrain/0` | `POST /drain` / `POST /undrain` |
  | `module_command/3` | `<METHOD> /modules/:name/:cmd` (body = args) |
  """
  use Plug.Router
  require Logger

  alias Kelix.Control

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

  get "/registrations" do
    aor = conn.query_params["aor"]
    json(conn, 200, Control.registrations(aor))
  end

  # ── write verbs ───────────────────────────────────────────────────────────────

  delete "/registrations/:aor" do
    contact =
      case conn.query_params["contact"] do
        nil -> :all
        "" -> :all
        c -> c
      end

    respond(conn, Control.unregister(aor, contact))
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

  # ── module-contributed commands (§8.1) ────────────────────────────────────────
  #
  # A declared command is reachable as `<method> /modules/<name>/<cmd>` where the
  # method is the one it declared in `describe_control/0`. Declared before the
  # generic `:cmd` matcher, `POST /modules/:name/reload` (config reload) wins over
  # a hypothetical `reload` command. The request body (a JSON object) is the args.
  match "/modules/:name/:cmd" do
    dispatch_module(conn, name, cmd)
  end

  match _ do
    json(conn, 404, %{error: "not found"})
  end

  # ── module dispatch ───────────────────────────────────────────────────────────

  defp dispatch_module(conn, name, cmd) do
    case find_command(name, cmd) do
      {:ok, %{rest: {method, _path}}} ->
        if String.upcase(to_string(method)) == conn.method do
          respond(conn, Control.module_command(name, cmd, body_map(conn)))
        else
          json(conn, 405, %{error: "method not allowed"})
        end

      :error ->
        json(conn, 404, %{error: "unknown module command"})
    end
  end

  # look up a module's declared command by name; :error if the module or command
  # is unknown (so an unauthenticated probe cannot enumerate the surface)
  defp find_command(name, cmd) do
    Kelix.Control.Registry.commands_for(name)
    |> Enum.find(fn c -> c.name == cmd end)
    |> case do
      nil -> :error
      command -> {:ok, command}
    end
  end

  # the parsed JSON body as a plain map (%{} for an unfetched/absent body)
  defp body_map(%{body_params: %Plug.Conn.Unfetched{}}), do: %{}
  defp body_map(%{body_params: params}) when is_map(params), do: params
  defp body_map(_), do: %{}

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
