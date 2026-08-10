defmodule Kelix.ControlAPITest do
  # The REST control frontal (design §10.3), driven directly with Plug.Test conns
  # (no socket). The :kelixip app is running, so the Kelix.Control surfaces are
  # live singletons — empty at boot. Auth is exercised separately below.
  use ExUnit.Case, async: false
  import Plug.Test
  import Plug.Conn

  @opts Kelix.ControlAPI.init([])

  setup do
    prev = Application.get_env(:kelixip, :control_api)
    # default: skip the credential check so route behaviour is tested in isolation
    Application.put_env(:kelixip, :control_api, %{auth: "none"})

    on_exit(fn ->
      if prev,
        do: Application.put_env(:kelixip, :control_api, prev),
        else: Application.delete_env(:kelixip, :control_api)
    end)

    :ok
  end

  defp call(conn), do: Kelix.ControlAPI.call(conn, @opts)
  defp body(conn), do: Jason.decode!(conn.resp_body)

  describe "read verbs" do
    test "GET /status" do
      conn = call(conn(:get, "/status"))
      assert conn.status == 200
      b = body(conn)
      assert b["node"] == to_string(node())
      assert is_integer(b["uptime_ms"])
      assert is_map(b["instances"])
    end

    test "GET /scenarios returns a JSON list" do
      conn = call(conn(:get, "/scenarios"))
      assert conn.status == 200
      assert is_list(body(conn))
    end

    test "GET /registrations returns a JSON list" do
      conn = call(conn(:get, "/registrations"))
      assert conn.status == 200
      assert is_list(body(conn))
    end

    # Registrations are a sub-resource of the domain: an unserved domain is a 404 on
    # the collection itself, not an empty list.
    test "GET /domains/:domain/registrations on an unserved domain → 404" do
      conn = call(conn(:get, "/domains/ghost.example.org/registrations"))
      assert conn.status == 404
      assert body(conn)["error"] == "not found"
    end

    test "GET /domains/:domain/registrations/:aor on an unregistered aor → 404" do
      conn = call(conn(:get, "/domains/ghost.example.org/registrations/alice"))
      assert conn.status == 404
    end

    test "GET /domains returns a JSON list" do
      conn = call(conn(:get, "/domains"))
      assert conn.status == 200
      assert is_list(body(conn))
    end

    test "GET /mediaservers returns a JSON list; :name serves one entry" do
      :ok = Supervisor.terminate_child(Kelix.Supervisor, Kelix.MediaPool)
      on_exit(fn -> Supervisor.restart_child(Kelix.Supervisor, Kelix.MediaPool) end)

      start_supervised!(
        {Kelix.MediaPool,
         pool: [%{name: "mcu1", module: :mockup, url: "http://10.0.0.1:8080", enabled: true}],
         probe: fn _ -> true end,
         first_check_ms: 60_000}
      )

      conn = call(conn(:get, "/mediaservers"))
      assert conn.status == 200
      assert [%{"name" => "mcu1", "module" => "mockup", "enabled" => true}] = body(conn)

      conn = call(conn(:get, "/mediaservers/mcu1"))
      assert conn.status == 200
      assert body(conn)["url"] == "http://10.0.0.1:8080"

      conn = call(conn(:get, "/mediaservers/ghost"))
      assert conn.status == 404
      assert body(conn)["error"] == "not found"
    end

    test "GET /domains/:name serves the same view kelictl shows" do
      Kelix.Test.Fixtures.serve_domains(
        ~s([[domain]]\nname = "api.example.com"\n\n[domain.registrar]\nscript = "r.exs"\n)
      )

      conn = call(conn(:get, "/domains/api.example.com"))
      assert conn.status == 200
      assert %{"name" => "api.example.com", "functions" => ["registrar"]} = body(conn)

      # …and the domain's registrations are a sub-resource of it (no registrar
      # module loaded here, so the list is empty rather than absent)
      conn = call(conn(:get, "/domains/api.example.com/registrations"))
      assert conn.status == 200
      assert body(conn) == %{"domain" => "api.example.com", "registrations" => []}
    end

    test "GET /domains/:name on an unknown domain is a 404" do
      conn = call(conn(:get, "/domains/ghost.example.org"))
      assert conn.status == 404
    end
  end

  describe "write verbs" do
    test "POST /scenarios/:id/shutdown on an unknown id → 404" do
      conn = call(conn(:post, "/scenarios/999999/shutdown"))
      assert conn.status == 404
    end

    test "POST /scenarios/:id/shutdown with a non-integer id → 400" do
      conn = call(conn(:post, "/scenarios/abc/shutdown"))
      assert conn.status == 400
    end

    test "DELETE /domains/:domain/registrations/:aor on an unknown aor → 404" do
      conn = call(conn(:delete, "/domains/example.com/registrations/ghost"))
      assert conn.status == 404
      assert body(conn)["error"] == "not found"
    end

    test "POST /scripts/reload reports a per-name result" do
      conn =
        conn(:post, "/scripts/reload", Jason.encode!(%{names: ["does-not-exist"]}))
        |> put_req_header("content-type", "application/json")
        |> call()

      assert conn.status == 200
      assert Map.has_key?(body(conn), "does-not-exist")
    end

    test "POST /scripts/reload without names → 400" do
      conn =
        conn(:post, "/scripts/reload", Jason.encode!(%{}))
        |> put_req_header("content-type", "application/json")
        |> call()

      assert conn.status == 400
    end

    test "POST /domains/reload without a configured path → 400" do
      prev = Application.get_env(:kelixip, :domains_path)
      Application.delete_env(:kelixip, :domains_path)
      on_exit(fn -> if prev, do: Application.put_env(:kelixip, :domains_path, prev) end)

      conn = call(conn(:post, "/domains/reload"))
      assert conn.status == 400
      assert body(conn)["error"] == "no_domains_path"
    end

    # The umbrella reload: the body is the per-stage report either way, so a client can
    # tell what was applied from what was refused.
    test "POST /reload-all reports every stage, and 400s on a refusal" do
      prev = Application.get_env(:kelixip, :domains_path)

      on_exit(fn ->
        if prev,
          do: Application.put_env(:kelixip, :domains_path, prev),
          else: Application.delete_env(:kelixip, :domains_path)
      end)

      # written but not reloaded: POST /reload-all is the subject, so it loads it
      %{path: path} =
        Kelix.Test.Fixtures.write_domains("""
        [[domain]]
        name = "apiall.example.com"

        [domain.registrar]
        script = "#{Path.join(__DIR__, "support/scripts/valid_registrar.exs")}"
        """)

      Application.put_env(:kelixip, :domains_path, path)

      conn = call(conn(:post, "/reload-all"))
      assert conn.status == 200
      report = body(conn)
      assert report["domains"] == "ok"
      assert is_integer(report["version"])
      assert is_map(report["scripts"])
      assert is_map(report["modules"])

      # a script the node refuses: 400, and the report names it — nothing was applied
      File.write!(path, """
      [[domain]]
      name = "apiall.example.com"

      [domain.registrar]
      script = "#{Path.join(__DIR__, "support/scripts/no_shutdown.exs")}"
      """)

      conn = call(conn(:post, "/reload-all"))
      assert conn.status == 400
      report = body(conn)
      assert ["error", message] = report["domains"]
      assert message =~ "cooperative shutdown"
      assert report["scripts"] == %{}
    end

    test "POST /mediaservers/:name toggles; unknown MCU → 404" do
      conn =
        conn(:post, "/mediaservers/ghost", Jason.encode!(%{enabled: false}))
        |> put_req_header("content-type", "application/json")
        |> call()

      assert conn.status == 404
      assert body(conn)["error"] == "unknown"
    end

    test "POST /mediaservers/:name without enabled → 400" do
      conn =
        conn(:post, "/mediaservers/ghost", Jason.encode!(%{}))
        |> put_req_header("content-type", "application/json")
        |> call()

      assert conn.status == 400
    end

    test "PUT /log/level applies a valid level and rejects a bad one" do
      prev = Logger.level()
      on_exit(fn -> Logger.configure(level: prev) end)

      conn =
        conn(:put, "/log/level", Jason.encode!(%{level: "debug"}))
        |> put_req_header("content-type", "application/json")
        |> call()

      assert conn.status == 200
      assert Logger.level() == :debug

      bad =
        conn(:put, "/log/level", Jason.encode!(%{level: "nope"}))
        |> put_req_header("content-type", "application/json")
        |> call()

      assert bad.status == 400
      assert body(bad)["error"] == "invalid_level"
    end

    test "POST /graceful-shutdown drains without stopping the VM" do
      Application.put_env(:kelixip, :graceful_stop, false)
      # Same arrangement Kelix.ControlTest makes for the same verb, which this test
      # was missing both halves of. `drain_wait_ms` defaults to 5 s, so leaving it
      # alone left a Task asleep that woke up long after this test to call
      # InstancePool.shutdown_all/1 on whatever was running by then; and `draining`
      # is a global that nothing here put back, so the node stayed out of rotation
      # for the rest of the suite and the next drain-sensitive test paid for it —
      # Kelix.OptionsTest reading 503 where it expects 200, or ControlTest's own
      # drain test failing on its opening `refute draining?`. Which one failed just
      # depended on the order ExUnit picked.
      Application.put_env(:kelixip, :drain_wait_ms, 0)

      on_exit(fn ->
        Application.delete_env(:kelixip, :graceful_stop)
        Application.delete_env(:kelixip, :drain_wait_ms)
        Kelix.Control.undrain()
      end)

      conn = call(conn(:post, "/graceful-shutdown"))
      assert conn.status == 202
      assert body(conn)["result"] == "draining"

      # the point of the verb, and asserting it is what makes the cleanup above
      # obviously necessary rather than something to forget again
      assert Kelix.Control.draining?()
    end

    test "POST /modules/:name/reload on an unconfigured module → 400" do
      conn = call(conn(:post, "/modules/registrar/reload"))
      assert conn.status == 400
      assert body(conn)["error"] == "not_configured"
    end
  end

  describe "module-contributed commands" do
    defmodule FakeCtl do
      def handle_control("ping", _args), do: {:ok, :pong}
      def handle_control(_cmd, _args), do: {:error, :unknown_cmd}
    end

    setup do
      Kelix.Test.Fixtures.with_module("fake", FakeCtl)

      Kelix.Control.Registry.register("fake", [
        %{name: "ping", args: [], rest: {:post, "/ping"}, rw: :r, help: "ping"}
      ])

      on_exit(fn -> Kelix.Control.Registry.deregister("fake") end)

      :ok
    end

    test "POST /modules/fake/ping routes to handle_control/2" do
      conn = call(conn(:post, "/modules/fake/ping"))
      assert conn.status == 200
      assert body(conn)["result"] == "pong"
    end

    test "a declared command reached with the wrong method → 405" do
      conn = call(conn(:get, "/modules/fake/ping"))
      assert conn.status == 405
    end

    test "an undeclared module command → 404" do
      conn = call(conn(:post, "/modules/fake/nope"))
      assert conn.status == 404
      assert body(conn)["error"] == "unknown module command"
    end

    # FW-5: the declarations are readable at runtime, so a client discovers the
    # routes instead of being handed them out of band. `GET /modules/fake` must not
    # be swallowed by the `/modules/:name/*path` glob that serves the commands.
    test "GET /modules lists what each loaded module contributes" do
      conn = call(conn(:get, "/modules"))
      assert conn.status == 200

      assert %{
               "fake" => %{
                 "commands" => [command],
                 "module" => "Elixir.Kelix.ControlAPITest.FakeCtl"
               }
             } =
               body(conn)

      assert command["name"] == "ping"
      assert command["methods"] == ["post"]
      assert command["path"] == "/ping"
    end

    test "GET /modules/:name is one module's surface, 404 when not loaded" do
      conn = call(conn(:get, "/modules/fake"))
      assert conn.status == 200
      assert body(conn)["name"] == "fake"
      assert length(body(conn)["commands"]) == 1

      conn = call(conn(:get, "/modules/ghost"))
      assert conn.status == 404
    end
  end

  describe "unknown route" do
    test "→ 404" do
      conn = call(conn(:get, "/nope"))
      assert conn.status == 404
    end
  end

  describe "auth middleware" do
    test "token mode: missing bearer → 401, valid bearer → 200" do
      Application.put_env(:kelixip, :control_api, %{auth: "token", token: "s3cret"})

      denied = call(conn(:get, "/status"))
      assert denied.status == 401

      ok =
        conn(:get, "/status")
        |> put_req_header("authorization", "Bearer s3cret")
        |> call()

      assert ok.status == 200
    end

    test "token mode: wrong token → 401" do
      Application.put_env(:kelixip, :control_api, %{auth: "token", token: "s3cret"})

      conn =
        conn(:get, "/status")
        |> put_req_header("authorization", "Bearer wrong")
        |> call()

      assert conn.status == 401
    end

    test "none mode: no credential required" do
      Application.put_env(:kelixip, :control_api, %{auth: "none"})
      assert call(conn(:get, "/status")).status == 200
    end

    test "mtls mode without a client cert → 403" do
      Application.put_env(:kelixip, :control_api, %{auth: "mtls"})
      assert call(conn(:get, "/status")).status == 403
    end
  end
end
