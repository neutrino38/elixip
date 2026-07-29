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

    test "DELETE /registrations/:aor on an unknown aor → 404" do
      conn = call(conn(:delete, "/registrations/ghost@example.com"))
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
      on_exit(fn -> Application.delete_env(:kelixip, :graceful_stop) end)

      conn = call(conn(:post, "/graceful-shutdown"))
      assert conn.status == 202
      assert body(conn)["result"] == "draining"
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
      Kelix.ModuleRegistry.register("fake", FakeCtl, %{})

      Kelix.Control.Registry.register("fake", [
        %{name: "ping", args: [], rest: {:post, "/ping"}, rw: :r, help: "ping"}
      ])

      on_exit(fn ->
        Kelix.ModuleRegistry.unregister("fake")
        Kelix.Control.Registry.deregister("fake")
      end)

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
