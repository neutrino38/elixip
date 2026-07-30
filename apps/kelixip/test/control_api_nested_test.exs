defmodule Kelix.ControlAPINestedTest do
  # FW-4: nested resource routes for module commands (docs/design/mcu_module.md
  # §8.3.4), driven through the real Plug pipeline with Plug.Test conns.
  use ExUnit.Case, async: false
  import Plug.Test
  import Plug.Conn

  @opts Kelix.ControlAPI.init([])

  # A module whose commands cover the whole FW-4 surface: a creation with
  # 201 + Location + declared errors, a nested collection and item, a
  # PUT/PATCH pair, and a literal-vs-param pair to resolve.
  defmodule NestedCtl do
    def describe_control() do
      [
        %{
          name: "conference.create",
          rest: {:post, "/conferences"},
          status: 201,
          location: "/conferences/:uid",
          errors: %{did_in_use: 400, no_did_available: 409},
          rw: :w,
          args: [],
          help: "create"
        },
        %{name: "conference.list", rest: {:get, "/conferences"}, rw: :r, args: [], help: "list"},
        %{
          name: "conference.show",
          rest: {:get, "/conferences/:uid"},
          errors: %{not_found: 404},
          rw: :r,
          args: [],
          help: "show"
        },
        %{
          name: "conference.update",
          rest: {[:put, :patch], "/conferences/:uid"},
          rw: :w,
          args: [],
          help: "update"
        },
        %{
          name: "conference.stats",
          rest: {:get, "/conferences/stats"},
          rw: :r,
          args: [],
          help: "the literal that must win over :uid"
        },
        %{
          name: "participant.list",
          rest: {:get, "/conferences/:uid/participants"},
          rw: :r,
          args: [],
          help: "participants"
        }
      ]
    end

    # every command echoes back the args it received, so a test can assert on the
    # merged map exactly as handle_control/2 sees it
    def handle_control("conference.create", args) do
      case args["did"] do
        "dup" -> {:error, :did_in_use}
        "full" -> {:error, :no_did_available}
        "boom" -> {:error, :something_else}
        # the result carries `uid`, which is what the Location template needs
        _ -> {:ok, %{uid: "c-3f9a", did: "8001", args: args}}
      end
    end

    def handle_control("conference.show", args) do
      case args["uid"] do
        "ghost" -> {:error, :not_found}
        uid -> {:ok, %{uid: uid, args: args}}
      end
    end

    # no `uid` in the result: the frontal must omit Location rather than guess
    def handle_control("conference.list", args), do: {:ok, %{cmd: "list", args: args}}
    def handle_control(cmd, args), do: {:ok, %{cmd: cmd, args: args}}
  end

  setup do
    prev = Application.get_env(:kelixip, :control_api)
    Application.put_env(:kelixip, :control_api, %{auth: "none"})

    Kelix.ModuleRegistry.register("nested", NestedCtl, %{})
    :ok = Kelix.Control.Registry.register("nested", NestedCtl.describe_control())

    on_exit(fn ->
      Kelix.ModuleRegistry.unregister("nested")
      Kelix.Control.Registry.deregister("nested")

      if prev,
        do: Application.put_env(:kelixip, :control_api, prev),
        else: Application.delete_env(:kelixip, :control_api)
    end)

    :ok
  end

  defp call(conn), do: Kelix.ControlAPI.call(conn, @opts)
  defp body(conn), do: Jason.decode!(conn.resp_body)
  defp result(conn), do: body(conn)["result"]

  defp json_conn(method, path, params) do
    conn(method, path, Jason.encode!(params))
    |> put_req_header("content-type", "application/json")
  end

  describe "template resolution" do
    test "a nested collection routes and merges its path param" do
      conn = call(conn(:get, "/modules/nested/conferences/c-1/participants"))
      assert conn.status == 200
      assert result(conn)["cmd"] == "participant.list"
      assert result(conn)["args"] == %{"uid" => "c-1"}
    end

    test "an item route captures :uid" do
      conn = call(conn(:get, "/modules/nested/conferences/c-1"))
      assert conn.status == 200
      assert result(conn)["uid"] == "c-1"
    end

    test "most-literal-first: /conferences/stats wins over /conferences/:uid" do
      conn = call(conn(:get, "/modules/nested/conferences/stats"))
      assert conn.status == 200
      assert result(conn)["cmd"] == "conference.stats"
    end

    test "a path matching no template → 404" do
      assert call(conn(:get, "/modules/nested/conferences/c-1/mosaics")).status == 404
      assert call(conn(:get, "/modules/nested/nope")).status == 404
    end

    test "reserved sub-resources answer 404 until they are implemented" do
      for path <- ["mosaics", "mosaics/0", "mixers", "mixers/0", "listeners"] do
        conn = call(conn(:get, "/modules/nested/conferences/c-1/#{path}"))
        assert conn.status == 404, "#{path} should be reserved, not half-working"
      end
    end

    test "an unknown module → 404" do
      assert call(conn(:get, "/modules/ghost/conferences")).status == 404
    end
  end

  describe "methods" do
    test "one declaration answers both PUT and PATCH" do
      for method <- [:put, :patch] do
        conn = call(json_conn(method, "/modules/nested/conferences/c-1", %{name: "Weekly"}))
        assert conn.status == 200
        assert result(conn)["cmd"] == "conference.update"
        assert result(conn)["args"] == %{"uid" => "c-1", "name" => "Weekly"}
      end
    end

    test "a path matching a template but not its method → 405 + Allow" do
      conn = call(conn(:delete, "/modules/nested/conferences/c-1"))
      assert conn.status == 405
      allow = conn |> get_resp_header("allow") |> List.first()
      # the sibling declarations on that path: GET (show), PUT/PATCH (update)
      assert allow =~ "GET"
      assert allow =~ "PUT"
      assert allow =~ "PATCH"
      refute allow =~ "DELETE"
    end
  end

  describe "arg merging (path < query < body)" do
    test "query params reach handle_control/2 (FW-2)" do
      conn = call(conn(:get, "/modules/nested/conferences?domain=example.com&did=8001"))
      assert conn.status == 200
      assert result(conn)["args"] == %{"domain" => "example.com", "did" => "8001"}
    end

    test "the body wins over the query" do
      conn =
        call(
          json_conn(:put, "/modules/nested/conferences/c-1?name=fromquery", %{name: "frombody"})
        )

      assert result(conn)["args"]["name"] == "frombody"
    end

    test "a body key colliding with a path param → 400 path_conflict" do
      conn = call(json_conn(:put, "/modules/nested/conferences/c-1", %{uid: "c-2"}))
      assert conn.status == 400
      assert body(conn)["error"] == "path_conflict"
      assert body(conn)["detail"] == "uid"
    end

    test "a body repeating the same value is not a conflict" do
      conn = call(json_conn(:put, "/modules/nested/conferences/c-1", %{uid: "c-1"}))
      assert conn.status == 200
    end
  end

  describe "declared status / Location / errors" do
    test "a creation answers 201 with a rendered Location" do
      conn = call(json_conn(:post, "/modules/nested/conferences", %{domain: "example.com"}))
      assert conn.status == 201
      assert get_resp_header(conn, "location") == ["/modules/nested/conferences/c-3f9a"]
      assert result(conn)["did"] == "8001"
    end

    test "declared error reasons map to their status" do
      assert call(json_conn(:post, "/modules/nested/conferences", %{did: "dup"})).status == 400
      assert call(json_conn(:post, "/modules/nested/conferences", %{did: "full"})).status == 409
    end

    test "an undeclared error reason falls back to 400" do
      conn = call(json_conn(:post, "/modules/nested/conferences", %{did: "boom"}))
      assert conn.status == 400
      assert body(conn)["error"] == "something_else"
    end

    test ":not_found declared as 404" do
      conn = call(conn(:get, "/modules/nested/conferences/ghost"))
      assert conn.status == 404
      assert body(conn)["error"] == "not_found"
    end

    test "no Location header when the command declares none" do
      conn = call(conn(:get, "/modules/nested/conferences"))
      assert conn.status == 200
      assert get_resp_header(conn, "location") == []
    end
  end

  describe "regressions (§8.3.5)" do
    test "the flat form of a nested command dispatches to the same clause" do
      flat = call(json_conn(:post, "/modules/nested/conference.create", %{domain: "example.com"}))
      canonical = call(json_conn(:post, "/modules/nested/conferences", %{domain: "example.com"}))

      assert flat.status == canonical.status
      assert body(flat) == body(canonical)
      assert get_resp_header(flat, "location") == get_resp_header(canonical, "location")
    end

    test "the flat form still honours the declared method" do
      assert call(conn(:get, "/modules/nested/conference.create")).status == 405
    end

    test "a pre-FW-4 single-segment command routes unchanged" do
      Kelix.ModuleRegistry.register("legacy", NestedCtl, %{})

      :ok =
        Kelix.Control.Registry.register("legacy", [
          %{name: "ping", args: [], rest: {:post, "/ping"}, rw: :r, help: "ping"}
        ])

      on_exit(fn ->
        Kelix.ModuleRegistry.unregister("legacy")
        Kelix.Control.Registry.deregister("legacy")
      end)

      conn = call(conn(:post, "/modules/legacy/ping"))
      assert conn.status == 200
      assert result(conn)["cmd"] == "ping"
      # and the pre-FW-4 405/404 behaviours are untouched
      assert call(conn(:get, "/modules/legacy/ping")).status == 405
      assert call(conn(:post, "/modules/legacy/nope")).status == 404
    end

    test "the fixed config-reload route still wins over the generic resolver" do
      conn = call(conn(:post, "/modules/nested/reload"))
      # Kelix.ModuleSupervisor.reload/1 on a module absent from config.toml
      assert conn.status == 400
      assert body(conn)["error"] == "not_configured"
    end
  end

  describe "registration-time conflict refusal" do
    test "an ambiguous command set registers nothing" do
      commands = [
        %{name: "a", args: [], rest: {:get, "/x/:uid"}, rw: :r, help: ""},
        %{name: "b", args: [], rest: {:get, "/x/:did"}, rw: :r, help: ""}
      ]

      assert {:error, {:ambiguous_templates, "a", "b"}} =
               Kelix.Control.Registry.register("ambiguous", commands)

      assert Kelix.Control.Registry.commands_for("ambiguous") == []
    end
  end
end
