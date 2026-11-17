defmodule Kelix.DebugTriggersFrontalsTest do
  # The three ways an operator reaches a debug trigger (debug-triggers-plan.md,
  # T4): Kelix.Control, kelictl and the REST API — the same rule, the same
  # refusals, against the node's own store.
  use ExUnit.Case, async: false
  import Plug.Test
  import Plug.Conn
  import Kelix.Test.Fixtures

  alias Kelix.Control
  alias Kelix.Control.CLI

  @opts Kelix.ControlAPI.init([])

  setup do
    dom = "front-#{System.unique_integer([:positive])}.test"

    serve_domains("""
    [[domain]]
    name = "#{dom}"

    [domain.registrar]
    script = "reg.exs"

    [[domain.call]]
    default = true
    script = "calls/call.exs"
    """)

    prev = Application.get_env(:kelixip, :control_api)
    Application.put_env(:kelixip, :control_api, %{auth: "none"})

    on_exit(fn ->
      for s <- ["reg.exs", "calls/call.exs"], do: Control.remove_debug_trigger(dom, s)

      if prev,
        do: Application.put_env(:kelixip, :control_api, prev),
        else: Application.delete_env(:kelixip, :control_api)
    end)

    %{dom: dom}
  end

  defp run(argv), do: CLI.run(argv, node())
  defp api(conn), do: Kelix.ControlAPI.call(conn, @opts)
  defp body(conn), do: Jason.decode!(conn.resp_body)

  defp put_json(path, data, admin \\ nil) do
    conn =
      conn(:put, path, Jason.encode!(data))
      |> put_req_header("content-type", "application/json")

    conn = if admin, do: put_req_header(conn, "x-kelix-admin", admin), else: conn
    api(conn)
  end

  describe "Kelix.Control" do
    test "flat filter keys, a filter map, text counts", %{dom: dom} do
      assert {:ok, %{total: 3, filter: %{caller: "1001"}, created_by: "ops"}} =
               Control.set_debug_trigger(
                 dom,
                 "reg.exs",
                 %{"count" => "3", "duration" => "2h", "caller" => "1001"},
                 actor: "ops"
               )

      assert {:ok, %{filter: %{source: "10.0.0.0/8"}}} =
               Control.set_debug_trigger(dom, "reg.exs", %{
                 count: 1,
                 duration: "1d",
                 filter: %{"source" => "10.0.0.0/8"}
               })

      assert [%{script: "reg.exs"}] = Control.debug_triggers(dom)
      assert Control.debug_triggers("other.test") == []
    end

    test "refusals, each with its class", %{dom: dom} do
      cases = [
        {%{count: 1, duration: "1h", color: "red"}, :invalid},
        {%{count: 1, duration: "1h", caller: "a", filter: %{callee: "b"}}, :invalid},
        {%{count: "many", duration: "1h"}, :invalid},
        {%{count: 1, duration: "1w"}, :invalid}
      ]

      for {attrs, class} <- cases do
        assert {:error, reason} = Control.set_debug_trigger(dom, "reg.exs", attrs)
        assert {^class, _message} = Control.debug_trigger_error(reason), inspect(attrs)
      end

      assert {:error, reason} =
               Control.set_debug_trigger("nope.test", "reg.exs", %{count: 1, duration: "1h"})

      assert {:not_found, "no domain nope.test"} = Control.debug_trigger_error(reason)
    end

    test "domain_scripts/1", %{dom: dom} do
      assert Control.domain_scripts(dom) == {:ok, ["reg.exs", "calls/call.exs"]}
      assert Control.domain_scripts("nope.test") == {:error, :not_found}
    end
  end

  describe "kelictl debug trigger" do
    test "set, show, list, remove", %{dom: dom} do
      assert {0, out} =
               run(~w(debug trigger set #{dom} reg.exs count=5 for=2h caller=1001 --admin ops))

      assert out =~ "debug trigger set"
      assert out =~ "runs left:  5/5"
      assert out =~ "filter:     caller=1001"
      assert out =~ "set by:     ops"

      assert {0, out} = run(~w(debug trigger show #{dom} reg.exs))
      assert out =~ ~r/time left:  (1h 59m|2h 0m)/

      assert {0, out} = run(~w(debug trigger list))
      assert out =~ "runs left"

      assert out =~
               ~r/#{Regex.escape(dom)}\s+reg\.exs\s+5\/5\s+(1h 59m|2h 0m)\s+caller=1001\s+ops/

      assert {0, "debug trigger removed"} =
               run(~w(debug trigger remove #{dom} reg.exs --admin ops))

      assert {3, "error: no debug trigger on this script"} =
               run(~w(debug trigger show #{dom} reg.exs))
    end

    test "a script name with a slash", %{dom: dom} do
      assert {0, _} = run(~w(debug trigger set #{dom} calls/call.exs count=1 for=10m))
      assert {0, out} = run(~w(debug trigger list #{dom}))
      assert out =~ "calls/call.exs"
    end

    test "exit codes: invalid 2, unknown 3", %{dom: dom} do
      assert {2, out} = run(~w(debug trigger set #{dom} reg.exs count=0 for=1h))
      assert out =~ "count must be an integer from 1 to"
      assert {2, _} = run(~w(debug trigger set #{dom} reg.exs count=1 for=1h caller=a callee=b))
      assert {3, _} = run(~w(debug trigger set #{dom} nope.exs count=1 for=1h))
      assert {3, _} = run(~w(debug trigger remove #{dom} reg.exs))
      assert {2, out} = run(~w(debug trigger set #{dom} reg.exs count=1 oops))
      assert out =~ "is not name=value"
      assert {2, out} = run(~w(debug trigger frobnicate))
      assert out =~ "usage: kelictl debug trigger"
    end

    test "no rule" do
      Enum.each(Control.debug_triggers(), &Control.remove_debug_trigger(&1.domain, &1.script))
      assert {0, "no debug trigger"} = run(~w(debug trigger list))
    end

    test "help and completion", %{dom: dom} do
      assert {0, help} = run(~w(debug help))
      assert help =~ "debug trigger set <domain> <script>"
      assert help =~ "PUT /debug/triggers"

      assert {0, out} = run(["complete", "debug", ""])
      assert "trigger" in String.split(out, "\n")
      assert {0, out} = run(["complete", "debug", "trigger", ""])
      assert String.split(out, "\n") |> Enum.sort() == ~w(list remove set show)
      assert {0, out} = run(["complete", "debug", "trigger", "set", dom, ""])
      assert String.split(out, "\n") |> Enum.sort() == ["calls/call.exs", "reg.exs"]

      {:ok, _} = Control.set_debug_trigger(dom, "reg.exs", %{count: 1, duration: "1h"})
      assert {0, "reg.exs"} = run(["complete", "debug", "trigger", "remove", dom, ""])
    end
  end

  describe "REST /debug/triggers" do
    test "PUT, GET one, GET all, DELETE", %{dom: dom} do
      conn =
        put_json(
          "/debug/triggers/#{dom}/reg.exs",
          %{count: 2, duration: "1d", filter: %{callee: "1002"}},
          "ops"
        )

      assert conn.status == 200
      assert %{"result" => rule} = body(conn)
      assert %{"total" => 2, "filter" => %{"callee" => "1002"}, "created_by" => "ops"} = rule
      assert {:ok, _, _} = DateTime.from_iso8601(rule["expires_at"])

      conn = api(conn(:get, "/debug/triggers/#{dom}/reg.exs"))
      assert conn.status == 200
      assert body(conn)["remaining"] == 2

      conn = api(conn(:get, "/debug/triggers?domain=#{dom}"))
      assert [%{"script" => "reg.exs"}] = body(conn)

      conn = api(conn(:delete, "/debug/triggers/#{dom}/reg.exs"))
      assert conn.status == 204

      conn = api(conn(:get, "/debug/triggers/#{dom}/reg.exs"))
      assert conn.status == 404
      assert body(conn)["error"] == "not_found"
    end

    test "a script name with a slash is the rest of the path", %{dom: dom} do
      conn = put_json("/debug/triggers/#{dom}/calls/call.exs", %{count: 1, duration: "10m"})
      assert conn.status == 200
      assert body(conn)["result"]["script"] == "calls/call.exs"
      assert api(conn(:delete, "/debug/triggers/#{dom}/calls/call.exs")).status == 204
    end

    test "refusals: 400 with the reason, 404 for an unknown domain", %{dom: dom} do
      conn = put_json("/debug/triggers/#{dom}/reg.exs", %{count: 1, duration: "forever"})
      assert conn.status == 400
      assert %{"error" => "invalid", "message" => "duration must be" <> _} = body(conn)

      conn = put_json("/debug/triggers/nope.test/reg.exs", %{count: 1, duration: "1h"})
      assert conn.status == 404
    end
  end
end
