defmodule Kelix.ControlAPIDomainsTest do
  # The domain edit routes of the REST frontal (docs/design/dynamic-domains-plan.md
  # §5). async: false — Kelix.Domains, the pool and the script registry are
  # singletons.
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog
  import Plug.Test
  import Plug.Conn

  @opts Kelix.ControlAPI.init([])

  @initial """
  [[domain]]
  name = "first.example"
  aliases = ["alias.example"]
  """

  setup do
    %{dir: dir, path: path} = Kelix.Test.Fixtures.serve_domains(@initial)
    Kelix.Test.Fixtures.with_script_dir(Path.join(__DIR__, "support/scripts"))

    prev_path = Application.get_env(:kelixip, :domains_path)
    prev_api = Application.get_env(:kelixip, :control_api)
    Application.put_env(:kelixip, :domains_path, path)
    Application.put_env(:kelixip, :control_api, %{auth: "none"})

    on_exit(fn ->
      File.chmod(dir, 0o755)
      File.chmod(path, 0o644)
      restore(:domains_path, prev_path)
      restore(:control_api, prev_api)
    end)

    %{dir: dir, path: path}
  end

  defp restore(key, nil), do: Application.delete_env(:kelixip, key)
  defp restore(key, value), do: Application.put_env(:kelixip, key, value)

  @s "domain_waiter.exs"

  # Each write is its own request; the log is not the subject here.
  defp send_req(method, path, body, headers \\ []) do
    conn =
      case body do
        nil ->
          conn(method, path)

        body ->
          conn(method, path, Jason.encode!(body))
          |> put_req_header("content-type", "application/json")
      end

    conn = Enum.reduce(headers, conn, fn {k, v}, c -> put_req_header(c, k, v) end)
    {conn, _log} = with_log(fn -> Kelix.ControlAPI.call(conn, @opts) end)
    {conn.status, Jason.decode!(conn.resp_body), conn}
  end

  defp req(method, path, body \\ nil) do
    {status, body, _conn} = send_req(method, path, body)
    {status, body}
  end

  defp show(name) do
    {200, d} = req(:get, "/domains/#{name}")
    d
  end

  defp version(), do: Kelix.Domains.current().version

  describe "editing a domain one element at a time" do
    test "create, then functions and rules, read back by GET /domains/<d>" do
      {201, %{"result" => %{"name" => "new.example", "version" => v}}, conn} =
        send_req(:post, "/domains", %{
          "name" => "new.example",
          "aliases" => ["n2.example"],
          "max_calls" => 5
        })

      assert get_resp_header(conn, "location") == ["/domains/new.example"]
      assert v == version()

      assert {200, _} = req(:patch, "/domains/new.example/registrar", %{"script" => @s})

      assert {201, %{"result" => %{"at" => 1}}} =
               req(:post, "/domains/new.example/calls", %{"pattern" => "default", "script" => @s})

      assert {201, %{"result" => %{"at" => 1}}} =
               req(:post, "/domains/new.example/calls", %{"pattern" => "1XXX", "script" => @s})

      {201, %{"result" => %{"at" => 2}}, conn} =
        send_req(:post, "/domains/new.example/calls", %{"pattern" => "2XXX", "script" => @s})

      assert get_resp_header(conn, "location") == ["/domains/new.example/calls/2"]

      assert {201, _} =
               req(:post, "/domains/new.example/chat", %{
                 "pattern" => "default",
                 "script" => @s,
                 "idle_timeout" => 60
               })

      assert {200, _} = req(:put, "/domains/new.example/options/keepalive", %{"script" => @s})

      assert {201, %{"result" => %{"at" => 1}}} =
               req(:post, "/domains/new.example/options", %{"pattern" => "conf-.", "script" => @s})

      {201, _, conn} =
        send_req(:post, "/domains/new.example/presence", %{
          "package" => "presence",
          "subscribe" => @s
        })

      assert get_resp_header(conn, "location") == ["/domains/new.example/presence/presence"]

      assert {201, %{"result" => %{"at" => 1}}} =
               req(:post, "/domains/new.example/presence/presence/subscribe", %{
                 "pattern" => "rls",
                 "script" => @s
               })

      d = show("new.example")
      assert d["aliases"] == ["n2.example"]
      assert d["max_calls"] == 5
      assert d["version"] == version()
      assert Enum.map(d["dial_plan"], & &1["pattern"]) == ["1XXX", "2XXX", nil]
      assert [%{"default" => true}] = d["chat"]
      assert d["options_keepalive"]["script"] == @s
      assert [%{"pattern" => "conf-."}] = d["options"]

      assert [
               %{
                 "event_package" => "presence",
                 "subscribe" => [%{"pattern" => "rls"}, %{"default" => true}]
               }
             ] =
               d["presence"]
    end

    test "update, move and remove address a rule by its number" do
      for p <- ["default", "1XXX", "2XXX"],
          do:
            {201, _} =
              req(:post, "/domains/first.example/calls", %{"pattern" => p, "script" => @s})

      assert {200, _} =
               req(:patch, "/domains/first.example/calls/2", %{"pattern" => "3XXX"})

      assert {200, _} = req(:post, "/domains/first.example/calls/2/move", %{"to" => 1})

      assert Enum.map(show("first.example")["dial_plan"], & &1["pattern"]) == [
               "3XXX",
               "1XXX",
               nil
             ]

      assert {200, _} = req(:delete, "/domains/first.example/calls/1")
      assert Enum.map(show("first.example")["dial_plan"], & &1["pattern"]) == ["1XXX", nil]

      # the catch-all stays last: the parser refuses the move, as it refuses the file
      assert {400, %{"error" => "invalid"}} =
               req(:post, "/domains/first.example/calls/2/move", %{"to" => 1})
    end

    test "PATCH sets and `none` removes a key; aliases, registrar, presence and keepalive go" do
      assert {200, _} = req(:patch, "/domains/first.example", %{"max_calls" => 7})
      assert show("first.example")["max_calls"] == 7
      assert {200, _} = req(:patch, "/domains/first.example", %{"max_calls" => "none"})
      assert show("first.example")["max_calls"] == nil

      {201, _, conn} = send_req(:post, "/domains/first.example/aliases", %{"host" => "b.example"})
      assert get_resp_header(conn, "location") == ["/domains/first.example/aliases/b.example"]
      assert {200, _} = req(:delete, "/domains/first.example/aliases/alias.example")
      assert show("first.example")["aliases"] == ["b.example"]

      assert {200, _} = req(:patch, "/domains/first.example/registrar", %{"script" => @s})
      assert {200, _} = req(:delete, "/domains/first.example/registrar")
      assert show("first.example")["registrar"] == nil

      assert {201, _} =
               req(:post, "/domains/first.example/presence", %{
                 "package" => "dialog",
                 "subscribe" => @s
               })

      assert {200, _} =
               req(:patch, "/domains/first.example/presence/dialog", %{"publish" => @s})

      assert [%{"publish" => %{"script" => @s}}] = show("first.example")["presence"]
      assert {200, _} = req(:delete, "/domains/first.example/presence/dialog")
      assert show("first.example")["presence"] == []

      assert {200, _} = req(:put, "/domains/first.example/options/keepalive", %{"script" => @s})
      assert {200, _} = req(:delete, "/domains/first.example/options/keepalive")
      assert show("first.example")["options_keepalive"] == nil
    end

    test "DELETE /domains/<d> says how many scenarios it stopped and what each purge did" do
      log =
        capture_log(fn ->
          conn =
            conn(:delete, "/domains/first.example")
            |> put_req_header("x-kelix-admin", "alice")
            |> Kelix.ControlAPI.call(@opts)

          assert conn.status == 200

          assert Jason.decode!(conn.resp_body)["result"] == %{
                   "name" => "first.example",
                   "version" => version(),
                   "stopped" => 0,
                   "purged" => %{"presence" => "not_loaded", "registrar" => "not_loaded"}
                 }
        end)

      assert log =~ "domain delete first.example by admin=alice"
      assert {404, _} = req(:get, "/domains/first.example")
    end

    test "the X-Kelix-Admin header names who asked, in the node's log" do
      log =
        capture_log(fn ->
          conn(:patch, "/domains/first.example", Jason.encode!(%{"max_calls" => 3}))
          |> put_req_header("content-type", "application/json")
          |> put_req_header("x-kelix-admin", "bob")
          |> Kelix.ControlAPI.call(@opts)
        end)

      assert log =~ "domain set first.example by admin=bob"
    end
  end

  describe "refusals" do
    test "404 for an unknown domain, alias, package or rule number" do
      assert {404, %{"error" => "not_found"}} = req(:delete, "/domains/ghost.example")
      assert {404, _} = req(:patch, "/domains/ghost.example", %{"max_calls" => 2})
      assert {404, _} = req(:delete, "/domains/first.example/aliases/nope.example")
      assert {404, _} = req(:delete, "/domains/first.example/presence/dialog")
      assert {404, _} = req(:delete, "/domains/first.example/calls/1")
      assert {404, _} = req(:delete, "/domains/first.example/presence/dialog/subscribe/1")
      # a list the domain cannot have is no route at all
      assert {404, %{"error" => "not found"}} = req(:post, "/domains/first.example/dialplan", %{})
    end

    test "409 for a name or an alias that already exists" do
      assert {409, %{"error" => "exists"}} = req(:post, "/domains", %{"name" => "first.example"})

      assert {409, %{"error" => "exists"}} =
               req(:post, "/domains/first.example/aliases", %{"host" => "alias.example"})
    end

    test "400 with the parser's message for an invalid argument" do
      assert {400, %{"error" => "invalid", "message" => msg}} =
               req(:patch, "/domains/first.example", %{"max_calls" => -1})

      assert msg =~ "max_calls"

      assert {400, %{"error" => "invalid", "message" => "unknown argument(s): colour"}} =
               req(:patch, "/domains/first.example", %{"colour" => "red"})

      assert {400, %{"message" => "the body needs `name`, a non-empty string"}} =
               req(:post, "/domains", %{})

      assert {400, %{"message" => "unknown argument(s): extra"}} =
               req(:post, "/domains/first.example/aliases", %{"host" => "b.example", "extra" => 1})

      assert {400, %{"message" => "unknown argument(s): from"}} =
               req(:post, "/domains/first.example/calls/1/move", %{"to" => 1, "from" => 2})

      assert {400, %{"message" => "`version` must be a positive integer"}} =
               req(:patch, "/domains/first.example?version=x", %{"max_calls" => 2})
    end

    test "400 for a script the node cannot serve, and nothing is written", %{path: path} do
      before = File.read!(path)

      assert {400, %{"error" => "scripts"}} =
               req(:post, "/domains/first.example/calls", %{
                 "pattern" => "default",
                 "script" => "missing.exs"
               })

      assert File.read!(path) == before
    end

    test "409 conflict for a stale version, in the body or the query string" do
      v = version()

      assert {201, _} =
               req(:post, "/domains/first.example/calls", %{
                 "pattern" => "default",
                 "script" => @s
               })

      assert {409, %{"error" => "conflict"}} =
               req(:delete, "/domains/first.example/calls/1?version=#{v}")

      assert {409, %{"error" => "conflict"}} =
               req(:post, "/domains/first.example/calls/1/move", %{"to" => 1, "version" => v})

      assert {200, _} = req(:delete, "/domains/first.example/calls/1?version=#{version()}")
    end

    test "409 file_changed after a hand edit not reloaded", %{path: path} do
      File.write!(path, File.read!(path) <> "# by hand\n")

      assert {409, %{"error" => "file_changed", "message" => msg}} =
               req(:patch, "/domains/first.example", %{"max_calls" => 2})

      assert msg =~ "POST /domains/reload"
    end

    test "503 read_only names the path, the reason and the user", %{dir: dir, path: path} do
      File.chmod!(path, 0o444)
      File.chmod!(dir, 0o555)

      assert {503,
              %{
                "error" => "read_only",
                "path" => ^path,
                "reason" => "eacces",
                "user" => user,
                "message" => msg
              }} =
               req(:patch, "/domains/first.example", %{"max_calls" => 2})

      assert is_binary(user)
      assert msg =~ "Nothing was applied."
    end
  end

  describe "GET /status" do
    test "says whether the file was edited by hand and not reloaded", %{path: path} do
      assert {200, %{"domains_file_changed" => false, "domains_writable" => true}} =
               req(:get, "/status")

      File.write!(path, File.read!(path) <> "# by hand\n")
      assert {200, %{"domains_file_changed" => true}} = req(:get, "/status")

      assert {200, _} = req(:post, "/domains/reload")
      assert {200, %{"domains_file_changed" => false}} = req(:get, "/status")
    end
  end

  describe "token auth" do
    setup do
      Application.put_env(:kelixip, :control_api, %{auth: "token", token: "s3cret"})
      :ok
    end

    test "a write without the bearer token is refused and applies nothing", %{path: path} do
      before = File.read!(path)

      assert {401, _} = req(:post, "/domains", %{"name" => "new.example"})
      assert {401, _} = req(:delete, "/domains/first.example")
      assert File.read!(path) == before

      assert {201, _, _} =
               send_req(:post, "/domains", %{"name" => "new.example"}, [
                 {"authorization", "Bearer s3cret"}
               ])

      assert {:ok, _} = Kelix.Control.domain("new.example")
    end
  end
end
