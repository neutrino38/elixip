defmodule Kelix.DomainsWriteTest do
  # async: false — Kelix.Domains, the pool and the script registry are singletons.
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog

  alias Kelix.{Control, Domains, InstancePool, Router}

  @initial """
  [[domain]]
  name = "first.example"

  [[domain]]
  name = "second.example"
  aliases = ["alias.example"]

  [module.registrar]
  default_expires = 3600
  """

  setup do
    %{dir: dir, path: path} = Kelix.Test.Fixtures.serve_domains(@initial)
    # the scripts the rest of the suite loads, from the same path: the registry
    # refuses a second file defining the same module
    Kelix.Test.Fixtures.with_script_dir(Path.join(__DIR__, "support/scripts"))

    prev = Application.get_env(:kelixip, :domains_path)
    Application.put_env(:kelixip, :domains_path, path)

    on_exit(fn ->
      File.chmod(dir, 0o755)
      File.chmod(path, 0o644)

      if prev,
        do: Application.put_env(:kelixip, :domains_path, prev),
        else: Application.delete_env(:kelixip, :domains_path)

      for row <- Control.monitor(),
          String.ends_with?(row.domain, ".example"),
          do: Control.shutdown_scenario(row.id)
    end)

    %{dir: dir, path: path}
  end

  defp doc(name, extra \\ %{}),
    do: Map.merge(%{"name" => name, "registrar" => %{"script" => "domain_waiter.exs"}}, extra)

  defp names(), do: Enum.map(Domains.current().domains, & &1.name)

  defp register(domain),
    do: %{method: :REGISTER, ruri: %SIP.Uri{userpart: "bob", domain: domain}}

  defp await_down(pid) do
    ref = Process.monitor(pid)
    assert_receive {:DOWN, ^ref, :process, ^pid, _}, 2_000
  end

  describe "put_domain/2" do
    test "creates a domain at the end, which then routes to its script", %{path: path} do
      capture_log(fn ->
        assert {:ok, %{name: "new.example", created: true, version: v}} =
                 Control.put_domain(doc("new.example"), actor: "alice")

        assert Domains.current().version == v
      end)

      assert names() == ["first.example", "second.example", "new.example"]
      assert File.read!(path) =~ ~s(name = "new.example")

      capture_log(fn ->
        assert {:accept, pid} = Router.dispatch(nil, register("new.example"))

        assert %{domain: "new.example", script: "domain_waiter.exs"} =
                 Enum.find(Control.monitor(), &(&1.pid == pid))
      end)
    end

    test "replaces a domain in its place, keeping the rest of the file" do
      capture_log(fn ->
        assert {:ok, %{created: false}} =
                 Control.put_domain(doc("FIRST.example", %{"max_calls" => 3}))
      end)

      assert names() == ["FIRST.example", "second.example"]
      assert hd(Domains.current().domains).max_calls == 3
      assert Domains.current().modules == %{"registrar" => %{"default_expires" => 3600}}
    end

    test "the file read back gives the same snapshot", %{path: path} do
      capture_log(fn -> {:ok, _} = Control.put_domain(doc("new.example")) end)

      {:ok, read_back} = Domains.parse(File.read!(path))
      assert read_back.source == Domains.current().source
      assert read_back.source_hash == Domains.current().source_hash
    end

    test "an invalid document or a missing script changes nothing", %{path: path} do
      before = File.read!(path)
      version = Domains.current().version

      assert {:error, {:invalid, msg}} =
               Control.put_domain(%{"name" => "x.example", "bogus" => 1})

      assert msg =~ "bogus"
      assert {:error, {:invalid, _}} = Control.put_domain(%{"aliases" => ["x"]})

      assert {:error, {:invalid, _}} =
               Control.put_domain(%{"name" => "x.example", "aliases" => ["second.example"]})

      capture_log(fn ->
        assert {:error, {:scripts, msg}} =
                 Control.put_domain(doc("x.example", %{"registrar" => %{"script" => "nope.exs"}}))

        assert msg =~ "nope.exs"
      end)

      assert File.read!(path) == before
      assert Domains.current().version == version
    end

    test "a stale version is a conflict" do
      v = Domains.current().version
      assert Control.put_domain(doc("new.example"), version: v - 1) == {:error, :conflict}
      capture_log(fn -> assert {:ok, _} = Control.put_domain(doc("new.example"), version: v) end)
    end

    test "a hand edit not reloaded blocks writes until a reload succeeds", %{path: path} do
      File.write!(path, File.read!(path) <> "\n# edited by hand\n")
      assert Control.put_domain(doc("new.example")) == {:error, :file_changed}

      # a failed reload keeps the old snapshot, and the block with it
      good = File.read!(path)
      File.write!(path, "not toml [[[")
      capture_log(fn -> assert {:error, _} = Control.reload_domains() end)
      assert Control.put_domain(doc("new.example")) == {:error, :file_changed}

      File.write!(path, good)
      capture_log(fn -> assert :ok = Control.reload_domains() end)
      capture_log(fn -> assert {:ok, _} = Control.put_domain(doc("new.example")) end)
      refute File.read!(path) =~ "edited by hand"
    end

    test "a file the node cannot write is refused, saying why and who", %{dir: dir, path: path} do
      before = File.read!(path)
      File.chmod!(path, 0o444)
      File.chmod!(dir, 0o555)

      assert {:error, {:read_only, %{path: ^path, reason: :eacces, user: user}}} =
               Control.put_domain(doc("new.example"))

      assert is_binary(user) and user != ""

      assert Domains.writable(path) ==
               {:error, {:read_only, %{path: path, reason: :eacces, user: user}}}

      # fixed without a restart
      File.chmod!(dir, 0o755)
      File.chmod!(path, 0o644)
      assert File.read!(path) == before
      assert Domains.writable(path) == :ok
      capture_log(fn -> assert {:ok, _} = Control.put_domain(doc("new.example")) end)
    end
  end

  describe "delete_domain/2" do
    test "removes the domain from the file and the router", %{path: path} do
      capture_log(fn ->
        assert {:ok, %{name: "second.example", stopped: 0, purged: purged}} =
                 Control.delete_domain("Second.Example", actor: "alice")

        # no registrar or presence module in this app: nothing held, nothing to purge
        assert purged == %{"registrar" => :not_loaded, "presence" => :not_loaded}
      end)

      assert names() == ["first.example"]
      refute File.read!(path) =~ "second.example"
      assert {:reject, 404, _} = Router.dispatch(nil, register("alias.example"))
    end

    test "an alias or an unknown name is not found" do
      assert Control.delete_domain("alias.example") == {:error, :not_found}
      assert Control.delete_domain("nowhere.example") == {:error, :not_found}
    end

    test "stops the running scenarios; a route resolved before is answered 404" do
      capture_log(fn -> {:ok, _} = Control.put_domain(doc("call.example")) end)
      stale = Domains.current()

      {:accept, pid} = Router.dispatch(nil, register("call.example"))

      capture_log(fn ->
        assert {:ok, %{stopped: 1}} = Control.delete_domain("call.example")
      end)

      await_down(pid)

      # the request the router resolved just before the delete reaches the pool now
      assert Router.dispatch(nil, register("call.example"), stale) == {:reject, 404, "Not Found"}

      # the same name created again runs
      capture_log(fn -> {:ok, _} = Control.put_domain(doc("call.example")) end)
      assert {:accept, _pid} = Router.dispatch(nil, register("call.example"))
    end
  end

  describe "a reload that removes a domain" do
    test "stops its scenarios, as a delete does", %{path: path} do
      capture_log(fn -> {:ok, _} = Control.put_domain(doc("call.example")) end)
      {:accept, pid} = Router.dispatch(nil, register("call.example"))

      text = File.read!(path)
      {:ok, map} = Toml.decode(text)
      domains = Enum.reject(map["domain"], &(&1["name"] == "call.example"))
      {:ok, without} = Kelix.Domains.Toml.encode(Map.put(map, "domain", domains))
      File.write!(path, without)

      capture_log(fn -> assert :ok = Control.reload_domains() end)
      await_down(pid)
      refute "call.example" in names()
    end
  end

  describe "export_domain/1" do
    test "gives back the document put_domain accepts, by name or alias" do
      assert {:ok, %{"name" => "second.example", "aliases" => ["alias.example"]} = d} =
               Control.export_domain("alias.example")

      capture_log(fn -> assert {:ok, %{created: false}} = Control.put_domain(d) end)
      assert Control.export_domain("nowhere.example") == {:error, :not_found}
    end
  end

  test "InstancePool.shutdown_domain/3 counts what it stops" do
    assert InstancePool.shutdown_domain("idle.example", :test, Domains.current().version) == 0
  end
end
