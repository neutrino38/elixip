defmodule Kelix.DB.PoolTest do
  @moduledoc """
  What `Kelix.DB.Pool` adds to the link it took over from `auth_db`: a pool per
  module under a name of its own, and the `[database]` defaults a module block
  inherits. The negotiation itself is proven where it has always been, through
  `Kelix.Mod.AuthDb.Pool` (`auth_db_pool_test.exs`, unchanged by the extraction).
  """
  use ExUnit.Case, async: false

  alias Kelix.DB.Pool

  @block %{
    "host" => "db.example.com",
    "database" => "silo",
    "username" => "silo",
    "password" => "s3cret"
  }

  describe "with_defaults/2 — [database] under a module block" do
    test "each key the block does not set comes from [database]" do
      defaults = %{"driver" => "postgres", "host" => "db.shared", "ssl_ca_cert_file" => "/ca.pem"}
      merged = Pool.with_defaults(Map.delete(@block, "host"), defaults)

      assert merged["driver"] == "postgres"
      assert merged["host"] == "db.shared"
      assert merged["ssl_ca_cert_file"] == "/ca.pem"
    end

    test "the block wins, key by key" do
      merged = Pool.with_defaults(@block, %{"host" => "db.shared", "port" => 6543})

      assert merged["host"] == "db.example.com"
      assert merged["port"] == 6543
    end

    test "nothing but where and how is inherited" do
      merged = Pool.with_defaults(%{}, %{"username" => "root", "pool_size" => 50, "host" => "h"})
      assert merged == %{"host" => "h"}
    end

    test "a config.toml with no [database] leaves the block as it is" do
      assert Pool.with_defaults(@block) == @block
    end
  end

  describe "one pool per module" do
    test "child_spec/2 is keyed on the pool's name, so two modules' pools coexist" do
      a = Pool.child_spec(@block, name: Kelix.Mod.AuthDb.Conn, label: "auth_db")
      b = Pool.child_spec(@block, name: Kelix.Mod.Silo.Conn, label: "silo")

      assert a.id == Kelix.Mod.AuthDb.Conn
      assert b.id == Kelix.Mod.Silo.Conn
      assert {Pool, :start_link, [@block, opts]} = b.start
      assert opts[:name] == Kelix.Mod.Silo.Conn
    end

    test "describe/3 reads the descriptor published under the module's own key" do
      key = Kelix.DB.PoolTest.Silo
      on_exit(fn -> Application.delete_env(:kelixip, key) end)

      assert %{state: :down, error: "the silo module is not loaded"} =
               Pool.describe(key, Kelix.Mod.Silo.Conn, "silo")

      Application.put_env(:kelixip, key, Pool.descriptor(@block, :tls_verified))
      view = Pool.describe(key, Kelix.Mod.Silo.Conn, "silo")

      assert view.state == :down
      assert view.error =~ "not running"
      assert view.database == "silo"
      assert view.tls == true
      refute Map.has_key?(view, :table)
    end

    test "negotiate/2 is the same decision whatever the module" do
      tls_less = fn _config, opts ->
        if Keyword.has_key?(opts, :ssl), do: {:error, :no_ssl}, else: :ok
      end

      insecure = Map.put(@block, "allow_insecure_db_connection", true)

      assert {:cleartext_fallback, []} = Pool.negotiate(insecure, probe: tls_less, label: "silo")
      assert {:tls_unverified, _} = Pool.negotiate(@block, probe: tls_less, label: "silo")
    end
  end

  describe "[database] in config.toml" do
    test "is optional, and empty by default" do
      assert {:ok, cfg} = Kelix.Config.parse("")
      assert cfg.database == %{}
    end

    test "is held as the block's own keys" do
      toml = """
      [database]
      driver = "postgres"
      host = "db.example.net"
      port = 5433
      ssl_ca_cert_file = "/etc/pki/db-ca.pem"
      connect_timeout_ms = 3000
      """

      assert {:ok, cfg} = Kelix.Config.parse(toml)

      assert cfg.database == %{
               "driver" => "postgres",
               "host" => "db.example.net",
               "port" => 5433,
               "ssl_ca_cert_file" => "/etc/pki/db-ca.pem",
               "connect_timeout_ms" => 3000
             }
    end

    test "refuses an account: each module connects with its own" do
      assert {:error, reason} = Kelix.Config.parse("[database]\nusername = \"root\"\n")
      assert reason =~ "username"
      assert reason =~ "account of its own"
    end

    test "refuses what it does not know, and a mistyped value" do
      assert {:error, reason} = Kelix.Config.parse("[database]\npool_size = 8\n")
      assert reason =~ "unknown key(s): pool_size"

      assert {:error, reason} = Kelix.Config.parse("[database]\ndriver = \"oracle\"\n")
      assert reason =~ "mysql|postgres"

      assert {:error, _} = Kelix.Config.parse("[database]\nssl = \"yes\"\n")
    end
  end
end
