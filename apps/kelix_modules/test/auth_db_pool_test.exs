defmodule Kelix.Mod.AuthDbPoolTest do
  @moduledoc """
  The subscriber-DB **link**: how its transport is negotiated (TLS first, cleartext
  only when the block confirms it) and what `kelictl auth_db show` reports about it.

  No database here. The negotiation is driven through `negotiate/2`'s `:probe`
  injection, which is what makes the branch that matters — a server that refuses
  TLS but answers in clear — testable at all: it cannot be provoked on demand from
  a real MariaDB. The live counterpart is `auth_db_live_test.exs`.
  """
  use ExUnit.Case, async: false

  alias Kelix.Mod.AuthDb
  alias Kelix.Mod.AuthDb.Pool

  @block %{
    "host" => "db.example.com",
    "port" => 3307,
    "database" => "kamailio",
    "username" => "kamailio",
    "password" => "s3cret",
    "table" => "os_subscriber"
  }

  # probes that answer without touching the network
  defp accepting(), do: [probe: fn _config, _opts -> :ok end]
  defp refusing(), do: [probe: fn _config, _opts -> {:error, :nope} end]

  # a server that speaks no TLS: the TLS attempt is refused, the cleartext one works
  defp tls_less() do
    [
      probe: fn _config, opts ->
        if Keyword.has_key?(opts, :ssl), do: {:error, :server_does_not_support_ssl}, else: :ok
      end
    ]
  end

  defp allowing_insecure(block \\ @block),
    do: Map.put(block, "allow_insecure_db_connection", true)

  describe "negotiate/2 — TLS is tried first, always" do
    test "a block that says nothing about TLS still gets an encrypted link" do
      assert {:tls_unverified, opts} = Pool.negotiate(@block, accepting())
      assert Keyword.has_key?(opts, :ssl)
    end

    test "ssl_ca_cert_file is what makes the server verified, not merely encrypted" do
      config = Map.put(@block, "ssl_ca_cert_file", "/etc/pki/ca.pem")

      assert {:tls_verified, opts} = Pool.negotiate(config, accepting())
      ssl = Keyword.fetch!(opts, :ssl)
      assert ssl[:verify] == :verify_peer
      assert ssl[:cacertfile] == "/etc/pki/ca.pem"
      # the hostname the certificate is checked against is the one we dial
      assert ssl[:server_name_indication] == ~c"db.example.com"
    end

    test "without a CA file the link is encrypted but the server is NOT authenticated" do
      assert {:tls_unverified, opts} = Pool.negotiate(@block, accepting())
      assert Keyword.fetch!(opts, :ssl)[:verify] == :verify_none
    end

    test "the TLS options use MyXQL's current spelling (a list under :ssl)" do
      # `ssl: true` + `ssl_opts:` logs a deprecation warning on every connect, and a
      # bare `ssl: true` raises a MatchError inside MyXQL 0.8.2.
      {_verdict, opts} = Pool.negotiate(@block, accepting())
      assert is_list(Keyword.fetch!(opts, :ssl))
      refute Keyword.has_key?(opts, :ssl_opts)
    end
  end

  describe "negotiate/2 — the cleartext fallback is gated" do
    test "a server that refuses TLS gets no fallback without the key: TLS is kept" do
      # …and every authentication then answers 500, which is the secure outcome.
      assert {:tls_unverified, opts} = Pool.negotiate(@block, tls_less())
      assert Keyword.has_key?(opts, :ssl)
    end

    test "allow_insecure_db_connection takes the fallback when the server really refuses TLS" do
      assert {:cleartext_fallback, opts} = Pool.negotiate(allowing_insecure(), tls_less())
      refute Keyword.has_key?(opts, :ssl)
    end

    test "a base answering on NEITHER transport keeps TLS — it is unreachable, not TLS-less" do
      # The transport is decided once, at start: downgrading here would turn a
      # transient outage into a permanent cleartext link.
      assert {:tls_unverified, opts} = Pool.negotiate(allowing_insecure(), refusing())
      assert Keyword.has_key?(opts, :ssl)
    end

    test "ssl = false is cleartext by configuration, and probes nothing at all" do
      probe = [probe: fn _c, _o -> flunk("negotiate/2 probed a link it was told not to open") end]
      config = allowing_insecure(Map.put(@block, "ssl", false))

      assert {:cleartext_configured, []} = Pool.negotiate(config, probe)
    end
  end

  describe "validate_config/1 — one gate to a cleartext link" do
    test "accepts the key" do
      assert AuthDb.validate_config(allowing_insecure()) == :ok
      assert AuthDb.validate_config(Map.put(@block, "allow_insecure_db_connection", false)) == :ok
    end

    test "rejects a non-boolean (TOML has no bare `yes`)" do
      assert {:error, reason} =
               AuthDb.validate_config(Map.put(@block, "allow_insecure_db_connection", "yes"))

      assert reason =~ "allow_insecure_db_connection must be a boolean"
    end

    test "refuses ssl = false unless the insecure key confirms it" do
      assert {:error, reason} = AuthDb.validate_config(Map.put(@block, "ssl", false))
      assert reason =~ "CLEARTEXT"
      assert reason =~ "allow_insecure_db_connection"

      assert AuthDb.validate_config(allowing_insecure(Map.put(@block, "ssl", false))) == :ok
    end

    test "ssl = true stays accepted — it is what the default now does anyway" do
      assert AuthDb.validate_config(Map.put(@block, "ssl", true)) == :ok
    end
  end

  describe "descriptor/2 — what show reports, and what it must never carry" do
    test "the connection identity, and the transport in both machine and human form" do
      d = Pool.descriptor(@block, :tls_verified)

      assert d.host == "db.example.com"
      assert d.port == 3307
      assert d.database == "kamailio"
      assert d.username == "kamailio"
      assert d.table == "os_subscriber"
      assert d.tls == true
      assert d.certificate == "verified"
      assert d.transport == "TLS, server certificate verified"
      assert d.pool_size == 4
      assert d.query_timeout_ms == 5_000
    end

    test "the DB password is nowhere in it" do
      values = @block |> Pool.descriptor(:tls_unverified) |> Map.values() |> Enum.map(&inspect/1)
      refute Enum.any?(values, &(&1 =~ "s3cret"))
    end

    test "each verdict says whether the link is encrypted, and why it is what it is" do
      assert %{tls: false, certificate: "-", transport: fallback} =
               Pool.descriptor(@block, :cleartext_fallback)

      assert fallback =~ "refused TLS"
      assert fallback =~ "allow_insecure_db_connection"

      assert %{tls: false, transport: configured} =
               Pool.descriptor(@block, :cleartext_configured)

      assert configured =~ "ssl = false"

      assert %{tls: true, certificate: "not verified"} =
               Pool.descriptor(@block, :tls_unverified)
    end

    test "pool_size and call_timeout_ms are reported as configured, not as defaults" do
      config = Map.merge(@block, %{"pool_size" => 8, "call_timeout_ms" => 1_500})
      d = Pool.descriptor(config, :tls_unverified)

      assert d.pool_size == 8
      assert d.query_timeout_ms == 1_500
    end
  end

  describe "kelictl auth_db show" do
    setup do
      previous = Application.get_env(:kelixip, Pool)
      Kelix.Test.Fixtures.with_module("auth_db", AuthDb)
      :ok = Kelix.Control.Registry.register("auth_db", AuthDb.describe_control())

      on_exit(fn ->
        Kelix.Control.Registry.deregister("auth_db")

        if previous,
          do: Application.put_env(:kelixip, Pool, previous),
          else: Application.delete_env(:kelixip, Pool)
      end)

      :ok
    end

    defp publish(verdict, config \\ @block) do
      Application.put_env(:kelixip, Pool, Pool.descriptor(config, verdict))
    end

    test "the module not being loaded is an answer, not a crash" do
      Application.delete_env(:kelixip, Pool)

      assert {:ok, %{state: :down, error: error}} = AuthDb.handle_control("show", %{})
      assert error =~ "not loaded"
    end

    test "a published link whose pool is down reports down, and says which pool" do
      publish(:tls_unverified)

      assert {:ok, view} = AuthDb.handle_control("show", %{})
      assert view.state == :down
      assert view.error =~ "connection pool is not running"
      # the descriptor still comes through: where it POINTS is knowable while down
      assert view.host == "db.example.com"
      assert view.tls == true
    end

    test "the CLI renders it as a labelled detail view" do
      publish(:cleartext_fallback, allowing_insecure())

      assert {0, out} = Kelix.Control.CLI.run(["auth_db", "show"], node())

      assert out =~ ~r/^State: +down$/m
      assert out =~ ~r/^Host: +db\.example\.com$/m
      assert out =~ ~r/^Port: +3307$/m
      assert out =~ ~r/^Database: +kamailio$/m
      assert out =~ ~r/^Username: +kamailio$/m
      assert out =~ ~r/^Tls: +false$/m
      assert out =~ ~r/^Transport: +cleartext — the server refused TLS/m
      # never the password, and never an inspected term
      refute out =~ "s3cret"
      refute out =~ "%{"
    end

    test "the state is a LIVE query, and a wedged pool is reported rather than fatal" do
      # A process standing in for the pool under its registered name: it never
      # answers. `show` must therefore ask it (proving the state is not a cached
      # flag) AND survive not being answered — the moment an operator most needs the
      # command is the moment the pool is stuck.
      publish(:tls_unverified, Map.put(@block, "call_timeout_ms", 200))

      stub = spawn(fn -> Process.sleep(:infinity) end)
      Process.register(stub, Pool.conn())
      on_exit(fn -> if Process.alive?(stub), do: Process.exit(stub, :kill) end)

      assert {:ok, view} = AuthDb.handle_control("show", %{})
      assert view.state == :down
      # it got past "not running": it really queried, and the failure came back
      refute view.error =~ "not running"
    end

    test "show takes no argument, and mistyping one says so rather than being ignored" do
      publish(:tls_unverified)

      assert {:error, reason} = AuthDb.handle_control("show", %{"args" => ["verbose"]})
      assert reason =~ "takes no argument"

      # a refused argument is a 400 on both frontals (FW-5), i.e. exit code 2
      assert {2, out} = Kelix.Control.CLI.run(["auth_db", "show", "verbose"], node())
      assert out =~ "takes no argument"
    end

    test "an undeclared command is named, not silently accepted" do
      assert AuthDb.handle_control("nope", %{}) == {:error, {:unknown_command, "nope"}}
    end

    test "the declared surface is what kelictl auth_db help prints" do
      {0, out} = Kelix.Control.CLI.run(["auth_db", "help"], node())

      assert out =~ "show"
      assert out =~ "[GET /modules/auth_db/db]"
      assert out =~ "is it encrypted"
    end
  end
end
