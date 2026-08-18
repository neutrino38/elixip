defmodule Kelix.ConfigTest do
  use ExUnit.Case, async: false

  alias Kelix.Config

  @valid """
  [server]
  node_name  = "kelixip@10.0.0.1"
  script_dir = "/srv/kelixip"
  user_agent = "kelixip/1.0"
  max_calls  = 2000

  [log]
  target = "syslog"
  level  = "debug"

  [[listen]]
  proto = "udp"
  port  = 5060

  [[listen]]
  proto = "tls"
  port  = 5061
  cert  = "/etc/kelixip/tls/fullchain.pem"
  key   = "/etc/kelixip/tls/privkey.pem"

  [mediaserver.pool.mcu1]
  module  = "mendooze"
  url     = "http://10.0.0.1:8080"
  enabled = true

  [control_api]
  enabled = true
  port    = 8090
  token   = "change-me"
  """

  describe "parse/1 — valid" do
    setup do
      {:ok, cfg} = Config.parse(@valid)
      %{cfg: cfg}
    end

    test "server section", %{cfg: cfg} do
      assert cfg.node_name == "kelixip@10.0.0.1"
      assert cfg.script_dir == "/srv/kelixip"
      assert cfg.user_agent == "kelixip/1.0"
      assert cfg.max_calls == 2000
      # unset -> default
      assert cfg.module_dir == "/usr/lib/kelixip/modules"
    end

    test "log section", %{cfg: cfg} do
      assert cfg.log == %{target: "syslog", facility: "local0", level: "debug"}
    end

    test "listeners with per-listener certs", %{cfg: cfg} do
      assert [udp, tls] = cfg.listen
      assert udp == %{proto: :udp, addr: "0.0.0.0", port: 5060, cert: nil, key: nil}
      assert tls.proto == :tls and tls.port == 5061
      assert tls.cert == "/etc/kelixip/tls/fullchain.pem"
      assert tls.key == "/etc/kelixip/tls/privkey.pem"
    end

    test "media server pool decoded into typed entries", %{cfg: cfg} do
      assert cfg.mediaserver_pool == [
               %{
                 name: "mcu1",
                 module: :mendooze,
                 url: "http://10.0.0.1:8080",
                 enabled: true
               }
             ]
    end

    test "control_api parsed into a typed map with defaults", %{cfg: cfg} do
      assert cfg.control_api == %{
               enabled: true,
               addr: "127.0.0.1",
               port: 8090,
               auth: "token",
               token: "change-me"
             }
    end
  end

  describe "parse/1 — [mediaserver.pool.*]" do
    # A media server is declared here and only here (the mcu module reads this same
    # list), so a typo must abort the boot rather than silently drop a server.
    test "absent → no pool" do
      assert {:ok, cfg} = Config.parse("")
      assert cfg.mediaserver_pool == []
    end

    test "entries come out in name order, whatever the file order" do
      toml = """
      [mediaserver.pool.zulu]
      module = "mendooze"
      url    = "http://10.0.0.9:8080"

      [mediaserver.pool.alpha]
      module = "mockup"
      url    = "http://10.0.0.1:8080"
      """

      assert {:ok, cfg} = Config.parse(toml)
      assert Enum.map(cfg.mediaserver_pool, & &1.name) == ["alpha", "zulu"]
    end

    test "enabled defaults to true and is honoured when given" do
      toml = """
      [mediaserver.pool.mcu1]
      module  = "mendooze"
      url     = "http://10.0.0.1:8080"
      enabled = false
      """

      assert {:ok, cfg} = Config.parse(toml)
      assert [%{enabled: false}] = cfg.mediaserver_pool
    end

    test "a module name that is neither shorthand is taken as a module" do
      toml = """
      [mediaserver.pool.mcu1]
      module = "MediaServer.Mockup"
      url    = "http://10.0.0.1:8080"
      """

      assert {:ok, cfg} = Config.parse(toml)
      assert [%{module: MediaServer.Mockup}] = cfg.mediaserver_pool
    end

    test "url is required" do
      assert {:error, msg} = Config.parse("[mediaserver.pool.mcu1]\nmodule = \"mendooze\"")
      assert msg =~ "[mediaserver.pool.mcu1]: missing required `url`"
    end

    test "module is required" do
      assert {:error, msg} = Config.parse("[mediaserver.pool.mcu1]\nurl = \"http://x:8080\"")
      assert msg =~ "[mediaserver.pool.mcu1]: missing required `module`"
    end

    test "an unknown key is named, not ignored" do
      toml = """
      [mediaserver.pool.mcu1]
      module    = "mendooze"
      url       = "http://10.0.0.1:8080"
      public_ip = "203.0.113.12"
      """

      assert {:error, msg} = Config.parse(toml)
      assert msg =~ "[mediaserver.pool.mcu1]: unknown key(s): public_ip"
    end

    test "a stray key in [mediaserver] is rejected" do
      assert {:error, msg} = Config.parse("[mediaserver]\nurl = \"http://x:8080\"")
      assert msg =~ "[mediaserver]: unknown key(s): url"
    end
  end

  describe "parse/1 — [control_api]" do
    test "absent → disabled" do
      assert {:ok, cfg} = Config.parse("")
      assert cfg.control_api == %{enabled: false}
    end

    test "token auth requires a non-empty token" do
      assert {:error, msg} = Config.parse("[control_api]\nauth = \"token\"")
      assert msg =~ "missing required `token`"
    end

    test "none auth needs no token" do
      assert {:ok, cfg} = Config.parse("[control_api]\nauth = \"none\"")
      assert cfg.control_api.auth == "none"
      assert cfg.control_api.token == nil
    end

    test "unknown auth mode is rejected" do
      assert {:error, msg} = Config.parse("[control_api]\nauth = \"basic\"")
      assert msg =~ "must be one of"
    end

    test "bad port is rejected" do
      assert {:error, msg} = Config.parse("[control_api]\nport = 70000\ntoken = \"x\"")
      assert msg =~ "must be a port"
    end

    test "mtls requires cert/key/cacert" do
      assert {:error, msg} = Config.parse("[control_api]\nauth = \"mtls\"")
      assert msg =~ "missing required `cert`"

      assert {:ok, cfg} =
               Config.parse("""
               [control_api]
               auth   = "mtls"
               cert   = "/c.pem"
               key    = "/k.pem"
               cacert = "/ca.pem"
               """)

      assert cfg.control_api.cert == "/c.pem"
      assert cfg.control_api.cacert == "/ca.pem"
    end

    test "cert on a token endpoint is rejected" do
      assert {:error, msg} = Config.parse("[control_api]\ntoken = \"x\"\ncert = \"/c.pem\"")
      assert msg =~ "only apply to mtls"
    end
  end

  describe "parse/1 — [metrics]" do
    test "absent → disabled" do
      assert {:ok, cfg} = Config.parse("")
      assert cfg.metrics == %{enabled: false}
    end

    test "present → enabled with loopback defaults" do
      assert {:ok, cfg} = Config.parse("[metrics]\nport = 9095")
      assert cfg.metrics == %{enabled: true, addr: "127.0.0.1", port: 9095}
    end

    test "unknown key is rejected" do
      assert {:error, msg} = Config.parse("[metrics]\nbogus = 1")
      assert msg =~ "unknown key"
    end

    test "bad port is rejected" do
      assert {:error, msg} = Config.parse("[metrics]\nport = 0")
      assert msg =~ "must be a port"
    end
  end

  test "defaults when sections are absent" do
    assert {:ok, cfg} = Config.parse("")
    assert cfg.node_name == "kelixip@127.0.0.1"
    assert cfg.user_agent == "Kelixip/1.4.1"
    assert cfg.log.target == "stdout"
    assert cfg.listen == []
  end

  describe "parse/1 — validation errors" do
    test "unknown top-level key" do
      assert {:error, msg} = Config.parse(~s(bogus = 1))
      assert msg =~ "unknown key"
    end

    test "unknown server key" do
      assert {:error, msg} = Config.parse(~s([server]\nbogus = 1))
      assert msg =~ "unknown key"
    end

    test "unknown listener proto" do
      assert {:error, msg} = Config.parse(~s([[listen]]\nproto = "sctp"\nport = 5060))
      assert msg =~ "unknown proto"
    end

    test "listener missing port" do
      assert {:error, msg} = Config.parse(~s([[listen]]\nproto = "udp"))
      assert msg =~ "missing required `port`"
    end

    test "tls listener requires cert" do
      assert {:error, msg} = Config.parse(~s([[listen]]\nproto = "tls"\nport = 5061))
      assert msg =~ "missing required `cert`"
    end

    # validated here so Kelix.Listener.Supervisor can convert it without guessing
    test "listener addr must be an IP address" do
      assert {:error, msg} =
               Config.parse(~s([[listen]]\nproto = "udp"\nport = 5060\naddr = "sip.example.com"))

      assert msg =~ "must be an IP address"
    end

    test "cert on a udp listener is rejected" do
      assert {:error, msg} =
               Config.parse(~s([[listen]]\nproto = "udp"\nport = 5060\ncert = "x"\nkey = "y"))

      assert msg =~ "only apply to tls/wss"
    end

    test "bad log level" do
      assert {:error, msg} = Config.parse(~s([log]\nlevel = "trace"))
      assert msg =~ "must be one of"
    end

    test "max_calls wrong type" do
      assert {:error, msg} = Config.parse(~s([server]\nmax_calls = "lots"))
      assert msg =~ "positive integer"
    end
  end

  describe "app-env translation + GenServer" do
    test "apply_app_env pushes user_agent into :elixip2 env" do
      prev = Application.get_env(:elixip2, :useragent)
      on_exit(fn -> Application.put_env(:elixip2, :useragent, prev) end)

      {:ok, cfg} = Config.parse(~s([server]\nuser_agent = "kelixip/test"))
      assert :ok = Config.apply_app_env(cfg)
      assert Application.get_env(:elixip2, :useragent) == "kelixip/test"
    end

    # Logger.configure(level:) only moves the PRIMARY level; each sink filters
    # again on its own, and config.exs caps the console at :warning — so
    # `[log].level = "debug"` used to raise the primary level and change nothing
    # the operator could actually see.
    test "apply_logger pushes [log].level down to the sinks, not just the primary" do
      {:ok, %{level: previous}} = :logger.get_handler_config(:default)
      prev_primary = Logger.level()

      on_exit(fn ->
        :logger.update_handler_config(:default, :level, previous)
        Logger.configure(level: prev_primary)
      end)

      {:ok, cfg} = Config.parse(~s([log]\nlevel = "debug"))
      assert :ok = Config.apply_logger(cfg)

      assert Logger.level() == :debug
      assert {:ok, %{level: :debug}} = :logger.get_handler_config(:default)
    end

    test "apply_logger leaves OTP's TLS handler alone (it would bury the SIP trace)" do
      case :logger.get_handler_config(:ssl_handler) do
        {:ok, %{level: before}} ->
          {:ok, cfg} = Config.parse(~s([log]\nlevel = "debug"))
          assert :ok = Config.apply_logger(cfg)
          assert {:ok, %{level: ^before}} = :logger.get_handler_config(:ssl_handler)

        _ ->
          # no ssl handler in this VM — nothing to protect
          assert true
      end
    end

    test "the app-started Kelix.Config holds defaults (booted with no path)" do
      cfg = Config.current()
      assert cfg.node_name == "kelixip@127.0.0.1"
      assert cfg.listen == []
    end
  end
end
