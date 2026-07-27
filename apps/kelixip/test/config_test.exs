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

    test "carries the sub-blocks for later phases", %{cfg: cfg} do
      assert cfg.mediaserver_pool["mcu1"]["url"] == "http://10.0.0.1:8080"
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

  test "defaults when sections are absent" do
    assert {:ok, cfg} = Config.parse("")
    assert cfg.node_name == "kelixip@127.0.0.1"
    assert cfg.user_agent == "kelixip/1.0"
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

    test "the app-started Kelix.Config holds defaults (booted with no path)" do
      cfg = Config.current()
      assert cfg.node_name == "kelixip@127.0.0.1"
      assert cfg.listen == []
    end
  end
end
