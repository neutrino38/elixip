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
      # no `addr` in the fixture: nil, which the listener supervisor expands into
      # one socket per family the host carries
      assert udp ==
               %{
                 proto: :udp,
                 addr: nil,
                 port: 5060,
                 cert: nil,
                 key: nil,
                 tag: :public,
                 networks: []
               }
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

  describe "parse/1 — [mediaserver] bitrate_feedback" do
    test "defaults to both dialects, the production value" do
      {:ok, cfg} = Config.parse("[server]\nscript_dir = \"/tmp\"")
      assert cfg.mediaserver_bitrate_feedback == [:remb, :tmmbr]

      {:ok, cfg} = Config.parse("[mediaserver]\nvideo_bitrate = 2000")
      assert cfg.mediaserver_bitrate_feedback == [:remb, :tmmbr]
    end

    # The four values an operator writes. Naming one dialect isolates one feedback
    # path; `none` is the open-loop rate-control measurement.
    test "the four documented forms decode" do
      for {written, expected} <- [
            {"none", []},
            {"tmmbr", [:tmmbr]},
            {"goog-remb", [:remb]},
            {"goog-remb, tmmbr", [:remb, :tmmbr]}
          ] do
        {:ok, cfg} = Config.parse("[mediaserver]\nbitrate_feedback = \"#{written}\"")

        assert cfg.mediaserver_bitrate_feedback == expected,
               "`#{written}` decoded to #{inspect(cfg.mediaserver_bitrate_feedback)}"
      end
    end

    # Hand-written config: order and spacing must not matter, or the operator gets
    # a parse error for a value that says exactly what the documented one says.
    test "order and spacing are free" do
      {:ok, cfg} = Config.parse("[mediaserver]\nbitrate_feedback = \"tmmbr,goog-remb\"")
      assert Enum.sort(cfg.mediaserver_bitrate_feedback) == [:remb, :tmmbr]
    end

    test "anything else is named, not ignored" do
      assert {:error, msg} = Config.parse("[mediaserver]\nbitrate_feedback = \"remb\"")
      assert msg =~ "[mediaserver]: `bitrate_feedback` must be"

      assert {:error, msg} = Config.parse("[mediaserver]\nbitrate_feedback = \"\"")
      assert msg =~ "[mediaserver]: `bitrate_feedback` must be"

      assert {:error, msg} = Config.parse("[mediaserver]\nbitrate_feedback = false")
      assert msg =~ "[mediaserver]: `bitrate_feedback` must be a string"
    end

    # Asking for none of one thing and some of another is a typo, not an intent.
    test "none cannot be combined with a dialect" do
      assert {:error, msg} = Config.parse("[mediaserver]\nbitrate_feedback = \"none, tmmbr\"")
      assert msg =~ "cannot combine `none` with a dialect"
    end

    test "it rides the Mendooze tuning block, next to the video bitrate" do
      # restored on exit: the block is global, and the video bitrate pushed here
      # otherwise outlives the test and fails whichever later test reads the node's
      # boot default out of it
      before = Application.get_env(:elixip2, MediaServer.Mendooze, [])
      on_exit(fn -> Application.put_env(:elixip2, MediaServer.Mendooze, before) end)

      {:ok, cfg} =
        Config.parse("[mediaserver]\nbitrate_feedback = \"none\"\nvideo_bitrate = 3000")

      :ok = Config.apply_app_env(cfg)
      block = Application.get_env(:elixip2, MediaServer.Mendooze, [])
      assert Keyword.get(block, :bitrate_feedback) == []
      assert Keyword.get(block, :video_bandwidth_kbps) == 3000
    end
  end

  describe "parse/1 — [mediaserver] transport_cc" do
    # Transport-wide congestion control is what feeds the media server's sender-side
    # bandwidth estimator (docs/design/kelixip-transport-wide-cc.md). It is off until
    # the recipe of §6 has run: the server does not yet report arrivals for what it
    # RECEIVES, so a peer that negotiates the extension gets nothing back for its own
    # outgoing stream.
    test "absent → off, on every path" do
      {:ok, cfg} = Config.parse("")
      refute cfg.mediaserver_transport_cc

      {:ok, cfg} = Config.parse("[mediaserver]\nvideo_bitrate = 2000")
      refute cfg.mediaserver_transport_cc
    end

    test "stated either way, and anything but a boolean is named" do
      {:ok, cfg} = Config.parse("[mediaserver]\ntransport_cc = true")
      assert cfg.mediaserver_transport_cc

      {:ok, cfg} = Config.parse("[mediaserver]\ntransport_cc = false")
      refute cfg.mediaserver_transport_cc

      assert {:error, msg} = Config.parse("[mediaserver]\ntransport_cc = \"yes\"")
      assert msg =~ "[mediaserver]: `transport_cc` must be a boolean"
    end

    # The shared SDP layer reads it from there, so the point-to-point adapter and the
    # mcu module negotiate the same thing — one of the two left behind is a call path
    # silently without sender-side rate control.
    test "it rides the Mendooze tuning block" do
      # restored on exit: the block is global, and a test that reads the node's boot
      # defaults out of it runs in this same file
      block = Application.get_env(:elixip2, MediaServer.Mendooze, [])
      on_exit(fn -> Application.put_env(:elixip2, MediaServer.Mendooze, block) end)

      {:ok, cfg} = Config.parse("[mediaserver]\ntransport_cc = true")
      :ok = Config.apply_app_env(cfg)
      assert Keyword.get(Application.get_env(:elixip2, MediaServer.Mendooze, []), :transport_cc)
    end
  end

  describe "parse/1 — [mediaserver] video_bitrate" do
    test "absent → 1500 kb/s, the node's default for both media paths" do
      assert {:ok, cfg} = Config.parse("")
      assert cfg.mediaserver_video_bitrate == 1500

      assert {:ok, cfg} =
               Config.parse("[mediaserver.pool.mcu1]\nmodule = \"mockup\"\nurl = \"u\"")

      assert cfg.mediaserver_video_bitrate == 1500
    end

    test "honoured when given, alongside the pool" do
      toml = """
      [mediaserver]
      video_bitrate = 2500

      [mediaserver.pool.mcu1]
      module = "mendooze"
      url    = "http://10.0.0.1:8080"
      """

      assert {:ok, cfg} = Config.parse(toml)
      assert cfg.mediaserver_video_bitrate == 2500
      assert [%{name: "mcu1"}] = cfg.mediaserver_pool
    end

    test "a non-positive value aborts the boot" do
      assert {:error, msg} = Config.parse("[mediaserver]\nvideo_bitrate = 0")
      assert msg =~ "[mediaserver]: `video_bitrate` must be a positive integer"

      assert {:error, msg} = Config.parse("[mediaserver]\nvideo_bitrate = \"800\"")
      assert msg =~ "[mediaserver]: `video_bitrate` must be a positive integer"
    end

    # The point-to-point path reads the bitrate off the Medooze adapter's tuning
    # block, so pushing it must not drop the timeouts config/config.exs put there.
    test "apply_app_env merges it into the Medooze block without losing its timeouts" do
      prev = Application.get_env(:elixip2, MediaServer.Mendooze)
      on_exit(fn -> Application.put_env(:elixip2, MediaServer.Mendooze, prev) end)

      Application.put_env(:elixip2, MediaServer.Mendooze, xmlrpc_timeout_ms: 2_000)

      {:ok, cfg} = Config.parse("[mediaserver]\nvideo_bitrate = 3000")
      assert :ok = Config.apply_app_env(cfg)

      block = Application.get_env(:elixip2, MediaServer.Mendooze)
      assert Keyword.get(block, :video_bandwidth_kbps) == 3000
      assert Keyword.get(block, :xmlrpc_timeout_ms) == 2_000
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
    assert cfg.user_agent == "Kelixip/1.5.1"
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

    test "an explicit IPv6 listener address is accepted" do
      assert {:ok, cfg} =
               Config.parse(~s([[listen]]\nproto = "udp"\nport = 5060\naddr = "2001:db8::1"))

      assert [%{addr: "2001:db8::1"}] = cfg.listen
    end

    # A wildcard states a family like any other address: "::" is every IPv6
    # interface, "0.0.0.0" every IPv4 one. Only an ABSENT addr names no family.
    test "a wildcard is an address, and keeps its family" do
      for addr <- ["::", "0:0:0:0:0:0:0:0", "0.0.0.0"] do
        assert {:ok, cfg} =
                 Config.parse(~s([[listen]]\nproto = "udp"\nport = 5060\naddr = "#{addr}"))

        assert [%{addr: ^addr}] = cfg.listen
      end
    end

    test "an absent addr is nil — the only spelling that names no family" do
      assert {:ok, cfg} = Config.parse(~s([[listen]]\nproto = "udp"\nport = 5060))
      assert [%{addr: nil}] = cfg.listen
    end

    test "a non-address addr is still refused" do
      assert {:error, msg} =
               Config.parse(~s([[listen]]\nproto = "udp"\nport = 5060\naddr = "nope"))

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
      assert cfg.mediaserver_video_bitrate == 1500

      # Pushed at boot, not only by an explicit [mediaserver] block: the media path
      # must never fall back to the adapter's own compiled-in value.
      assert Application.get_env(:elixip2, MediaServer.Mendooze)[:video_bandwidth_kbps] == 1500
    end
  end
  describe "[tls] — the outbound leg's policy" do
    test "absent means no check: verifying a peer is an interconnect decision" do
      assert {:ok, cfg} = Config.parse("")
      assert cfg.tls == %{verify: false, ca: nil}
    end

    test "verify = true is the deliberate act, and it is explicit" do
      assert {:ok, cfg} = Config.parse(~s([tls]\nverify = true))
      assert cfg.tls.verify == true
    end

    test "a ca that cannot be read is refused at parse time" do
      assert {:error, msg} = Config.parse(~s([tls]\nca = "/no/such/ca.pem"))
      assert msg =~ "not a readable file"
    end

    test "a readable ca is kept" do
      path = Path.expand("../../elixip2/certs/certificate.pem", __DIR__)
      assert {:ok, cfg} = Config.parse(~s([tls]\nca = "#{path}"))
      assert cfg.tls.ca == path
    end

    test "an unknown key is refused, like everywhere else" do
      assert {:error, msg} = Config.parse(~s([tls]\nverfy = true))
      assert msg =~ "[tls]"
    end

    # The repository rule for a new key is that the parser, the installation guide
    # and the shipped config move in one lot. This is the half a test can hold: the
    # file we ship still parses against the parser we ship.
    test "the config.toml shipped in packaging/ still parses whole" do
      path = Path.expand("../../../packaging/config/config.toml", __DIR__)
      assert {:ok, content} = File.read(path)
      assert {:ok, cfg} = Config.parse(content)
      assert cfg.tls.verify == false
    end

    test "apply_app_env/1 is what the outbound leg actually reads" do
      previous = Application.fetch_env(:elixip2, :tls_verify)
      on_exit(fn ->
        case previous do
          {:ok, v} -> Application.put_env(:elixip2, :tls_verify, v)
          :error -> Application.delete_env(:elixip2, :tls_verify)
        end

        Application.delete_env(:elixip2, :tls_cacertfile)
      end)

      {:ok, cfg} = Config.parse(~s([tls]\nverify = true))
      :ok = Config.apply_app_env(cfg)

      assert Application.get_env(:elixip2, :tls_verify) == true
      refute Application.get_env(:elixip2, :tls_cacertfile)
    end
  end
  describe "[[listen]] tag and networks — which side a listener sits on" do
    defp listener(extra) do
      Config.parse(~s([[listen]]\nproto = "udp"\nport = 5060\n#{extra}))
    end

    test "public by default, read off the absence of the key" do
      assert {:ok, cfg} = listener("")
      assert [%{tag: :public, networks: []}] = cfg.listen
    end

    test "\"public\" is accepted and does nothing" do
      assert {:ok, cfg} = listener(~s(tag = "public"))
      assert [%{tag: :public}] = cfg.listen
    end

    test "an internal listener naming an address takes its subnet from the interface" do
      assert {:ok, cfg} = listener(~s(addr = "127.0.0.1"\ntag = "internal"))
      assert [%{tag: :internal, networks: []}] = cfg.listen

      # No `networks` stated, so the prefix is the interface's — whatever this
      # host's loopback netmask says, which in IPv4 is a /8.
      assert Config.internal_networks(cfg) == [{{127, 0, 0, 0}, 8}]
    end

    test "stated networks REPLACE the detection rather than adding to it" do
      assert {:ok, cfg} =
               listener(~s(addr = "127.0.0.1"\ntag = "internal"\nnetworks = ["10.0.0.0/8", "fd00::/8"]))

      assert Config.internal_networks(cfg) ==
               [{{10, 0, 0, 0}, 8}, {{0xFD00, 0, 0, 0, 0, 0, 0, 0}, 8}]

      # 127.0.0.0/8 would have been detected, and is deliberately absent.
      refute {{127, 0, 0, 0}, 8} in Config.internal_networks(cfg)
    end

    test "a wildcard internal listener is refused: it defines no network" do
      # It sits on every subnet, so taking it to mean "everything is internal"
      # would silently make the public side empty.
      assert {:error, msg} = listener(~s(tag = "internal"))
      assert msg =~ "defines none"
    end

    test "a wildcard internal listener stating its networks is fine" do
      assert {:ok, cfg} = listener(~s(tag = "internal"\nnetworks = ["10.0.0.0/8"]))
      assert Config.internal_networks(cfg) == [{{10, 0, 0, 0}, 8}]
    end

    test "a public listener contributes nothing, whatever it sits on" do
      assert {:ok, cfg} = listener(~s(addr = "127.0.0.1"))
      assert Config.internal_networks(cfg) == []
    end

    test "bad values are refused with the key named" do
      assert {:error, msg} = listener(~s(tag = "inside"))
      assert msg =~ "`tag`"

      assert {:error, msg} = listener(~s(tag = "internal"\nnetworks = ["10.0.0.0"]))
      assert msg =~ "not a CIDR"

      assert {:error, msg} = listener(~s(tag = "internal"\nnetworks = ["10.0.0.0/33"]))
      assert msg =~ "not a CIDR"

      assert {:error, msg} = listener(~s(tag = "internal"\nnetworks = "10.0.0.0/8"))
      assert msg =~ "`networks`"
    end

    test "apply_app_env/1 is what the classifier actually reads" do
      previous = Application.fetch_env(:elixip2, :internal_networks)

      on_exit(fn ->
        case previous do
          {:ok, v} -> Application.put_env(:elixip2, :internal_networks, v)
          :error -> Application.delete_env(:elixip2, :internal_networks)
        end
      end)

      {:ok, cfg} = listener(~s(tag = "internal"\nnetworks = ["10.0.0.0/8"]))
      :ok = Config.apply_app_env(cfg)

      assert SIP.NetUtils.net_side({10, 1, 2, 3}) == :internal
      assert SIP.NetUtils.net_side({8, 8, 8, 8}) == :public
    end
  end
end
