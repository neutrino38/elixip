defmodule SIP.Test.NetUtils do
  use ExUnit.Case
  doctest SIP.NetUtils

   # Proxy to use for tests (centralized in config/test.exs)
   @proxy Application.compile_env(:elixip2, :test_account).proxy

  # Commonly accepted modern cipher suites (Mozilla "intermediate" profile),
  # all providing PFS via ephemeral ECDHE key exchange. Mirrors the list used
  # by SIP.Transport.ImplHelpers.
  @tls_ciphers [
    ~c"ECDHE-ECDSA-AES256-GCM-SHA384",
    ~c"ECDHE-RSA-AES256-GCM-SHA384",
    ~c"ECDHE-ECDSA-CHACHA20-POLY1305",
    ~c"ECDHE-RSA-CHACHA20-POLY1305",
    ~c"ECDHE-ECDSA-AES128-GCM-SHA256",
    ~c"ECDHE-RSA-AES128-GCM-SHA256"
  ]


  test "Create a netmask for network such as 10.0.0.0/8" do
    netmask = SIP.NetUtils.cidr_netmask( {10,0,0,0}, 8)
    assert netmask == {255, 0, 0, 0}
  end

  test "Create a netmask for network such as 172.21.0.0/16" do
    netmask = SIP.NetUtils.cidr_netmask( {172,21,0,0}, 16)
    assert netmask == {255, 255, 0, 0}
  end

  test "Create a netmask for network such as 192.168.1.0/24" do
    netmask = SIP.NetUtils.cidr_netmask( {192,168,1,0}, 24)
    assert netmask == {255, 255, 255, 0}
  end

  test "Create a netmask for network such as 192.168.1.0/28" do
    netmask = SIP.NetUtils.cidr_netmask( {192,168,1,0}, 28)
    assert netmask == {255, 255, 255, 240}
  end

  test "Extract the network from an IP like 10.250.0.30/8" do
    netmask = SIP.NetUtils.cidr_network( {10,250,0,30}, 8)
    assert netmask == {10, 0, 0, 0}
  end

  test "Extract the network from an IP like 172.21.100.2/16" do
    netmask = SIP.NetUtils.cidr_network( {172,21,100,2}, 16)
    assert netmask == {172, 21, 0, 0}
  end

  test "Compute an IP V6 network" do
    { :ok, _ipv6 } = :inet.parse_address(~c"2a01:cb15:810f:7900:4d3c:2081:792b:863a")
    netw = SIP.NetUtils.cidr_network( {10753, 51989, 33039, 30976, 19772, 8321, 31019, 34362}, 64)
    assert netw == {10753, 51989, 33039, 30976, 0, 0, 0, 0}
    assert :inet.ntoa(netw) == ~c"2a01:cb15:810f:7900::"
  end

  test "Compute an IP V6 netmask" do
    { :ok, _ipv6 } = :inet.parse_address(~c"2a01:cb15:810f:7900:4d3c:2081:792b:863a")
    netm = SIP.NetUtils.cidr_netmask( {10753, 51989, 33039, 30976, 19772, 8321, 31019, 34362}, 64)
    assert :inet.ntoa(netm) == ~c"ffff:ffff:ffff:ffff::"
  end

  test "get IPV6 including loopback" do
    ips = SIP.NetUtils.get_local_ips( [ :loopback, :ipv6 ] )
    assert {0, 0, 0, 0, 0, 0, 0, 1} in ips
  end

  test "get IPV4 including loopback" do
    ips = SIP.NetUtils.get_local_ips( [ :loopback, :ipv4 ] )
    assert {127, 0, 0, 1} in ips
  end


  test "get local IPV4 from Wifi" do
    one_ip =
      case :os.type() do
        {:win32, _} ->
          ~c"powershell -Command \"(Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Wi-Fi).IPAddress\""
          |> :os.cmd()
          |> List.to_string()
          |> String.split(["\r\n", "\n"], trim: true)
          |> hd()

        {:unix, _} ->
          # Linux: récupère l'IPv4 de l'interface Wi-Fi (wlan0 par défaut)
          wifi_if =
          "/sys/class/net"
          |> File.ls!()
          |> Enum.find(fn ifname ->
            File.exists?("/sys/class/net/#{ifname}/wireless")
          end)

          unless wifi_if do
            flunk("No Wi-Fi interface detected")
          end

          cmd = ~c"sh -c \"ip -4 addr show #{wifi_if} | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){3}'\""

          cmd
          |> :os.cmd()
          |> List.to_string()
          |> String.split(["\r\n", "\n"], trim: true)
          |> hd()
      end

    {:ok, one_ip} =
      one_ip
      |> String.to_charlist()
      |> :inet.parse_address()

    ips = SIP.NetUtils.get_local_ips([:ipv4])
    assert one_ip in ips
  end

  test "pick a free UDP port" do
    {:ok, port} = SIP.NetUtils.pick_free_port(:udp)
    assert port >= 5000 and port <= 65535
    # The returned port must actually be bindable
    {:ok, sock} = :gen_udp.open(port, [])
    :gen_udp.close(sock)
  end

  test "pick a free TCP port" do
    {:ok, port} = SIP.NetUtils.pick_free_port(:tcp)
    assert port >= 5000 and port <= 65535
    {:ok, sock} = :gen_tcp.listen(port, reuseaddr: true)
    :gen_tcp.close(sock)
  end

  test "never pick an occupied port" do
    # Occupy the single port of a one-port range: the picker must give up
    # rather than return the busy port.
    {:ok, sock} = :gen_udp.open(65535, [])
    assert SIP.NetUtils.pick_free_port(:udp, 65535) == {:error, :nofreeport}
    :gen_udp.close(sock)
  end

  test "resolution" do
    assert :inet.getaddr(String.to_charlist("toto.tutu"), :inet) == { :error, :nxdomain}
    assert :inet.getaddr(String.to_charlist("sip.visioassistance.net"), :inet) == {:ok, {91, 134, 191, 39}}
    assert SIP.Resolver.resolve(%SIP.Uri{ domain: "sip.tuttoatoata.net", port: 5077 }, false) == :nxdomain
    assert SIP.Resolver.resolve(%SIP.Uri{ domain: "sip.visioassistance.net", port: 5077 }, false) ==  { {91, 134, 191, 39}, 5077 }

  end

  @tag :live
  test "resolution SRV" do
    # Adapt to actual DNS config
    SIP.Resolver.get_dns_default_dns_server()
    possible_answers = [ {{212, 129, 18, 151}, 5060}, { {91, 134, 191, 39}, 5060 } ]
    assert SIP.Resolver.resolve(%SIP.Uri{ domain: "visioassistance.net", port: 5077 }, true) in possible_answers
  end

  @tag :live
  test "SSL connection with Erlang" do
    # Pour generer les fichiers
    # openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa_keygen_bits:4096
    # openssl req -new -x509 -key key.pem -out cert.pem -days 1000 -sha384

    ssl_options = [
      verify: :verify_none,
      versions: [:"tlsv1.2"],
      # Commonly accepted ECDHE cipher suites (PFS via ephemeral key exchange).
      # RSA-only suites such as AES256-GCM-SHA384 are rejected by the server.
      ciphers: Application.get_env(:elixip2, :tls_ciphers, @tls_ciphers)
    ]
    #Resoudre le proxy de preprod
    { ip, _port } =SIP.Resolver.resolve(%SIP.Uri{ domain: @proxy, port: 5061 }, false)

    # Établir une connexion SSL

    :ssl.start()
    case :ssl.connect(ip, 5061, ssl_options) do
      {:ok, socket} ->
        assert true
        :ssl.close(socket)

      {:error, reason} ->
        IO.puts("Err : #{inspect(reason)}")
        assert false
    end
  end

  @tag :live
  test "SSL connection with socket2" do
    ssl_options = [
      cert: [path: "certs/certificate.pem"],
      key: [ path: "certs/private_key.pem" ],
      verify: false, # Désactive la vérification du certificat pour simplifier l'exemple
      versions: [:"tlsv1.2"], # Spécifie la version de TLS à utiliser
      ciphers: Application.get_env(:elixip2, :tls_ciphers, @tls_ciphers)
    ]

    #Resoudre le proxy de preprod
    { ip, _port } = SIP.Resolver.resolve(%SIP.Uri{ domain: @proxy, port: 5061 }, false)

    _sock = Socket.SSL.connect!(ip, 5061, ssl_options)
  end

  @tag :live
  test "WSS connection with socket2" do
    wss_options = [
      cert: [path: "certs/certificate.pem"],
      key: [ path: "certs/private_key.pem" ],
      verify: false, # Désactive la vérification du certificat
      versions: [:"tlsv1.2"], # Spécifie la version de TLS à utiliser
      ciphers: Application.get_env(:elixip2, :tls_ciphers, @tls_ciphers),
      protocol: ["sip"],
      secure: true
    ]
    sock = Socket.Web.connect!(@proxy, 443,wss_options)
    Socket.Web.close(sock)
  end
end
