defmodule Kelix.Mod.SipServersRoutingTest do
  @moduledoc """
  Recognising a request from a server, finding the server a request is for, and
  shaping a request for one (lot L2 of `docs/design/sip-server-specs.md`).

  Names are resolved by `FakeDns` below, so a test says which address a name has
  instead of depending on the network.
  """
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog
  import SIP.Test.Wait

  alias Kelix.Mod.SipServers
  alias Kelix.Mod.SipServers.Resolution
  alias SIP.B2bua.Peer

  @domain "example.com"

  defmodule FakeDns do
    @names %{
      "sbc1.operator.net" => {192, 0, 2, 10},
      "sbc2.operator.net" => {192, 0, 2, 11},
      "proxy.partner.net" => {198, 51, 100, 5},
      "app-a.example.net" => {10, 0, 0, 77},
      "app-b.example.net" => {10, 0, 0, 77}
    }

    def resolve(server) do
      targets =
        for uri <- [server.primary_uri, server.backup_uri], uri != nil, into: %{} do
          {:ok, parsed} = SIP.Uri.parse(uri)
          transport = SIP.Uri.get_transport(parsed) || "UDP"
          port = SIP.Uri.target_port(parsed)

          ip =
            case :inet.parse_address(String.to_charlist(parsed.domain)) do
              {:ok, ip} -> ip
              _ -> Map.fetch!(@names, parsed.domain)
            end

          {uri, [{transport, ip, port}]}
        end

      {:ok, targets, 300}
    end
  end

  setup_all do
    toml = Path.join(System.tmp_dir!(), "sip_servers_routing_domains.toml")

    File.write!(toml, """
    [[domain]]
    name = "example.com"

    [[domain]]
    name = "other.com"
    """)

    :ok = Kelix.Domains.reload(toml)
    Application.put_env(:kelix_modules, :sip_servers_resolver, FakeDns)

    on_exit(fn ->
      Application.delete_env(:kelix_modules, :sip_servers_resolver)
      empty = Path.join(System.tmp_dir!(), "sip_servers_routing_empty.toml")
      File.write!(empty, "")
      _ = Kelix.Domains.reload(empty)
      File.rm(toml)
    end)

    :ok
  end

  setup do
    start_supervised!(SipServers.child_spec(:sip_servers, %{}))
    :ok
  end

  defp create(args) do
    {:ok, _} = SipServers.handle_control("server.create", Map.put_new(args, "domain", @domain))
    :ok
  end

  defp app(slug, uri, extra \\ %{}),
    do:
      create(
        Map.merge(%{"slug" => slug, "type" => "sip-application", "primary_uri" => uri}, extra)
      )

  defp proxy(slug, extra) do
    create(
      Map.merge(
        %{
          "slug" => slug,
          "type" => "sip-proxy",
          "primary_uri" => "sip:proxy.partner.net",
          "ext_domain" => "partner.net"
        },
        extra
      )
    )
  end

  defp trunk(slug, extra \\ %{}) do
    create(
      Map.merge(
        %{
          "slug" => slug,
          "type" => "sip-trunk",
          "primary_uri" => "sip:0123456789@sbc1.operator.net"
        },
        extra
      )
    )
  end

  # Resolution runs off the service's process: wait for it to land.
  defp resolved!(slug) do
    until!(fn ->
      state = :sys.get_state(SipServers)
      Map.has_key?(state.resolved, {@domain, slug})
    end)
  end

  defp uri(user, host), do: %SIP.Uri{scheme: "sip:", userpart: user, domain: host}

  # A request as the transport layer hands it over: the R-URI stamped with where it
  # came from.
  defp request(ruri, from \\ nil) do
    ruri =
      case from do
        {mod, ip, port} -> %SIP.Uri{ruri | tp_module: mod, destip: ip, destport: port}
        nil -> ruri
      end

    %{
      method: :INVITE,
      ruri: ruri,
      from: %SIP.Uri{uri("alice", "caller.net") | displayname: "Alice", hparams: %{"tag" => "f1"}},
      to: uri(ruri.userpart, ruri.domain)
    }
  end

  describe "matches_server/2" do
    test "by source address and transport, whatever the source port" do
      :ok = app("acd", "sip:10.0.0.5:5060;transport=tcp")
      resolved!("acd")

      req = request(uri("3000", @domain), {SIP.Transport.TCP, {10, 0, 0, 5}, 51_234})
      assert {"acd", %Peer{ruri: :peer}} = SipServers.matches_server(@domain, req)

      # same address, another transport; another address; no source at all
      udp = request(uri("3000", @domain), {SIP.Transport.UDP, {10, 0, 0, 5}, 5060})
      assert SipServers.matches_server(@domain, udp) == :no_match

      other = request(uri("3000", @domain), {SIP.Transport.TCP, {10, 0, 0, 9}, 5060})
      assert SipServers.matches_server(@domain, other) == :no_match

      assert SipServers.matches_server(@domain, request(uri("3000", @domain))) == :no_match
    end

    test "a server named by host is recognised at the address it resolved to" do
      :ok = trunk("op")
      resolved!("op")

      req = request(uri("+33970260233", @domain), {SIP.Transport.UDP, {192, 0, 2, 10}, 40_000})
      assert {"op", _peer} = SipServers.matches_server(@domain, req)
    end

    test "only within the request's domain" do
      :ok = app("acd", "sip:10.0.0.5")
      resolved!("acd")

      req = request(uri("3000", "other.com"), {SIP.Transport.UDP, {10, 0, 0, 5}, 5060})
      assert SipServers.matches_server("other.com", req) == :no_match
    end

    test "two servers resolving to one address are recognised as neither, and said" do
      log =
        capture_log(fn ->
          :ok = app("a", "sip:app-a.example.net")
          :ok = app("b", "sip:app-b.example.net")
          resolved!("a")
          resolved!("b")
          :sys.get_state(SipServers)
        end)

      assert log =~ "a, b"
      assert log =~ "10.0.0.77"

      req = request(uri("3000", @domain), {SIP.Transport.UDP, {10, 0, 0, 77}, 5060})
      assert SipServers.matches_server(@domain, req) == :no_match
    end
  end

  describe "find_server/2" do
    test "a proxy by its remote domain and aliases, an application by its host" do
      :ok = proxy("pbx", %{"ext_domain_aliases" => "sip.partner.net"})
      :ok = app("acd", "sip:10.0.0.5")
      :ok = trunk("op")

      assert SipServers.find_server(@domain, request(uri("bob", "partner.net"))) == "pbx"
      assert SipServers.find_server(@domain, request(uri("bob", "SIP.partner.net"))) == "pbx"
      assert SipServers.find_server(@domain, request(uri("3000", "10.0.0.5"))) == "acd"

      # a trunk is never found by host, and an unknown host is no server
      assert SipServers.find_server(@domain, request(uri("x", "sbc1.operator.net"))) == :no_match
      assert SipServers.find_server(@domain, request(uri("x", "nowhere.net"))) == :no_match
    end
  end

  describe "forward/3" do
    test "an application server receives the dialled user at its own address" do
      :ok = app("acd", "sip:10.0.0.5:5060;transport=tcp")
      req = request(uri("3000", @domain))

      assert {^req, %Peer{ruri: :peer, fork: :serial, uris: [target]}} =
               SipServers.forward(@domain, req, "acd")

      assert target.userpart == "3000"
      assert target.domain == "10.0.0.5"
      assert SIP.Uri.get_transport(target) == "TCP"
    end

    test "a proxy keeps the R-URI, moved to its remote domain when it was ours" do
      :ok = proxy("pbx", %{})
      req = request(uri("bob", @domain))

      assert {newreq, %Peer{ruri: :keep, uris: ["sip:proxy.partner.net"]}} =
               SipServers.forward(@domain, req, "pbx")

      assert newreq.ruri.domain == "partner.net"
      assert newreq.to.domain == "partner.net"
      assert newreq.from == req.from
    end

    test "a trunk: R-URI and To at the trunk, From is the account" do
      :ok = trunk("op")
      req = request(uri("+33970260233", @domain))

      assert {newreq, %Peer{ruri: :peer, uris: [target]}} = SipServers.forward(@domain, req, "op")
      assert target.userpart == "+33970260233"
      assert target.domain == "sbc1.operator.net"

      assert newreq.to.userpart == "+33970260233"
      assert newreq.to.domain == "sbc1.operator.net"
      assert newreq.from.userpart == "0123456789"
      assert newreq.from.domain == "sbc1.operator.net"
      assert newreq.from.displayname == nil
      assert newreq.from.hparams["tag"] == "f1"
    end

    test "a trunk with ext_domain is sent where its URIs resolved, primary then backup" do
      :ok =
        trunk("op", %{
          "backup_uri" => "sip:0123456789@sbc2.operator.net",
          "ext_domain" => "operator.net"
        })

      resolved!("op")
      req = request(uri("+33970260233", @domain))

      assert {newreq, %Peer{ruri: :peer, use_srv: false, uris: [first, second]}} =
               SipServers.forward(@domain, req, "op")

      assert {first.domain, first.destip} == {"operator.net", {192, 0, 2, 10}}
      assert {second.domain, second.destip} == {"operator.net", {192, 0, 2, 11}}
      assert first.destproto == "UDP"
      assert newreq.from.domain == "operator.net"
    end

    test "loadsharing starts each call on the next server" do
      :ok =
        app("acd", "sip:10.0.0.5", %{"backup_uri" => "sip:10.0.0.6", "ha_mode" => "loadsharing"})

      req = request(uri("3000", @domain))

      firsts =
        for _ <- 1..3,
            {_, %Peer{uris: [t | _]}} = SipServers.forward(@domain, req, "acd"),
            do: t.domain

      assert firsts == ["10.0.0.5", "10.0.0.6", "10.0.0.5"]
    end

    test "an unknown server" do
      assert {:error, :not_found} =
               SipServers.forward(@domain, request(uri("x", @domain)), "nope")
    end
  end

  describe "Resolution" do
    test "a literal address never expires" do
      server = %SipServers.Server{
        primary_uri: "sip:10.0.0.5;transport=tcp",
        backup_uri: "sip:10.0.0.6"
      }

      assert {:ok, targets, :infinity} = Resolution.resolve(server)
      assert targets["sip:10.0.0.5;transport=tcp"] == [{"TCP", {10, 0, 0, 5}, 5060}]
      assert targets["sip:10.0.0.6"] == [{"UDP", {10, 0, 0, 6}, 5060}]
    end

    test "a name only the host knows is resolved, with a lifetime" do
      server = %SipServers.Server{primary_uri: "sip:localhost:5070"}

      assert {:ok, %{"sip:localhost:5070" => [{"UDP", _ip, 5070} | _]}, ttl} =
               Resolution.resolve(server)

      assert is_integer(ttl)
    end
  end
end
