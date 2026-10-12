defmodule Kelix.Mod.SipServersTest do
  @moduledoc """
  The SIP server definitions (design `docs/design/sip-server-specs.md`, lot L1):
  what an operator may declare, what two servers of a domain may not share, and
  what a restart brings back.
  """
  use ExUnit.Case, async: false

  alias Kelix.Mod.SipServers
  alias Kelix.Mod.SipServers.{Server, Store}

  @domain "example.com"

  # The domains a server may name: the node must serve them.
  setup_all do
    toml = Path.join(System.tmp_dir!(), "sip_servers_domains.toml")

    File.write!(toml, """
    [[domain]]
    name = "example.com"

    [[domain]]
    name = "other.com"
    """)

    :ok = Kelix.Domains.reload(toml)

    on_exit(fn ->
      empty = Path.join(System.tmp_dir!(), "sip_servers_domains_empty.toml")
      File.write!(empty, "")
      _ = Kelix.Domains.reload(empty)
      File.rm(toml)
    end)

    :ok
  end

  setup context do
    path =
      Path.join(System.tmp_dir!(), "kelix-sip-servers-#{System.unique_integer([:positive])}.json")

    on_exit(fn -> File.rm_rf!(path) end)
    if body = context[:content], do: File.write!(path, body)

    start_supervised!(SipServers.child_spec(:sip_servers, %{"server_file" => path}))
    %{path: path}
  end

  defp control(command, args), do: SipServers.handle_control(command, args)

  defp create(args), do: control("server.create", Map.put_new(args, "domain", @domain))

  defp app(slug, uri),
    do: create(%{"slug" => slug, "type" => "sip-application", "primary_uri" => uri})

  defp trunk(slug, extra \\ %{}) do
    create(
      Map.merge(
        %{
          "slug" => slug,
          "type" => "sip-trunk",
          "primary_uri" => "sip:0123456789@sbc1.operator.net",
          "auth_username" => "0123456789",
          "auth_realm" => "operator.net",
          "auth_password" => "secret"
        },
        extra
      )
    )
  end

  defp restart() do
    path = current_path()
    stop_supervised!(SipServers)
    start_supervised!(SipServers.child_spec(:sip_servers, %{"server_file" => path}))
  end

  defp current_path(), do: :sys.get_state(SipServers).file

  describe "declaring a server" do
    test "an application server, with the defaults filled in" do
      assert {:ok, s} = app("acd", "sip:10.0.0.5:5060;transport=tcp")
      assert s.type == "sip-application"
      assert s.ha_mode == "failover"
      assert s.send_keepalive == true
      assert s.auth == "none"
    end

    test "kelictl values are strings, and read as the API's" do
      assert {:ok, s} =
               create(%{
                 "slug" => "pbx",
                 "type" => "sip-proxy",
                 "primary_uri" => "sip:proxy.partner.net",
                 "use_dns_srv" => "true",
                 "ext_domain" => "Partner.NET",
                 "ext_domain_aliases" => "sip.partner.net, alt.partner.net",
                 "probe_interval" => "30"
               })

      assert s.use_dns_srv == true
      assert s.ext_domain == "partner.net"
      assert s.ext_domain_aliases == ["sip.partner.net", "alt.partner.net"]
      assert s.probe_interval == 30
    end

    test "a third URI and the source networks, as kelictl and the API give them" do
      assert {:ok, s} =
               create(%{
                 "slug" => "hub",
                 "type" => "sip-application",
                 "primary_uri" => "sip:sip.pstnhub.microsoft.com:5061;transport=tls",
                 "backup_uri" => "sip:sip2.pstnhub.microsoft.com:5061;transport=tls",
                 "tertiary_uri" => "sip:sip3.pstnhub.microsoft.com:5061;transport=tls",
                 "source_networks" => "52.112.0.0/14, 52.120.0.0/14"
               })

      assert s.tertiary_uri == "sip:sip3.pstnhub.microsoft.com:5061;transport=tls"
      assert s.source_networks == ["52.112.0.0/14", "52.120.0.0/14"]

      assert Enum.map(s.uris, & &1.role) == ["primary", "backup", "tertiary"]

      assert {:ok, s} =
               control("server.update", %{
                 "domain" => @domain,
                 "slug" => "hub",
                 "source_networks" => ["52.112.0.0/14"]
               })

      assert s.source_networks == ["52.112.0.0/14"]

      assert {:error, msg} =
               create(%{
                 "slug" => "typo",
                 "type" => "sip-application",
                 "primary_uri" => "sip:10.0.0.9",
                 "source_networks" => "52.112.0.0/33"
               })

      assert msg =~ "source_networks"
    end

    test "the slug is a hostname" do
      assert {:error, msg} = app("not a host", "sip:10.0.0.5")
      assert msg =~ "hostname"
    end

    test "a field the type does not use is refused, not ignored" do
      assert {:error, msg} =
               create(%{
                 "slug" => "acd",
                 "type" => "sip-application",
                 "primary_uri" => "sip:10.0.0.5",
                 "register_expires" => "600"
               })

      assert msg =~ "register_expires"
    end

    test "an application server is a host, a trunk is an account on one" do
      assert {:error, msg} = app("acd", "sip:acd@10.0.0.5")
      assert msg =~ "no user part"

      assert {:error, msg} = trunk("op", %{"primary_uri" => "sip:sbc1.operator.net"})
      assert msg =~ "user part"
    end

    test "a server needs a type and a primary URI" do
      assert {:error, msg} = create(%{"slug" => "x"})
      assert msg =~ "type"
      assert msg =~ "primary_uri"
    end
  end

  describe "trunk credentials" do
    test "the password is kept as one HA1 per algorithm, never shown" do
      assert {:ok, shown} = trunk("op")
      assert shown.auth == "set"
      refute Map.has_key?(shown, :auth_ha1)
      refute inspect(shown) =~ "secret"

      [server] = SipServers.servers(@domain)

      assert server.auth_ha1 == [
               %{
                 algorithm: "MD5",
                 hex: SIP.Auth.compute_ha1("MD5", "0123456789", "operator.net", "secret")
               },
               %{
                 algorithm: "SHA-256",
                 hex: SIP.Auth.compute_ha1("SHA-256", "0123456789", "operator.net", "secret")
               }
             ]
    end

    test "a password without user and realm is refused" do
      assert {:error, msg} =
               trunk("op", %{"auth_username" => nil, "auth_realm" => nil})

      assert msg =~ "auth_username and auth_realm"
    end

    test "changing the realm without the password is refused" do
      {:ok, _} = trunk("op")

      assert {:error, msg} =
               control("server.update", %{
                 "domain" => @domain,
                 "slug" => "op",
                 "auth_realm" => "other.net"
               })

      assert msg =~ "auth_password again"
    end
  end

  describe "what two servers of a domain may not share" do
    test "a slug" do
      {:ok, _} = app("acd", "sip:10.0.0.5")
      assert {:error, :exists} = app("acd", "sip:10.0.0.6")
    end

    test "an address" do
      {:ok, _} = app("acd", "sip:10.0.0.5")
      assert {:error, :address_in_use} = app("ivr", "sip:10.0.0.5:5070")
    end

    test "a source network" do
      {:ok, _} =
        create(%{
          "slug" => "a",
          "type" => "sip-application",
          "primary_uri" => "sip:10.0.0.5",
          "source_networks" => "52.112.0.0/14"
        })

      assert {:error, :address_in_use} =
               create(%{
                 "slug" => "b",
                 "type" => "sip-application",
                 "primary_uri" => "sip:10.0.0.6",
                 "source_networks" => "52.114.0.0/16"
               })

      assert {:ok, _} =
               create(%{
                 "slug" => "c",
                 "type" => "sip-application",
                 "primary_uri" => "sip:10.0.0.7",
                 "source_networks" => "52.120.0.0/14"
               })
    end

    test "a remote domain, between two proxies" do
      proxy = fn slug, uri ->
        create(%{
          "slug" => slug,
          "type" => "sip-proxy",
          "primary_uri" => uri,
          "ext_domain" => "partner.net"
        })
      end

      {:ok, _} = proxy.("pbx1", "sip:proxy1.partner.net")
      assert {:error, :ext_domain_in_use} = proxy.("pbx2", "sip:proxy2.partner.net")
    end

    test "nothing is shared across domains" do
      {:ok, _} = app("acd", "sip:10.0.0.5")

      assert {:ok, _} =
               create(%{
                 "domain" => "other.com",
                 "slug" => "acd",
                 "type" => "sip-application",
                 "primary_uri" => "sip:10.0.0.5"
               })
    end
  end

  test "the control surface is routable as declared" do
    assert :ok = Kelix.Control.Route.check_conflicts(SipServers.describe_control())
  end

  test "a domain the node does not serve is refused" do
    assert {:error, :unknown_domain} =
             create(%{
               "domain" => "nowhere.net",
               "slug" => "acd",
               "type" => "sip-application",
               "primary_uri" => "sip:10.0.0.5"
             })
  end

  describe "control" do
    test "update keeps what it was not given" do
      {:ok, _} = app("acd", "sip:10.0.0.5")

      {:ok, s} =
        control("server.update", %{
          "domain" => @domain,
          "slug" => "acd",
          "backup_uri" => "sip:10.0.0.6"
        })

      assert s.primary_uri == "sip:10.0.0.5"
      assert s.backup_uri == "sip:10.0.0.6"
    end

    test "list, show, delete" do
      {:ok, _} = app("acd", "sip:10.0.0.5")
      {:ok, _} = app("ivr", "sip:10.0.0.7")

      assert {:ok, [%{slug: "acd"}, %{slug: "ivr"}]} =
               control("server.list", %{"domain" => @domain})

      assert {:ok, %{slug: "ivr"}} =
               control("server.show", %{"domain" => @domain, "slug" => "ivr"})

      assert {:ok, %{deleted: true}} =
               control("server.delete", %{"domain" => @domain, "slug" => "ivr"})

      assert {:error, :not_found} =
               control("server.show", %{"domain" => @domain, "slug" => "ivr"})
    end

    test "remote AORs belong to a proxy" do
      {:ok, _} =
        create(%{
          "slug" => "pbx",
          "type" => "sip-proxy",
          "primary_uri" => "sip:proxy.partner.net",
          "ext_domain" => "partner.net"
        })

      key = %{"domain" => @domain, "slug" => "pbx"}
      {:ok, _} = control("aor.add", Map.put(key, "aor", "Alice@partner.net"))
      {:ok, _} = control("aor.add", Map.put(key, "aor", "bob@partner.net"))
      {:ok, _} = control("aor.rm", Map.put(key, "aor", "bob@partner.net"))
      assert {:ok, [%{aor: "alice@partner.net"}]} = control("aor.list", key)

      {:ok, _} = app("acd", "sip:10.0.0.5")

      assert {:error, msg} =
               control("aor.add", %{"domain" => @domain, "slug" => "acd", "aor" => "x@y"})

      assert msg =~ "sip-proxy"
    end
  end

  # The rows an operator reads: the list keeps to one URI per server and counts the
  # others, the detail lays every URI out with its role and state.
  describe "kelictl rendering" do
    setup do
      Kelix.Test.Fixtures.with_module("sip_servers", SipServers)
      :ok = Kelix.Control.Registry.register("sip_servers", SipServers.describe_control())
      on_exit(fn -> Kelix.Control.Registry.deregister("sip_servers") end)
    end

    test "server.list shows the first URI and counts the others; server.show tabulates them" do
      {:ok, _} =
        create(%{
          "slug" => "hub",
          "type" => "sip-application",
          "primary_uri" => "sip:sip.pstnhub.microsoft.com:5061;transport=tls",
          "backup_uri" => "sip:sip2.pstnhub.microsoft.com:5061;transport=tls",
          "tertiary_uri" => "sip:sip3.pstnhub.microsoft.com:5061;transport=tls",
          "source_networks" => "52.112.0.0/14,52.120.0.0/14"
        })

      {:ok, _} = app("acd", "sip:10.0.0.5")

      {0, out} = Kelix.Control.CLI.run(["sip_servers", "server.list"], node())
      [header, acd, hub] = String.split(out, "\n")
      assert header =~ ~r/^domain\s+slug\s+type\s+uris\s+ha_mode$/
      assert acd =~ ~r/acd\s+sip-application\s+sip:10\.0\.0\.5\s+failover$/
      assert hub =~ ~r/sip:sip\.pstnhub\.microsoft\.com:5061;transport=tls \(\+2\)\s+failover$/

      {0, out} =
        Kelix.Control.CLI.run(
          ["sip_servers", "server.show", "domain=#{@domain}", "slug=hub"],
          node()
        )

      assert out =~ ~r"""
             ^Uris:
               role      uri                                                state
               primary   sip:sip\.pstnhub\.microsoft\.com:5061;transport=tls   \w+
               backup    sip:sip2\.pstnhub\.microsoft\.com:5061;transport=tls  \w+
               tertiary  sip:sip3\.pstnhub\.microsoft\.com:5061;transport=tls  \w+
             """m

      assert out =~ ~r{^Source networks:\s+52\.112\.0\.0/14, 52\.120\.0\.0/14$}m
      refute out =~ "Primary uri:"
      refute out =~ "Reachability:"
    end
  end

  describe "persistence" do
    test "a restart brings the servers back, credentials included", %{path: path} do
      {:ok, _} = trunk("op")
      {:ok, _} = app("acd", "sip:10.0.0.5")
      [before_trunk] = SipServers.servers(@domain) |> Enum.filter(&(&1.slug == "op"))

      restart()

      assert [%Server{slug: "acd"}, %Server{slug: "op"} = op] = SipServers.servers(@domain)
      assert op.auth_ha1 == before_trunk.auth_ha1
      refute File.read!(path) =~ "secret"
    end

    test "the file is readable by its owner only", %{path: path} do
      {:ok, _} = app("acd", "sip:10.0.0.5")
      assert File.stat!(path).mode |> Bitwise.band(0o777) == 0o600
    end

    @tag content: "{ not json"
    test "an unreadable file is left alone, and nothing is written over it", %{path: path} do
      {:ok, _} = app("acd", "sip:10.0.0.5")
      assert File.read!(path) == "{ not json"
    end

    @tag content: ~s({"version": 1, "servers": [
             {"domain": "example.com", "slug": "acd", "type": "sip-application", "primary_uri": "sip:10.0.0.5"},
             {"domain": "example.com", "slug": "bad", "type": "sip-application"}]})
    test "one bad row does not cost the others" do
      assert [%Server{slug: "acd"}] = SipServers.servers(@domain)
    end

    test "store round trip, field by field", %{path: path} do
      {:ok, _} =
        trunk("op", %{
          "backup_uri" => "sip:0123456789@sbc2.operator.net",
          "tertiary_uri" => "sip:0123456789@sbc3.operator.net",
          "source_networks" => "198.51.100.0/24"
        })

      assert {:ok, [s]} = Store.load(path)
      assert s.backup_uri == "sip:0123456789@sbc2.operator.net"
      assert s.tertiary_uri == "sip:0123456789@sbc3.operator.net"
      assert s.source_networks == ["198.51.100.0/24"]
      assert length(s.auth_ha1) == 2
    end
  end
end
