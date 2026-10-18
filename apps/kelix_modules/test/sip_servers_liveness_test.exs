defmodule Kelix.Mod.SipServersLivenessTest do
  @moduledoc """
  Whether a server's URIs are reachable, and what the B2BUA learns of it through
  `trunk_pid` (lot L3 of `docs/design/sip-server-specs.md`).

  The servers are mockup peers (`;unittest=…`), so an OPTIONS really goes out and a
  peer really answers it.
  """
  use ExUnit.Case, async: false
  import SIP.Test.Wait

  alias Kelix.Mod.SipServers
  alias Kelix.Mod.SipServers.Link
  alias SIP.B2bua.Peer
  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

  @domain "example.com"

  # Every server of this suite is named `<name>.example.net`, and lives at a
  # 10.0.1.x address of its own.
  defmodule FakeDns do
    def resolve(server) do
      targets =
        for uri <- SipServers.Server.uris(server), into: %{} do
          {:ok, parsed} = SIP.Uri.parse(uri)
          n = :erlang.phash2(parsed.domain, 250) + 1
          {uri, [{"UDP", {10, 0, 1, n}, 5060}]}
        end

      {:ok, targets, 300}
    end
  end

  setup_all do
    toml = Path.join(System.tmp_dir!(), "sip_servers_liveness_domains.toml")
    File.write!(toml, ~s([[domain]]\nname = "example.com"\n))
    :ok = Kelix.Domains.reload(toml)
    Application.put_env(:kelix_modules, :sip_servers_resolver, FakeDns)

    on_exit(fn ->
      Application.delete_env(:kelix_modules, :sip_servers_resolver)
      empty = Path.join(System.tmp_dir!(), "sip_servers_liveness_empty.toml")
      File.write!(empty, "")
      _ = Kelix.Domains.reload(empty)
      File.rm(toml)
    end)

    :ok
  end

  setup do
    start_supervised!(SipServers.child_spec(:sip_servers, %{"keepalive_interval" => 1}))
    :ok
  end

  defp uri(name), do: "sip:#{name}.example.net;unittest=#{name}"

  defp peer!(name, opts \\ []) do
    tp = SIP.Transport.Selector.select_transport(uri(name)).tp_pid
    :ok = Mockup.set_peer(tp, Manual, opts)
    :ok = Mockup.attach_probe(tp)
    tp
  end

  defp app(slug, extra \\ %{}) do
    args =
      Map.merge(
        %{
          "domain" => @domain,
          "slug" => slug,
          "type" => "sip-appsrv",
          "primary_uri" => uri(slug)
        },
        extra
      )

    {:ok, _} = SipServers.handle_control("server.create", args)
    :ok
  end

  defp link(slug), do: Map.fetch!(:sys.get_state(SipServers).links, {@domain, slug})

  defp state_of(slug, uri), do: Map.fetch!(Link.states(link(slug)), uri)

  defp request_from(ip) do
    ruri = %SIP.Uri{
      scheme: "sip:",
      userpart: "3000",
      domain: @domain,
      tp_module: SIP.Transport.UDP,
      destip: ip,
      destport: 5060
    }

    %{method: :INVITE, ruri: ruri}
  end

  test "an answered OPTIONS brings a URI up, and show says so" do
    _tp = peer!("live1")
    :ok = app("live1")

    assert_receive {:sip_mockup, {:request_sent, :OPTIONS, options}}, 3_000
    assert options.ruri.domain == "live1.example.net"
    until!(fn -> state_of("live1", uri("live1")) == :up end)

    {:ok, shown} =
      SipServers.handle_control("server.show", %{"domain" => @domain, "slug" => "live1"})

    assert shown.reachability == %{uri("live1") => "up"}
  end

  test "the OPTIONS Contact publishes the bound address by default" do
    _tp = peer!("addr1")
    :ok = app("addr1")

    assert_receive {:sip_mockup, {:request_sent, :OPTIONS, options}}, 3_000
    refute options.contact.domain == @domain
  end

  test "use_fqdn_contact: the OPTIONS Contact names the server's domain, without a port" do
    _tp = peer!("fqdn1")
    :ok = app("fqdn1", %{"use_fqdn_contact" => "true"})

    assert_receive {:sip_mockup, {:request_sent, :OPTIONS, options}}, 3_000
    assert SIP.Uri.serialize(options.contact) == {:ok, "<sip:example.com;transport=udp>"}
  end

  test "ext_domain: the OPTIONS asks for the domain, sent where the URI resolved" do
    _tp = peer!("ext1")

    {:ok, _} =
      SipServers.handle_control("server.create", %{
        "domain" => @domain,
        "slug" => "ext1",
        "type" => "sip-proxy",
        "primary_uri" => uri("ext1"),
        "ext_domain" => "partner-ext1.net"
      })

    assert_receive {:sip_mockup, {:request_sent, :OPTIONS, options}}, 3_000
    assert options.ruri.domain == "partner-ext1.net"
    assert {:ok, %SIP.Uri{domain: "partner-ext1.net"}} = SIP.Uri.parse(options.to)
    until!(fn -> state_of("ext1", uri("ext1")) == :up end)
  end

  test "a 503 takes it down: the B2BUA is told to skip it, not its backup" do
    _primary = peer!("live2", options_code: 503)
    _backup = peer!("live2b")
    :ok = app("live2", %{"backup_uri" => uri("live2b")})

    until!(fn -> state_of("live2", uri("live2")) == :down end)
    until!(fn -> state_of("live2", uri("live2b")) == :up end)

    {_req, %Peer{trunk_pid: pid, uris: [primary, backup]}} =
      SipServers.forward(@domain, request_from({10, 0, 0, 1}), "live2")

    assert pid == link("live2")
    refute GenServer.call(pid, {:reachable?, primary})
    assert GenServer.call(pid, {:reachable?, backup})
  end

  test "an unanswered OPTIONS takes it down, a request from it brings it back" do
    _tp = peer!("live3", reply_options: false)
    :ok = app("live3")
    assert_receive {:sip_mockup, {:request_sent, :OPTIONS, _}}, 3_000

    # Timer F is 32 s: say it fired, for the probe in flight.
    pid = link("live3")
    until!(fn -> map_size(:sys.get_state(pid).probes) > 0 end)
    [tid | _] = Map.keys(:sys.get_state(pid).probes)
    send(pid, {:transaction_timeout, :timerF, tid, nil, SIP.NICT})
    until!(fn -> state_of("live3", uri("live3")) == :down end)

    [{_uri, [{_t, ip, _p}]}] =
      Map.to_list(:sys.get_state(SipServers).resolved[{@domain, "live3"}].targets)

    assert {"live3", %Peer{trunk_pid: ^pid}} =
             SipServers.matches_server(@domain, request_from(ip))

    until!(fn -> state_of("live3", uri("live3")) == :up end)
  end

  test "send_keepalive = false: no OPTIONS, and an unknown URI counts as reachable" do
    _tp = peer!("live4")
    :ok = app("live4", %{"send_keepalive" => "false"})

    refute_receive {:sip_mockup, {:request_sent, :OPTIONS, _}}, 1_500
    assert state_of("live4", uri("live4")) == :unknown
    assert GenServer.call(link("live4"), {:reachable?, uri("live4")})
  end

  test "deleting a server stops its process" do
    _tp = peer!("live5")
    :ok = app("live5")
    pid = link("live5")
    ref = Process.monitor(pid)

    {:ok, _} =
      SipServers.handle_control("server.delete", %{"domain" => @domain, "slug" => "live5"})

    assert_receive {:DOWN, ^ref, :process, ^pid, _}, 2_000
  end
end
