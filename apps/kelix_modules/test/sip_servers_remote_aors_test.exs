defmodule Kelix.Mod.SipServersRemoteAorsTest do
  @moduledoc """
  Probing the remote AORs of a `sip-proxy`, and what presence learns of them (lot
  L5 of `docs/design/sip-server-specs.md`).

  The proxy is a mockup peer: it answers every OPTIONS, the proxy's own keepalive
  and the probes it relays, with the code it is given.
  """
  use ExUnit.Case, async: false
  import SIP.Test.Wait

  alias Kelix.Mod.{Presence, SipServers}
  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

  @domain "example.com"

  # Every server of this suite lives at a 10.0.2.x address of its own.
  defmodule FakeDns do
    def resolve(server) do
      targets =
        for uri <- [server.primary_uri, server.backup_uri], uri != nil, into: %{} do
          {:ok, parsed} = SIP.Uri.parse(uri)
          n = :erlang.phash2(parsed.domain, 250) + 1
          {uri, [{"UDP", {10, 0, 2, n}, 5060}]}
        end

      {:ok, targets, 300}
    end
  end

  setup_all do
    toml = Path.join(System.tmp_dir!(), "sip_servers_aors_domains.toml")
    File.write!(toml, ~s([[domain]]\nname = "example.com"\n))
    :ok = Kelix.Domains.reload(toml)
    Application.put_env(:kelix_modules, :sip_servers_resolver, FakeDns)

    on_exit(fn ->
      Application.delete_env(:kelix_modules, :sip_servers_resolver)
      empty = Path.join(System.tmp_dir!(), "sip_servers_aors_empty.toml")
      File.write!(empty, "")
      _ = Kelix.Domains.reload(empty)
      File.rm(toml)
    end)

    :ok
  end

  setup do
    start_supervised!(Presence)
    start_supervised!(SipServers.child_spec(:sip_servers, %{}))
    :ok
  end

  defp proxy_uri(name), do: "sip:#{name}.example.net;unittest=#{name}"

  defp proxy!(name, opts \\ []) do
    tp = SIP.Transport.Selector.select_transport(proxy_uri(name)).tp_pid
    :ok = Mockup.set_peer(tp, Manual, opts)
    :ok = Mockup.attach_probe(tp)
    tp
  end

  defp create(slug, aors, extra \\ %{}) do
    args =
      Map.merge(
        %{
          "domain" => @domain,
          "slug" => slug,
          "type" => "sip-proxy",
          "primary_uri" => proxy_uri(slug),
          "ext_domain" => "#{slug}.net",
          "send_keepalive" => "false",
          "probe_remote_aors" => "true",
          "probe_interval" => "1"
        },
        extra
      )

    {:ok, _} = SipServers.handle_control("server.create", args)

    for aor <- aors do
      {:ok, _} =
        SipServers.handle_control("aor.add", %{"domain" => @domain, "slug" => slug, "aor" => aor})
    end

    :ok
  end

  defp aors(slug) do
    {:ok, rows} = SipServers.handle_control("aor.list", %{"domain" => @domain, "slug" => slug})
    Map.new(rows, &{&1.aor, &1.state})
  end

  # What a watcher of the AOR would be told; nil when presence holds nothing.
  defp presence(user) do
    case Presence.presentity(@domain, user) do
      %{status: status} -> status
      other -> other
    end
  end

  test "each AOR is probed through the proxy, and an answered one is open" do
    _tp = proxy!("pbx1")
    :ok = create("pbx1", ["alice@pbx1.net", "bob@pbx1.net"])

    assert_receive {:sip_mockup, {:request_sent, :OPTIONS, probe}}, 3_000
    assert probe.ruri.userpart in ["alice", "bob"]
    assert probe.ruri.domain == "pbx1.net"

    until!(fn -> aors("pbx1") == %{"alice@pbx1.net" => "open", "bob@pbx1.net" => "open"} end)
    until!(fn -> presence("alice") == "open" and presence("bob") == "open" end)
  end

  test "an AOR the proxy does not reach is closed" do
    _tp = proxy!("pbx2", options_code: 480)
    :ok = create("pbx2", ["carol@pbx2.net"])

    until!(fn -> aors("pbx2") == %{"carol@pbx2.net" => "closed"} end)
    until!(fn -> presence("carol") == "closed" end)
  end

  test "an AOR removed has its presence withdrawn" do
    _tp = proxy!("pbx3")
    :ok = create("pbx3", ["dave@pbx3.net"])
    until!(fn -> presence("dave") == "open" end)

    {:ok, _} =
      SipServers.handle_control("aor.rm", %{
        "domain" => @domain,
        "slug" => "pbx3",
        "aor" => "dave@pbx3.net"
      })

    until!(fn -> presence("dave") == nil end)
    assert aors("pbx3") == %{}
  end

  test "without probe_remote_aors nothing is probed" do
    _tp = proxy!("pbx4")
    :ok = create("pbx4", ["erin@pbx4.net"], %{"probe_remote_aors" => "false"})

    refute_receive {:sip_mockup, {:request_sent, :OPTIONS, _}}, 1_500
    assert aors("pbx4") == %{"erin@pbx4.net" => "none"}
    assert presence("erin") == nil
  end

  test "a presence restart is reported again" do
    _tp = proxy!("pbx5")
    :ok = create("pbx5", ["fred@pbx5.net"])
    until!(fn -> presence("fred") == "open" end)

    :ok = stop_supervised(Presence)
    start_supervised!(Presence)

    until!(fn -> presence("fred") == "open" end)
  end
end
