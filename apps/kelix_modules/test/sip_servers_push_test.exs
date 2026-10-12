defmodule Kelix.Mod.SipServersPushTest do
  @moduledoc """
  What kelescope's domain screen is pushed about the servers of a domain: the
  rows, their changes, the metrics and the alarms (lot L6a of
  `docs/design/sip-server-specs.md`).
  """
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog
  import SIP.Test.Wait

  alias Kelix.Mod.SipServers
  alias Kelix.Mod.SipServers.Link
  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

  @domain "example.com"

  # A literal address resolves to itself, `shared-*` names to one address,
  # `unresolved-*` names to nothing, any other name to a 10.0.3.x address of its own.
  defmodule FakeDns do
    def resolve(server) do
      if String.contains?(server.primary_uri, "unresolved-"),
        do: {:error, :nxdomain},
        else: resolve_all(server)
    end

    defp resolve_all(server) do
      targets =
        for uri <- [server.primary_uri, server.backup_uri], uri != nil, into: %{} do
          {:ok, parsed} = SIP.Uri.parse(uri)

          ip =
            case :inet.parse_address(String.to_charlist(parsed.domain)) do
              {:ok, ip} ->
                ip

              _ ->
                if String.starts_with?(parsed.domain, "shared-"),
                  do: {10, 0, 3, 254},
                  else: {10, 0, 3, :erlang.phash2(parsed.domain, 250) + 1}
            end

          {uri, [{"UDP", ip, 5060}]}
        end

      {:ok, targets, 300}
    end
  end

  setup_all do
    toml = Path.join(System.tmp_dir!(), "sip_servers_push_domains.toml")
    File.write!(toml, ~s([[domain]]\nname = "example.com"\n))
    :ok = Kelix.Domains.reload(toml)
    Application.put_env(:kelix_modules, :sip_servers_resolver, FakeDns)

    on_exit(fn ->
      Application.delete_env(:kelix_modules, :sip_servers_resolver)
      empty = Path.join(System.tmp_dir!(), "sip_servers_push_empty.toml")
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
    tp
  end

  defp create(slug, type, primary, extra \\ %{}) do
    args =
      Map.merge(
        %{"domain" => @domain, "slug" => slug, "type" => type, "primary_uri" => primary},
        extra
      )

    {:ok, _} = SipServers.handle_control("server.create", args)
    :ok
  end

  defp delete(slug),
    do: SipServers.handle_control("server.delete", %{"domain" => @domain, "slug" => slug})

  defp link(slug), do: Map.fetch!(:sys.get_state(SipServers).links, {@domain, slug})

  # The last row pushed for `slug` that satisfies `fun`.
  defp pushed!(slug, fun) do
    receive do
      {:kelix_sip_servers, @domain, {:upsert, %{slug: ^slug} = row}} ->
        if fun.(row), do: row, else: pushed!(slug, fun)
    after
      4_000 -> flunk("no row for #{slug} matching the condition was pushed")
    end
  end

  defp invite_from(ip) do
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

  test "a subscriber gets the rows, then every creation, change and deletion" do
    :ok = create("acd", "sip-application", "sip:10.0.0.5", %{"send_keepalive" => "false"})

    assert {:ok, %{owner: owner, servers: [%{slug: "acd", type: "sip-application"}]}} =
             SipServers.subscribe_sip_servers(self(), @domain)

    assert owner == Process.whereis(SipServers)

    :ok = create("ivr", "sip-application", "sip:10.0.0.6", %{"send_keepalive" => "false"})
    assert pushed!("ivr", &(&1.primary_uri == "sip:10.0.0.6"))

    {:ok, _} =
      SipServers.handle_control("server.update", %{
        "domain" => @domain,
        "slug" => "ivr",
        "backup_uri" => "sip:10.0.0.7"
      })

    assert pushed!("ivr", &(&1.backup_uri == "sip:10.0.0.7"))

    {:ok, _} = delete("ivr")
    assert_receive {:kelix_sip_servers, @domain, {:remove, "ivr"}}, 2_000

    :ok = SipServers.unsubscribe_sip_servers(self(), @domain)
    {:ok, _} = delete("acd")
    refute_receive {:kelix_sip_servers, @domain, {:remove, "acd"}}, 300
  end

  test "a URI coming up is pushed, with the OPTIONS response time" do
    {:ok, _} = SipServers.subscribe_sip_servers(self(), @domain)
    _tp = peer!("push1")
    :ok = create("push1", "sip-application", uri("push1"))

    row = pushed!("push1", &(&1.reachability == %{uri("push1") => "up"}))
    assert is_integer(row.metrics.options_rtt_ms.last)
  end

  test "calls in, calls out and failures by code are counted" do
    :ok = create("gw", "sip-application", "sip:10.0.0.8", %{"send_keepalive" => "false"})
    until!(fn -> Map.has_key?(:sys.get_state(SipServers).resolved, {@domain, "gw"}) end)
    {:ok, _} = SipServers.subscribe_sip_servers(self(), @domain)

    assert {"gw", _} = SipServers.matches_server(@domain, invite_from({10, 0, 0, 8}))
    assert {_req, _peer} = SipServers.forward(@domain, invite_from({10, 0, 0, 1}), "gw")

    target = %SIP.Uri{scheme: "sip:", userpart: "3000", domain: "10.0.0.8"}
    GenServer.cast(link("gw"), {:call_result, target, 486})
    GenServer.cast(link("gw"), {:call_result, target, 200})

    row =
      pushed!("gw", fn row ->
        row.metrics.calls_in == 1 and row.metrics.calls_out == 1 and row.metrics.answered == 1
      end)

    assert row.metrics.failures == %{"486" => 1}
  end

  test "a forward that finds nowhere to send is not counted as a call out" do
    capture_log(fn ->
      :ok =
        create("lost", "sip-trunk", "sip:42@unresolved-lost.example.net", %{
          "send_keepalive" => "false",
          "register" => "false",
          "ext_domain" => "operator.net"
        })

      assert {:error, :not_resolved} =
               SipServers.forward(@domain, invite_from({10, 0, 0, 1}), "lost")
    end)

    assert Link.status(link("lost")).metrics.calls_out == 0
  end

  test "a challenge for another realm raises an alarm, cleared by a new password" do
    {:ok, _} = SipServers.subscribe_sip_servers(self(), @domain)
    _tp = peer!("push2")

    :ok =
      create("push2", "sip-trunk", "sip:0123@push2.example.net;unittest=push2", %{
        "send_keepalive" => "false",
        "register" => "false",
        "auth_username" => "0123",
        "auth_realm" => "operator.net",
        "auth_password" => "secret"
      })

    challenge = %{"realm" => "elsewhere.net", "nonce" => "n"}

    capture_log(fn ->
      assert {:error, {:realm_mismatch, _, _}} =
               GenServer.call(link("push2"), {:authorize, 401, challenge, :INVITE, "sip:x"})
    end)

    assert_receive {:kelix_sip_servers, @domain,
                    {:alarm,
                     %{
                       kind: "realm_mismatch",
                       server: "push2",
                       expected: "operator.net",
                       received: "elsewhere.net"
                     }}},
                   2_000

    assert pushed!("push2", &match?([%{kind: "realm_mismatch"}], &1.alarms))

    {:ok, _} =
      SipServers.handle_control("server.update", %{
        "domain" => @domain,
        "slug" => "push2",
        "auth_realm" => "elsewhere.net",
        "auth_password" => "secret"
      })

    assert pushed!("push2", &(&1.alarms == []))
  end

  test "two servers sharing an address raise an alarm naming both, gone with one of them" do
    {:ok, _} = SipServers.subscribe_sip_servers(self(), @domain)

    capture_log(fn ->
      :ok =
        create("a", "sip-application", "sip:shared-a.example.net", %{"send_keepalive" => "false"})

      :ok =
        create("b", "sip-application", "sip:shared-b.example.net", %{"send_keepalive" => "false"})

      assert_receive {:kelix_sip_servers, @domain,
                      {:alarm,
                       %{kind: "shared_address", address: "10.0.3.254", servers: ["a", "b"]}}},
                     2_000
    end)

    {:ok, shown} = SipServers.handle_control("server.show", %{"domain" => @domain, "slug" => "a"})
    assert [%{kind: "shared_address", servers: ["a", "b"]}] = shown.alarms

    {:ok, _} = delete("b")
    assert pushed!("a", &(&1.alarms == []))
  end

  test "a subscriber that dies is forgotten" do
    subscriber = spawn(fn -> Process.sleep(:infinity) end)
    {:ok, _} = SipServers.subscribe_sip_servers(subscriber, @domain)
    assert map_size(:sys.get_state(SipServers).subs[@domain]) == 1

    Process.exit(subscriber, :kill)
    until!(fn -> map_size(:sys.get_state(SipServers).subs[@domain]) == 0 end)
  end

  test "Kelix.Control reaches the module by its configured name, and answers without it" do
    assert Kelix.Control.subscribe_sip_servers(self(), @domain) ==
             {:ok, %{owner: nil, servers: []}}

    Kelix.ModuleRegistry.register("sip_servers", SipServers, %{})
    on_exit(fn -> Kelix.ModuleRegistry.unregister("sip_servers") end)

    :ok = create("acd", "sip-application", "sip:10.0.0.5", %{"send_keepalive" => "false"})

    assert {:ok, %{owner: owner, servers: [%{slug: "acd"}]}} =
             Kelix.Control.subscribe_sip_servers(self(), @domain)

    assert owner == Process.whereis(SipServers)
    assert Kelix.Control.unsubscribe_sip_servers(self(), @domain) == :ok
  end

  test "status/1 is what the row carries" do
    :ok = create("acd", "sip-application", "sip:10.0.0.5", %{"send_keepalive" => "false"})

    assert %{reachability: _, registration: nil, aor_states: %{}, metrics: _, alarms: []} =
             Link.status(link("acd"))
  end
end
