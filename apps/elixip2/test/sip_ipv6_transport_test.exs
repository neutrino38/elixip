defmodule SIP.Test.IPv6Transport do
  @moduledoc """
  Step 3 of docs/design/multi-interface.md: a listener binds the family of the
  address it was given, and an outbound leg resolves a name in the family the
  node can source from.

  Not `async`: both halves read `:elixip2` application env keys that are
  node-wide.
  """
  use ExUnit.Case, async: false

  @loopback_v6 {0, 0, 0, 0, 0, 0, 0, 1}
  @loopback_v4 {127, 0, 0, 1}

  setup do
    previous = Application.fetch_env(:elixip2, :udp_local_addr)

    on_exit(fn ->
      case previous do
        {:ok, addr} -> Application.put_env(:elixip2, :udp_local_addr, addr)
        :error -> Application.delete_env(:elixip2, :udp_local_addr)
      end
    end)

    :ok
  end

  # ── The family the node sources from ─────────────────────────────────────────

  test "a bound local address names the node's family" do
    Application.put_env(:elixip2, :udp_local_addr, @loopback_v6)
    assert SIP.NetUtils.preferred_family() == :ipv6

    Application.put_env(:elixip2, :udp_local_addr, @loopback_v4)
    assert SIP.NetUtils.preferred_family() == :ipv4
  end

  test "without one it is :udp_family, and IPv4 by default" do
    Application.delete_env(:elixip2, :udp_local_addr)
    assert SIP.NetUtils.preferred_family() == :ipv4

    Application.put_env(:elixip2, :udp_family, :ipv6)
    on_exit(fn -> Application.delete_env(:elixip2, :udp_family) end)
    assert SIP.NetUtils.preferred_family() == :ipv6
  end

  # ── Resolution follows it ────────────────────────────────────────────────────

  test "a name that has both records resolves in the node's family" do
    uri = %SIP.Uri{domain: "localhost", port: 5060}

    Application.put_env(:elixip2, :udp_local_addr, @loopback_v6)
    assert {@loopback_v6, 5060} == SIP.Resolver.resolve(uri, false)

    Application.put_env(:elixip2, :udp_local_addr, @loopback_v4)
    assert {@loopback_v4, 5060} == SIP.Resolver.resolve(uri, false)
  end

  test "a literal of the other family still resolves" do
    Application.put_env(:elixip2, :udp_local_addr, @loopback_v6)

    assert {{192, 168, 1, 17}, 5070} ==
             SIP.Resolver.resolve(%SIP.Uri{domain: "192.168.1.17", port: 5070}, false)

    Application.put_env(:elixip2, :udp_local_addr, @loopback_v4)

    assert {{8193, 3512, 0, 0, 0, 0, 0, 1}, 5070} ==
             SIP.Resolver.resolve(%SIP.Uri{domain: "2001:db8::1", port: 5070}, false)
  end

  test "a name with no record at all still answers :nxdomain" do
    Application.put_env(:elixip2, :udp_local_addr, @loopback_v6)

    assert :nxdomain ==
             SIP.Resolver.resolve(%SIP.Uri{domain: "no.such.host.invalid", port: 5060}, false)
  end

  # ── The UDP socket ───────────────────────────────────────────────────────────

  test "the UDP transport binds the family and the address it was given" do
    {:ok, port} = SIP.NetUtils.pick_free_port(:udp)
    Application.put_env(:elixip2, :udp_local_addr, @loopback_v6)
    Application.put_env(:elixip2, :udp_local_port, port)

    {:ok, pid} = GenServer.start(SIP.Transport.UDP, {nil, 0})
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)

    assert {:ok, @loopback_v6, ^port} = GenServer.call(pid, :getlocalipandport)

    socket = :sys.get_state(pid).socket
    assert {:ok, {@loopback_v6, ^port}} = :inet.sockname(socket)

    # What the peer reads back: the bracketed reference of RFC 3261 §19.1.1.
    contact = SIP.Transport.build_contact_uri(SIP.Transport.UDP, pid)
    assert SIP.Uri.serialize(contact) == {:ok, "<sip:[::1]:#{port};transport=udp>"}
  end
end
