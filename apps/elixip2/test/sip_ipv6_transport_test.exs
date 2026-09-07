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
  # ── The TCP listener ─────────────────────────────────────────────────────────

  test "the TCP listener binds the family and the address it was given" do
    {:ok, pid} = GenServer.start(SIP.Transport.TCPListener, {@loopback_v6, 0, []})
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)

    assert {:ok, @loopback_v6, port} = GenServer.call(pid, :getlocalipandport)
    assert {@loopback_v6, ^port} = Socket.local!(:sys.get_state(pid).socket)

    # And it accepts over that family: a v6 client reaches it and is counted.
    client = Socket.TCP.connect!("[::1]", port, timeout: 2_000)
    assert eventually(fn -> SIP.Transport.TCPListener.connection_count(pid) == 1 end)

    Socket.close(client)
    assert eventually(fn -> SIP.Transport.TCPListener.connection_count(pid) == 0 end)
  end

  # ── The TLS listener ─────────────────────────────────────────────────────────

  test "the TLS listener binds the family and the address it was given" do
    opts = [certfile: "certs/certificate.pem", keyfile: "certs/private_key.pem"]
    {:ok, pid} = GenServer.start(SIP.Transport.TLSListener, {@loopback_v6, 0, opts})
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)

    assert {:ok, @loopback_v6, port} = GenServer.call(pid, :getlocalipandport)
    assert {@loopback_v6, ^port} = Socket.local!(:sys.get_state(pid).socket)

    # And it handshakes over that family: a v6 client reaches it and is counted.
    {:ok, client} =
      :ssl.connect(@loopback_v6, port,
        [:binary, {:active, false}, verify: :verify_none, versions: [:"tlsv1.2"]])

    assert eventually(fn -> SIP.Transport.TLSListener.connection_count(pid) == 1 end)

    :ssl.close(client)
    assert eventually(fn -> SIP.Transport.TLSListener.connection_count(pid) == 0 end)
  end

  # ── The WSS listener ─────────────────────────────────────────────────────────

  test "the WSS listener binds the family and the address it was given" do
    opts = [certfile: "certs/certificate.pem", keyfile: "certs/private_key.pem"]
    {:ok, pid} = GenServer.start(SIP.Transport.WSSListener, {@loopback_v6, 0, opts})
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)

    assert {:ok, @loopback_v6, port} = GenServer.call(pid, :getlocalipandport)
    assert {@loopback_v6, ^port} = Socket.local!(:sys.get_state(pid).socket)

    # And it upgrades over that family: a v6 client completes TLS then the
    # WebSocket handshake, and is counted.
    client =
      Socket.Web.connect!("[::1]", port,
        secure: true, verify: false, versions: [:"tlsv1.2"], protocol: ["sip"])

    assert eventually(fn -> SIP.Transport.WSSListener.connection_count(pid) == 1 end)

    Socket.Web.close(client)
    assert eventually(fn -> SIP.Transport.WSSListener.connection_count(pid) == 0 end)
  end

  # ── Two UDP sockets, one per family ──────────────────────────────────────────

  test "a node binds one UDP socket per family, on the same port" do
    {:ok, port} = SIP.NetUtils.pick_free_port(:udp)

    sockets =
      for {family, addr} <- [ipv4: @loopback_v4, ipv6: @loopback_v6] do
        {:ok, pid} = GenServer.start(SIP.Transport.UDP, {:bind, addr, port, [family: family]})
        on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)

        assert {:ok, ^addr, ^port} = GenServer.call(pid, :getlocalipandport)
        assert {:ok, {^addr, ^port}} = :inet.sockname(:sys.get_state(pid).socket)

        {family, pid}
      end

    # Two live sockets, distinct processes: the v6 one is not the v4 one wearing
    # a mapped address. `v6only` is what makes the shared port possible at all —
    # a dual-stack v6 wildcard claims the v4 port and the second bind fails.
    assert [{:ipv4, pid4}, {:ipv6, pid6}] = sockets
    refute pid4 == pid6

    # And each announces its own family in a Contact.
    assert SIP.Uri.serialize(SIP.Transport.build_contact_uri(SIP.Transport.UDP, pid4)) ==
             {:ok, "<sip:127.0.0.1:#{port};transport=udp>"}

    assert SIP.Uri.serialize(SIP.Transport.build_contact_uri(SIP.Transport.UDP, pid6)) ==
             {:ok, "<sip:[::1]:#{port};transport=udp>"}
  end

  test "an explicit bind ignores the app env, so two sockets can differ" do
    {:ok, port} = SIP.NetUtils.pick_free_port(:udp)
    # The env names a v4 address; the explicit bind is v6 and must win.
    Application.put_env(:elixip2, :udp_local_addr, @loopback_v4)
    Application.put_env(:elixip2, :udp_local_port, port + 1)

    {:ok, pid} =
      GenServer.start(SIP.Transport.UDP, {:bind, @loopback_v6, port, [family: :ipv6]})

    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)

    assert {:ok, @loopback_v6, ^port} = GenServer.call(pid, :getlocalipandport)
  end

  # ── The wildcard follows the family ──────────────────────────────────────────

  test "a TCP listener told :all binds the wildcard of ITS family" do
    {:ok, pid} = GenServer.start(SIP.Transport.TCPListener, {:all, 0, [family: :ipv4]})
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)

    assert {{0, 0, 0, 0}, _port} = Socket.local!(:sys.get_state(pid).socket)
  end

  # The IPv6 arm of the rule above needs a host carrying an advertisable IPv6
  # address: a listener has to write one into its Via and its Contact, so on a
  # v4-only host it stops :networkdown before it binds anything. Exercised on the
  # dual-stack machine, not here.
  @tag :skip
  test "a TCP listener told :all and :ipv6 binds ::" do
    {:ok, pid} = GenServer.start(SIP.Transport.TCPListener, {:all, 0, [family: :ipv6]})
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)

    assert {{0, 0, 0, 0, 0, 0, 0, 0}, _port} = Socket.local!(:sys.get_state(pid).socket)
  end

  test "a socket refuses the other family, which is why there are two" do
    {:ok, port} = SIP.NetUtils.pick_free_port(:udp)

    {:ok, v4} = GenServer.start(SIP.Transport.UDP, {:bind, @loopback_v4, port, [family: :ipv4]})
    {:ok, v6} = GenServer.start(SIP.Transport.UDP, {:bind, @loopback_v6, port, [family: :ipv6]})
    on_exit(fn -> for p <- [v4, v6], Process.alive?(p), do: GenServer.stop(p) end)

    msg = "OPTIONS sip:probe@unit.test SIP/2.0\r\n\r\n"

    # Each socket reaches its own family...
    assert :ok = GenServer.call(v4, {:sendmsg, msg, @loopback_v4, port})
    assert :ok = GenServer.call(v6, {:sendmsg, msg, @loopback_v6, port})

    # ...and only its own. This is the whole reason a node binds two: the kernel
    # answers :eafnosupport, so a single socket could never carry both. It holds
    # in both directions, `v6only` leaving the v6 socket no mapped-address
    # fallback to the v4 world.
    assert :transporterror = GenServer.call(v4, {:sendmsg, msg, @loopback_v6, port})
    assert :transporterror = GenServer.call(v6, {:sendmsg, msg, @loopback_v4, port})
  end

  defp eventually(check, attempts \\ 40) do
    cond do
      check.() -> true
      attempts == 0 -> false
      true -> Process.sleep(25) && eventually(check, attempts - 1)
    end
  end
end
