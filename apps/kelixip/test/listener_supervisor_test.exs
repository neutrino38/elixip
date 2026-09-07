defmodule Kelix.Listener.SupervisorTest do
  @moduledoc """
  Kelix.Listener.Supervisor — one child per [[listen]] entry (design §2.1).

  The tests bind real sockets on free high ports, so they run serially and use a
  test-owned supervisor (the application-level one has no [[listen]] entry, hence
  no child).
  """
  use ExUnit.Case, async: false

  alias Kelix.Listener.Supervisor, as: LSup

  setup do
    # A test-owned tree: Kelix.Listener.Supervisor registers itself under its own
    # name, so stop the (childless) application one for the duration of the test.
    :ok = Supervisor.terminate_child(Kelix.Supervisor, LSup)
    on_exit(fn -> Supervisor.restart_child(Kelix.Supervisor, LSup) end)
    :ok
  end

  defp free_port(proto) do
    {:ok, port} = SIP.NetUtils.pick_free_port(proto)
    port
  end

  defp entry(proto, port, extra \\ %{}) do
    Map.merge(%{proto: proto, addr: "127.0.0.1", port: port, cert: nil, key: nil}, extra)
  end

  test "no [[listen]] entry ⇒ no child, no port bound" do
    pid = start_supervised!({LSup, listen: []})
    assert Supervisor.which_children(pid) == []
    assert LSup.status() == []
  end

  test "a tcp entry binds the port and shows up in status/0" do
    port = free_port(:tcp)
    start_supervised!({LSup, listen: [entry(:tcp, port)]})

    assert [%{proto: :tcp, addr: "127.0.0.1", port: ^port, up: true}] = LSup.status()
    # the socket really is bound: a second bind on the same port must fail
    assert {:error, :eaddrinuse} = :gen_tcp.listen(port, [:binary, {:reuseaddr, true}])
  end

  test "a udp entry starts the bidirectional transport under the Selector's name" do
    port = free_port(:udp)
    start_supervised!({LSup, listen: [entry(:udp, port)]})

    # the app env names the node's primary udp socket (preferred_family/0 reads it)
    assert Application.get_env(:elixip2, :udp_local_port) == port

    # registered under the name the selector looks up ⇒ an outbound datagram of
    # that family reuses this socket instead of binding the same port again
    name = SIP.Transport.Selector.unreliable_instance_name("UDP", :ipv4)
    assert [{pid, _}] = Registry.lookup(Registry.SIPTransport, name)
    assert Process.alive?(pid)
  end

  test "a udp entry per family: both are kept, on the same port" do
    port = free_port(:udp)

    pid =
      start_supervised!(
        {LSup, listen: [entry(:udp, port), entry(:udp, port, %{addr: "::1"})]}
      )

    assert [{:udp, "127.0.0.1", ^port}, {:udp, "::1", ^port}] =
             Enum.map(Supervisor.which_children(pid), &elem(&1, 0)) |> Enum.sort()

    for family <- [:ipv4, :ipv6] do
      name = SIP.Transport.Selector.unreliable_instance_name("UDP", family)
      assert [{p, _}] = Registry.lookup(Registry.SIPTransport, name), "no #{family} socket"
      assert Process.alive?(p)
    end
  end

  test "two udp entries of the SAME family: only the first is kept" do
    p1 = free_port(:udp)
    p2 = free_port(:udp)
    pid = start_supervised!({LSup, listen: [entry(:udp, p1), entry(:udp, p2)]})

    assert [{:udp, "127.0.0.1", ^p1}] = Enum.map(Supervisor.which_children(pid), &elem(&1, 0))
  end


  describe "an entry with no addr binds every family the host carries" do
    # Host-dependent by nature, so the assertion is the RULE, not a fixed list:
    # one child per family the host has an advertisable address of. On a v4-only
    # host that is exactly one, and nothing changes from before step 4.
    defp host_families do
      Enum.filter([:ipv4, :ipv6], &(SIP.NetUtils.get_local_ips([&1]) != []))
    end

    test "one tcp child per family, each on the wildcard of its own family" do
      port = free_port(:tcp)
      pid = start_supervised!({LSup, listen: [entry(:tcp, port, %{addr: nil})]})

      bound = Enum.map(LSup.status(pid), & &1.addr) |> Enum.sort()
      expected = Enum.map(host_families(), &%{ipv4: "0.0.0.0", ipv6: "::"}[&1]) |> Enum.sort()

      assert bound == expected
      assert Enum.all?(Supervisor.which_children(pid), fn {_id, p, _, _} -> is_pid(p) end)
    end

    test "an explicit 0.0.0.0 stays IPv4 only — it is an IPv4 address" do
      port = free_port(:tcp)
      pid = start_supervised!({LSup, listen: [entry(:tcp, port, %{addr: "0.0.0.0"})]})

      assert [%{addr: "0.0.0.0"}] = LSup.status(pid)
    end
  end

  test "tls carries its own cert/key (per-listener certs, §3.1)" do
    # The framework default is the relative "certs/certificate.pem", which does not
    # exist from this app's directory — so binding here proves the per-listener
    # cert/key of the [[listen]] entry reached the listener.
    port = free_port(:tcp)

    certs = %{
      cert: Path.expand("../../elixip2/certs/certificate.pem", __DIR__),
      key: Path.expand("../../elixip2/certs/private_key.pem", __DIR__)
    }

    start_supervised!({LSup, listen: [entry(:tls, port, certs)]})
    assert [%{proto: :tls, port: ^port, up: true}] = LSup.status()
  end

  test "status/0 is empty when the supervisor is not running" do
    assert LSup.status() == []
  end
end
