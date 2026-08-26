defmodule SIP.Test.TransportSelector do
  @moduledoc """
  `SIP.Transport.Selector.select_transport/1` — the three levels of selection
  (kelixip design §6.4, decision §16.6):

    1. a live `tp_pid` → send over that flow, no DNS and no registry lookup;
    2. `destip` + `destport` already known → skip DNS, find/launch the transport;
    3. otherwise → resolve the R-URI (the historical path, covered by the rest of
       the suite).

  The assertions deliberately avoid depending on shared state: whether an
  unresolvable host yields `:invalidsipdestination` or `:invalidtransport`, and
  whether port 5060 is free, both depend on what the other test files did. So a
  fall-through is asserted as **"the flow was not used"**, and the transports
  launched here are local fakes with instance names that cannot collide with the
  real ones in `Registry.SIPTransport`.
  """
  use ExUnit.Case, async: false

  alias SIP.Transport.Selector

  # Stands in for an inbound connected transport (a browser's WSS spawned by the
  # listener): a live process that is NOT in Registry.SIPTransport.
  defmodule FakeFlow do
    use GenServer
    def transport_str, do: "wss"
    def is_reliable, do: true
    @impl true
    def init(_), do: {:ok, nil}
  end

  # A launchable fake: reliable, so its registry instance name carries the peer,
  # "UDP_<ip>:<port>" — never a name the node's real sockets use. It binds
  # nothing, so level 2 can be tested without touching a port.
  defmodule FakeDest do
    use GenServer
    def transport_str, do: "udp"
    def is_reliable, do: true
    @impl true
    def init(_), do: {:ok, nil}
  end

  # An unreliable launchable fake, under a protocol name of its own so its
  # instances cannot collide with the node's real UDP sockets.
  defmodule FakeDatagram do
    use GenServer
    def transport_str, do: "udpfake"
    def is_reliable, do: false
    @impl true
    def init(_), do: {:ok, nil}
  end

  setup_all do
    :ok = Selector.start()
    :ok
  end

  defp flow() do
    {:ok, pid} = GenServer.start_link(FakeFlow, nil)
    pid
  end

  defp dead_flow() do
    {:ok, pid} = GenServer.start(FakeFlow, nil)
    ref = Process.monitor(pid)
    GenServer.stop(pid)
    receive do: ({:DOWN, ^ref, :process, ^pid, _} -> :ok)
    pid
  end

  defp uri(fields) do
    struct(%SIP.Uri{userpart: "bob", domain: "nowhere.invalid", scheme: "sip:"}, fields)
  end

  # level 1 did not fire: whatever the selector returned, it is not that flow
  defp refute_flow_used(result, pid) do
    case result do
      %SIP.Uri{tp_pid: ^pid} -> flunk("the selector sent over the flow #{inspect(pid)}")
      _ -> :ok
    end
  end

  describe "level 1 — send over an existing flow" do
    test "a live tp_pid is used as-is, without resolving anything" do
      pid = flow()

      assert %SIP.Uri{tp_pid: ^pid, tp_module: FakeFlow, destproto: "WSS"} =
               Selector.select_transport(uri(tp_pid: pid, tp_module: FakeFlow))
    end

    test "an already resolved flow keeps its destination untouched" do
      pid = flow()

      selected =
        Selector.select_transport(
          uri(tp_pid: pid, tp_module: FakeFlow, destip: {10, 0, 0, 9}, destport: 41_234)
        )

      assert selected.destip == {10, 0, 0, 9}
      assert selected.destport == 41_234
      assert selected.tp_pid == pid
    end

    test "the module is derived from destproto when only that is known" do
      pid = flow()
      selected = Selector.select_transport(uri(tp_pid: pid, destproto: "WSS"))
      assert selected.tp_module == SIP.Transport.WSS
      assert selected.tp_pid == pid
    end

    test "a dead flow is not used (its binding is purged anyway)" do
      pid = dead_flow()

      Selector.select_transport(uri(tp_pid: pid, tp_module: FakeFlow))
      |> refute_flow_used(pid)
    end

    test "the transport is never guessed: no module and no destproto ⇒ not used" do
      pid = flow()

      Selector.select_transport(uri(tp_pid: pid))
      |> refute_flow_used(pid)
    end

    test "the unittest marker still wins over a live flow" do
      pid = flow()

      selected =
        Selector.select_transport(
          uri(tp_pid: pid, tp_module: FakeFlow, params: %{"unittest" => "1"})
        )

      refute_flow_used(selected, pid)
      assert selected.tp_module == SIP.Test.Transport.Mockup
    end
  end

  describe "level 2 — an already resolved destination skips DNS" do
    test "destip + destport: the stored destination is kept and the transport launched" do
      selected =
        Selector.select_transport(
          uri(destip: {10, 0, 0, 9}, destport: 41_235, destproto: "UDP", tp_module: FakeDest)
        )

      # kept as given — the resolver would have overwritten them from the host
      assert selected.destip == {10, 0, 0, 9}
      assert selected.destport == 41_235
      assert is_pid(selected.tp_pid)
      assert Process.alive?(selected.tp_pid)
    end

    test "no destproto ⇒ UDP (decision §16.6)" do
      selected =
        Selector.select_transport(uri(destip: {10, 0, 0, 10}, destport: 41_236, tp_module: FakeDest))

      assert selected.destproto == "UDP"
      assert is_pid(selected.tp_pid)
    end

    test "a destport of 0 is not a resolved destination" do
      # falls through to resolution, which does NOT keep destip as given
      result = Selector.select_transport(uri(destip: {10, 0, 0, 9}, tp_module: FakeDest))
      refute match?(%SIP.Uri{destip: {10, 0, 0, 9}}, result)
    end
  end
  describe "an unreliable transport has one instance per family" do
    test "the name carries the family, and the two do not collide" do
      assert Selector.unreliable_instance_name("UDP", :ipv4) == "UDP_ipv4"
      assert Selector.unreliable_instance_name("UDP", :ipv6) == "UDP_ipv6"
      refute Selector.unreliable_instance_name("UDP", :ipv4) ==
               Selector.unreliable_instance_name("UDP", :ipv6)
    end

    test "two destinations of different families get two instances" do
      v4 = uri(destip: {192, 0, 2, 1}, destport: 5060,
               destproto: "UDPFAKE", tp_module: FakeDatagram)
      v6 = uri(destip: {0x2001, 0xdb8, 0, 0, 0, 0, 0, 1}, destport: 5060,
               destproto: "UDPFAKE", tp_module: FakeDatagram)

      assert %SIP.Uri{tp_pid: pid4} = Selector.select_transport(v4)
      assert %SIP.Uri{tp_pid: pid6} = Selector.select_transport(v6)

      assert is_pid(pid4) and is_pid(pid6)

      # The whole point: a v6 datagram must not be handed the v4 socket, which
      # would answer :eafnosupport.
      refute pid4 == pid6
    end

    test "a second destination of the same family reuses its instance" do
      one = uri(destip: {192, 0, 2, 8}, destport: 5060,
                destproto: "UDPFAKE2", tp_module: FakeDatagram)
      two = uri(destip: {192, 0, 2, 9}, destport: 5062,
                destproto: "UDPFAKE2", tp_module: FakeDatagram)

      assert %SIP.Uri{tp_pid: pid} = Selector.select_transport(one)
      assert %SIP.Uri{tp_pid: ^pid} = Selector.select_transport(two)
    end
  end
end
