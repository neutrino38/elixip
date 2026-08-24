defmodule Kelix.Mod.McuIPv6Test do
  @moduledoc """
  IPv6 on the MCU module: the control channel, and the addressing profile a leg
  asks the media server for (`docs/design/multi-interface.md`, MCU section; MCU
  API §6.7 and §6.7 bis).

  Two halves, and they are independent. The **control channel** must reach a
  media server named by an IPv6 literal — that is a `:httpc` question, tested
  against a real loopback socket rather than a mock, because the failure it
  guards was invisible above the transport. The **profile** is what makes the
  media go out of the right interface, and it is read off the recorded RPCs.
  """
  use ExUnit.Case, async: false

  alias Kelix.Mcu.TestStub
  alias Kelix.Mod.Mcu
  alias Kelix.Mod.Mcu.{Client, Config, XmlRpc}

  @mediaservers [%{name: "mcu1", url: "http://127.0.0.1:18080"}]

  @domain "example.com"
  @rec_port 52_014
  @media_ip_v6 "2001:db8::12"

  # What a server carrying both families answers `GetNetworkProfiles` (§6.7).
  @profiles_both [
    %{
      "name" => "publicv4",
      "available" => true,
      "announced" => "203.0.113.12",
      "bind" => "",
      "default" => true
    },
    %{
      "name" => "publicv6",
      "available" => true,
      "announced" => @media_ip_v6,
      "bind" => @media_ip_v6,
      "default" => false
    },
    %{
      "name" => "internalv4",
      "available" => false,
      "announced" => "",
      "bind" => "",
      "default" => false
    },
    %{
      "name" => "internalv6",
      "available" => false,
      "announced" => "",
      "bind" => "",
      "default" => false
    }
  ]

  # The same server with no IPv6 address at all.
  @profiles_v4_only Enum.map(@profiles_both, fn
                      %{"name" => "publicv6"} = p -> %{p | "available" => false}
                      p -> p
                    end)

  # An IPv6 SIP phone: one address, in the family it will receive media on.
  @offer_v6 """
  v=0\r
  o=- 1 1 IN IP6 2001:db8:1::50\r
  s=-\r
  c=IN IP6 2001:db8:1::50\r
  t=0 0\r
  m=audio 40000 RTP/AVP 8 0 101\r
  a=rtpmap:8 PCMA/8000\r
  a=rtpmap:0 PCMU/8000\r
  a=rtpmap:101 telephone-event/8000\r
  a=sendrecv\r
  """

  # The same leg putting the call on hold, IPv6 style: RFC 6157 §4 spells the
  # legacy blackhole `::`, and nothing about it says "this media died".
  @offer_v6_hold String.replace(@offer_v6, "c=IN IP6 2001:db8:1::50", "c=IN IP6 ::")

  @offer_v4 """
  v=0\r
  o=- 1 1 IN IP4 192.168.1.50\r
  s=-\r
  c=IN IP4 192.168.1.50\r
  t=0 0\r
  m=audio 40000 RTP/AVP 8\r
  a=rtpmap:8 PCMA/8000\r
  a=sendrecv\r
  """

  defmodule MockDialog do
    @moduledoc "Captures the SIP replies the script composes."
    use GenServer

    def start_link(test), do: GenServer.start_link(__MODULE__, test)
    def init(test), do: {:ok, test}

    def handle_call({:replyreq, req, code, reason, fields}, _from, test) do
      send(test, {:replied, code, reason, fields, req})
      {:reply, :ok, test}
    end

    def handle_call({:newreq, req}, _from, test) do
      send(test, {:sent_request, Map.get(req, :method), req})
      {:reply, {:ok, self()}, test}
    end

    def handle_call(msg, _from, test) do
      send(test, {:dialog_call, msg})
      {:reply, :ok, test}
    end

    def handle_cast(_msg, test), do: {:noreply, test}
    def handle_info(_msg, test), do: {:noreply, test}
  end

  setup_all do
    %{
      scenario:
        SIP.Scenario.Loader.load_file!(Path.expand("../../kelixip/scripts/mcu.exs", __DIR__))
    }
  end

  setup context do
    {:ok, config} = Config.parse(%{"did_range" => "8000-8009", "dtmf" => true})
    start_supervised!({Mcu, config: config, module_name: "mcu", mediaservers: @mediaservers})

    profiles = Map.get(context, :profiles, @profiles_both)

    returns = %{
      "GetNetworkProfiles" => Map.get(context, :network_profiles, {:ok, profiles}),
      "StartReceiving" => {:ok, [@rec_port, Map.get(context, :media_ip, @media_ip_v6)]}
    }

    start_supervised!(
      {Client,
       name: "mcu1",
       base_url: "http://127.0.0.1:18080",
       transport: TestStub.transport(self(), returns),
       register: {Mcu, "mcu1"},
       reconnect_ms: 0},
      id: :client_mcu1
    )

    wait_for_client()

    {:ok, %{uid: uid, did: did}} =
      Mcu.handle_control("conference.create", %{"domain" => @domain, "name" => "Weekly"})

    _setup_rpcs = TestStub.rpc_order()

    %{uid: uid, did: did}
  end

  defp wait_for_client(attempts \\ 100) do
    case Mcu.mediaserver("mcu1") do
      {:ok, %{status: :up, client: pid}} when is_pid(pid) ->
        :ok

      _ when attempts > 0 ->
        Process.sleep(10)
        wait_for_client(attempts - 1)

      _ ->
        flunk("the mcu1 client never came up")
    end
  end

  defp invite(did, sdp) do
    %{
      method: :INVITE,
      ruri: %SIP.Uri{userpart: did, domain: @domain},
      from: %SIP.Uri{userpart: "alice", domain: "phone.example.com"},
      to: %SIP.Uri{userpart: did, domain: @domain},
      callid: "call-#{System.unique_integer([:positive])}",
      cseq: [1, :INVITE],
      body: sdp,
      contenttype: "application/sdp"
    }
  end

  defp start_call(scenario, req) do
    {:ok, dialog} = MockDialog.start_link(self())

    {pid, _ref} =
      SIP.Scenario.Runner.spawn_uas_instance(scenario,
        dialog_pid: dialog,
        inbound_request: req,
        config_overrides: [domain: @domain]
      )

    on_exit(fn -> if Process.alive?(pid), do: send(pid, {:scenario_ctl, :shutdown, :test}) end)
    send(pid, {:INVITE, req, nil, dialog})
    {pid, dialog}
  end

  defp wait_for(fun, attempts \\ 200) do
    case fun.() do
      nil when attempts > 0 ->
        Process.sleep(10)
        wait_for(fun, attempts - 1)

      false when attempts > 0 ->
        Process.sleep(10)
        wait_for(fun, attempts - 1)

      value ->
        value
    end
  end

  defp non_empty([]), do: nil
  defp non_empty(list), do: list

  # ── the control channel ──────────────────────────────────────────────────────

  describe "the XML-RPC channel over IPv6" do
    setup do
      # A one-shot XML-RPC responder on ::1, i.e. the real transport rather than
      # the recording stub: what broke was below the envelope.
      {:ok, listener} =
        :gen_tcp.listen(0, [:binary, ip: {0, 0, 0, 0, 0, 0, 0, 1}, active: false, reuseaddr: true])

      {:ok, port} = :inet.port(listener)

      body =
        "<?xml version=\"1.0\"?><methodResponse><params><param><value><struct>" <>
          "<member><name>returnCode</name><value><int>1</int></value></member>" <>
          "<member><name>returnVal</name><value><array><data>" <>
          "<value><int>7</int></value>" <>
          "</data></array></value></member>" <>
          "</struct></value></param></params></methodResponse>"

      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)
        {:ok, _request} = :gen_tcp.recv(socket, 0, 5_000)

        :gen_tcp.send(socket, [
          "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: ",
          Integer.to_string(byte_size(body)),
          "\r\nConnection: close\r\n\r\n",
          body
        ])

        :gen_tcp.close(socket)
      end)

      on_exit(fn -> :gen_tcp.close(listener) end)

      %{port: port}
    end

    test "a base_url naming an IPv6 literal reaches the server", %{port: port} do
      :ok = XmlRpc.ensure_profile()

      assert {:ok, [7]} =
               XmlRpc.call("http://[::1]:#{port}", "EventQueueCreate", [], timeout_ms: 2_000)
    end

    test "the profile asks for IPv6 first and falls back to IPv4" do
      # `:inet`, httpc's default, hands the bracketed host to an IPv4-only
      # connect and fails on :nxdomain before any byte leaves the node.
      assert XmlRpc.profile_options()[:ipfamily] == :inet6fb4
    end
  end

  # ── what the server says it carries ──────────────────────────────────────────

  describe "GetNetworkProfiles" do
    test "the channel reads the profiles at connection time" do
      {:ok, %{client: client}} = Mcu.mediaserver("mcu1")

      assert %{
               "publicv4" => %{available: true, announced: "203.0.113.12", default: true},
               "publicv6" => %{available: true, announced: @media_ip_v6, default: false},
               "internalv6" => %{available: false}
             } = Client.network_profiles(client)
    end

    @tag network_profiles: {:error, {:xmlrpc_fault, -506, "method not found"}}
    test "a server whose API predates it carries no profile knowledge" do
      {:ok, %{client: client}} = Mcu.mediaserver("mcu1")
      assert Client.network_profiles(client) == :unsupported
    end
  end

  # ── the profile of a leg ─────────────────────────────────────────────────────

  describe "the addressing profile a leg asks for" do
    test "an IPv6 caller asks for publicv6, on both planes", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did, @offer_v6))
      assert_receive {:replied, 200, _reason, fields, _req}, 2000

      # last parameter of StartReceiving (§6.7 bis), after the offer struct
      assert_received {:rpc, "StartReceiving",
                       [_conf, _part, _media, _map, _role, _proto, _offer, "publicv6"]}

      # and the answer advertises the address that profile announces
      assert fields[:body] =~ "c=IN IP6 #{@media_ip_v6}"

      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      ack_time = wait_for(fn -> non_empty(TestStub.rpc_calls()) end)

      # the same profile on the send plane: in symmetric RTP it is one socket, and
      # the server refuses a second, different one
      assert {"StartSending", [_conf, _part, _media, _ip, _port, _map, _role, "publicv6"]} =
               Enum.find(ack_time, fn {method, _params} -> method == "StartSending" end)
    end

    test "an IPv4 caller asks for publicv4 on the same conference", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did, @offer_v4))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      assert_received {:rpc, "StartReceiving",
                       [_conf, _part, _media, _map, _role, _proto, _offer, "publicv4"]}
    end

    @tag profiles: @profiles_v4_only
    test "a family the server does not carry refuses the call, never falls back", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did, @offer_v6))

      # A silent fallback would answer 200 with an IPv4 address an IPv6 caller
      # cannot reach: no media, nothing said, and the peer to discover it.
      assert_receive {:replied, 500, _reason, _fields, _req}, 2000
      refute_received {:replied, 200, _reason, _fields, _req}
      refute_received {:rpc, "StartReceiving", _params}
    end

    @tag network_profiles: {:error, {:xmlrpc_fault, -506, "method not found"}}
    @tag media_ip: "203.0.113.12"
    test "a server that knows no profile is called exactly as before", ctx do
      {_pid, _dialog} = start_call(ctx.scenario, invite(ctx.did, @offer_v4))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      # seven parameters, the call a controller that never heard of profiles makes
      assert_received {:rpc, "StartReceiving", [_conf, _part, _media, _map, _role, _proto, _offer]}
    end
  end

  # ── the IPv6 blackhole ───────────────────────────────────────────────────────

  describe "a hold spelled `c=IN IP6 ::`" do
    test "disarms the receive watchdog instead of reaping the call", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did, @offer_v6))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      send(pid, {:ACK, %{method: :ACK}, nil, dialog})
      _ack_time = wait_for(fn -> non_empty(TestStub.rpc_order()) end)

      send(pid, {:INVITE, invite(ctx.did, @offer_v6_hold), nil, dialog})
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      # 0 disarms (§16.1): a peer that blackholes its media owes us no RTP, and
      # watching it hangs up a perfectly healthy held call ten seconds later
      assert wait_for(fn ->
               receive do
                 {:rpc, "StartRTPTimeout", [_conf, _part, _media, 0, _role]} -> true
               after
                 0 -> nil
               end
             end)
    end

    test "the profile stays the one the leg fixed", ctx do
      {pid, dialog} = start_call(ctx.scenario, invite(ctx.did, @offer_v6))
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000
      _answer_time = TestStub.rpc_order()

      # `::` names no family to derive from, so a leg that re-derived its profile
      # here would send none at all and let the server fall back to publicv4 —
      # under a port it has already published.
      send(pid, {:INVITE, invite(ctx.did, @offer_v6_hold), nil, dialog})
      assert_receive {:replied, 200, _reason, _fields, _req}, 2000

      assert_received {:rpc, "StartReceiving",
                       [_conf, _part, _media, _map, _role, _proto, _offer, "publicv6"]}
    end
  end
end
