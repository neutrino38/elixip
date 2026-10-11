defmodule SIP.Test.SecurityTransport do
  # What the transport layer reports as an incident, on real sockets: the
  # sender's own address and port, and nothing for what is not an attack.
  use ExUnit.Case, async: false

  alias Elixip.Security.Incident

  @loopback {127, 0, 0, 1}

  defmodule Sink do
    def take(incident), do: send(:security_transport_test, {:incident, incident})
  end

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok
  end

  setup do
    prev = Application.get_env(:elixip2, :security_sink)
    prev_size = Application.get_env(:elixip2, :max_message_size)
    Process.register(self(), :security_transport_test)
    Application.put_env(:elixip2, :security_sink, {Sink, :take})

    on_exit(fn ->
      if prev,
        do: Application.put_env(:elixip2, :security_sink, prev),
        else: Application.delete_env(:elixip2, :security_sink)

      Application.put_env(:elixip2, :max_message_size, prev_size)
    end)

    :ok
  end

  defp udp_transport do
    {:ok, port} = SIP.NetUtils.pick_free_port(:udp)
    {:ok, tp} = GenServer.start(SIP.Transport.UDP, {:bind, @loopback, port, [family: :ipv4]})
    on_exit(fn -> if Process.alive?(tp), do: GenServer.stop(tp) end)

    {:ok, client} = :gen_udp.open(0, [:binary, :inet, ip: @loopback])
    {:ok, {_, client_port}} = :inet.sockname(client)
    {port, client, client_port}
  end

  defp register_wire do
    "REGISTER sip:example.com SIP/2.0\r\n" <>
      "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKsec1\r\n" <>
      "From: <sip:alice@example.com>;tag=1928301774\r\n" <>
      "To: <sip:alice@example.com>\r\n" <>
      "Call-ID: security-transport@example.com\r\n" <>
      "CSeq: 1 REGISTER\r\n" <>
      "Contact: <sip:alice@127.0.0.1:5060>\r\n" <>
      "Max-Forwards: 70\r\n" <>
      "Content-Length: 0\r\n\r\n"
  end

  test "a garbage UDP datagram is one invalid_packet from the sender's address and port" do
    {port, client, client_port} = udp_transport()
    :ok = :gen_udp.send(client, @loopback, port, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")

    assert_receive {:incident,
                    %Incident{
                      type: :invalid_packet,
                      src: @loopback,
                      port: ^client_port,
                      proto: "UDP",
                      reason: :unparsable
                    }},
                   1_000

    refute_receive {:incident, _}, 200
  end

  test "an empty datagram and a STUN binding request are not incidents" do
    {port, client, _} = udp_transport()
    :ok = :gen_udp.send(client, @loopback, port, "\r\n\r\n")
    :ok = :gen_udp.send(client, @loopback, port, <<0x0001::16, 0::16, 0x2112A442::32, 7::96>>)

    refute_receive {:incident, _}, 300
  end

  test "a datagram past the size bound is reported too_large" do
    Application.put_env(:elixip2, :max_message_size, 2_000)
    {port, client, client_port} = udp_transport()

    sdp = String.duplicate("a=padding-line-for-the-size-bound\r\n", 100)

    wire =
      "INVITE sip:bob@example.com SIP/2.0\r\n" <>
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKsec2\r\n" <>
        "From: <sip:alice@example.com>;tag=a\r\nTo: <sip:bob@example.com>\r\n" <>
        "Call-ID: too-large-sec\r\nCSeq: 1 INVITE\r\nMax-Forwards: 70\r\n" <>
        "Content-Type: application/sdp\r\nContent-Length: #{byte_size(sdp)}\r\n\r\n" <> sdp

    assert byte_size(wire) > 2_000
    :ok = :gen_udp.send(client, @loopback, port, wire)

    assert_receive {:incident,
                    %Incident{
                      type: :invalid_packet,
                      src: @loopback,
                      port: ^client_port,
                      proto: "UDP",
                      reason: :too_large
                    }},
                   1_000

    # …and it is still answered, as before.
    assert_receive {:udp, ^client, _ip, ^port, resp}, 1_000
    assert {:ok, %{response: 513}} = SIPMsg.parse(resp, fn _c, _m, _l, _li -> nil end)
  end

  test "a well-formed REGISTER is not an incident" do
    {port, client, _} = udp_transport()
    :ok = :gen_udp.send(client, @loopback, port, register_wire())

    refute_receive {:incident, _}, 500
  end

  test "over TCP, a stream that is not SIP is reported as garbage" do
    {:ok, listener} = GenServer.start(SIP.Transport.TCPListener, {@loopback, 0, []})
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    {:ok, _ip, port} = GenServer.call(listener, :getlocalipandport)

    {:ok, socket} = :gen_tcp.connect(@loopback, port, [:binary, {:active, false}])
    {:ok, {_, client_port}} = :inet.sockname(socket)
    :ok = :gen_tcp.send(socket, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

    assert_receive {:incident,
                    %Incident{
                      type: :invalid_packet,
                      src: @loopback,
                      port: ^client_port,
                      proto: "TCP",
                      reason: :garbage
                    }},
                   2_000

    :gen_tcp.close(socket)
  end

  test "over TLS, a client that connects and leaves without a handshake is a transport_error" do
    opts = [certfile: "certs/certificate.pem", keyfile: "certs/private_key.pem"]
    {:ok, listener} = GenServer.start(SIP.Transport.TLSListener, {@loopback, 0, opts})
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    {:ok, _ip, port} = GenServer.call(listener, :getlocalipandport)

    {:ok, socket} = :gen_tcp.connect(@loopback, port, [:binary, {:active, false}])
    {:ok, {_, client_port}} = :inet.sockname(socket)
    :ok = :gen_tcp.send(socket, "not a client hello\r\n")
    :gen_tcp.close(socket)

    assert_receive {:incident,
                    %Incident{
                      type: :transport_error,
                      src: @loopback,
                      port: ^client_port,
                      proto: "TLS",
                      reason: :tls_handshake
                    }},
                   3_000
  end
end
