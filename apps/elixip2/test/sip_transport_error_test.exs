defmodule SIP.Test.TransportError do
  @moduledoc """
  A socket error from the peer stops the transport instance cleanly.

  Seen against the Teams Direct Routing hub: a fatal TLS alert arrives as
  `{:ssl_error, socket, reason}`, which no clause matched, so the instance died
  of a FunctionClauseError.
  """
  use ExUnit.Case, async: false

  @loopback {127, 0, 0, 1}
  @peer {{127, 0, 0, 2}, 5061}

  defp start_inbound(module, socket) do
    {peer_ip, peer_port} = @peer
    {:ok, pid} = GenServer.start(module, {:inbound, socket, @loopback, 0, peer_ip, peer_port})
    {pid, Process.monitor(pid)}
  end

  test "TLS: a fatal alert stops the instance normally" do
    {:ok, socket} =
      :ssl.listen(0,
        certfile: ~c"certs/certificate.pem",
        keyfile: ~c"certs/private_key.pem"
      )

    {pid, ref} = start_inbound(SIP.Transport.TLS, socket)

    alert =
      {:tls_alert, {:unexpected_message, ~c"CLIENT ALERT: Fatal - Unexpected Message"}}

    send(pid, {:ssl_error, socket, alert})

    assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 1_000
  end

  test "TCP: a socket error stops the instance normally" do
    {:ok, socket} = :gen_tcp.listen(0, [])
    {pid, ref} = start_inbound(SIP.Transport.TCP, socket)

    send(pid, {:tcp_error, socket, :econnreset})

    assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 1_000
  end
end
