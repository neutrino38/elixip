defmodule SIP.Test.KeepaliveCRLF do
  @moduledoc """
  Transport keep-alives (RFC 5626 §4.4.1 double CRLF and the variants clients
  actually send) are dropped, not reported as parse errors.

  Linphone pings a UDP registrar every 30 s with `\\r\\n\\r\\n`; each ping used to
  print three lines at :error/:info level (`bad_first_line`, "Failed to parse SIP
  msg first line", "Received an invalid SIP message from …"), so a night of idle
  phones buried the real errors.

  Pure functions over binaries — no listener, no singleton, nothing to serialise on.
  """
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  describe "SIPMsg.keepalive?/1" do
    test "recognises the keep-alive payloads seen on the wire" do
      # RFC 5626 §4.4.1 ping, its pong, and the variants (lone NUL, padding).
      assert SIPMsg.keepalive?("\r\n\r\n")
      assert SIPMsg.keepalive?("\r\n")
      assert SIPMsg.keepalive?("\n")
      assert SIPMsg.keepalive?(<<0>>)
      assert SIPMsg.keepalive?(" \t\r\n")

      # An empty datagram carries no message either.
      assert SIPMsg.keepalive?("")
    end

    test "does not swallow a real message nor a genuinely malformed one" do
      assert {:ok, register} = File.read("test/SIP-REGISTER.txt")
      refute SIPMsg.keepalive?(register)

      # Garbage must still be reported: silencing it would hide real bugs.
      refute SIPMsg.keepalive?("NOTASIPMESSAGE\r\n\r\n")
      refute SIPMsg.keepalive?("\r\n\r\nx")
    end
  end

  describe "transports" do
    test "a keep-alive datagram is dropped with no error in the log" do
      state = %{some: :state}

      log =
        capture_log(fn ->
          assert {:noreply, ^state} =
                   SIP.Transport.ImplHelpers.process_incoming_message(
                     state,
                     "\r\n\r\n",
                     "UDP",
                     SIP.Transport.UDP,
                     nil,
                     {172, 21, 104, 60},
                     36_157
                   )
        end)

      refute log =~ "invalid SIP message"
      refute log =~ "bad_first_line"
      assert log =~ "keep-alive"
    end

    test "a STUN packet is dropped and named as such" do
      state = %{some: :state}
      stun = <<0x0001::16, 0::16, 0x2112A442::32, 0::96>>

      log =
        capture_log(fn ->
          assert {:noreply, ^state} =
                   SIP.Transport.ImplHelpers.process_incoming_message(
                     state,
                     stun,
                     "UDP",
                     SIP.Transport.UDP,
                     nil,
                     {172, 21, 104, 60},
                     36_157
                   )
        end)

      refute log =~ "invalid SIP message"
      assert log =~ "STUN"
    end

    test "a CRLF ping on a stream transport does not eat the message behind it" do
      assert {:ok, register} = File.read("test/SIP-REGISTER.txt")
      me = self()

      cb = fn what, msg -> send(me, {what, msg}) end

      # One TCP segment: the ping, then a complete REGISTER. The ping used to take
      # the :error path, which flushed the whole buffer — REGISTER included.
      SIP.Transport.Depack.on_data_received(
        %SIP.Transport.Depack{},
        "\r\n\r\n" <> register <> "\r\n\r\n",
        cb
      )

      assert_received {:ping, ""}
      assert_received {:msg, delivered}
      assert {:ok, parsed} = SIPMsg.parse(delivered, fn _c, _m, _l, _line -> :ok end)
      assert parsed.method == :REGISTER
    end
  end
end
