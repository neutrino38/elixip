defmodule SIP.Test.SIP.Depack do
  use ExUnit.Case
  doctest SIP.Transport.Depack

  setup_all do
    :ok
  end

  test "depackize a simple SIP message" do
    depak = %SIP.Transport.Depack{}
    { code, msg } = File.read("test/SIP-REGISTER-AUTH.txt")
    assert code == :ok # Test if file containing the SIP message is loaded

    func = fn _event, message ->
      { code, parsed_msg } = SIPMsg.parse(message, fn code, errmsg, lineno, line ->
        IO.puts("\n" <> errmsg)
        IO.puts("Offending line #{lineno}: #{line}")
        IO.puts("Error code #{code}")
      end)

      assert code == :ok
      assert parsed_msg.method == :REGISTER

      send(self(), :message_received)
    end

    depak= SIP.Transport.Depack.on_data_received(depak, msg, func)
    IO.puts("adding empty line")
    SIP.Transport.Depack.on_data_received(depak, "\r\n\r\n", func)

    # Callback should be called only once
    receive do
      :message_received ->
        assert true

    after
      10_000 -> assert(false, "Callback was not called")
    end

    # Callback should be called only once
    receive do
      :message_received ->
        assert(false, "Callback was called a 2nd time")

    after
      1_000 -> assert true
    end

  end

end
