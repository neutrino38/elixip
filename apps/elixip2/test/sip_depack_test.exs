defmodule SIP.Test.SIP.Depack do
  # Pure reassembly over a binary: no listener, no singleton, nothing to serialise on.
  use ExUnit.Case, async: true
  doctest SIP.Transport.Depack

  test "depackize a simple SIP message" do
    depak = %SIP.Transport.Depack{}
    assert {:ok, msg} = File.read("test/SIP-REGISTER-AUTH.txt")

    func = fn _event, message ->
      {code, parsed_msg} =
        SIPMsg.parse(message, fn code, errmsg, lineno, line ->
          IO.puts("\n" <> errmsg)
          IO.puts("Offending line #{lineno}: #{line}")
          IO.puts("Error code #{code}")
        end)

      assert code == :ok
      assert parsed_msg.method == :REGISTER

      send(self(), :message_received)
    end

    depak = SIP.Transport.Depack.on_data_received(depak, msg, func)
    SIP.Transport.Depack.on_data_received(depak, "\r\n\r\n", func)

    # `on_data_received/3` calls the callback inline, so by the time both calls have
    # returned every invocation has already happened and its message is already in
    # this process's mailbox. That makes both of these questions about the mailbox as
    # it stands, not about the future: waiting cannot change either answer.
    #
    # It used to wait anyway — up to 10 s for the first (free, the message is there)
    # and a full second for the second, which was the whole cost of this file. And the
    # second was weaker for waiting: a 1 s window says "no second callback within a
    # second", where what is meant is "no second callback, full stop".
    assert_received :message_received
    refute_received :message_received
  end
end
