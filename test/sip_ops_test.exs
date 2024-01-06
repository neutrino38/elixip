defmodule SIP.Test.SIPMsgOps do
  use ExUnit.Case
  doctest SIPMsgOps

  test "Create a 100 trying resp" do
    { code, msg } = File.read("test/SIP-INVITE-LVP.txt")
    assert code == :ok # Test if file containing the SIP message is loaded

    { code, parsed_msg } = SIPMsg.parse(msg, fn code, errmsg, lineno, line ->
    IO.puts("\n" <> errmsg)
    IO.puts("Offending line #{lineno}: #{line}")
    IO.puts("Error code #{code}")
    end)

    assert code == :ok
    assert parsed_msg.method == :INVITE

    siprsp = SIPMsgOps.reply_to_request(parsed_msg, 100, "Trying")
    assert siprsp.method == false
    assert siprsp.response_code == 100

    _siprsp_str = SIPMsg.serialize(siprsp)

  end


end
