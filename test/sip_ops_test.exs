defmodule SIP.Test.SIPMsgOps do
  use ExUnit.Case
  doctest SIPMsgOps

  setup_all do
    { code, msg } = File.read("test/SIP-INVITE-LVP.txt")
    assert code == :ok # Test if file containing the SIP message is loaded

    { code, parsed_msg } = SIPMsg.parse(msg, fn code, errmsg, lineno, line ->
    IO.puts("\n" <> errmsg)
    IO.puts("Offending line #{lineno}: #{line}")
    IO.puts("Error code #{code}")
    end)

    assert code == :ok
    assert parsed_msg.method == :INVITE

    { :ok, [ sipreq: parsed_msg ]}
  end

  test "Create a 100 trying resp", context do

    siprsp = SIPMsgOps.reply_to_request(context.sipreq, 100, "Trying")
    assert siprsp.method == false
    assert siprsp.response == 100

    _siprsp_str = SIPMsg.serialize(siprsp)

  end

  test "Create a 200 OK resp without body not totag", context do
    try do
      _siprsp = SIPMsgOps.reply_to_request(context.sipreq, 200, "OK")
      assert false # An exception should have been thrown
    rescue
      RuntimeError -> :ok
    end
  end

  test "Create a 200 OK resp without body", context do
    try do
      _siprsp = SIPMsgOps.reply_to_request(context.sipreq, 200, "OK", [], "zz77998")
      assert false # An exception should have been thrown
    rescue
      RuntimeError -> :ok
    end
  end

  test "Create a 200 OK resp with an empty body", context do
    try do
      _siprsp = SIPMsgOps.reply_to_request(context.sipreq, 200, "OK", [ body: [] ], "zz77998")
      assert false # An exception should have been thrown
    rescue
      RuntimeError -> :ok
    end
  end

  test "Create a 200 OK resp with no contact field", context do
    try do
      body = %{ contentype: "application/sdp", data: "blabla"}
      _siprsp = SIPMsgOps.reply_to_request(context.sipreq, 200, "OK", [ body: [ body ] ], "zz77998")
      assert false # An exception should have been thrown
    rescue
      RuntimeError -> :ok
    end
  end


  test "Create an INVITE 200 OK with all what's needed", context do
    body = %{ contentype: "application/sdp", data: "blabla"}
    upd_fields = [ body: [ body ], contact: "<sip:90901@212.83.152.250:5090>" ]
    siprsp = SIPMsgOps.reply_to_request(context.sipreq, 200, "OK", upd_fields, "zz77998")
    assert siprsp.method == false
    assert siprsp.response == 200

    _siprsp_str = SIPMsg.serialize(siprsp)

  end

end
