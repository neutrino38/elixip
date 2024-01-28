defmodule SIP.Test.SIP.Msg.Ops do
  use ExUnit.Case
  doctest SIP.Msg.Ops

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

    siprsp = SIP.Msg.Ops.reply_to_request(context.sipreq, 100, "Trying")
    assert siprsp.method == false
    assert siprsp.response == 100

    _siprsp_str = SIPMsg.serialize(siprsp)

  end

  test "Create a 200 OK resp without body not totag", context do
    try do
      _siprsp = SIP.Msg.Ops.reply_to_request(context.sipreq, 200, "OK")
      assert false # An exception should have been thrown
    rescue
      RuntimeError -> :ok
    end
  end

  test "Create a 200 OK resp without body", context do
    try do
      _siprsp = SIP.Msg.Ops.reply_to_request(context.sipreq, 200, "OK", [], "zz77998")
      assert false # An exception should have been thrown
    rescue
      RuntimeError -> :ok
    end
  end

  test "Create a 200 OK resp with an empty body", context do
    try do
      _siprsp = SIP.Msg.Ops.reply_to_request(context.sipreq, 200, "OK", [ body: [] ], "zz77998")
      assert false # An exception should have been thrown
    rescue
      RuntimeError -> :ok
    end
  end

  test "Create a 200 OK resp with no contact field", context do
    try do
      body = %{ contentype: "application/sdp", data: "blabla"}
      _siprsp = SIP.Msg.Ops.reply_to_request(context.sipreq, 200, "OK", [ body: [ body ] ], "zz77998")
      assert false # An exception should have been thrown
    rescue
      RuntimeError -> :ok
    end
  end

  test "Add a single body to a SIP message" do
    body = %{ contenttype: "application/sdp", data: "blabla" }
    sipmsg = SIP.Msg.Ops.update_sip_msg(%{}, { :body, [ body ]})
    assert sipmsg.contenttype == "application/sdp"
    assert sipmsg.contentlength > 0

  end

  test "Create an INVITE 200 OK with all what's needed", context do
    body = %{ contenttype: "application/sdp", data: "blabla" }
    upd_fields = [ body: [ body ], contact: "<sip:90901@212.83.152.250:5090>" ]
    siprsp = SIP.Msg.Ops.reply_to_request(context.sipreq, 200, "OK", upd_fields, "zz77998")
    assert siprsp.method == false
    assert siprsp.response == 200

    _siprsp_str = SIPMsg.serialize(siprsp)
    #IO.puts(siprsp_str)

  end

  test "Create a 486 Busy, serialize it then reparse it", context do
    siprsp = SIP.Msg.Ops.reply_to_request(context.sipreq, 486, nil, [], "tt88767")
    assert siprsp.method == false
    assert siprsp.response == 486
    siprsp_str = SIPMsg.serialize(siprsp)
    { code, _parsed_msg } = SIPMsg.parse(siprsp_str, fn code, errmsg, lineno, line ->
      IO.puts("\n" <> errmsg)
      IO.puts("Offending line #{lineno}: #{line}")
      IO.puts("Error code #{code}")
      end)
    assert code == :ok
  end

  test "Create an ACK message from the request and serialize it", context do
    ackmsg = SIP.Msg.Ops.ack_request(context.sipreq, nil)
    assert ackmsg.method == :ACK
    assert is_map(ackmsg.ruri)
    assert ackmsg.ruri != nil
    _sipack_str = SIPMsg.serialize(ackmsg)
  end
end
