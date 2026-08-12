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

  # The contract the depacketizer and the serializer share, and the one that broke:
  # Content-Length is the size of the message body ALONE (RFC 3261 §20.14). Depack
  # framed on that reading while `SIPMsg` parsed on another — it counted the CRLF
  # separating headers from body, so it kept `clen - 2` octets and every received
  # body silently lost its final CRLF while `:contentlength` kept the sender's
  # value. A B2BUA relaying that body over TCP then wrote 531 octets under a
  # `Content-Length: 533`, and the callee waited forever for two more: the INVITE
  # never completed, the call hung with no response at all, and the missing two
  # octets were finally supplied by the CANCEL that followed on the same
  # connection — so the callee rang exactly when the caller gave up, never saw the
  # CANCEL, and answered into a stream two octets out of step.
  test "a relayed message re-frames byte-for-byte: serialize -> depack -> same body" do
    sdp =
      "v=0\r\no=alice 3687 2887 IN IP4 172.22.0.4\r\ns=Talk\r\nc=IN IP4 172.22.0.4\r\n" <>
        "t=0 0\r\nm=audio 62540 RTP/AVP 96 0 8\r\na=rtpmap:96 opus/48000/2\r\n" <>
        "a=rtcp-fb:* ccm tmmbr\r\n"

    wire =
      "INVITE sip:bob@172.22.0.3:46334;transport=tcp SIP/2.0\r\n" <>
        "Via: SIP/2.0/TCP 172.21.105.71:5070;branch=z9hG4bKrelay1\r\n" <>
        "From: \"Alice\" <sip:alice@example.com>;tag=CqG4dY2En\r\n" <>
        "To: sip:bob@example.com\r\nCall-ID: relay-1\r\nCSeq: 21 INVITE\r\n" <>
        "Max-Forwards: 70\r\nContent-Type: application/sdp\r\n" <>
        "Content-Length: #{byte_size(sdp)}\r\n\r\n" <> sdp

    {:ok, inbound} = SIPMsg.parse(wire, fn _c, _m, _l, _li -> nil end)

    # Nothing is lost on the way in: the body is every octet Content-Length named,
    # final CRLF included.
    [part] = inbound.body
    assert part.data == sdp
    assert byte_size(part.data) == inbound.contentlength

    # …and the message we put back on the wire carries exactly that many octets,
    # which is what makes the far end's depacketizer able to find its end.
    relayed = SIPMsg.serialize(inbound)
    [_headers, body_out] = String.split(relayed, "\r\n\r\n", parts: 2)
    assert byte_size(body_out) == inbound.contentlength

    # Feed it to the depacketizer one octet at a time — a TCP peer is entitled to
    # split anywhere — and it must yield exactly one message, with nothing left
    # dangling and no second message conjured out of the tail.
    parent = self()
    cb = fn :msg, message -> send(parent, {:framed, message}) end

    depak =
      relayed
      |> :binary.bin_to_list()
      |> Enum.reduce(%SIP.Transport.Depack{}, fn byte, acc ->
        SIP.Transport.Depack.on_data_received(acc, <<byte>>, cb)
      end)

    assert_received {:framed, framed}
    refute_received {:framed, _other}
    assert framed == relayed
    assert depak.state == :wait_for_msg
    assert depak.buffer == ""

    {:ok, reparsed} = SIPMsg.parse(framed, fn _c, _m, _l, _li -> nil end)
    assert [%{data: ^sdp}] = reparsed.body
  end
end
