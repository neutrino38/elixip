defmodule SIP.Test.MsgTooLarge do
  @moduledoc """
  A SIP message past the size bound is REFUSED, not dropped.

  The bound used to be 10 000 graphemes checked before any parsing, and a `raise`
  was all it did: the transport caught it, logged, and answered nothing. So a
  12 947-byte screen-sharing re-INVITE died two layers below the scenario, and the
  caller — unable to tell that silence from a network outage — waited out its
  Timer B. These tests pin the three halves of the fix: the bound is configurable,
  it is measured PAST the headers so a 513 can be built out of them, and a normal
  WebRTC offer now fits under it.
  """
  use ExUnit.Case
  require SIP.Uri

  alias SIP.Test.Transport.Mockup
  alias SIP.Test.Peers

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    Application.put_env(:elixip2, :proxyusesrv, false)
    :ok
  end

  setup do
    prev = Application.get_env(:elixip2, :max_message_size)
    on_exit(fn -> Application.put_env(:elixip2, :max_message_size, prev) end)
    :ok
  end

  defp put_limit(bytes), do: Application.put_env(:elixip2, :max_message_size, bytes)

  defp nocb(), do: fn _code, _errmsg, _lineno, _line -> nil end

  # An SDP-shaped filler of exactly `size` bytes: one a= line repeated, so the
  # body is plausible as well as big.
  defp filler(size) do
    line = "a=ssrc:1234567890 cname:padding-for-the-size-test\r\n"

    String.duplicate(line, div(size, byte_size(line)) + 1)
    |> binary_part(0, size)
  end

  defp invite_wire(sdp) do
    "INVITE sip:bob@example.com SIP/2.0\r\n" <>
      "Via: SIP/2.0/UDP 82.184.8.2:53936;branch=z9hG4bKtoolarge\r\n" <>
      "From: \"Alice\" <sip:alice@example.com>;tag=alice-tag\r\n" <>
      "To: <sip:bob@example.com>\r\n" <>
      "Call-ID: too-large-1\r\n" <>
      "CSeq: 7725 INVITE\r\n" <>
      "Max-Forwards: 70\r\n" <>
      "Contact: <sip:alice@82.184.8.2:53936>\r\n" <>
      "Content-Type: application/sdp\r\n" <>
      "Content-Length: #{byte_size(sdp)}\r\n\r\n" <> sdp
  end

  defp mockup_transport(name) do
    ruri =
      %SIP.Uri{scheme: "sip:", domain: "example.com", port: 5060}
      |> SIP.Uri.set_uri_param("unittest", name)
      |> SIP.Transport.Selector.select_transport()

    assert is_pid(ruri.tp_pid)
    ruri.tp_pid
  end

  test "the bound is configurable, and a message past it comes back with its headers" do
    put_limit(2_000)
    wire = invite_wire(filler(3_000))

    assert {:msg_too_large, req} = SIPMsg.parse(wire, nocb())

    # The headers are handed back BECAUSE a refusal has to be answerable: this is
    # what reply_to_request/3 needs, and none of it is known before the parse.
    assert req.method == :INVITE
    assert req.callid == "too-large-1"
    assert req.cseq == [7725, :INVITE]
    assert Map.has_key?(req, :via)

    resp = SIP.Msg.Ops.reply_to_request(req, 513, nil)
    assert resp.response == 513
    assert resp.reason == "Message too large"
  end

  test "the same message is accepted once the bound is raised above it" do
    wire = invite_wire(filler(3_000))

    put_limit(2_000)
    assert {:msg_too_large, _req} = SIPMsg.parse(wire, nocb())

    put_limit(10_000)
    assert {:ok, req} = SIPMsg.parse(wire, nocb())
    assert req.method == :INVITE
  end

  test "a WebRTC-sized offer fits under the configured default" do
    # Four m-sections of a screen-sharing offer weigh 12 947 bytes. The old bound
    # of 10 000 fell in the middle of normal use: three m-sections passed (8 501),
    # four did not.
    assert SIPMsg.max_message_size() == 64_000

    sdp = filler(12_947)
    assert {:ok, req} = SIPMsg.parse(invite_wire(sdp), nocb())
    assert [%{data: ^sdp}] = req.body
    assert req.contentlength == byte_size(sdp)
  end

  test "an oversized request is answered 513 on the transport it arrived on" do
    put_limit(2_000)
    tp_pid = mockup_transport("toolarge")
    :ok = Mockup.attach_probe(tp_pid)
    :ok = Mockup.set_peer(tp_pid, Peers.Passive, [])

    {:ok, req} = SIPMsg.parse(invite_wire("v=0\r\n"), nocb())
    big = filler(3_000)
    :ok = Mockup.inject(tp_pid, oversize(req, big))

    assert_receive {:sip_mockup, {:response_sent, 513, resp}}, 1_000
    assert resp.reason == "Message too large"
    assert resp.callid == "too-large-1"
    assert resp.cseq == [7725, :INVITE]
    # The refusal carries no body of its own.
    assert resp.contentlength == 0
  end

  test "an oversized ACK is dropped: an ACK is never answered" do
    put_limit(2_000)
    tp_pid = mockup_transport("toolargeack")
    :ok = Mockup.attach_probe(tp_pid)
    :ok = Mockup.set_peer(tp_pid, Peers.Passive, [])

    {:ok, req} = SIPMsg.parse(invite_wire("v=0\r\n"), nocb())
    ack = %{oversize(req, filler(3_000)) | method: :ACK, cseq: [7725, :ACK]}
    :ok = Mockup.inject(tp_pid, ack)

    refute_receive {:sip_mockup, {:response_sent, _code, _resp}}, 300
  end

  test "an oversized response is dropped: a response is never answered" do
    put_limit(2_000)
    big = filler(3_000)

    wire =
      "SIP/2.0 200 OK\r\n" <>
        "Via: SIP/2.0/UDP 82.184.8.2:53936;branch=z9hG4bKtoolarge\r\n" <>
        "From: \"Alice\" <sip:alice@example.com>;tag=alice-tag\r\n" <>
        "To: <sip:bob@example.com>;tag=bob-tag\r\n" <>
        "Call-ID: too-large-2\r\n" <>
        "CSeq: 7725 INVITE\r\n" <>
        "Content-Type: application/sdp\r\n" <>
        "Content-Length: #{byte_size(big)}\r\n\r\n" <> big

    # The test process stands in for the transport here: the refusal would go out
    # through SIP.Transport.send_msg/4, which is a GenServer.call on self(), so an
    # attempt to answer this response would land in this mailbox as a $gen_call.
    state = %{localip: {127, 0, 0, 1}, localport: 5060, upperlayer: nil}

    assert {:noreply, ^state} =
             SIP.Transport.ImplHelpers.process_incoming_message(
               state,
               wire,
               "UDP",
               nil,
               nil,
               {82, 184, 8, 2},
               53_936
             )

    refute_receive {:"$gen_call", _from, {:sendmsg, _msg, _ip, _port}}, 300
  end

  test "the depacketizer frames a 13 kB message arriving in a single read" do
    # It used to check its own 8 000-byte bound against the WHOLE accumulated
    # buffer, body included, and raise out of the transport's callback: the TCP
    # connection died instead of the parser getting a chance to refuse.
    sdp = filler(12_947)
    wire = invite_wire(sdp)

    parent = self()
    cb = fn :msg, message -> send(parent, {:framed, message}) end
    depak = SIP.Transport.Depack.on_data_received(%SIP.Transport.Depack{}, wire, cb)

    assert_received {:framed, ^wire}
    assert depak.state == :wait_for_msg
  end

  test "the depacketizer still bounds a header block that never ends" do
    put_limit(2_000)
    cb = fn _what, _msg -> nil end

    assert_raise RuntimeError, fn ->
      SIP.Transport.Depack.on_data_received(
        %SIP.Transport.Depack{},
        "INVITE sip:bob@example.com SIP/2.0\r\n" <> String.duplicate("X-Pad: pad\r\n", 400),
        cb
      )
    end
  end

  defp oversize(req, body) do
    %{req | body: [%{contenttype: "application/sdp", data: body}], contentlength: byte_size(body)}
  end
end
