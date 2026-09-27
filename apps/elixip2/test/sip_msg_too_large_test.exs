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

  # The bound sits above OTP's default UDP receive buffer (1460 octets on an IPv6
  # socket, 8192 on IPv4): a 513 comes back only if the datagram reached the parser
  # whole. Cut to the buffer, it would fall under the bound and go on truncated.
  for {family, inet, addr} <- [
        {:ipv4, :inet, {127, 0, 0, 1}},
        {:ipv6, :inet6, {0, 0, 0, 0, 0, 0, 0, 1}}
      ] do
    test "a #{family} datagram past the default receive buffer reaches the parser whole" do
      addr = unquote(Macro.escape(addr))
      put_limit(9_000)
      {:ok, port} = SIP.NetUtils.pick_free_port(:udp)

      {:ok, tp_pid} =
        GenServer.start(SIP.Transport.UDP, {:bind, addr, port, [family: unquote(family)]})

      on_exit(fn -> if Process.alive?(tp_pid), do: GenServer.stop(tp_pid) end)

      {:ok, client} = :gen_udp.open(0, [:binary, unquote(inet), ip: addr])
      :ok = :gen_udp.send(client, addr, port, invite_wire(filler(9_500)))

      assert_receive {:udp, ^client, _ip, ^port, resp}, 1_000
      assert {:ok, %{response: 513}} = SIPMsg.parse(resp, nocb())
    end
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

  # ── What the depacketizer accumulates, and where it stops ──────────────────
  #
  # Three states hold attacker-controlled octets, and two of them used to hold
  # them without any bound: a first line that never ends (:wait_for_msg), and a
  # body whose Content-Length announced a gigabyte (:reading_body). One hundred
  # connections per listener by default, each able to make the node hold whatever
  # it cares to send.

  defp depack(data, buf \\ %SIP.Transport.Depack{}) do
    parent = self()

    SIP.Transport.Depack.on_data_received(buf, data, fn what, msg -> send(parent, {what, msg}) end)
  end

  test "a first line that never ends is bounded, and nothing is answered" do
    put_limit(2_000)

    buf = depack(String.duplicate("X", 3_000))

    # No CRLF, so not even a first line: there is nothing to build a response out
    # of, and the empty header block says so.
    assert_received {:too_large, ""}
    assert buf.state == :refused
    assert buf.buffer == ""
  end

  test "a header block that never ends is bounded, and nothing is answered" do
    put_limit(2_000)

    buf =
      depack("INVITE sip:bob@example.com SIP/2.0\r\n" <> String.duplicate("X-Pad: pad\r\n", 400))

    assert_received {:too_large, ""}
    assert buf.state == :refused
  end

  test "an announced body past the bound is refused before one octet is buffered" do
    put_limit(2_000)

    # Only the headers are sent: the gigabyte is never written, and the refusal
    # must not wait for it. This is what turns the attack into 450 bytes of work.
    headers =
      "INVITE sip:bob@example.com SIP/2.0\r\n" <>
        "Via: SIP/2.0/TCP 82.184.8.2:53936;branch=z9hG4bKflood\r\n" <>
        "From: \"Alice\" <sip:alice@example.com>;tag=alice-tag\r\n" <>
        "To: <sip:bob@example.com>\r\n" <>
        "Call-ID: flood-1\r\n" <>
        "CSeq: 1 INVITE\r\n" <>
        "Content-Type: application/sdp\r\n" <>
        "Content-Length: 1000000000\r\n\r\n"

    buf = depack(headers)

    assert_received {:too_large, handed_up}
    assert buf.state == :refused
    assert buf.body == ""

    # The header block handed up is answerable, which is the whole point of handing
    # it up rather than "". `:missing_body` is the expected code and not a failure:
    # we deliberately did not read the gigabyte it announces.
    assert {:missing_body, req} = SIPMsg.parse(handed_up, nocb())
    assert req.method == :INVITE
    assert req.callid == "flood-1"
    assert req.cseq == [1, :INVITE]
    resp = SIP.Msg.Ops.reply_to_request(req, 513, nil)
    assert resp.response == 513
    assert resp.reason == "Message too large"
  end

  test "a refused depacketizer frames nothing more" do
    put_limit(2_000)

    buf = depack(String.duplicate("X", 3_000))
    assert_received {:too_large, ""}

    # A whole valid message arriving behind the refusal is not framed: the
    # connection is on its way down.
    buf = depack(invite_wire("v=0\r\n"), buf)
    assert buf.state == :refused
    refute_received {:msg, _}
  end

  test "an unusable Content-Length is a 400, not a crash and not a desync" do
    # `String.to_integer/1` used to raise out of the transport's callback and kill
    # the connection with no answer at all.
    for value <- ["lots", "", "5x", "0x10"] do
      buf = depack(bodyless_invite("Content-Length: #{value}"))
      assert_received {:bad_frame, _headers}, "Content-Length: #{value} was not refused"
      assert buf.state == :refused
    end
  end

  test "a NEGATIVE Content-Length is refused, not framed backwards" do
    # It used to go straight through, and String.split_at/2 counts from the END:
    # split_at("abcdefgh", -5) is {"abc", "defgh"}. So the body was framed
    # truncated and its tail re-read as the start of the next message — a frame
    # desync on a connection several dialogs may be sharing.
    buf = depack(bodyless_invite("Content-Length: -5") <> "AAAAAAAAAAAAAAAAAAAA")

    assert_received {:bad_frame, _headers}
    assert buf.state == :refused
    refute_received {:msg, _}
  end

  test "a header line with no \": \" is skipped, not fatal" do
    # It used to be destructured as [header, val] and raise a MatchError, taking
    # the connection with it.
    wire = bodyless_invite("X-Broken\r\nContent-Length: 0")

    buf = depack(wire)
    assert_received {:msg, framed}
    assert framed == String.trim_trailing(wire, "\r\n\r\n")
    assert buf.state == :wait_for_msg
  end

  # ── Integer headers, read from the wire ────────────────────────────────────
  #
  # `String.to_integer/1` used to be called on four header values straight off the
  # network. A peer's typo then raised from INSIDE the parser, and the only thing a
  # transport could do with an exception was log "unparsable message" and drop it:
  # the reason was lost, and so was any chance of answering.

  test "a malformed integer header is a parse error, never an exception" do
    for {header, value, expected} <- [
          {"Content-Length", "lots", :invalid_contentlength_header},
          {"Content-Length", "5x", :invalid_contentlength_header},
          {"Content-Length", "-5", :invalid_contentlength_header},
          {"Expires", "soon", :invalid_expires_header},
          {"Expires", "-1", :invalid_expires_header},
          {"Max-Forwards", "many", :invalid_maxforwards_header},
          {"CSeq", "x INVITE", :invalid_cseq_header}
        ] do
      wire = integer_header_invite(header, value)

      code =
        try do
          SIPMsg.parse(wire, nocb()) |> elem(0)
        rescue
          e -> {:raised, e.__struct__}
        end

      assert code == expected, "#{header}: #{value} answered #{inspect(code)}"
    end
  end

  test "a well-formed integer header is still read, spaces and all" do
    assert {:ok, req} = SIPMsg.parse(integer_header_invite("Expires", "600"), nocb())
    assert req.expires == 600

    # Trailing whitespace is tolerated rather than fatal — the message layer owns
    # how forgiving the reading is (see the Message Layer note in CLAUDE.md).
    assert {:ok, req} = SIPMsg.parse(integer_header_invite("Expires", "600 "), nocb())
    assert req.expires == 600
  end

  # A REGISTER carrying `header: value` and no body. REGISTER rather than INVITE so
  # `Expires` is in its natural place.
  defp integer_header_invite(header, value) do
    "REGISTER sip:example.com SIP/2.0\r\n" <>
      "Via: SIP/2.0/TCP 82.184.8.2:53936;branch=z9hG4bKint\r\n" <>
      "From: \"Alice\" <sip:alice@example.com>;tag=alice-tag\r\n" <>
      "To: <sip:alice@example.com>\r\n" <>
      "Call-ID: int-1\r\n" <>
      if(header == "CSeq", do: "", else: "CSeq: 1 REGISTER\r\n") <>
      "#{header}: #{value}\r\n" <>
      if(header == "Content-Length", do: "", else: "Content-Length: 0\r\n") <> "\r\n"
  end

  # An INVITE whose last header is `extra`, with no body.
  defp bodyless_invite(extra) do
    "INVITE sip:bob@example.com SIP/2.0\r\n" <>
      "Via: SIP/2.0/TCP 82.184.8.2:53936;branch=z9hG4bKclen\r\n" <>
      "From: \"Alice\" <sip:alice@example.com>;tag=alice-tag\r\n" <>
      "To: <sip:bob@example.com>\r\n" <>
      "Call-ID: clen-1\r\n" <>
      "CSeq: 1 INVITE\r\n" <> extra <> "\r\n\r\n"
  end

  defp oversize(req, body) do
    %{req | body: [%{contenttype: "application/sdp", data: body}], contentlength: byte_size(body)}
  end
end
