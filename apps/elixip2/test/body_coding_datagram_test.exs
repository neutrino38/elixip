defmodule SIP.Test.BodyCodingDatagram do
  @moduledoc """
  A MESSAGE past 1300 octets on a datagram transport leaves deflated
  (`SIP.Msg.BodyCoding.fit_datagram/1`), and the body a store keeps is the body
  as it was on the wire (`SIPMsg.body_octets/1`) — docs/design/chat-media-plan.md, S1.
  """
  use ExUnit.Case, async: true

  alias SIP.Msg.BodyCoding

  @ft_xml """
  <?xml version="1.0" encoding="UTF-8"?>\r
  <file xmlns="urn:gsma:params:xml:ns:rcs:rcs:fthttp" xmlns:am="urn:gsma:params:xml:ns:rcs:rcs:rram">\r
  <file-info type="file">\r
  <file-size>48213</file-size>\r
  <file-name>IMG_20261002_102145.jpg</file-name>\r
  <content-type>image/jpeg</content-type>\r
  <data url="https://files.example.com/files/tmp/66fd0b2c1a2e3_9f8e7d6c5b4a39281706.jpg" until="2026-10-09T10:21:45Z"/>\r
  </file-info>\r
  </file>\r
  """

  defp message(body, contenttype, extra \\ %{}) do
    Map.merge(
      %{
        "Max-Forwards" => 70,
        method: :MESSAGE,
        ruri: %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "unit.test", port: 5060},
        via: ["SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKdatagram1"],
        from: "<sip:alice@unit.test>;tag=a1",
        to: "<sip:bob@unit.test>",
        callid: "datagram-test",
        cseq: [1, :MESSAGE],
        contenttype: contenttype
      },
      extra
    )
    |> SIP.Msg.Ops.update_sip_msg({:body, body})
    |> Map.put(:contenttype, contenttype)
  end

  # The CPIM envelope of a file message with a caption: what Trix sends.
  defp large_body do
    caption = String.duplicate("Une photo de la terrasse, prise ce matin. ", 15)

    "From: <sip:alice@unit.test>\r\nTo: <sip:bob@unit.test>\r\n" <>
      "DateTime: 2026-10-02T10:21:45Z\r\nNS: imdn <urn:ietf:params:imdn>\r\n" <>
      "imdn.Message-ID: 7Kq2xP9fLm3a\r\n\r\n" <>
      "Content-Type: application/vnd.gsma.rcs-ft-http+xml\r\n\r\n" <> @ft_xml <> caption
  end

  defp read_back(msg) do
    {:ok, parsed} = SIPMsg.parse(SIPMsg.serialize(msg), fn _, _, _, _ -> :ok end)
    parsed
  end

  describe "fit_datagram/1" do
    test "a MESSAGE that fits is left as it is" do
      msg = message("Rendez-vous jeudi", "text/plain;charset=UTF-8")
      assert BodyCoding.fit_datagram(msg) == msg
    end

    test "a MESSAGE past 1300 octets leaves deflated, and reads back to the same body" do
      msg = message(large_body(), "message/cpim")
      assert byte_size(SIPMsg.serialize(msg)) > 1300

      fitted = BodyCoding.fit_datagram(msg)
      wire = SIPMsg.serialize(fitted)

      assert fitted["Content-Encoding"] == "deflate"
      assert fitted.contenttype == "message/cpim"
      assert byte_size(wire) < 1300

      back = read_back(fitted)
      assert SIP.Msg.Ops.body_string(back) == large_body()
      assert back.decoded_from == "deflate"
    end

    test "a multipart is deflated whole, its Content-Type and boundary kept" do
      parts = [
        # Both end in whitespace of their own, which must read back as written.
        %{contenttype: "application/vnd.gsma.rcs-ft-http+xml", data: @ft_xml},
        %{contenttype: "text/plain;charset=UTF-8", data: String.duplicate("légende ", 120)}
      ]

      msg = SIP.Msg.Ops.update_sip_msg(message("", "text/plain"), {:body, parts})
      octets = SIPMsg.body_octets(msg.body)
      fitted = BodyCoding.fit_datagram(msg)

      assert fitted["Content-Encoding"] == "deflate"
      assert fitted.contenttype == msg.contenttype
      assert fitted.contenttype =~ "boundary="

      back = read_back(fitted)
      assert SIPMsg.body_octets(back.body) == octets
      assert Enum.map(back.body, & &1.data) == Enum.map(parts, & &1.data)
    end

    test "only a MESSAGE: an INVITE's SDP is never touched" do
      msg = message(String.duplicate("a=x\r\n", 400), "application/sdp", %{method: :INVITE})
      assert BodyCoding.fit_datagram(msg) == msg
    end

    test "a body already coded, or marked for clear, is left as it is" do
      coded = message(large_body(), "message/cpim", %{"Content-Encoding" => "identity"})
      assert BodyCoding.fit_datagram(coded) == coded

      clear = BodyCoding.send_in_clear(message(large_body(), "message/cpim"))
      assert BodyCoding.fit_datagram(clear) == clear
    end

    test "the clear mark never reaches the wire" do
      wire = SIPMsg.serialize(BodyCoding.send_in_clear(message("x", "text/plain")))
      refute wire =~ ~r/send_in_clear/i
    end
  end

  describe "coding_refused?/1" do
    test "a 415 listing codings without deflate" do
      assert BodyCoding.coding_refused?(%{"Accept-Encoding" => "identity", response: 415})
      assert BodyCoding.coding_refused?(%{"Accept-Encoding" => "gzip", response: 415})
    end

    test "not a 415 refusing the media type, nor one that reads deflate" do
      refute BodyCoding.coding_refused?(%{"Accept" => "text/plain", response: 415})
      refute BodyCoding.coding_refused?(%{"Accept-Encoding" => "deflate, gzip", response: 415})
      refute BodyCoding.coding_refused?(%{"Accept-Encoding" => "identity", response: 488})
    end
  end

  describe "SIPMsg.body_octets/1" do
    test "a parsed multipart is carried whole, with the boundary its type names" do
      body =
        "--b1\r\nContent-Type: application/vnd.gsma.rcs-ft-http+xml\r\n\r\n<file/>\r\n" <>
          "--b1\r\nContent-Type: text/plain;charset=UTF-8\r\n\r\nla terrasse\r\n--b1--\r\n"

      wire =
        "MESSAGE sip:bob@unit.test SIP/2.0\r\n" <>
          "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKoctets\r\n" <>
          "From: <sip:alice@unit.test>;tag=a1\r\nTo: <sip:bob@unit.test>\r\n" <>
          "Call-ID: octets\r\nCSeq: 1 MESSAGE\r\n" <>
          "Content-Type: multipart/mixed;boundary=b1\r\n" <>
          "Content-Length: #{byte_size(body)}\r\n\r\n" <> body

      {:ok, req} = SIPMsg.parse(wire, fn _, _, _, _ -> :ok end)

      assert SIP.Msg.Ops.body_string(req) == "<file/>"
      assert SIPMsg.body_octets(req.body) == body
    end

    test "a part's own trailing whitespace is kept; the delimiter's line break is not" do
      body =
        "--b1\r\nContent-Type: application/xml\r\n\r\n<file/>\r\n\r\n" <>
          "--b1\r\nContent-Type: text/plain;charset=UTF-8\r\n\r\nla terrasse \r\n--b1--\r\n"

      parts = SIPMsg.parse_multi_part_body("multipart/mixed;boundary=b1", body)

      assert Enum.map(parts, & &1.data) == ["<file/>\r\n", "la terrasse "]
      assert SIPMsg.multipart_body(parts) == body
    end

    test "a part with no MIME header, padding after a delimiter, bare LF line breaks" do
      body =
        "preamble\r\n--b1  \r\n\r\nno headers\r\n" <>
          "--b1\nContent-Type: text/plain\n\nline one\nline two\n--b1--\nepilogue"

      parts = SIPMsg.parse_multi_part_body("multipart/mixed;boundary=b1", body)

      assert Enum.map(parts, & &1.data) == ["no headers", "line one\nline two"]
      assert Enum.map(parts, & &1.contenttype) == ["text/plain; charset=UTF-8", "text/plain"]
    end

    test "a boundary string inside a part's data, not at a line start, does not split it" do
      body =
        "--b1\r\nContent-Type: text/plain\r\n\r\nsee --b1 here\r\n--b1--\r\n"

      [part] = SIPMsg.parse_multi_part_body("multipart/mixed;boundary=b1", body)
      assert part.data == "see --b1 here"
    end

    test "a blank line between a delimiter and Content-* headers is skipped (RFC 6442 examples)" do
      body =
        "--b1\r\n\r\nContent-Type: application/pidf+xml\r\nContent-ID: <t@x>\r\n\r\n<presence/>\r\n" <>
          "--b1\r\n\r\nTo: not a MIME header\r\n--b1--\r\n"

      [pidf, bare] = SIPMsg.parse_multi_part_body("multipart/mixed;boundary=b1", body)

      assert pidf.contenttype == "application/pidf+xml"
      assert pidf.data == "<presence/>"
      assert bare.data == "To: not a MIME header"
    end

    test "a bare body, a part without boundary, no body" do
      assert SIPMsg.body_octets("hello") == "hello"
      assert SIPMsg.body_octets([%{contenttype: "text/plain", data: "hello"}]) == "hello"
      assert SIPMsg.body_octets([]) == ""
      assert SIPMsg.body_octets(nil) == ""
    end
  end
end
