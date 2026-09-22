defmodule SIP.Test.BodyEncoding do
  use ExUnit.Case, async: true

  @moduledoc """
  `Content-Encoding` on an inbound body (RFC 3261 §20.12).

  The message below is the one that made this necessary: Linphone Desktop 6.2.2
  opening its buddy list with a single SUBSCRIBE whose resource list is deflated
  (RFC 5367 + RFC 4662, captured 2026-09-22). Every case here is about the same
  three invariants:

    * `Content-Length` counts the octets **on the wire**, so it is read before the
      body is decoded and re-stated as the size of the clear text afterwards;
    * the `Content-Encoding` header goes away with the compression it named — a
      message holding clear text under a `deflate` header is one a B2BUA relays
      wrong;
    * a coding we cannot undo is **refused**, never dropped: the parse code is what
      the transport turns into a 415.
  """

  @resource_list """
  <?xml version="1.0" encoding="UTF-8"?>
  <resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists">
   <list>
    <entry uri="sip:900020123@visioassistance.net"/>
    <entry uri="sip:magali.buu@weshwesh.eu"/>
   </list>
  </resource-lists>
  """

  defp nocb, do: fn _code, _msg, _line, _text -> nil end

  # The captured SUBSCRIBE, with whatever body and headers a case needs.
  defp subscribe(body, extra_headers) do
    "SUBSCRIBE sip:rls@sip.linphone.org SIP/2.0\r\n" <>
      "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK.59smhlIG8;rport\r\n" <>
      "From: \"Bob\" <sip:bob@weshwesh.eu>;tag=sxplenBxl\r\n" <>
      "To: <sip:rls@sip.linphone.org>\r\n" <>
      "CSeq: 20 SUBSCRIBE\r\n" <>
      "Call-ID: BO0d5IK3qZ\r\n" <>
      "Max-Forwards: 70\r\n" <>
      "Supported: eventlist\r\n" <>
      "Event: presence\r\n" <>
      "Expires: 3600\r\n" <>
      "Content-Type: application/resource-lists+xml\r\n" <>
      Enum.map_join(extra_headers, "", fn {name, value} -> "#{name}: #{value}\r\n" end) <>
      "Content-Length: #{byte_size(body)}\r\n\r\n" <>
      body
  end

  defp zlib(data), do: :zlib.compress(data)

  # Raw DEFLATE (RFC 1951), which is what half the field means by "deflate".
  defp raw_deflate(data) do
    z = :zlib.open()
    :ok = :zlib.deflateInit(z, :default, :deflated, -15, 8, :default)
    compressed = :zlib.deflate(z, data, :finish)
    :ok = :zlib.deflateEnd(z)
    :zlib.close(z)
    IO.iodata_to_binary(compressed)
  end

  defp body_data(msg) do
    case msg.body do
      [%{data: data} | _] -> data
      data when is_binary(data) -> data
    end
  end

  describe "a deflated body" do
    test "in zlib format (RFC 1950) reads as clear text" do
      raw = subscribe(zlib(@resource_list), [{"Content-Encoding", "deflate"}])

      assert {:ok, req} = SIPMsg.parse(raw, nocb())
      assert body_data(req) == @resource_list
    end

    test "in raw DEFLATE format (RFC 1951) reads the same" do
      raw = subscribe(raw_deflate(@resource_list), [{"Content-Encoding", "deflate"}])

      assert {:ok, req} = SIPMsg.parse(raw, nocb())
      assert body_data(req) == @resource_list
    end

    test "Content-Length counted the compressed octets, and now counts the clear ones" do
      compressed = zlib(@resource_list)
      raw = subscribe(compressed, [{"Content-Encoding", "deflate"}])

      # The premise of the whole reading: the two sizes differ, and the header on
      # the wire is the compressed one.
      assert byte_size(compressed) < byte_size(@resource_list)

      assert {:ok, req} = SIPMsg.parse(raw, nocb())
      assert req.contentlength == byte_size(@resource_list)
    end

    test "the Content-Encoding header goes away with the compression it named" do
      raw = subscribe(zlib(@resource_list), [{"Content-Encoding", "deflate"}])

      assert {:ok, req} = SIPMsg.parse(raw, nocb())

      refute Enum.any?(req, fn
               {key, _value} when is_binary(key) -> String.downcase(key) == "content-encoding"
               _other -> false
             end)

      assert SIP.Msg.Ops.body_encoding(req) == nil
    end

    test "re-serializing it announces the clear body, which is what a B2BUA relays" do
      raw = subscribe(zlib(@resource_list), [{"Content-Encoding", "deflate"}])
      {:ok, req} = SIPMsg.parse(raw, nocb())

      out = SIPMsg.serialize(req)

      refute out =~ "Content-Encoding"
      assert out =~ "Content-Length: #{byte_size(@resource_list)}"
      assert {:ok, reparsed} = SIPMsg.parse(out, nocb())
      assert body_data(reparsed) == @resource_list
    end

    # The coding is a token, held in lower case by the IANA registry, and a peer
    # writing `Deflate` means that token. (The header NAME is another matter: the
    # parser demands the canonical spelling of every header name it reads, which
    # is a bound of its own and not this reading's.)
    test "the coding value is case-insensitive" do
      raw = subscribe(zlib(@resource_list), [{"Content-Encoding", "Deflate"}])

      assert {:ok, req} = SIPMsg.parse(raw, nocb())
      assert body_data(req) == @resource_list
    end
  end

  describe "a body this node cannot read" do
    test "an unknown coding is refused, not dropped" do
      raw = subscribe(@resource_list, [{"Content-Encoding", "br"}])

      assert {:unsupported_content_encoding, req} = SIPMsg.parse(raw, nocb())
      # Enough of the request survives to answer it: the transport builds the 415
      # out of these.
      assert req.method == :SUBSCRIBE
      assert req.callid == "BO0d5IK3qZ"
    end

    test "a body that will not inflate gets the same refusal" do
      raw = subscribe("this is not deflated at all", [{"Content-Encoding", "deflate"}])

      assert {:unsupported_content_encoding, _req} = SIPMsg.parse(raw, nocb())
    end

    test "a truncated deflate stream is not taken for a clear body" do
      compressed = zlib(@resource_list)
      truncated = binary_part(compressed, 0, byte_size(compressed) - 5)
      raw = subscribe(truncated, [{"Content-Encoding", "deflate"}])

      assert {:unsupported_content_encoding, _req} = SIPMsg.parse(raw, nocb())
    end
  end

  describe "no coding at all" do
    test "identity is the body as sent" do
      raw = subscribe(@resource_list, [{"Content-Encoding", "identity"}])

      assert {:ok, req} = SIPMsg.parse(raw, nocb())
      assert body_data(req) == @resource_list
      assert req.contentlength == byte_size(@resource_list)
    end

    test "no header is the body as sent" do
      raw = subscribe(@resource_list, [])

      assert {:ok, req} = SIPMsg.parse(raw, nocb())
      assert body_data(req) == @resource_list
    end
  end
end
