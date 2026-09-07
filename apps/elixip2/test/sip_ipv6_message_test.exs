defmodule SIP.Test.IPv6Message do
  @moduledoc """
  Reading and writing an `IPv6reference` (RFC 3261 §19.1.1 and §20.42 `sent-by`)
  in a SIP message: URIs, Via headers, and the addresses a transport hands over
  as tuples.
  """
  use ExUnit.Case, async: true

  # ── SIP.NetUtils.sip_host/1 — the one rendering point ─────────────────────────

  test "an IPv6 address is rendered as a bracketed reference" do
    assert SIP.NetUtils.sip_host({8193, 3512, 0, 0, 0, 0, 0, 1}) == "[2001:db8::1]"
    assert SIP.NetUtils.sip_host({0, 0, 0, 0, 0, 0, 0, 1}) == "[::1]"
    assert SIP.NetUtils.sip_host("2001:db8::1") == "[2001:db8::1]"
  end

  test "an IPv4 address, a hostname and an already bracketed literal are unchanged" do
    assert SIP.NetUtils.sip_host({192, 168, 1, 17}) == "192.168.1.17"
    assert SIP.NetUtils.sip_host("192.168.1.17") == "192.168.1.17"
    assert SIP.NetUtils.sip_host("domain.fr") == "domain.fr"
    assert SIP.NetUtils.sip_host("[::1]") == "[::1]"
  end

  # ── Parsing ───────────────────────────────────────────────────────────────────

  test "parse an IPv6 URI with no port" do
    {code, uri} = SIP.Uri.parse("sip:[2001:db8::1]")
    assert code == :ok
    assert uri.domain == "2001:db8::1"
    assert uri.port == 5060
  end

  test "parse an IPv6 URI with a user part and a port" do
    {code, uri} = SIP.Uri.parse("sip:bob@[2001:db8::1]:5070")
    assert code == :ok
    assert uri.userpart == "bob"
    assert uri.domain == "2001:db8::1"
    assert uri.port == 5070
  end

  test "parse an IPv6 name-addr with a header parameter" do
    {code, uri} = SIP.Uri.parse("<sip:bob@[::1]>;tag=x")
    assert code == :ok
    assert uri.domain == "::1"
    assert uri.hparams == %{"tag" => "x"}
  end

  test "parse an IPv6 URI carrying a transport parameter" do
    {code, uri} = SIP.Uri.parse("sip:[fd00::2]:5071;transport=tcp")
    assert code == :ok
    assert uri.domain == "fd00::2"
    assert uri.port == 5071
    assert uri.proto == "TCP"
  end

  # A link-local address in a Via or a Contact cannot be reached from another
  # link. :inet.parse_address/1 accepts the zone and drops it silently, so the
  # refusal has to be explicit.
  test "a zone identifier is refused" do
    {code, _uri} = SIP.Uri.parse("sip:[fe80::1%eth0]:5060")
    assert code == :invalid_sip_domain
  end

  test "an IPv6 literal without its brackets is refused" do
    {code, _uri} = SIP.Uri.parse("sip:2001:db8::1")
    assert code == :invalid_sip_domain
  end

  # Any host with two colons used to reach a `case` with no matching clause, so
  # the parser raised — and nothing on the inbound path rescued it, which took
  # the whole transport instance down. A typo, a scanner, anything.
  test "a malformed host is refused without raising" do
    for uri_str <- [
          "sip:[2001:db8::1",
          "sip:[not-an-address]:5060",
          "sip:[2001:db8::1]junk",
          "sip:[2001:db8::1]:notaport",
          "sip:[1.2.3.4]",
          "sip:a:b:c@domain.fr",
          "sip:bob@do@main.fr"
        ] do
      {code, _uri} = SIP.Uri.parse(uri_str)
      assert code != :ok, "#{uri_str} should not have parsed"
    end
  end

  # ── Serializing ───────────────────────────────────────────────────────────────

  test "round trip parse then serialize" do
    for uri_str <- [
          "sip:[2001:db8::1]",
          "sip:bob@[2001:db8::1]:5070",
          "<sip:bob@[::1]>;tag=x"
        ] do
      {:ok, uri} = SIP.Uri.parse(uri_str)
      assert {:ok, ^uri_str} = SIP.Uri.serialize(uri)
    end

    # A URI parameter forces the angle brackets (see the module doc); what
    # matters here is that the literal keeps them too.
    {:ok, uri} = SIP.Uri.parse("sip:[fd00::2]:5071;transport=tcp")
    assert {:ok, "<sip:[fd00::2]:5071;transport=tcp>"} = SIP.Uri.serialize(uri)
  end

  # The address a transport reports is a tuple, and it lands in `domain` as one
  # (SIP.Transport.build_contact_uri/2). Written by hand it came out as `sip:::1`.
  test "serialize an URI whose domain is an IPv6 tuple" do
    loopback = {0, 0, 0, 0, 0, 0, 0, 1}

    assert {:ok, "sip:[::1]"} =
             SIP.Uri.serialize(%SIP.Uri{domain: loopback, port: 5060, scheme: "sip:"})

    assert {:ok, "sip:[::1]:5070"} =
             SIP.Uri.serialize(%SIP.Uri{domain: loopback, port: 5070, scheme: "sip:"})

    assert {:ok, "sip:bob@[::1]:5070"} =
             SIP.Uri.serialize(%SIP.Uri{
               domain: loopback,
               userpart: "bob",
               port: 5070,
               scheme: "sip:"
             })
  end

  test "serialize a Request-URI whose domain is an IPv6 tuple" do
    uri = %SIP.Uri{
      domain: {8193, 3512, 0, 0, 0, 0, 0, 1},
      port: 5070,
      scheme: "sip:",
      displayname: "Bob",
      hparams: %{"tag" => "x"}
    }

    assert {:ok, "sip:[2001:db8::1]:5070"} = SIP.Uri.serialize_ruri(uri)
  end

  # ── Via ───────────────────────────────────────────────────────────────────────

  test "add_via writes a bracketed sent-by" do
    {:ok, msg} = File.read("test/SIP-INVITE-LVP.txt")
    {:ok, parsed} = SIPMsg.parse(msg, fn _c, _m, _l, _line -> :ok end)

    branch = "z9hG4bK6ea6b3a1"
    v6 = {8193, 3512, 0, 0, 0, 0, 0, 1}

    with_port = SIP.Msg.Ops.add_via(parsed, {v6, 5070, "TCP"}, branch)
    assert hd(with_port.via) == "SIP/2.0/TCP [2001:db8::1]:5070;branch=" <> branch

    default_port = SIP.Msg.Ops.add_via(parsed, {v6, 5060, "UDP"}, branch)
    assert hd(default_port.via) == "SIP/2.0/UDP [2001:db8::1];branch=" <> branch
  end

  # The branch is read back by reinjecting the sent-by into the URI parser
  # (SIPMsg.parse_transaction_id/2), so the Via depends on the same two fixes.
  test "parse a message whose Via and Contact are IPv6" do
    branch = "z9hG4bK6ea6b3a1"

    msg =
      [
        "REGISTER sip:[2001:db8::1]:5070 SIP/2.0",
        "Via: SIP/2.0/TCP [2001:db8::2]:5070;branch=" <> branch,
        "From: <sip:bob@[2001:db8::1]>;tag=abcd",
        "To: <sip:bob@[2001:db8::1]>",
        "Call-ID: 6a7b8c9d@[2001:db8::2]",
        "CSeq: 1 REGISTER",
        "Contact: <sip:bob@[2001:db8::2]:5070;transport=tcp>;expires=3600",
        "Max-Forwards: 70",
        "Content-Length: 0",
        "",
        ""
      ]
      |> Enum.join("\r\n")

    {code, parsed} = SIPMsg.parse(msg, fn _c, _m, _l, _line -> :ok end)

    assert code == :ok
    assert parsed.method == :REGISTER
    assert parsed.ruri.domain == "2001:db8::1"
    assert parsed.ruri.port == 5070
    assert parsed.transid == branch
    # From and To stay strings until someone reads a parameter out of them
    # (SIPMsg.compute_dialog_id/4 does, through the URI parser).
    assert {:ok, "abcd"} = SIP.Uri.get_uri_param(parsed.from, "tag")
    assert parsed.contact.domain == "2001:db8::2"
    assert parsed.contact.port == 5070
    assert parsed.contact.proto == "TCP"
  end
end
