defmodule SIP.Test.Stun do
  @moduledoc """
  `SIP.Stun` only has to answer one question today — "is this STUN and not SIP?" —
  but it answers it on a port that carries real signalling, so both directions of
  the mistake matter: a SIP message read as STUN disappears silently, and a STUN
  message read as SIP is reported as a parse error.

  Pure functions over binaries — nothing to serialise on.
  """
  use ExUnit.Case, async: true
  doctest SIP.Stun

  # A Binding Request as RFC 5626 §4.4.2 sends it to the SIP UDP port: type 0x0001
  # (class :request, method 0x001), no attributes, magic cookie, 96-bit txid.
  @txid <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12>>
  @binding_request <<0x0001::16, 0::16, 0x2112A442::32>> <> @txid

  test "decodes a Binding Request, keeping what a response would need" do
    assert {:ok, req} = SIP.Stun.decode(@binding_request)
    assert req.class == :request
    assert req.method == 0x001
    # A response echoes the request's transaction id (§6), so it has to survive.
    assert req.txid == @txid
    assert req.attributes == ""
    assert SIP.Stun.describe(req) == "Binding Request"
  end

  test "splits the class out of the interleaved type field" do
    # §6: the 2 class bits sit at positions 7 and 11 of the type field, so the
    # Binding Success Response is 0x0101 and the Error Response 0x0111.
    for {type, class} <- [
          {0x0001, :request},
          {0x0011, :indication},
          {0x0101, :success_response},
          {0x0111, :error_response}
        ] do
      assert {:ok, msg} = SIP.Stun.decode(<<type::16, 0::16, 0x2112A442::32>> <> @txid)
      assert msg.class == class
      assert msg.method == 0x001
    end
  end

  test "returns the attribute block still encoded" do
    # One 8-byte attribute: type 0x0020 (XOR-MAPPED-ADDRESS), length 4, value.
    attrs = <<0x0020::16, 4::16, 0xDEADBEEF::32>>
    packet = <<0x0101::16, byte_size(attrs)::16, 0x2112A442::32>> <> @txid <> attrs

    assert {:ok, msg} = SIP.Stun.decode(packet)
    assert msg.attributes == attrs
  end

  describe "message?/1 does not confuse STUN with SIP" do
    test "a real SIP message and a keep-alive are not STUN" do
      assert {:ok, register} = File.read("test/SIP-REGISTER.txt")
      refute SIP.Stun.message?(register)
      refute SIP.Stun.message?("\r\n\r\n")
      refute SIP.Stun.message?("")
    end

    test "the three header checks each reject" do
      # Wrong magic cookie.
      refute SIP.Stun.message?(<<0x0001::16, 0::16, 0xDEADBEEF::32>> <> @txid)

      # Leading bits not zero (this is where RTP/DTLS would fall, RFC 7983).
      refute SIP.Stun.message?(<<0x8001::16, 0::16, 0x2112A442::32>> <> @txid)

      # Declared length not a multiple of 4 (§15 pads every attribute to a word).
      refute SIP.Stun.message?(<<0x0001::16, 6::16, 0x2112A442::32>> <> @txid <> <<0::48>>)

      # Truncated: header cut short, then attributes shorter than announced.
      refute SIP.Stun.message?(binary_part(@binding_request, 0, 12))
      refute SIP.Stun.message?(<<0x0001::16, 8::16, 0x2112A442::32>> <> @txid <> <<0::32>>)
    end
  end
end
