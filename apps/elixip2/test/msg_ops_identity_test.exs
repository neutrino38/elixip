defmodule SIP.Test.MsgOpsIdentity do
  use ExUnit.Case, async: true

  @moduledoc """
  The framework's single reading of "who is this request from"
  (`SIP.Msg.Ops.asserted_username/1`): the digest username it authenticates with,
  else the user part of P-Asserted-Identity (RFC 3325), else the user part of
  From.

  The precedence is the point: From is what the caller claims, P-Asserted-Identity
  is what a trusted upstream asserts about it, and the digest username is the only
  one the server has had a chance to verify. Anything reading an identity out of a
  request — the monitor's `account` column, a module deciding what to display —
  goes through here rather than picking a header of its own.
  """

  alias SIP.Msg.Ops

  defp uri(s) do
    {:ok, u} = SIP.Uri.parse(s)
    u
  end

  # A map literal, not a keyword list: a header SIPMsg has no atom for is keyed by
  # its wire spelling, so the fields mix string and atom keys.
  defp invite(fields), do: Map.merge(%{method: :INVITE}, Map.new(fields))

  describe "precedence" do
    test "the digest username wins over both headers" do
      req =
        invite(%{
          "P-Asserted-Identity" => "<sip:+33970260233@example.com>",
          authorization: %{"username" => "alice", "authproc" => "Digest"},
          from: uri("sip:bob@example.com")
        })

      assert Ops.asserted_username(req) == "alice"
    end

    test "Proxy-Authorization counts as credentials too" do
      req = invite(%{proxyauthorization: %{"username" => "alice"}, from: uri("sip:bob@x.com")})
      assert Ops.asserted_username(req) == "alice"
    end

    test "without credentials, P-Asserted-Identity wins over From" do
      req =
        invite(%{
          "P-Asserted-Identity" => "\"Alice\" <sip:+33970260233@example.com>",
          from: uri("sip:anonymous@anonymous.invalid")
        })

      assert Ops.asserted_username(req) == "+33970260233"
    end

    test "without either, From is what is left" do
      req = invite(%{from: uri("\"Bob\" <sip:bob@example.com>;tag=x")})
      assert Ops.asserted_username(req) == "bob"
    end

    test "nil when the request asserts nothing" do
      assert Ops.asserted_username(invite(%{})) == nil
      assert Ops.asserted_username(invite(%{from: uri("sip:example.com")})) == nil
    end
  end

  describe "reading P-Asserted-Identity off the wire" do
    # SIPMsg has no atom for this header, so it lands under the spelling the peer
    # used — and header names are case-insensitive (RFC 3261 §7.3.1).
    test "the header name is matched case-insensitively" do
      req = invite(%{"p-asserted-IDENTITY" => "sip:carol@example.com"})
      assert Ops.asserted_username(req) == "carol"
    end

    # RFC 3325 §9.1: one sip: and one tel:, on one line or on two.
    test "two values on one line: the first that yields a user wins" do
      req = invite(%{"P-Asserted-Identity" => "sip:dave@example.com, tel:+33970260233"})
      assert Ops.asserted_username(req) == "dave"
    end

    test "two occurrences arrive as a list" do
      req = invite(%{"P-Asserted-Identity" => ["tel:+33970260233", "sip:dave@example.com"]})
      assert Ops.asserted_username(req) == "+33970260233"
    end

    test "a tel: URI asserts its number, parameters and brackets aside" do
      req = invite(%{"P-Asserted-Identity" => "<tel:+33970260233;phone-context=+33>"})
      assert Ops.asserted_username(req) == "+33970260233"
    end

    test "an unparsable value falls through to From rather than raising" do
      req = invite(%{"P-Asserted-Identity" => "junk", from: uri("sip:bob@example.com")})
      assert Ops.asserted_username(req) == "bob"
    end
  end

  describe "auth_username/1" do
    test "the claimed username, nil without credentials" do
      assert Ops.auth_username(invite(%{authorization: %{"username" => "alice"}})) == "alice"
      assert Ops.auth_username(invite(%{authorization: %{"username" => ""}})) == nil
      assert Ops.auth_username(invite(%{from: uri("sip:bob@x.com")})) == nil
    end
  end
end
