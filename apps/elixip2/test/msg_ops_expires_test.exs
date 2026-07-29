defmodule SIP.Test.MsgOpsExpires do
  use ExUnit.Case, async: true

  @moduledoc """
  The framework's single reading of the REGISTER lifetime rule
  (`SIP.Msg.Ops.requested_expires/2` & friends — RFC 3261 §10.2.4 precedence,
  §20.19 default, resolved per contact).

  Every case below is one that a re-derivation of this rule got wrong somewhere in
  the tree, each found on real traffic one at a time: the header ignored (a
  registration evaporating after 1 s), the header read *before* the Contact
  parameter (a rebinding handset taken for an un-registration), the precedence
  resolved across the request instead of per contact (same), a crash on a
  non-numeric parameter. They now all live here, once.
  """

  alias SIP.Msg.Ops

  defp uri(s) do
    {:ok, u} = SIP.Uri.parse(s)
    u
  end

  defp contact(s, expires),
    do: SIP.Uri.set_uri_param(uri(s), "expires", to_string(expires))

  defp register(fields), do: Map.merge(%{method: :REGISTER}, Map.new(fields))

  describe "precedence, per contact" do
    test "the Contact parameter wins over the Expires header" do
      req = register(contact: contact("sip:alice@example.com", 120), expires: 600)
      assert Ops.requested_expires(req) == 120
    end

    test "without a parameter, the Expires header applies" do
      req = register(contact: uri("sip:alice@example.com"), expires: 600)
      assert Ops.requested_expires(req) == 600
    end

    test "without either, the RFC default applies" do
      req = register(contact: uri("sip:alice@example.com"))
      assert Ops.requested_expires(req) == Ops.register_default_expires()
      assert Ops.requested_expires(req) == 3600
    end

    test "a caller can substitute its own default (kelixip's per-domain value)" do
      req = register(contact: uri("sip:alice@example.com"))
      assert Ops.requested_expires(req, 900) == 900
      assert Ops.contact_expires(uri("sip:alice@example.com"), nil, 900) == 900
    end

    test "a header carried as text is read, not compared as a term" do
      req = register(contact: uri("sip:alice@example.com"), expires: "60")
      assert Ops.expires_header(req) == 60
      assert Ops.requested_expires(req) == 60
    end

    test "no Contact at all: the header, else the default" do
      assert Ops.requested_expires(register(expires: 300)) == 300
      assert Ops.requested_expires(register([])) == 3600
      assert Ops.contact_lifetimes(register(expires: 300)) == []
    end
  end

  describe "a rebinding REGISTER is not an un-registration" do
    # The shape a real handset sends when it moves: drop the old binding, add the
    # new one whose lifetime is in the header only.
    setup do
      %{
        req:
          register(
            contact: [contact("sip:alice@1.1.1.1", 0), uri("sip:alice@2.2.2.2")],
            expires: 600
          )
      }
    end

    test "each contact resolves on its own", %{req: req} do
      assert Ops.contact_lifetimes(req) == [0, 600]
    end

    test "the request asks for its longest-lived binding", %{req: req} do
      assert Ops.requested_expires(req) == 600
      refute Ops.unregister?(req)
    end

    test "dropping every binding IS an un-registration" do
      req = register(contact: [contact("sip:alice@1.1.1.1", 0), contact("sip:alice@2.2.2.2", 0)])
      assert Ops.requested_expires(req) == 0
      assert Ops.unregister?(req)
    end

    test "Expires: 0 with no parameter is an un-registration" do
      req = register(contact: uri("sip:alice@example.com"), expires: 0)
      assert Ops.unregister?(req)
    end
  end

  describe "wildcard Contact (§10.2.2)" do
    test "carries no lifetime of its own: the header speaks for it" do
      assert Ops.unregister?(register(contact: :*, expires: 0))
      assert Ops.requested_expires(register(contact: :*, expires: 600)) == 600
      assert Ops.contact_expires_param(:*) == nil
    end
  end

  describe "tolerance" do
    # A malformed parameter must not crash the dialog that reads it. The URI parser
    # rejects such a URI outright today, so this shape only reaches us from a
    # message built in code — which is exactly where it used to raise.
    test "a valueless or non-numeric parameter falls back instead of raising" do
      valueless = %SIP.Uri{uri("sip:alice@example.com") | params: %{"expires" => true}}
      junk = %SIP.Uri{uri("sip:alice@example.com") | params: %{"expires" => "later"}}

      assert Ops.contact_expires_param(valueless) == nil
      assert Ops.contact_expires_param(junk) == nil
      assert Ops.contact_expires(valueless, 600) == 600
      assert Ops.contact_expires(junk, nil, 900) == 900
    end

    test "an absent or unusable Expires header reads as nil, not as a default" do
      assert Ops.expires_header(register([])) == nil
      assert Ops.expires_header(register(expires: "soon")) == nil
      assert Ops.expires_header(register(expires: -1)) == nil
    end

    test "an unparsed Contact reads through the header" do
      req = register(contact: "<sip:alice@example.com>", expires: 300)
      assert Ops.contact_lifetimes(req) == [300]
    end
  end
end
