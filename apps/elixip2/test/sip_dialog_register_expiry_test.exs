defmodule SIP.Test.DialogRegisterExpiry do
  use ExUnit.Case, async: true

  @moduledoc """
  Regression tests for the lifetime a REGISTER dialog arms itself with
  (RFC 3261 §10.2.4 precedence: the Contact `expires` parameter when present,
  otherwise the `Expires` header, otherwise the default).

  Reading only the Contact parameter broke every real SIP phone: most send the
  lifetime as an `Expires` header and no parameter, so the dialog read "no
  lifetime", treated a plain registration as an un-registration and tore itself
  down after 1 s — which dropped the freshly stored binding through the
  registrar's monitor on the dialog pid. Observed against a real handset on
  2026-07-28, after synthetic probes (which all set the Contact parameter) had
  missed it.
  """

  alias SIP.DialogImpl

  # Remaining ms on the armed expiration timer, rounded to seconds.
  defp armed_seconds(req, direction \\ :inbound) do
    state = DialogImpl.arm_expiration_timer(%DialogImpl{direction: direction}, req)
    ms = :erlang.read_timer(state.expirationtimer)
    :erlang.cancel_timer(state.expirationtimer)
    round(ms / 1000)
  end

  defp register(fields), do: Map.merge(%{method: :REGISTER}, Map.new(fields))

  defp contact(params), do: %SIP.Uri{userpart: "alice", domain: "10.0.0.1", params: params}

  describe "inbound REGISTER" do
    test "the Expires header sets the lifetime when the Contact carries no parameter" do
      req = register(contact: contact(%{}), expires: 600)
      assert armed_seconds(req) == 600
    end

    test "the Contact parameter wins over the Expires header" do
      req = register(contact: contact(%{"expires" => "900"}), expires: 600)
      assert armed_seconds(req) == 900
    end

    test "with neither, the default applies rather than an immediate teardown" do
      assert armed_seconds(register(contact: contact(%{}))) == 3600
    end

    test "the longest-lived Contact wins when several are offered" do
      req = register(contact: [contact(%{"expires" => "120"}), contact(%{"expires" => "800"})])
      assert armed_seconds(req) == 800
    end

    # What a real handset does when it rebinds: ONE REGISTER carrying the old
    # contact with ;expires=0 to drop it, and the new one (bearing a +sip.instance)
    # whose lifetime is in the Expires header. Resolving the parameter across the
    # whole request instead of per contact yielded 0 — the removal alone — so the
    # dialog read a rebinding as an un-registration and tore itself down.
    test "a rebinding (drop one contact, add another) is NOT an un-registration" do
      req =
        register(
          contact: [
            contact(%{"expires" => "0"}),
            %SIP.Uri{
              userpart: "alice",
              domain: "10.0.0.2",
              params: %{"+sip.instance" => "<urn:uuid:f81d4fae>"}
            }
          ],
          expires: 600
        )

      assert armed_seconds(req) == 600
    end

    test "a contact with no parameter falls back to the header, per contact" do
      req = register(contact: [contact(%{"expires" => "0"}), contact(%{})], expires: 300)
      assert armed_seconds(req) == 300
    end

    test "an explicit 0 is an un-registration, whichever source states it" do
      # ~1 s teardown: the dialog only has to outlive the 200 OK
      assert armed_seconds(register(contact: contact(%{"expires" => "0"}))) == 1
      assert armed_seconds(register(contact: contact(%{}), expires: 0)) == 1
    end

    test "a wildcard Contact + Expires: 0 is an un-registration, not a crash" do
      assert armed_seconds(register(contact: :*, expires: 0)) == 1
    end
  end

  # The message that actually exposed the bug, captured off the wire on 2026-07-28
  # (sofia-sip 1.13.17 handset, `Supported: gruu, outbound`). Kept verbatim except
  # for the digest nonce/cnonce/response, blanked out: a `response=` is a hash
  # attackable offline for the HA1, and the test does not care about it.
  describe "the real rebinding REGISTER from a handset" do
    setup do
      {:ok, raw} = File.read("test/SIP-REGISTER-REBIND.txt")
      {:ok, req} = SIPMsg.parse(raw, fn _c, _m, _l, _li -> nil end)
      %{req: req}
    end

    test "it parses into two contacts, the removal and the new binding", %{req: req} do
      assert [new_contact, old_contact] = req.contact

      # the new binding: no expires parameter of its own, an RFC 5626 instance
      assert new_contact.domain == "172.21.104.60"
      assert SIP.Uri.get_uri_param(new_contact, "expires") == {:no_such_param, nil}
      assert {:ok, "1"} = SIP.Uri.get_uri_param(new_contact, "reg-id")

      # the contact being dropped
      assert old_contact.domain == "172.22.0.2"
      assert {:ok, "0"} = SIP.Uri.get_uri_param(old_contact, "expires")

      assert req.expires == 180
    end

    test "the dialog lives the 180 s of the Expires header, not 1 s", %{req: req} do
      # Before the fix the removal's `expires=0` won across the whole request, the
      # dialog read an un-registration and tore itself down after 1 s, killing the
      # instance and (over a connected transport) the binding with it.
      assert armed_seconds(req) == 180
    end

    test "the methods= parameter with commas inside quotes is not split", %{req: req} do
      assert [new_contact | _] = req.contact
      assert {:ok, methods} = SIP.Uri.get_uri_param(new_contact, "methods")
      assert methods =~ "INVITE" and methods =~ "UPDATE"
    end
  end

  describe "outbound REGISTER" do
    # The dialog's own timer is a safety net: it expires the dialog when the session
    # layer stops refreshing. It therefore runs for the FULL lifetime — at half of it
    # (which is when the session layer schedules its refresh) it would race the very
    # refresh it exists to catch, and could tear the dialog down just as the refresh
    # goes out. Sending the refresh was never done here: the handler behind the old
    # half-lifetime timer was a `# TODO send refresher` no-op.
    test "the dialog expires a client registration that is never refreshed" do
      req = register(contact: contact(%{}), expires: 600)
      assert armed_seconds(req, :outbound) == 600
    end

    test "an un-REGISTER tears the dialog down at once, in both directions" do
      req = register(contact: contact(%{"expires" => "0"}), expires: 0)
      assert armed_seconds(req, :outbound) <= 1
      assert armed_seconds(req, :inbound) <= 1
    end
  end
end
