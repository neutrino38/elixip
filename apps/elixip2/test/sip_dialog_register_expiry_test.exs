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

    test "an explicit 0 is an un-registration, whichever source states it" do
      # ~1 s teardown: the dialog only has to outlive the 200 OK
      assert armed_seconds(register(contact: contact(%{"expires" => "0"}))) == 1
      assert armed_seconds(register(contact: contact(%{}), expires: 0)) == 1
    end

    test "a wildcard Contact + Expires: 0 is an un-registration, not a crash" do
      assert armed_seconds(register(contact: :*, expires: 0)) == 1
    end
  end

  describe "outbound REGISTER" do
    test "a client refreshes at half the granted lifetime" do
      req = register(contact: contact(%{}), expires: 600)
      assert armed_seconds(req, :outbound) == 300
    end
  end
end
