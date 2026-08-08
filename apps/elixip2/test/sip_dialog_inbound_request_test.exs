defmodule SIP.Test.DialogInboundRequest do
  use ExUnit.Case, async: true

  @moduledoc """
  Requests we originate inside an INBOUND dialog (RFC 3261 §12.2.1.1).

  A UAS is the callee: its own identity is the *To* of the request that created
  the dialog, and the tag it generated is the *To* tag. Addressing an outbound
  BYE the UAC way — From from the original From, To from the original To —
  names the callee on both sides, and the far end matches no dialog.

  Found the day `play.exs` first reached its `hanging_up` state at end of file:
  the BYE raised before it could even be built, and once that was fixed the
  addressing was still the caller's. Nothing covered a UAS-originated in-dialog
  request until then.
  """

  alias SIP.DialogImpl

  # The INVITE a UAS receives: alice calls bob, alice's tag is on From.
  defp inbound_invite do
    %{
      method: :INVITE,
      ruri: %SIP.Uri{userpart: "bob", domain: "example.com"},
      from: %SIP.Uri{userpart: "alice", domain: "example.com", params: %{"tag" => "alice-tag"}},
      to: %SIP.Uri{userpart: "bob", domain: "example.com"},
      contact: %SIP.Uri{userpart: "alice", domain: "10.0.0.9", port: 5060}
    }
  end

  defp inbound_dialog do
    %DialogImpl{
      direction: :inbound,
      msg: inbound_invite(),
      fromtag: "alice-tag",
      totag: "bob-tag",
      remotetarget: %SIP.Uri{userpart: "alice", domain: "10.0.0.9", port: 5060}
    }
  end

  defp bare_bye do
    %{method: :BYE, ruri: %SIP.Uri{userpart: nil, domain: nil}, from: nil, to: nil}
  end

  describe "inbound dialog" do
    test "the BYE carries our identity in From and the caller's in To" do
      req = DialogImpl.address_in_dialog(bare_bye(), inbound_dialog())

      assert req.from.userpart == "bob"
      assert req.to.userpart == "alice"
    end

    test "the tags follow the same swap: ours on From, the caller's on To" do
      req = DialogImpl.address_in_dialog(bare_bye(), inbound_dialog())

      assert req.from.params["tag"] == "bob-tag"
      assert req.to.params["tag"] == "alice-tag"
    end

    test "the request is routed to the caller's Contact" do
      req = DialogImpl.address_in_dialog(bare_bye(), inbound_dialog())

      assert req.ruri.userpart == "alice"
      assert req.ruri.domain == "10.0.0.9"
    end

    test "the remote target and route set are learnt from the INVITE itself" do
      # An outbound dialog learns them from the establishing response; an inbound
      # one has no response to learn from, so init must take them off the request.
      invite = Map.put(inbound_invite(), :recordroute, "<sip:proxy.example.com;lr=on>")

      state = %DialogImpl{
        direction: :inbound,
        msg: invite,
        remotetarget: Map.get(invite, :contact),
        routeset: Map.get(invite, :recordroute, [])
      }

      assert state.remotetarget.domain == "10.0.0.9"

      assert DialogImpl.add_route_set(%{method: :BYE}, state).route ==
               "<sip:proxy.example.com;lr=on>"
    end
  end

  describe "outbound dialog is unchanged" do
    defp outbound_dialog do
      %DialogImpl{
        direction: :outbound,
        msg: %{
          method: :INVITE,
          ruri: %SIP.Uri{userpart: "bob", domain: "example.com"},
          from: %SIP.Uri{userpart: "alice", domain: "example.com"},
          to: %SIP.Uri{userpart: "bob", domain: "example.com"}
        },
        fromtag: "alice-tag",
        totag: "bob-tag",
        remotetarget: %SIP.Uri{userpart: "bob", domain: "10.0.0.7", port: 5060}
      }
    end

    test "we stay the From, the callee stays the To, tags likewise" do
      req =
        DialogImpl.address_in_dialog(
          %{
            method: :BYE,
            ruri: %SIP.Uri{userpart: nil, domain: nil},
            from: %SIP.Uri{userpart: "alice", domain: "example.com"},
            to: nil
          },
          outbound_dialog()
        )

      assert req.from.userpart == "alice"
      assert req.from.params["tag"] == "alice-tag"
      assert req.to.userpart == "bob"
      assert req.to.params["tag"] == "bob-tag"
      assert req.ruri.domain == "10.0.0.7"
    end
  end
end
