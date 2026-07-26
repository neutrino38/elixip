defmodule SIP.Test.DialogRouteSet do
  use ExUnit.Case, async: true

  @moduledoc """
  Regression tests for the dialog route set applied to in-dialog requests
  (RFC 3261 §12.2.1.1). A proxy chain returns several Record-Route headers,
  stored as a list; a single proxy returns one, stored as a binary. Both must
  end up on the BYE/re-INVITE, or the request bypasses the proxies and never
  reaches the far end (observed against kamailio + the IVeS WebRTC gateway,
  which insert two Record-Route headers).
  """

  alias SIP.DialogImpl

  describe "add_route_set/2" do
    test "a multi-Record-Route proxy chain (list) is copied verbatim" do
      rs = ["<sip:91.134.191.39;r2=on;lr=on>", "<sip:91.134.191.39:443;transport=ws;r2=on;lr=on>"]
      req = DialogImpl.add_route_set(%{method: :BYE}, %DialogImpl{routeset: rs})
      assert req.route == rs
    end

    test "a single Record-Route (binary) is copied verbatim" do
      req = DialogImpl.add_route_set(%{method: :BYE}, %DialogImpl{routeset: "<sip:91.134.191.39;lr=on>"})
      assert req.route == "<sip:91.134.191.39;lr=on>"
    end

    test "no route set (empty list default) adds no Route header" do
      req = DialogImpl.add_route_set(%{method: :BYE}, %DialogImpl{routeset: []})
      refute Map.has_key?(req, :route)
    end

    test "an empty-string route set adds no Route header" do
      req = DialogImpl.add_route_set(%{method: :BYE}, %DialogImpl{routeset: ""})
      refute Map.has_key?(req, :route)
    end
  end

  test "a list route set serializes to one Route header per hop" do
    rs = ["<sip:91.134.191.39;lr=on>", "<sip:91.134.191.39:443;transport=ws;lr=on>"]

    req = %{
      method: :BYE,
      ruri: %SIP.Uri{userpart: "bob", domain: "91.134.191.41", port: 5070},
      from: %SIP.Uri{userpart: "alice", domain: "example.com", params: %{"tag" => "a"}},
      to: %SIP.Uri{userpart: "bob", domain: "example.com", params: %{"tag" => "b"}},
      callid: "call-1",
      cseq: [3, :BYE],
      via: ["SIP/2.0/WSS 172.22.0.2:5060;branch=z9hG4bKtest"],
      contentlength: 0
    }

    serialized = req |> DialogImpl.add_route_set(%DialogImpl{routeset: rs}) |> SIPMsg.serialize()

    # one Route: line per hop, in the stored order
    routes = for line <- String.split(serialized, "\r\n"), String.starts_with?(line, "Route:"), do: line
    assert routes == ["Route: <sip:91.134.191.39;lr=on>", "Route: <sip:91.134.191.39:443;transport=ws;lr=on>"]
  end
end
