defmodule SIP.Test.MsgOpsParties do
  use ExUnit.Case, async: true

  @moduledoc """
  Every name a request gives for its caller and its callee, and the address it
  came from (`SIP.Msg.Ops.caller_users/1`, `callee_users/1`, `source_ip/1`) —
  what a kelixip debug trigger filters on (debug-triggers-plan.md, T1).
  """

  alias SIP.Msg.Ops

  defp uri(s) do
    {:ok, u} = SIP.Uri.parse(s)
    u
  end

  defp invite(fields), do: Map.merge(%{method: :INVITE}, Map.new(fields))

  describe "caller_users/1" do
    test "From, then every P-Asserted-Identity value" do
      req =
        invite(%{
          "P-Asserted-Identity" => "<sip:+33970260233@example.com>, <tel:+33970260234>",
          from: "\"Bob\" <sip:bob@example.com>;tag=1"
        })

      assert Ops.caller_users(req) == ["bob", "+33970260233", "+33970260234"]
    end

    test "two occurrences of P-Asserted-Identity arrive as a list" do
      req =
        invite(%{
          "p-asserted-identity" => ["tel:+33970260233", "sip:dave@example.com"],
          from: uri("sip:bob@example.com")
        })

      assert Ops.caller_users(req) == ["bob", "+33970260233", "dave"]
    end

    # Microsoft Teams Direct Routing, verbatim: bracketed, comma, no space.
    test "an unspaced bracketed pair yields both values" do
      req = invite(%{"P-Asserted-Identity" => "<tel:+33977190504>,<sip:emmanuel.buu@ives.fr>"})
      assert Ops.caller_users(req) == ["+33977190504", "emmanuel.buu"]
    end

    test "a comma inside a display name is not a value separator" do
      req = invite(%{"P-Asserted-Identity" => "\"Dupont, Jean\" <sip:jean@example.com>"})
      assert Ops.caller_users(req) == ["jean"]
    end

    test "the digest username is not a caller name" do
      req =
        invite(%{
          from: uri("sip:bob@example.com"),
          authorization: %{"username" => "alice", "authproc" => "Digest"}
        })

      assert Ops.caller_users(req) == ["bob"]
    end

    test "deduplicated: the same name in From and PAI counts once" do
      req = invite(%{"P-Asserted-Identity" => "<sip:bob@b.com>", from: "<sip:bob@a.com>;tag=1"})
      assert Ops.caller_users(req) == ["bob"]
    end

    test "nothing to read, or nothing readable, is an empty list" do
      assert Ops.caller_users(invite(%{})) == []
      assert Ops.caller_users(invite(%{"P-Asserted-Identity" => "junk", from: "junk <<"})) == []
      assert Ops.caller_users(invite(%{from: uri("sip:example.com")})) == []
    end
  end

  describe "callee_users/1" do
    test "To, then the Request-URI — a raw To string, as SIPMsg leaves it" do
      req = invite(%{to: "<sip:1002@example.com>", ruri: uri("sip:bob@10.0.0.5:5060")})
      assert Ops.callee_users(req) == ["1002", "bob"]
    end

    test "deduplicated when the request was not retargeted" do
      req = invite(%{to: uri("sip:1002@example.com"), ruri: uri("sip:1002@example.com")})
      assert Ops.callee_users(req) == ["1002"]
    end

    test "a Request-URI without user part leaves To alone" do
      req = invite(%{to: "<sip:1002@example.com>", ruri: uri("sip:example.com")})
      assert Ops.callee_users(req) == ["1002"]
    end

    test "nothing to read is an empty list" do
      assert Ops.callee_users(invite(%{})) == []
    end
  end

  describe "source_ip/1" do
    test "the address the transport layer stamped" do
      req = %{
        ruri: %SIP.Uri{
          userpart: "bob",
          domain: "example.com",
          destip: {192, 0, 2, 7},
          destport: 5061,
          tp_module: SIP.Transport.UDP
        }
      }

      assert Ops.source_ip(req) == {192, 0, 2, 7}
    end

    test "nil for a request that did not come off the network" do
      assert Ops.source_ip(%{ruri: %SIP.Uri{userpart: "bob", domain: "example.com"}}) == nil
      assert Ops.source_ip(%{}) == nil
    end
  end
end
