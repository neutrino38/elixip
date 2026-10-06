defmodule SIP.Test.MsgOpsMessage do
  use ExUnit.Case, async: true

  @moduledoc """
  The framework's single reading of a page-mode MESSAGE (RFC 3428):
  `SIP.Msg.Ops.message_kind/1`, `content_expires/1`, `instance_id/1` and
  `device_key/1` (docs/design/chat-basic-plan.md, C1).

  As for the presence readings: a value off the network may be junk and must read
  as "absent" rather than crash, and a parsed message answers exactly as a
  hand-built one.
  """

  alias SIP.Msg.Ops

  defp parsed(headers, body) do
    raw =
      "MESSAGE sip:bob@example.com SIP/2.0\r\n" <>
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776asdhds\r\n" <>
        "From: <sip:alice@example.com>;tag=1928301774\r\n" <>
        "To: <sip:bob@example.com>\r\n" <>
        "Call-ID: a84b4c76e66710@10.0.0.1\r\n" <>
        "CSeq: 1 MESSAGE\r\n" <>
        Enum.map_join(headers, "", fn {name, value} -> "#{name}: #{value}\r\n" end) <>
        "Content-Length: #{byte_size(body)}\r\n\r\n" <> body

    {:ok, req} = SIPMsg.parse(raw, fn _code, _msg, _line, _text -> nil end)
    req
  end

  defp built(headers, body) do
    headers
    |> Map.new()
    |> Map.merge(%{method: :MESSAGE, body: if(body == "", do: nil, else: body)})
  end

  defp both(headers, body, fun) do
    from_wire = fun.(parsed(headers, body))
    from_hand = fun.(built(headers, body))

    assert from_wire == from_hand,
           "parsed #{inspect(from_wire)} but hand-built #{inspect(from_hand)}"

    from_wire
  end

  defp cpim(inner_type, text \\ "Hello") do
    "From: <sip:alice@example.com>\r\n" <>
      "To: <sip:bob@example.com>\r\n" <>
      "DateTime: 2026-09-29T14:00:00Z\r\n" <>
      "NS: imdn <urn:ietf:params:imdn>\r\n" <>
      "imdn.Message-ID: 34jk324j\r\n" <>
      "\r\n" <>
      if(inner_type, do: "Content-Type: #{inner_type}\r\n", else: "") <>
      "\r\n" <> text
  end

  describe "message_kind/1" do
    cases = [
      {"plain text", "text/plain;charset=UTF-8", "Hello", :im},
      {"a typing indicator", "application/im-iscomposing+xml", "<isComposing/>", :is_composing},
      {"the type is case-insensitive", "Application/Im-IsComposing+XML", "<isComposing/>",
       :is_composing},
      {"a disposition notification", "message/imdn+xml", "<imdn/>", :imdn}
    ]

    for {name, ct, body, expected} <- cases do
      test name do
        assert both([{"Content-Type", unquote(ct)}], unquote(body), &Ops.message_kind/1) ==
                 unquote(expected)
      end
    end

    test "a CPIM envelope is read through to the type it wraps" do
      ct = [{"Content-Type", "message/cpim"}]
      assert both(ct, cpim("text/plain; charset=utf-8"), &Ops.message_kind/1) == :im

      assert both(ct, cpim("application/im-iscomposing+xml"), &Ops.message_kind/1) ==
               :is_composing

      assert both(ct, cpim("message/imdn+xml"), &Ops.message_kind/1) == :imdn
    end

    test "a CPIM envelope with LF line endings is read too" do
      body = String.replace(cpim("application/im-iscomposing+xml"), "\r\n", "\n")
      assert Ops.message_kind(built([{"Content-Type", "message/cpim"}], body)) == :is_composing
    end

    test "a Content-Type line in the text of the message is the user's, not the envelope's" do
      body = cpim("text/plain", "Content-Type: application/im-iscomposing+xml")
      assert Ops.message_kind(built([{"Content-Type", "message/cpim"}], body)) == :im
    end

    test "a CPIM envelope naming no type, an envelope with no body, no body at all: :im" do
      ct = [{"Content-Type", "message/cpim"}]
      assert both(ct, cpim(nil), &Ops.message_kind/1) == :im
      assert Ops.message_kind(built(ct, "")) == :im
      assert Ops.message_kind(%{method: :MESSAGE}) == :im
    end
  end

  describe "content_expires/1" do
    test "the sender's Expires, in seconds" do
      assert both(
               [{"Content-Type", "text/plain"}, {"Expires", "120"}],
               "Hi",
               &Ops.content_expires/1
             ) == 120
    end

    test "absent is nil, not a default" do
      assert both([{"Content-Type", "text/plain"}], "Hi", &Ops.content_expires/1) == nil
    end

    test "junk is nil" do
      assert Ops.content_expires(built([{"Expires", "soon"}], "Hi")) == nil
      assert Ops.content_expires(built([{"Expires", ""}], "Hi")) == nil
    end
  end

  describe "instance_id/1 and device_key/1" do
    defp contact(s) do
      {:ok, u} = SIP.Uri.parse(s)
      u
    end

    test "the instance ID, unquoted, out of its brackets, a UUID folded to lower case" do
      c =
        contact(
          "<sip:bob@10.0.0.2:5060;transport=tcp>;expires=600;" <>
            "+sip.instance=\"<urn:uuid:A11CE000-0000-4000-8000-000000000001>\";reg-id=1"
        )

      assert Ops.instance_id(c) == "urn:uuid:a11ce000-0000-4000-8000-000000000001"
      assert Ops.device_key(c) == "urn:uuid:a11ce000-0000-4000-8000-000000000001"
    end

    test "the same device re-registering from a new address keeps its key" do
      instance = "+sip.instance=\"<urn:uuid:a11ce000-0000-4000-8000-000000000001>\""
      a = contact("<sip:bob@10.0.0.2:5060>;expires=600;" <> instance)
      b = contact("<sip:bob@192.0.2.7:40112;transport=tcp>;expires=3600;" <> instance)
      assert Ops.device_key(a) == Ops.device_key(b)
    end

    test "a URN other than a UUID is kept as sent" do
      c = contact("<sip:bob@10.0.0.2>;+sip.instance=\"<urn:gsma:imei:35-209900-176148-1>\"")
      assert Ops.instance_id(c) == "urn:gsma:imei:35-209900-176148-1"
    end

    test "no instance ID: the contact URI, without its header parameters" do
      a = contact("<sip:bob@10.0.0.2:5060;transport=tcp>;expires=600;q=0.5")
      b = contact("<sip:bob@10.0.0.2:5060;transport=tcp>;expires=3600")
      assert Ops.instance_id(a) == nil
      # 5060 is the default port and is not written: the same address either way
      assert Ops.device_key(a) == "sip:bob@10.0.0.2;transport=tcp"
      assert Ops.device_key(a) == Ops.device_key(b)
    end

    test "junk reads as absent rather than crashing" do
      assert Ops.instance_id(contact("<sip:bob@10.0.0.2>;+sip.instance")) == nil
      assert Ops.instance_id(contact("<sip:bob@10.0.0.2>;+sip.instance=\"<>\"")) == nil
      assert Ops.instance_id(nil) == nil
      assert Ops.device_key(:*) == nil
    end
  end

  describe "page_summary/1" do
    test "kind, sender, type and size — never the text" do
      msg = %{
        from: "\"Alice\" <sip:alice@Example.com>;tag=1",
        contenttype: "text/plain;charset=UTF-8",
        body: "Rendez-vous jeudi"
      }

      summary = Ops.page_summary(msg)
      assert summary == "im from alice@example.com (text/plain, 17 octets)"
      refute summary =~ "Rendez-vous"
      assert Ops.page_summary(%{}) == "im from an unknown sender (no type, 0 octets)"
    end
  end

  describe "arrival_flow/1, reach_contact/2, register_targets/1" do
    defp uri(s) do
      {:ok, u} = SIP.Uri.parse(s)
      u
    end

    # A REGISTER as the transport layer hands it over: its R-URI stamped with
    # where it came from and the connection that carried it.
    defp register(contacts, extra \\ %{}) do
      ruri = %SIP.Uri{
        uri("sip:example.com")
        | destip: {192, 0, 2, 7},
          destport: 40112,
          destproto: "TCP",
          tp_pid: self(),
          tp_module: SIP.Transport.TCP
      }

      Map.merge(%{method: :REGISTER, ruri: ruri, contact: Enum.map(contacts, &uri/1)}, extra)
    end

    test "the flow is where the request came from, and over what" do
      assert Ops.arrival_flow(register([])) == %{
               received: {"TCP", {192, 0, 2, 7}, 40112},
               tp_pid: self(),
               tp_module: SIP.Transport.TCP
             }

      assert Ops.arrival_flow(%{}) == %{received: nil, tp_pid: nil, tp_module: nil}
    end

    test "a contact is reached as a Request-URI over the flow, keeping its instance ID" do
      c =
        uri(
          ~s("Bob" <sip:bob@10.0.0.2:5060;transport=tcp>;expires=600;q=0.5;) <>
            ~s(+sip.instance="<urn:uuid:a11ce000-0000-4000-8000-000000000001>")
        )

      target = Ops.reach_contact(c, Ops.arrival_flow(register([])))

      assert target.displayname == nil
      assert target.destip == {192, 0, 2, 7} and target.destport == 40112
      assert target.tp_pid == self()
      assert Ops.device_key(target) == "urn:uuid:a11ce000-0000-4000-8000-000000000001"
      assert {:ok, "sip:bob@10.0.0.2;transport=tcp"} = SIP.Uri.serialize_ruri(target)
    end

    test "a REGISTER reaches the contacts it binds, not the ones it drops" do
      req = register(["<sip:bob@10.0.0.2>;expires=0", "<sip:bob@10.0.0.3>", "<sip:bob@10.0.0.4>"])
      req = Map.put(req, :expires, "600")

      assert [a, b] = Ops.register_targets(req)
      assert a.domain == "10.0.0.3" and b.domain == "10.0.0.4"
      assert a.tp_pid == self()
    end

    test "an un-registration and the wildcard reach nobody" do
      assert Ops.register_targets(register(["<sip:bob@10.0.0.2>"], %{expires: "0"})) == []
      assert Ops.register_targets(%{contact: :*, expires: "0"}) == []
    end
  end

  describe "address_of_record/2" do
    test "user@host of From and To, whatever the tags and display names" do
      req = parsed([], "")
      assert Ops.address_of_record(req, :from) == "alice@example.com"
      assert Ops.address_of_record(req, :to) == "bob@example.com"

      hand = %{from: ~s("Alice" <sip:alice@Example.COM>;tag=x9), to: "<sip:bob@example.com>"}
      assert Ops.address_of_record(hand, :from) == "alice@example.com"
    end

    test "the host is folded, the user part is not" do
      req = %{from: %SIP.Uri{userpart: "Alice", domain: "EXAMPLE.com"}}
      assert Ops.address_of_record(req, :from) == "Alice@example.com"
    end

    test "absent, junk or user-less is nil" do
      assert Ops.address_of_record(%{}, :from) == nil
      assert Ops.address_of_record(%{to: "not a uri <<"}, :to) == nil
      assert Ops.address_of_record(%{to: %SIP.Uri{domain: "example.com"}}, :to) == nil
    end
  end

  describe "source_flow/1 and source_connection/1" do
    defp stamped(mod, pid) do
      %{
        ruri: %SIP.Uri{
          userpart: "bob",
          domain: "example.com",
          destip: {192, 0, 2, 7},
          destport: 5061,
          tp_module: mod,
          tp_pid: pid
        }
      }
    end

    test "the transport, address and port the transport layer stamped" do
      assert Ops.source_flow(stamped(SIP.Transport.UDP, self())) == {"UDP", {192, 0, 2, 7}, 5061}
      assert Ops.source_flow(stamped(SIP.Transport.WSS, self())) == {"WSS", {192, 0, 2, 7}, 5061}
    end

    test "a connection only for a connected transport" do
      assert Ops.source_connection(stamped(SIP.Transport.TLS, self())) == self()
      assert Ops.source_connection(stamped(SIP.Transport.UDP, self())) == nil
    end

    test "a request that did not come off the network has neither" do
      req = %{ruri: %SIP.Uri{userpart: "bob", domain: "example.com"}}
      assert Ops.source_flow(req) == nil
      assert Ops.source_connection(req) == nil
      assert Ops.source_flow(%{}) == nil
    end
  end
end
