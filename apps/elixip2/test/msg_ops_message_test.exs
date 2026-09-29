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
end
