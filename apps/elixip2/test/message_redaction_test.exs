defmodule SIP.Test.MessageRedaction do
  use ExUnit.Case, async: true

  @moduledoc """
  A MESSAGE's content is never recorded — not in the journal, not in the debug
  logs (GDPR; docs/design/chat-basic-plan.md, C1b).

  `SIPMsg.redacted/1` is the one place deciding what goes; `SIPMsg.readable/1`
  (the journal's text) and `SIPMsg.loggable/1` (the transports' dumps) are its
  callers. Each case below searches the output for the text itself: a redaction
  that leaves the words anywhere is not one.
  """

  @secret "Rendez-vous chez le cardiologue jeudi"

  defp wire(headers, body, method \\ "MESSAGE") do
    "#{method} sip:bob@example.com SIP/2.0\r\n" <>
      "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776asdhds\r\n" <>
      "From: <sip:alice@example.com>;tag=1928301774\r\n" <>
      "To: <sip:bob@example.com>\r\n" <>
      "Call-ID: a84b4c76e66710@10.0.0.1\r\n" <>
      "CSeq: 1 #{method}\r\n" <>
      Enum.map_join(headers, "", fn {name, value} -> "#{name}: #{value}\r\n" end) <>
      "Content-Length: #{byte_size(body)}\r\n\r\n" <> body
  end

  defp parsed(headers, body, method \\ "MESSAGE") do
    {:ok, msg} = SIPMsg.parse(wire(headers, body, method), fn _, _, _, _ -> :ok end)
    msg
  end

  defp cpim(inner_type, text) do
    "From: <sip:alice@example.com>\r\n" <>
      "To: <sip:bob@example.com>\r\n" <>
      "DateTime: 2026-09-29T14:00:00Z\r\n" <>
      "NS: imdn <urn:ietf:params:imdn>\r\n" <>
      "imdn.Message-ID: 34jk324j\r\n" <>
      "\r\n" <>
      "Content-Type: #{inner_type}\r\n" <>
      "\r\n" <> text
  end

  defp text_of(msg), do: SIPMsg.serialize(msg)

  describe "redacted/1" do
    test "a plain-text MESSAGE: the body goes, the headers stay" do
      msg = parsed([{"Content-Type", "text/plain;charset=UTF-8"}], @secret)
      out = text_of(SIPMsg.redacted(msg))

      refute out =~ "cardiologue"
      assert out =~ "<content not recorded: text/plain, #{byte_size(@secret)} octets>"
      assert out =~ "From: <sip:alice@example.com>"
      # the size of what really went on the wire
      assert out =~ "Content-Length: #{byte_size(@secret)}"
    end

    test "the Subject goes too" do
      msg = parsed([{"Subject", "Résultats d'analyse"}, {"Content-Type", "text/plain"}], @secret)
      out = text_of(SIPMsg.redacted(msg))
      refute out =~ "analyse"
      assert out =~ "Subject: <not recorded>"
    end

    # The parser refuses one-letter header names, so the compact form only comes
    # from a message built by hand — which a scenario may do.
    test "and its compact form, on a hand-built message" do
      msg = %{"s" => "analyse", method: :MESSAGE, contenttype: "text/plain", body: @secret}
      assert %{"s" => "<not recorded>"} = SIPMsg.redacted(msg)
    end

    test "a CPIM envelope keeps its addressing and timing, loses its content" do
      msg = parsed([{"Content-Type", "message/cpim"}], cpim("text/plain; charset=utf-8", @secret))
      out = text_of(SIPMsg.redacted(msg))

      refute out =~ "cardiologue"
      assert out =~ "imdn.Message-ID: 34jk324j"
      assert out =~ "DateTime: 2026-09-29T14:00:00Z"
      assert out =~ "Content-Type: text/plain; charset=utf-8"
      assert out =~ "<content not recorded: text/plain, #{byte_size(@secret)} octets>"
    end

    test "a malformed CPIM envelope goes whole" do
      msg = parsed([{"Content-Type", "message/cpim"}], "no blank line, " <> @secret)
      out = text_of(SIPMsg.redacted(msg))
      refute out =~ "cardiologue"
      assert out =~ "<content not recorded: message/cpim,"
    end

    test "a typing indicator and a disposition notification are kept whole" do
      typing = parsed([{"Content-Type", "application/im-iscomposing+xml"}], "<isComposing/>")
      imdn = parsed([{"Content-Type", "message/imdn+xml"}], "<imdn><delivered/></imdn>")

      assert SIPMsg.redacted(typing) == typing
      assert SIPMsg.redacted(imdn) == imdn
    end

    test "anything but a MESSAGE is not touched" do
      info = parsed([{"Content-Type", "text/plain"}], @secret, "INFO")
      assert SIPMsg.redacted(info) == info
    end
  end

  describe "readable/1 — the journal's text" do
    test "carries no content, and says so" do
      {text, _} = SIPMsg.readable(parsed([{"Content-Type", "text/plain"}], @secret))
      refute text =~ "cardiologue"
      assert text =~ "content not recorded"
    end

    test "the wire form too" do
      {text, _} = SIPMsg.readable(wire([{"Content-Type", "text/plain"}], @secret))
      refute text =~ "cardiologue"
    end
  end

  describe "the journal event" do
    test "a MESSAGE someone wrote is recorded redacted, and flagged" do
      ev = SIP.Scenario.SipTrace.event(:in, parsed([{"Content-Type", "text/plain"}], @secret))

      assert ev.redacted
      refute ev.body =~ "cardiologue"
      assert ev.method == :MESSAGE
    end

    test "a typing indicator is recorded whole, and not flagged" do
      ev =
        SIP.Scenario.SipTrace.event(
          :in,
          parsed([{"Content-Type", "application/im-iscomposing+xml"}], "<isComposing/>")
        )

      refute ev.redacted
      assert ev.body =~ "<isComposing/>"
    end
  end

  describe "loggable/1 — the transports' dumps" do
    test "a MESSAGE is dumped without its content" do
      out = SIPMsg.loggable(wire([{"Content-Type", "text/plain"}], @secret))
      refute out =~ "cardiologue"
      assert out =~ "MESSAGE sip:bob@example.com SIP/2.0"
    end

    test "any other message is dumped exactly as it went" do
      invite = wire([{"Content-Type", "text/plain"}], "hello", "INFO")
      assert SIPMsg.loggable(invite) == invite
    end

    test "a MESSAGE that will not parse is not shown at all" do
      out = SIPMsg.loggable("MESSAGE garbage\r\n\r\n" <> @secret)
      refute out =~ "cardiologue"
      assert out =~ "content not recorded"
    end
  end
end
