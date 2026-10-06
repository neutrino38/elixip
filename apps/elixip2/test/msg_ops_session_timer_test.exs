defmodule SIP.Test.MsgOpsSessionTimer do
  use ExUnit.Case, async: true

  @moduledoc """
  The single reading of the RFC 4028 headers (`SIP.Msg.Ops.session_expires/1`,
  `min_se/1`) and their removal at a B2BUA leg boundary
  (`strip_session_timer/1`, applied by `prepare_forwarded_request/2`).
  """

  alias SIP.Msg.Ops

  # What JsSIP sends: a session timer it asks the far end to refresh.
  defp invite(extra_headers) do
    raw =
      "INVITE sip:bob@example.com SIP/2.0\r\n" <>
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKst1\r\n" <>
        "Max-Forwards: 70\r\n" <>
        "From: <sip:alice@example.com>;tag=a1\r\n" <>
        "To: <sip:bob@example.com>\r\n" <>
        "Call-ID: st-1\r\n" <>
        "CSeq: 1 INVITE\r\n" <>
        "Contact: <sip:alice@10.0.0.1:5060>\r\n" <>
        extra_headers <>
        "Content-Length: 0\r\n\r\n"

    {:ok, msg} = SIPMsg.parse(raw, fn _code, _errmsg, _lineno, _line -> nil end)
    msg
  end

  describe "session_expires/1" do
    test "reads the interval and the refresher off a parsed message" do
      req = invite("Session-Expires: 90;refresher=uac\r\n")
      assert Ops.session_expires(req) == {90, :uac}
    end

    test "the refresher is optional, case-insensitive, and unknown values read as none" do
      assert Ops.session_expires(%{"Session-Expires" => "1800"}) == {1800, nil}
      assert Ops.session_expires(%{"session-expires" => "1800; Refresher=UAS"}) == {1800, :uas}
      assert Ops.session_expires(%{"Session-Expires" => "1800;refresher=foo"}) == {1800, nil}
    end

    test "the compact form counts" do
      assert Ops.session_expires(%{"x" => "600;refresher=uas"}) == {600, :uas}
    end

    test "absent or unusable is nil, never a crash" do
      assert Ops.session_expires(%{}) == nil
      assert Ops.session_expires(%{"Session-Expires" => ""}) == nil
      assert Ops.session_expires(%{"Session-Expires" => "soon"}) == nil
      assert Ops.session_expires(%{"Session-Expires" => "0"}) == nil
      assert Ops.session_expires(%{"Session-Expires" => "-5"}) == nil
    end
  end

  describe "min_se/1" do
    test "reads the floor, tolerating parameters and spelling" do
      assert Ops.min_se(invite("Min-SE: 90\r\n")) == 90
      assert Ops.min_se(%{"min-se" => " 120;foo=bar"}) == 120
    end

    test "absent or unusable is nil" do
      assert Ops.min_se(%{}) == nil
      assert Ops.min_se(%{"Min-SE" => "x"}) == nil
    end
  end

  describe "strip_session_timer/1" do
    test "drops both headers and the timer option tag, keeps the other tags" do
      req =
        invite(
          "Session-Expires: 90;refresher=uac\r\n" <>
            "Min-SE: 90\r\n" <>
            "Supported: timer, 100rel, replaces\r\n" <>
            "Require: timer\r\n"
        )

      stripped = Ops.strip_session_timer(req)

      assert Ops.session_expires(stripped) == nil
      assert Ops.min_se(stripped) == nil
      refute "timer" in Ops.supported_extensions(stripped)
      assert Ops.supported_extensions(stripped) == ["100rel", "replaces"]
      assert Ops.required_extensions(stripped) == []
    end

    test "a Supported holding only timer disappears, and a raw string keeps its shape" do
      assert Ops.strip_session_timer(%{supported: ["timer"]}) == %{}

      assert Ops.strip_session_timer(%{"Require" => "Timer, replaces"}) ==
               %{"Require" => "replaces"}
    end

    test "the compact form is stripped too" do
      assert Ops.strip_session_timer(%{"x" => "90", "X-Other" => "1"}) == %{"X-Other" => "1"}
    end

    test "a request crossing a B2BUA leg loses its session timer" do
      req =
        invite(
          "Session-Expires: 90;refresher=uac\r\n" <>
            "Min-SE: 90\r\n" <>
            "Supported: timer, ice\r\n"
        )

      {:ok, fwd} = Ops.prepare_forwarded_request(req)

      assert Ops.session_expires(fwd) == nil
      assert Ops.min_se(fwd) == nil
      assert Ops.supported_extensions(fwd) == ["ice"]
    end
  end
end
