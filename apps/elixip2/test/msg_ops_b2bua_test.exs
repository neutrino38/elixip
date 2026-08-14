defmodule SIP.Test.MsgOpsB2bua do
  use ExUnit.Case, async: true

  @moduledoc """
  The framework's single reading of "what part of a SIP message crosses a B2BUA
  leg boundary" (`SIP.Msg.Ops.prepare_forwarded_request/2` and
  `forwarded_reply_fields/1` — design in docs/design/b2bua_module.md §1, §4-§5).

  The samples are real traffic (`SIP-INVITE-LVP.txt` / `SIP-200-LVP.txt`): an
  INVITE that crossed two proxies (two Via, two Record-Route, credentials, a
  from-tag, Max-Forwards already decremented to 16) and its SDP-bearing 200.
  """

  alias SIP.Msg.Ops

  defp parse!(file) do
    {:ok, raw} = File.read(Path.join(__DIR__, file))

    {:ok, msg} =
      SIPMsg.parse(raw, fn _code, _errmsg, _lineno, _line -> nil end)

    msg
  end

  defp forwarded!(req, opts \\ []) do
    {:ok, fwd} = Ops.prepare_forwarded_request(req, opts)
    fwd
  end

  describe "prepare_forwarded_request/2 — what is dropped" do
    test "hop-scoped routing, previous target and credentials never cross" do
      fwd = forwarded!(parse!("SIP-INVITE-LVP.txt"))

      for field <- [
            :via,
            :route,
            :recordroute,
            "Path",
            :proxyauthorization,
            :authorization,
            :transid
          ] do
        refute Map.has_key?(fwd, field), "#{inspect(field)} crossed the leg boundary"
      end
    end

    test "the Contact's identity crosses, its address and parameters do not" do
      req = parse!("SIP-INVITE-LVP.txt")
      fwd = forwarded!(req)

      # The sample's Contact: <sip:33970260233@192.168.24.71:61884;transport=tcp;alias=…>
      # The userpart says WHO — it crosses. Host, port, transport and the binding
      # parameters are the inbound leg's own address, stamped anew by the
      # transport layer of the OUTBOUND leg (SIP.Transport.add_contact_header/3).
      assert fwd.contact.userpart == "33970260233"
      assert fwd.contact.domain == "0.0.0.0"
      assert fwd.contact.params == %{}
      assert fwd.contact.hparams == %{}
    end

    test "the dialog identity is cleared, not reused: no Call-ID, no tags" do
      req = parse!("SIP-INVITE-LVP.txt")
      {_code, fromtag} = SIP.Uri.get_uri_param(req.from, "tag")
      assert is_binary(fromtag)

      fwd = forwarded!(req)

      assert fwd.callid == nil
      assert {:no_such_param, nil} = SIP.Uri.get_uri_param(fwd.from, "tag")
      assert {:no_such_param, nil} = SIP.Uri.get_uri_param(fwd.to, "tag")
    end

    test "the R-URI keeps its identity but loses its routing" do
      req = parse!("SIP-INVITE-LVP.txt")

      # Simulate the transport stamping of an inbound request: the routing
      # fields point back at the leg the request arrived on.
      req = %{
        req
        | ruri: %SIP.Uri{req.ruri | destip: {1, 2, 3, 4}, destport: 5060, tp_pid: self()}
      }

      fwd = forwarded!(req)

      assert fwd.ruri.userpart == req.ruri.userpart
      assert fwd.ruri.domain == req.ruri.domain
      assert fwd.ruri.destip == nil
      assert fwd.ruri.destport == 0
      assert fwd.ruri.tp_pid == nil
    end
  end

  describe "prepare_forwarded_request/2 — what crosses" do
    test "body, identity headers and unknown headers pass through unchanged" do
      req = parse!("SIP-INVITE-LVP.txt")
      fwd = forwarded!(req)

      assert fwd.body == req.body
      assert fwd.contenttype == req.contenttype

      # The From identity survives (only its tag is gone; a textual header is
      # parsed on the way, same as the dialog layer's set_tag does).
      {:ok, orig_from} = SIP.Uri.parse(req.from)
      assert fwd.from.userpart == orig_from.userpart
      assert fwd.from.domain == orig_from.domain
      assert Map.get(fwd, "P-Asserted-Identity") == Map.get(req, "P-Asserted-Identity")
      assert Map.get(fwd, "X-Account-Code") == Map.get(req, "X-Account-Code")
      assert fwd.method == :INVITE
    end

    test "the User-Agent is ours, not the caller's" do
      req = parse!("SIP-INVITE-LVP.txt")
      assert req.useragent =~ "LiveVideoPlugin"

      fwd = forwarded!(req)
      assert fwd.useragent == Application.get_env(:elixip2, :useragent, "Elixipp/0.1")

      assert forwarded!(req, useragent: "MyB2BUA/1.0").useragent == "MyB2BUA/1.0"
    end
  end

  describe "prepare_forwarded_request/2 — Max-Forwards (RFC 3261 §16.6, §20.22)" do
    test "decremented on the way through" do
      req = parse!("SIP-INVITE-LVP.txt")
      assert Map.get(req, "Max-Forwards") == 16
      assert Map.get(forwarded!(req), "Max-Forwards") == 15
    end

    test "absent -> the RFC default, decremented" do
      req = Map.delete(parse!("SIP-INVITE-LVP.txt"), "Max-Forwards")
      assert Map.get(forwarded!(req), "Max-Forwards") == 69
    end

    test "a textual or garbage value is read tolerantly" do
      req = parse!("SIP-INVITE-LVP.txt")
      assert Map.get(forwarded!(Map.put(req, "Max-Forwards", "5")), "Max-Forwards") == 4
      assert Map.get(forwarded!(Map.put(req, "Max-Forwards", "abc")), "Max-Forwards") == 69
    end

    test "exhausted -> {:error, :too_many_hops}, nothing forwarded" do
      req = Map.put(parse!("SIP-INVITE-LVP.txt"), "Max-Forwards", 0)
      assert Ops.prepare_forwarded_request(req) == {:error, :too_many_hops}
    end
  end

  describe "forwarded_reply_fields/1" do
    test "an SDP-bearing 200: the body crosses with its Content-Type, the Contact as identity only" do
      resp = parse!("SIP-200-LVP.txt")
      fields = Ops.forwarded_reply_fields(resp)

      sdp = SIP.Session.extract_sdp(resp)
      assert [%{contenttype: ct, data: ^sdp}] = Keyword.fetch!(fields, :body)
      assert ct =~ "sdp"

      # The sample's Contact: <sip:90901@212.83.152.250:5090>. The answerer's
      # userpart crosses; its address is left for the answering leg's transport
      # to stamp (placeholder host, no parameters of either kind).
      contact = Keyword.fetch!(fields, :contact)
      assert contact.userpart == "90901"
      assert contact.domain == "0.0.0.0"
      assert contact.params == %{}
      assert contact.hparams == %{}
    end

    test "a body-less response carries nothing but the passthrough headers" do
      resp =
        parse!("SIP-200-LVP.txt")
        |> Map.put(:body, [])
        |> Map.put("Reason", "Q.850;cause=16")

      fields = Ops.forwarded_reply_fields(resp)
      refute Keyword.has_key?(fields, :body)
      assert {"Reason", "Q.850;cause=16"} in fields
    end

    test "the fields build a valid relayed reply through the normal reply path" do
      resp = parse!("SIP-200-LVP.txt")
      req = parse!("SIP-INVITE-LVP.txt")

      fields =
        Ops.forwarded_reply_fields(resp) ++
          [contact: "sip:b2bua@example.org"]

      relayed = Ops.reply_to_request(req, 200, "OK", fields, "b2buatotag")

      assert relayed.response == 200
      assert SIP.Session.extract_sdp(relayed) == SIP.Session.extract_sdp(resp)
      # The relayed reply belongs to the inbound leg's dialog, not the outbound's.
      assert relayed.callid == req.callid
      assert relayed.contact.userpart == "b2bua"
    end
  end

  # The other reading a B2BUA needs from the message layer: not what crosses a
  # leg boundary, but WHETHER a re-offer has to (design §R4.1b). The samples are
  # built here rather than read from a file because what is under test is a
  # *difference* between two offers, and one file cannot show a difference.
  describe "reoffer_kind/2" do
    @base """
    v=0\r
    o=- 1 1 IN IP4 10.0.0.1\r
    s=-\r
    c=IN IP4 10.0.0.1\r
    t=0 0\r
    m=audio 7000 RTP/AVP 0 8\r
    a=rtpmap:0 PCMU/8000\r
    a=rtpmap:8 PCMA/8000\r
    a=sendrecv\r
    m=video 7002 RTP/AVP 99\r
    a=rtpmap:99 H264/90000\r
    a=sendrecv\r
    """

    defp offer(sdp), do: %{method: :INVITE, body: [%{contenttype: "application/sdp", data: sdp}]}
    defp kind(sdp, previous \\ @base), do: Ops.reoffer_kind(offer(sdp), previous)

    test "the same offer again asks for nothing" do
      assert kind(@base) == :no_change
    end

    test "no body at all is a session-timer refresh, not an offer" do
      assert Ops.reoffer_kind(%{method: :INVITE, body: []}, @base) == :no_sdp
      assert Ops.reoffer_kind(%{method: :UPDATE, body: nil}, @base) == :no_sdp
    end

    test "nothing to compare against is not a guess" do
      assert Ops.reoffer_kind(offer(@base), nil) == :unknown
      assert Ops.reoffer_kind(offer(@base), "") == :unknown
      assert Ops.reoffer_kind(offer("not an sdp at all"), @base) == :unknown
    end

    test "hold and retrieve, both spellings of each" do
      assert kind(String.replace(@base, "a=sendrecv", "a=sendonly")) == :hold
      assert kind(String.replace(@base, "a=sendrecv", "a=inactive")) == :hold
      # RFC 2543 hold: the address goes away rather than the direction.
      assert kind(String.replace(@base, "c=IN IP4 10.0.0.1", "c=IN IP4 0.0.0.0")) == :hold

      held = String.replace(@base, "a=sendrecv", "a=sendonly")
      assert Ops.reoffer_kind(offer(@base), held) == :resume
    end

    test "a hold that also moves is still a hold" do
      moved_and_held =
        @base
        |> String.replace("a=sendrecv", "a=sendonly")
        |> String.replace("c=IN IP4 10.0.0.1", "c=IN IP4 10.0.0.2")

      assert kind(moved_and_held) == :hold
    end

    test "the media set moving is what only the far end can answer" do
      # withdrawn (RFC 3264 §8: port 0, the section stays)
      assert kind(String.replace(@base, "m=video 7002", "m=video 0")) == :media_change
      # added
      assert kind(@base <> "m=text 7004 RTP/AVP 98\r\na=rtpmap:98 t140/1000\r\n") == :media_change
      # a codec dropped: with two legs bridged, what they settled on is what the
      # direct attach relies on
      assert kind(String.replace(@base, "m=audio 7000 RTP/AVP 0 8", "m=audio 7000 RTP/AVP 0")) ==
               :media_change
    end

    test "only the address moving is ours to absorb" do
      assert kind(String.replace(@base, "c=IN IP4 10.0.0.1", "c=IN IP4 10.0.0.2")) ==
               :address_change

      assert kind(String.replace(@base, "m=audio 7000", "m=audio 7100")) == :address_change

      # An ICE restart is a move too — new credentials, same media.
      iced = @base <> "a=ice-ufrag:aaaa\r\na=ice-pwd:bbbb\r\n"
      restarted = @base <> "a=ice-ufrag:cccc\r\na=ice-pwd:dddd\r\n"
      assert Ops.reoffer_kind(offer(restarted), iced) == :address_change
    end
  end
end
