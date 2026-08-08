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

      for field <- [:via, :route, :recordroute, "Path", :contact, :proxyauthorization, :authorization, :transid] do
        refute Map.has_key?(fwd, field), "#{inspect(field)} crossed the leg boundary"
      end
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
      req = %{req | ruri: %SIP.Uri{req.ruri | destip: {1, 2, 3, 4}, destport: 5060, tp_pid: self()}}

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
    test "an SDP-bearing 200: the body crosses with its Content-Type, the Contact does not" do
      resp = parse!("SIP-200-LVP.txt")
      fields = Ops.forwarded_reply_fields(resp)

      sdp = SIP.Session.extract_sdp(resp)
      assert [%{contenttype: ct, data: ^sdp}] = Keyword.fetch!(fields, :body)
      assert ct =~ "sdp"
      refute Keyword.has_key?(fields, :contact)
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
end
