defmodule SIP.Test.MsgOpsPresence do
  use ExUnit.Case, async: true

  @moduledoc """
  The framework's single reading of the event-notification headers
  (`SIP.Msg.Ops.event_package/1` & friends — RFC 6665 §8.2, RFC 3903 §11).

  Two things every case below checks. First, tolerance: a value off the network
  may be junk, and reading it must answer "absent" rather than crash the dialog
  doing the reading — the rule `parse_expires/2` already encodes. Second, that a
  **parsed** message and a **hand-built** one answer identically: the first
  carries the atom key `SIPMsg` assigns, the second the header name as a string
  key in whatever case its author typed, and a reading that saw only one of them
  is a reading half the stack cannot use.
  """

  alias SIP.Msg.Ops

  # The same request in both shapes: parsed off the wire, and built by hand the
  # way a template or a scenario builds one.
  defp parsed(headers) do
    raw =
      "SUBSCRIBE sip:bob@example.com SIP/2.0\r\n" <>
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776asdhds\r\n" <>
        "From: <sip:alice@example.com>;tag=1928301774\r\n" <>
        "To: <sip:bob@example.com>\r\n" <>
        "Call-ID: a84b4c76e66710@10.0.0.1\r\n" <>
        "CSeq: 314159 SUBSCRIBE\r\n" <>
        Enum.map_join(headers, "", fn {name, value} -> "#{name}: #{value}\r\n" end) <>
        "Content-Length: 0\r\n\r\n"

    {:ok, req} = SIPMsg.parse(raw, fn _code, _msg, _line, _text -> nil end)
    req
  end

  defp built(headers) do
    Enum.reduce(headers, %{method: :SUBSCRIBE}, fn {name, value}, acc ->
      Map.update(acc, name, value, fn
        existing when is_list(existing) -> existing ++ [value]
        existing -> [existing, value]
      end)
    end)
  end

  # Assert one reading answers the same for both shapes, and return the answer.
  defp both(headers, fun) do
    from_wire = fun.(parsed(headers))
    from_hand = fun.(built(headers))

    assert from_wire == from_hand,
           "parsed #{inspect(from_wire)} but hand-built #{inspect(from_hand)}"

    from_wire
  end

  describe "event_package/1" do
    cases = [
      {"a bare package", [{"Event", "presence"}], {"presence", nil}},
      {"a package with an id", [{"Event", "presence;id=abc"}], {"presence", "abc"}},
      {"the package name is case-insensitive", [{"Event", "PRESENCE"}], {"presence", nil}},
      {"the id is not", [{"Event", "presence;id=Ab12"}], {"presence", "Ab12"}},
      {"a templated package name", [{"Event", "presence.winfo"}], {"presence.winfo", nil}},
      {"an id among other parameters", [{"Event", "dialog;foo=bar;id=7"}], {"dialog", "7"}},
      {"a quoted id", [{"Event", ~s(presence;id="x9")}], {"presence", "x9"}},
      {"spaces around the parameters", [{"Event", "presence ; id=abc"}], {"presence", "abc"}},
      {"no Event header at all", [], nil},
      {"an empty Event header", [{"Event", ""}], nil},
      {"a valueless id says nothing", [{"Event", "presence;id"}], {"presence", nil}}
    ]

    for {title, headers, expected} <- cases do
      test title do
        assert both(unquote(Macro.escape(headers)), &Ops.event_package/1) ==
                 unquote(Macro.escape(expected))
      end
    end
  end

  describe "accepted_content_types/1" do
    cases = [
      {"one type", [{"Accept", "application/pidf+xml"}], ["application/pidf+xml"]},
      {"a comma-separated list", [{"Accept", "application/pidf+xml, text/plain"}],
       ["application/pidf+xml", "text/plain"]},
      {"spread over two header lines",
       [{"Accept", "application/pidf+xml"}, {"Accept", "text/plain"}],
       ["application/pidf+xml", "text/plain"]},
      {"q values are dropped, the order sent is kept",
       [{"Accept", "text/plain;q=0.1, application/pidf+xml;q=0.9"}],
       ["text/plain", "application/pidf+xml"]},
      {"folded to lower case", [{"Accept", "Application/PIDF+XML"}], ["application/pidf+xml"]},
      {"a duplicate is listed once", [{"Accept", "text/plain"}, {"Accept", "text/plain"}],
       ["text/plain"]},
      {"an empty entry is not a type", [{"Accept", "text/plain, , "}], ["text/plain"]},
      {"no Accept header is an empty list, not a refusal", [], []}
    ]

    for {title, headers, expected} <- cases do
      test title do
        assert both(unquote(Macro.escape(headers)), &Ops.accepted_content_types/1) ==
                 unquote(Macro.escape(expected))
      end
    end
  end

  describe "subscription_expires/2" do
    cases = [
      {"the header wins over the package default", [{"Expires", "600"}], 600},
      {"no header: the package default", [], 3600},
      {"Expires: 0 is an un-subscription, not an absence", [{"Expires", "0"}], 0}
    ]

    for {title, headers, expected} <- cases do
      test title do
        assert both(unquote(Macro.escape(headers)), &Ops.subscription_expires(&1, 3600)) ==
                 unquote(expected)
      end
    end

    # The parser refuses a non-numeric Expires outright (:invalid_expires_header),
    # so junk only ever reaches this reading through a hand-built message — where
    # it must still answer "absent" rather than raise.
    test "junk reads as absent" do
      assert Ops.subscription_expires(built([{"Expires", "soon"}]), 3600) == 3600
      assert Ops.subscription_expires(%{method: :SUBSCRIBE, expires: "soon"}, 3600) == 3600
    end

    test "it is not the REGISTER reading: no Contact parameter is consulted" do
      {:ok, contact} = SIP.Uri.parse("sip:alice@10.0.0.1")
      contact = SIP.Uri.set_header_param(contact, "expires", "120")
      req = %{method: :SUBSCRIBE, contact: contact, expires: 600}

      assert Ops.requested_expires(req) == 120
      assert Ops.subscription_expires(req, 3600) == 600
    end
  end

  describe "subscription_state/1" do
    cases = [
      {"active with its expiry", [{"Subscription-State", "active;expires=3600"}],
       {:active, %{"expires" => 3600}}},
      {"pending", [{"Subscription-State", "pending"}], {:pending, %{}}},
      {"terminated with a reason", [{"Subscription-State", "terminated;reason=timeout"}],
       {:terminated, %{"reason" => "timeout"}}},
      {"an unknown reason is carried through",
       [{"Subscription-State", "terminated;reason=someone-unplugged-it"}],
       {:terminated, %{"reason" => "someone-unplugged-it"}}},
      {"retry-after comes back as a number",
       [{"Subscription-State", "terminated;reason=probation;retry-after=60"}],
       {:terminated, %{"reason" => "probation", "retry-after" => 60}}},
      {"the state is case-insensitive", [{"Subscription-State", "ACTIVE"}], {:active, %{}}},
      {"an extension state stays a string, it does not become an atom",
       [{"Subscription-State", "suspended"}], {"suspended", %{}}},
      {"a valueless expires is dropped, not handed on as junk",
       [{"Subscription-State", "active;expires"}], {:active, %{}}},
      {"a non-numeric expires likewise", [{"Subscription-State", "active;expires=soon"}],
       {:active, %{}}},
      {"no header at all", [], nil},
      {"an empty header", [{"Subscription-State", ""}], nil}
    ]

    for {title, headers, expected} <- cases do
      test title do
        assert both(unquote(Macro.escape(headers)), &Ops.subscription_state/1) ==
                 unquote(Macro.escape(expected))
      end
    end
  end

  describe "publish_etag/1" do
    cases = [
      {"a tag", [{"SIP-If-Match", "dx200xyz"}], "dx200xyz"},
      {"surrounding space is not part of it", [{"SIP-If-Match", "  dx200xyz  "}], "dx200xyz"},
      {"the tag is case-sensitive", [{"SIP-If-Match", "DX200xyz"}], "DX200xyz"},
      {"no header: an initial publication", [], nil},
      {"an empty header is no tag", [{"SIP-If-Match", "   "}], nil}
    ]

    for {title, headers, expected} <- cases do
      test title do
        assert both(unquote(Macro.escape(headers)), &Ops.publish_etag/1) ==
                 unquote(Macro.escape(expected))
      end
    end
  end

  # A PUBLISH in both shapes, body and all: the readings below are the ones that
  # look at what a message CARRIES and not only at its headers. A body off the
  # wire always states its type — the parser refuses one that does not — so the
  # pair only differs on the headers the caller names.
  defp publish_parsed(headers, body) do
    headers =
      if body == "" or List.keymember?(headers, "Content-Type", 0),
        do: headers,
        else: headers ++ [{"Content-Type", "application/pidf+xml"}]

    raw =
      "PUBLISH sip:bob@example.com SIP/2.0\r\n" <>
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776asdhds\r\n" <>
        "From: <sip:bob@example.com>;tag=1928301774\r\n" <>
        "To: <sip:bob@example.com>\r\n" <>
        "Call-ID: a84b4c76e66710@10.0.0.1\r\n" <>
        "CSeq: 314159 PUBLISH\r\n" <>
        Enum.map_join(headers, "", fn {name, value} -> "#{name}: #{value}\r\n" end) <>
        "Content-Length: #{byte_size(body)}\r\n\r\n" <> body

    {:ok, req} = SIPMsg.parse(raw, fn _code, _msg, _line, _text -> nil end)
    req
  end

  defp publish_built(headers, body) do
    req = Enum.into(headers, %{method: :PUBLISH})

    if body == "",
      do: req,
      else: req |> Map.put(:body, body) |> Map.put_new("Content-Type", "application/pidf+xml")
  end

  defp both_publish(headers, body, fun) do
    from_wire = fun.(publish_parsed(headers, body))
    from_hand = fun.(publish_built(headers, body))

    assert from_wire == from_hand,
           "parsed #{inspect(from_wire)} but hand-built #{inspect(from_hand)}"

    from_wire
  end

  describe "entity_tag/1" do
    cases = [
      {"the tag a compositor granted", [{"SIP-ETag", "dx200xyz"}], "dx200xyz"},
      {"surrounding space is not part of it", [{"SIP-ETag", " dx200xyz "}], "dx200xyz"},
      {"the tag is case-sensitive", [{"SIP-ETag", "DX200xyz"}], "DX200xyz"},
      {"a 200 to a removal grants none", [], nil},
      {"an empty header is no tag", [{"SIP-ETag", "  "}], nil}
    ]

    for {title, headers, expected} <- cases do
      test title do
        assert both(unquote(Macro.escape(headers)), &Ops.entity_tag/1) ==
                 unquote(Macro.escape(expected))
      end
    end

    test "it is the other half of publish_etag/1, and they never read each other" do
      msg = %{"SIP-ETag" => "granted", "SIP-If-Match" => "presented", method: :PUBLISH}
      assert Ops.entity_tag(msg) == "granted"
      assert Ops.publish_etag(msg) == "presented"
    end
  end

  describe "body_string/1 and body_content_type/1" do
    test "a body carried as a bare string, with the message's Content-Type" do
      headers = [{"Content-Type", "application/pidf+xml"}]
      assert both_publish(headers, "<presence/>", &Ops.body_string/1) == "<presence/>"

      assert both_publish(headers, "<presence/>", &Ops.body_content_type/1) ==
               "application/pidf+xml"
    end

    test "the parser's part shape states its own type, and that one wins" do
      msg = %{
        method: :PUBLISH,
        contenttype: "application/sdp",
        body: [%{contenttype: "application/pidf+xml", data: "<presence/>"}]
      }

      assert Ops.body_string(msg) == "<presence/>"
      assert Ops.body_content_type(msg) == "application/pidf+xml"
    end

    test "the type is folded and stripped of its parameters" do
      msg = %{method: :PUBLISH, contenttype: "Application/PIDF+XML;charset=utf-8", body: "x"}
      assert Ops.body_content_type(msg) == "application/pidf+xml"
    end

    test "no body at all, and a body of nothing, both read as absent" do
      assert Ops.body_string(%{method: :PUBLISH}) == nil
      assert Ops.body_string(%{method: :PUBLISH, body: ""}) == nil
      assert Ops.body_string(%{method: :PUBLISH, body: []}) == nil
      assert Ops.body_content_type(%{method: :PUBLISH}) == nil
    end
  end

  describe "publish_operation/2" do
    @doc_body "<presence/>"

    test "a body and no tag: an initial publication, for the package's own default" do
      assert both_publish([], @doc_body, &Ops.publish_operation(&1, 3600)) ==
               {:initial, nil, 3600}
    end

    test "a body and a tag: a modification" do
      assert both_publish(
               [{"SIP-If-Match", "dx200xyz"}],
               @doc_body,
               &Ops.publish_operation(&1, 3600)
             ) ==
               {:modify, "dx200xyz", 3600}
    end

    test "a tag and no body: a refresh" do
      assert both_publish([{"SIP-If-Match", "dx200xyz"}], "", &Ops.publish_operation(&1, 3600)) ==
               {:refresh, "dx200xyz", 3600}
    end

    test "Expires: 0 is a removal, whatever else it carries" do
      assert both_publish(
               [{"SIP-If-Match", "dx200xyz"}, {"Expires", "0"}],
               @doc_body,
               &Ops.publish_operation(&1, 3600)
             ) == {:remove, "dx200xyz", 0}
    end

    test "an initial publication with Expires: 0 names no state to keep" do
      assert both_publish([{"Expires", "0"}], @doc_body, &Ops.publish_operation(&1, 3600)) ==
               {:remove, nil, 0}
    end

    test "neither a tag nor a body is a request that asks for nothing" do
      assert both_publish([], "", &Ops.publish_operation(&1, 3600)) == :invalid
    end

    test "the Expires header wins over the package default when it states one" do
      assert both_publish([{"Expires", "600"}], @doc_body, &Ops.publish_operation(&1, 3600)) ==
               {:initial, nil, 600}
    end

    # Hand-built only: `SIPMsg.parse/2` refuses a message whose Expires is not a
    # number (`:invalid_expires_header`), so the junk this reading has to
    # survive is the junk a template or a script writes, not a peer.
    test "a malformed Expires falls back on the package default rather than crashing" do
      req = publish_built([{"Expires", "soon"}], @doc_body)
      assert Ops.publish_operation(req, 3600) == {:initial, nil, 3600}
    end
  end

  describe "allow_events/1" do
    test "composes the domain's package names" do
      assert Ops.allow_events(["presence", "presence.winfo"]) == "presence, presence.winfo"
    end

    test "a single package" do
      assert Ops.allow_events(["presence"]) == "presence"
    end

    test "a domain enabling nothing composes an empty value" do
      assert Ops.allow_events([]) == ""
    end

    test "blanks and duplicates are dropped" do
      assert Ops.allow_events([" presence ", "", "presence", "dialog"]) == "presence, dialog"
    end
  end

  describe "the headers survive a round trip through the parser" do
    test "a NOTIFY keeps its Event and Subscription-State once re-serialized" do
      headers = [
        {"Event", "presence;id=abc"},
        {"Subscription-State", "active;expires=3600"},
        {"Accept", "application/pidf+xml"},
        {"SIP-If-Match", "dx200xyz"}
      ]

      raw = SIPMsg.serialize(parsed(headers))
      {:ok, again} = SIPMsg.parse(raw, fn _code, _msg, _line, _text -> nil end)

      assert Ops.event_package(again) == {"presence", "abc"}
      assert Ops.subscription_state(again) == {:active, %{"expires" => 3600}}
      assert Ops.accepted_content_types(again) == ["application/pidf+xml"]
      assert Ops.publish_etag(again) == "dx200xyz"
    end

    test "a 2xx keeps its SIP-ETag once re-serialized" do
      rsp =
        parsed([{"Event", "presence"}, {"SIP-ETag", "dx200xyz"}, {"Expires", "3600"}])

      raw = SIPMsg.serialize(rsp)
      {:ok, again} = SIPMsg.parse(raw, fn _code, _msg, _line, _text -> nil end)

      assert Ops.entity_tag(again) == "dx200xyz"
    end
  end
end
