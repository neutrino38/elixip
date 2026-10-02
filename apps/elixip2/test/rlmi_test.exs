defmodule SIP.Test.Rlmi do
  use ExUnit.Case, async: true

  @moduledoc """
  The two documents of a list subscription, and the `multipart/related` that
  carries them (RFC 4662, RFC 5367 over RFC 4826, RFC 2387).

  The list comes IN as `application/resource-lists+xml` — the watcher's own
  buddies, in its SUBSCRIBE — and goes OUT as an RLMI manifest plus one PIDF part
  per buddy. What every case below is really checking is that the two halves meet:
  the `cid` of an instance is the `Content-ID` of a part that exists.
  """

  alias SIP.Presence.Rlmi
  alias SIP.Presence.Rlmi.Instance
  alias SIP.Presence.Rlmi.Resource

  doctest SIP.Presence.ResourceLists

  # The body of the captured SUBSCRIBE (Linphone Desktop 6.2.2, 2026-09-22).
  @captured_list """
  <?xml version="1.0" encoding="UTF-8"?>
  <resource-lists xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="urn:ietf:params:xml:ns:resource-lists">
   <list>
    <entry uri="sip:900020123@visioassistance.net"/>
    <entry uri="sip:9876@conf.weshwesh.eu"/>
    <entry uri="sip:magali.buu@weshwesh.eu"/>
   </list>
  </resource-lists>
  """

  describe "the resource list a watcher sends" do
    test "the captured buddy list reads as its three entries, in order" do
      assert {:ok, entries} = SIP.Presence.ResourceLists.parse(@captured_list)

      assert entries == [
               "sip:900020123@visioassistance.net",
               "sip:9876@conf.weshwesh.eu",
               "sip:magali.buu@weshwesh.eu"
             ]
    end

    test "nested lists are walked, and a duplicate entry is named once" do
      body = """
      <resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists">
       <list name="root">
        <entry uri="sip:a@x"/>
        <list name="inner"><entry uri="sip:b@x"/><entry uri="sip:a@x"/></list>
       </list>
      </resource-lists>
      """

      assert {:ok, ["sip:a@x", "sip:b@x"]} = SIP.Presence.ResourceLists.parse(body)
    end

    # Both name a document to fetch over XCAP, which this node does not do.
    # Skipping them beats refusing the list: the buddies we CAN serve are served.
    test "entry-ref and external are skipped, the entries beside them are not" do
      body = """
      <resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists">
       <list>
        <entry-ref ref="resource-lists/users/bob/index/~~/*"/>
        <external anchor="http://xcap.example.com/list"/>
        <entry uri="sip:bob@example.com"/>
       </list>
      </resource-lists>
      """

      assert {:ok, ["sip:bob@example.com"]} = SIP.Presence.ResourceLists.parse(body)
    end

    test "a list naming nobody is an empty list, not an error" do
      body =
        ~s(<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list/></resource-lists>)

      assert {:ok, []} = SIP.Presence.ResourceLists.parse(body)
    end

    test "junk off the network is refused without raising" do
      assert {:error, {:malformed_xml, _}} = SIP.Presence.ResourceLists.parse("<resource-lists")

      assert {:error, {:not_a_resource_list, "presence"}} =
               SIP.Presence.ResourceLists.parse(~s(<presence/>))

      assert {:error, :doctype_not_allowed} =
               SIP.Presence.ResourceLists.parse(~s(<!DOCTYPE x SYSTEM "x"><resource-lists/>))
    end
  end

  describe "SIP.Msg.Ops.recipient_list/1" do
    @list ~s(<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list><entry uri="sip:bob@example.com"/></list></resource-lists>)

    test "a recipient-list body is the list" do
      msg = %{
        "Content-Disposition" => "recipient-list",
        contenttype: "application/resource-lists+xml",
        body: @list
      }

      assert {:ok, ["sip:bob@example.com"]} = SIP.Msg.Ops.recipient_list(msg)
    end

    test "no disposition is no list" do
      assert :none = SIP.Msg.Ops.recipient_list(%{})
    end

    # Linphone's unsubscribe: the disposition copied from the initial SUBSCRIBE,
    # no body under it. A refresh may omit the list (RFC 5367).
    test "a recipient-list disposition over no body is no list" do
      assert :none = SIP.Msg.Ops.recipient_list(%{"Content-Disposition" => "recipient-list"})
    end

    test "a recipient-list disposition over another body is an error" do
      msg = %{
        "Content-Disposition" => "recipient-list",
        contenttype: "application/pidf+xml",
        body: "<presence/>"
      }

      assert {:error, {:not_a_resource_list, "application/pidf+xml"}} =
               SIP.Msg.Ops.recipient_list(msg)
    end
  end

  describe "the RLMI manifest" do
    defp manifest(opts) do
      %Rlmi{
        uri: "sip:rls@sip.linphone.org",
        version: Keyword.get(opts, :version, 0),
        full_state: Keyword.get(opts, :full_state, true),
        resources: Keyword.get(opts, :resources, [])
      }
    end

    test "a served resource points at the part carrying its state" do
      list =
        manifest(
          resources: [
            %Resource{
              uri: "sip:magali.buu@weshwesh.eu",
              name: "Magali",
              instances: [%Instance{id: "i1", state: :active, cid: "part1@kelixip"}]
            }
          ]
        )

      assert {:ok, xml} = Rlmi.serialize(list)
      assert xml =~ ~s(<list xmlns="urn:ietf:params:xml:ns:rlmi")
      assert xml =~ ~s(uri="sip:rls@sip.linphone.org")
      assert xml =~ ~s(<resource uri="sip:magali.buu@weshwesh.eu">)
      assert xml =~ ~s(<instance id="i1" state="active" cid="part1@kelixip"/>)
    end

    # A buddy on a domain this node does not serve. Silence would leave the
    # watcher waiting on a resource that will never come.
    test "an unserved resource is terminated with a reason, and carries no cid" do
      instance = Rlmi.unserved("sip:900020123@visioassistance.net")

      {:ok, xml} =
        manifest(
          resources: [
            %Resource{uri: "sip:900020123@visioassistance.net", instances: [instance]}
          ]
        )
        |> Rlmi.serialize()

      assert xml =~ ~s(state="terminated" reason="noresource"/>)
      refute xml =~ "cid="
    end

    test "the first NOTIFY is full state, the ones after it are not" do
      assert {:ok, first} = Rlmi.serialize(manifest(version: 0, full_state: true))
      assert {:ok, later} = Rlmi.serialize(manifest(version: 1, full_state: false))

      assert first =~ ~s(version="0" fullState="true")
      assert later =~ ~s(version="1" fullState="false")
    end

    test "a list with no uri is refused rather than sent unaddressed" do
      assert {:error, :no_list_uri} = Rlmi.serialize(%Rlmi{})
    end

    test "an instance id is stable for one URI, and differs between two" do
      assert Rlmi.instance_id("sip:bob@x") == Rlmi.instance_id("sip:bob@x")
      refute Rlmi.instance_id("sip:bob@x") == Rlmi.instance_id("sip:alice@x")
    end

    test "it round-trips: what is written reads back as what it says" do
      list =
        manifest(
          version: 3,
          full_state: false,
          resources: [
            %Resource{
              uri: "sip:bob@x",
              name: "Bob & co",
              instances: [%Instance{id: "i1", state: :active, cid: "p1@n"}]
            },
            %Resource{
              uri: "sip:carol@y",
              instances: [%Instance{id: "i2", state: :terminated, reason: "noresource"}]
            }
          ]
        )

      {:ok, xml} = Rlmi.serialize(list)

      assert {:ok, read} = Rlmi.parse(xml)
      assert read.uri == "sip:rls@sip.linphone.org"
      assert read.version == 3
      assert read.full_state == false
      assert [bob, carol] = read.resources
      assert bob.uri == "sip:bob@x"
      assert bob.name == "Bob & co"
      assert [%Instance{id: "i1", state: :active, cid: "p1@n"}] = bob.instances
      assert [%Instance{state: :terminated, reason: "noresource"}] = carol.instances
    end

    test "junk off the network is refused without raising" do
      assert {:error, {:not_an_rlmi_document, "presence"}} = Rlmi.parse(~s(<presence/>))
      assert {:error, {:malformed_xml, _}} = Rlmi.parse("<list")
    end
  end

  describe "the multipart/related body they travel in" do
    defp parts do
      [
        %{"Content-ID" => "<rlmi@kelixip>", contenttype: "application/rlmi+xml", data: "<list/>"},
        %{
          "Content-ID" => "<p1@kelixip>",
          contenttype: "application/pidf+xml",
          data: "<presence/>"
        }
      ]
    end

    test "the composed Content-Type names the root part and the boundary" do
      {stamped, content_type} =
        SIP.Msg.Ops.compose_multipart(parts(),
          subtype: "related",
          type: "application/rlmi+xml",
          start: "<rlmi@kelixip>"
        )

      assert content_type =~ ~s(multipart/related; type="application/rlmi+xml")
      assert content_type =~ ~s(start="<rlmi@kelixip>")
      assert [%{boundary: boundary}, %{boundary: boundary}] = stamped
      assert content_type =~ "boundary=" <> boundary
    end

    test "a part is serialized with its Content-ID, which is what cid= points at" do
      {stamped, _content_type} = SIP.Msg.Ops.compose_multipart(parts(), subtype: "related")

      octets = SIPMsg.multipart_body(stamped)

      assert octets =~ "Content-Type: application/rlmi+xml\r\nContent-ID: <rlmi@kelixip>\r\n\r\n"
      assert octets =~ "Content-Type: application/pidf+xml\r\nContent-ID: <p1@kelixip>\r\n\r\n"
    end

    test "a related body parses back into its parts, headers included" do
      {stamped, content_type} =
        SIP.Msg.Ops.compose_multipart(parts(),
          subtype: "related",
          type: "application/rlmi+xml",
          start: "<rlmi@kelixip>"
        )

      read = SIPMsg.parse_multi_part_body(content_type, SIPMsg.multipart_body(stamped))

      assert [rlmi, pidf] = read
      assert rlmi.contenttype == "application/rlmi+xml"
      assert rlmi["Content-ID"] == "<rlmi@kelixip>"
      assert rlmi.data == "<list/>"
      assert pidf.contenttype == "application/pidf+xml"
      assert pidf["Content-ID"] == "<p1@kelixip>"
    end

    # The boundary is read out of the parameters wherever they sit, and a quoted
    # one is not part of the delimiter.
    test "the boundary is found whatever the parameter order, quoted or not" do
      assert SIPMsg.multipart_boundary(
               ~s(multipart/related; boundary=abc; type="application/rlmi+xml")
             ) ==
               "abc"

      assert SIPMsg.multipart_boundary(
               ~s(multipart/related; type="x/y"; BOUNDARY="a=b"; start="<c>")
             ) ==
               "a=b"

      assert SIPMsg.multipart_boundary("application/pidf+xml") == nil
    end

    test "mixed still composes the way it did, boundary generated and Content-Type set" do
      msg =
        SIP.Msg.Ops.update_sip_msg(
          %{method: :MESSAGE},
          {:body,
           [
             %{contenttype: "text/plain", data: "hello"},
             %{contenttype: "application/sdp", data: "v=0"}
           ]}
        )

      assert msg.contenttype =~ "multipart/mixed; boundary="
      assert msg.contentlength == byte_size(SIPMsg.multipart_body(msg.body))
    end

    test "a message built from composed parts keeps the Content-Type it was given" do
      {stamped, content_type} =
        SIP.Msg.Ops.compose_multipart(parts(), subtype: "related", type: "application/rlmi+xml")

      msg =
        %{method: :NOTIFY}
        |> Map.put(:contenttype, content_type)
        |> SIP.Msg.Ops.update_sip_msg({:body, stamped})

      assert msg.contenttype == content_type
      assert msg.contentlength == byte_size(SIPMsg.multipart_body(stamped))
    end
  end
end
