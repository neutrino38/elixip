defmodule SIP.Test.Pidf do
  use ExUnit.Case, async: true

  @moduledoc """
  PIDF (RFC 3863) and the `presence` event package over it: what comes off the
  wire, what goes back on it, and what is refused.

  The documents in `test/PIDF-*.xml` are the shapes a real client publishes —
  Linphone's tuple + `dm:person` + `rpid:activities`, a second device, an
  extension namespace nobody here models. They sit beside the `SIP-*.txt`
  messages for the same reason: a parser tested only against what it can write is
  tested against itself. Captures from the field replace them at P6, where a
  Linphone actually subscribes to a notifier.
  """

  alias SIP.Presence.Doc
  alias SIP.Presence.Pidf
  alias SIP.Presence.Tuple

  @presence SIP.EventPackage.Presence

  defp sample(name), do: File.read!(Path.join(__DIR__, "PIDF-#{name}.xml"))

  # ── Reading ─────────────────────────────────────────────────────────────────

  describe "parse/1" do
    test "reads the tuple, the contact and the timestamp of an open document" do
      assert {:ok, doc} = Pidf.parse(sample("linphone-open"))

      assert doc.entity == "sip:alice@ives.fr"
      assert [%Tuple{} = tuple] = doc.tuples
      assert tuple.id == "tid-83c6d1"
      assert tuple.status == :open
      assert tuple.contact == "sip:alice@192.168.0.12;transport=tls"
      assert tuple.timestamp == ~U[2026-09-18 09:12:43Z]
      # An empty <rpid:activities/> says nothing, and nothing is what it produces.
      assert doc.activity == nil
      assert Doc.open?(doc)
    end

    test "reads the RPID activity off the person, and both notes" do
      assert {:ok, doc} = Pidf.parse(sample("linphone-away"))

      assert doc.activity == :away
      assert doc.note == "Back at 5"
      assert [%Tuple{priority: 0.8, note: note}] = doc.tuples
      # The entities the document escaped, unescaped exactly once.
      assert note == "R&D <meeting>"
    end

    test "reads a closed document with no contact at all" do
      assert {:ok, doc} = Pidf.parse(sample("linphone-closed"))

      assert [%Tuple{status: :closed, contact: nil}] = doc.tuples
      refute Doc.open?(doc)
      assert Doc.contacts(doc) == []
    end

    test "keeps every tuple, and folds them into one reachability" do
      assert {:ok, doc} = Pidf.parse(sample("two-tuples"))

      assert length(doc.tuples) == 2
      # One tuple open out of two is a presentity that can be reached.
      assert Doc.status(doc) == :open
      # …and only through the device that said so, priority first.
      assert Doc.contacts(doc) == ["sip:dave@192.168.1.31"]
    end

    test "stays usable on a document carrying namespaces it does not model" do
      assert {:ok, doc} = Pidf.parse(sample("unknown-namespace"))

      assert doc.entity == "sip:erin@ives.fr"
      assert [%Tuple{status: :open, contact: "sip:erin@10.0.0.9"}] = doc.tuples
    end

    test "tolerates a document with no namespace declared at all" do
      body = """
      <presence entity="sip:frank@ives.fr">
        <tuple id="t1"><status><basic>OPEN</basic></status></tuple>
      </presence>
      """

      assert {:ok, doc} = Pidf.parse(body)
      # `basic` is a token, and a client that shouts it still means open.
      assert [%Tuple{status: :open}] = doc.tuples
    end

    test "reads a status it cannot make sense of as closed" do
      for basic <- ["", "unavailable", "<other/>"] do
        body =
          ~s(<presence entity="sip:g@ives.fr"><tuple id="t1"><status><basic>) <>
            basic <> ~s(</basic></status></tuple></presence>)

        assert {:ok, doc} = Pidf.parse(body)
        assert [%Tuple{status: :closed}] = doc.tuples, "#{inspect(basic)} read as open"
      end
    end

    test "drops a timestamp and a priority it cannot read, and keeps the rest" do
      body = """
      <presence xmlns="urn:ietf:params:xml:ns:pidf" entity="sip:h@ives.fr">
        <tuple id="t1">
          <status><basic>open</basic></status>
          <contact priority="high">sip:h@10.0.0.1</contact>
          <timestamp>last tuesday</timestamp>
        </tuple>
      </presence>
      """

      assert {:ok, doc} = Pidf.parse(body)
      assert [%Tuple{contact: "sip:h@10.0.0.1", priority: nil, timestamp: nil}] = doc.tuples
    end

    test "reads an element of another namespace in the activities as a mark, at most eight" do
      marks = Enum.map_join(1..12, &"<acme:m#{&1}/>")

      body = """
      <presence xmlns="urn:ietf:params:xml:ns:pidf"
                xmlns:dm="urn:ietf:params:xml:ns:pidf:data-model"
                xmlns:rpid="urn:ietf:params:xml:ns:pidf:rpid"
                xmlns:acme="urn:example:acme" entity="sip:i@ives.fr">
        <tuple id="t1"><status><basic>open</basic></status></tuple>
        <dm:person id="p1"><rpid:activities>#{marks}<rpid:away/></rpid:activities></dm:person>
      </presence>
      """

      assert {:ok, doc} = Pidf.parse(body)
      # first in the document, yet not the activity: it is not RPID's
      assert doc.activity == :away
      assert doc.marks == Enum.map(1..8, &{"urn:example:acme", "m#{&1}"})
    end

    test "carries an activity nobody has heard of through as a string" do
      body = """
      <presence xmlns="urn:ietf:params:xml:ns:pidf"
                xmlns:dm="urn:ietf:params:xml:ns:pidf:data-model"
                xmlns:rpid="urn:ietf:params:xml:ns:pidf:rpid" entity="sip:i@ives.fr">
        <tuple id="t1"><status><basic>open</basic></status></tuple>
        <dm:person id="p1"><rpid:activities><rpid:skydiving/></rpid:activities></dm:person>
      </presence>
      """

      assert {:ok, doc} = Pidf.parse(body)
      # A binary, not an atom: the body is unauthenticated, and the atom table
      # does not grow with what a stranger publishes.
      assert doc.activity == "skydiving"
    end
  end

  # ── The refusals ────────────────────────────────────────────────────────────

  # Captured from Linphone-Desktop 6.2.3 and Trix (JsSIP 3.13.8) on 2026-10-01
  # (presence-composite-plan.md, PC0). Both say "available" by sending NO
  # `<dm:person>` at all, never an empty one: a document with no activity is how
  # a client clears the person state, and it must read as exactly that.
  describe "parse/1 on field captures" do
    test "available is no person at all, and reads as no activity and no note" do
      for name <- ~w(linphone623-open trix-open) do
        assert {:ok, doc} = Pidf.parse(sample(name))
        assert [%Tuple{status: :open}] = doc.tuples
        assert {doc.activity, doc.note} == {nil, nil}, name
      end
    end

    test "busy is an RPID activity on the person, with or without text in it" do
      for name <- ~w(linphone623-busy trix-busy) do
        assert {:ok, doc} = Pidf.parse(sample(name))
        assert doc.activity == :busy, name
        assert Doc.open?(doc)
      end
    end

    # Captured from Trix on 2026-10-03: "do not disturb" is RPID's busy, which is
    # what a watcher that is not Trix should show, plus a mark of Trix's own.
    test "Trix's do not disturb is busy, with its mark beside it" do
      assert {:ok, doc} = Pidf.parse(sample("trix-dnd"))
      assert doc.activity == :busy
      assert doc.marks == [{"urn:trix:params:xml:ns:pidf", "dnd"}]
    end

    test "Trix carries no contact; Linphone carries the AOR" do
      assert {:ok, %Doc{tuples: [%Tuple{contact: nil}]}} = Pidf.parse(sample("trix-open"))

      assert {:ok, %Doc{tuples: [%Tuple{contact: "sip:bob@weshwesh.eu"}]}} =
               Pidf.parse(sample("linphone623-open"))
    end
  end

  describe "parse/1 refuses" do
    test "a body over the size bound, without looking at it" do
      body = "<presence entity=\"sip:j@ives.fr\">" <> String.duplicate("<!-- pad -->", 10_000)

      assert {:error, {:body_too_large, _size}} = Pidf.parse(body)
    end

    test "a doctype, declaration and all" do
      body = """
      <?xml version="1.0"?>
      <!DOCTYPE presence [<!ENTITY lol "lol">]>
      <presence entity="sip:k@ives.fr"><tuple id="t1"><status><basic>&lol;</basic></status></tuple></presence>
      """

      assert Pidf.parse(body) == {:error, :doctype_not_allowed}
    end

    test "the classic entity expansion, at the declaration" do
      body = """
      <?xml version="1.0"?>
      <!DOCTYPE lolz [
       <!ENTITY lol "lol">
       <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
       <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
      ]>
      <presence entity="sip:l@ives.fr"><tuple id="t1"><note>&lol3;</note></tuple></presence>
      """

      assert Pidf.parse(body) == {:error, :doctype_not_allowed}
    end

    test "a truncated document, by answering rather than raising" do
      assert {:error, {:malformed_xml, _reason}} = Pidf.parse("<presence><tuple>")
      assert {:error, {:malformed_xml, _reason}} = Pidf.parse("not xml at all")
      assert {:error, {:malformed_xml, _reason}} = Pidf.parse("")
    end

    test "a well-formed document that is not a presence document" do
      assert {:error, {:not_a_presence_document, "rlmi"}} =
               Pidf.parse(~s(<rlmi xmlns="urn:ietf:params:xml:ns:rlmi"/>))
    end

    test "anything that is not a body" do
      assert {:error, {:not_a_body, nil}} = Pidf.parse(nil)
    end
  end

  # ── Writing ─────────────────────────────────────────────────────────────────

  describe "serialize/1" do
    test "writes a document a watcher can read back unchanged" do
      for name <-
            ~w(linphone-open linphone-away linphone-closed two-tuples) ++
              ~w(linphone623-open linphone623-busy trix-open trix-busy trix-dnd) do
        assert {:ok, doc} = Pidf.parse(sample(name))
        assert {:ok, body} = Pidf.serialize(doc)

        assert {:ok, ^doc} = Pidf.parse(body),
               "#{name} does not survive the round trip"
      end
    end

    test "declares the dm/rpid prefixes only when there is a person to carry" do
      {:ok, plain} =
        "sip:m@ives.fr" |> Doc.new(:open, contact: "sip:m@10.0.0.1") |> Pidf.serialize()

      refute plain =~ "rpid"

      {:ok, rich} = "sip:m@ives.fr" |> Doc.new(:open, activity: :on_the_phone) |> Pidf.serialize()
      assert rich =~ ~s(xmlns:rpid="urn:ietf:params:xml:ns:pidf:rpid")
      # RFC 4480's own spelling of the activity, not the atom's.
      assert rich =~ "<rpid:on-the-phone/>"
    end

    test "writes the marks in their own namespace, after the activity" do
      doc =
        Doc.new("sip:m@ives.fr", :open,
          activity: :away,
          marks: [{"urn:trix:params:xml:ns:pidf", "auto"}]
        )

      assert {:ok, body} = Pidf.serialize(doc)
      assert body =~ ~s(xmlns:m1="urn:trix:params:xml:ns:pidf")
      assert body =~ "<rpid:activities><rpid:away/><m1:auto/></rpid:activities>"
      assert {:ok, ^doc} = Pidf.parse(body)
    end

    test "a mark alone is still a person, and not an activity" do
      doc = Doc.new("sip:m@ives.fr", :open, marks: [{"urn:example:acme", "flag"}])

      assert {:ok, body} = Pidf.serialize(doc)
      assert {:ok, %Doc{activity: nil, marks: [{"urn:example:acme", "flag"}]}} = Pidf.parse(body)
    end

    test "leaves out a mark whose name is not one an element may have" do
      doc = Doc.new("sip:m@ives.fr", :open, activity: :busy, marks: [{"urn:example:acme", "a b"}])

      assert {:ok, body} = Pidf.serialize(doc)
      assert body =~ "<rpid:activities><rpid:busy/></rpid:activities>"
    end

    test "escapes what would otherwise close an element" do
      doc = Doc.new("sip:n@ives.fr", :open, note: ~s(a & b <c> "d"))

      assert {:ok, body} = Pidf.serialize(doc)
      assert {:ok, reparsed} = Pidf.parse(body)
      assert reparsed.note == ~s(a & b <c> "d")
    end

    test "names a tuple the caller did not name" do
      doc = %Doc{
        entity: "sip:o@ives.fr",
        tuples: [%Tuple{status: :open}, %Tuple{status: :closed}]
      }

      assert {:ok, body} = Pidf.serialize(doc)
      assert body =~ ~s(<tuple id="t1">)
      assert body =~ ~s(<tuple id="t2">)
    end

    test "refuses a document that does not say who it is about" do
      assert Pidf.serialize(%Doc{tuples: []}) == {:error, :no_entity}
      assert {:error, {:not_a_presence_document, _}} = Pidf.serialize("open")
    end
  end

  # ── The package ─────────────────────────────────────────────────────────────

  describe "SIP.EventPackage.Presence" do
    test "answers the behaviour's questions" do
      assert @presence.name() == "presence"
      assert @presence.default_expires() == 3600
      assert @presence.min_expires() < @presence.default_expires()
      assert @presence.max_expires() > @presence.default_expires()
      assert @presence.content_types() == ["application/pidf+xml"]
    end

    test "parses and serializes through PIDF, whatever the case of the type" do
      assert {:ok, doc} = @presence.parse("application/PIDF+XML", sample("linphone-open"))
      assert %Doc{entity: "sip:alice@ives.fr"} = doc
      assert {:ok, body} = @presence.serialize("application/pidf+xml", doc)
      assert body =~ "sip:alice@ives.fr"
    end

    test "refuses a content type it does not produce, and a document it cannot write" do
      assert {:error, {:unsupported_content_type, "text/plain"}} =
               @presence.parse("text/plain", "open")

      assert {:error, {:unsupported_content_type, "text/plain"}} =
               @presence.serialize("text/plain", %Doc{entity: "sip:p@ives.fr"})

      # The mistake this refusal exists for: a scenario handing the package a
      # line of text instead of a document. A NOTIFY carrying "open" as
      # application/pidf+xml is a watcher displaying nothing.
      assert {:error, {:not_a_presence_document, "open"}} =
               @presence.serialize("application/pidf+xml", "open")
    end

    test "registers itself as a provided package at boot" do
      SIP.EventPackage.register_builtins()

      assert {:ok, @presence} = SIP.EventPackage.lookup("presence")
      # Case-insensitively, the way `Event` is matched.
      assert {:ok, @presence} = SIP.EventPackage.lookup("PRESENCE")
      assert %{origin: :builtin} = Map.fetch!(SIP.EventPackage.registered(), "presence")
    end
  end
end
