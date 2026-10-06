defmodule SIP.Test.PresenceDoc do
  use ExUnit.Case, async: true

  @moduledoc """
  `SIP.Presence.Doc.compose/2`: the documents of a presentity's live
  publications, one per device, under the person state the collection holds
  (docs/design/presence-composite-plan.md, PC2).

  Pure: no collection, no expiry, no decision about which publication sets the
  person — only what the composite document says given those.
  """

  alias SIP.Presence.Doc
  alias SIP.Presence.Pidf
  alias SIP.Presence.Tuple

  doctest SIP.Presence.Doc

  @bob "sip:bob@ives.fr"

  defp person(opts \\ []), do: struct(Doc, Keyword.put_new(opts, :entity, @bob))

  defp sample(name), do: File.read!(Path.join(__DIR__, "PIDF-#{name}.xml"))

  describe "compose/2" do
    test "one device: its tuple, under the held person" do
      desk = Doc.new(@bob, :open, contact: "sip:bob@10.0.0.4", id: "t1")

      doc = Doc.compose(person(activity: :busy, note: "desk"), [{"r1", desk}])

      assert doc.entity == @bob
      assert [%Tuple{id: "t-r1-1", status: :open, contact: "sip:bob@10.0.0.4"}] = doc.tuples
      assert doc.activity == :busy
      assert doc.note == "desk"
    end

    test "two devices, one open and one closed: open, both tuples kept in order" do
      desk = Doc.new(@bob, :closed)
      mobile = Doc.new(@bob, :open, contact: "sip:bob@10.0.0.9")

      doc = Doc.compose(person(), [{"desk", desk}, {"mobile", mobile}])

      assert Doc.status(doc) == :open

      assert Enum.map(doc.tuples, &{&1.id, &1.status}) ==
               [{"t-desk-1", :closed}, {"t-mobile-1", :open}]

      assert Doc.contacts(doc) == ["sip:bob@10.0.0.9"]
    end

    test "every device closed: closed" do
      doc = Doc.compose(person(), [{"a", Doc.new(@bob, :closed)}, {"b", Doc.new(@bob, :closed)}])

      refute Doc.open?(doc)
    end

    test "the person set by one device is kept after that device leaves" do
      # Bob went away on his mobile, then closed it: only the desk phone, which
      # never said anything about the person, is left.
      desk = Doc.new(@bob, :open)

      doc = Doc.compose(person(activity: :away), [{"desk", desk}])

      assert doc.activity == :away
      assert Doc.status(doc) == :open
    end

    test "a cleared person is cleared, whatever a publication's own person says" do
      # The desk phone's document still carries the `busy` it published an hour
      # ago; the mobile's later "back to available" cleared the held person.
      desk = Doc.new(@bob, :open, activity: :busy, note: "old")
      mobile = Doc.new(@bob, :open)

      doc = Doc.compose(person(), [{"desk", desk}, {"mobile", mobile}])

      assert doc.activity == nil
      assert doc.note == nil
    end

    test "colliding tuple ids from two devices come out distinct" do
      a = Doc.new(@bob, :open, id: "t1")
      b = Doc.new(@bob, :closed, id: "t1")

      doc = Doc.compose(person(), [{"ruid-a", a}, {"ruid-b", b}])

      ids = Enum.map(doc.tuples, & &1.id)
      assert ids == ["t-ruid-a-1", "t-ruid-b-1"]
      assert ids == Enum.uniq(ids)
    end

    test "a device publishing several tuples keeps them all, numbered by position" do
      {:ok, two} = Pidf.parse(sample("two-tuples"))

      doc = Doc.compose(person(), [{"k", two}])

      assert length(doc.tuples) == length(two.tuples)

      assert Enum.map(doc.tuples, & &1.id) ==
               for(n <- 1..length(two.tuples), do: "t-k-#{n}")

      assert Enum.map(doc.tuples, & &1.status) == Enum.map(two.tuples, & &1.status)
    end

    test "the tuple id is stable when the publisher mints a new one on every PUBLISH" do
      # Linphone 6.2.3 changes its tuple id on every PUBLISH: two successive
      # documents of one device, under one key, give one id.
      {:ok, open} = Pidf.parse(sample("linphone623-open"))
      {:ok, busy} = Pidf.parse(sample("linphone623-busy"))
      refute hd(open.tuples).id == hd(busy.tuples).id

      ids = for doc <- [open, busy], do: hd(Doc.compose(person(), [{"r1", doc}]).tuples).id

      assert ids == ["t-r1-1", "t-r1-1"]
    end

    test "the entity is the presentity's, not a publication's" do
      other = Doc.new("sip:bob@10.0.0.4", :open)

      assert Doc.compose(person(), [{"r1", other}]).entity == @bob
    end

    test "no publication: no tuple, closed" do
      doc = Doc.compose(person(activity: :away), [])

      assert doc.tuples == []
      refute Doc.open?(doc)
    end

    test "the marks are the held person's, not a publication's" do
      dnd = [{"urn:trix:params:xml:ns:pidf", "dnd"}]
      own = Doc.new(@bob, :open, activity: :away, marks: [{"urn:example:acme", "x"}])

      doc = Doc.compose(person(activity: :busy, marks: dnd), [{"r1", own}])

      assert {doc.activity, doc.marks} == {:busy, dnd}
    end

    test "the composite round-trips through PIDF" do
      a = Doc.new(@bob, :open, contact: "sip:bob@10.0.0.4", id: "t1")
      b = Doc.new(@bob, :closed, id: "t1")
      doc = Doc.compose(person(activity: :away, note: "lunch"), [{"a", a}, {"b", b}])

      assert {:ok, parsed} = with({:ok, xml} <- Pidf.serialize(doc), do: Pidf.parse(xml))
      assert parsed.entity == @bob
      assert parsed.activity == :away

      assert Enum.map(parsed.tuples, &{&1.id, &1.status}) == [
               {"t-a-1", :open},
               {"t-b-1", :closed}
             ]
    end
  end
end
