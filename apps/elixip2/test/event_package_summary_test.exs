defmodule SIP.EventPackageSummaryTest do
  # The one-line readings the presence scripts log: what a document states and
  # what a publication does to it.
  use ExUnit.Case, async: true

  alias SIP.DialogInfo.{Dialog, Doc}

  test "a presence document: status, activity as the wire spells it, note, devices" do
    doc = SIP.Presence.Doc.new("sip:bob@ives.fr", :open, activity: :on_the_phone, note: "desk")
    assert SIP.EventPackage.summary(doc) == ~s(open, on-the-phone, note "desk")

    assert SIP.EventPackage.summary(SIP.Presence.Doc.new("sip:bob@ives.fr", :closed)) == "closed"

    two = %{doc | tuples: doc.tuples ++ doc.tuples, activity: "lunch", note: nil}
    assert SIP.EventPackage.summary(two) == "open, lunch, 2 devices"
  end

  test "a dialog-info document: its dialogs and their states" do
    assert SIP.EventPackage.summary(%Doc{entity: "sip:bob@ives.fr"}) == "no dialog"

    doc = %Doc{dialogs: [%Dialog{state: :confirmed}, %Dialog{state: :early}]}
    assert SIP.EventPackage.summary(doc) == "2 dialogs: confirmed, early"

    assert SIP.EventPackage.summary(%Doc{dialogs: [%Dialog{state: :trying}]}) ==
             "1 dialog: trying"
  end

  test "no state, a raw body and an unknown document are named, never dumped" do
    assert SIP.EventPackage.summary(nil) == "no state"
    assert SIP.EventPackage.summary("<x/>") == "4-byte body"
    assert SIP.EventPackage.summary(%URI{}) == "a URI"
  end

  test "a publication says what it does to the state" do
    pub = %SIP.Publication{doc: SIP.Presence.Doc.new("sip:bob@ives.fr", :open)}
    assert SIP.Publication.describe(pub) == "new: open"
    assert SIP.Publication.describe(%{pub | operation: :modify}) == "modified: open"
    assert SIP.Publication.describe(%{pub | operation: :refresh}) == "refresh, state unchanged"
    assert SIP.Publication.describe(%{pub | operation: :remove}) == "removal"
  end
end
