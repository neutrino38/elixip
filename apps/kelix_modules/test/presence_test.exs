defmodule Kelix.Mod.PresenceTest do
  # async: false — Kelix.Mod.Presence is a named singleton, shared with
  # presence_script_test; serialize to avoid concurrent start_supervised.
  use ExUnit.Case, async: false

  alias Kelix.Mod.Presence

  @domain "example.com"
  @package "presence"

  setup do
    pid = start_supervised!({Presence, []})
    %{pid: pid}
  end

  # A publication as `check_publish/1` hands it to the script: already read
  # against the event package, with the operation, the tag presented and the
  # lifetime that may be granted.
  defp publication(user, opts \\ []) do
    %SIP.Publication{
      username: user,
      domain: @domain,
      event: @package,
      etag: Keyword.get(opts, :etag),
      operation: Keyword.get(opts, :operation, :initial),
      content_type: "application/pidf+xml",
      body: Keyword.get(opts, :body, "<presence/>"),
      doc: Keyword.get(opts, :doc, doc(user, :open)),
      sender: "sip:#{user}@#{@domain}",
      flow: Keyword.get(opts, :flow)
    }
    |> SIP.Publication.grant(Keyword.get(opts, :expires, 3600))
  end

  defp doc(user, status, note \\ nil),
    do: SIP.Presence.Doc.new("sip:#{user}@#{@domain}", status, note: note)

  # What a watcher is told is the composite (`SIP.Presence.Doc.compose/2`), whose
  # tuple ids are the collection's: compared without them.
  defp unnamed(%SIP.Presence.Doc{} = doc),
    do: %{doc | tuples: Enum.map(doc.tuples, &%{&1 | id: nil})}

  # A subscription as `accept_subscription/1` hands it back: granted, active, and
  # naming the resource in `presentity_uri`.
  defp subscription(presentity, watcher, opts \\ []) do
    presentity_domain = Keyword.get(opts, :presentity_domain, @domain)

    %SIP.Subscription{
      callid: Keyword.get(opts, :callid, "call-#{presentity}-#{watcher}"),
      to_tag: "totag",
      from_tag: "fromtag",
      event: Keyword.get(opts, :event, @package),
      event_id: Keyword.get(opts, :event_id),
      presentity_uri: "sip:#{presentity}@#{presentity_domain}",
      watcher_username: watcher,
      watcher_domain: @domain,
      to_user: presentity,
      to_domain: presentity_domain
    }
    |> SIP.Subscription.put_status(Keyword.get(opts, :status, :active))
    |> SIP.Subscription.grant(Keyword.get(opts, :expires, 3600))
  end

  describe "publish/2 — the entity-tag lifecycle (RFC 3903 §4.1)" do
    test "an initial publication is granted a tag and its lifetime" do
      assert {:ok, etag, 3600} = Presence.publish(@domain, publication("bob"))
      assert is_binary(etag) and etag != ""
    end

    # The tag the publisher presented is spent: every successful publication gets
    # a NEW one, which is what its next refresh must present.
    test "a refresh presenting the tag gets a fresh one" do
      {:ok, first, _} = Presence.publish(@domain, publication("bob"))

      assert {:ok, second, 1800} =
               Presence.publish(
                 @domain,
                 publication("bob", operation: :refresh, etag: first, expires: 1800)
               )

      assert second != first
    end

    # The one answer only the holder of the tags can give — everything else
    # `check_publish/1` already refused before the script called us.
    test "a tag this collection does not hold is 412" do
      assert {:error, 412} =
               Presence.publish(@domain, publication("bob", operation: :refresh, etag: "nope"))
    end

    test "a spent tag is 412 — a publisher may not replay the previous one" do
      {:ok, first, _} = Presence.publish(@domain, publication("bob"))

      {:ok, _second, _} =
        Presence.publish(@domain, publication("bob", operation: :modify, etag: first))

      assert {:error, 412} =
               Presence.publish(@domain, publication("bob", operation: :modify, etag: first))
    end

    # A removal names no state, so it is handed no tag: one handed there would be
    # presented on the next refresh and answered 412 for ever.
    test "a removal answers with no entity-tag and no lifetime" do
      {:ok, etag, _} = Presence.publish(@domain, publication("bob"))

      assert {:ok, nil, 0} =
               Presence.publish(
                 @domain,
                 publication("bob", operation: :remove, etag: etag, expires: 0)
               )

      assert Presence.state_of(@domain, {"bob", @package}) == nil
    end

    # A refresh carries no body (RFC 3903 §4.1): what is published stays, only
    # its lifetime moves.
    test "a refresh keeps the document it refreshes" do
      published = doc("bob", :open, "In a meeting")
      {:ok, etag, _} = Presence.publish(@domain, publication("bob", doc: published))

      {:ok, _, _} =
        Presence.publish(
          @domain,
          publication("bob", operation: :refresh, etag: etag, doc: nil, body: nil)
        )

      assert unnamed(Presence.state_of(@domain, {"bob", @package})) == unnamed(published)
    end

    test "a modification replaces it" do
      {:ok, etag, _} = Presence.publish(@domain, publication("bob"))
      closed = doc("bob", :closed)

      {:ok, _, _} =
        Presence.publish(@domain, publication("bob", operation: :modify, etag: etag, doc: closed))

      assert unnamed(Presence.state_of(@domain, {"bob", @package})) == unnamed(closed)
    end

    # RFC 3903 §4.1: a handset and a desk phone may hold state for one presentity
    # at the same time, each with a tag of its own.
    test "two publishers of one presentity each keep their own tag" do
      {:ok, phone, _} = Presence.publish(@domain, publication("bob", doc: doc("bob", :open)))
      {:ok, desk, _} = Presence.publish(@domain, publication("bob", doc: doc("bob", :closed)))

      assert phone != desk
      assert [_, _] = Presence.presentities(@domain)

      # both tags still refresh
      assert {:ok, _, _} =
               Presence.publish(@domain, publication("bob", operation: :refresh, etag: phone))

      assert {:ok, _, _} =
               Presence.publish(@domain, publication("bob", operation: :refresh, etag: desk))
    end
  end

  # The flow a PUBLISH came in on, as `SIP.Msg.Ops.arrival_flow/1` reads it: over
  # a connection, the transport instance is the connection — a process standing
  # in for it here, which the test kills to drop it.
  defp connection() do
    pid = spawn(fn -> receive do: (:drop -> :ok) end)
    %{received: {:wss, {10, 0, 0, 7}, 40_000}, tp_pid: pid, tp_module: SIP.Transport.WSS}
  end

  defp udp(port),
    do: %{received: {:udp, {10, 0, 0, 7}, port}, tp_pid: self(), tp_module: SIP.Transport.UDP}

  defp drop(%{tp_pid: pid}) do
    ref = Process.monitor(pid)
    send(pid, :drop)
    assert_receive {:DOWN, ^ref, :process, ^pid, _}
  end

  describe "one publication per publisher" do
    # A client that lost its entity-tag across a reconnection starts over with an
    # initial PUBLISH: it replaces what it published, it does not add a state.
    test "an initial PUBLISH replaces the publisher's previous one" do
      flow = udp(5070)
      {:ok, first, _} = Presence.publish(@domain, publication("bob", flow: flow))

      {:ok, _second, _} =
        Presence.publish(@domain, publication("bob", flow: flow, doc: doc("bob", :closed)))

      assert [%{status: "closed"}] = Presence.presentities(@domain)

      assert {:error, 412} =
               Presence.publish(@domain, publication("bob", operation: :refresh, etag: first))
    end

    test "over a connection, the connection is the publisher" do
      flow = connection()
      {:ok, _, _} = Presence.publish(@domain, publication("bob", flow: flow))
      {:ok, _, _} = Presence.publish(@domain, publication("bob", flow: flow))

      assert [_one] = Presence.presentities(@domain)
    end

    test "two publishers keep a state each" do
      {:ok, _, _} = Presence.publish(@domain, publication("bob", flow: udp(5070)))
      {:ok, _, _} = Presence.publish(@domain, publication("bob", flow: udp(5080)))

      assert [_, _] = Presence.presentities(@domain)
    end

    # The removal of the most recent state brings back the other publisher's,
    # which is live — not a stale copy of the same publisher's.
    test "removing the latest state brings back the other publisher's" do
      {:ok, _, _} =
        Presence.publish(@domain, publication("bob", flow: udp(5070), doc: doc("bob", :closed)))

      {:ok, etag, _} = Presence.publish(@domain, publication("bob", flow: udp(5080)))

      {:ok, nil, 0} =
        Presence.publish(@domain, publication("bob", operation: :remove, etag: etag, expires: 0))

      assert status(Presence.state_of(@domain, {"bob", @package})) == :closed
    end

    # A refresh carries no state: it neither moves its publication's tuples nor
    # touches the person another publisher stated since.
    test "a refresh changes nothing in the composite" do
      {:ok, phone, _} =
        Presence.publish(@domain, publication("bob", flow: udp(5070), doc: doc("bob", :open)))

      {:ok, _, _} =
        Presence.publish(
          @domain,
          publication("bob", flow: udp(5080), doc: doc("bob", :closed, "desk"))
        )

      before = Presence.state_of(@domain, {"bob", @package})

      {:ok, _, _} =
        Presence.publish(
          @domain,
          publication("bob", flow: udp(5070), operation: :refresh, etag: phone, doc: nil)
        )

      assert Presence.state_of(@domain, {"bob", @package}) == before
      assert %SIP.Presence.Doc{note: "desk"} = before
    end

    # Two PUBLISHes in the same second: the second states the person.
    test "the latest person state wins, within the same second too" do
      for note <- ["a", "b", "c", "d"] do
        {:ok, _, _} =
          Presence.publish(
            @domain,
            publication("bob", flow: udp(5070), doc: doc("bob", :open, note <> "1"))
          )

        {:ok, _, _} =
          Presence.publish(
            @domain,
            publication("bob", flow: udp(5080), doc: doc("bob", :open, note <> "2"))
          )

        assert Presence.state_of(@domain, {"bob", @package}).note == note <> "2"
      end
    end
  end

  # presence-composite-plan.md, PC3: one document per presentity, the tuples of
  # every live publication under one person state.
  describe "the composite state" do
    defp activity(user, status, activity, stamp \\ nil),
      do:
        SIP.Presence.Doc.new("sip:#{user}@#{@domain}", status,
          activity: activity,
          timestamp: stamp
        )

    defp bob, do: Presence.state_of(@domain, {"bob", @package})

    test "the tuples are the union: one open device makes the presentity open" do
      {:ok, _, _} =
        Presence.publish(@domain, publication("bob", flow: udp(5070), doc: doc("bob", :closed)))

      {:ok, _, _} =
        Presence.publish(@domain, publication("bob", flow: udp(5080), doc: doc("bob", :open)))

      assert SIP.Presence.Doc.status(bob()) == :open
      assert [%{status: :closed}, %{status: :open}] = bob().tuples
      assert bob().entity == "sip:bob@#{@domain}"
    end

    # §1, first symptom: away on the phone, the phone closed — Bob is still away,
    # not what the desk phone said two hours ago.
    test "the person state outlives the device that set it" do
      phone = connection()
      {:ok, _} = Presence.watch(@domain, subscription("bob", "alice"))

      {:ok, _, _} = Presence.publish(@domain, publication("bob", flow: udp(5070)))
      assert_receive {:presence, :state, _, _desk}

      {:ok, _, _} =
        Presence.publish(
          @domain,
          publication("bob", flow: phone, doc: activity("bob", :open, :away))
        )

      assert_receive {:presence, :state, _, %SIP.Presence.Doc{activity: :away}}

      drop(phone)

      assert_receive {:presence, :state, _, %SIP.Presence.Doc{activity: :away, tuples: [_desk]}}
    end

    # Decision 1: the field clients say "available" by publishing no person at
    # all; a modification without an activity clears it, a refresh does not.
    test "a modification with no activity clears the person state" do
      {:ok, etag, _} =
        Presence.publish(@domain, publication("bob", doc: activity("bob", :open, :busy)))

      assert bob().activity == :busy

      {:ok, etag, _} =
        Presence.publish(@domain, publication("bob", operation: :refresh, etag: etag, doc: nil))

      assert bob().activity == :busy

      {:ok, _, _} =
        Presence.publish(
          @domain,
          publication("bob", operation: :modify, etag: etag, doc: doc("bob", :open))
        )

      assert bob().activity == nil
    end

    # §1, second symptom: a device subscribed to its own presentity is told the
    # composite, its own tuple included, and has nothing to republish.
    test "a device watching its own presentity follows its other device" do
      desk = udp(5070)
      {:ok, _} = Presence.watch(@domain, subscription("bob", "bob"))

      {:ok, _, _} = Presence.publish(@domain, publication("bob", flow: desk))
      assert_receive {:presence, :state, _, _}

      {:ok, phone, _} =
        Presence.publish(
          @domain,
          publication("bob", flow: udp(5080), doc: activity("bob", :open, :busy))
        )

      assert_receive {:presence, :state, _, %SIP.Presence.Doc{activity: :busy, tuples: [_, _]}}

      {:ok, nil, 0} =
        Presence.publish(@domain, publication("bob", operation: :remove, etag: phone, expires: 0))

      assert_receive {:presence, :state, _, %SIP.Presence.Doc{activity: :busy, tuples: [_]}}
    end

    # Trix publishes "do not disturb" as busy plus `<trix:dnd/>`, and reads its
    # own status back from the composite: a mark lost on the way turned DND into
    # busy on the next page load (2026-10-03).
    test "the person keeps the marks it was published with" do
      dnd = [{"urn:trix:params:xml:ns:pidf", "dnd"}]
      {:ok, _} = Presence.watch(@domain, subscription("bob", "bob"))

      {:ok, _, _} =
        Presence.publish(
          @domain,
          publication("bob",
            doc: SIP.Presence.Doc.new("sip:bob@#{@domain}", :open, activity: :busy, marks: dnd)
          )
        )

      assert_receive {:presence, :state, _, %SIP.Presence.Doc{activity: :busy, marks: ^dnd}}
      assert bob().marks == dnd
    end

    # Linphone stamps every PUBLISH anew and mints new tuple ids: neither is news.
    test "republishing what the composite says notifies nobody" do
      {:ok, _} = Presence.watch(@domain, subscription("bob", "alice"))

      {:ok, etag, _} =
        Presence.publish(
          @domain,
          publication("bob", doc: activity("bob", :open, :busy, ~U[2026-10-01 19:18:51Z]))
        )

      assert_receive {:presence, :state, _, _}

      republished = %{
        activity("bob", :open, :busy, ~U[2026-10-01 19:20:00Z])
        | tuples: [
            %{
              hd(activity("bob", :open, :busy).tuples)
              | id: "pkgmk2",
                timestamp: ~U[2026-10-01 19:20:00Z]
            }
          ]
      }

      {:ok, etag, _} =
        Presence.publish(
          @domain,
          publication("bob", operation: :modify, etag: etag, doc: republished)
        )

      {:ok, _, _} =
        Presence.publish(@domain, publication("bob", operation: :refresh, etag: etag, doc: nil))

      refute_receive {:presence, :state, _, _}, 100
    end

    # The tuples are named after the publication's `ruid`, which outlives its
    # entity-tags: a device that did not move keeps its ids.
    test "a publication keeps its tuple ids across modifications" do
      {:ok, etag, _} = Presence.publish(@domain, publication("bob"))
      [%{id: id}] = bob().tuples

      {:ok, _, _} =
        Presence.publish(
          @domain,
          publication("bob", operation: :modify, etag: etag, doc: activity("bob", :open, :away))
        )

      assert [%{id: ^id}] = bob().tuples
      assert [%{ruid: ruid}] = Presence.presentities(@domain)
      assert id == "t-#{ruid}-1"
    end

    # A client that lost its tag starts over from the same flow: same device,
    # same tuples.
    test "an initial PUBLISH replacing the publisher's own keeps its ruid" do
      {:ok, _, _} = Presence.publish(@domain, publication("bob", flow: udp(5070)))
      [%{id: id}] = bob().tuples

      {:ok, _, _} = Presence.publish(@domain, publication("bob", flow: udp(5070)))
      assert [%{id: ^id}] = bob().tuples
    end
  end

  describe "a publication does not outlive its connection" do
    test "the connection drops: its publication goes, and the watchers are told" do
      flow = connection()
      {:ok, _} = Presence.watch(@domain, subscription("bob", "alice"))
      {:ok, _, _} = Presence.publish(@domain, publication("bob", flow: flow))
      assert_receive {:presence, :state, _resource, %SIP.Presence.Doc{}}

      drop(flow)

      assert_receive {:presence, :state, {"bob", @domain, @package}, nil}
      assert Presence.presentities(@domain) == []
    end

    test "the other publishers' states stay" do
      flow = connection()

      {:ok, _, _} =
        Presence.publish(@domain, publication("bob", flow: udp(5070), doc: doc("bob", :closed)))

      {:ok, _, _} = Presence.publish(@domain, publication("bob", flow: flow))
      {:ok, _, _} = Presence.publish(@domain, publication("carol", flow: flow))

      drop(flow)

      assert eventually(fn -> match?([%{status: "closed"}], Presence.presentities(@domain)) end)
    end

    # A client that reconnected and refreshed with the tag it kept: the
    # publication moved to the new connection, the old one's end is not its end.
    test "a refresh over a new connection moves the publication to it" do
      old = connection()
      new = connection()
      {:ok, etag, _} = Presence.publish(@domain, publication("bob", flow: old))

      {:ok, _, _} =
        Presence.publish(
          @domain,
          publication("bob", flow: new, operation: :refresh, etag: etag, doc: nil)
        )

      drop(old)
      assert [_still] = Presence.presentities(@domain)

      drop(new)
      assert eventually(fn -> Presence.presentities(@domain) == [] end)
    end

    test "over UDP, only the lifetime ends a publication" do
      {:ok, _, _} = Presence.publish(@domain, publication("bob", flow: udp(5070)))
      assert [_one] = Presence.presentities(@domain)
    end
  end

  describe "watch/2 and the fan-out" do
    test "a watcher is handed the state as it stands" do
      published = doc("bob", :open, "Available")
      {:ok, _etag, _} = Presence.publish(@domain, publication("bob", doc: published))

      assert {:ok, held} = Presence.watch(@domain, subscription("bob", "alice"))
      assert unnamed(held) == unnamed(published)
    end

    test "a watcher of a resource nobody published gets nil, not an error" do
      assert {:ok, nil} = Presence.watch(@domain, subscription("bob", "alice"))
    end

    # Decision 1: the push reaches the watcher's SCENARIO INSTANCE, which sends
    # the NOTIFY from its own state — never the dialog from inside the module.
    test "one PUBLISH becomes one push per watcher" do
      {:ok, _} = Presence.watch(@domain, subscription("bob", "alice"))

      other = watcher_process(self())
      {:ok, _} = call_watch(other, subscription("bob", "carol"))

      published = doc("bob", :open, "Back")
      {:ok, _etag, _} = Presence.publish(@domain, publication("bob", doc: published))

      resource = {"bob", @domain, @package}
      assert_receive {:presence, :state, ^resource, pushed}
      assert unnamed(pushed) == unnamed(published)
      assert_receive {:watcher_got, ^other, {:presence, :state, ^resource, ^pushed}}
    end

    test "a watcher of another resource is not pushed to" do
      {:ok, _} = Presence.watch(@domain, subscription("carol", "alice"))
      {:ok, _etag, _} = Presence.publish(@domain, publication("bob"))

      refute_receive {:presence, :state, _resource, _doc}, 100
    end

    # "Nothing is published about this resource any more": what to notify then is
    # the watcher script's decision, not the collection's.
    test "a removal pushes nil" do
      {:ok, _} = Presence.watch(@domain, subscription("bob", "alice"))
      {:ok, etag, _} = Presence.publish(@domain, publication("bob"))
      assert_receive {:presence, :state, _resource, _doc}

      {:ok, nil, 0} =
        Presence.publish(@domain, publication("bob", operation: :remove, etag: etag, expires: 0))

      assert_receive {:presence, :state, _resource, nil}
    end

    # An un-SUBSCRIBE is accepted as a lifetime of zero and IS the end of a
    # subscription: storing it would leave a watcher nothing will ever reach.
    test "a subscription granted zero seconds is not stored" do
      {:ok, _} =
        Presence.watch(@domain, subscription("bob", "alice", status: :terminated, expires: 0))

      assert Presence.watchers(@domain, "bob") == []
    end

    test "unwatch/1 drops the caller" do
      {:ok, _} = Presence.watch(@domain, subscription("bob", "alice"))
      assert [_one] = Presence.watchers(@domain, "bob")

      :ok = Presence.unwatch(@domain)
      assert Presence.watchers(@domain, "bob") == []
    end

    # A subscription lives as long as the instance that accepted it, and that
    # instance dies with its dialog. Nothing has to say so.
    test "a watcher that dies is dropped" do
      other = watcher_process(self())
      {:ok, _} = call_watch(other, subscription("bob", "carol"))
      assert [_one] = Presence.watchers(@domain, "bob")

      ref = Process.monitor(other)
      send(other, :stop)
      assert_receive {:DOWN, ^ref, :process, ^other, _}

      # the module's own monitor has to be processed before the read
      assert eventually(fn -> Presence.watchers(@domain, "bob") == [] end)
    end
  end

  describe "expiry" do
    test "a lapsed publication is no longer the state of its resource" do
      {:ok, _etag, _} = Presence.publish(@domain, publication("bob", expires: 0))
      assert Presence.state_of(@domain, {"bob", @package}) == nil
      assert Presence.presentities(@domain) == []
    end

    # The sweep is what tells the watchers: a watcher left believing in a state
    # nobody refreshed is the failure it exists to prevent.
    test "the sweep pushes the resource's watchers" do
      stop_supervised!(Presence)
      start_supervised!({Presence, [sweep_ms: 50]})

      {:ok, _} = Presence.watch(@domain, subscription("bob", "alice"))
      {:ok, _etag, _} = Presence.publish(@domain, publication("bob", expires: 1))
      assert_receive {:presence, :state, _resource, _doc}

      assert_receive {:presence, :state, {"bob", @domain, @package}, nil}, 2_000
    end
  end

  describe "per-domain isolation" do
    test "two domains publishing the same user part hold two resources" do
      {:ok, _, _} = Presence.publish(@domain, publication("bob", doc: doc("bob", :open)))

      other = %{publication("bob") | domain: "other.example"}
      {:ok, _, _} = Presence.publish("other.example", other)

      assert [%{presentity_uri: "sip:bob@example.com"}] = Presence.presentities(@domain)
      assert [%{presentity_uri: "sip:bob@other.example"}] = Presence.presentities("other.example")
    end

    test "a watcher of one domain is not pushed by the other" do
      {:ok, _} = Presence.watch(@domain, subscription("bob", "alice"))

      other = %{publication("bob") | domain: "other.example"}
      {:ok, _, _} = Presence.publish("other.example", other)

      refute_receive {:presence, :state, _resource, _doc}, 100
    end
  end

  # The domain that ROUTED a SUBSCRIBE says nothing about the domains of what it
  # asks to watch. A Linphone client opens its buddy list on
  # `sip:rls@sip.linphone.org` — an URI that names no presentity at all — and
  # lists three buddies on three other domains. Keying what it watches on the
  # routed domain files every one of them under a domain nobody ever publishes on.
  describe "a resource belongs to the domain of its own URI" do
    @other "other.example"

    test "a watcher admitted through one domain is pushed by a PUBLISH on the resource's" do
      sub = subscription("bob", "alice", presentity_domain: @other)
      {:ok, nil} = Presence.watch(@domain, sub)

      published = SIP.Presence.Doc.new("sip:bob@#{@other}", :open, note: "Back")
      pub = %{publication("bob", doc: published) | domain: @other}
      {:ok, _etag, _} = Presence.publish(@other, pub)

      assert_receive {:presence, :state, {"bob", @other, @package}, pushed}
      assert unnamed(pushed) == unnamed(published)
    end

    test "and it is listed on that domain, under the presentity it actually watches" do
      {:ok, _} = Presence.watch(@domain, subscription("bob", "alice", presentity_domain: @other))

      assert Presence.watchers(@domain, "bob") == []
      assert [%{presentity_uri: "sip:bob@other.example"}] = Presence.watchers(@other, "bob")
    end

    test "the state it is handed at registration is the resource's own" do
      pub = %{publication("bob", doc: doc("bob", :open, "Elsewhere")) | domain: @other}
      {:ok, _etag, _} = Presence.publish(@other, pub)

      assert {:ok, %SIP.Presence.Doc{note: "Elsewhere"}} =
               Presence.watch(@domain, subscription("bob", "alice", presentity_domain: @other))
    end
  end

  describe "watch_many/3 — one subscription, N resources (RFC 4662)" do
    @entries [
      "sip:900020123@visioassistance.net",
      "sip:9876@conf.weshwesh.eu",
      "sip:magali.buu@weshwesh.eu"
    ]

    # Two of the three entries are on domains this node serves; the third is on a
    # domain it has never heard of, which is the normal shape of a buddy list.
    setup do
      path =
        Path.join(
          System.tmp_dir!(),
          "presence_rls_domains_#{System.unique_integer([:positive])}.toml"
        )

      File.write!(path, """
      [[domain]]
      name = "weshwesh.eu"

        [[domain.presence]]
        event-package = "presence"
        subscribe = "presence-subscribe.exs"

      [[domain]]
      name = "conf.weshwesh.eu"

        [[domain.presence]]
        event-package = "presence"
        subscribe = "presence-subscribe.exs"
      """)

      :ok = Kelix.Domains.reload(path)

      on_exit(fn ->
        empty = Path.join(System.tmp_dir!(), "presence_rls_empty.toml")
        File.write!(empty, "")
        _ = Kelix.Domains.reload(empty)
        File.rm(path)
      end)

      :ok
    end

    test "answers one state per entry, keyed on the URI the watcher wrote" do
      pub = %{publication("magali.buu", doc: doc("magali.buu", :open)) | domain: "weshwesh.eu"}
      {:ok, _etag, _} = Presence.publish("weshwesh.eu", pub)

      assert {:ok, docs} =
               Presence.watch_many(@domain, subscription("rls", "bob"), @entries)

      assert Map.keys(docs) |> Enum.sort() == Enum.sort(@entries)
      assert docs["sip:900020123@visioassistance.net"] == nil
      assert %SIP.Presence.Doc{} = docs["sip:magali.buu@weshwesh.eu"]
    end

    test "each entry is watched on its own domain, and each pushes once" do
      {:ok, _} = Presence.watch_many(@domain, subscription("rls", "bob"), @entries)

      assert [%{presentity_uri: "sip:9876@conf.weshwesh.eu"}] =
               Presence.watchers("conf.weshwesh.eu", "9876")

      pub = %{publication("9876") | domain: "conf.weshwesh.eu"}
      {:ok, _etag, _} = Presence.publish("conf.weshwesh.eu", pub)

      assert_receive {:presence, :state, {"9876", "conf.weshwesh.eu", @package}, _doc}
      refute_receive {:presence, :state, _resource, _doc}, 100
    end

    # The list is the client's, so the number of domains in it is the client's
    # too: registering a watcher per invented domain is a table and a monitor per
    # invented domain. The entry still gets an answer — `nil`, which the notifier
    # reports as `noresource`.
    test "an entry on a domain this node does not serve is answered, not registered" do
      assert {:ok, docs} = Presence.watch_many(@domain, subscription("rls", "bob"), @entries)

      assert docs["sip:900020123@visioassistance.net"] == nil
      assert Presence.watchers("visioassistance.net", "900020123") == []
    end

    test "unwatch/1 drops it from every domain its list spans" do
      {:ok, _} = Presence.watch_many(@domain, subscription("rls", "bob"), @entries)

      :ok = Presence.unwatch(@domain)

      for uri <- @entries do
        {:ok, %SIP.Uri{userpart: user, domain: dom}} = SIP.Uri.parse(uri)
        assert Presence.watchers(dom, user) == []
      end
    end

    test "an instance that dies is dropped from every domain too" do
      other = watcher_process(self())

      assert {:ok, _} = call_watch_many(other, subscription("rls", "bob"), @entries)

      assert [_one] = Presence.watchers("weshwesh.eu", "magali.buu")

      ref = Process.monitor(other)
      send(other, :stop)
      assert_receive {:DOWN, ^ref, :process, ^other, _}

      assert eventually(fn ->
               Presence.watchers("weshwesh.eu", "magali.buu") == [] and
                 Presence.watchers("conf.weshwesh.eu", "9876") == []
             end)
    end
  end

  # Nothing published: a registration reported by the registrar script opens the
  # presentity; a subscriber of a domain with a registrar is closed otherwise.
  # Everything else has no state.
  describe "a resource nobody publishes" do
    @entries [
      "sip:900020123@visioassistance.net",
      "sip:9876@conf.weshwesh.eu",
      "sip:magali.buu@weshwesh.eu",
      "sip:nobody@weshwesh.eu"
    ]

    @magali {"magali.buu", "weshwesh.eu", "presence"}

    setup do
      Kelix.Test.Fixtures.serve_domains("""
      [[domain]]
      name = "weshwesh.eu"

        [domain.registrar]
        script = "registrar.exs"

        [[domain.presence]]
        event-package = "presence"
        subscribe = "presence-subscribe.exs"

      [[domain]]
      name = "conf.weshwesh.eu"

        [[domain.presence]]
        event-package = "presence"
        subscribe = "presence-subscribe.exs"
      """)

      start_supervised!(Kelix.Mod.Registrar)

      Application.put_env(:kelixip, :authdb_ha1_lookup, fn
        "magali.buu", "weshwesh.eu" -> {:ok, "0123456789abcdef0123456789abcdef"}
        _user, _realm -> :notfound
      end)

      on_exit(fn -> Application.delete_env(:kelixip, :authdb_ha1_lookup) end)
      :ok
    end

    # One device of magali's: its REGISTER dialog (a live process standing in for
    # it), and the context its registrar-presence instance reports with.
    defp device(host) do
      dialog = spawn(fn -> Process.sleep(:infinity) end)
      on_exit(fn -> Process.exit(dialog, :kill) end)
      %{host: host, dialog: dialog}
    end

    defp register_req(%{host: host}, expires) do
      %{
        method: :REGISTER,
        to: %SIP.Uri{userpart: "magali.buu", domain: "weshwesh.eu"},
        ruri: %SIP.Uri{
          userpart: "magali.buu",
          domain: "weshwesh.eu",
          destip: {1, 2, 3, 4},
          destport: 5060,
          destproto: "UDP",
          tp_pid: self()
        },
        contact: %SIP.Uri{userpart: "magali.buu", domain: host, port: 5060},
        expires: expires,
        callid: "reg-" <> host
      }
    end

    defp ctx(device, req) do
      %SIP.Context{domain: "weshwesh.eu", dialogpid: device.dialog}
      |> SIP.Context.appdata_set(:last_uas_req, req)
    end

    # What registrar-presence.exs does with a REGISTER: save it, then report it.
    defp register(device, expires \\ 3600) do
      req = register_req(device, expires)
      {verdict, _granted} = Kelix.Mod.Registrar.save(req, "weshwesh.eu", device.dialog)
      :ok = Presence.registration_changed(ctx(device, req))
      verdict
    end

    # ... and with the end of its dialog, the binding still in the store.
    defp registration_ended(device),
      do: :ok = Presence.registration_ended(ctx(device, register_req(device, 3600)))

    defp status(%SIP.Presence.Doc{} = doc), do: SIP.Presence.Doc.status(doc)

    # An un-REGISTER is also the unPUBLISH of the device that sends it: told by
    # the flow, as a publisher is. Another device's publication stays.
    test "an un-REGISTER withdraws what the device published, and only that" do
      phone = device("10.0.0.9")
      :registered = register(phone)
      over_phone = SIP.Msg.Ops.arrival_flow(register_req(phone, 3600))

      published = fn flow, doc ->
        pub = %{publication("magali.buu", flow: flow, doc: doc) | domain: "weshwesh.eu"}
        {:ok, _, _} = Presence.publish("weshwesh.eu", pub)
      end

      published.(udp(5080), doc("magali.buu", :closed, "desk"))
      published.(over_phone, doc("magali.buu", :open, "phone"))
      {:ok, _} = Presence.watch_many(@domain, subscription("rls", "bob"), @entries)

      :unregistered = register(phone, 0)

      # the phone's tuple goes; the person it stated stays (see *The composite
      # state*)
      assert_receive {:presence, :state, @magali,
                      %SIP.Presence.Doc{note: "phone", tuples: [%{note: "desk"}]}}

      assert [%{activity: _}] =
               Enum.filter(Presence.presentities("weshwesh.eu"), &(&1.source == "publish"))
    end

    # A UDP registration that was not refreshed: the device is gone, and so is
    # what it published.
    test "a registration that ends withdraws what the device published" do
      phone = device("10.0.0.9")
      :registered = register(phone)
      over_phone = SIP.Msg.Ops.arrival_flow(register_req(phone, 3600))
      pub = %{publication("magali.buu", flow: over_phone) | domain: "weshwesh.eu"}
      {:ok, _, _} = Presence.publish("weshwesh.eu", pub)

      registration_ended(phone)

      assert Presence.state_of("weshwesh.eu", {"magali.buu", "presence"}) == nil
    end

    # The same device (same flow) registered again through another dialog: the
    # first dialog's end is not the device's.
    test "unless the device still holds a binding over the same flow" do
      phone = device("10.0.0.9")
      again = device("10.0.0.10")
      :registered = register(phone)
      :registered = register(again)
      over_phone = SIP.Msg.Ops.arrival_flow(register_req(phone, 3600))
      pub = %{publication("magali.buu", flow: over_phone) | domain: "weshwesh.eu"}
      {:ok, _, _} = Presence.publish("weshwesh.eu", pub)

      registration_ended(phone)

      assert %SIP.Presence.Doc{} = Presence.state_of("weshwesh.eu", {"magali.buu", "presence"})
    end

    test "a refreshing REGISTER withdraws nothing" do
      phone = device("10.0.0.9")
      :registered = register(phone)
      over_phone = SIP.Msg.Ops.arrival_flow(register_req(phone, 3600))
      pub = %{publication("magali.buu", flow: over_phone) | domain: "weshwesh.eu"}
      {:ok, _, _} = Presence.publish("weshwesh.eu", pub)

      :registered = register(phone)

      assert %SIP.Presence.Doc{} = Presence.state_of("weshwesh.eu", {"magali.buu", "presence"})
    end

    test "a registered subscriber is open, the others have no state" do
      :registered = register(device("10.0.0.9"))

      assert {:ok, docs} = Presence.watch_many(@domain, subscription("rls", "bob"), @entries)

      assert status(docs["sip:magali.buu@weshwesh.eu"]) == :open
      # a user the subscriber base does not know
      assert docs["sip:nobody@weshwesh.eu"] == nil
      # a served domain with no registrar
      assert docs["sip:9876@conf.weshwesh.eu"] == nil
      # a domain this node does not serve
      assert docs["sip:900020123@visioassistance.net"] == nil
    end

    test "a subscriber that is not registered is closed" do
      assert {:ok, docs} = Presence.watch_many(@domain, subscription("rls", "bob"), @entries)
      assert status(docs["sip:magali.buu@weshwesh.eu"]) == :closed
    end

    # A registration nobody reported is not seen: registrar.exs does not report.
    test "a binding the registrar script did not report leaves the subscriber closed" do
      phone = device("10.0.0.9")
      {:registered, _} = Kelix.Mod.Registrar.save(register_req(phone, 3600), "weshwesh.eu")

      assert {:ok, docs} = Presence.watch_many(@domain, subscription("rls", "bob"), @entries)
      assert status(docs["sip:magali.buu@weshwesh.eu"]) == :closed
    end

    # `kelictl presence list weshwesh.eu` answered `(none)` for a registered
    # subscriber its watchers were told was open.
    test "list and show carry a reported registration, unwatched and unpublished" do
      :registered = register(device("10.0.0.9"))

      assert {:ok, [%{aor: "magali.buu", status: "open", sources: "registrar", watchers: 0}]} =
               Presence.handle_control("list", %{"domain" => "weshwesh.eu"})

      assert {:ok, %{states: [row], watchers: []}} =
               Presence.handle_control("show", %{"domain" => "weshwesh.eu", "aor" => "magali.buu"})

      assert %{
               presentity_uri: "sip:magali.buu@weshwesh.eu",
               event: "presence",
               source: "registrar",
               status: "open",
               etag: nil
             } = row
    end

    test "the registration row goes with the last device" do
      phone = device("10.0.0.9")
      :registered = register(phone)
      registration_ended(phone)

      assert {:ok, []} = Presence.handle_control("list", %{"domain" => "weshwesh.eu"})
    end

    test "the live panel shows a registration, and its end" do
      {:ok, []} = Presence.subscribe_presentities("weshwesh.eu", self())

      phone = device("10.0.0.9")
      :registered = register(phone)

      assert_receive {:kelix_presence, "weshwesh.eu",
                      {:upsert,
                       %{aor: "magali.buu", status: "open", states: [%{source: "registrar"}]}}}

      registration_ended(phone)
      assert_receive {:kelix_presence, "weshwesh.eu", {:remove, "magali.buu"}}
    end

    test "a publication and a registration are both listed" do
      :registered = register(device("10.0.0.9"))
      pub = %{publication("magali.buu", doc: doc("magali.buu", :closed)) | domain: "weshwesh.eu"}
      {:ok, _etag, _} = Presence.publish("weshwesh.eu", pub)

      # one line for the AOR, stating what its watchers are told: the composite,
      # open through the registered device the publication does not speak for
      assert {:ok, [%{aor: "magali.buu", status: "open", sources: "publish, registrar"}]} =
               Presence.handle_control("list", %{"domain" => "weshwesh.eu"})

      # show heads its states with the same composite
      assert {:ok, %{status: "open", activity: nil, calls: nil, states: states}} =
               Presence.handle_control("show", %{"domain" => "weshwesh.eu", "aor" => "magali.buu"})

      assert [%{source: "publish", status: "closed"}, %{source: "registrar", status: "open"}] =
               Enum.sort_by(states, & &1.source)
    end

    test "a live publication wins over the registration" do
      :registered = register(device("10.0.0.9"))

      pub = %{
        publication("magali.buu", doc: doc("magali.buu", :closed, "busy"))
        | domain: "weshwesh.eu"
      }

      {:ok, _etag, _} = Presence.publish("weshwesh.eu", pub)

      assert {:ok, docs} = Presence.watch_many(@domain, subscription("rls", "bob"), @entries)
      assert %SIP.Presence.Doc{note: "busy"} = docs["sip:magali.buu@weshwesh.eu"]
    end

    test "watch/2 answers the same reading" do
      sub = subscription("magali.buu", "bob", presentity_domain: "weshwesh.eu")
      assert {:ok, doc} = Presence.watch(@domain, sub)
      assert status(doc) == :closed

      :registered = register(device("10.0.0.9"))
      assert {:ok, doc} = Presence.watch(@domain, sub)
      assert status(doc) == :open
    end

    test "registering pushes open once, un-registering pushes closed" do
      {:ok, _} = Presence.watch_many(@domain, subscription("rls", "bob"), @entries)
      phone = device("10.0.0.9")

      :registered = register(phone)
      assert_receive {:presence, :state, @magali, doc}
      assert status(doc) == :open

      # a refreshing REGISTER changes nothing a watcher can see
      :registered = register(phone)
      refute_receive {:presence, :state, @magali, _doc}, 100

      :unregistered = register(phone, 0)
      assert_receive {:presence, :state, @magali, doc}
      assert status(doc) == :closed
    end

    test "a registration that ends — dropped or not refreshed — pushes closed" do
      phone = device("10.0.0.9")
      :registered = register(phone)
      {:ok, _} = Presence.watch_many(@domain, subscription("rls", "bob"), @entries)

      # the store still holds the binding: the ending dialog's own do not count
      registration_ended(phone)
      assert_receive {:presence, :state, @magali, doc}
      assert status(doc) == :closed
    end

    test "a subscriber stays open while one of its devices is registered" do
      {phone, softphone} = {device("10.0.0.9"), device("10.0.0.10")}
      :registered = register(phone)
      :registered = register(softphone)
      {:ok, _} = Presence.watch_many(@domain, subscription("rls", "bob"), @entries)

      # one device un-registers, the other drops: closed only after the second.
      # The first one's tuple goes, which the watchers are told — still open
      :registered = register(phone, 0)
      assert_receive {:presence, :state, @magali, %SIP.Presence.Doc{tuples: [_one]} = doc}
      assert status(doc) == :open

      registration_ended(softphone)
      assert_receive {:presence, :state, @magali, doc}
      assert status(doc) == :closed
    end

    # No registrar script sees a binding dropped by hand: the control layer, which
    # both kelictl and REST go through, reports it when presence is loaded.
    test "a registration removed by kelictl / REST pushes closed" do
      Kelix.ModuleRegistry.register("registrar", Kelix.Mod.Registrar, %{})
      Kelix.ModuleRegistry.register("presence", Presence, %{})

      on_exit(fn ->
        Kelix.ModuleRegistry.unregister("registrar")
        Kelix.ModuleRegistry.unregister("presence")
      end)

      :registered = register(device("10.0.0.9"))
      {:ok, _} = Presence.watch_many(@domain, subscription("rls", "bob"), @entries)

      assert :ok = Kelix.Control.unregister("weshwesh.eu", "magali.buu")
      assert_receive {:presence, :state, @magali, doc}
      assert status(doc) == :closed
    end

    test "removing one of two devices by hand keeps the subscriber open" do
      Kelix.ModuleRegistry.register("registrar", Kelix.Mod.Registrar, %{})
      Kelix.ModuleRegistry.register("presence", Presence, %{})

      on_exit(fn ->
        Kelix.ModuleRegistry.unregister("registrar")
        Kelix.ModuleRegistry.unregister("presence")
      end)

      :registered = register(device("10.0.0.9"))
      :registered = register(device("10.0.0.10"))
      {:ok, _} = Presence.watch_many(@domain, subscription("rls", "bob"), @entries)

      [%{contact: first} | _] = Kelix.Mod.Registrar.bindings("weshwesh.eu", "magali.buu")
      {:ok, contact} = SIP.Uri.serialize_ruri(first)

      assert :ok = Kelix.Control.unregister("weshwesh.eu", "magali.buu", contact)
      assert_receive {:presence, :state, @magali, %SIP.Presence.Doc{tuples: [_one]} = doc}
      assert status(doc) == :open
      assert [_other] = Kelix.Mod.Registrar.bindings("weshwesh.eu", "magali.buu")
    end

    # Withdrawing a report falls back on what the registrar side says — and a
    # resource that only ever existed through the report has no state left.
    test "a withdrawn report leaves a subscriber closed and a room with no state" do
      reporter = reporter_process()

      {:ok, _} =
        Presence.watch_many(@domain, subscription("rls", "bob"), [
          "sip:magali.buu@weshwesh.eu",
          "sip:8001@weshwesh.eu"
        ])

      for user <- ["magali.buu", "8001"] do
        room = SIP.Presence.Doc.new("sip:#{user}@weshwesh.eu", :open, activity: :busy)
        :ok = report_from(reporter, user, room, :mcu, "weshwesh.eu")
        assert_receive {:presence, :state, {^user, "weshwesh.eu", "presence"}, %{activity: :busy}}
      end

      send(reporter, :stop)

      assert_receive {:presence, :state, @magali, doc}
      assert status(doc) == :closed
      assert_receive {:presence, :state, {"8001", "weshwesh.eu", "presence"}, nil}
    end

    # A device that publishes is told by its flow, as a publisher is: its
    # registration adds nothing to what its publication already says.
    test "the registration of a device that publishes adds no tuple" do
      phone = device("10.0.0.9")
      over_phone = SIP.Msg.Ops.arrival_flow(register_req(phone, 3600))

      pub = %{
        publication("magali.buu", flow: over_phone, doc: doc("magali.buu", :closed))
        | domain: "weshwesh.eu"
      }

      {:ok, _etag, _} = Presence.publish("weshwesh.eu", pub)
      {:ok, _} = Presence.watch_many(@domain, subscription("rls", "bob"), @entries)

      :registered = register(phone)
      refute_receive {:presence, :state, _resource, _doc}, 100

      assert %SIP.Presence.Doc{tuples: [%{status: :closed}]} =
               Presence.state_of("weshwesh.eu", {"magali.buu", "presence"})
    end

    # Bob is reachable on the desk phone that only registers while his mobile
    # publishes: the device adds one open tuple, offering its contact.
    test "a registered device that publishes nothing adds an open tuple" do
      pub = %{
        publication("magali.buu", flow: udp(5070), doc: doc("magali.buu", :closed))
        | domain: "weshwesh.eu"
      }

      {:ok, _etag, _} = Presence.publish("weshwesh.eu", pub)
      {:ok, _} = Presence.watch_many(@domain, subscription("rls", "bob"), @entries)

      phone = device("10.0.0.9")
      :registered = register(phone)

      assert_receive {:presence, :state, @magali, %SIP.Presence.Doc{tuples: tuples} = doc}
      assert status(doc) == :open

      assert [
               %{status: :closed, contact: nil},
               %{status: :open, contact: "sip:magali.buu@10.0.0.9"}
             ] =
               tuples

      # a refreshing REGISTER moves nothing
      :registered = register(phone)
      refute_receive {:presence, :state, @magali, _doc}, 100

      # the device goes: the publication alone again
      :unregistered = register(phone, 0)
      assert_receive {:presence, :state, @magali, %SIP.Presence.Doc{tuples: [_one]} = doc}
      assert status(doc) == :closed
    end

    # The person is the presentity's, not a device's: a registered device's
    # tuple sits beside the activity a publication set.
    test "a registered device keeps the published activity" do
      :registered = register(device("10.0.0.9"))

      pub = %{
        publication("magali.buu",
          flow: udp(5070),
          doc: SIP.Presence.Doc.new("sip:magali.buu@weshwesh.eu", :closed, activity: :away)
        )
        | domain: "weshwesh.eu"
      }

      {:ok, _etag, _} = Presence.publish("weshwesh.eu", pub)

      assert %SIP.Presence.Doc{activity: :away, tuples: [_published, _registered]} =
               Presence.state_of("weshwesh.eu", {"magali.buu", "presence"})
    end

    test "when the publication goes, a registered subscriber is pushed open" do
      :registered = register(device("10.0.0.9"))
      pub = %{publication("magali.buu", doc: doc("magali.buu", :closed)) | domain: "weshwesh.eu"}
      {:ok, etag, _} = Presence.publish("weshwesh.eu", pub)
      {:ok, _} = Presence.watch_many(@domain, subscription("rls", "bob"), @entries)

      removal = %{
        publication("magali.buu", operation: :remove, etag: etag, expires: 0)
        | domain: "weshwesh.eu"
      }

      {:ok, nil, 0} = Presence.publish("weshwesh.eu", removal)

      assert_receive {:presence, :state, @magali, doc}
      assert status(doc) == :open
    end
  end

  describe "report/4 — a state another module states" do
    @room {"8001", @domain, @package}

    defp busy(user), do: SIP.Presence.Doc.new("sip:#{user}@#{@domain}", :open, activity: :busy)

    test "a reported state is what a watcher is handed, and state_of/2 does not see it" do
      reporter = reporter_process()
      :ok = report_from(reporter, "8001", doc("8001", :open))

      assert {:ok, doc} = Presence.watch(@domain, subscription("8001", "alice"))
      assert status(doc) == :open
      # state_of/2 is what is PUBLISHED about a resource
      assert Presence.state_of(@domain, {"8001", @package}) == nil
    end

    test "a change of the resolved state is pushed, and only then" do
      reporter = reporter_process()
      {:ok, nil} = Presence.watch(@domain, subscription("8001", "alice"))

      :ok = report_from(reporter, "8001", doc("8001", :open))
      assert_receive {:presence, :state, @room, doc}
      assert status(doc) == :open

      # the same thing said again is news to nobody
      :ok = report_from(reporter, "8001", doc("8001", :open))
      refute_receive {:presence, :state, @room, _doc}, 100

      :ok = report_from(reporter, "8001", busy("8001"))
      assert_receive {:presence, :state, @room, %SIP.Presence.Doc{activity: :busy}}

      # withdrawn: no state left, on a domain with no registrar
      :ok = report_from(reporter, "8001", nil)
      assert_receive {:presence, :state, @room, nil}
    end

    test "the reporter's death withdraws every state it reported" do
      reporter = reporter_process()
      :ok = report_from(reporter, "8001", doc("8001", :open))
      :ok = report_from(reporter, "8002", doc("8002", :closed))
      {:ok, _} = Presence.watch(@domain, subscription("8001", "alice"))
      {:ok, _} = Presence.watch(@domain, subscription("8002", "alice"))

      send(reporter, :stop)

      assert_receive {:presence, :state, {"8001", @domain, @package}, nil}
      assert_receive {:presence, :state, {"8002", @domain, @package}, nil}
      refute Presence.exists?(@domain, "8001")
    end

    test "a publication wins over a report, which comes back when it expires" do
      stop_supervised!(Presence)
      start_supervised!({Presence, [sweep_ms: 50]})

      reporter = reporter_process()
      :ok = report_from(reporter, "8001", busy("8001"))
      {:ok, _} = Presence.watch(@domain, subscription("8001", "alice"))

      published = doc("8001", :closed, "maintenance")
      {:ok, _etag, _} = Presence.publish(@domain, publication("8001", doc: published, expires: 1))
      assert_receive {:presence, :state, @room, pushed}
      assert unnamed(pushed) == unnamed(published)

      # under a live publication, a report changes nothing a watcher can see
      :ok = report_from(reporter, "8001", doc("8001", :open))
      refute_receive {:presence, :state, @room, _doc}, 100

      assert_receive {:presence, :state, @room, doc}, 2_000
      assert status(doc) == :open
      assert doc.activity == nil
    end

    test "the most recent source wins, and withdrawing it brings the other back" do
      mcu = reporter_process()
      other = reporter_process()
      {:ok, _} = Presence.watch(@domain, subscription("8001", "alice"))

      :ok = report_from(mcu, "8001", doc("8001", :open), :mcu)
      assert_receive {:presence, :state, @room, _open}
      :ok = report_from(other, "8001", doc("8001", :closed), :other)
      assert_receive {:presence, :state, @room, closed}
      assert status(closed) == :closed

      :ok = report_from(other, "8001", nil, :other)
      assert_receive {:presence, :state, @room, open}
      assert status(open) == :open
    end

    test "exists?/2 answers for a reported resource" do
      refute Presence.exists?(@domain, "8001")

      reporter = reporter_process()
      :ok = report_from(reporter, "8001", doc("8001", :open))

      assert Presence.exists?(@domain, "8001")
      assert Presence.exists?(%SIP.Context{domain: @domain}, "8001")

      :ok = report_from(reporter, "8001", nil)
      refute Presence.exists?(@domain, "8001")
    end

    test "list, show and the live panel carry the reported state with its source" do
      {:ok, []} = Presence.subscribe_presentities(@domain, self())
      reporter = reporter_process()
      :ok = report_from(reporter, "8001", busy("8001"))

      assert_receive {:kelix_presence, @domain,
                      {:upsert,
                       %{
                         aor: "8001",
                         status: "open",
                         activity: "busy",
                         states: [%{source: "mcu"}]
                       }}}

      assert {:ok, [%{aor: "8001", status: "open", activity: "busy", sources: "mcu", calls: nil}]} =
               Presence.handle_control("list", %{"domain" => @domain})

      assert {:ok, %{states: [row]}} =
               Presence.handle_control("show", %{"domain" => @domain, "aor" => "8001"})

      assert %{
               presentity_uri: "sip:8001@example.com",
               source: "mcu",
               status: "open",
               activity: "busy"
             } = row

      :ok = report_from(reporter, "8001", nil)
      assert_receive {:kelix_presence, @domain, {:remove, "8001"}}
    end
  end

  describe "report/5 — the dialog package (RFC 4235)" do
    @bob_calls {"bob", @domain, "dialog"}

    setup do
      Application.put_env(:kelixip, :authdb_ha1_lookup, fn
        "bob", @domain -> {:ok, "0123456789abcdef0123456789abcdef"}
        _user, _realm -> :notfound
      end)

      on_exit(fn -> Application.delete_env(:kelixip, :authdb_ha1_lookup) end)
    end

    defp idle(user), do: %SIP.DialogInfo.Doc{entity: "sip:#{user}@#{@domain}"}

    defp on_a_call(user) do
      %SIP.DialogInfo.Doc{
        entity: "sip:#{user}@#{@domain}",
        dialogs: [
          %SIP.DialogInfo.Dialog{
            id: "d1",
            call_id: "call-1",
            direction: :recipient,
            state: :confirmed,
            remote: %SIP.DialogInfo.Party{identity: "sip:alice@#{@domain}"}
          }
        ]
      }
    end

    # Decision 7: an idle phone is an empty document, which its BLF key displays
    # as "no call"; noresource would end the subscription at subscribe time. No
    # registrar on this domain, no binding: the registration rank does not apply.
    test "a subscriber nobody reports on is an empty document, not no state" do
      assert {:ok, doc} = Presence.watch(@domain, subscription("bob", "alice", event: "dialog"))
      assert doc == idle("bob")
    end

    test "a user nobody provisioned has no state" do
      assert {:ok, nil} =
               Presence.watch(@domain, subscription("nobody", "alice", event: "dialog"))
    end

    test "a report is pushed, and its withdrawal pushes the empty document back" do
      reporter = reporter_process()
      {:ok, _idle} = Presence.watch(@domain, subscription("bob", "alice", event: "dialog"))

      doc = on_a_call("bob")
      :ok = report_dialog_from(reporter, "bob", doc)
      assert_receive {:presence, :state, @bob_calls, ^doc}

      # the same thing said again is news to nobody
      :ok = report_dialog_from(reporter, "bob", doc)
      refute_receive {:presence, :state, @bob_calls, _doc}, 100

      :ok = report_dialog_from(reporter, "bob", nil)
      assert_receive {:presence, :state, @bob_calls, empty}
      assert empty == idle("bob")
    end

    test "the reporter's death brings the empty document back too" do
      reporter = reporter_process()
      {:ok, _idle} = Presence.watch(@domain, subscription("bob", "alice", event: "dialog"))
      :ok = report_dialog_from(reporter, "bob", on_a_call("bob"))
      assert_receive {:presence, :state, @bob_calls, %SIP.DialogInfo.Doc{dialogs: [_one]}}

      send(reporter, :stop)
      assert_receive {:presence, :state, @bob_calls, %SIP.DialogInfo.Doc{dialogs: []}}
    end

    test "a resource that only existed through the report has no state once withdrawn" do
      reporter = reporter_process()
      {:ok, nil} = Presence.watch(@domain, subscription("nobody", "alice", event: "dialog"))

      :ok = report_dialog_from(reporter, "nobody", on_a_call("nobody"))
      assert_receive {:presence, :state, {"nobody", @domain, "dialog"}, %SIP.DialogInfo.Doc{}}

      :ok = report_dialog_from(reporter, "nobody", nil)
      assert_receive {:presence, :state, {"nobody", @domain, "dialog"}, nil}
    end

    test "the two packages of one AOR are two resources" do
      reporter = reporter_process()
      {:ok, _} = Presence.watch(@domain, subscription("bob", "alice"))
      {:ok, _} = Presence.watch(@domain, subscription("bob", "carol", event: "dialog"))

      :ok = report_dialog_from(reporter, "bob", on_a_call("bob"))
      assert_receive {:presence, :state, @bob_calls, _calls}
      refute_receive {:presence, :state, {"bob", @domain, "presence"}, _doc}, 100

      :ok = report_from(reporter, "bob", doc("bob", :open))
      assert_receive {:presence, :state, {"bob", @domain, "presence"}, _open}
      refute_receive {:presence, :state, @bob_calls, _doc}, 100
    end

    test "list, show and the live panel render the document by its dialog count" do
      {:ok, []} = Presence.subscribe_presentities(@domain, self())
      reporter = reporter_process()
      :ok = report_dialog_from(reporter, "bob", on_a_call("bob"), :dialog_state)

      assert_receive {:kelix_presence, @domain, {:upsert, %{aor: "bob", states: [row]}}}
      assert %{event: "dialog", source: "dialog_state", status: "1 dialog"} = row

      assert {:ok, [%{aor: "bob", calls: 1, sources: "dialog_state"}]} =
               Presence.handle_control("list", %{"domain" => @domain})

      assert {:ok, %{states: [^row]}} =
               Presence.handle_control("show", %{"domain" => @domain, "aor" => "bob"})
    end
  end

  describe "exists?/2 against the subscriber base" do
    setup do
      Application.put_env(:kelixip, :authdb_ha1_lookup, fn
        "bob", @domain -> {:ok, "0123456789abcdef0123456789abcdef"}
        _user, _realm -> :notfound
      end)

      on_exit(fn -> Application.delete_env(:kelixip, :authdb_ha1_lookup) end)
    end

    test "a subscriber exists, a user nobody provisioned does not" do
      assert Presence.exists?(@domain, "bob")
      assert Presence.exists?(@domain, "BOB")
      refute Presence.exists?(@domain, "nobody")
      refute Presence.exists?(@domain, nil)
    end
  end

  describe "the control surface" do
    setup do
      {:ok, etag, _} = Presence.publish(@domain, publication("bob"))
      {:ok, _} = Presence.watch(@domain, subscription("bob", "alice"))
      %{etag: etag}
    end

    test "list renders one row per presentity" do
      assert {:ok, [row]} = Presence.handle_control("list", %{"domain" => @domain})
      assert %{aor: "bob", status: "open", watchers: 1, sources: "publish"} = row
    end

    # kamailio's column names, deliberately: one vocabulary for an operator who
    # migrated from it.
    test "show renders the states under kamailio's column names", %{etag: etag} do
      assert {:ok, %{states: [row]}} =
               Presence.handle_control("show", %{"domain" => @domain, "aor" => "bob"})

      assert row.presentity_uri == "sip:bob@#{@domain}"
      assert row.event == @package
      assert row.etag == etag
      assert row.expires > 0
    end

    test "watchers names the watcher and the subscription" do
      assert {:ok, [row]} =
               Presence.handle_control("watchers", %{"domain" => @domain, "aor" => "bob"})

      assert row.watcher == "sip:alice@#{@domain}"
      assert row.status == "active"
      assert row.presentity_uri == "sip:bob@#{@domain}"
    end

    test "show carries both halves" do
      assert {:ok, detail} =
               Presence.handle_control("show", %{"domain" => @domain, "aor" => "bob"})

      assert [_state] = detail.states
      assert [_watcher] = detail.watchers
    end

    # `kelictl presence list D bob` listed every presentity of D: the surplus
    # token was dropped, so the operator read the result as filtered.
    test "a token no argument takes is refused, not dropped" do
      assert {:error, "unexpected argument: bob"} =
               Presence.handle_control("list", %{
                 "domain" => @domain,
                 "args" => ["domain=#{@domain}", "bob"]
               })

      assert {:ok, [_row]} =
               Presence.handle_control("list", %{
                 "domain" => @domain,
                 "args" => ["domain=#{@domain}"]
               })
    end

    test "show of an AOR nothing is held about is a 404" do
      assert {:error, :not_found} =
               Presence.handle_control("show", %{"domain" => @domain, "aor" => "nobody"})
    end

    # The published state goes; the subscriptions stay, and are told there is
    # nothing left. Tearing them down would look the same here and quite
    # different on the wire.
    test "remove drops the state and pushes the watchers" do
      assert {:ok, _} = Presence.handle_control("remove", %{"domain" => @domain, "aor" => "bob"})
      assert_receive {:presence, :state, _resource, nil}
      assert Presence.presentities(@domain) == []
      assert [_still_watching] = Presence.watchers(@domain, "bob")
    end

    test "remove of an unknown AOR is a 404" do
      assert {:error, :not_found} =
               Presence.handle_control("remove", %{"domain" => @domain, "aor" => "nobody"})
    end

    test "an unknown command is named as such" do
      assert {:error, {:unknown_command, "bogus"}} =
               Presence.handle_control("bogus", %{"domain" => @domain})
    end

    # Two commands no request could tell apart would make dispatch depend on
    # iteration order, so the whole surface is refused at registration. Both
    # frontals derive from this one declaration, so checking it here checks
    # `kelictl presence` and `/modules/presence` at once.
    test "the declared command set is routable" do
      assert :ok = Kelix.Control.Route.check_conflicts(Presence.describe_control())

      # every declared command answers something — a name in describe_control/0
      # with no handle_control/2 clause is a command that 500s on first use
      for %{name: name} <- Presence.describe_control() do
        refute match?(
                 {:error, {:unknown_command, _}},
                 Presence.handle_control(name, %{"domain" => @domain, "aor" => "bob"})
               )
      end
    end
  end

  describe "validate_config/1" do
    test "accepts what the module declares" do
      assert :ok = Presence.validate_config(%{})
      assert :ok = Presence.validate_config(%{"call_timeout_ms" => 2_000})
    end

    # Fail fast on a typo instead of silently running on the default — and on a
    # key that belongs to the event package rather than to this collection.
    test "refuses an unknown key" do
      assert {:error, msg} = Presence.validate_config(%{"default_expires" => 3600})
      assert msg =~ "unknown key(s): default_expires"

      assert {:error, msg2} = Presence.validate_config(%{"policy" => "registered"})
      assert msg2 =~ "policy"
    end

    test "refuses a bad call timeout" do
      assert {:error, msg} = Presence.validate_config(%{"call_timeout_ms" => 0})
      assert msg =~ "positive integer"
    end
  end

  # A stand-in reporting module: `report/4` monitors its caller, so the report
  # has to come from a process whose death a test can decide.
  defp reporter_process() do
    pid =
      spawn(fn ->
        reporter_loop()
      end)

    on_exit(fn -> Process.exit(pid, :kill) end)
    pid
  end

  defp reporter_loop() do
    receive do
      {:report, from, domain, user, source, doc} ->
        send(from, {:reported, self(), Presence.report(domain, user, source, doc)})
        reporter_loop()

      {:report, from, domain, user, source, doc, package} ->
        send(from, {:reported, self(), Presence.report(domain, user, source, doc, package)})
        reporter_loop()

      :stop ->
        :ok
    end
  end

  defp report_from(reporter, user, doc, source \\ :mcu, domain \\ @domain) do
    send(reporter, {:report, self(), domain, user, source, doc})
    assert_receive {:reported, ^reporter, result}
    result
  end

  defp report_dialog_from(reporter, user, doc, source \\ :dialog_state) do
    send(reporter, {:report, self(), @domain, user, source, doc, "dialog"})
    assert_receive {:reported, ^reporter, result}
    result
  end

  # A stand-in watcher instance: it forwards what the fan-out pushes to it, so a
  # test can assert on a push that did NOT go to the test process.
  defp watcher_process(owner) do
    spawn(fn -> watcher_loop(owner) end)
  end

  defp watcher_loop(owner) do
    receive do
      :stop ->
        :ok

      {:watch, from, sub} ->
        send(from, {:watched, Presence.watch(@domain, sub)})
        watcher_loop(owner)

      {:watch_many, from, sub, uris} ->
        send(from, {:watched, Presence.watch_many(@domain, sub, uris)})
        watcher_loop(owner)

      msg ->
        send(owner, {:watcher_got, self(), msg})
        watcher_loop(owner)
    end
  end

  defp call_watch(pid, sub) do
    send(pid, {:watch, self(), sub})
    assert_receive {:watched, result}
    result
  end

  defp call_watch_many(pid, sub, uris) do
    send(pid, {:watch_many, self(), sub, uris})
    assert_receive {:watched, result}
    result
  end

  defp eventually(fun, attempts \\ 20) do
    cond do
      fun.() -> true
      attempts == 0 -> false
      true -> Process.sleep(10) && eventually(fun, attempts - 1)
    end
  end
end
