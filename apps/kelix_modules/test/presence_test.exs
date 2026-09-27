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
      sender: "sip:#{user}@#{@domain}"
    }
    |> SIP.Publication.grant(Keyword.get(opts, :expires, 3600))
  end

  defp doc(user, status, note \\ nil),
    do: SIP.Presence.Doc.new("sip:#{user}@#{@domain}", status, note: note)

  # A subscription as `accept_subscription/1` hands it back: granted, active, and
  # naming the resource in `presentity_uri`.
  defp subscription(presentity, watcher, opts \\ []) do
    presentity_domain = Keyword.get(opts, :presentity_domain, @domain)

    %SIP.Subscription{
      callid: Keyword.get(opts, :callid, "call-#{presentity}-#{watcher}"),
      to_tag: "totag",
      from_tag: "fromtag",
      event: @package,
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

      assert Presence.state_of(@domain, {"bob", @package}) == published
    end

    test "a modification replaces it" do
      {:ok, etag, _} = Presence.publish(@domain, publication("bob"))
      closed = doc("bob", :closed)

      {:ok, _, _} =
        Presence.publish(@domain, publication("bob", operation: :modify, etag: etag, doc: closed))

      assert Presence.state_of(@domain, {"bob", @package}) == closed
    end

    # RFC 3903 §4.1: a handset and a desk phone may hold state for one presentity
    # at the same time, each with a tag of its own. v1 emits the most recent
    # rather than composing them — see the moduledoc.
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

  describe "watch/2 and the fan-out" do
    test "a watcher is handed the state as it stands" do
      published = doc("bob", :open, "Available")
      {:ok, _etag, _} = Presence.publish(@domain, publication("bob", doc: published))

      assert {:ok, ^published} = Presence.watch(@domain, subscription("bob", "alice"))
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
      assert_receive {:presence, :state, ^resource, ^published}
      assert_receive {:watcher_got, ^other, {:presence, :state, ^resource, ^published}}
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

      published = doc("bob", :open, "Back")
      pub = %{publication("bob", doc: published) | domain: @other}
      {:ok, _etag, _} = Presence.publish(@other, pub)

      assert_receive {:presence, :state, {"bob", @other, @package}, ^published}
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

    defp status(%SIP.Presence.Doc{tuples: [%{status: status}]}), do: status

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

      # one device un-registers, the other drops: closed only after the second
      # the AOR keeps the other device's binding, so it stays registered
      :registered = register(phone, 0)
      refute_receive {:presence, :state, @magali, _doc}, 100

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
      refute_receive {:presence, :state, @magali, _doc}, 100
      assert [_other] = Kelix.Mod.Registrar.bindings("weshwesh.eu", "magali.buu")
    end

    test "a registration is not pushed over a live publication" do
      pub = %{publication("magali.buu") | domain: "weshwesh.eu"}
      {:ok, _etag, _} = Presence.publish("weshwesh.eu", pub)
      {:ok, _} = Presence.watch_many(@domain, subscription("rls", "bob"), @entries)

      :registered = register(device("10.0.0.9"))
      refute_receive {:presence, :state, _resource, _doc}, 100
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

  describe "the control surface" do
    setup do
      {:ok, etag, _} = Presence.publish(@domain, publication("bob"))
      {:ok, _} = Presence.watch(@domain, subscription("bob", "alice"))
      %{etag: etag}
    end

    # kamailio's column names, deliberately: one vocabulary for an operator who
    # migrated from it.
    test "list renders the presentity rows", %{etag: etag} do
      assert {:ok, [row]} = Presence.handle_control("list", %{"domain" => @domain})
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
