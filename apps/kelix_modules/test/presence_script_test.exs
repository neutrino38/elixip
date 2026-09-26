defmodule Kelix.PresenceScriptTest do
  # Drives the two reference presence scripts — the files an operator installs,
  # not fixtures written to pass — through spawned instances, with a mock dialog
  # capturing the SIP replies and the NOTIFYs:
  #   PUBLISH → 200 + SIP-ETag, refresh → new tag, stale tag → 412
  #   SUBSCRIBE → 200 + NOTIFY, one PUBLISH → one NOTIFY per watcher
  use ExUnit.Case, async: false

  alias Kelix.Mod.Presence

  @domain "example.com"
  @pass "secret"
  @package "presence"
  @presentity "bob"
  @watcher "alice"
  @pidf """
  <?xml version="1.0" encoding="UTF-8"?>
  <presence xmlns="urn:ietf:params:xml:ns:pidf" entity="sip:bob@example.com">
    <tuple id="t1"><status><basic>open</basic></status></tuple>
  </presence>
  """

  # The dialog, as far as these scripts use it: it answers requests, sends
  # NOTIFYs, and holds the subscription. Every call is reported to the test.
  defmodule MockDialog do
    use GenServer
    def start_link(test), do: GenServer.start_link(__MODULE__, test)
    def init(test), do: {:ok, test}

    def handle_call({:replyreq, req, code, reason, fields}, _from, test) do
      send(test, {:replied, code, reason, fields, req})
      {:reply, :ok, test}
    end

    # What SIP.DialogImpl fills in: the tags, the CSeqs and the route set.
    def handle_call({:set_subscription, sub}, _from, test) do
      sub = %SIP.Subscription{sub | callid: "call-1", to_tag: "totag", from_tag: "fromtag"}
      send(test, {:subscription, sub})
      {:reply, {:ok, sub}, test}
    end

    def handle_call({:send_notify, body, content_type}, _from, test) do
      send(test, {:notified, body, content_type})
      {:reply, :ok, test}
    end

    def handle_call({:end_subscription, reason}, _from, test) do
      send(test, {:subscription_ended, reason})
      {:reply, :ok, test}
    end

    def handle_call(_msg, _from, test), do: {:reply, :ok, test}
    def handle_info(_msg, test), do: {:noreply, test}
  end

  setup_all do
    %{
      subscribe:
        SIP.Scenario.Loader.load_file!(
          Path.expand("../../kelixip/scripts/presence-subscribe.exs", __DIR__)
        ),
      publish:
        SIP.Scenario.Loader.load_file!(
          Path.expand("../../kelixip/scripts/presence-publish.exs", __DIR__)
        ),
      rls:
        SIP.Scenario.Loader.load_file!(
          Path.expand("../../kelixip/scripts/presence-rls.exs", __DIR__)
        )
    }
  end

  setup do
    start_supervised!(Presence)
    SIP.EventPackage.register_builtins()

    # The "subscriber DB": bob and alice are provisioned, nobody else is. Both
    # questions are asked of it now — does this user exist, and is this digest
    # theirs — so it answers with the HA1 a real base would store.
    Application.put_env(:kelixip, :authdb_ha1_lookup, fn
      user, @domain when user in [@presentity, @watcher] -> {:ok, ha1(user)}
      _user, _realm -> :notfound
    end)

    on_exit(fn -> Application.delete_env(:kelixip, :authdb_ha1_lookup) end)
    :ok
  end

  defp subscribe(opts \\ []) do
    %{
      method: :SUBSCRIBE,
      from: %SIP.Uri{userpart: Keyword.get(opts, :watcher, @watcher), domain: @domain},
      to: %SIP.Uri{userpart: Keyword.get(opts, :user, @presentity), domain: @domain},
      ruri: %SIP.Uri{userpart: Keyword.get(opts, :user, @presentity), domain: @domain},
      event: Keyword.get(opts, :event, @package),
      expires: Keyword.get(opts, :expires, 3600),
      callid: "call-1"
    }
  end

  # `user` is the presentity (To / R-URI); `sender` is who is publishing it (From),
  # the same by default. They differ in exactly one case worth testing — a
  # provisioned user publishing about one who is not — and telling them apart is
  # what makes that 404 reachable now that the sender is authenticated.
  defp publish(opts \\ []) do
    user = Keyword.get(opts, :user, @presentity)

    base = %{
      method: :PUBLISH,
      from: %SIP.Uri{userpart: Keyword.get(opts, :sender, user), domain: @domain},
      to: %SIP.Uri{userpart: user, domain: @domain},
      ruri: %SIP.Uri{userpart: user, domain: @domain},
      event: @package,
      expires: Keyword.get(opts, :expires, 3600),
      callid: "call-2",
      body: Keyword.get(opts, :body, @pidf),
      contenttype: "application/pidf+xml"
    }

    case Keyword.get(opts, :etag) do
      nil -> base
      etag -> Map.put(base, :sipifmatch, etag)
    end
  end

  # ── the digest, done as a client does it ─────────────────────────────────────

  defp ha1(user), do: SIP.Auth.compute_ha1("MD5", user, @domain, @pass)

  # The sender of a request is its From: that is who the digest must prove, and
  # who `Kelix.Mod.AuthDb`'s identity check compares the credentials against for
  # anything that is not a REGISTER.
  defp sender(%{from: %SIP.Uri{userpart: user}}), do: user

  defp digest_auth(nonce, req) do
    user = sender(req)
    uri = "sip:#{@domain}"
    cnonce = "0a4f113b"
    nc = "00000001"

    response =
      SIP.Auth.compute_auth_response_from_ha1(
        "MD5",
        nonce,
        ha1(user),
        Atom.to_string(req.method),
        uri,
        %{"nc" => nc, "cnonce" => cnonce, "qop" => "auth"}
      )

    %{
      "username" => user,
      "realm" => @domain,
      "nonce" => nonce,
      "uri" => uri,
      "response" => response,
      "algorithm" => "MD5",
      "qop" => "auth",
      "nc" => nc,
      "cnonce" => cnonce
    }
  end

  # What a UA does with a request that is challenged: send it, read the nonce out
  # of the 401, replay it with the credentials. Every test below goes through this,
  # because every request the scripts serve does.
  defp submit(pid, dialog, req) do
    send(pid, {req.method, req, nil, dialog})
    assert_receive {:replied, 401, "Unauthorized", fields, _}, 1000
    nonce = fields[:wwwauthenticate]["nonce"]

    authenticated = Map.put(req, :authorization, digest_auth(nonce, req))
    send(pid, {req.method, authenticated, nil, dialog})
    authenticated
  end

  # The event package is injected by the router, exactly as the domain name is:
  # the script is the domain's, the package is the block's.
  defp spawn_instance(module, dialog, req) do
    {pid, _ref} =
      SIP.Scenario.Runner.spawn_uas_instance(module,
        dialog_pid: dialog,
        inbound_request: req,
        config_overrides: [domain: @domain, event_package: @package]
      )

    on_exit(fn -> send(pid, {:scenario_ctl, :shutdown, :test}) end)
    pid
  end

  describe "presence-publish.exs" do
    test "PUBLISH → 200 with the mandatory SIP-ETag and Expires", %{publish: module} do
      {:ok, dialog} = MockDialog.start_link(self())
      pid = spawn_instance(module, dialog, publish())

      submit(pid, dialog, publish())
      assert_receive {:replied, 200, _reason, fields, _req}, 1000

      # RFC 3903 §6 makes both mandatory on the 2xx: without the tag the
      # publisher can never refresh what it just published.
      assert is_binary(fields[:sipetag])
      assert fields[:expires] == 3600
      assert [%{presentity_uri: "sip:bob@example.com"}] = Presence.presentities(@domain)
    end

    test "a refresh presenting the granted tag is answered with a fresh one", %{publish: m} do
      {:ok, dialog} = MockDialog.start_link(self())
      pid = spawn_instance(m, dialog, publish())

      submit(pid, dialog, publish())
      assert_receive {:replied, 200, _, fields, _}, 1000
      first = fields[:sipetag]

      # a PUBLISH is one transaction: the refresh is served by its own instance
      pid2 = spawn_instance(m, dialog, publish(etag: first, body: nil))
      submit(pid2, dialog, publish(etag: first, body: nil))
      assert_receive {:replied, 200, _, refreshed, _}, 1000

      assert is_binary(refreshed[:sipetag])
      assert refreshed[:sipetag] != first
    end

    # The one answer only the holder of the tags can give — everything else
    # check_publish/1 refused before the script saw it.
    test "a tag this node does not hold is 412", %{publish: m} do
      {:ok, dialog} = MockDialog.start_link(self())
      req = publish(etag: "never-issued", body: nil)
      pid = spawn_instance(m, dialog, req)

      submit(pid, dialog, req)
      assert_receive {:replied, 412, _reason, _fields, _}, 1000
    end

    test "a removal is answered with no entity-tag", %{publish: m} do
      {:ok, dialog} = MockDialog.start_link(self())
      pid = spawn_instance(m, dialog, publish())
      submit(pid, dialog, publish())
      assert_receive {:replied, 200, _, fields, _}, 1000

      removal = publish(etag: fields[:sipetag], body: nil, expires: 0)
      pid2 = spawn_instance(m, dialog, removal)
      submit(pid2, dialog, removal)
      assert_receive {:replied, 200, _, removed, _}, 1000

      # There is no state left to name: a tag handed here would be presented on
      # the next refresh and answered 412 for ever.
      assert removed[:sipetag] == nil
      assert Presence.presentities(@domain) == []
    end

    # bob is provisioned and proves it; the presentity he publishes about is not.
    # The sender being someone else is the only way to reach this refusal now —
    # a PUBLISH whose sender is unknown never gets past the digest.
    test "a presentity nobody provisioned is 404", %{publish: m} do
      {:ok, dialog} = MockDialog.start_link(self())
      req = publish(user: "nobody", sender: @presentity)
      pid = spawn_instance(m, dialog, req)

      submit(pid, dialog, req)
      assert_receive {:replied, 404, _, _, _}, 1000
      assert Presence.presentities(@domain) == []
    end

    test "a store that is down answers 503 — never silence", %{publish: m} do
      {:ok, dialog} = MockDialog.start_link(self())
      pid = spawn_instance(m, dialog, publish())
      stop_supervised!(Presence)

      submit(pid, dialog, publish())
      assert_receive {:replied, 503, _, _, _}, 1000
    end
  end

  describe "presence-subscribe.exs" do
    test "SUBSCRIBE → 200 + NOTIFY carrying the state as it stands", %{subscribe: m} do
      {:ok, dialog} = MockDialog.start_link(self())
      pid = spawn_instance(m, dialog, subscribe())

      submit(pid, dialog, subscribe())
      assert_receive {:replied, 200, "OK", fields, _}, 1000

      # Allow-Events is the DOMAIN's, composed from its [[domain.presence]]
      # blocks — here none is served (no Kelix.Domains snapshot in this test), so
      # the header is absent rather than invented.
      assert fields[:expires] == 3600

      # Nothing published yet: the watcher is told the state is closed rather
      # than left waiting for a NOTIFY that would never come.
      assert_receive {:notified, body, "application/pidf+xml"}, 1000
      assert body =~ "closed"
    end

    test "one PUBLISH becomes one NOTIFY on the watcher's dialog", %{subscribe: sub, publish: pub} do
      {:ok, dialog} = MockDialog.start_link(self())
      watcher = spawn_instance(sub, dialog, subscribe())
      submit(watcher, dialog, subscribe())
      assert_receive {:replied, 200, "OK", _, _}, 1000
      assert_receive {:notified, _closed, _}, 1000

      publisher = spawn_instance(pub, dialog, publish())
      submit(publisher, dialog, publish())
      assert_receive {:replied, 200, _, _, _}, 1000

      # The fan-out reached the watcher INSTANCE, which sent the NOTIFY from its
      # own state (DESIGN-PRESENCE.md, decision 1).
      assert_receive {:notified, body, "application/pidf+xml"}, 1000
      assert body =~ "open"
    end

    test "a presentity nobody provisioned is 404", %{subscribe: m} do
      {:ok, dialog} = MockDialog.start_link(self())
      req = subscribe(user: "nobody")
      pid = spawn_instance(m, dialog, req)

      submit(pid, dialog, req)
      assert_receive {:replied, 404, _, _, _}, 1000
      assert Presence.watchers(@domain, "nobody") == []
    end

    # The store is what holds who watches what: with none, the watcher is told
    # the subscription cannot be served rather than being left subscribed to a
    # collection that will never push to it.
    test "a store that is down ends the subscription instead of half-serving it", %{subscribe: m} do
      {:ok, dialog} = MockDialog.start_link(self())
      pid = spawn_instance(m, dialog, subscribe())
      stop_supervised!(Presence)

      submit(pid, dialog, subscribe())
      assert_receive {:subscription_ended, :noresource}, 1000
    end

    test "the collection knows the watcher, under kamailio's names", %{subscribe: m} do
      {:ok, dialog} = MockDialog.start_link(self())
      pid = spawn_instance(m, dialog, subscribe())
      submit(pid, dialog, subscribe())
      assert_receive {:notified, _, _}, 1000

      assert [row] = Presence.watchers(@domain, @presentity)
      assert row.watcher == "sip:alice@example.com"
      assert row.presentity_uri == "sip:bob@example.com"
      assert row.status == "active"
      assert row.callid == "call-1"
    end

    # The dialog owns the end of a subscription: it sends the final NOTIFY and
    # hands the scenario exactly one of these. The script's part is to stop
    # watching — and the collection's monitor is the net under it.
    test "the subscription ending stops the watching", %{subscribe: m} do
      {:ok, dialog} = MockDialog.start_link(self())
      pid = spawn_instance(m, dialog, subscribe())
      submit(pid, dialog, subscribe())
      assert_receive {:notified, _, _}, 1000
      assert [_watching] = Presence.watchers(@domain, @presentity)

      send(pid, {:subscription_terminated, make_ref(), :timeout})
      assert eventually(fn -> Presence.watchers(@domain, @presentity) == [] end)
    end
  end

  # One SUBSCRIBE naming N buddies, answered by one NOTIFY carrying them all
  # (RFC 4662 with the list in the request, RFC 5367). The Request-URI names the
  # LIST — `sip:rls@…`, which is not a provisioned AOR — so everything this script
  # does differently follows from there.
  describe "presence-rls.exs" do
    @outsider "sip:900020123@visioassistance.net"

    setup do
      path =
        Path.join(
          System.tmp_dir!(),
          "presence_rls_script_#{System.unique_integer([:positive])}.toml"
        )

      File.write!(path, """
      [[domain]]
      name = "#{@domain}"

        [[domain.presence]]
        event-package = "presence"
        subscribe = "presence-rls.exs"
      """)

      :ok = Kelix.Domains.reload(path)

      on_exit(fn ->
        empty = Path.join(System.tmp_dir!(), "presence_rls_script_empty.toml")
        File.write!(empty, "")
        _ = Kelix.Domains.reload(empty)
        File.rm(path)
      end)

      :ok
    end

    test "SUBSCRIBE to a list → 200 + a NOTIFY naming every entry", %{rls: m} do
      {:ok, dialog} = MockDialog.start_link(self())
      req = list_subscribe([bob_uri(), @outsider])
      pid = spawn_instance(m, dialog, req)

      submit(pid, dialog, req)
      assert_receive {:replied, 200, "OK", _fields, _}, 1000
      assert_receive {:notified, body, content_type}, 1000

      assert content_type =~ ~s(multipart/related; type="application/rlmi+xml")
      {manifest, _parts} = read_list(body, content_type)

      assert manifest.uri == "sip:rls@#{@domain}"
      assert manifest.full_state == true

      assert Enum.map(manifest.resources, & &1.uri) |> Enum.sort() ==
               Enum.sort([bob_uri(), @outsider])
    end

    # A buddy on a domain this node does not serve. The entry is named all the
    # same, `terminated;reason=noresource`, so the watcher stops waiting for it.
    test "an entry this node does not serve is reported, not omitted", %{rls: m} do
      {:ok, dialog} = MockDialog.start_link(self())
      req = list_subscribe([@outsider])
      pid = spawn_instance(m, dialog, req)

      submit(pid, dialog, req)
      assert_receive {:notified, body, content_type}, 1000
      {manifest, parts} = read_list(body, content_type)

      assert [%SIP.Presence.Rlmi.Resource{instances: [instance]}] = manifest.resources
      assert instance.state == :terminated
      assert instance.reason == "noresource"
      # Nothing to point at, so no part beside the manifest.
      assert parts == []
    end

    # The fan-out reaches the watcher instance one buddy at a time; the script
    # collects them and sends ONE partial NOTIFY, which is what keeps a roster
    # coming online from producing a NOTIFY per buddy.
    test "a PUBLISH becomes one partial NOTIFY", %{rls: m, publish: pub} do
      {:ok, dialog} = MockDialog.start_link(self())
      req = list_subscribe([bob_uri(), @outsider])
      watcher = spawn_instance(m, dialog, req)

      submit(watcher, dialog, req)
      assert_receive {:notified, _full_state, _}, 1000

      publisher = spawn_instance(pub, dialog, publish())
      submit(publisher, dialog, publish())
      assert_receive {:replied, 200, _, _, _}, 1000

      assert_receive {:notified, body, content_type}, 2000
      {manifest, parts} = read_list(body, content_type)

      assert manifest.full_state == false
      assert manifest.version == 1
      # Only what changed, and its state travels with it.
      assert [%{uri: uri, instances: [%{state: :active, cid: cid}]}] = manifest.resources
      assert uri == bob_uri()
      assert [part] = parts
      assert part["Content-ID"] == "<" <> cid <> ">"
      assert part.data =~ "open"
    end

    test "the collection knows the watcher on the entry's own domain", %{rls: m} do
      {:ok, dialog} = MockDialog.start_link(self())
      req = list_subscribe([bob_uri(), @outsider])
      pid = spawn_instance(m, dialog, req)

      submit(pid, dialog, req)
      assert_receive {:notified, _, _}, 1000

      assert [row] = Presence.watchers(@domain, @presentity)
      assert row.presentity_uri == bob_uri()
      assert Presence.watchers("visioassistance.net", "900020123") == []
    end
  end

  # The digest itself, on both halves. It is what says WHO is watching and WHOSE
  # state is being published: a SUBSCRIBE names its watcher in a From anyone can
  # write, and an unauthenticated PUBLISH lets a stranger declare a user online.
  # A subscriber who publishes nothing: its registrations, reported by the
  # registrar script, open and close it — and each change reaches the watcher as
  # a NOTIFY.
  describe "registrar-presence.exs" do
    setup do
      Kelix.Test.Fixtures.serve_domains("""
      [[domain]]
      name = "example.com"

        [domain.registrar]
        script = "registrar-presence.exs"
        min_expires = 1

        [[domain.presence]]
        event-package = "presence"
        subscribe = "presence-subscribe.exs"
      """)

      start_supervised!(Kelix.Mod.Registrar)

      %{
        registrar:
          SIP.Scenario.Loader.load_file!(
            Path.expand("../../kelixip/scripts/registrar-presence.exs", __DIR__)
          )
      }
    end

    defp register(host, opts \\ []) do
      %{
        method: :REGISTER,
        from: %SIP.Uri{userpart: @presentity, domain: @domain},
        to: %SIP.Uri{userpart: @presentity, domain: @domain},
        ruri: %SIP.Uri{
          userpart: @presentity,
          domain: @domain,
          destip: {1, 2, 3, 4},
          destport: 5060,
          destproto: "UDP"
        },
        contact: %SIP.Uri{userpart: @presentity, domain: host, port: 5060},
        expires: Keyword.get(opts, :expires, 3600),
        callid: "reg-" <> host
      }
    end

    # One device: its REGISTER dialog and its registrar-presence instance.
    defp registered_device(module, host, opts \\ []) do
      {:ok, dialog} = MockDialog.start_link(self())

      {pid, _ref} =
        SIP.Scenario.Runner.spawn_uas_instance(module,
          dialog_pid: dialog,
          inbound_request: register(host, opts),
          config_overrides: [domain: @domain]
        )

      on_exit(fn -> send(pid, {:scenario_ctl, :shutdown, :test}) end)

      submit(pid, dialog, register(host, opts))
      assert_receive {:replied, 200, "OK", _, _}, 1000
      %{pid: pid, dialog: dialog, host: host}
    end

    defp watch_bob(module) do
      {:ok, dialog} = MockDialog.start_link(self())
      watcher = spawn_instance(module, dialog, subscribe())
      submit(watcher, dialog, subscribe())
      assert_receive {:replied, 200, "OK", _, _}, 1000
      assert_receive {:notified, body, "application/pidf+xml"}, 1000
      body
    end

    test "registering NOTIFYs open, the connection dropping NOTIFYs closed",
         %{subscribe: sub, registrar: reg} do
      assert watch_bob(sub) =~ "closed"

      phone = registered_device(reg, "10.0.0.9")
      assert_receive {:notified, body, "application/pidf+xml"}, 1000
      assert body =~ "<basic>open</basic>"

      send(phone.pid, {:dialog_terminated, phone.dialog, :transport_down})
      assert_receive {:notified, body, "application/pidf+xml"}, 1000
      assert body =~ "<basic>closed</basic>"
    end

    test "a registration that was not refreshed NOTIFYs closed",
         %{subscribe: sub, registrar: reg} do
      phone = registered_device(reg, "10.0.0.9")
      assert watch_bob(sub) =~ "<basic>open</basic>"

      # what the dialog's :registerexpire timer ends it with
      send(phone.pid, {:dialog_terminated, phone.dialog, :normal})
      assert_receive {:notified, body, "application/pidf+xml"}, 1000
      assert body =~ "<basic>closed</basic>"
    end

    # The mock dialog has no lifetime timer: what ends the wait is the
    # registration lapsing in the registrar, which is the one clock that counts.
    test "a registration nobody refreshes NOTIFYs closed when it lapses",
         %{subscribe: sub, registrar: reg} do
      _phone = registered_device(reg, "10.0.0.9", expires: 2)
      assert watch_bob(sub) =~ "<basic>open</basic>"

      assert_receive {:notified, body, "application/pidf+xml"}, 3_500
      assert body =~ "<basic>closed</basic>"
    end

    # A refused refresh changes no binding. The session must outlive it — the
    # idle 5 s of a session never registered would end it first, and nothing
    # would then report the lapse.
    test "a refused refresh keeps the session, which reports the lapse",
         %{subscribe: sub, registrar: reg} do
      phone = registered_device(reg, "10.0.0.9", expires: 3)
      assert watch_bob(sub) =~ "<basic>open</basic>"

      # a wildcard without Expires: 0 is a 400, and changes nothing
      bad = %{register("10.0.0.9") | contact: :*}
      submit(phone.pid, phone.dialog, bad)
      assert_receive {:replied, 400, _, _, _}, 1000
      assert [_still] = Kelix.Mod.Registrar.bindings(@domain, @presentity)

      assert_receive {:notified, body, "application/pidf+xml"}, 4_000
      assert body =~ "<basic>closed</basic>"
    end

    test "one device leaving keeps the subscriber open while another is registered",
         %{subscribe: sub, registrar: reg} do
      phone = registered_device(reg, "10.0.0.9")
      _softphone = registered_device(reg, "10.0.0.10")
      assert watch_bob(sub) =~ "<basic>open</basic>"

      # the phone un-registers its own contact, then its dialog ends
      submit(phone.pid, phone.dialog, register("10.0.0.9", expires: 0))
      assert_receive {:replied, 200, "OK", _, _}, 1000
      send(phone.pid, {:dialog_terminated, phone.dialog, :normal})
      refute_receive {:notified, _body, _}, 300

      assert [%{contact: %SIP.Uri{domain: "10.0.0.10"}}] =
               Kelix.Mod.Registrar.bindings(@domain, @presentity)
    end
  end

  describe "authentication" do
    test "an unauthenticated SUBSCRIBE is challenged, and nothing is watched", %{subscribe: m} do
      {:ok, dialog} = MockDialog.start_link(self())
      pid = spawn_instance(m, dialog, subscribe())

      send(pid, {:SUBSCRIBE, subscribe(), nil, dialog})

      # 401, not 407: the presence server answers for itself, not as a proxy.
      assert_receive {:replied, 401, "Unauthorized", fields, _}, 1000
      params = fields[:wwwauthenticate]
      assert params["realm"] == @domain
      assert params["qop"] == "auth" and params["algorithm"] == "MD5"
      assert Presence.watchers(@domain, @presentity) == []
    end

    test "an unauthenticated PUBLISH is challenged, and nothing is published", %{publish: m} do
      {:ok, dialog} = MockDialog.start_link(self())
      pid = spawn_instance(m, dialog, publish())

      send(pid, {:PUBLISH, publish(), nil, dialog})

      assert_receive {:replied, 401, "Unauthorized", fields, _}, 1000
      assert fields[:wwwauthenticate]["realm"] == @domain
      assert Presence.presentities(@domain) == []
    end

    # The whole point of the challenge: a watcher who cannot prove who they are
    # reads nobody's state. The block answers the refusal and keeps waiting, so a
    # client that fixes its password can say so.
    test "a SUBSCRIBE with a wrong password is refused", %{subscribe: m} do
      {:ok, dialog} = MockDialog.start_link(self())
      pid = spawn_instance(m, dialog, subscribe())

      send(pid, {:SUBSCRIBE, subscribe(), nil, dialog})
      assert_receive {:replied, 401, _, fields, _}, 1000
      nonce = fields[:wwwauthenticate]["nonce"]

      wrong = Map.put(digest_auth(nonce, subscribe()), "response", String.duplicate("f", 32))
      send(pid, {:SUBSCRIBE, Map.put(subscribe(), :authorization, wrong), nil, dialog})

      assert_receive {:replied, code, _, _, _}, 1000
      assert code in [401, 403]
      assert Presence.watchers(@domain, @presentity) == []
    end

    # A watcher stays authenticated for as long as it keeps proving it: the refresh
    # is a SUBSCRIBE of its own, challenged like the first one.
    test "a refresh is authenticated too", %{subscribe: m} do
      {:ok, dialog} = MockDialog.start_link(self())
      pid = spawn_instance(m, dialog, subscribe())

      submit(pid, dialog, subscribe())
      assert_receive {:replied, 200, "OK", _, _}, 1000
      assert_receive {:notified, _, _}, 1000

      submit(pid, dialog, subscribe(expires: 1800))
      assert_receive {:replied, 200, "OK", fields, _}, 1000
      assert fields[:expires] == 1800
    end
  end

  # ── the list subscription's own fixtures ─────────────────────────────────────

  defp bob_uri, do: "sip:#{@presentity}@#{@domain}"

  # The SUBSCRIBE a client sends to open its buddy list: the list in the body,
  # the Request-URI naming the list and not a presentity.
  defp list_subscribe(entries) do
    body =
      ~s(<?xml version="1.0" encoding="UTF-8"?>\n) <>
        ~s(<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists">\n <list>\n) <>
        Enum.map_join(entries, "", fn uri -> ~s(  <entry uri="#{uri}"/>\n) end) <>
        " </list>\n</resource-lists>\n"

    %{
      "Require" => "recipient-list-subscribe",
      "Content-Disposition" => "recipient-list",
      method: :SUBSCRIBE,
      from: %SIP.Uri{userpart: @watcher, domain: @domain},
      to: %SIP.Uri{userpart: "rls", domain: @domain},
      ruri: %SIP.Uri{userpart: "rls", domain: @domain},
      event: @package,
      accept: "multipart/related, application/pidf+xml, application/rlmi+xml",
      supported: ["eventlist"],
      expires: 3600,
      callid: "call-1",
      body: body,
      contenttype: "application/resource-lists+xml"
    }
  end

  # `send_notify` is handed the composed PARTS, not the octets: the dialog is what
  # serializes them, and here the dialog is a mock.
  defp read_list(parts, content_type) when is_list(parts) do
    assert content_type =~ "multipart/related"
    [root | rest] = parts
    assert root.contenttype == "application/rlmi+xml"
    {:ok, manifest} = SIP.Presence.Rlmi.parse(root.data)
    {manifest, rest}
  end

  defp eventually(fun, attempts \\ 20) do
    cond do
      fun.() -> true
      attempts == 0 -> false
      true -> Process.sleep(10) && eventually(fun, attempts - 1)
    end
  end
end
