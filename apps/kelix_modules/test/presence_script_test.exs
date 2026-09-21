defmodule Kelix.PresenceScriptTest do
  # Drives the two reference presence scripts — the files an operator installs,
  # not fixtures written to pass — through spawned instances, with a mock dialog
  # capturing the SIP replies and the NOTIFYs:
  #   PUBLISH → 200 + SIP-ETag, refresh → new tag, stale tag → 412
  #   SUBSCRIBE → 200 + NOTIFY, one PUBLISH → one NOTIFY per watcher
  use ExUnit.Case, async: false

  alias Kelix.Mod.Presence

  @domain "example.com"
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
        )
    }
  end

  setup do
    start_supervised!(Presence)
    SIP.EventPackage.register_builtins()

    # The "subscriber DB": bob and alice are provisioned, nobody else is. What the
    # scripts ask of it is existence, not a secret.
    Application.put_env(:kelixip, :authdb_ha1_lookup, fn
      user, @domain when user in [@presentity, @watcher] -> {:ok, String.duplicate("a", 32)}
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

  defp publish(opts \\ []) do
    base = %{
      method: :PUBLISH,
      from: %SIP.Uri{userpart: Keyword.get(opts, :user, @presentity), domain: @domain},
      to: %SIP.Uri{userpart: Keyword.get(opts, :user, @presentity), domain: @domain},
      ruri: %SIP.Uri{userpart: Keyword.get(opts, :user, @presentity), domain: @domain},
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

      send(pid, {:PUBLISH, publish(), nil, dialog})
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

      send(pid, {:PUBLISH, publish(), nil, dialog})
      assert_receive {:replied, 200, _, fields, _}, 1000
      first = fields[:sipetag]

      # a PUBLISH is one transaction: the refresh is served by its own instance
      pid2 = spawn_instance(m, dialog, publish(etag: first, body: nil))
      send(pid2, {:PUBLISH, publish(etag: first, body: nil), nil, dialog})
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

      send(pid, {:PUBLISH, req, nil, dialog})
      assert_receive {:replied, 412, _reason, _fields, _}, 1000
    end

    test "a removal is answered with no entity-tag", %{publish: m} do
      {:ok, dialog} = MockDialog.start_link(self())
      pid = spawn_instance(m, dialog, publish())
      send(pid, {:PUBLISH, publish(), nil, dialog})
      assert_receive {:replied, 200, _, fields, _}, 1000

      removal = publish(etag: fields[:sipetag], body: nil, expires: 0)
      pid2 = spawn_instance(m, dialog, removal)
      send(pid2, {:PUBLISH, removal, nil, dialog})
      assert_receive {:replied, 200, _, removed, _}, 1000

      # There is no state left to name: a tag handed here would be presented on
      # the next refresh and answered 412 for ever.
      assert removed[:sipetag] == nil
      assert Presence.presentities(@domain) == []
    end

    test "a presentity nobody provisioned is 404", %{publish: m} do
      {:ok, dialog} = MockDialog.start_link(self())
      req = publish(user: "nobody")
      pid = spawn_instance(m, dialog, req)

      send(pid, {:PUBLISH, req, nil, dialog})
      assert_receive {:replied, 404, _, _, _}, 1000
      assert Presence.presentities(@domain) == []
    end

    test "a store that is down answers 503 — never silence", %{publish: m} do
      {:ok, dialog} = MockDialog.start_link(self())
      pid = spawn_instance(m, dialog, publish())
      stop_supervised!(Presence)

      send(pid, {:PUBLISH, publish(), nil, dialog})
      assert_receive {:replied, 503, _, _, _}, 1000
    end
  end

  describe "presence-subscribe.exs" do
    test "SUBSCRIBE → 200 + NOTIFY carrying the state as it stands", %{subscribe: m} do
      {:ok, dialog} = MockDialog.start_link(self())
      pid = spawn_instance(m, dialog, subscribe())

      send(pid, {:SUBSCRIBE, subscribe(), nil, dialog})
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
      send(watcher, {:SUBSCRIBE, subscribe(), nil, dialog})
      assert_receive {:replied, 200, "OK", _, _}, 1000
      assert_receive {:notified, _closed, _}, 1000

      publisher = spawn_instance(pub, dialog, publish())
      send(publisher, {:PUBLISH, publish(), nil, dialog})
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

      send(pid, {:SUBSCRIBE, req, nil, dialog})
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

      send(pid, {:SUBSCRIBE, subscribe(), nil, dialog})
      assert_receive {:subscription_ended, :noresource}, 1000
    end

    test "the collection knows the watcher, under kamailio's names", %{subscribe: m} do
      {:ok, dialog} = MockDialog.start_link(self())
      pid = spawn_instance(m, dialog, subscribe())
      send(pid, {:SUBSCRIBE, subscribe(), nil, dialog})
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
      send(pid, {:SUBSCRIBE, subscribe(), nil, dialog})
      assert_receive {:notified, _, _}, 1000
      assert [_watching] = Presence.watchers(@domain, @presentity)

      send(pid, {:subscription_terminated, make_ref(), :timeout})
      assert eventually(fn -> Presence.watchers(@domain, @presentity) == [] end)
    end
  end

  defp eventually(fun, attempts \\ 20) do
    cond do
      fun.() -> true
      attempts == 0 -> false
      true -> Process.sleep(10) && eventually(fun, attempts - 1)
    end
  end
end
