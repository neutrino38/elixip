defmodule SIP.Test.SubscriptionLayer do
  # The event-package table lives in :persistent_term and the presence processing
  # module in a node-wide Agent: two of these running at once would decide each
  # other's outcome.
  use ExUnit.Case, async: false

  @moduledoc """
  The subscription layer (RFC 6665) over the mockup transport, both halves of it:
  a notifier answering SUBSCRIBEs and a watcher living with the NOTIFYs that come
  back.

  Everything here runs through `SIP.Test.EventPackages.Dummy`, whose document is a
  line of text — no PIDF, no XML parser, no `presence` package. That is what the
  behaviour is *for* (docs/design/presence-basic-plan.md, P2): when
  `SIP.EventPackage.Presence` is substituted for it and this suite still passes,
  that is the proof the behaviour is a behaviour and not a hole shaped like one
  implementation.
  """

  alias SIP.Test.EventPackages.Dummy
  alias SIP.Test.Peers.NotifyingUAS
  alias SIP.Test.Transport.Mockup

  require Logger

  # ── The notifier this suite runs ────────────────────────────────────────────

  defmodule Fixture.Notifier do
    @moduledoc false
    use SIP.Scenario
    uas(:presence)
    config(domain: "unit.test")

    state initial_state do
      goto(authorize)
    end

    # The whole negotiation is `accept_subscription/1`'s: 489, 406 and 423 have
    # already gone out by the time it answers {:error, code}, which is what a
    # script never having to read `Event` looks like.
    state authorize do
      on_events do
        {:SUBSCRIBE, _req, _t, _d} ->
          case accept_subscription(package: "dummy", expires: appdata_get(:granted)) do
            {:ok, _sub} ->
              notify("open")
              goto(subscribed, "200 + NOTIFY")

            {:error, code} ->
              goto(refused, "#{code}")
          end
      after
        5_000 -> scenario_failure("no SUBSCRIBE received")
      end
    end

    # A refusal does not end the instance: the dialog is still there, and a
    # watcher that was answered 423 asks again with a longer lifetime.
    state refused do
      on_events do
        {:SUBSCRIBE, _req, _t, _d} -> goto(authorize, "retry")
        {:subscription_terminated, _ref, reason} -> scenario_success("#{reason}")
        {:dialog_terminated, _d, _r} -> scenario_success("dialog gone")
      after
        10_000 -> scenario_success("nothing more came")
      end
    end

    state subscribed do
      on_events do
        # A refresh on the same dialog: negotiated again, granted again.
        {:SUBSCRIBE, _req, _t, _d} ->
          case accept_subscription(package: "dummy", expires: appdata_get(:granted)) do
            {:ok, _sub} ->
              notify("open")
              stay("refresh")

            {:error, code} ->
              stay("#{code}")
          end

        {:subscription_terminated, _ref, reason} ->
          probe(:terminated, reason)
          scenario_success("#{reason}")

        {:dialog_terminated, _d, _r} ->
          scenario_success("dialog gone")
      after
        20_000 -> scenario_failure("the subscription never ended")
      end
    end

    defp probe(tag, payload) do
      case Process.whereis(:subscription_test) do
        nil -> :ok
        pid -> send(pid, {tag, payload})
      end
    end
  end

  # ── The watcher this suite runs ─────────────────────────────────────────────

  defmodule Fixture.Watcher do
    @moduledoc false
    use SIP.Scenario
    config(username: "alice", authusername: "alice", domain: "unit.test", passwd: "secret")

    state initial_state do
      send_SUBSCRIBE(appdata_get(:target), "dummy", expires: appdata_get(:expires) || 60)
      goto(wait_200)
    end

    state wait_200 do
      on_events do
        {100, _rsp, _t, _d} ->
          stay("100 Trying")

        # The NOTIFY may arrive BEFORE the 200 that belongs to it (RFC 6665
        # §4.2.1.2 has the notifier send the 2xx first, and UDP reorders anyway).
        # The dialog has already answered it 200 by the time we see it.
        {:NOTIFY, req, _t, _d} ->
          probe(:notify, req)
          stay("early NOTIFY")

        {200, rsp, t, _d} ->
          process_sip_reply(rsp, t)
          probe(:dialog, sip_ctx.dialogpid)
          probe(:subscribed, current_subscription())
          goto(subscribed, "200 OK")

        {code, _rsp, _t, _d} when code in 400..699 ->
          probe(:refused, code)
          scenario_failure("SUBSCRIBE refused with #{code}")
      after
        5_000 -> scenario_failure("no answer to the SUBSCRIBE")
      end
    end

    state subscribed do
      on_events do
        {:NOTIFY, req, _t, _d} ->
          probe(:notify, req)
          stay("NOTIFY")

        # The refresh the dialog sent on its own behalf comes back here.
        {200, rsp, t, _d} ->
          process_sip_reply(rsp, t)
          stay("refresh accepted")

        {:subscription_terminated, _ref, reason} ->
          probe(:terminated, reason)
          scenario_success("#{reason}")

        {:dialog_terminated, _d, _r} ->
          stay("dialog gone")
      after
        20_000 -> scenario_failure("the subscription never ended")
      end
    end

    defp probe(tag, payload) do
      case Process.whereis(:subscription_test) do
        nil -> :ok
        pid -> send(pid, {tag, payload})
      end
    end
  end

  defmodule Fixture.WatcherPeer do
    @moduledoc """
    The far end of a notifier: it answers the NOTIFYs 200 and nothing else.

    Not a detail. `SIP.Test.Peers.Passive` answers nothing, so the NICT carrying
    each NOTIFY retransmits it every T1..T2 — and a test waiting for the NEXT
    NOTIFY is handed a copy of the last one instead, which passes for whatever it
    was asserting.
    """
    use SIP.Test.Peer

    @impl true
    def on_request(%{method: :NOTIFY} = req, state) do
      {[reply(req, 200, "OK", [], 10)], state}
    end

    def on_request(req, state), do: default_request(req, state)
  end

  # ── The presence processing module ──────────────────────────────────────────

  defmodule Fixture.PresenceUAS do
    @moduledoc """
    One notifier instance per inbound SUBSCRIBE dialog — what `Elixip.ScenarioUAS`
    will do for `uas :presence` in P6, minus the quota and the counters this suite
    has no use for.
    """
    @behaviour SIP.Session.Presence

    @impl true
    def on_new_subscribe(dialog_pid, req, _transaction_id) do
      {module, appdata} = :persistent_term.get({__MODULE__, :scenario})

      {pid, _ref} =
        SIP.Scenario.Runner.spawn_uas_instance(module,
          dialog_pid: dialog_pid,
          inbound_request: req,
          appdata: appdata
        )

      {:accept, pid}
    end

    @impl true
    def on_new_publish(_dialog_pid, _req, _transaction_id),
      do: {:reject, 501, "Not Implemented"}

    def serve(module, appdata \\ %{}) do
      :persistent_term.put({__MODULE__, :scenario}, {module, appdata})
      :ok = SIP.Session.ConfigRegistry.set_presence_processing_module(__MODULE__)
    end
  end

  # ── Fixtures ────────────────────────────────────────────────────────────────

  setup_all do
    {:ok, _} = SIP.Session.ConfigRegistry.start()
    SIP.Test.AppEnv.preserve_proxy()
    Application.put_env(:elixip2, :proxyusesrv, false)

    :ok = SIP.EventPackage.register(Dummy, origin: :builtin)
    on_exit(fn -> SIP.EventPackage.unregister(Dummy) end)
    :ok
  end

  setup do
    # The scenarios report to this process by name: they run in processes the
    # dialog layer spawned, so there is no pid to pass them.
    Process.unregister(:subscription_test)
    Process.register(self(), :subscription_test)
    :ok
  catch
    :error, :badarg ->
      Process.register(self(), :subscription_test)
      :ok
  end

  # ── The notifier half ───────────────────────────────────────────────────────

  describe "the notifier" do
    test "accepts a SUBSCRIBE and sends the state in the first NOTIFY" do
      Fixture.PresenceUAS.serve(Fixture.Notifier)
      tp = attach("notifier-accept")

      req = subscribe(instance: "notifier-accept", expires: 60)
      cid = req.callid
      Mockup.inject(tp, req)

      assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid} = rsp}}, 2_000
      # What the notifier GRANTED, which is what the watcher must arm its refresh
      # on — not what it asked for.
      assert SIP.Msg.Ops.expires_header(rsp) == 60

      assert_receive {:sip_mockup, {:request_sent, :NOTIFY, %{callid: ^cid} = notify}}, 2_000
      assert {:active, params} = SIP.Msg.Ops.subscription_state(notify)
      assert params["expires"] <= 60
      assert {"dummy", nil} = SIP.Msg.Ops.event_package(notify)
      assert body_of(notify) == "open"
    end

    test "refuses a lifetime below the package minimum with 423 and a Min-Expires" do
      Fixture.PresenceUAS.serve(Fixture.Notifier)
      tp = attach("notifier-423")

      # The dummy package's min_expires is 10.
      req = subscribe(instance: "notifier-423", expires: 5)
      cid = req.callid
      Mockup.inject(tp, req)

      assert_receive {:sip_mockup, {:response_sent, 423, %{callid: ^cid} = rsp}}, 2_000
      # Mandatory: without it the watcher has no way to know what to ask for and
      # simply gives up (the rule RFC 3261 §10.3 step 7 already imposes on a
      # REGISTER).
      assert rsp["Min-Expires"] == "10" or Map.get(rsp, "Min-Expires") == "10"
    end

    test "refuses an Accept the package cannot satisfy with 406" do
      Fixture.PresenceUAS.serve(Fixture.Notifier)
      tp = attach("notifier-406")

      req = subscribe(instance: "notifier-406", accept: "application/pidf+xml")
      cid = req.callid
      Mockup.inject(tp, req)

      assert_receive {:sip_mockup, {:response_sent, 406, %{callid: ^cid}}}, 2_000
    end

    test "refuses an event package the node does not know with 489" do
      Fixture.PresenceUAS.serve(Fixture.Notifier)
      tp = attach("notifier-489")

      req = subscribe(instance: "notifier-489", event: "nosuchpackage")
      cid = req.callid
      Mockup.inject(tp, req)

      assert_receive {:sip_mockup, {:response_sent, 489, %{callid: ^cid}}}, 2_000
    end

    test "refuses a package it does not serve with 489, without the script looking" do
      # `dialog` is a perfectly good package name; this scenario simply does not
      # serve it, and says so before any of its own code runs.
      Fixture.PresenceUAS.serve(Fixture.Notifier)
      tp = attach("notifier-489-other")

      req = subscribe(instance: "notifier-489-other", event: "dialog")
      cid = req.callid
      Mockup.inject(tp, req)

      assert_receive {:sip_mockup, {:response_sent, 489, %{callid: ^cid}}}, 2_000
    end

    test "accepts a refresh on the same dialog and answers it 200" do
      Fixture.PresenceUAS.serve(Fixture.Notifier)
      tp = attach("notifier-refresh")

      req = subscribe(instance: "notifier-refresh", expires: 60)
      cid = req.callid
      Mockup.inject(tp, req)
      assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid}}}, 2_000
      assert_receive {:sip_mockup, {:request_sent, :NOTIFY, %{callid: ^cid}}}, 2_000

      # The refresh: same Call-ID and same From tag, one CSeq further on. It is
      # what `auto_store/2` must stash, or the scenario would re-negotiate the
      # request that created it.
      Mockup.inject(tp, refresh(req, 2))
      assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid}}}, 2_000
      assert_receive {:sip_mockup, {:request_sent, :NOTIFY, %{callid: ^cid}}}, 2_000
    end

    test "refuses a second event package on an established dialog with 489" do
      Fixture.PresenceUAS.serve(Fixture.Notifier)
      tp = attach("notifier-second-package")

      req = subscribe(instance: "notifier-second-package", expires: 60)
      cid = req.callid
      Mockup.inject(tp, req)
      assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid}}}, 2_000

      # v1 refuses it (design decision 3). The key already carries the package, so
      # allowing it later widens nothing.
      Mockup.inject(tp, refresh(req, 2) |> Map.put(:event, "dialog"))
      assert_receive {:sip_mockup, {:response_sent, 489, %{callid: ^cid}}}, 2_000
    end

    test "sends the final NOTIFY itself when the granted lifetime lapses" do
      # One second, granted by the scenario over what the watcher asked for. The
      # script says nothing about the end of the subscription — that is the point.
      Fixture.PresenceUAS.serve(Fixture.Notifier, %{granted: 1})
      tp = attach("notifier-expiry")

      req = subscribe(instance: "notifier-expiry", expires: 60)
      cid = req.callid
      Mockup.inject(tp, req)

      assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid} = rsp}}, 2_000
      assert SIP.Msg.Ops.expires_header(rsp) == 1
      assert_receive {:sip_mockup, {:request_sent, :NOTIFY, %{callid: ^cid}}}, 2_000

      assert %{"reason" => "timeout"} = await_final_notify(cid)

      # …and exactly one termination event, which the scenario echoed to us.
      assert_receive {:terminated, :timeout}, 2_000
      refute_receive {:terminated, _reason}, 500
    end
  end

  # ── The watcher half ────────────────────────────────────────────────────────

  describe "the watcher" do
    test "records what the notifier granted and answers its NOTIFYs by itself" do
      tp = watcher_transport("watcher-basic", granted: 30)
      run_watcher("sip:bob@unit.test;unittest=watcher-basic", expires: 60)

      assert_receive {:sip_mockup, {:request_sent, :SUBSCRIBE, sub}}, 2_000
      assert {"dummy", nil} = SIP.Msg.Ops.event_package(sub)
      # The Accept advertised is the package's own list, asked of the package.
      assert SIP.Msg.Ops.accepted_content_types(sub) == ["text/plain"]

      assert_receive {:subscribed, %SIP.Subscription{} = subscription}, 2_000
      assert subscription.event == "dummy"
      # `expires` is ABSOLUTE, kamailio's convention, so what was granted is read
      # back through remaining/1 and never by subtracting by hand somewhere else.
      assert SIP.Subscription.remaining(subscription) in 28..30
      assert SIP.Subscription.status(subscription) == :pending

      # The first NOTIFY: answered 200 by the dialog, and surfaced to the scenario.
      assert_receive {:sip_mockup, {:response_sent, 200, %{method: false}}}, 2_000
      assert_receive {:notify, notify}, 2_000
      assert body_of(notify) == "open"

      NotifyingUAS.send_notify(tp, "closed")
      assert_receive {:notify, second}, 2_000
      assert body_of(second) == "closed"
    end

    test "answers a NOTIFY that overtook its own 200, instead of 481" do
      # The race RFC 6665 §4.2.1.2 forbids and UDP produces anyway. Matched on
      # Call-ID plus our own tag, the dialog adopts the tag the NOTIFY carries.
      _tp = watcher_transport("watcher-race", notify_first: true, reply_delay: 300)
      run_watcher("sip:bob@unit.test;unittest=watcher-race", expires: 60)

      assert_receive {:sip_mockup, {:request_sent, :SUBSCRIBE, _sub}}, 2_000
      assert_receive {:sip_mockup, {:response_sent, code, %{method: false}}}, 3_000
      assert code == 200, "a NOTIFY overtaking its 200 was answered #{code}"
      assert_receive {:notify, _notify}, 2_000
      assert_receive {:subscribed, %SIP.Subscription{}}, 3_000
    end

    test "surfaces exactly one termination when the notifier ends the subscription" do
      tp = watcher_transport("watcher-terminated", granted: 30)
      run_watcher("sip:bob@unit.test;unittest=watcher-terminated", expires: 60)

      assert_receive {:subscribed, %SIP.Subscription{}}, 2_000
      assert_receive {:notify, _first}, 2_000

      NotifyingUAS.terminate(tp, :noresource)

      assert_receive {:terminated, :noresource}, 2_000
      refute_receive {:terminated, _reason}, 500
    end

    test "surfaces one termination when the dialog carrying the subscription dies" do
      _tp = watcher_transport("watcher-dialog-death", granted: 30)
      run_watcher("sip:bob@unit.test;unittest=watcher-dialog-death", expires: 60)

      assert_receive {:dialog, dialog_pid}, 2_000
      assert_receive {:subscribed, %SIP.Subscription{}}, 2_000

      # Nothing in RFC 6665 ends a subscription this way; the application is owed
      # its one event all the same, with `invariant` — §4.1.3's reason for a
      # subscription ended by something other than its own lifecycle.
      SIP.Dialog.terminate(dialog_pid, :transport_down)

      assert_receive {:terminated, :invariant}, 2_000
      refute_receive {:terminated, _reason}, 500
    end
  end

  # ── Helpers ─────────────────────────────────────────────────────────────────

  # A mockup instance of this test's own, with the probe pointed at us and a peer
  # that answers nothing: a named instance per test, so two of them never drive
  # each other (Mockup.select_instance/1).
  defp attach(instance) do
    {:ok, uri} = SIP.Uri.parse("sip:bob@unit.test")

    routed =
      SIP.Transport.Selector.select_transport(SIP.Uri.set_uri_param(uri, "unittest", instance))

    :ok = Mockup.attach_probe(routed.tp_pid)
    :ok = Mockup.set_peer(routed.tp_pid, Fixture.WatcherPeer)
    routed.tp_pid
  end

  defp watcher_transport(instance, peer_opts) do
    tp = attach(instance)
    :ok = Mockup.set_peer(tp, NotifyingUAS, peer_opts)
    tp
  end

  defp run_watcher(target, opts) do
    test_pid = self()

    spawn(fn ->
      send(
        test_pid,
        {:watcher_done,
         SIP.Scenario.Runner.run_instance(Fixture.Watcher,
           appdata: %{target: target, expires: Keyword.get(opts, :expires, 60)}
         )}
      )
    end)
  end

  # The NOTIFY that ends the subscription, told from the ones before it by what it
  # says rather than by how many came first: a NOTIFY whose 200 is late is
  # retransmitted, and counting them counts copies.
  defp await_final_notify(callid, timeout \\ 6_000) do
    receive do
      {:sip_mockup, {:request_sent, :NOTIFY, %{callid: ^callid} = msg}} ->
        case SIP.Msg.Ops.subscription_state(msg) do
          {:terminated, params} -> params
          _still_active -> await_final_notify(callid, timeout)
        end
    after
      timeout -> flunk("no terminated NOTIFY for call #{callid}")
    end
  end

  # A SUBSCRIBE as it comes off the wire.
  defp subscribe(opts) do
    branch = SIP.Msg.Ops.generate_branch_value()
    callid = Keyword.get(opts, :callid, SIP.Msg.Ops.generate_from_or_to_tag())
    fromtag = Keyword.get(opts, :fromtag, SIP.Msg.Ops.generate_from_or_to_tag())

    {:ok, ruri} = SIP.Uri.parse("sip:bob@unit.test")
    ruri = SIP.Uri.set_uri_param(ruri, "unittest", Keyword.fetch!(opts, :instance))

    from =
      SIP.Uri.set_header_param(
        %SIP.Uri{scheme: "sip:", userpart: "alice", domain: "unit.test"},
        "tag",
        fromtag
      )

    %{
      "Max-Forwards" => "70",
      method: :SUBSCRIBE,
      ruri: ruri,
      from: from,
      to: %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "unit.test"},
      contact: %SIP.Uri{scheme: "sip:", userpart: "alice", domain: "82.184.8.2", port: 53_936},
      event: Keyword.get(opts, :event, "dummy"),
      accept: Keyword.get(opts, :accept, "text/plain"),
      expires: Keyword.get(opts, :expires, 60),
      callid: callid,
      cseq: [Keyword.get(opts, :cseq, 1), :SUBSCRIBE],
      transid: branch,
      via: ["SIP/2.0/UDP 82.184.8.2:53936;branch=#{branch}"],
      useragent: "Mockup-watcher",
      contentlength: 0
    }
  end

  # The same subscription, asked for again: same Call-ID and From tag, next CSeq,
  # a transaction of its own.
  defp refresh(req, cseq) do
    branch = SIP.Msg.Ops.generate_branch_value()

    %{
      req
      | cseq: [cseq, :SUBSCRIBE],
        transid: branch,
        via: ["SIP/2.0/UDP 82.184.8.2:53936;branch=#{branch}"]
    }
  end

  defp body_of(msg) do
    case Map.get(msg, :body) do
      body when is_binary(body) -> body
      [%{data: data} | _] -> data
      _ -> nil
    end
  end
end
