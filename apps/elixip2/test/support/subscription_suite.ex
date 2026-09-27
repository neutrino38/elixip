defmodule SIP.Test.SubscriptionSuite do
  @moduledoc """
  The subscription layer (RFC 6665) over the mockup transport, both halves of it:
  a notifier answering SUBSCRIBEs and a watcher living with the NOTIFYs that come
  back — written once and run against **any** event package.

      use SIP.Test.SubscriptionSuite, traits: SIP.Test.SubscriptionTraits.Presence

  It is a suite in a macro rather than a test file because of what P4's "done
  when" asks for: the same tests, passing over
  `SIP.Test.EventPackages.Dummy` (a line of text) and over
  `SIP.EventPackage.Presence` (PIDF). Two files asserting the same things would
  drift apart at the first fix applied to one of them, and the claim — that the
  behaviour is a behaviour and not a hole shaped like one implementation — is
  only worth anything while the two runs are the *same* run.

  What differs between them is `SIP.Test.SubscriptionTraits`, six answers wide.
  """

  defmacro __using__(opts) do
    traits = Keyword.fetch!(opts, :traits)

    quote do
      # The event-package table lives in :persistent_term and the presence
      # processing module in a node-wide Agent: two of these running at once
      # would decide each other's outcome.
      use ExUnit.Case, async: false

      alias SIP.Test.Peers.NotifyingUAS
      alias SIP.Test.Transport.Mockup

      require Logger

      @traits unquote(traits)

      # ── The notifier this suite runs ──────────────────────────────────────

      defmodule Fixture.Notifier do
        @moduledoc false
        use SIP.Scenario
        uas(:presence)
        config(domain: "unit.test")

        state initial_state do
          goto(authorize)
        end

        # The whole negotiation is `accept_subscription/1`'s: 489, 406 and 423
        # have already gone out by the time it answers {:error, code}, which is
        # what a script never having to read `Event` looks like.
        state authorize do
          on_events do
            {:SUBSCRIBE, _req, _t, _d} ->
              case accept_subscription(
                     package: unquote(traits).package().name(),
                     expires: appdata_get(:granted)
                   ) do
                {:ok, _sub} ->
                  notify(unquote(traits).document(:open))
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
              case accept_subscription(
                     package: unquote(traits).package().name(),
                     expires: appdata_get(:granted)
                   ) do
                {:ok, _sub} ->
                  notify(unquote(traits).document(:open))
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

      # ── The watcher this suite runs ───────────────────────────────────────

      defmodule Fixture.Watcher do
        @moduledoc false
        use SIP.Scenario
        config(username: "alice", authusername: "alice", domain: "unit.test", passwd: "secret")

        state initial_state do
          send_SUBSCRIBE(appdata_get(:target), unquote(traits).package().name(),
            expires: appdata_get(:expires) || unquote(traits).expires()
          )

          goto(wait_200)
        end

        state wait_200 do
          on_events do
            {100, _rsp, _t, _d} ->
              stay("100 Trying")

            # The NOTIFY may arrive BEFORE the 200 that belongs to it (RFC 6665
            # §4.2.1.2 has the notifier send the 2xx first, and UDP reorders
            # anyway). The dialog has already answered it 200 by the time we see
            # it.
            {:NOTIFY, req, _t, _d} ->
              probe(:notify, req)
              stay("early NOTIFY")

            {200, rsp, t, _d} ->
              process_sip_reply(rsp, t)
              probe(:dialog, var!(sip_ctx).dialogpid)
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

        Not a detail. `SIP.Test.Peers.Passive` answers nothing, so the NICT
        carrying each NOTIFY retransmits it every T1..T2 — and a test waiting for
        the NEXT NOTIFY is handed a copy of the last one instead, which passes
        for whatever it was asserting.
        """
        use SIP.Test.Peer

        @impl true
        def on_request(%{method: :NOTIFY} = req, state) do
          {[reply(req, 200, "OK", [], 10)], state}
        end

        def on_request(req, state), do: default_request(req, state)
      end

      # ── Fixtures ──────────────────────────────────────────────────────────

      setup_all do
        {:ok, _} = SIP.Session.ConfigRegistry.start()
        SIP.Test.AppEnv.preserve_proxy()
        Application.put_env(:elixip2, :proxyusesrv, false)

        :ok = SIP.EventPackage.register(@traits.package(), origin: :builtin)
        on_exit(fn -> SIP.EventPackage.unregister(@traits.package()) end)
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

      # ── The notifier half ─────────────────────────────────────────────────

      describe "the notifier" do
        test "accepts a SUBSCRIBE and sends the state in the first NOTIFY" do
          SIP.Test.PresenceUAS.serve(Fixture.Notifier)
          tp = attach("notifier-accept")

          req = subscribe(instance: "notifier-accept")
          cid = req.callid
          Mockup.inject(tp, req)

          assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid} = rsp}}, 2_000
          # What the notifier GRANTED, which is what the watcher must arm its
          # refresh on — not what it asked for.
          assert SIP.Msg.Ops.expires_header(rsp) == @traits.expires()

          assert_receive {:sip_mockup, {:request_sent, :NOTIFY, %{callid: ^cid} = notify}}, 2_000
          assert {:active, params} = SIP.Msg.Ops.subscription_state(notify)
          assert params["expires"] <= @traits.expires()
          assert {package_name(), nil} == SIP.Msg.Ops.event_package(notify)
          # The type the package negotiated, not the SDP a bare body defaults to.
          assert notify.contenttype == content_type()
          assert @traits.status_of(body_of(notify)) == :open
        end

        test "refuses a lifetime below the package minimum with 423 and a Min-Expires" do
          SIP.Test.PresenceUAS.serve(Fixture.Notifier)
          tp = attach("notifier-423")

          req = subscribe(instance: "notifier-423", expires: @traits.too_brief())
          cid = req.callid
          Mockup.inject(tp, req)

          assert_receive {:sip_mockup, {:response_sent, 423, %{callid: ^cid} = rsp}}, 2_000
          # Mandatory: without it the watcher has no way to know what to ask for
          # and simply gives up (the rule RFC 3261 §10.3 step 7 already imposes
          # on a REGISTER).
          minimum = to_string(@traits.package().min_expires())
          assert rsp["Min-Expires"] == minimum or Map.get(rsp, "Min-Expires") == minimum
        end

        test "refuses an Accept the package cannot satisfy with 406" do
          SIP.Test.PresenceUAS.serve(Fixture.Notifier)
          tp = attach("notifier-406")

          req = subscribe(instance: "notifier-406", accept: @traits.bad_accept())
          cid = req.callid
          Mockup.inject(tp, req)

          assert_receive {:sip_mockup, {:response_sent, 406, %{callid: ^cid}}}, 2_000
        end

        test "refuses an event package the node does not know with 489" do
          SIP.Test.PresenceUAS.serve(Fixture.Notifier)
          tp = attach("notifier-489")

          req = subscribe(instance: "notifier-489", event: "nosuchpackage")
          cid = req.callid
          Mockup.inject(tp, req)

          assert_receive {:sip_mockup, {:response_sent, 489, %{callid: ^cid}}}, 2_000
        end

        test "refuses a package it does not serve with 489, without the script looking" do
          # `message-summary` is a perfectly good package name; this scenario
          # simply does not serve it, and says so before any of its own code runs.
          SIP.Test.PresenceUAS.serve(Fixture.Notifier)
          tp = attach("notifier-489-other")

          req = subscribe(instance: "notifier-489-other", event: "message-summary")
          cid = req.callid
          Mockup.inject(tp, req)

          assert_receive {:sip_mockup, {:response_sent, 489, %{callid: ^cid}}}, 2_000
        end

        # RFC 3261 §8.2.2.3: the refusal has to NAME the extension, or the watcher
        # has no way to know what to send instead and simply retries the same
        # request.
        test "refuses an extension it does not implement with 420 and an Unsupported" do
          SIP.Test.PresenceUAS.serve(Fixture.Notifier)
          tp = attach("notifier-420")

          req = subscribe(instance: "notifier-420", require: "gruu")
          cid = req.callid
          Mockup.inject(tp, req)

          assert_receive {:sip_mockup, {:response_sent, 420, %{callid: ^cid} = rsp}}, 2_000
          assert Map.get(rsp, "Unsupported") == "gruu"
        end

        test "the Unsupported names only what is unsupported" do
          SIP.Test.PresenceUAS.serve(Fixture.Notifier)
          tp = attach("notifier-420-mixed")

          req = subscribe(instance: "notifier-420-mixed", require: "eventlist, gruu")
          cid = req.callid
          Mockup.inject(tp, req)

          assert_receive {:sip_mockup, {:response_sent, 420, %{callid: ^cid} = rsp}}, 2_000
          assert Map.get(rsp, "Unsupported") == "gruu"
        end

        test "a Require the layer does implement refuses nothing" do
          SIP.Test.PresenceUAS.serve(Fixture.Notifier)
          tp = attach("notifier-420-none")

          req = subscribe(instance: "notifier-420-none", require: "eventlist")
          cid = req.callid
          Mockup.inject(tp, req)

          assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid}}}, 2_000
        end

        test "accepts a refresh on the same dialog and answers it 200" do
          SIP.Test.PresenceUAS.serve(Fixture.Notifier)
          tp = attach("notifier-refresh")

          req = subscribe(instance: "notifier-refresh")
          cid = req.callid
          Mockup.inject(tp, req)
          assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid}}}, 2_000
          assert_receive {:sip_mockup, {:request_sent, :NOTIFY, %{callid: ^cid}}}, 2_000

          # The refresh: same Call-ID and same From tag, one CSeq further on. It
          # is what `auto_store/2` must stash, or the scenario would re-negotiate
          # the request that created it.
          Mockup.inject(tp, refresh(req, 2))
          assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid}}}, 2_000
          assert_receive {:sip_mockup, {:request_sent, :NOTIFY, %{callid: ^cid}}}, 2_000
        end

        test "refuses a second event package on an established dialog with 489" do
          SIP.Test.PresenceUAS.serve(Fixture.Notifier)
          tp = attach("notifier-second-package")

          req = subscribe(instance: "notifier-second-package")
          cid = req.callid
          Mockup.inject(tp, req)
          assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid}}}, 2_000

          # v1 refuses it (design decision 3). The key already carries the
          # package, so allowing it later widens nothing.
          Mockup.inject(tp, refresh(req, 2) |> Map.put(:event, "message-summary"))
          assert_receive {:sip_mockup, {:response_sent, 489, %{callid: ^cid}}}, 2_000
        end

        test "answers an un-SUBSCRIBE with the final NOTIFY and nothing else" do
          SIP.Test.PresenceUAS.serve(Fixture.Notifier)
          tp = attach("notifier-unsubscribe")

          req = subscribe(instance: "notifier-unsubscribe")
          cid = req.callid
          Mockup.inject(tp, req)
          assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid}}}, 2_000
          assert_receive {:sip_mockup, {:request_sent, :NOTIFY, %{callid: ^cid}}}, 2_000

          # `Expires: 0` is accepted like any other SUBSCRIBE, and what it accepts
          # is the end of the subscription. The script notifies as it does on any
          # refresh — and the state it hands over must NOT go out: the next NOTIFY
          # on this dialog is the terminated one, or a watcher is told `active`
          # one second before it is told the subscription is over.
          Mockup.inject(tp, refresh(req, 2) |> Map.put(:expires, 0))
          assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid} = rsp}}, 2_000
          assert SIP.Msg.Ops.expires_header(rsp) == 0

          assert_receive {:sip_mockup, {:request_sent, :NOTIFY, %{callid: ^cid} = notify}}, 3_000

          assert {:terminated, _params} = SIP.Msg.Ops.subscription_state(notify),
                 "an un-SUBSCRIBE was followed by a NOTIFY that was not the final one"
        end

        test "sends the final NOTIFY itself when the granted lifetime lapses" do
          # One second, granted by the scenario over what the watcher asked for.
          # The script says nothing about the end of the subscription — that is
          # the point.
          SIP.Test.PresenceUAS.serve(Fixture.Notifier, %{granted: 1})
          tp = attach("notifier-expiry")

          req = subscribe(instance: "notifier-expiry")
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

      # ── The watcher half ──────────────────────────────────────────────────

      describe "the watcher" do
        test "records what the notifier granted and answers its NOTIFYs by itself" do
          tp = watcher_transport("watcher-basic", granted: 30)
          run_watcher("sip:bob@unit.test;unittest=watcher-basic")

          assert_receive {:sip_mockup, {:request_sent, :SUBSCRIBE, sub}}, 2_000
          assert {package_name(), nil} == SIP.Msg.Ops.event_package(sub)
          # The Accept advertised is the package's own list, asked of the package.
          assert SIP.Msg.Ops.accepted_content_types(sub) ==
                   Enum.map(@traits.package().content_types(), &String.downcase/1)

          assert_receive {:subscribed, %SIP.Subscription{} = subscription}, 2_000
          assert subscription.event == package_name()
          # `expires` is ABSOLUTE, kamailio's convention, so what was granted is
          # read back through remaining/1 and never by subtracting by hand
          # somewhere else.
          assert SIP.Subscription.remaining(subscription) in 28..30
          assert SIP.Subscription.status(subscription) == :pending

          # The first NOTIFY: answered 200 by the dialog, and surfaced to the
          # scenario.
          assert_receive {:sip_mockup, {:response_sent, 200, %{method: false}}}, 2_000
          assert_receive {:notify, notify}, 2_000
          assert @traits.status_of(body_of(notify)) == :open

          NotifyingUAS.send_notify(tp, wire_document(:closed))
          assert_receive {:notify, second}, 2_000
          assert @traits.status_of(body_of(second)) == :closed
        end

        test "answers a NOTIFY that overtook its own 200, instead of 481" do
          # The race RFC 6665 §4.2.1.2 forbids and UDP produces anyway. Matched
          # on Call-ID plus our own tag, the dialog adopts the tag the NOTIFY
          # carries.
          _tp = watcher_transport("watcher-race", notify_first: true, reply_delay: 300)
          run_watcher("sip:bob@unit.test;unittest=watcher-race")

          assert_receive {:sip_mockup, {:request_sent, :SUBSCRIBE, _sub}}, 2_000
          assert_receive {:sip_mockup, {:response_sent, code, %{method: false}}}, 3_000
          assert code == 200, "a NOTIFY overtaking its 200 was answered #{code}"
          assert_receive {:notify, _notify}, 2_000
          assert_receive {:subscribed, %SIP.Subscription{}}, 3_000
        end

        test "surfaces exactly one termination when the notifier ends the subscription" do
          tp = watcher_transport("watcher-terminated", granted: 30)
          run_watcher("sip:bob@unit.test;unittest=watcher-terminated")

          assert_receive {:subscribed, %SIP.Subscription{}}, 2_000
          assert_receive {:notify, _first}, 2_000

          NotifyingUAS.terminate(tp, :noresource)

          assert_receive {:terminated, :noresource}, 2_000
          refute_receive {:terminated, _reason}, 500
        end

        test "surfaces one termination when the dialog carrying the subscription dies" do
          _tp = watcher_transport("watcher-dialog-death", granted: 30)
          run_watcher("sip:bob@unit.test;unittest=watcher-dialog-death")

          assert_receive {:dialog, dialog_pid}, 2_000
          assert_receive {:subscribed, %SIP.Subscription{}}, 2_000

          # Nothing in RFC 6665 ends a subscription this way; the application is
          # owed its one event all the same, with `invariant` — §4.1.3's reason
          # for a subscription ended by something other than its own lifecycle.
          SIP.Dialog.terminate(dialog_pid, :transport_down)

          assert_receive {:terminated, :invariant}, 2_000
          refute_receive {:terminated, _reason}, 500
        end
      end

      # ── Helpers ───────────────────────────────────────────────────────────

      defp package_name, do: @traits.package().name()

      defp content_type, do: hd(@traits.package().content_types())

      # The document as it goes on the wire — written by the package itself, so a
      # peer injecting a NOTIFY never hand-builds a body the package would not
      # have produced.
      defp wire_document(status) do
        {:ok, body} = @traits.package().serialize(content_type(), @traits.document(status))
        body
      end

      # A mockup instance of this test's own, with the probe pointed at us and a
      # peer that answers nothing: a named instance per test, so two of them
      # never drive each other (Mockup.select_instance/1).
      defp attach(instance) do
        {:ok, uri} = SIP.Uri.parse("sip:bob@unit.test")

        routed =
          SIP.Transport.Selector.select_transport(
            SIP.Uri.set_uri_param(uri, "unittest", instance)
          )

        :ok = Mockup.attach_probe(routed.tp_pid)
        :ok = Mockup.set_peer(routed.tp_pid, Fixture.WatcherPeer)
        routed.tp_pid
      end

      defp watcher_transport(instance, peer_opts) do
        tp = attach(instance)

        peer_opts =
          peer_opts
          |> Keyword.put(:event, package_name())
          |> Keyword.put(:content_type, content_type())
          |> Keyword.put(:body, wire_document(:open))

        :ok = Mockup.set_peer(tp, NotifyingUAS, peer_opts)
        tp
      end

      defp run_watcher(target) do
        test_pid = self()

        spawn(fn ->
          send(
            test_pid,
            {:watcher_done,
             SIP.Scenario.Runner.run_instance(Fixture.Watcher,
               appdata: %{target: target, expires: @traits.expires()}
             )}
          )
        end)
      end

      # The NOTIFY that ends the subscription, told from the ones before it by
      # what it says rather than by how many came first: a NOTIFY whose 200 is
      # late is retransmitted, and counting them counts copies.
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

        req = %{
          "Max-Forwards" => "70",
          method: :SUBSCRIBE,
          ruri: ruri,
          from: from,
          to: %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "unit.test"},
          contact: %SIP.Uri{
            scheme: "sip:",
            userpart: "alice",
            domain: "82.184.8.2",
            port: 53_936
          },
          event: Keyword.get(opts, :event, package_name()),
          accept: Keyword.get(opts, :accept, content_type()),
          expires: Keyword.get(opts, :expires, @traits.expires()),
          callid: callid,
          cseq: [Keyword.get(opts, :cseq, 1), :SUBSCRIBE],
          transid: branch,
          via: ["SIP/2.0/UDP 82.184.8.2:53936;branch=#{branch}"],
          useragent: "Mockup-watcher",
          contentlength: 0
        }

        case Keyword.get(opts, :require) do
          nil -> req
          tags -> Map.put(req, "Require", tags)
        end
      end

      # The same subscription, asked for again: same Call-ID and From tag, next
      # CSeq, a transaction of its own.
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
  end
end
