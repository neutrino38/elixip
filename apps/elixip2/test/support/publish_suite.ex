defmodule SIP.Test.PublishSuite do
  @moduledoc """
  The publication layer (RFC 3903) over the mockup transport: a compositor
  answering PUBLISHes, written once and run against **any** event package.

      use SIP.Test.PublishSuite, traits: SIP.Test.SubscriptionTraits.Presence

  A suite in a macro for the reason P4 gave for the subscription one
  (`SIP.Test.SubscriptionSuite`): the same tests have to pass over
  `SIP.Test.EventPackages.Dummy`, whose document is a line of text, and over
  `SIP.EventPackage.Presence`, whose document is PIDF. Two files asserting the
  same things in their own words drift apart at the first fix applied to one of
  them.

  It shares `SIP.Test.SubscriptionTraits` rather than defining traits of its own
  — the six answers are the same six, read for the other half of presence:
  `bad_accept/0` is the content type the package cannot produce, so here it is
  the one it cannot *read* (the **415**), and `too_brief/0` is below its
  minimum on both paths.

  The publisher is hand-built and injected (`publish/1` below), not driven by a
  scenario: v1 ships no PUBLISH client, and what is under test is the answer a
  compositor gives to what a real publisher sends — Linphone's included.
  """

  defmacro __using__(opts) do
    traits = Keyword.fetch!(opts, :traits)

    quote do
      # The event-package table lives in :persistent_term, the presence
      # processing module in a node-wide Agent and the collection in a named
      # one: two of these running at once would decide each other's outcome.
      use ExUnit.Case, async: false

      alias SIP.Test.PublishCollection
      alias SIP.Test.Transport.Mockup

      @traits unquote(traits)

      # ── The compositor this suite runs ────────────────────────────────────

      defmodule Fixture.Compositor do
        @moduledoc false
        use SIP.Scenario
        uas(:presence)
        config(domain: "unit.test")

        state initial_state do
          goto(publishing)
        end

        # The whole of RFC 3903's reading is `check_publish/1`'s: 400, 415, 423
        # and 489 have already gone out by the time it answers {:error, code}.
        # What is left is the collection's verdict and the answer that states it.
        state publishing do
          on_events do
            {:PUBLISH, _req, _t, _d} ->
              case check_publish(package: unquote(traits).package().name()) do
                {:ok, pub} ->
                  case SIP.Test.PublishCollection.publish(pub) do
                    {:ok, etag, expires} ->
                      reply_publish(200, etag: etag, expires: expires)
                      scenario_success("published")

                    {:ok, :removed} ->
                      reply_publish(200, expires: 0)
                      scenario_success("removed")

                    {:error, 412} ->
                      reply_publish(412, "Conditional Request Failed")
                      scenario_success("stale etag")
                  end

                {:error, code} ->
                  scenario_success("refused #{code}")
              end
          after
            5_000 -> scenario_failure("no PUBLISH received")
          end
        end
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
        :ok = PublishCollection.start()
        SIP.Test.PresenceUAS.serve(Fixture.Compositor)
        :ok
      end

      # ── The publication lifecycle ─────────────────────────────────────────

      describe "publishing a state" do
        test "an initial publication is answered 200 with an entity-tag and the lifetime granted" do
          tp = attach("publish-initial")
          rsp = publish(tp, instance: "publish-initial", body: wire_document(:open))

          assert rsp.response == 200
          assert is_binary(SIP.Msg.Ops.entity_tag(rsp))
          # What the compositor GRANTED, which is what the publisher must arm
          # its refresh on — not what it asked for.
          assert SIP.Msg.Ops.expires_header(rsp) == @traits.expires()

          assert [%SIP.Publication{} = stored] = PublishCollection.all()
          assert stored.username == "bob"
          assert stored.domain == "unit.test"
          assert stored.event == package_name()
          assert @traits.status_of(stored.body) == :open
          # ABSOLUTE, kamailio's convention, so what was granted is read back
          # through remaining/1 and never by subtracting by hand somewhere else.
          assert SIP.Publication.remaining(stored) in (@traits.expires() - 2)..@traits.expires()
        end

        test "a refresh presenting that tag keeps the document and is given a new one" do
          tp = attach("publish-refresh")
          first = publish(tp, instance: "publish-refresh", body: wire_document(:open))
          etag = SIP.Msg.Ops.entity_tag(first)

          # A refresh carries no body at all (RFC 3903 §4.1): the state is the
          # one already held, for longer.
          rsp = publish(tp, instance: "publish-refresh", etag: etag, cseq: 2)

          assert rsp.response == 200
          assert SIP.Msg.Ops.expires_header(rsp) == @traits.expires()

          refreshed = SIP.Msg.Ops.entity_tag(rsp)
          assert is_binary(refreshed)

          assert refreshed != etag,
                 "a successful publication must be given a new entity-tag (RFC 3903 §4.1)"

          assert [stored] = PublishCollection.all()
          assert @traits.status_of(stored.body) == :open
          assert stored.etag == refreshed
        end

        test "a modification replaces the document" do
          tp = attach("publish-modify")
          first = publish(tp, instance: "publish-modify", body: wire_document(:open))

          rsp =
            publish(tp,
              instance: "publish-modify",
              etag: SIP.Msg.Ops.entity_tag(first),
              body: wire_document(:closed),
              cseq: 2
            )

          assert rsp.response == 200
          assert [stored] = PublishCollection.all()
          assert @traits.status_of(stored.body) == :closed
        end

        test "a removal drops the state, and its 200 names no entity-tag" do
          tp = attach("publish-remove")
          first = publish(tp, instance: "publish-remove", body: wire_document(:open))

          rsp =
            publish(tp,
              instance: "publish-remove",
              etag: SIP.Msg.Ops.entity_tag(first),
              expires: 0,
              cseq: 2
            )

          assert rsp.response == 200
          # There is no state left to name (RFC 3903 §6): a publisher handed one
          # here would present it on a refresh and be answered 412 forever.
          assert SIP.Msg.Ops.entity_tag(rsp) == nil
          assert PublishCollection.all() == []
        end

        test "an entity-tag naming no state we hold is answered 412" do
          tp = attach("publish-412")
          rsp = publish(tp, instance: "publish-412", etag: "nosuchtag")

          # The one verdict the framework cannot reach: only the collection
          # knows which tags it has issued (plan decision 5).
          assert rsp.response == 412
          assert rsp.reason == "Conditional Request Failed"
        end
      end

      # ── The refusals the script never writes ──────────────────────────────

      describe "the refusals" do
        test "a PUBLISH with neither a body nor an entity-tag is answered 400" do
          tp = attach("publish-400")
          rsp = publish(tp, instance: "publish-400")

          assert rsp.response == 400
          assert PublishCollection.all() == []
        end

        test "a body the package cannot read is answered 415, saying what it accepts" do
          tp = attach("publish-415")

          rsp =
            publish(tp,
              instance: "publish-415",
              body: "whatever",
              content_type: @traits.bad_accept()
            )

          assert rsp.response == 415
          # Without it the publisher has no way to know what to send instead and
          # simply gives up.
          assert SIP.Msg.Ops.accepted_content_types(rsp) ==
                   Enum.map(@traits.package().content_types(), &String.downcase/1)
        end

        test "a lifetime below the package minimum is answered 423 with a Min-Expires" do
          tp = attach("publish-423")

          rsp =
            publish(tp,
              instance: "publish-423",
              body: wire_document(:open),
              expires: @traits.too_brief()
            )

          assert rsp.response == 423
          minimum = to_string(@traits.package().min_expires())
          assert rsp["Min-Expires"] == minimum or Map.get(rsp, "Min-Expires") == minimum
        end

        test "an event package the node does not know is answered 489" do
          tp = attach("publish-489")

          rsp =
            publish(tp,
              instance: "publish-489",
              body: wire_document(:open),
              event: "nosuchpackage"
            )

          assert rsp.response == 489
        end

        test "a package it does not serve is answered 489, without the script looking" do
          # `message-summary` is a perfectly good package name; this scenario
          # simply does not serve it, and says so before any of its own code runs.
          tp = attach("publish-489-other")

          rsp =
            publish(tp,
              instance: "publish-489-other",
              body: wire_document(:open),
              event: "message-summary"
            )

          assert rsp.response == 489
        end
      end

      # ── Helpers ───────────────────────────────────────────────────────────

      defp package_name, do: @traits.package().name()

      defp content_type, do: hd(@traits.package().content_types())

      # The document as it goes on the wire — written by the package itself, so
      # a publisher never hand-builds a body the package would not have produced.
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
        routed.tp_pid
      end

      # Inject one PUBLISH and hand back the final response to it.
      defp publish(tp, opts) do
        req = publish_msg(opts)
        Mockup.inject(tp, req)
        await_response(req.callid)
      end

      defp await_response(callid, timeout \\ 3_000) do
        receive do
          {:sip_mockup, {:response_sent, code, %{callid: ^callid} = rsp}} when code >= 200 ->
            rsp

          {:sip_mockup, _other} ->
            await_response(callid, timeout)
        after
          timeout -> flunk("no final response to the PUBLISH on call #{callid}")
        end
      end

      # A PUBLISH as it comes off the wire. Each one is its own transaction on
      # its own Call-ID unless the test says otherwise: RFC 3903 §4.1 ties a
      # refresh to the entity-tag it presents, never to the dialog or the
      # Call-ID that carried the publication before it.
      defp publish_msg(opts) do
        branch = SIP.Msg.Ops.generate_branch_value()
        callid = Keyword.get(opts, :callid, SIP.Msg.Ops.generate_from_or_to_tag())
        fromtag = Keyword.get(opts, :fromtag, SIP.Msg.Ops.generate_from_or_to_tag())
        body = Keyword.get(opts, :body)

        {:ok, ruri} = SIP.Uri.parse("sip:bob@unit.test")
        ruri = SIP.Uri.set_uri_param(ruri, "unittest", Keyword.fetch!(opts, :instance))

        from =
          SIP.Uri.set_header_param(
            %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "unit.test"},
            "tag",
            fromtag
          )

        req = %{
          "Max-Forwards" => "70",
          method: :PUBLISH,
          ruri: ruri,
          from: from,
          to: %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "unit.test"},
          event: Keyword.get(opts, :event, package_name()),
          expires: Keyword.get(opts, :expires, @traits.expires()),
          callid: callid,
          cseq: [Keyword.get(opts, :cseq, 1), :PUBLISH],
          transid: branch,
          via: ["SIP/2.0/UDP 82.184.8.2:53936;branch=#{branch}"],
          useragent: "Mockup-publisher",
          contentlength: 0
        }

        req
        |> put_unless_nil(:sipifmatch, Keyword.get(opts, :etag))
        |> put_body(body, Keyword.get(opts, :content_type, content_type()))
      end

      defp put_unless_nil(req, _key, nil), do: req
      defp put_unless_nil(req, key, value), do: Map.put(req, key, value)

      defp put_body(req, nil, _content_type), do: req

      defp put_body(req, body, content_type) do
        req
        |> Map.put(:body, body)
        |> Map.put(:contenttype, content_type)
        |> Map.put(:contentlength, byte_size(body))
      end
    end
  end
end
