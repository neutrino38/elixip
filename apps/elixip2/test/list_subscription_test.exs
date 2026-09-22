defmodule SIP.Test.ListSubscription do
  # The event-package table lives in :persistent_term and the presence processing
  # module in a node-wide Agent: two of these at once decide each other's outcome.
  use ExUnit.Case, async: false

  @moduledoc """
  A list subscription, end to end over the mockup transport: the SUBSCRIBE a
  Linphone client actually sends (RFC 5367 — `Require: recipient-list-subscribe`,
  the buddies in the body) and the NOTIFY it must get back (RFC 4662 — an RLMI
  manifest plus one PIDF part per buddy, `Require: eventlist`).

  The one thing every case here is really about: a watcher can only display a
  buddy whose `cid` names a part that is in the message.
  """

  alias SIP.Presence.Rlmi
  alias SIP.Test.Transport.Mockup

  @list_uri "sip:rls@sip.linphone.org"
  @bob "sip:bob@unit.test"
  @carol "sip:carol@elsewhere.example"

  # The notifier under test: it watches nothing and holds no collection — the
  # states it notifies are handed to it in appdata, so this exercises the
  # framework and not a kelixip module.
  defmodule Fixture.ListNotifier do
    @moduledoc false
    use SIP.Scenario
    uas(:presence)
    config(domain: "unit.test")

    state initial_state do
      goto(authorize)
    end

    state authorize do
      on_events do
        {:SUBSCRIBE, _req, _t, _d} ->
          case accept_subscription(package: "presence") do
            {:ok, sub} ->
              notify_list(states_for(sub.list_entries, appdata_get(:states)))
              announce_self()
              goto(subscribed, "200 + list NOTIFY")

            {:error, code} ->
              goto(refused, "#{code}")
          end
      after
        5_000 -> scenario_failure("no SUBSCRIBE received")
      end
    end

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
        # A state changed: one partial NOTIFY naming only what moved.
        {:push, states} ->
          notify_list(states)
          stay("partial push")

        {:subscription_terminated, _ref, reason} -> scenario_success("#{reason}")
        {:dialog_terminated, _d, _r} -> scenario_success("dialog gone")
      after
        20_000 -> scenario_failure("the subscription never ended")
      end
    end

    # A label, not logic: the states a test set up, restricted to what the
    # watcher actually asked for.
    defp states_for(entries, states),
      do: Map.new(entries, fn uri -> {uri, Map.get(states || %{}, uri)} end)

    # The instance runs in a process the dialog layer spawned, so a test that
    # wants to push a state change into it — the way a collection's fan-out does
    # — has no other way to learn its pid.
    defp announce_self do
      case Process.whereis(:subscription_test) do
        nil -> :ok
        pid -> send(pid, {:instance, self()})
      end
    end
  end

  defmodule Fixture.WatcherPeer do
    @moduledoc "Answers every NOTIFY 200, so none of them is retransmitted."
    use SIP.Test.Peer

    @impl true
    def on_request(%{method: :NOTIFY} = req, state), do: {[reply(req, 200, "OK", [], 10)], state}
    def on_request(req, state), do: default_request(req, state)
  end

  setup_all do
    {:ok, _} = SIP.Session.ConfigRegistry.start()
    SIP.Test.AppEnv.preserve_proxy()
    Application.put_env(:elixip2, :proxyusesrv, false)
    :ok = SIP.EventPackage.register(SIP.EventPackage.Presence, origin: :builtin)
    :ok
  end

  setup do
    Process.unregister(:subscription_test)
    Process.register(self(), :subscription_test)
    :ok
  catch
    :error, :badarg ->
      Process.register(self(), :subscription_test)
      :ok
  end

  describe "the SUBSCRIBE a client sends" do
    test "is answered 200, and the NOTIFY carries the manifest and one part per buddy" do
      tp = attach("list-ok")
      doc = SIP.Presence.Doc.new(@bob, :open, note: "Available")
      serve(%{@bob => doc})

      req = subscribe(instance: "list-ok", entries: [@bob, @carol])
      cid = req.callid
      Mockup.inject(tp, req)

      assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid}}}, 2_000
      assert_receive {:sip_mockup, {:request_sent, :NOTIFY, %{callid: ^cid} = notify}}, 2_000

      # RFC 4662 §3.2: without this the watcher may not read the body as a list.
      assert Map.get(notify, "Require") == "eventlist"
      assert notify.contenttype =~ ~s(multipart/related; type="application/rlmi+xml")

      {manifest, parts} = read_list_notify(notify)

      # The list URI is the Request-URI as received — here it carries the mockup's
      # own routing parameter, which a real one does not.
      assert manifest.uri =~ @list_uri
      assert manifest.version == 0
      assert manifest.full_state == true

      # Bob is served: his instance points at a part that is really there.
      bob = resource(manifest, @bob)
      assert [%Rlmi.Instance{state: :active, cid: bob_cid}] = bob.instances
      assert %{data: pidf} = Enum.find(parts, &(&1["Content-ID"] == "<" <> bob_cid <> ">"))
      assert {:ok, %SIP.Presence.Doc{note: "Available"}} = SIP.Presence.Pidf.parse(pidf)

      # Carol is not: named all the same, so the watcher stops waiting for her.
      carol = resource(manifest, @carol)
      assert [%Rlmi.Instance{state: :terminated, reason: "noresource", cid: nil}] = carol.instances
    end

    # A collection keyed on `{user, domain, event}` hands the state back under the
    # folded AOR. The watcher matches its roster by string, so the manifest has to
    # name the buddy the way the watcher listed it.
    test "a resource is named with the URI the watcher wrote, not the one pushed back" do
      tp = attach("list-case")
      listed = "sip:Bob@Unit.Test"
      serve(%{})

      req = subscribe(instance: "list-case", entries: [listed])
      cid = req.callid
      Mockup.inject(tp, req)

      assert_receive {:sip_mockup, {:request_sent, :NOTIFY, %{callid: ^cid} = first}}, 2_000
      {_manifest, _} = read_list_notify(first)

      send(instance_pid(), {:push, %{"sip:bob@unit.test" => SIP.Presence.Doc.new(@bob, :open)}})

      assert_receive {:sip_mockup, {:request_sent, :NOTIFY, %{callid: ^cid} = second}}, 2_000
      {manifest, _} = read_list_notify(second)

      assert [%{uri: ^listed}] = manifest.resources
    end

    test "the second NOTIFY is partial, and its version has moved" do
      tp = attach("list-partial")
      serve(%{})

      req = subscribe(instance: "list-partial", entries: [@bob])
      cid = req.callid
      Mockup.inject(tp, req)

      assert_receive {:sip_mockup, {:request_sent, :NOTIFY, %{callid: ^cid} = first}}, 2_000
      {first_manifest, _} = read_list_notify(first)
      assert first_manifest.full_state == true
      assert first_manifest.version == 0

      send(instance_pid(), {:push, %{@bob => SIP.Presence.Doc.new(@bob, :open)}})

      assert_receive {:sip_mockup, {:request_sent, :NOTIFY, %{callid: ^cid} = second}}, 2_000
      {second_manifest, _} = read_list_notify(second)
      assert second_manifest.full_state == false
      assert second_manifest.version == 1
      assert [_bob] = second_manifest.resources
    end

    # RFC 4662 §4.1: a notifier MUST NOT send an event list to a watcher that did
    # not say it could read one.
    test "without Supported: eventlist it is 406, not a body the watcher cannot read" do
      tp = attach("list-406")
      serve(%{})

      req = subscribe(instance: "list-406", entries: [@bob], supported: nil)
      cid = req.callid
      Mockup.inject(tp, req)

      assert_receive {:sip_mockup, {:response_sent, 406, %{callid: ^cid}}}, 2_000
    end

    test "without an Accept that can carry a list it is 406 too" do
      tp = attach("list-406-accept")
      serve(%{})

      req =
        subscribe(instance: "list-406-accept", entries: [@bob], accept: "application/pidf+xml")

      cid = req.callid
      Mockup.inject(tp, req)

      assert_receive {:sip_mockup, {:response_sent, 406, %{callid: ^cid}}}, 2_000
    end

    # It asked for a list subscription and supplied something that is not a list:
    # subscribing it to nothing would leave it watching an empty roster for an
    # hour without ever being told why.
    test "a recipient-list body that is not a resource list is 400" do
      tp = attach("list-400")
      serve(%{})

      req = subscribe(instance: "list-400", entries: [@bob])
      req = %{req | body: "<presence/>", contenttype: "application/pidf+xml"}
      cid = req.callid
      Mockup.inject(tp, req)

      assert_receive {:sip_mockup, {:response_sent, 400, %{callid: ^cid}}}, 2_000
    end
  end

  describe "a deflated exchange" do
    test "the list arrives compressed and the answer names the same buddies" do
      tp = attach("list-deflate")
      serve(%{@bob => SIP.Presence.Doc.new(@bob, :open)})

      req = subscribe(instance: "list-deflate", entries: [@bob, @carol])

      # What the capture shows: the body deflated, its Content-Length counting the
      # compressed octets. Going through the parser is the point — this is the
      # path a real SUBSCRIBE takes.
      raw = SIPMsg.serialize(req)
      [headers, body] = String.split(raw, "\r\n\r\n", parts: 2)
      compressed = :zlib.compress(body)

      raw =
        headers
        |> String.replace(~r/Content-Length: \d+/, "Content-Length: #{byte_size(compressed)}")
        |> Kernel.<>("\r\nContent-Encoding: deflate\r\n\r\n")
        |> Kernel.<>(compressed)

      {:ok, parsed} = SIPMsg.parse(raw, fn _c, _m, _l, _t -> nil end)
      cid = req.callid
      Mockup.inject(tp, parsed)

      assert_receive {:sip_mockup, {:request_sent, :NOTIFY, %{callid: ^cid} = notify}}, 2_000
      {manifest, _parts} = read_list_notify(notify)

      assert Enum.map(manifest.resources, & &1.uri) |> Enum.sort() == Enum.sort([@bob, @carol])
    end
  end

  # ── helpers ─────────────────────────────────────────────────────────────────

  defp serve(states), do: SIP.Test.PresenceUAS.serve(Fixture.ListNotifier, %{states: states})

  defp attach(instance) do
    {:ok, uri} = SIP.Uri.parse("sip:rls@unit.test")

    routed =
      SIP.Transport.Selector.select_transport(SIP.Uri.set_uri_param(uri, "unittest", instance))

    :ok = Mockup.attach_probe(routed.tp_pid)
    :ok = Mockup.set_peer(routed.tp_pid, Fixture.WatcherPeer)
    routed.tp_pid
  end

  # The scenario instance serving the one dialog of this test, so a test can push
  # a state change into it the way a collection's fan-out would.
  defp instance_pid do
    assert_receive {:instance, pid}, 2_000
    pid
  end

  defp resource(manifest, uri), do: Enum.find(manifest.resources, &(&1.uri == uri))

  # The SUBSCRIBE Linphone Desktop sends, minus what a mockup transport supplies.
  defp subscribe(opts) do
    branch = SIP.Msg.Ops.generate_branch_value()
    entries = Keyword.fetch!(opts, :entries)

    {:ok, ruri} = SIP.Uri.parse(@list_uri)
    ruri = SIP.Uri.set_uri_param(ruri, "unittest", Keyword.fetch!(opts, :instance))

    from =
      SIP.Uri.set_header_param(
        %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "unit.test"},
        "tag",
        SIP.Msg.Ops.generate_from_or_to_tag()
      )

    req = %{
      "Max-Forwards" => "70",
      "Require" => "recipient-list-subscribe",
      "Content-Disposition" => "recipient-list",
      "Accept-Encoding" => "deflate",
      method: :SUBSCRIBE,
      ruri: ruri,
      from: from,
      to: %SIP.Uri{scheme: "sip:", userpart: "rls", domain: "sip.linphone.org"},
      contact: %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "82.184.8.2", port: 53_936},
      event: "presence",
      accept:
        Keyword.get(opts, :accept, "multipart/related, application/pidf+xml, application/rlmi+xml"),
      expires: 3600,
      callid: SIP.Msg.Ops.generate_from_or_to_tag(),
      cseq: [1, :SUBSCRIBE],
      transid: branch,
      via: ["SIP/2.0/UDP 82.184.8.2:53936;branch=#{branch}"],
      useragent: "Linphone-Desktop/6.2.2",
      contenttype: "application/resource-lists+xml"
    }

    req =
      case Keyword.get(opts, :supported, "eventlist") do
        nil -> req
        value -> Map.put(req, :supported, value)
      end

    # The Content-Type is re-stated after the body: `update_sip_msg/2` assumes a
    # bare binary body is SDP, which a resource list is not.
    req
    |> SIP.Msg.Ops.update_sip_msg({:body, resource_list(entries)})
    |> Map.put(:contenttype, "application/resource-lists+xml")
  end

  defp resource_list(entries) do
    ~s(<?xml version="1.0" encoding="UTF-8"?>\n) <>
      ~s(<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists">\n <list>\n) <>
      Enum.map_join(entries, "", fn uri -> ~s(  <entry uri="#{uri}"/>\n) end) <>
      " </list>\n</resource-lists>\n"
  end
end
