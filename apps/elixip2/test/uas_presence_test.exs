defmodule SIP.Test.UASPresence do
  @moduledoc """
  Presence end to end with no node (docs/design/presence-basic-plan.md, P6): the
  `elixipp` factory that routes an inbound SUBSCRIBE or PUBLISH to a
  `uas :presence` scenario, and the two reference scenarios it runs.

  The scenarios are loaded from `scenarios/` — the real files an operator runs,
  not fixtures written to pass: a macro that changes shape breaks them here
  before it breaks a demo.
  """

  use ExUnit.Case

  alias SIP.Test.Peers.NotifyingUAS
  alias SIP.Test.Transport.Mockup

  # The reference scenarios, compiled once from their .exs files.
  @notifier SIP.Scenario.Loader.load_file!("scenarios/uas_presence.exs")
  @watcher SIP.Scenario.Loader.load_file!("scenarios/uac_subscribe.exs")

  # What the notifier grants (scenarios/uas_presence.exs, @granted_expires).
  @granted 300
  @content_type "application/pidf+xml"

  # A presence scenario that blocks: the quota is about how many instances are
  # alive, not about what they do.
  defmodule Fixture.Blocking do
    use SIP.Scenario
    uas(:presence)
    config(domain: "example.com", event_package: "presence")

    state initial_state do
      on_events do
        {:never, _ignored} -> scenario_failure("unexpected")
      after
        60_000 -> scenario_success("timeout")
      end
    end
  end

  setup_all do
    {:ok, _} = SIP.Session.ConfigRegistry.start()
    SIP.Test.AppEnv.preserve_proxy()
    Application.put_env(:elixip2, :proxyusesrv, false)
    # What `SIP.FSL.Host.bootstrap/0` does on a real run: without it every
    # SUBSCRIBE would be answered 489, whatever the scenario declares.
    :ok = SIP.EventPackage.register_builtins()
    :ok
  end

  setup do
    on_exit(fn -> stop_factory() end)
    :ok
  end

  # ── The factory: what never reaches a script ────────────────────────────────

  describe "Elixip.ScenarioUAS, for presence" do
    test "answers 489 to a package the scenario does not serve" do
      start_factory(scenario_module: @notifier, max_instances: 5)

      # `dialog` is a perfectly good package name; this scenario declares
      # `event_package: "presence"` and says so before any of its code runs.
      assert {:reject, 489, "Bad Event"} =
               Elixip.ScenarioUAS.on_new_subscribe(self(), subscribe_req("dialog"), self())

      assert {:reject, 489, "Bad Event"} =
               Elixip.ScenarioUAS.on_new_publish(self(), publish_req("dialog"), self())

      # A SUBSCRIBE with no Event header at all is the same answer: the package
      # is what says which state is being asked for.
      assert {:reject, 489, "Bad Event"} =
               Elixip.ScenarioUAS.on_new_subscribe(self(), subscribe_req(nil), self())
    end

    test "accepts the package it serves and spawns one instance per dialog" do
      start_factory(scenario_module: Fixture.Blocking, max_instances: 2)

      assert {:accept, pid} =
               Elixip.ScenarioUAS.on_new_subscribe(self(), subscribe_req("presence"), self())

      assert is_pid(pid) and Process.alive?(pid)
      assert Elixip.ScenarioUAS.stats().active == 1
    end

    test "answers 503 beyond the concurrency quota" do
      start_factory(scenario_module: Fixture.Blocking, max_instances: 1)

      assert {:accept, _pid} =
               Elixip.ScenarioUAS.on_new_subscribe(self(), subscribe_req("presence"), self())

      assert {:reject, 503, "Service Unavailable"} =
               Elixip.ScenarioUAS.on_new_subscribe(self(), subscribe_req("presence"), self())

      assert Elixip.ScenarioUAS.stats().total_rejected_quota == 1
    end
  end

  # ── The reference notifier, driven by real traffic ──────────────────────────

  describe "scenarios/uas_presence.exs" do
    test "accepts a SUBSCRIBE, sends the state, refreshes it and ends it" do
      start_factory(scenario_module: @notifier, max_instances: 5)
      tp = attach("uas-presence")

      req = subscribe("uas-presence", expires: 600)
      cid = req.callid
      Mockup.inject(tp, req)

      assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid} = rsp}}, 2_000
      # min(asked, the scenario's ceiling, the package's max): what the watcher
      # must arm its refresh on.
      assert SIP.Msg.Ops.expires_header(rsp) == @granted
      # A property of the domain, on the response that knows it (plan decision 3).
      assert allow_events(rsp) == "presence"

      assert_receive {:sip_mockup, {:request_sent, :NOTIFY, %{callid: ^cid} = notify}}, 2_000
      assert {:active, _params} = SIP.Msg.Ops.subscription_state(notify)
      assert {"presence", nil} == SIP.Msg.Ops.event_package(notify)
      assert {:ok, doc} = SIP.Presence.Pidf.parse(SIP.Msg.Ops.body_string(notify))
      assert SIP.Presence.Doc.status(doc) == :open
      assert doc.entity == "sip:bob@unit.test"

      # A refresh on the same dialog: negotiated again, granted again, notified
      # again.
      Mockup.inject(tp, refresh(req, 2))
      assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid}}}, 2_000
      assert_receive {:sip_mockup, {:request_sent, :NOTIFY, %{callid: ^cid}}}, 2_000

      # The un-SUBSCRIBE: answered 200, and ended by the final NOTIFY the dialog
      # sends — never by the script.
      Mockup.inject(tp, refresh(req, 3) |> Map.put(:expires, 0))
      assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid}}}, 2_000
      assert %{"reason" => _reason} = await_final_notify(cid)
    end

    test "answers a PUBLISH 200 with an entity-tag, keeping nothing" do
      start_factory(scenario_module: @notifier, max_instances: 5)
      tp = attach("uas-publish")

      {:ok, body} =
        SIP.Presence.Pidf.serialize(SIP.Presence.Doc.new("sip:bob@unit.test", :open))

      req = publish("uas-publish", body)
      cid = req.callid
      Mockup.inject(tp, req)

      assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid} = rsp}}, 2_000
      assert is_binary(SIP.Msg.Ops.entity_tag(rsp))
      assert SIP.Msg.Ops.expires_header(rsp) > 0
    end
  end

  # ── The reference watcher, against a notifier that answers ──────────────────

  describe "scenarios/uac_subscribe.exs" do
    test "subscribes, reads each state, then un-subscribes and stops" do
      tp = attach("uac-subscribe")

      {:ok, open} =
        SIP.Presence.Pidf.serialize(SIP.Presence.Doc.new("sip:bob@unit.test", :open))

      {:ok, closed} =
        SIP.Presence.Pidf.serialize(SIP.Presence.Doc.new("sip:bob@unit.test", :closed))

      :ok =
        Mockup.set_peer(tp, NotifyingUAS,
          event: "presence",
          content_type: @content_type,
          body: open,
          granted: 120
        )

      test_pid = self()

      spawn(fn ->
        send(
          test_pid,
          {:watcher_done,
           SIP.Scenario.Runner.run_instance(@watcher,
             config_overrides: [watch: "sip:bob@unit.test;unittest=uac-subscribe"]
           )}
        )
      end)

      assert_receive {:sip_mockup, {:request_sent, :SUBSCRIBE, sub}}, 2_000
      assert {"presence", nil} == SIP.Msg.Ops.event_package(sub)
      # Asked of the package, not written in the scenario.
      assert SIP.Msg.Ops.accepted_content_types(sub) == [@content_type]

      # The first NOTIFY is the peer's own; the watcher answers it 200 through
      # the dialog and displays what it carries.
      assert_receive {:sip_mockup, {:response_sent, 200, %{method: false}}}, 2_000

      # A state change: the second NOTIFY takes it to its un-SUBSCRIBE.
      NotifyingUAS.send_notify(tp, closed)

      assert_receive {:sip_mockup, {:request_sent, :SUBSCRIBE, bye}}, 3_000
      assert SIP.Msg.Ops.expires_header(bye) == 0

      # The 200 to the un-SUBSCRIBE is not the end: the final NOTIFY is, and it
      # is what the scenario waits for.
      assert_receive {:watcher_done, :ok}, 5_000
    end
  end

  # ── Helpers ─────────────────────────────────────────────────────────────────

  # `Elixip.ScenarioUAS` is a named singleton linked to the test that started it,
  # so the previous test's may still be dying when the next one starts: take the
  # name over deterministically rather than assuming it is free.
  defp start_factory(opts, attempts \\ 10) do
    case Elixip.ScenarioUAS.start_link(opts) do
      {:ok, _pid} ->
        :ok = SIP.Session.ConfigRegistry.set_presence_processing_module(Elixip.ScenarioUAS)

      {:error, {:already_started, pid}} when attempts > 0 ->
        stop_and_await(pid)
        start_factory(opts, attempts - 1)
    end
  end

  defp stop_factory do
    case Process.whereis(Elixip.ScenarioUAS) do
      nil -> :ok
      pid -> stop_and_await(pid)
    end
  end

  defp stop_and_await(pid) do
    ref = Process.monitor(pid)

    try do
      GenServer.stop(pid)
    catch
      :exit, _ -> :ok
    end

    receive do
      {:DOWN, ^ref, :process, ^pid, _reason} -> :ok
    after
      1_000 -> Process.demonitor(ref, [:flush])
    end
  end

  # A mockup instance of this test's own, with the probe pointed at us.
  defp attach(instance) do
    {:ok, uri} = SIP.Uri.parse("sip:bob@unit.test")

    routed =
      SIP.Transport.Selector.select_transport(SIP.Uri.set_uri_param(uri, "unittest", instance))

    :ok = Mockup.attach_probe(routed.tp_pid)
    :ok = Mockup.set_peer(routed.tp_pid, SIP.Test.Peers.Passive)
    routed.tp_pid
  end

  defp allow_events(msg), do: Map.get(msg, :allowevents) || Map.get(msg, "Allow-Events")

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

  # The requests a watcher and a publisher send, as they come off the wire.
  defp subscribe(instance, opts) do
    presence_req(:SUBSCRIBE, instance, opts)
    |> Map.put(:accept, @content_type)
    |> Map.put(:expires, Keyword.get(opts, :expires, 600))
  end

  defp publish(instance, body) do
    presence_req(:PUBLISH, instance, [])
    |> Map.put(:expires, 3600)
    |> Map.put(:contenttype, @content_type)
    |> Map.put(:body, body)
    |> Map.put(:contentlength, byte_size(body))
  end

  defp presence_req(method, instance, opts) do
    branch = SIP.Msg.Ops.generate_branch_value()
    callid = SIP.Msg.Ops.generate_from_or_to_tag()
    fromtag = SIP.Msg.Ops.generate_from_or_to_tag()

    {:ok, ruri} = SIP.Uri.parse("sip:bob@unit.test")

    %{
      "Max-Forwards" => "70",
      method: method,
      ruri: SIP.Uri.set_uri_param(ruri, "unittest", instance),
      from:
        SIP.Uri.set_header_param(
          %SIP.Uri{scheme: "sip:", userpart: "alice", domain: "unit.test"},
          "tag",
          fromtag
        ),
      to: %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "unit.test"},
      contact: %SIP.Uri{scheme: "sip:", userpart: "alice", domain: "82.184.8.2", port: 53_936},
      event: Keyword.get(opts, :event, "presence"),
      callid: callid,
      cseq: [1, method],
      transid: branch,
      via: ["SIP/2.0/UDP 82.184.8.2:53936;branch=#{branch}"],
      useragent: "Mockup-watcher",
      contentlength: 0
    }
  end

  # The same subscription asked for again: same Call-ID and From tag, next CSeq,
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

  # The bare maps the factory callbacks are called with directly: they never
  # reach the wire, and what is read of them is the Event header.
  defp subscribe_req(event), do: presence_map(:SUBSCRIBE, event)
  defp publish_req(event), do: presence_map(:PUBLISH, event)

  defp presence_map(method, nil), do: %{method: method, ruri: %SIP.Uri{domain: "example.com"}}

  defp presence_map(method, event),
    do: %{method: method, ruri: %SIP.Uri{domain: "example.com"}, event: event}
end
