defmodule SIP.Test.SubscriptionChallenged do
  @moduledoc """
  A subscription whose initial SUBSCRIBE was challenged: the dialog is created by
  the unauthenticated request and established by the 2xx to its authenticated
  replay, which carries a CSeq of its own.
  """

  use ExUnit.Case, async: false

  alias SIP.Test.Transport.Mockup

  @challenge %{
    "realm" => "unit.test",
    "nonce" => "nonce",
    "algorithm" => "MD5",
    "qop" => "auth",
    :authproc => "Digest"
  }

  defmodule Notifier do
    @moduledoc false
    use SIP.Scenario
    use SIP.Session.CallUAS
    uas(:presence)
    config(domain: "unit.test")

    state initial_state do
      goto(challenge)
    end

    state challenge do
      on_events do
        {:SUBSCRIBE, _req, _t, _d} ->
          challenge_request(appdata_get(:challenge), 401)
          goto(authorize, "challenged")
      after
        5_000 -> scenario_failure("no SUBSCRIBE received")
      end
    end

    state authorize do
      on_events do
        {:SUBSCRIBE, _req, _t, _d} ->
          {:ok, _sub} = accept_subscription(package: SIP.Test.EventPackages.Dummy.name())
          notify("open")
          goto(subscribed, "200 + NOTIFY")
      after
        5_000 -> scenario_failure("no replay received")
      end
    end

    # The un-SUBSCRIBE is challenged too, and its replay never comes: the
    # deadline it armed is what ends the subscription.
    state subscribed do
      on_events do
        {:SUBSCRIBE, _req, _t, _d} ->
          challenge_request(appdata_get(:challenge), 401)
          goto(ending, "un-SUBSCRIBE challenged")
      after
        10_000 -> scenario_failure("no un-SUBSCRIBE received")
      end
    end

    state ending do
      on_events do
        {:subscription_terminated, _ref, reason} -> scenario_success("#{reason}")
        {:dialog_terminated, _d, reason} -> scenario_failure("dialog gone: #{inspect(reason)}")
      after
        10_000 -> scenario_failure("the subscription never ended")
      end
    end
  end

  defmodule WatcherPeer do
    @moduledoc false
    use SIP.Test.Peer

    # A 200 to a NOTIFY carries no Contact, as Linphone's does not.
    @impl true
    def on_request(%{method: :NOTIFY} = req, state) do
      {[reply(req, 200, "OK", [], 10)], state}
    end

    def on_request(req, state), do: default_request(req, state)
  end

  setup_all do
    {:ok, _} = SIP.Session.ConfigRegistry.start()
    SIP.Test.AppEnv.preserve_proxy()
    Application.put_env(:elixip2, :proxyusesrv, false)

    :ok = SIP.EventPackage.register(SIP.Test.EventPackages.Dummy, origin: :builtin)
    on_exit(fn -> SIP.EventPackage.unregister(SIP.Test.EventPackages.Dummy) end)
    :ok
  end

  test "the final NOTIFY goes to the watcher's Contact" do
    SIP.Test.PresenceUAS.serve(Notifier, %{challenge: @challenge})

    {:ok, uri} = SIP.Uri.parse("sip:bob@unit.test")
    ruri = SIP.Uri.set_uri_param(uri, "unittest", "subscription-challenged")
    tp = SIP.Transport.Selector.select_transport(ruri).tp_pid
    :ok = Mockup.attach_probe(tp)
    :ok = Mockup.set_peer(tp, WatcherPeer)

    req = subscribe(ruri, 1, 3600)
    cid = req.callid

    Mockup.inject(tp, req)
    assert_receive {:sip_mockup, {:response_sent, 401, %{callid: ^cid}}}, 2_000

    Mockup.inject(tp, subscribe(ruri, 2, 3600))
    assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid}}}, 2_000
    assert_receive {:sip_mockup, {:request_sent, :NOTIFY, %{callid: ^cid}}}, 2_000

    Mockup.inject(tp, subscribe(ruri, 3, 0))
    assert_receive {:sip_mockup, {:response_sent, 401, %{callid: ^cid}}}, 2_000

    assert_receive {:sip_mockup, {:request_sent, :NOTIFY, %{callid: ^cid} = notify}}, 4_000
    assert {:terminated, _params} = SIP.Msg.Ops.subscription_state(notify)
    assert notify.ruri.domain == "82.184.8.2"
  end

  defp subscribe(ruri, cseq, expires) do
    branch = SIP.Msg.Ops.generate_branch_value()

    %{
      "Max-Forwards" => "70",
      method: :SUBSCRIBE,
      ruri: ruri,
      from:
        SIP.Uri.set_header_param(
          %SIP.Uri{scheme: "sip:", userpart: "alice", domain: "unit.test"},
          "tag",
          "watcher-tag"
        ),
      to: %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "unit.test"},
      contact: %SIP.Uri{scheme: "sip:", userpart: "alice", domain: "82.184.8.2", port: 53_936},
      event: SIP.Test.EventPackages.Dummy.name(),
      accept: hd(SIP.Test.EventPackages.Dummy.content_types()),
      expires: expires,
      callid: "subscription-challenged",
      cseq: [cseq, :SUBSCRIBE],
      transid: branch,
      via: ["SIP/2.0/UDP 82.184.8.2:53936;branch=#{branch}"],
      useragent: "Mockup-watcher",
      contentlength: 0
    }
  end
end
