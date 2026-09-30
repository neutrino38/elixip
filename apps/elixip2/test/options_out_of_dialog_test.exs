defmodule SIP.Test.OptionsOutOfDialog do
  use ExUnit.Case

  @moduledoc """
  An OPTIONS received **outside** any dialog: a capability query, and in practice the
  liveness ping a proxy sends to decide whether this node still takes traffic
  (RFC 3261 §11.2).

  Two properties are pinned here:

    * the answer comes from the module the application registered
      (`SIP.Session.Options`), and 500 when it registered none — there is
      deliberately no framework-wide default, since what a node supports depends on
      the application running on it;
    * **no dialog is created**. OPTIONS is not dialog-forming (§12.1), and the dialog
      this used to create lived 60 s: one lingering process for every ping, forever,
      on any node under monitoring. That half of the test is the one that documents
      the leak.

  In-dialog OPTIONS are a different path (the dialog answers those itself) and are
  covered by SIP.Test.Keepalive.
  """

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _} = SIP.Session.ConfigRegistry.start()
    Application.put_env(:elixip2, :proxyusesrv, false)
    :ok
  end

  setup do
    prev = SIP.Session.ConfigRegistry.get_options_processing_module()
    on_exit(fn -> SIP.Session.ConfigRegistry.set_options_processing_module(prev) end)
    :ok
  end

  # Answers 200 and advertises what it supports.
  defmodule Responder do
    @behaviour SIP.Session.Options

    @impl true
    def on_options(_req, _transaction_id) do
      {:reply, 200, "OK", [{"Allow", "OPTIONS, REGISTER"}]}
    end
  end

  # Answers 503: the node is draining and wants upstream to stop sending traffic.
  defmodule Draining do
    @behaviour SIP.Session.Options

    @impl true
    def on_options(_req, _transaction_id), do: {:reply, 503, "Service Unavailable", []}
  end

  # Leaves the answer to the framework.
  defmodule Defaulting do
    @behaviour SIP.Session.Options

    @impl true
    def on_options(_req, _transaction_id), do: :default
  end

  # Serves the OPTIONS itself: the dialog layer opens a dialog and hands it to
  # `on_new_options/3`, whose app is the test process named in the app env.
  defmodule Dispatching do
    @behaviour SIP.Session.Options

    @impl true
    def on_options(_req, _transaction_id), do: :dispatch

    @impl true
    def on_new_options(_dialog_pid, _req, _transaction_id),
      do: {:accept, Application.get_env(:elixip2, :options_test_app)}
  end

  # Send an out-of-dialog OPTIONS through the mockup transport and return its
  # From-tag and Call-ID — the dialog id it would create, To tag aside.
  defp send_options(callid, ftag \\ nil, cseq \\ 1) do
    ruri =
      %SIP.Uri{scheme: "sip:", domain: "example.com", port: 5060}
      |> SIP.Uri.set_uri_param("unittest", "options_ood")
      |> SIP.Transport.Selector.select_transport()

    :ok = SIP.Test.Transport.Mockup.attach_probe(ruri.tp_pid)

    aor = %SIP.Uri{scheme: "sip:", userpart: "alice", domain: "example.com"}
    ftag = ftag || "ft-#{System.unique_integer([:positive])}"

    req = %{
      "Max-Forwards" => "70",
      method: :OPTIONS,
      ruri: ruri,
      from: SIP.Uri.set_uri_param(aor, "tag", ftag),
      # No To tag: this request claims no dialog.
      to: aor,
      useragent: "Elixipp-test",
      callid: callid,
      cseq: [cseq, :OPTIONS],
      contentlength: 0,
      via: ["SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK#{System.unique_integer([:positive])}"],
      transid: "z9hG4bK#{System.unique_integer([:positive])}"
    }

    SIP.Test.Transport.Mockup.inject(ruri.tp_pid, req)
    {ftag, callid}
  end

  defp dialog_alive?({ftag, callid}) do
    Registry.lookup(Registry.SIPDialog, {ftag, callid, nil}) != []
  end

  test "the registered module decides the answer, and no dialog is created" do
    :ok = SIP.Session.ConfigRegistry.set_options_processing_module(Responder)
    cid = "opt-#{System.unique_integer([:positive])}"

    id = send_options(cid)
    assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid} = resp}}, 2_000

    # The capabilities the module advertised reached the wire…
    assert Map.get(resp, "Allow") == "OPTIONS, REGISTER"
    # …and a response above 100 carries a To tag, which no dialog provided here.
    assert {:ok, _tag} = SIP.Uri.get_uri_param(resp.to, "tag")

    # The leak this fixes: not one process behind.
    Process.sleep(100)
    refute dialog_alive?(id)
  end

  test "a draining node answers 503, so upstream takes it out of rotation" do
    :ok = SIP.Session.ConfigRegistry.set_options_processing_module(Draining)
    cid = "opt-#{System.unique_integer([:positive])}"

    send_options(cid)
    assert_receive {:sip_mockup, {:response_sent, 503, %{callid: ^cid}}}, 2_000
  end

  test "a module answering :default gets a bare 200" do
    :ok = SIP.Session.ConfigRegistry.set_options_processing_module(Defaulting)
    cid = "opt-#{System.unique_integer([:positive])}"

    send_options(cid)
    assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid} = resp}}, 2_000
    refute Map.has_key?(resp, "Allow")
  end

  test "no module registered: 500, and still no dialog" do
    :ok = SIP.Session.ConfigRegistry.set_options_processing_module(nil)
    cid = "opt-#{System.unique_integer([:positive])}"

    id = send_options(cid)
    assert_receive {:sip_mockup, {:response_sent, 500, %{callid: ^cid}}}, 2_000

    Process.sleep(100)
    refute dialog_alive?(id)
  end

  describe "an OPTIONS the application serves itself (:dispatch)" do
    setup do
      :ok = SIP.Session.ConfigRegistry.set_options_processing_module(Dispatching)
      Application.put_env(:elixip2, :options_test_app, self())
      on_exit(fn -> Application.delete_env(:elixip2, :options_test_app) end)
      :ok
    end

    test "reaches the app on a dialog of its own, and the app's answer goes out" do
      cid = "opt-#{System.unique_integer([:positive])}"
      id = send_options(cid)

      assert_receive {:OPTIONS, req, _trans, dlg}, 2_000
      assert dialog_alive?(id)
      # Nothing is answered until the app decides.
      refute_receive {:sip_mockup, {:response_sent, _, %{callid: ^cid}}}, 100

      SIP.Dialog.reply(dlg, req, 404, "Not Found", [])
      assert_receive {:sip_mockup, {:response_sent, 404, %{callid: ^cid}}}, 2_000
    end

    # The re-submission after a 407: same Call-ID and From-tag, no To tag, a new
    # CSeq. It must reach the instance that challenged, not the dialog's own
    # keepalive answer.
    test "a second OPTIONS on the same dialog reaches the app and rearms the lifetime" do
      cid = "opt-#{System.unique_integer([:positive])}"
      {ftag, _} = id = send_options(cid)

      assert_receive {:OPTIONS, req1, _trans, dlg}, 2_000
      SIP.Dialog.reply(dlg, req1, 407, "Proxy Authentication Required", [])
      assert_receive {:sip_mockup, {:response_sent, 407, %{callid: ^cid}}}, 2_000

      first = :erlang.read_timer(:sys.get_state(dlg).expirationtimer)
      assert is_integer(first) and first <= 32_000
      Process.sleep(50)

      send_options(cid, ftag, 2)
      assert_receive {:OPTIONS, %{cseq: [2, :OPTIONS]} = req2, _trans, ^dlg}, 2_000
      refute_received {:sip_mockup, {:response_sent, 200, %{callid: ^cid}}}

      second = :erlang.read_timer(:sys.get_state(dlg).expirationtimer)
      assert second > first

      SIP.Dialog.reply(dlg, req2, 200, "OK", [])
      assert_receive {:sip_mockup, {:response_sent, 200, %{callid: ^cid}}}, 2_000
      assert dialog_alive?(id)
    end
  end

  # The OPTIONS lifetime belongs to a dialog an OPTIONS created. An OPTIONS
  # keepalive we send on an inbound call must leave the call's own timer alone:
  # 32 s instead of 1800 would hang up a call that is working.
  test "an OPTIONS on an inbound INVITE dialog does not arm the OPTIONS lifetime" do
    call = %SIP.DialogImpl{direction: :inbound, msg: %{method: :INVITE}}
    assert SIP.DialogImpl.arm_expiration_timer(call, %{method: :OPTIONS}) == call

    probe = %SIP.DialogImpl{direction: :inbound, msg: %{method: :OPTIONS}}
    armed = SIP.DialogImpl.arm_expiration_timer(probe, %{method: :OPTIONS})
    assert is_reference(armed.expirationtimer)
    :erlang.cancel_timer(armed.expirationtimer)
  end
end
