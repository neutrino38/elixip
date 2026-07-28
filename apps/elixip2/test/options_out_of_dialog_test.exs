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

  # Send an out-of-dialog OPTIONS through the mockup transport and return its
  # Call-ID, the transport pid and the dialog id it would have created.
  defp send_options(callid) do
    ruri =
      %SIP.Uri{scheme: "sip:", domain: "example.com", port: 5060}
      |> SIP.Uri.set_uri_param("unittest", "1")
      |> SIP.Transport.Selector.select_transport()

    :ok = GenServer.call(ruri.tp_pid, :settestapp)

    aor = %SIP.Uri{scheme: "sip:", userpart: "alice", domain: "example.com"}
    ftag = "ft-#{System.unique_integer([:positive])}"

    req = %{
      "Max-Forwards" => "70",
      method: :OPTIONS,
      ruri: ruri,
      from: SIP.Uri.set_uri_param(aor, "tag", ftag),
      # No To tag: this request claims no dialog.
      to: aor,
      useragent: "Elixipp-test",
      callid: callid,
      cseq: [1, :OPTIONS],
      contentlength: 0,
      via: ["SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK#{System.unique_integer([:positive])}"],
      transid: "z9hG4bK#{System.unique_integer([:positive])}"
    }

    send(ruri.tp_pid, {:recv, req})
    {ftag, callid}
  end

  defp dialog_alive?({ftag, callid}) do
    Registry.lookup(Registry.SIPDialog, {ftag, callid, nil}) != []
  end

  test "the registered module decides the answer, and no dialog is created" do
    :ok = SIP.Session.ConfigRegistry.set_options_processing_module(Responder)
    cid = "opt-#{System.unique_integer([:positive])}"

    id = send_options(cid)
    assert_receive {:uas_response, 200, %{callid: ^cid} = resp}, 2_000

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
    assert_receive {:uas_response, 503, %{callid: ^cid}}, 2_000
  end

  test "a module answering :default gets a bare 200" do
    :ok = SIP.Session.ConfigRegistry.set_options_processing_module(Defaulting)
    cid = "opt-#{System.unique_integer([:positive])}"

    send_options(cid)
    assert_receive {:uas_response, 200, %{callid: ^cid} = resp}, 2_000
    refute Map.has_key?(resp, "Allow")
  end

  test "no module registered: 500, and still no dialog" do
    :ok = SIP.Session.ConfigRegistry.set_options_processing_module(nil)
    cid = "opt-#{System.unique_integer([:positive])}"

    id = send_options(cid)
    assert_receive {:uas_response, 500, %{callid: ^cid}}, 2_000

    Process.sleep(100)
    refute dialog_alive?(id)
  end
end
