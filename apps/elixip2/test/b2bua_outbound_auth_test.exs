defmodule SIP.Test.B2bua.OutboundAuth do
  @moduledoc """
  A 401/407 from the far end of the outbound leg, answered by the B2BUA itself
  when the peer carries `credentials` (docs/design/sip-server-specs.md, prologue
  "answering a challenge on the B2BUA's outbound leg").

  The caller must never see that challenge: it is addressed to us, for a realm
  that is not the caller's. The request is re-sent once, authenticated, and a
  second challenge is an ordinary failure.
  """
  use ExUnit.Case

  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

  alias SIP.B2bua.Peer
  alias SIP.Session.B2bua

  # The process a peer's `credentials` names. It answers the challenge from a
  # password it holds, and tells the test what it was asked.
  defmodule Credentials do
    use GenServer

    def start_link(test_pid), do: GenServer.start_link(__MODULE__, test_pid)

    @impl true
    def init(test_pid), do: {:ok, test_pid}

    @impl true
    def handle_call({:authorize, code, challenge, method, uri}, _from, test_pid) do
      send(test_pid, {:authorize, code, method, uri})

      params =
        SIP.Auth.build_auth_response(
          challenge["algorithm"] || "MD5",
          "trunkuser",
          challenge["nonce"],
          challenge["realm"],
          "secret",
          :plain,
          method,
          uri
        )

      {:reply, {:ok, params}, test_pid}
    end
  end

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _} = SIP.Session.ConfigRegistry.start()
    :ok
  end

  setup do
    B2bua.forget_event()
    {:ok, stub} = SIP.Test.B2bua.InboundDialogStub.start_link(self())
    on_exit(fn -> if Process.alive?(stub), do: GenServer.stop(stub) end)
    {:ok, creds} = Credentials.start_link(self())
    %{ctx: %SIP.Context{dialogpid: stub}, creds: creds}
  end

  defp target(name) do
    %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "#{name}.example.com", port: 5060}
    |> SIP.Uri.set_uri_param("unittest", name)
  end

  defp peer!(name) do
    tp = SIP.Transport.Selector.select_transport(target(name)).tp_pid
    :ok = Mockup.set_peer(tp, Manual)
    :ok = Mockup.attach_probe(tp)
    tp
  end

  defp inbound_invite do
    {:ok, raw} = File.read(Path.join(__DIR__, "SIP-INVITE-LVP.txt"))
    {:ok, req} = SIPMsg.parse(raw, fn _c, _m, _l, _line -> nil end)
    Map.put(req, :callid, SIP.Msg.Ops.generate_branch_value())
  end

  # The scenario's `proceeding` clause: hand the response that came back on the
  # outbound leg to b2bua_forward_reply.
  defp forward_reply(ctx, dlg, code) do
    assert_receive {:outbound, {^code, resp, tid, ^dlg}}, 3_000
    B2bua.note_event({:outbound, {code, resp, tid, dlg}})
    B2bua.do_relay_reply(ctx, resp)
  end

  test "a challenged INVITE is re-sent authenticated, and the caller sees no 407",
       %{ctx: ctx, creds: creds} do
    tp = peer!("aut1")

    peer = %Peer{uris: [target("aut1")], credentials: creds}
    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)
    assert_receive {:sip_mockup, {:request_sent, :INVITE, first}}, 2_000
    dlg = B2bua.outbound_leg(ctx).dialogpid

    Manual.simulate(tp, 407, 50)
    ctx = forward_reply(ctx, dlg, 407)
    assert ctx.lasterr == :ok

    # Asked for the request as it went out…
    assert_receive {:authorize, 407, :INVITE, uri}, 2_000
    assert uri =~ "aut1.example.com"

    # …and re-sent with the answer, as a new request of the same dialog.
    assert_receive {:sip_mockup, {:request_sent, :INVITE, second}}, 2_000
    assert %{"username" => "trunkuser", "response" => _} = second.proxyauthorization
    assert second.callid == first.callid
    assert hd(second.cseq) > hd(first.cseq)
    refute_receive {:replied, 407, _, _, _}, 200

    # The far end accepts it, and that is what the caller gets.
    Manual.simulate(tp, 200, 50)
    _ctx = forward_reply(ctx, dlg, 200)
    assert_receive {:replied, 200, _reason, _req, _fields}, 2_000
  end

  test "a second challenge to the same request is relayed as a failure",
       %{ctx: ctx, creds: creds} do
    tp = peer!("aut2")

    peer = %Peer{uris: [target("aut2")], credentials: creds}
    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _first}}, 2_000
    dlg = B2bua.outbound_leg(ctx).dialogpid

    Manual.simulate(tp, 407, 50)
    ctx = forward_reply(ctx, dlg, 407)
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _second}}, 2_000

    Manual.simulate(tp, 407, 50)
    _ctx = forward_reply(ctx, dlg, 407)
    assert_receive {:replied, 407, _reason, _req, _fields}, 2_000
    refute_receive {:sip_mockup, {:request_sent, :INVITE, _third}}, 200
  end

  test "without credentials the challenge is relayed as before", %{ctx: ctx} do
    tp = peer!("aut3")

    ctx = B2bua.do_create_leg(ctx, inbound_invite(), %Peer{uris: [target("aut3")]}, false)
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _first}}, 2_000
    dlg = B2bua.outbound_leg(ctx).dialogpid

    Manual.simulate(tp, 407, 50)
    _ctx = forward_reply(ctx, dlg, 407)
    assert_receive {:replied, 407, _reason, _req, _fields}, 2_000
    refute_receive {:authorize, _, _, _}, 100
  end

  test "an in-dialog request challenged is re-sent at the remote target",
       %{ctx: ctx, creds: creds} do
    tp = peer!("aut4")

    peer = %Peer{uris: [target("aut4")], credentials: creds}
    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)
    leg = B2bua.outbound_leg(ctx)
    dlg = leg.dialogpid
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 2_000

    # The call is up first: an in-dialog request needs a dialog.
    Manual.simulate(tp, 200, 50)
    assert_receive {:outbound, {200, _rsp, _tid, ^dlg}}, 3_000
    ctx = B2bua.drop_pending(ctx, leg.initial_trans)

    # The caller refreshes its session; the far end challenges the relayed UPDATE.
    Process.put(:scenario_event_leg, :inbound)
    uri = %SIP.Uri{userpart: nil, domain: nil}

    update = %{
      "Max-Forwards" => "70",
      method: :UPDATE,
      ruri: uri,
      from: uri,
      to: uri,
      useragent: "Elixipp-test",
      callid: nil,
      cseq: [3, :UPDATE],
      contentlength: 0
    }

    ctx = B2bua.do_relay_request(ctx, update)
    assert_receive {:sip_mockup, {:request_sent, :UPDATE, first}}, 2_000

    Manual.simulate(tp, 407, 50)
    ctx = forward_reply(ctx, dlg, 407)

    # The digest covers the Request-URI the dialog addressed it to, not ours.
    {:ok, wire} = SIP.Uri.serialize_ruri(first.ruri)
    assert_receive {:authorize, 407, :UPDATE, ^wire}, 2_000

    assert_receive {:sip_mockup, {:request_sent, :UPDATE, second}}, 2_000
    assert %{"uri" => ^wire} = second.proxyauthorization
    assert hd(second.cseq) > hd(first.cseq)
    refute_receive {:replied, 407, _, _, _}, 200

    B2bua.release_legs(ctx)
  end

  test "a challenged BYE is re-sent, so the call can still end", %{ctx: ctx, creds: creds} do
    tp = SIP.Transport.Selector.select_transport(target("aut5")).tp_pid
    :ok = Mockup.set_peer(tp, Manual, challenge_bye: true)
    :ok = Mockup.attach_probe(tp)

    peer = %Peer{uris: [target("aut5")], credentials: creds}
    ctx = B2bua.do_create_leg(ctx, inbound_invite(), peer, false)
    leg = B2bua.outbound_leg(ctx)
    dlg = leg.dialogpid
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 2_000

    Manual.simulate(tp, 200, 50)
    assert_receive {:outbound, {200, _rsp, _tid, ^dlg}}, 3_000
    ctx = B2bua.drop_pending(ctx, leg.initial_trans)

    # The caller hangs up; the BYE relayed onto the outbound leg is challenged.
    Process.put(:scenario_event_leg, :inbound)
    uri = %SIP.Uri{userpart: nil, domain: nil}

    bye = %{
      "Max-Forwards" => "70",
      method: :BYE,
      ruri: uri,
      from: uri,
      to: uri,
      useragent: "Elixipp-test",
      callid: nil,
      cseq: [3, :BYE],
      contentlength: 0
    }

    ctx = B2bua.do_relay_request(ctx, bye)
    assert_receive {:sip_mockup, {:request_sent, :BYE, first}}, 2_000
    _ctx = forward_reply(ctx, dlg, 407)

    assert_receive {:authorize, 407, :BYE, _uri}, 2_000
    assert_receive {:sip_mockup, {:request_sent, :BYE, second}}, 2_000
    assert %{"response" => _} = second.proxyauthorization
    assert hd(second.cseq) > hd(first.cseq)

    # Accepted this time: the dialog ends.
    ref = Process.monitor(dlg)
    assert_receive {:DOWN, ^ref, :process, ^dlg, _}, 5_000
  end
end
