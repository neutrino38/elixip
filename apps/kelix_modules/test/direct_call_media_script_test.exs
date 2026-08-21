defmodule Kelix.DirectCallMediaScriptTest do
  @moduledoc """
  The media variant of the reference call script
  (`apps/kelixip/scripts/direct-call-with-auth-and-media.exs`) once its
  establishment states became one `SBB.Call.call/1`.

  What it pins down is the part the block does NOT decide. Every outcome of a
  media call leaves through `releasing`, because what the media server holds for
  the call has to be given back whichever way the call ended — so the same
  `{:call, :cancelled, _}` that `direct-call.exs` calls an abort is a release
  here, and the script says so in its own arms. That is requirement S3 of the
  spec, tested rather than asserted in prose.
  """
  use ExUnit.Case, async: false

  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

  alias Kelix.Mod.Registrar

  @domain "example.com"
  @caller "alice"
  @callee "bob"
  @password "secret"
  @ruri "sip:bob@example.com"

  @ha1 SIP.Auth.compute_ha1("MD5", @caller, @domain, @password)

  @offer """
  v=0\r
  o=- 1 1 IN IP4 192.168.1.50\r
  s=-\r
  c=IN IP4 192.168.1.50\r
  t=0 0\r
  m=audio 40000 RTP/AVP 8 0 101\r
  a=rtpmap:8 PCMA/8000\r
  a=rtpmap:0 PCMU/8000\r
  a=rtpmap:101 telephone-event/8000\r
  a=sendrecv\r
  """

  defmodule MockDialog do
    use GenServer
    def start_link(test), do: GenServer.start_link(__MODULE__, test)
    def init(test), do: {:ok, test}

    def handle_call({:replyreq, req, code, reason, fields}, _from, test) do
      send(test, {:replied, code, reason, fields, req})
      {:reply, :ok, test}
    end

    def handle_call({:newreq, req}, _from, test) do
      send(test, {:sent_on_inbound, req})
      {:reply, {:ok, self()}, test}
    end

    def handle_call(_msg, _from, test), do: {:reply, :ok, test}
    def handle_info(_msg, test), do: {:noreply, test}
  end

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()

    %{
      scenario:
        SIP.Scenario.Loader.load_file!(
          Path.expand("../../kelixip/scripts/direct-call-with-auth-and-media.exs", __DIR__)
        )
    }
  end

  setup do
    start_supervised!(Registrar)

    Application.put_env(:kelixip, :authdb_ha1_lookup, fn
      @caller, @domain -> {:ok, @ha1}
      _user, _realm -> :notfound
    end)

    on_exit(fn -> Application.delete_env(:kelixip, :authdb_ha1_lookup) end)
    :ok
  end

  defp contact(peer) do
    %SIP.Uri{userpart: @callee, domain: "10.0.0.9", port: 5060}
    |> SIP.Uri.set_uri_param("unittest", peer)
  end

  defp register_callee(peer) do
    req = %{
      method: :REGISTER,
      to: %SIP.Uri{userpart: @callee, domain: @domain},
      ruri: %SIP.Uri{userpart: @callee, domain: @domain},
      contact: contact(peer),
      expires: 3600,
      callid: "reg-#{peer}"
    }

    {:registered, _granted} = Registrar.save(req, @domain)
    :ok
  end

  defp mockup_pid(peer) do
    tp = SIP.Transport.Selector.select_transport(contact(peer)).tp_pid
    :ok = Mockup.set_peer(tp, Manual)
    :ok = Mockup.attach_probe(tp)
    tp
  end

  defp invite(callid, auth \\ nil) do
    req = %{
      "Max-Forwards" => 70,
      method: :INVITE,
      ruri: %SIP.Uri{userpart: @callee, domain: @domain},
      from: %SIP.Uri{userpart: @caller, domain: @domain, params: %{"tag" => "alice-tag"}},
      to: %SIP.Uri{userpart: @callee, domain: @domain},
      contact: %SIP.Uri{userpart: @caller, domain: "10.0.0.1", port: 5060},
      callid: callid,
      cseq: [1, :INVITE],
      contenttype: "application/sdp",
      body: [%{contenttype: "application/sdp", data: @offer}],
      contentlength: byte_size(@offer)
    }

    if auth, do: Map.put(req, :proxyauthorization, auth), else: req
  end

  defp in_dialog(method, invite) do
    %{invite | method: method, body: [], contentlength: 0, cseq: [2, method]}
  end

  defp credentials(challenge) do
    response =
      SIP.Auth.compute_auth_response_from_ha1(
        "MD5",
        challenge["nonce"],
        @ha1,
        "INVITE",
        @ruri,
        %{"nc" => "00000001", "cnonce" => "0a4f113b", "qop" => "auth"}
      )

    %{
      "username" => @caller,
      "realm" => challenge["realm"],
      "nonce" => challenge["nonce"],
      "uri" => @ruri,
      "response" => response,
      "algorithm" => "MD5",
      "qop" => "auth",
      "nc" => "00000001",
      "cnonce" => "0a4f113b"
    }
  end

  # One instance, with the mockup media adapter and its verdict surfaced.
  defp start_instance(module, dialog, req) do
    test = self()

    {pid, ref} =
      spawn_monitor(fn ->
        outcome =
          SIP.Scenario.Runner.run_instance(module,
            dialog_pid: dialog,
            inbound_request: req,
            config_overrides: [
              domain: @domain,
              mediaserver: %{module: :mockup, url: "http://127.0.0.1:8080"}
            ]
          )

        send(test, {:instance_done, outcome})
      end)

    on_exit(fn -> if Process.alive?(pid), do: send(pid, {:scenario_ctl, :shutdown, :test}) end)
    {pid, ref}
  end

  # Get past the digest gate: the script challenges, the caller answers, and the
  # authenticated INVITE is the one that reaches `call/1`.
  defp authenticated_call(module, dialog, callid) do
    req = invite(callid)
    {instance, ref} = start_instance(module, dialog, req)
    send(instance, {:INVITE, req, self(), dialog})

    assert_receive {:replied, 100, "Trying", _f, _r}, 5_000
    assert_receive {:replied, 407, _reason, fields, _req}, 5_000
    challenge = Keyword.fetch!(fields, :proxyauthenticate)

    auth_req = invite(callid, credentials(challenge))
    send(instance, {:INVITE, auth_req, self(), dialog})
    {instance, ref, auth_req}
  end

  # ── S3: the host names the exits, and here every exit frees the media ───────

  # The same `{:call, :cancelled, _}` that `direct-call.exs` reports as an abort
  # is a RELEASE here: the block says what happened, the script says what it
  # means, and what it means for a media call is that the endpoints go back.
  test "a cancelled call leaves through releasing, not through an abort",
       %{scenario: module} do
    :ok = register_callee("dcm-cancel")
    tp = mockup_pid("dcm-cancel")
    {:ok, dialog} = MockDialog.start_link(self())

    {instance, ref, req} = authenticated_call(module, dialog, "call-media-cancel")

    assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000

    Manual.simulate(tp, 180, 50)
    assert_receive {:replied, 180, _reason, _f, _r}, 5_000

    send(instance, {:CANCEL, in_dialog(:CANCEL, req), self(), dialog})

    # `releasing` runs media_cleanup_ressources() and ends on scenario_success.
    # An {:aborted, _} here would mean the block's outcome went straight to a
    # terminal and the media server kept holding the call's endpoints.
    assert_receive {:instance_done, :ok}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end

  # And the media argument still reaches the forward from inside the block: the
  # INVITE that goes out carries an offer of ours, not the caller's.
  test "the call is established with a media plane and the ACK crosses",
       %{scenario: module} do
    :ok = register_callee("dcm-ok")
    tp = mockup_pid("dcm-ok")
    {:ok, dialog} = MockDialog.start_link(self())

    {instance, ref, req} = authenticated_call(module, dialog, "call-media-ok")
    assert_receive {:sip_mockup, {:request_sent, :INVITE, fwd}}, 5_000

    # Ours: the media server's offer, not the phone's — the caller's connection
    # address is nowhere in what we sent.
    forwarded = SIP.Msg.Ops.sdp_body(fwd)
    assert is_binary(forwarded) and forwarded != ""
    refute forwarded =~ "192.168.1.50"

    # And carried in the top rung of the peer's profile ladder: the registered
    # device is offered DTLS-SRTP over ICE first, whatever the caller offered us.
    assert forwarded =~ "RTP/SAVPF"
    assert forwarded =~ "a=fingerprint:"

    Manual.simulate(tp, 200, 50)
    assert_receive {:replied, 200, _reason, _f, _r}, 5_000

    send(instance, {:ACK, in_dialog(:ACK, req), self(), dialog})
    assert_receive {:sip_mockup, {:request_sent, :ACK, _}}, 5_000

    # Out of the block and in `connected`: a BYE from the caller now ends it, and
    # it too goes out through a release.
    send(instance, {:BYE, in_dialog(:BYE, req), self(), dialog})
    assert_receive {:instance_done, :ok}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end

  # ── The callee's offer profile: one ladder, walked by the framework ─────────

  # A phone that cannot do WebRTC says "not this body" and is offered the next
  # rung on a new INVITE to the same target, without the caller hearing anything
  # about it. `415` rather than `488` on purpose: the script widens `fallback_on`
  # because that is what equipment in the field answers.
  test "a callee refusing the WebRTC offer is re-offered the next rung",
       %{scenario: module} do
    :ok = register_callee("dcm-ladder")
    tp = mockup_pid("dcm-ladder")
    {:ok, dialog} = MockDialog.start_link(self())

    {instance, ref, req} = authenticated_call(module, dialog, "call-media-ladder")

    assert_receive {:sip_mockup, {:request_sent, :INVITE, first}}, 5_000
    assert SIP.Msg.Ops.sdp_body(first) =~ "RTP/SAVPF"

    Manual.simulate(tp, 415, 50)

    # The middle rung: the feedback profile, no DTLS and no ICE.
    assert_receive {:sip_mockup, {:request_sent, :INVITE, second}}, 5_000
    offer = SIP.Msg.Ops.sdp_body(second)
    assert offer =~ "RTP/AVPF"
    refute offer =~ "a=fingerprint:"

    # The caller has heard nothing of the refusal: their first final response is
    # the answer to the call.
    refute_received {:replied, 415, _reason, _f, _r}

    Manual.simulate(tp, 200, 50)
    assert_receive {:replied, 200, _reason, _f, _r}, 5_000

    send(instance, {:ACK, in_dialog(:ACK, req), self(), dialog})
    assert_receive {:sip_mockup, {:request_sent, :ACK, _}}, 5_000

    send(instance, {:BYE, in_dialog(:BYE, req), self(), dialog})
    assert_receive {:instance_done, :ok}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^instance, _}, 5_000
  end
end
