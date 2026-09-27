defmodule Kelix.DialogStateEndToEndTest do
  @moduledoc """
  The call occupancy of two users, end to end (docs/design/dialog-state-plan.md,
  DS6): a real INVITE from Alice, routed by the kelixip router to the reference
  `direct-call-with-auth.exs`, authenticated, relayed to Bob's registered
  contact — two real dialogs, each stamped by the module that proves its far
  end — and what `Kelix.Mod.DialogState` makes of them in presence.

  The watchers are the test process, registered on the four resources (each
  user's `dialog` and `presence` packages) the way a notifier instance is: what
  presence pushes to it is what a BLF key and a buddy list would be NOTIFYed.

  The suite runs on a domain of its own: other suites leave stamped dialogs
  alive, and this one reads every stamped dialog there is.
  """
  use ExUnit.Case, async: false

  alias Kelix.Mod.{DialogState, Presence, Registrar}
  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

  @domain "blf.example"
  @password "secret"
  @script Path.expand("../../kelixip/scripts/direct-call-with-auth.exs", __DIR__)
  @registrar_script Path.expand("../../kelixip/scripts/registrar-presence.exs", __DIR__)

  # Alice's phone losing the answer to the BYE: it answers everything else as
  # Manual does, so the BYE's transaction has to retransmit.
  defmodule ByeLostPeer do
    @moduledoc false
    use SIP.Test.Peer

    @impl true
    def on_request(%{method: :BYE}, state), do: {[], state}
    def on_request(req, state), do: default_request(req, state)
  end

  setup do
    Kelix.Test.Fixtures.serve_domains("""
    [[domain]]
    name = "#{@domain}"

      [domain.registrar]
      script = "#{@registrar_script}"

      [[domain.call]]
      default = true
      script = "#{@script}"

      [[domain.presence]]
      event-package = "presence"
      subscribe = "presence-subscribe.exs"

      [[domain.presence]]
      event-package = "dialog"
      subscribe = "presence-subscribe.exs"
    """)

    Application.put_env(:kelixip, :authdb_ha1_lookup, fn
      user, @domain when user in ["alice", "bob"] ->
        {:ok, SIP.Auth.compute_ha1("MD5", user, @domain, @password)}

      _user, _realm ->
        :notfound
    end)

    on_exit(fn -> Application.delete_env(:kelixip, :authdb_ha1_lookup) end)

    start_supervised!(Registrar)
    start_supervised!(Presence)
    start_supervised!({DialogState, retry_ms: 20})

    # What the script's load-time contract checks (`uses_modules`): the modules
    # a node configured with them would have registered.
    Kelix.Test.Fixtures.with_module("registrar", Registrar)
    Kelix.Test.Fixtures.with_module("auth_db", Kelix.Mod.AuthDb)
    :ok
  end

  # ── the two handsets ─────────────────────────────────────────────────────────

  defp handset(user, instance) do
    %SIP.Uri{userpart: user, domain: "10.0.0.#{byte_size(instance)}", port: 5060}
    |> SIP.Uri.set_uri_param("unittest", instance)
  end

  defp peer!(uri) do
    tp = SIP.Transport.Selector.select_transport(uri).tp_pid
    :ok = Mockup.set_peer(tp, Manual)
    :ok = Mockup.attach_probe(tp)
    tp
  end

  # Bob's phone registered, and reported so, as registrar-presence.exs does.
  defp register_bob(instance) do
    req = %{
      method: :REGISTER,
      to: %SIP.Uri{userpart: "bob", domain: @domain},
      ruri: %SIP.Uri{userpart: "bob", domain: @domain},
      contact: handset("bob", instance),
      expires: 3600,
      callid: "reg-" <> instance
    }

    {:registered, _} = Registrar.save(req, @domain)
    :ok = Presence.registration_changed(@domain, "bob")
    peer!(handset("bob", instance))
  end

  # Alice's INVITE as it comes off the wire, on her own transport.
  defp invite(instance, callid, cseq, auth \\ nil) do
    branch = SIP.Msg.Ops.generate_branch_value()

    ruri =
      %SIP.Uri{scheme: "sip:", userpart: "bob", domain: @domain}
      |> SIP.Uri.set_uri_param("unittest", instance)
      |> SIP.Transport.Selector.select_transport()

    req = %{
      "Max-Forwards" => "70",
      method: :INVITE,
      ruri: ruri,
      from: %SIP.Uri{
        scheme: "sip:",
        userpart: "alice",
        domain: @domain,
        hparams: %{"tag" => "alice-" <> callid}
      },
      to: %SIP.Uri{scheme: "sip:", userpart: "bob", domain: @domain},
      contact: handset("alice", instance),
      callid: callid,
      cseq: [cseq, :INVITE],
      transid: branch,
      via: ["SIP/2.0/UDP 10.0.0.1:5060;branch=#{branch}"],
      useragent: "alice-test",
      contentlength: 0
    }

    if auth, do: Map.put(req, :proxyauthorization, auth), else: req
  end

  defp credentials(challenge) do
    uri = "sip:bob@#{@domain}"
    ha1 = SIP.Auth.compute_ha1("MD5", "alice", @domain, @password)
    params = %{"nc" => "00000001", "cnonce" => "0a4f113b", "qop" => "auth"}

    # The shape SIPMsg parses a Proxy-Authorization into; the mockup serialises
    # what it injects, and the scheme is the `:authproc` key.
    %{
      :authproc => "Digest",
      "username" => "alice",
      "realm" => challenge["realm"],
      "nonce" => challenge["nonce"],
      "uri" => uri,
      "response" =>
        SIP.Auth.compute_auth_response_from_ha1(
          "MD5",
          challenge["nonce"],
          ha1,
          "INVITE",
          uri,
          params
        ),
      "algorithm" => "MD5",
      "qop" => "auth",
      "nc" => "00000001",
      "cnonce" => "0a4f113b"
    }
  end

  # Alice calls: challenged, answers the challenge, and the call is relayed.
  defp alice_calls(alice_tp, instance, callid) do
    Mockup.inject(alice_tp, invite(instance, callid, 1))
    assert_receive {:sip_mockup, {:response_sent, 407, rsp}}, 5_000
    challenge = rsp.proxyauthenticate
    authenticated = invite(instance, callid, 2, credentials(challenge))
    Mockup.inject(alice_tp, authenticated)
    assert_receive {:sip_mockup, {:request_sent, :INVITE, _fwd}}, 5_000
    authenticated
  end

  # ── the watchers ─────────────────────────────────────────────────────────────

  defp watch(user, package) do
    sub =
      %SIP.Subscription{
        callid: "watch-#{user}-#{package}",
        event: package,
        presentity_uri: "sip:#{user}@#{@domain}",
        watcher_username: "carol",
        watcher_domain: @domain
      }
      |> SIP.Subscription.put_status(:active)
      |> SIP.Subscription.grant(3600)

    {:ok, doc} = Presence.watch(@domain, sub)
    doc
  end

  # The pushes to one resource, until one satisfies `pred`.
  defp await_doc(user, package, pred, timeout \\ 5_000) do
    resource = {user, @domain, package}

    receive do
      {:presence, :state, ^resource, doc} ->
        if pred.(doc), do: doc, else: await_doc(user, package, pred, timeout)
    after
      timeout -> flunk("#{user}'s #{package} never reached the expected state")
    end
  end

  defp dialogs(doc), do: Enum.map(doc.dialogs, &{&1.direction, &1.state})
  defp activity(%SIP.Presence.Doc{} = doc), do: {SIP.Presence.Doc.status(doc), doc.activity}

  test "ringing, answered, hung up: both BLF keys and both presences follow the call" do
    alice_tp = peer!(handset("alice", "blf-a1"))
    bob_tp = register_bob("blf-b1")

    assert %SIP.DialogInfo.Doc{dialogs: []} = watch("alice", "dialog")
    assert %SIP.DialogInfo.Doc{dialogs: []} = watch("bob", "dialog")
    assert activity(watch("alice", "presence")) == {:closed, nil}
    assert activity(watch("bob", "presence")) == {:open, nil}
    {:ok, %{dialogs: []}} = DialogState.subscribe_dialogs(@domain, self())

    alice_calls(alice_tp, "blf-a1", "blf-call-1")

    # 1. Bob rings: Alice placed a call that is early, Bob received one.
    Manual.simulate(bob_tp, 180, 0)
    await_doc("alice", "dialog", &(dialogs(&1) == [{:initiator, :early}]))
    await_doc("bob", "dialog", &(dialogs(&1) == [{:recipient, :early}]))
    # a ringing phone is not on the phone
    refute_received {:presence, :state, {_, @domain, "presence"}, _}

    # 2. Bob answers: both confirmed, both on the phone.
    Manual.simulate(bob_tp, 200, 0)
    assert_receive {:sip_mockup, {:response_sent, 200, ok}}, 5_000
    Mockup.inject(alice_tp, ack(ok))

    await_doc("alice", "dialog", &(dialogs(&1) == [{:initiator, :confirmed}]))
    await_doc("bob", "dialog", &(dialogs(&1) == [{:recipient, :confirmed}]))
    assert activity(await_doc("alice", "presence", &(&1 != nil))) == {:open, :on_the_phone}
    assert activity(await_doc("bob", "presence", &(&1 != nil))) == {:open, :on_the_phone}

    # 3. Bob hangs up: no call left, and each presence back to what it was.
    Manual.hangup(bob_tp)
    await_doc("alice", "dialog", &(dialogs(&1) == []))
    await_doc("bob", "dialog", &(dialogs(&1) == []))
    assert activity(await_doc("alice", "presence", & &1)) == {:closed, nil}
    assert activity(await_doc("bob", "presence", & &1)) == {:open, nil}

    # Why each leg ended, read from its user's side: Bob hung up his own call,
    # and Alice's was ended by the BYE this node relayed to her. The challenge
    # she answered first is no refusal.
    assert %{event: :remote_bye} = ended_row("sip:bob@blf.example")
    assert %{event: :local_bye} = ended_row("sip:alice@blf.example")
  end

  # The BYE relayed to Alice leaves just as the script ends. Her leg must
  # outlive the script until that BYE is answered: stopping it killed the
  # transaction, and on UDP a lost BYE was never sent again.
  test "the BYE relayed to the caller is retransmitted after the script has ended" do
    alice_tp = peer!(handset("alice", "blf-a3"))
    :ok = Mockup.set_peer(alice_tp, ByeLostPeer)
    bob_tp = register_bob("blf-b3")

    alice_calls(alice_tp, "blf-a3", "blf-call-3")
    Manual.simulate(bob_tp, 200, 0)
    assert_receive {:sip_mockup, {:response_sent, 200, ok}}, 5_000
    Mockup.inject(alice_tp, ack(ok))

    watch("alice", "dialog")
    Manual.hangup(bob_tp)
    assert_receive {:sip_mockup, {:request_sent, :BYE, %{callid: "blf-call-3"}}}, 5_000

    # Her key goes dark with the BYE, not with its answer (RFC 3261 §15.1.1)…
    await_doc("alice", "dialog", &(&1.dialogs == []))

    # …while the BYE itself is sent again until she answers it.
    assert_receive {:sip_mockup, {:request_sent, :BYE, %{callid: "blf-call-3"}}}, 3_000
  end

  defp ended_row(aor) do
    receive do
      {:kelix_dialogs, @domain, {:upsert, %{aor: ^aor, state: :terminated} = row}} -> row
    after
      5_000 -> flunk("no terminated row for #{aor}")
    end
  end

  test "a call Alice cancels while Bob rings ends cancelled, never on the phone" do
    alice_tp = peer!(handset("alice", "blf-a2"))
    bob_tp = register_bob("blf-b2")
    {:ok, %{dialogs: []}} = DialogState.subscribe_dialogs(@domain, self())
    watch("alice", "presence")
    watch("bob", "presence")

    authenticated = alice_calls(alice_tp, "blf-a2", "blf-call-2")
    Manual.simulate(bob_tp, 180, 0)

    assert_receive {:kelix_dialogs, @domain,
                    {:upsert, %{aor: "sip:bob@blf.example", state: :early}}},
                   5_000

    Mockup.inject(alice_tp, cancel(authenticated))

    assert_receive {:kelix_dialogs, @domain,
                    {:upsert,
                     %{aor: "sip:alice@blf.example", state: :terminated, event: alice_event}}},
                   5_000

    assert_receive {:kelix_dialogs, @domain,
                    {:upsert, %{aor: "sip:bob@blf.example", state: :terminated, event: bob_event}}},
                   5_000

    assert alice_event == :cancelled
    assert bob_event == :cancelled
    refute_received {:kelix_dialogs, @domain, {:upsert, %{state: :confirmed}}}
    refute_received {:presence, :state, {_, @domain, "presence"}, _}
  end

  # Alice's ACK to the 2xx she was relayed: in the dialog, our tag on To.
  defp ack(ok) do
    branch = SIP.Msg.Ops.generate_branch_value()
    [cseq, _] = ok.cseq

    %{
      "Max-Forwards" => "70",
      method: :ACK,
      ruri: ok.contact || ok.to,
      from: ok.from,
      to: ok.to,
      callid: ok.callid,
      cseq: [cseq, :ACK],
      transid: branch,
      via: ["SIP/2.0/UDP 10.0.0.1:5060;branch=#{branch}"],
      contentlength: 0
    }
  end

  # CANCEL matches the INVITE's transaction: same branch, same CSeq number.
  defp cancel(invite) do
    [cseq, :INVITE] = invite.cseq
    %{invite | method: :CANCEL, cseq: [cseq, :CANCEL]} |> Map.delete(:proxyauthorization)
  end
end
