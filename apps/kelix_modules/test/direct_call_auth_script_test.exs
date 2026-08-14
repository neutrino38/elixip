defmodule Kelix.DirectCallWithAuthScriptTest do
  @moduledoc """
  The authenticated variant of the reference call script
  (`apps/kelixip/scripts/direct-call-with-auth.exs`): the same relay as
  `direct-call.exs`, gated on a digest the caller must produce.

  Tested here for the same reason `b2bua_script_test.exs` is — this is the only
  app where both halves exist (the script, and the `auth_db` / `registrar`
  modules it calls). The subscriber table is injected as a function
  (`:authdb_ha1_lookup`), so nothing touches MariaDB; the callee is reached
  through the in-process UDP mockup.
  """
  use ExUnit.Case, async: false

  alias Kelix.Mod.Registrar

  @domain "example.com"
  @caller "alice"
  @callee "bob"
  @password "secret"
  @ruri "sip:bob@example.com"

  @ha1 SIP.Auth.compute_ha1("MD5", @caller, @domain, @password)

  defmodule MockDialog do
    use GenServer
    def start_link(test), do: GenServer.start_link(__MODULE__, test)
    def init(test), do: {:ok, test}

    def handle_call({:replyreq, req, code, reason, fields}, _from, test) do
      send(test, {:replied, code, reason, fields, req})
      {:reply, :ok, test}
    end

    # A dialog also ORIGINATES: what the callee sends is relayed onto this leg.
    # The transaction pid handed back is this process — the B2BUA correlation only
    # ever compares it, never calls it. Without this clause the catch-all answered
    # `:ok`, which the relay reads as a failure ({:b2bua, :relay_failed, …}).
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
          Path.expand("../../kelixip/scripts/direct-call-with-auth.exs", __DIR__)
        )
    }
  end

  setup do
    start_supervised!(Registrar)

    # The subscriber base: alice is known, anyone else is not.
    Application.put_env(:kelixip, :authdb_ha1_lookup, fn
      @caller, @domain -> {:ok, @ha1}
      _user, _realm -> :notfound
    end)

    on_exit(fn -> Application.delete_env(:kelixip, :authdb_ha1_lookup) end)
    :ok
  end

  # Bob's handset, registered at an address that routes to the mockup.
  defp contact(host, peer) do
    %SIP.Uri{userpart: @callee, domain: host, port: 5060}
    |> SIP.Uri.set_uri_param("unittest", peer)
  end

  defp register_callee(host \\ "10.0.0.9", peer \\ "auth1") do
    req = %{
      method: :REGISTER,
      to: %SIP.Uri{userpart: @callee, domain: @domain},
      ruri: %SIP.Uri{userpart: @callee, domain: @domain},
      contact: contact(host, peer),
      expires: 3600,
      callid: "reg-#{host}-#{peer}"
    }

    {:registered, _granted} = Registrar.save(req, @domain)
    :ok
  end

  defp mockup_pid(peer \\ "auth1") do
    tp = SIP.Transport.Selector.select_transport(contact("10.0.0.9", peer)).tp_pid
    :ok = GenServer.call(tp, :settestapp)
    tp
  end

  # An INVITE arriving for bob@example.com, with or without credentials.
  defp invite(auth \\ nil, cseq \\ 1) do
    req = %{
      "Max-Forwards" => 70,
      method: :INVITE,
      ruri: %SIP.Uri{userpart: @callee, domain: @domain},
      from: %SIP.Uri{userpart: @caller, domain: @domain, params: %{"tag" => "alice-tag"}},
      to: %SIP.Uri{userpart: @callee, domain: @domain},
      contact: %SIP.Uri{userpart: @caller, domain: "10.0.0.1", port: 5060},
      callid: "call-auth-1",
      cseq: [cseq, :INVITE],
      contentlength: 0
    }

    if auth, do: Map.put(req, :proxyauthorization, auth), else: req
  end

  # What a UA answers a 407 with: the digest of the challenge it just received,
  # in the qop=auth form every current client uses. `:nc` is the request counter —
  # a client increments it at every reuse of the nonce, and reusing a value is a
  # replay (`Kelix.NonceCache`), which is why each attempt below passes its own.
  defp credentials(challenge, opts \\ []) do
    nc = Keyword.get(opts, :nc, "00000001")
    cnonce = "0a4f113b"

    response =
      SIP.Auth.compute_auth_response_from_ha1(
        "MD5",
        challenge["nonce"],
        Keyword.get(opts, :ha1, @ha1),
        "INVITE",
        @ruri,
        %{"nc" => nc, "cnonce" => cnonce, "qop" => "auth"}
      )

    %{
      "username" => Keyword.get(opts, :username, @caller),
      "realm" => challenge["realm"],
      "nonce" => challenge["nonce"],
      "uri" => @ruri,
      "response" => response,
      "algorithm" => "MD5",
      "qop" => "auth",
      "nc" => nc,
      "cnonce" => cnonce
    }
  end

  defp spawn_call(module, dialog, req) do
    {pid, _ref} =
      SIP.Scenario.Runner.spawn_uas_instance(module,
        dialog_pid: dialog,
        inbound_request: req,
        config_overrides: [domain: @domain]
      )

    on_exit(fn -> if Process.alive?(pid), do: send(pid, {:scenario_ctl, :shutdown, :test}) end)
    pid
  end

  # The 407 the script sends, and the challenge params it carries.
  defp challenge_received! do
    assert_receive {:replied, 100, "Trying", _f, _r}, 5_000
    assert_receive {:replied, 407, reason, fields, _req}, 5_000
    assert reason == SIP.Msg.Ops.sip_reason(407)
    Keyword.fetch!(fields, :proxyauthenticate)
  end

  test "an INVITE with no credentials is challenged 407, and no call goes out",
       %{scenario: module} do
    :ok = register_callee()
    _tp = mockup_pid()

    {:ok, dialog} = MockDialog.start_link(self())
    req = invite()
    pid = spawn_call(module, dialog, req)
    send(pid, {:INVITE, req, self(), dialog})

    challenge = challenge_received!()

    # A proxy challenge, with a nonce this node can verify and the qop every
    # current UA needs to answer.
    assert challenge["realm"] == @domain
    assert challenge["qop"] == "auth"
    assert challenge["algorithm"] == "MD5"
    assert SIP.Auth.Nonce.validate(challenge["nonce"], @domain) == :ok
    refute Map.has_key?(challenge, "stale")

    # Nothing is relayed on the strength of an unauthenticated INVITE.
    refute_receive {:invite_sent, _fwd}, 500
  end

  test "the INVITE that comes back with a valid digest is relayed to the registered contact",
       %{scenario: module} do
    :ok = register_callee()
    _tp = mockup_pid()

    {:ok, dialog} = MockDialog.start_link(self())
    pid = spawn_call(module, dialog, invite())
    send(pid, {:INVITE, invite(), self(), dialog})

    challenge = challenge_received!()

    # Same dialog, new CSeq: the retry lands on the same instance.
    authenticated = invite(credentials(challenge), 2)
    send(pid, {:INVITE, authenticated, self(), dialog})

    assert_receive {:invite_sent, fwd}, 5_000
    assert fwd.ruri.userpart == @callee
    assert fwd.ruri.domain == "10.0.0.9"
  end

  # The whole call, ended by the CALLEE — the half no suite covered, and where the
  # 481 of 2026-08-12 came from: the teardown asked the outbound leg whether it was
  # still established, the dialog said yes although Bob had just BYEd it, and Bob
  # was sent a second BYE he answered "481 Call/Transaction Does Not Exist".
  test "when the callee hangs up, its BYE is relayed and answered — and it gets nothing more",
       %{scenario: module} do
    :ok = register_callee("10.0.0.19", "auth_bye")
    tp = mockup_pid("auth_bye")

    {:ok, dialog} = MockDialog.start_link(self())
    pid = spawn_call(module, dialog, invite())
    ref = Process.monitor(pid)
    send(pid, {:INVITE, invite(), self(), dialog})

    challenge = challenge_received!()
    send(pid, {:INVITE, invite(credentials(challenge), 2), self(), dialog})
    assert_receive {:invite_sent, _fwd}, 5_000

    # Bob answers, Alice's ACK is relayed: the call is up on both legs.
    GenServer.cast(tp, {:simulate, 200, 0})
    assert_receive {:replied, 200, _reason, _fields, _req}, 5_000
    send(pid, {:ACK, %{invite(nil, 2) | method: :ACK, cseq: [2, :ACK]}, nil, dialog})
    assert_receive :ACK, 5_000

    # Bob hangs up.
    SIP.Test.Transport.UDPMockup.hangup(tp)

    # His BYE crosses to Alice, in her own dialog…
    assert_receive {:sent_on_inbound, bye}, 5_000
    assert bye.method == :BYE

    # …and the leg he closed ends there and then, which is what the instance is
    # waiting for in `wait_far_bye_ok`. Promptly: a dialog that stays established
    # takes the state's 5 s "BYE unanswered" timeout instead.
    assert_receive {:DOWN, ^ref, :process, ^pid, _}, 2_000

    # Bob, who is done, is sent nothing at all — a `:BYE` here is the teardown's,
    # on a dialog Bob closed himself, and what he answers it is 481. Longer than
    # the timeout above on purpose: that is when it used to go out.
    refute_receive :BYE, 8_000
  end

  test "a wrong password is refused 403, and the caller may still try again",
       %{scenario: module} do
    :ok = register_callee()
    _tp = mockup_pid()

    {:ok, dialog} = MockDialog.start_link(self())
    pid = spawn_call(module, dialog, invite())
    send(pid, {:INVITE, invite(), self(), dialog})

    challenge = challenge_received!()

    wrong = credentials(challenge, ha1: SIP.Auth.compute_ha1("MD5", @caller, @domain, "wrong"))
    send(pid, {:INVITE, invite(wrong, 2), self(), dialog})

    assert_receive {:replied, 403, "Forbidden", _fields, _req}, 5_000
    refute_receive {:invite_sent, _fwd}, 500

    # The instance is still there — a client that fixes its credentials gets its
    # call, instead of the silence a dead instance would answer with.
    good = credentials(challenge, nc: "00000002")
    send(pid, {:INVITE, invite(good, 3), self(), dialog})
    assert_receive {:invite_sent, fwd}, 5_000
    assert fwd.ruri.domain == "10.0.0.9"
  end

  test "an unknown subscriber is refused 403 too, and no call goes out",
       %{scenario: module} do
    :ok = register_callee()
    _tp = mockup_pid()

    {:ok, dialog} = MockDialog.start_link(self())
    pid = spawn_call(module, dialog, invite())
    send(pid, {:INVITE, invite(), self(), dialog})

    challenge = challenge_received!()
    send(pid, {:INVITE, invite(credentials(challenge, username: "mallory"), 2), self(), dialog})

    assert_receive {:replied, 403, "Forbidden", _fields, _req}, 5_000
    refute_receive {:invite_sent, _fwd}, 500
  end

  test "the script declares both modules it needs", %{scenario: module} do
    assert module.__scenario_type__() == :uas_invite
    assert module.__scenario_config__()[:uses_modules] == [:registrar, :auth_db]
  end
end
