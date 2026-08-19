defmodule Kelix.AuthSbbTest do
  @moduledoc """
  `Kelix.Mod.AuthDb.SBB.authenticate/1` — the challenge cycle as a service
  building block (design docs/design/evolution-auth-db.md §4).

  Tested here rather than in `:elixip2` for the reason the block lives here: it
  needs a verdict, and the verdict needs a subscriber table. The table is
  injected as a function (`:authdb_ha1_lookup`), so nothing touches MariaDB.
  """
  use ExUnit.Case, async: false

  @domain "example.com"
  @caller "alice"
  @password "secret"
  @ruri "sip:bob@example.com"

  @ha1 SIP.Auth.compute_ha1("MD5", @caller, @domain, @password)

  # A dialog that reports every reply to the test, as the script tests do.
  defmodule MockDialog do
    use GenServer
    def start_link(test), do: GenServer.start_link(__MODULE__, test)
    def init(test), do: {:ok, test}

    def handle_call({:replyreq, _req, code, reason, fields}, _from, test) do
      send(test, {:replied, code, reason, fields})
      {:reply, :ok, test}
    end

    def handle_call(_msg, _from, test), do: {:reply, :ok, test}
    def handle_info(_msg, test), do: {:noreply, test}
  end

  # The smallest host there is: one state that enters the block, and one arm per
  # outcome. Everything it reports goes to the registered probe, so a test can
  # assert on what the block answered without owning the instance.
  defmodule Gate do
    use SIP.Scenario
    use Kelix.Mod.AuthDb

    uas(:invite)

    defp report(what) do
      case Process.whereis(:auth_sbb_probe) do
        nil -> :ok
        pid -> send(pid, what)
      end
    end

    state initial_state do
      on_events do
        {:INVITE, _req, _trans, _dlg} ->
          reply_invite(100, "Trying")
          goto(authenticate_caller)
      after
        5_000 -> scenario_failure("no INVITE")
      end
    end

    state authenticate_caller do
      AuthDb.SBB.authenticate(
        args: %{max_attempts: ctx_get(:max_attempts)},
        timeout: ctx_get(:sbb_timeout) || 32_000
      )

      on_events do
        {:auth, :authenticated, data} ->
          report({:outcome, :authenticated, data, ctx_get(:asserted_identity)})
          scenario_success("authenticated")

        {:auth, :cancelled, data} ->
          report({:outcome, :cancelled, data, nil})
          scenario_success("cancelled")

        {:auth, :caller_gone, data} ->
          report({:outcome, :caller_gone, data, nil})
          scenario_success("caller gone")

        {:auth, :timeout, data} ->
          report({:outcome, :timeout, data, nil})
          scenario_success("timeout")

        {:auth, :refused, data} ->
          report({:outcome, :refused, data, nil})
          scenario_success("refused")
      end
    end

    on_shutdown do
      scenario_aborted("stopped")
    end
  end

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    :ok
  end

  setup do
    Application.put_env(:kelixip, :authdb_ha1_lookup, fn
      @caller, @domain -> {:ok, @ha1}
      _user, _realm -> :notfound
    end)

    Process.register(self(), :auth_sbb_probe)

    on_exit(fn ->
      Application.delete_env(:kelixip, :authdb_ha1_lookup)
    end)

    :ok
  end

  defp invite(auth \\ nil, cseq \\ 1) do
    req = %{
      "Max-Forwards" => 70,
      method: :INVITE,
      ruri: %SIP.Uri{userpart: "bob", domain: @domain},
      from: %SIP.Uri{userpart: @caller, domain: @domain, params: %{"tag" => "alice-tag"}},
      to: %SIP.Uri{userpart: "bob", domain: @domain},
      contact: %SIP.Uri{userpart: @caller, domain: "10.0.0.1", port: 5060},
      callid: "call-sbb-1",
      cseq: [cseq, :INVITE],
      contentlength: 0
    }

    if auth, do: Map.put(req, :proxyauthorization, auth), else: req
  end

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

  defp start_gate(opts \\ []) do
    {:ok, dialog} = MockDialog.start_link(self())
    req = invite()

    {pid, _ref} =
      SIP.Scenario.Runner.spawn_uas_instance(Gate,
        dialog_pid: dialog,
        inbound_request: req,
        config_overrides: [domain: @domain] ++ opts
      )

    on_exit(fn -> if Process.alive?(pid), do: send(pid, {:scenario_ctl, :shutdown, :test}) end)
    send(pid, {:INVITE, req, self(), dialog})
    {pid, dialog}
  end

  defp challenge_received! do
    assert_receive {:replied, 100, "Trying", _f}, 5_000
    assert_receive {:replied, 407, _reason, fields}, 5_000
    Keyword.fetch!(fields, :proxyauthenticate)
  end

  defp resubmit(pid, dialog, auth, cseq) do
    req = invite(auth, cseq)
    send(pid, {:INVITE, req, self(), dialog})
    req
  end

  describe "the challenge cycle" do
    test "an INVITE with no credentials is challenged 407" do
      start_gate()
      challenge = challenge_received!()

      assert challenge["realm"] == @domain
      assert challenge["qop"] == "auth"
      assert SIP.Auth.Nonce.validate(challenge["nonce"], @domain) == :ok
      refute Map.has_key?(challenge, "stale")
    end

    test "credentials that check out end the block, and record the identity" do
      {pid, dialog} = start_gate()
      challenge = challenge_received!()
      resubmit(pid, dialog, credentials(challenge), 2)

      # The re-submitted INVITE gets its own 100: it is a new transaction.
      assert_receive {:replied, 100, "Trying", _f}, 5_000

      assert_receive {:outcome, :authenticated, data, asserted}, 5_000
      assert data.user == @caller
      assert data.realm == @domain

      # …and the identity is in the context, ready for the forward to assert.
      assert asserted == %SIP.Uri{
               scheme: "sip:",
               userpart: @caller,
               domain: @domain
             }
    end

    test "a wrong password is answered 403 and the block keeps waiting" do
      {pid, dialog} = start_gate()
      challenge = challenge_received!()

      wrong = SIP.Auth.compute_ha1("MD5", @caller, @domain, "not-the-password")
      resubmit(pid, dialog, credentials(challenge, ha1: wrong), 2)

      assert_receive {:replied, 100, "Trying", _f}, 5_000
      assert_receive {:replied, 403, _reason, _fields}, 5_000

      # One request's verdict is not the end of the conversation: the block is
      # still there, and a client that fixes its credentials is served.
      refute_receive {:outcome, _, _, _}, 300

      resubmit(pid, dialog, credentials(challenge, nc: "00000002"), 3)
      assert_receive {:outcome, :authenticated, _data, _asserted}, 5_000
    end

    test "an unknown user is answered 403, like a wrong password" do
      {pid, dialog} = start_gate()
      challenge = challenge_received!()

      resubmit(pid, dialog, credentials(challenge, username: "mallory"), 2)
      assert_receive {:replied, 403, _reason, _fields}, 5_000
      refute_receive {:outcome, _, _, _}, 300
    end
  end

  describe "giving up" do
    test "max_attempts bounds the rejected attempts, and says how many" do
      {pid, dialog} = start_gate(max_attempts: 2)
      challenge = challenge_received!()
      wrong = SIP.Auth.compute_ha1("MD5", @caller, @domain, "not-the-password")

      resubmit(pid, dialog, credentials(challenge, ha1: wrong), 2)
      assert_receive {:replied, 403, _r, _f}, 5_000
      refute_receive {:outcome, :refused, _, _}, 300

      resubmit(pid, dialog, credentials(challenge, ha1: wrong, nc: "00000002"), 3)
      assert_receive {:replied, 403, _r, _f}, 5_000

      assert_receive {:outcome, :refused, data, _}, 5_000
      assert data.attempts == 2
      assert data.code == 403
    end

    test "max_attempts: :infinity answers forever, as the scripts did before" do
      {pid, dialog} = start_gate(max_attempts: :infinity)
      challenge = challenge_received!()
      wrong = SIP.Auth.compute_ha1("MD5", @caller, @domain, "not-the-password")

      for nc <- ["00000002", "00000003", "00000004", "00000005"] do
        resubmit(pid, dialog, credentials(challenge, ha1: wrong, nc: nc), 2)
        assert_receive {:replied, 403, _r, _f}, 5_000
      end

      refute_receive {:outcome, :refused, _, _}, 300
    end
  end

  describe "the block's own deadline" do
    # The `after 32_000` the two states used to carry, which was never a property
    # of a call flow but of how long a challenge is worth waiting for: a UA
    # replays one within a second, and what does not is a scanner or a phone with
    # a wrong password.
    test "a caller that never comes back is given up on, as an outcome" do
      start_gate(sbb_timeout: 300)
      challenge_received!()

      assert_receive {:outcome, :timeout, data, _}, 5_000
      assert data.block == Kelix.Mod.AuthDb.SBB.Authenticate
    end
  end

  describe "the caller goes away" do
    test "a CANCEL on the challenged attempt ends the block, not the dialog" do
      {pid, dialog} = start_gate()
      challenge_received!()

      send(pid, {:CANCEL, invite(), self(), dialog})
      assert_receive {:outcome, :cancelled, %{}, _}, 5_000
    end

    test "a dialog that ends while we wait comes back as caller_gone, with why" do
      {pid, dialog} = start_gate()
      challenge_received!()

      send(pid, {:dialog_terminated, dialog, :timeout})
      assert_receive {:outcome, :caller_gone, %{reason: :timeout}, _}, 5_000
    end
  end
end
