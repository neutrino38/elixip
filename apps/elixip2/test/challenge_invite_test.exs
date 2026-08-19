defmodule SIP.Test.ChallengeInvite do
  use ExUnit.Case, async: true

  @moduledoc """
  `challenge_invite/2` and the dead-dialog protection of `do_reply_invite/4`
  (design docs/design/evolution-auth-db.md §4.5).
  """

  alias SIP.Session.CallUAS

  defp ctx_with(dialogpid) do
    %SIP.Context{dialogpid: dialogpid}
    |> SIP.Context.appdata_set(:last_uas_req, %{method: :INVITE, ruri: "sip:bob@example.com"})
  end

  describe "do_challenge_invite/3" do
    test "407 lands in Proxy-Authenticate, 401 in WWW-Authenticate" do
      assert SIP.Msg.Ops.challenge_header(407) == :proxyauthenticate
      assert SIP.Msg.Ops.challenge_header(401) == :wwwauthenticate
    end

    test "refuses a code that is not a challenge" do
      assert_raise FunctionClauseError, fn ->
        CallUAS.do_challenge_invite(ctx_with(self()), %{"realm" => "x"}, 403)
      end
    end
  end

  describe "do_reply_invite/4 on a dialog that has died" do
    test "sets lasterr instead of exiting" do
      # A pid that is gone: replying to it exits, which used to reach the
      # per-state try and fail the scenario.
      dead = spawn(fn -> :ok end)
      ref = Process.monitor(dead)
      assert_receive {:DOWN, ^ref, :process, ^dead, _}

      ctx = CallUAS.do_reply_invite(ctx_with(dead), 407, "Proxy Authentication Required", [])
      assert ctx.lasterr == :dialogterminated
    end

    test "a challenge on a dead dialog reports the same way" do
      dead = spawn(fn -> :ok end)
      ref = Process.monitor(dead)
      assert_receive {:DOWN, ^ref, :process, ^dead, _}

      ctx = CallUAS.do_challenge_invite(ctx_with(dead), %{"realm" => "example.com"}, 407)
      assert ctx.lasterr == :dialogterminated
    end
  end
end
