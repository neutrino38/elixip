defmodule SIP.Test.Call2 do
  use ExUnit.Case
  require SIP.Dialog
  use SIP.Session.CallUAC

  alias SIP.Session.CallUAC

  # Account to use for tests (centralized in config/test.exs)
  @account Application.compile_env(:elixip2, :test_account)
  @username @account.username
  @authusername @account.authusername
  @displayname @account.displayname
  @domain @account.domain
  @proxy @account.proxy
  @passwd @account.passwd

  @callee "sip:90901@#{@domain}"

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _config_pid} = SIP.Session.ConfigRegistry.start()

    Application.put_env(:elixip2, :proxyuri, %SIP.Uri{domain: @proxy, scheme: "sip:", port: 5060})
    Application.put_env(:elixip2, :proxyusesrv, false)
    :ok
  end


  # Wait for the final 200 OK, ignoring provisional (1xx) responses.
  defp wait_for_200(timeout) do
    receive do
      {200, rsp, trans_pid, _dialog_pid} ->
        {:ok, rsp, trans_pid}

      {code, _rsp, _trans_pid, _dialog_pid} when is_integer(code) and code >= 100 and code < 200 ->
        wait_for_200(timeout)

      {code, _rsp, _trans_pid, _dialog_pid} when is_integer(code) ->
        {:error, code}
    after
      timeout -> {:error, :timeout}
    end
  end

  # Extract the SDP answer payload from a response message.
  defp extract_sdp(rsp) do
    case Map.get(rsp, :body) do
      body when is_binary(body) ->
        body

      [%{data: data} | _] ->
        data

      list when is_list(list) ->
        case Enum.find(list, fn part -> to_string(part[:contenttype]) =~ "sdp" end) do
          %{data: data} -> data
          _ -> nil
        end

      _ ->
        nil
    end
  end

  # Wait for an in-dialog MESSAGE forwarded by the dialog layer and answer it
  # with a 200 OK. Returns the received request message.
  defp answer_message(timeout) do
    receive do
      {:MESSAGE, req, _trans_pid, dialog_pid} ->
        :ok = SIP.Dialog.reply(dialog_pid, req, 200, "OK", [])
        {:ok, req}
    after
      timeout -> {:error, :timeout}
    end
  end

  @tag :live
  @tag timeout: 60_000
  test "echo call" do
    sip_ctx = %SIP.Context{
      username: @username,
      authusername: @authusername,
      displayname: @displayname,
      domain: @domain
    }

    ctx_set(:passwd, @passwd)

    # ── Set up the media server (mockup) and build a local SDP offer ──────────
    {:ok, server} = MediaServer.Mockup.connect({"localhost", 8080})
    assert is_pid(server)

    {:ok, conn} = MediaServer.Mockup.create_peer_connection(server, self(), webrtc_support: :no)
    assert is_pid(conn)

    {:ok, offer} = MediaServer.Mockup.get_local_offer(conn)
    assert is_binary(offer)

    # ── Place the call: INVITE, then re-INVITE with proxy authentication ──────
    send_INVITE(@callee, offer, 90)
    assert ctx_get(:lasterr) == :ok

    sip_ctx =
      receive do
        {407, rsp, _trans_pid, _dialog_pid} ->
          send_auth_INVITE(rsp, @callee, offer, 90)
          sip_ctx

        {code, _rsp, _trans_pid, _dialog_pid} when is_integer(code) ->
          flunk("Expected a 407 challenge, got #{code}")
      after
        5_000 -> flunk("No 407 challenge received")
      end

    assert ctx_get(:lasterr) == :ok

    # ── Wait for the call to be answered (200 OK) ─────────────────────────────
    {:ok, ok_rsp, ok_trans} = wait_for_200(25_000)

    # Acknowledge the 200 OK to confirm the dialog.
    CallUAC.ack(sip_ctx, ok_trans)

    # Feed the remote SDP answer to the media server; this starts ICE checks.
    answer = extract_sdp(ok_rsp)
    assert is_binary(answer)
    :ok = MediaServer.Mockup.set_remote_answer(conn, answer)
    # ── Wait until ICE connectivity is established ────────────────────────────
    assert_receive {:ms_event, ^conn, :ice_connected}, 5_000

        # ── Run an echo (media loopback) for 20 seconds ───────────────────────────
    {:ok, echo} = MediaServer.Mockup.create_echo(conn)
    assert is_pid(echo)
    assert_receive {:ms_event, ^echo, :echo_started}, 1_000

    # ── Acknowledge the in-dialog MESSAGE sent by the echo service ────────────
    answer_message(5_000)


    Process.sleep(20_000)

    :ok = MediaServer.Mockup.stop_echo(echo)

    # ── Hang up: send BYE and wait for its 200 OK ─────────────────────────────
    send_BYE()
    assert ctx_get(:lasterr) == :ok
    assert_receive {200, _bye_rsp, _trans_pid, _dialog_pid}, 5_000

    # ── Tear down the media server resources ──────────────────────────────────
    :ok = MediaServer.Mockup.close_peer_connection(conn)
    :ok = MediaServer.Mockup.disconnect(server, [])
  end
end
