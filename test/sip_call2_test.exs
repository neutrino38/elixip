defmodule SIP.Test.Call2 do
  use ExUnit.Case
  require SIP.Dialog
  use SIP.Session.CallUAC
  use SIP.Session.Media

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

  # Wait for the player end-of-file event, answering any in-dialog MESSAGE that
  # arrives meanwhile (and ignoring other traffic) so the dialog stays healthy.
  defp wait_for_player_ended(player, timeout) do
    receive do
      {:ms_event, ^player, :player_ended} ->
        :ok

      {:MESSAGE, req, _trans_pid, dialog_pid} ->
        SIP.Dialog.reply(dialog_pid, req, 200, "OK", [])
        wait_for_player_ended(player, timeout)

      _other ->
        wait_for_player_ended(player, timeout)
    after
      timeout -> {:error, :timeout}
    end
  end

  # Wait for the recorder-stopped event, answering any in-dialog MESSAGE that
  # arrives meanwhile (and ignoring other traffic). Returns the stop reason.
  defp wait_for_recorder_stopped(recorder, timeout) do
    receive do
      {:ms_event, ^recorder, {:recorder_stopped, reason}} ->
        {:ok, reason}

      {:MESSAGE, req, _trans_pid, dialog_pid} ->
        SIP.Dialog.reply(dialog_pid, req, 200, "OK", [])
        wait_for_recorder_stopped(recorder, timeout)

      _other ->
        wait_for_recorder_stopped(recorder, timeout)
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
    media_connect(MediaServer.Mockup, "sip:localhost:8080")

    # ── Place the call: INVITE, then re-INVITE with proxy authentication ──────
    send_INVITE(@callee, :mediaserver, [timeout: 90, webrtc: :no])
    assert ctx_get(:lasterr) == :ok

    sip_ctx =
      receive do
        {407, rsp, _trans_pid, _dialog_pid} ->
          send_auth_INVITE(rsp, @callee, :mediaserver, [timeout: 90])
          sip_ctx

        {code, _rsp, _trans_pid, _dialog_pid} when is_integer(code) ->
          flunk("Expected a 407 challenge, got #{code}")
      after
        5_000 -> flunk("No 407 challenge received")
      end

    assert ctx_get(:lasterr) == :ok

    # The media server handle and the peer connection were set up by the
    # INVITE flow (media_connect + get_sdp_offer). Retrieve them from the context.
    server = ctx_get(:mediaserverpid)
    conn = ctx_get(:mediapeerconnectionid)
    assert is_pid(server)
    assert is_pid(conn)

    # ── Wait for the call to be answered (200 OK) ─────────────────────────────
    {:ok, ok_rsp, ok_trans} = wait_for_200(25_000)
    process_invite_reply(ok_rsp)

    # Acknowledge the 200 OK to confirm the dialog.
    CallUAC.ack(sip_ctx, ok_trans)

    # ── Wait until ICE connectivity is established ────────────────────────────
    assert_receive {:ms_event, ^conn, :ice_connected}, 5_000

        # ── Run an echo (media loopback) for 20 seconds ───────────────────────────
    media_start_echo()
    echo = SIP.Context.appdata_get(sip_ctx, :mediaactionid)
    assert is_pid(echo)
    assert_receive {:ms_event, ^echo, :echo_started}, 1_000

    # ── Acknowledge the in-dialog MESSAGE sent by the echo service ────────────
    answer_message(5_000)


    Process.sleep(20_000)

    media_stop()

    # ── Hang up: send BYE and wait for its 200 OK ─────────────────────────────
    send_BYE()
    assert ctx_get(:lasterr) == :ok
    assert_receive {200, _bye_rsp, _trans_pid, _dialog_pid}, 5_000

    # ── Media resources are released automatically on call end ────────────────
    # The dialog layer notifies us when it terminates (after the BYE); we then
    # release every media resource through a single context-driven entry point,
    # instead of calling close_peer_connection/disconnect explicitly.
    assert_receive {:dialog_terminated, _dialog_pid, _reason}, 5_000
    media_cleanup_ressources()

    # Everything has been torn down and cleared from the context.
    refute Process.alive?(conn)
    refute Process.alive?(server)
    assert ctx_get(:mediaserverpid) == nil
    assert SIP.Context.appdata_get(sip_ctx, :mediapeerconnectionid) == nil
  end

  @tag :live
  @tag timeout: 60_000
  test "play" do
    sip_ctx = %SIP.Context{
      username: @username,
      authusername: @authusername,
      displayname: @displayname,
      domain: @domain
    }

    ctx_set(:passwd, @passwd)

    # ── Set up the media server (mockup) and build a local SDP offer ──────────
    media_connect(MediaServer.Mockup, "sip:localhost:8080")

    # ── Place the call: INVITE, then re-INVITE with proxy authentication ──────
    send_INVITE(@callee, :mediaserver, [timeout: 90, webrtc: :no])
    assert ctx_get(:lasterr) == :ok

    sip_ctx =
      receive do
        {407, rsp, _trans_pid, _dialog_pid} ->
          send_auth_INVITE(rsp, @callee, :mediaserver, [timeout: 90])
          sip_ctx

        {code, _rsp, _trans_pid, _dialog_pid} when is_integer(code) ->
          flunk("Expected a 407 challenge, got #{code}")
      after
        5_000 -> flunk("No 407 challenge received")
      end

    assert ctx_get(:lasterr) == :ok

    server = ctx_get(:mediaserverpid)
    conn = ctx_get(:mediapeerconnectionid)
    assert is_pid(server)
    assert is_pid(conn)

    # ── Wait for the call to be answered (200 OK) ─────────────────────────────
    {:ok, ok_rsp, ok_trans} = wait_for_200(25_000)
    process_invite_reply(ok_rsp)
    CallUAC.ack(sip_ctx, ok_trans)

    # ── Wait until ICE connectivity is established ────────────────────────────
    assert_receive {:ms_event, ^conn, :ice_connected}, 5_000

    # ── Play a (fictitious) media file; the mockup plays it for 15 s ──────────
    media_play("toto.mp4")
    player = SIP.Context.appdata_get(sip_ctx, :mediaactionid)
    assert is_pid(player)
    assert_receive {:ms_event, ^player, :player_started}, 1_000

    # ── Hang up at end of file ────────────────────────────────────────────────
    assert wait_for_player_ended(player, 20_000) == :ok

    send_BYE()
    assert ctx_get(:lasterr) == :ok
    assert_receive {200, _bye_rsp, _trans_pid, _dialog_pid}, 5_000

    # ── Media resources are released automatically on call end ────────────────
    assert_receive {:dialog_terminated, _dialog_pid, _reason}, 5_000
    media_cleanup_ressources()

    refute Process.alive?(conn)
    refute Process.alive?(server)
    assert ctx_get(:mediaserverpid) == nil
    assert SIP.Context.appdata_get(sip_ctx, :mediapeerconnectionid) == nil
  end

  @tag :live
  @tag timeout: 60_000
  test "record" do
    sip_ctx = %SIP.Context{
      username: @username,
      authusername: @authusername,
      displayname: @displayname,
      domain: @domain
    }

    ctx_set(:passwd, @passwd)

    # ── Set up the media server (mockup) and build a local SDP offer ──────────
    media_connect(MediaServer.Mockup, "sip:localhost:8080")

    # ── Place the call: INVITE, then re-INVITE with proxy authentication ──────
    send_INVITE(@callee, :mediaserver, [timeout: 90, webrtc: :no])
    assert ctx_get(:lasterr) == :ok

    sip_ctx =
      receive do
        {407, rsp, _trans_pid, _dialog_pid} ->
          send_auth_INVITE(rsp, @callee, :mediaserver, [timeout: 90])
          sip_ctx

        {code, _rsp, _trans_pid, _dialog_pid} when is_integer(code) ->
          flunk("Expected a 407 challenge, got #{code}")
      after
        5_000 -> flunk("No 407 challenge received")
      end

    assert ctx_get(:lasterr) == :ok

    server = ctx_get(:mediaserverpid)
    conn = ctx_get(:mediapeerconnectionid)
    assert is_pid(server)
    assert is_pid(conn)

    # ── Wait for the call to be answered (200 OK) ─────────────────────────────
    {:ok, ok_rsp, ok_trans} = wait_for_200(25_000)
    process_invite_reply(ok_rsp)
    CallUAC.ack(sip_ctx, ok_trans)

    # ── Wait until ICE connectivity is established ────────────────────────────
    assert_receive {:ms_event, ^conn, :ice_connected}, 5_000

    # ── Record to a (fictitious) file for 30 s ────────────────────────────────
    media_record("toto.mp4", 30_000)
    recorder = SIP.Context.appdata_get(sip_ctx, :mediaactionid)
    assert is_pid(recorder)
    assert_receive {:ms_event, ^recorder, :recorder_started}, 1_000

    # ── Hang up when the recording ends (after its 30 s duration) ─────────────
    assert wait_for_recorder_stopped(recorder, 35_000) == {:ok, :duration}

    send_BYE()
    assert ctx_get(:lasterr) == :ok
    assert_receive {200, _bye_rsp, _trans_pid, _dialog_pid}, 5_000

    # ── Media resources are released automatically on call end ────────────────
    assert_receive {:dialog_terminated, _dialog_pid, _reason}, 5_000
    media_cleanup_ressources()

    refute Process.alive?(conn)
    refute Process.alive?(server)
    assert ctx_get(:mediaserverpid) == nil
    assert SIP.Context.appdata_get(sip_ctx, :mediapeerconnectionid) == nil
  end
end
