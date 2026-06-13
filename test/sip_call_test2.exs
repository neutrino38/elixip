defmodule SIP.Test.Call2 do
  use ExUnit.Case
  require SIP.Dialog
  doctest SIP.Session.CallUAC

  alias SIP.Session.CallUAC

  # Account to use for tests (centralized in config/test.exs)
  @account Application.compile_env(:elixip2, :test_account)
  @username @account.username
  @authusername @account.authusername
  @displayname @account.displayname
  @domain @account.domain
  @proxy @account.proxy
  @passwd @account.passwd

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _config_pid} = SIP.Session.ConfigRegistry.start()

    Application.put_env(:elixip2, :proxyuri, %SIP.Uri{domain: @proxy, scheme: "sip:", port: 5060})
    Application.put_env(:elixip2, :proxyusesrv, false)
    :ok
  end

  test "echo call" do
    sip_ctx = %SIP.Context{
      username: @username,
      authusername: @authusername,
      displayname: @displayname,
      domain: @domain
    }

    ctx_set(:passwd, @passwd)

    {:ok, server} = MediaServer.Mockup.connect({"localhost", 8080})
    assert is_pid(server)

    {:ok, conn} = MediaServer.Mockup.create_peer_connection(server, self(), webrtc_support: :no)
    assert is_pid(conn)

    ctx_set(:conn, conn)

    {:ok, echo} = MediaServer.Mockup.create_echo(conn)
    assert is_pid(echo)

    {:ok, offer} = MediaServer.Mockup.get_local_offer(conn)
    assert is_binary(offer)

    send_INVITE("90901@visioassistance.net", offer, 90)

    ^sip_ctx =
      receive do
        {407, rsp, _trans_pid, _dialog_pid} ->
          send_auth_INVITE(rsp, "90901@visioassistance.net", offer, 90)
          sip_ctx
      end
  end
end
