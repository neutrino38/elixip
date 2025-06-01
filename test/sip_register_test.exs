defmodule SIP.Test.Register do
  use ExUnit.Case
  require SIP.Dialog
  doctest SIP.Dialog
  use SIP.Session.RegisterUAC

  # Account to use for tests
  @username "33970262547"
  @authusername "33970262547"
  @displayname "CRT V2 User"
  @domain "visioassistance.net"
  @proxy "testsip.djanah.com"
  @passwd "crtv2user1"

  setup_all do
    # Initialize transaction and transport layers
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    { :ok, _config_pid } = SIP.Session.ConfigRegistry.start()

    # Force SIP proxy / registrar
    Application.put_env(:elixip2, :proxyuri, %SIP.Uri{ domain: @proxy, scheme: "sip:", port: 5060 })
    Application.put_env(:elixip2, :proxyusesrv, false)
    :ok
  end

  # Utility fonction that wait for a named process to appear
  defp assert_appears(procname, timeout) when timeout > 0 do
    case Process.whereis(procname) do
      nil ->
        # Sleep + recurtion
        Process.sleep(10)
        assert_appears(procname, timeout - 10)

      procpid ->
        assert is_pid(procpid)
        procpid
    end
  end

  defp assert_appears(_procname, timeout) when timeout <= 0 do
    assert(false, "registrar process did not launch on time")
  end

  test "Inbound REGISTER" do
    # Define module as registrar module
    :ok = SIP.Session.ConfigRegistry.set_registration_processing_module(TestRegistrar)

    # Load a REGISTER message from a file
    { code, msg } = File.read("test/SIP-REGISTER-LVP.txt")
    assert code == :ok

    # Parse it
    { code, parsed_msg } = SIPMsg.parse(msg, fn code, errmsg, lineno, line ->
			IO.puts("\n" <> errmsg)
			IO.puts("Offending line #{lineno}: #{line}")
			IO.puts("Error code #{code}")
			end)
    assert code == :ok

    # Add unittest param to RURI to trigger UDP mockeup transport selection
    upd_uri = SIP.Uri.set_uri_param(parsed_msg.ruri, "unittest", "1")
    parsed_msg = SIP.Msg.Ops.update_sip_msg( parsed_msg, { :ruri, upd_uri })

    upd_uri = SIP.Transport.Selector.select_transport(upd_uri)

    # Simulate a received REGISTER by UDP mockeup transport
    send(upd_uri.tp_pid, { :recv, parsed_msg})

    # Attendre l'apparition du processus test_registrar
    registrar_pid = assert_appears(:test_registrar, 2000)

    send(registrar_pid, { :stop, self() })


    receive do
      reg_count when is_integer(reg_count) ->
        # One register shgould be processed
        assert reg_count == 1
        Process.sleep(20)

      _ -> assert(false, "Some strange stuff was received")

      # Add Timeout
    end
  end

  test "Context" do
    sip_ctx = %SIP.Context{}
    ctx_set :displayname, "Emmanuel BUU"
    ctx_set :domain, "visioassistance.net"
    ctx_set :username, "33924765453"

    assert  ctx_get(:username) == "33924765453"
    from = ctx_from()
    assert from.displayname == "Emmanuel BUU"
    SIP.Context.set(sip_ctx, :dialogpid, self())

  end

  @tag :live
  test "Client Register using UDP" do

    sip_ctx = %SIP.Context{
      username: @username,
      authusername: @authusername,
      displayname: @displayname,
      domain: @domain
    }

    ctx_set :passwd, @passwd

    send_REGISTER 600
    assert ctx_get(:lasterr) == :ok


    ^sip_ctx = receive do
      { 401, rsp, _trans_pid, _dialog_pid } ->
        send_auth_REGISTER(rsp, 600)
        sip_ctx
    end

    ^sip_ctx = receive do
      { 200, rsp, _trans_pid, _dialog_pid } ->
        # IO.puts(inspect(rsp.contact.params))
        assert SIP.Uri.get_uri_param(rsp.contact, "expires") == {:ok, "600"}
        sip_ctx

      { resp_code, _rsp, _trans_pid, _dialog_pid } when is_integer(resp_code) ->
        assert(false, "Received unexpected SIP response #{resp_code}")

      _ -> assert(false, "Received unexpected msg")

    after
      1_000 -> assert(false, "Did not receive 200 OK on time")
    end

  end

  @tag :live
  test "Client OPTIONS UDP" do

    sip_ctx = %SIP.Context{
      username: @username,
      authusername: @authusername,
      displayname: @displayname,
      domain: @domain
    }


    ctx_set :passwd, @passwd

    send_OPTIONS()
    assert ctx_get(:lasterr) == :ok

    ^sip_ctx = receive do
      { _response, _rsp, _trans_pid, _dialog_pid } ->
        sip_ctx
    after
      1_000 -> assert(false, "Did not receive 200 OK on time")
    end
    Process.sleep(1000)

    # Send a second option
    send_OPTIONS()
    assert ctx_get(:lasterr) == :ok

    ^sip_ctx = receive do
      { _response, _rsp, _trans_pid, _dialog_pid } ->
        sip_ctx
    after
      1_000 -> assert(false, "Did not receive 200 OK on time")
    end

  end

  @tag :live
  test "Client Register using TCP" do

    sip_ctx = %SIP.Context{
      username: @username,
      authusername: @authusername,
      displayname: @displayname,
      domain: @domain
    }

    ctx_set :passwd, @passwd

    Application.put_env(:elixip2, :proxyuri, %SIP.Uri{ domain: @proxy, proto: "TCP", scheme: "sip:", port: 5060 })

    send_REGISTER 600
    assert ctx_get(:lasterr) == :ok


    ^sip_ctx = receive do
      { 401, rsp, _trans_pid, _dialog_pid } ->
        send_auth_REGISTER(rsp, 600)
        sip_ctx
    end

    ^sip_ctx = receive do
      { 200, rsp, _trans_pid, _dialog_pid } ->
        # IO.puts(inspect(rsp.contact.params))
        assert SIP.Uri.get_uri_param(rsp.contact, "expires") == {:ok, "600"}
        sip_ctx

      { resp_code, _rsp, _trans_pid, _dialog_pid } when is_integer(resp_code) ->
        assert(false, "Received unexpected SIP response #{resp_code}")

      _ -> assert(false, "Received unexpected msg")

    after
      1_000 -> assert(false, "Did not receive 200 OK on time")
    end

  end

  @tag :live
  test "Client Register / OPTIONS / unREGISTER using TLS" do

    sip_ctx = %SIP.Context{
      username: @username,
      authusername: @authusername,
      displayname: @displayname,
      domain: @domain
    }

    ctx_set :passwd, @passwd

    Application.put_env(:elixip2, :proxyuri, %SIP.Uri{ domain: @proxy, proto: "TLS", scheme: "sip:", port: 5061 })

    send_REGISTER 600
    assert ctx_get(:lasterr) == :ok


    ^sip_ctx = receive do
      { 401, rsp, _trans_pid, _dialog_pid } ->
        send_auth_REGISTER(rsp, 600)
        sip_ctx
    end

    ^sip_ctx = receive do
      { 200, rsp, _trans_pid, _dialog_pid } ->
        # IO.puts(inspect(rsp.contact.params))
        assert SIP.Uri.get_uri_param(rsp.contact, "expires") == {:ok, "600"}
        sip_ctx

      { resp_code, _rsp, _trans_pid, _dialog_pid } when is_integer(resp_code) ->
        assert(false, "Received unexpected SIP response #{resp_code}")

      _ -> assert(false, "Received unexpected msg")

    after
      1_000 -> assert(false, "auth REGISTER reply was was not recieved")
    end

    Process.sleep(1000)

    # Send an option
    send_OPTIONS()
    assert ctx_get(:lasterr) == :ok

    ^sip_ctx = receive do
      { _response, _rsp, _trans_pid, _dialog_pid } ->
        sip_ctx
    after
      1_000 -> assert(false, "Did not OPTIONS reply")
    end

    Process.sleep(1000)

    send_REGISTER 0
    assert ctx_get(:lasterr) == :ok


    ^sip_ctx = receive do
      { 401, rsp, _trans_pid, _dialog_pid } ->
        IO.puts("We received 401.")
        send_auth_REGISTER(rsp, 0)
        sip_ctx
    end

    assert ctx_get(:lasterr) == :ok
    ^sip_ctx = receive do
      { 200, rsp, _trans_pid, _dialog_pid } ->
        contact = Map.get(rsp, :contact)
        if contact != nil do
          assert SIP.Uri.get_uri_param(rsp.contact, "expires") == {:ok, "0"}
        else
          assert contact == nil
        end
        # IO.puts(inspect(rsp.contact.params))
        sip_ctx

      { resp_code, _rsp, _trans_pid, _dialog_pid } when is_integer(resp_code) ->
        assert(false, "Received unexpected SIP response #{resp_code}")

      _ -> assert(false, "Received unexpected msg")

    after
      2_000 -> assert(false, "un REGISTER reply not received")
    end

  end

  @tag :live
  test "Client Register using WSS" do

    sip_ctx = %SIP.Context{
      username: @username,
      authusername: @authusername,
      displayname: @displayname,
      domain: @domain
    }

    ctx_set :passwd, @passwd

    Application.put_env(:elixip2, :proxyuri, %SIP.Uri{ domain: @proxy, proto: "WSS", scheme: "sip:", port: 443 })

    send_REGISTER 600
    assert ctx_get(:lasterr) == :ok


    ^sip_ctx = receive do
      { 401, rsp, _trans_pid, _dialog_pid } ->
        send_auth_REGISTER(rsp, 600)
        sip_ctx
    end

    ^sip_ctx = receive do
      { 200, rsp, _trans_pid, _dialog_pid } ->
        # IO.puts(inspect(rsp.contact.params))
        assert SIP.Uri.get_uri_param(rsp.contact, "expires") == {:ok, "600"}
        sip_ctx

      { resp_code, _rsp, _trans_pid, _dialog_pid } when is_integer(resp_code) ->
        assert(false, "Received unexpected SIP response #{resp_code}")

      _ -> assert(false, "Received unexpected msg")

    after
      1_000 -> assert(false, "Did not receive 200 OK on time")
    end

  end

end
