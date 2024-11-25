defmodule SIP.Test.Register do
  use ExUnit.Case
  require SIP.Dialog
  doctest SIP.Dialog
  use SIP.Session.RegisterUAC

  defmodule TestRegistrar do
    use SIP.Session.Registrar
    require Logger
    @behaviour SIP.Session.Registrar


    defp registrar_process_loop(state) do
      receive do
        { :REGISTER, reg, _trans_pid, dialog_pid } ->
          # If a register message is received, replay 200 OK
          Logger.info("REGISTRAR: replying to REGISTER")
          SIP.Dialog.reply(dialog_pid, reg, 200, "OK", [])
          Logger.info("REGISTRAR: processed an inbound REGISTER")
          # then increase the register counter
          registrar_process_loop(%{state | registered: state.registered + 1 })

        { :stop, caller_pid } ->
          send(caller_pid, state.registered)
          nil
      end
    end

    @impl true
    def on_new_registration(dialog_id, _register) do
      Logger.info("on_new_registration called in test")
      case Process.whereis(:test_registrar) do
        nil ->
          state = %{ registered: 0, dialogid: dialog_id }
          new_reg_pid = spawn_link(fn -> registrar_process_loop(state) end)
          Logger.info("Created dummy registrar process #{inspect(new_reg_pid)}")
          # Register the process
          Process.register(new_reg_pid, :test_registrar)
          { :accept, new_reg_pid }

        registrar_pid when is_pid(registrar_pid) ->
          { :accept, registrar_pid }
      end
    end

    @impl true
    def on_registration_expired(_dialog_pid, _app_pid) do
      nil
    end
  end

  setup_all do
    # Initialize transaction and transport layers
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    { :ok, _config_pid } = SIP.Session.ConfigRegistry.start()
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

    { :ok, _t_mod, t_pid, _dest_ip, _port } = SIP.Transport.Selector.select_transport(upd_uri, false)

    # Simulate a received REGISTER by UDP mockeup transport
    send(t_pid, { :recv, parsed_msg})

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

  test "Client Register" do
    sip_ctx = %SIP.Context{
      username: "33970262547",
      authusername: "33970262547",
      displayname: "Test User",
      domain: "visioassistance.net"
    }

    proxyuri = %SIP.Uri{ domain: "sip.visioassistance.net", scheme: "sip:", port: 5060 }
    Application.put_env(:elixip2, :proxyuri, proxyuri)
    ctx_set :passwd, "crtv2user1"

    send_REGISTER 600
    assert ctx_get(:lasterr) == :ok


    ^sip_ctx = receive do
      { resp_code, rsp, _trans_pid, _dialog_pid } ->
        assert resp_code == 401
        send_auth_REGISTER(rsp, 600)
        sip_ctx
    end

    ^sip_ctx = receive do
      { resp_code, _rsp, _trans_pid, _dialog_pid } ->
        assert resp_code == 200
        sip_ctx

      _ -> assert(false, "Received unexpected msg")

    after
      1_000 -> assert(false, "Did not receive 200 OK on time")
    end

  end
end
