defmodule SIP.Test.Register do
  use ExUnit.Case
  import SIP.Test.Wait
  require SIP.Dialog
  doctest SIP.Dialog
  use SIP.Session.RegisterUAC

  # Account to use for tests
  # Account to use for tests (centralized in config/test.exs)
  @account Application.compile_env(:elixip2, :test_account)
  @username @account.username
  @authusername @account.authusername
  @displayname @account.displayname
  @domain @account.domain
  @proxy @account.proxy
  @passwd @account.passwd

  setup_all do
    SIP.Test.AppEnv.preserve_proxy()

    # Initialize transaction and transport layers
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    { :ok, _config_pid } = SIP.Session.ConfigRegistry.start()
    Application.put_env(:elixip2, :proxyusesrv, false)
    :ok
  end

  # Reset proxyuri to default (UDP) before each test to prevent contamination
  # between tests that override the transport protocol.
  setup do
    Application.put_env(:elixip2, :proxyuri, %SIP.Uri{ domain: @proxy, scheme: "sip:", port: 5060 })
    :ok
  end

  # The 200 OK to a REGISTER lists ALL active bindings of the account
  # (RFC 3261 10.3) — ours plus any left by other transports or previous
  # runs. Assert that one of them was granted the expiration we requested.
  defp assert_a_binding_expires(contact, expected) do
    expires_list =
      contact
      |> List.wrap()
      |> Enum.map(&SIP.Uri.get_uri_param(&1, "expires"))

    assert {:ok, expected} in expires_list,
           "no contact binding with expires=#{expected} in #{inspect(contact)}"
  end

  # The :test_registrar process is a named singleton shared by every test
  # file that registers TestRegistrar (TCP/TLS/WSS listener tests do): it
  # survives across tests and keeps counting. Stop any leftover instance so
  # this test counts only its own REGISTER.
  defp reset_test_registrar() do
    case Process.whereis(:test_registrar) do
      nil ->
        :ok

      pid ->
        send(pid, {:stop, self()})

        receive do
          count when is_integer(count) -> :ok
        after
          1_000 -> :ok
        end

        # wait for the name to be released before going on
        until!(fn -> Process.whereis(:test_registrar) == nil end, 1_000)
    end
  end


  # The exchange every "Client Register using <transport>" test performs: ask for a
  # lifetime, get challenged, authenticate, and check the 200 granted what we asked
  # for. It was copy-pasted once per transport — four times, differing only in the
  # proxy URI the caller sets.
  #
  # A macro, not a function, and that is not a style choice: `send_REGISTER` and its
  # siblings thread the context by rebinding `var!(sip_ctx)` in the CALLER's scope
  # (SIPSessionRegister.ex:201-226). Inside a `defp` the rebinding lands on the
  # function's own local and is dropped on return, so the caller keeps a context that
  # never registered anything — which is precisely how a first attempt at this broke
  # "OPTIONS and unREGISTER": its `send_OPTIONS()` had no registration to send on and
  # the proxy answered :methodnotallowed.
  defmacrop register_and_authenticate(expires) do
    quote do
      expires = unquote(expires)

      send_REGISTER(expires)
      assert ctx_get(:lasterr) == :ok

      # Each receive hands the (rebound) context back and it is assigned on, the shape
      # the four copies used: the macros rebind inside the clause, and the clause is
      # the only place that value can be read from.
      var!(sip_ctx) =
        receive do
          {401, rsp, _trans_pid, _dialog_pid} ->
            send_auth_REGISTER(rsp, expires)
            var!(sip_ctx)
        after
          2_000 -> flunk("no 401 challenge to the REGISTER")
        end

      # send_sip_request consumes the dialog layer's {:onnewdialog, :ok, tid} and
      # stores the initial transaction in the context.
      assert is_pid(ctx_get(:last_uac_register_tid))

      var!(sip_ctx) =
        receive do
          {200, rsp, _trans_pid, _dialog_pid} ->
            assert_a_binding_expires(rsp.contact, to_string(expires))
            var!(sip_ctx)

          {resp_code, _rsp, _trans_pid, _dialog_pid} when is_integer(resp_code) ->
            flunk("Received unexpected SIP response #{resp_code}")

          other ->
            flunk("Received unexpected msg #{inspect(other)}")
        after
          2_000 -> flunk("no 200 OK to the authenticated REGISTER")
        end

      var!(sip_ctx)
    end
  end

  defp test_context do
    %SIP.Context{
      username: @username,
      authusername: @authusername,
      displayname: @displayname,
      domain: @domain
    }
  end

  test "Inbound REGISTER" do
    # Define module as registrar module
    :ok = SIP.Session.ConfigRegistry.set_registration_processing_module(TestRegistrar)

    # Discard any registration count accumulated by other test files
    reset_test_registrar()

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
    upd_uri = SIP.Uri.set_uri_param(parsed_msg.ruri, "unittest", "sip_register")
    parsed_msg = SIP.Msg.Ops.update_sip_msg( parsed_msg, { :ruri, upd_uri })

    upd_uri = SIP.Transport.Selector.select_transport(upd_uri)

    # Simulate a received REGISTER by UDP mockeup transport
    SIP.Test.Transport.Mockup.inject(upd_uri.tp_pid, parsed_msg)

    # Attendre l'apparition du processus test_registrar
    registrar_pid = until!(fn -> Process.whereis(:test_registrar) end, 2_000)

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

  # The same client REGISTER over each transport the stack offers. Only the proxy URI
  # differs — the exchange is `register_and_authenticate/2` for all of them — and it
  # had been written out four times, ~40 lines apiece. UDP takes the setup's default,
  # so it names no URI of its own.
  @register_transports [
    {"UDP", nil},
    {"TCP", %SIP.Uri{domain: @proxy, proto: "TCP", scheme: "sip:", port: 5060}},
    {"TLS", %SIP.Uri{domain: @proxy, proto: "TLS", scheme: "sip:", port: 5061}},
    {"WSS", %SIP.Uri{domain: @proxy, proto: "WSS", scheme: "sip:", port: 443}}
  ]

  for {transport, proxy_uri} <- @register_transports do
    @tag :live
    @proxy_uri proxy_uri
    test "Client Register using #{transport}" do
      sip_ctx = test_context()
      ctx_set(:passwd, @passwd)
      if @proxy_uri, do: Application.put_env(:elixip2, :proxyuri, @proxy_uri)

      register_and_authenticate(600)
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


  # What this adds over "Client Register using TLS" above is the rest of the
  # registration's life: a keepalive OPTIONS in the middle, then an un-REGISTER, on a
  # registration that really was established. The initial exchange is the shared one.
  @tag :live
  test "OPTIONS and unREGISTER on an established TLS registration" do
    sip_ctx = test_context()
    ctx_set(:passwd, @passwd)

    Application.put_env(:elixip2, :proxyuri, %SIP.Uri{
      domain: @proxy,
      proto: "TLS",
      scheme: "sip:",
      port: 5061
    })

    register_and_authenticate(600)

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
        send_auth_REGISTER(rsp, 0)
        sip_ctx
    end

    assert ctx_get(:lasterr) == :ok
    ^sip_ctx = receive do
      { 200, rsp, _trans_pid, _dialog_pid } ->
        contact = Map.get(rsp, :contact)
        if contact != nil do
          nil
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


end
