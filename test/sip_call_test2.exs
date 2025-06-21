defmodule SIP.Test.Call2 do
  use ExUnit.Case
  require SIP.Dialog
  doctest SIP.Session.CallUAC

  alias SIP.Session.CallUAC

  require MediaServer.Mockup

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

  test "echo call" do
  sip_ctx = %SIP.Context{
      username: @username,
      authusername: @authusername,
      displayname: @displayname,
      domain: @domain
    }

    ctx_set :passwd, @passwd

    # Create the RTC connection
    { :ok, mediapid } = MediaServer.Mockup.createRTCConnection(
      "localhost", self(), [ webrtc_support: :no ])
    assert is_pid(mediapid)

    ctx_set :mediapid, mediapid

    # Create an echo media resource
    { :ok, echo_id } = MediaServer.Mockup.createMediaEcho(mediapid)

    #Connect the echo to the RTC connection
    :ok == MediaServer.Mockup.connectStream(mediapid, :outbound, [ media_type: { :audio, :video, :text } ], :echo, echo_id)
    :ok == MediaServer.Mockup.connectStream(mediapid, :inbbound, [ media_type: { :audio, :video, :text } ], :echo, echo_id)

    # Obtain local offer
    { :ok, offer } = MediaServer.Mockup.getLocalOffer(mediapid)

    send_INVITE("90901@visioassistance.net", offer, 90)

    ^sip_ctx = receive do
      { 407, rsp, _trans_pid, _dialog_pid } ->
        send_auth_INVITE(rsp, "90901@visioassistance.net", offer, 90)
        sip_ctx
    end

  end
end
