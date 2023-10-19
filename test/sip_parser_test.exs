defmodule SIPParserTest do
  use ExUnit.Case
  doctest SIPUri

  test "Parse an URI that has only a domain" do
		{ code, parsed_uri } = SIPUri.parse("sip:domain.fr")
		assert code == :ok
		assert parsed_uri.domain == "domain.fr"
  end

  test "Parse a simple URI" do

		{ code, parsed_uri } = SIPUri.parse("sip:simple@domain.fr")
		assert code == :ok
		assert parsed_uri.userpart == "simple"
		assert parsed_uri.domain == "domain.fr"
		assert Map.has_key?(parsed_uri, "port") == false
		assert parsed_uri.params == %{}
  end

  test "Parse a faulty SIP URI" do
		{ code, _parsed_uri } = SIPUri.parse("sipp:simple@domain.fr")
		assert code == :invalid_sip_uri_general
	end

  test "Parse an URI with transport parameter" do
		{ code, parsed_uri } = SIPUri.parse("sip:simple@domain.fr:5060;transport=TCP")
			assert code == :ok
			assert parsed_uri.userpart == "simple"
			assert parsed_uri.domain == "domain.fr"
			assert parsed_uri.port == 5060
			assert parsed_uri.params == %{ "transport" => "TCP" }
	end

  test "Parse an URI with <> and transport parameter" do
			{ code, parsed_uri } = SIPUri.parse("<sip:simple@domain.fr:5030>;transport=TCP;rport")
			assert code == :ok
			assert parsed_uri.userpart == "simple"
			assert parsed_uri.domain == "domain.fr"
			assert parsed_uri.port == 5030
			assert parsed_uri.params == %{ "rport" => true, "transport" => "TCP"}
	end

  test "Parse an URI with a display name and several parameters" do
			{ code, parsed_uri } = SIPUri.parse("\"omé tür\" <sip:simple@domain.fr:50>;transport=TCP;rport")
			assert code == :ok
			assert parsed_uri.userpart == "simple"
			assert parsed_uri.domain == "domain.fr"
			assert parsed_uri.port == 50
			assert parsed_uri.params == %{ "rport" => true, "transport" => "TCP"}
			assert parsed_uri.displayname == "omé tür"
	end

	test "Parse an URI with a display name without spece" do
		{ code, parsed_uri } = SIPUri.parse("\"Site%20Arras%20POLE%20EMPLOI\"<sip:+33970260233@visioassistance.net>;tag=8075639")
		assert code == :ok
		assert parsed_uri.params == %{ "tag" => "8075639" }
	end

	test "Serialize a SIP URI" do
		uri = %{
			port: 50,
			scheme: "sip:",
			domain: "domain.fr",
			params: %{"rport" => true, "transport" => "TCP"},
			userpart: "simple",
			displayname: "omé tür"
		}

		{ code, uristr } = SIPUri.serialize(uri)
		assert code == :ok
		assert uristr == "\"om%C3%A9+t%C3%BCr\" <sip:simple@domain.fr:50>;rport;transport=TCP"
	end
  test "Load and parse a REGISTER message" do
    { code, msg } = File.read("test/SIP-REGISTER.txt")
		assert code == :ok

		{ code, parsed_msg } = SIPMsg.parse(msg, fn code, errmsg, lineno, line ->
			IO.puts("\n" <> errmsg)
			IO.puts("Offending line #{lineno}: #{line}")
			IO.puts("Error code #{code}")
		end)

    assert code == :ok
		assert parsed_msg.method == :REGISTER
		assert parsed_msg.ruri.domain == "example.com"
		assert parsed_msg.contact.port == 3246
		assert parsed_msg.proxyauthorization["realm"] == "\"SIP Communications Service\""
		assert parsed_msg.from == "<sip:lynctest8@example.com>;tag=2257063211;epid=22570632"
		assert parsed_msg.callid == "A2B000F95CB8XZRikcdYitb4QBvEr4P2"
  end

	test "Load and parse a spam REGISTER message" do
    { code, msg } = File.read("test/SIP-REGISTER-LVP.txt")
		assert code == :ok

		{ code, parsed_msg } = SIPMsg.parse(msg, fn code, errmsg, lineno, line ->
			IO.puts("\n" <> errmsg)
			IO.puts("Offending line #{lineno}: #{line}")
			IO.puts("Error code #{code}")
		end)

    assert code == :ok
		assert parsed_msg.method == :REGISTER
		assert parsed_msg.ruri.domain == "212.83.152.250"
  end

  test "Load and parse an invalid unREGISTER message" do

		{ code, msg } = File.read("test/SIP-unREGISTER.txt")
		assert code == :ok

		{ code, _parsed_msg } = SIPMsg.parse(msg, fn _code, _errmsg, lineno, line ->
			assert lineno == 1
			assert line == "UNREGISTER sip:example.com SIP/2.0"
			end)
		assert code == :invalid_request
	end

  test "Parse a SIMPLE body with correct content length" do
		{ code, data } = File.read("test/SDP-SIMPLE.txt")
		assert code == :ok

		bodylist = SIPMsg.parse_multi_part_body("application/sdp", data)
		assert code == :ok
		[ body ] = bodylist
		assert body.contenttype == "application/sdp"
		assert body.data == data
	end

  test "Parse an INVITE message with a simple body" do

  	{ code, msg } = File.read("test/SIP-INVITE-BASIC-AUDIO.txt")
		assert code == :ok # Test if file containing the SIP message is loaded

		{ code, parsed_msg } = SIPMsg.parse(msg, fn code, errmsg, lineno, line ->
			IO.puts("\n" <> errmsg)
			IO.puts("Offending line #{lineno}: #{line}")
			IO.puts("Error code #{code}")
			end)

    assert code == :ok
		assert parsed_msg.method == :INVITE
		assert parsed_msg.contenttype == "application/sdp"

		[ body ] = parsed_msg.body
		{ code, data } = File.read("test/SDP-SIMPLE.txt")
		assert code == :ok
		assert body.contenttype == "application/sdp"
		assert body.data == data
  end

  test "Parse an INVITE message with a mixed/multipart body" do
	{ code, msg } = File.read("test/SIP-INVITE-LOST.txt")
  	assert code == :ok # Test if file containing the SIP message is loaded

  	{ code, parsed_msg } = SIPMsg.parse(msg, fn code, errmsg, lineno, line ->
	  IO.puts("\n" <> errmsg)
	  IO.puts("Offending line #{lineno}: #{line}")
	  IO.puts("Error code #{code}")
  	end)

  	assert code == :ok
  	assert parsed_msg.method == :INVITE
  	assert parsed_msg.contenttype == "multipart/mixed; boundary=boundary1"
		assert Kernel.length(parsed_msg.body) == 2
		body2 = Enum.at(parsed_msg.body,1)
		assert body2.contenttype == "application/pidf+xml"
  end

		test "Parse an INVITE message sent by the LiveVideoPlugin" do
			{ code, msg } = File.read("test/SIP-INVITE-LVP.txt")
			assert code == :ok # Test if file containing the SIP message is loaded

			{ code, parsed_msg } = SIPMsg.parse(msg, fn code, errmsg, lineno, line ->
			IO.puts("\n" <> errmsg)
			IO.puts("Offending line #{lineno}: #{line}")
			IO.puts("Error code #{code}")
			end)

			assert code == :ok
			assert parsed_msg.method == :INVITE
			assert parsed_msg.contenttype == "application/sdp"
			assert parsed_msg.transid == "z9hG4bK18d9.829852dcccb559fa7184dc4ab9a406e8.0"
			assert parsed_msg.dialog_id == {"8075639", "32645600-4c01-bc8f-670c-deac31158db8", nil}
		end

		test "Parse an 180 response sent by the LiveVideoPlugin" do
			{ code, msg } = File.read("test/SIP-180-LVP.txt")
			assert code == :ok # Test if file containing the SIP message is loaded

			{ code, parsed_msg } = SIPMsg.parse(msg, fn code, errmsg, lineno, line ->
			IO.puts("\n" <> errmsg)
			IO.puts("Offending line #{lineno}: #{line}")
			IO.puts("Error code #{code}")
			end)

			assert code == :ok
			assert parsed_msg.method == false
			assert parsed_msg.response == 180
			assert parsed_msg.transid == "z9hG4bK18d9.829852dcccb559fa7184dc4ab9a406e8.0"
		end

		test "Parse an 200 response sent by the LiveVideoPlugin" do
			{ code, msg } = File.read("test/SIP-200-LVP.txt")
			assert code == :ok # Test if file containing the SIP message is loaded

			{ code, parsed_msg } = SIPMsg.parse(msg, fn code, errmsg, lineno, line ->
				IO.puts("\n" <> errmsg)
				IO.puts("Offending line #{lineno}: #{line}")
				IO.puts("Error code #{code}")
			end)

			assert code == :ok
			assert parsed_msg.method == false
			assert parsed_msg.response == 200
			assert Kernel.length(parsed_msg.body) == 1
			assert parsed_msg.dialog_id == {"8075639", "32645600-4c01-bc8f-670c-deac31158db8", "as424e7930"}
		end

		test "Parse an BYE then reserialize it then reparse it" do
			{ code, msg } = File.read("test/SIP-BYE-LVP.txt")
			assert code == :ok # Test if file containing the SIP message is loaded

			{ code, parsed_msg } = SIPMsg.parse(msg, fn code, errmsg, lineno, line ->
				IO.puts("\n" <> errmsg)
				IO.puts("Offending line #{lineno}: #{line}")
				IO.puts("Error code #{code}")
			end)

			assert code == :ok
			assert parsed_msg.method == :BYE
			assert parsed_msg.dialog_id == {"8075639", "32645600-4c01-bc8f-670c-deac31158db8", "as424e7930"}

			msg2 = SIPMsg.serialize(parsed_msg)
			# IO.puts("\n")
			# IO.puts(msg2)
			{ code, parsed_msg2 } = SIPMsg.parse(msg2, fn code, errmsg, lineno, line ->
				IO.puts("\n" <> errmsg)
				IO.puts("Offending line #{lineno}: #{line}")
				IO.puts("Error code #{code}")
			end)

			assert code == :ok
			assert parsed_msg2.method == :BYE
			assert parsed_msg2.dialog_id == {"8075639", "32645600-4c01-bc8f-670c-deac31158db8", "as424e7930"}
		end
end
