defmodule SIP.Test.FileTransfer do
  @moduledoc """
  Chat attachments (docs/design/chat-media-plan.md, S1): the RCS `fthttp` XML
  read and written, found in a MESSAGE however a client wraps it, and the
  upload against a store that behaves as the reference server does — read in
  its code (DESIGN-CHAT-MEDIA §2.8), simulated here as a `Req` adapter.

  The `:live` test runs the same upload against a real store:
  `FHFT_URL` (default: the rehearsal of packaging/fhft/rehearsal/).
  """
  use ExUnit.Case, async: true

  alias SIP.FileTransfer
  alias SIP.FileTransfer.Info

  # What the rehearsal's PHP answered on 2026-10-07, byte for byte.
  @server_xml ~s(<?xml version="1.0" encoding="UTF-8"?>\n) <>
                ~s(<file xmlns="urn:gsma:params:xml:ns:rcs:rcs:fthttp"><file-info type="file">) <>
                ~s(<file-size>3000</file-size><file-name>photo.jpg</file-name>) <>
                ~s(<content-type>image/jpeg</content-type>) <>
                ~s(<data url="http://localhost:8089/files/tmp/6ac665a6c7175_51cfe9c75571d3803c98.jpg" ) <>
                ~s(until="2026-10-14T15:30:46Z"/></file-info></file>\n)

  @voice_xml """
  <?xml version="1.0" encoding="UTF-8"?>\r
  <file xmlns="urn:gsma:params:xml:ns:rcs:rcs:fthttp" xmlns:am="urn:gsma:params:xml:ns:rcs:rcs:rram">\r
  <file-info type="thumbnail">\r
  <file-size>120</file-size>\r
  <data url="https://files.example.com/files/tmp/thumb.jpg" until="2026-10-09T10:21:45Z"/>\r
  </file-info>\r
  <file-info type="file">\r
  <file-size>18432</file-size>\r
  <file-name>vocal_2026-10-02-10-21-45.mka</file-name>\r
  <content-type>audio/wav;voice-recording=yes</content-type>\r
  <am:playing-length>4320</am:playing-length>\r
  <file-key>ignored</file-key>\r
  <data url="https://files.example.com/files/tmp/68de1c2a_9f3a.mka" until="2026-10-09T10:21:45Z"/>\r
  </file-info>\r
  </file>\r
  """

  describe "parse/1" do
    test "the reference server's XML" do
      assert {:ok, %Info{} = info} = FileTransfer.parse(@server_xml)
      assert info.url =~ "/files/tmp/6ac665a6c7175_51cfe9c75571d3803c98.jpg"
      assert info.until == "2026-10-14T15:30:46Z"
      assert {info.name, info.size, info.content_type} == {"photo.jpg", 3000, "image/jpeg"}
      refute FileTransfer.voice_message?(info)
    end

    test "a voice message: the file, not the thumbnail; the length in milliseconds" do
      assert {:ok, info} = FileTransfer.parse(@voice_xml)
      assert info.url =~ "68de1c2a_9f3a.mka"
      assert info.playing_length == 4320
      assert info.size == 18432
      assert FileTransfer.voice_message?(info)
    end

    test "the name is percent-decoded" do
      xml =
        String.replace(
          @server_xml,
          "photo.jpg</file-name>",
          "IMG%200042%20%C3%A9t%C3%A9.jpg</file-name>"
        )

      assert {:ok, %Info{name: "IMG 0042 été.jpg"}} = FileTransfer.parse(xml)
    end

    test "refused without raising: no file, no url, a doctype, junk" do
      assert {:error, :no_file_info} =
               FileTransfer.parse(
                 String.replace(@server_xml, ~s(type="file"), ~s(type="thumbnail"))
               )

      assert {:error, :no_url} =
               FileTransfer.parse(String.replace(@server_xml, ~s(url="), ~s(href=")))

      assert {:error, :doctype_not_allowed} =
               FileTransfer.parse(
                 ~s(<?xml version="1.0"?><!DOCTYPE file [<!ENTITY x "y">]><file/>)
               )

      assert {:error, {:malformed_xml, _}} = FileTransfer.parse("<file><file-info>")
    end
  end

  describe "serialize/1" do
    test "Linphone's shape, and it reads back to the same file" do
      {:ok, info} = FileTransfer.parse(@voice_xml)
      xml = FileTransfer.serialize(%{info | name: "vocal 1.mka"})

      assert xml =~ ~s(xmlns:am="urn:gsma:params:xml:ns:rcs:rcs:rram")
      assert xml =~ "<file-name>vocal%201.mka</file-name>\r\n"
      assert xml =~ "<am:playing-length>4320</am:playing-length>"
      assert String.ends_with?(xml, "</file>\r\n")
      assert FileTransfer.parse(xml) == {:ok, %{info | name: "vocal 1.mka"}}
    end
  end

  describe "SIP.Msg.Ops.file_transfer_xml/1" do
    @ft "application/vnd.gsma.rcs-ft-http+xml"

    defp cpim(type, content) do
      "From: <sip:alice@unit.test>\r\nTo: <sip:bob@unit.test>\r\n" <>
        "NS: imdn <urn:ietf:params:imdn>\r\nimdn.Message-ID: 7Kq2\r\n\r\n" <>
        "Content-Type: #{type}\r\n\r\n" <> content
    end

    test "bare, in CPIM, beside a caption, beside a caption in CPIM" do
      assert SIP.Msg.Ops.file_transfer_xml(%{contenttype: @ft, body: @server_xml}) == @server_xml

      assert SIP.Msg.Ops.file_transfer_xml(%{
               contenttype: "message/cpim",
               body: cpim(@ft, @server_xml)
             }) ==
               @server_xml

      parts = [
        %{contenttype: @ft, data: @server_xml, boundary: "b1"},
        %{contenttype: "text/plain;charset=UTF-8", data: "la terrasse", boundary: "b1"}
      ]

      assert SIP.Msg.Ops.file_transfer_xml(%{
               contenttype: "multipart/mixed;boundary=b1",
               body: parts
             }) ==
               @server_xml

      inner = SIPMsg.multipart_body(parts)
      cpim_multi = cpim("multipart/mixed;boundary=b1", inner)

      assert SIP.Msg.Ops.file_transfer_xml(%{contenttype: "message/cpim", body: cpim_multi}) ==
               @server_xml
    end

    test "a text names no file" do
      assert SIP.Msg.Ops.file_transfer_xml(%{contenttype: "text/plain", body: "bonjour"}) == nil

      assert SIP.Msg.Ops.file_transfer_xml(%{
               contenttype: "message/cpim",
               body: cpim("text/plain", "bonjour")
             }) == nil
    end
  end

  # ── The upload, against the reference server's behaviour ────────────────────

  defmodule PhpStore do
    @moduledoc """
    flexisip-http-file-transfer-server 524ab71, as hft.php and common.php do it:
    every request challenged when digest is on, MD5 alone offered (the rows of
    AUTH_QUERY), an authenticated POST without a file answered 400. A `Req`
    adapter, run in the caller's process: the test it reports to and whether
    digest is on are read from that process's dictionary.
    """

    @realm "unit.test"
    @nonce "ae526c5c0a63c7a09a756166b922837adbbf43d99db562b9f1dfca4aae6f91e6"

    def nonce, do: @nonce

    def setup(digest? \\ true), do: Process.put(__MODULE__, {self(), digest?})

    def run(request) do
      {test, digest?} = Process.get(__MODULE__)
      ha1 = SIP.Auth.compute_ha1(:md5, "alice", @realm, "secret")
      auth = Req.Request.get_header(request, "authorization")
      type = Req.Request.get_header(request, "content-type")
      file? = Enum.any?(type, &String.starts_with?(&1, "multipart/form-data"))

      send(
        test,
        {:store_got, %{auth: auth, file?: file?, from: Req.Request.get_header(request, "from")}}
      )

      response =
        cond do
          digest? and not valid?(auth, ha1, request.url.path) ->
            Req.Response.new(status: 401)
            |> Req.Response.put_header(
              "www-authenticate",
              ~s(Digest realm="#{@realm}",qop="auth",algorithm=MD5,nonce="#{@nonce}",opaque="#{md5(@realm)}")
            )

          not file? and digest? ->
            Req.Response.new(status: 400)

          not file? ->
            Req.Response.new(status: 204)

          true ->
            Req.Response.new(status: 200, body: SIP.Test.FileTransfer.server_xml())
        end

      {request, response}
    end

    defp valid?([value], ha1, path) do
      {:ok, p} = SIPMsg.parse_challenge(value)

      p["uri"] == path and p["realm"] == @realm and p["nonce"] == @nonce and
        p["opaque"] == md5(@realm) and
        SIP.Auth.expected_response_from_ha1(:md5, ha1, "POST", p) == p["response"]
    end

    defp valid?(_none, _ha1, _path), do: false

    defp md5(s), do: :crypto.hash(:md5, s) |> Base.encode16(case: :lower)
  end

  def server_xml, do: @server_xml

  @realm "unit.test"
  @file_ %{name: "photo.jpg", content_type: "image/jpeg", data: :binary.copy(<<0xFF>>, 3000)}
  @url "https://files.unit.test/files/hft.php"

  test "with digest: the challenge learnt on the empty POST, answered on the file POST" do
    PhpStore.setup()
    creds = %{from: "sip:alice@unit.test", username: "alice", passwd: "secret"}

    assert {:ok, info} = FileTransfer.upload(@url, @file_, creds, adapter: PhpStore)
    assert info.url =~ "/files/tmp/"
    assert {info.name, info.content_type} == {"photo.jpg", "image/jpeg"}

    assert_received {:store_got, %{auth: [], file?: false, from: ["sip:alice@unit.test"]}}
    assert_received {:store_got, %{auth: [_digest], file?: true}}
    refute_received {:store_got, _third}
  end

  test "an HA1 computed with the SIP domain answers as the password does" do
    PhpStore.setup()

    creds = %{
      from: "sip:alice@unit.test",
      username: "alice",
      ha1: SIP.Auth.compute_ha1(:md5, "alice", @realm, "secret")
    }

    assert {:ok, _info} = FileTransfer.upload(@url, @file_, creds, adapter: PhpStore)
  end

  test "a wrong password: 401 after the second try, and no more" do
    PhpStore.setup()
    creds = %{from: "sip:alice@unit.test", username: "alice", passwd: "wrong"}

    assert FileTransfer.upload(@url, @file_, creds, adapter: PhpStore) == {:error, {:http, 401}}
    assert_received {:store_got, %{file?: false}}
    assert_received {:store_got, %{file?: true}}
    assert_received {:store_got, %{file?: true}}
    refute_received {:store_got, _fourth}
  end

  test "without digest: 204, then the file with no Authorization" do
    PhpStore.setup(false)
    creds = %{from: "sip:alice@unit.test", username: "alice", passwd: "secret"}

    assert {:ok, _info} =
             FileTransfer.upload(@url, @file_, creds, adapter: PhpStore)

    assert_received {:store_got, %{auth: [], file?: false}}
    assert_received {:store_got, %{auth: [], file?: true}}
  end

  @tag :live
  test "against a real store: upload, then download the same octets" do
    url = System.get_env("FHFT_URL", "http://localhost:8089/files/hft.php")
    creds = %{from: "sip:alice@unit.test", username: "alice", passwd: "secret"}
    data = :crypto.strong_rand_bytes(2048)
    file = %{name: "live.jpg", content_type: "image/jpeg", data: data}

    assert {:ok, info} = FileTransfer.upload(url, file, creds)
    assert info.size == 2048
    assert FileTransfer.download(info, []) == {:ok, data}
  end
end
