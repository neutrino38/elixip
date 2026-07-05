defmodule Mendooze.XmlRpcTest do
  use ExUnit.Case, async: true

  alias MediaServer.Mendooze.XmlRpc

  @moduledoc """
  Unit tests for the JSR309 XML-RPC client, against a minimal in-test HTTP
  server (:gen_tcp loopback) returning canned responses.
  """

  # ── Minimal fake HTTP server ───────────────────────────────────────────────
  # handler.(method, path, body) -> response iodata | :no_reply (for timeouts)

  defp start_fake_server(handler) do
    test_pid = self()

    {:ok, lsock} =
      :gen_tcp.listen(0, [:binary, packet: :http_bin, active: false, reuseaddr: true])

    {:ok, port} = :inet.port(lsock)
    Task.start_link(fn -> accept_loop(lsock, handler, test_pid) end)
    "http://127.0.0.1:#{port}"
  end

  defp accept_loop(lsock, handler, test_pid) do
    case :gen_tcp.accept(lsock) do
      {:ok, sock} ->
        serve(sock, handler, test_pid)
        accept_loop(lsock, handler, test_pid)

      {:error, _} ->
        :ok
    end
  end

  defp serve(sock, handler, test_pid) do
    {:ok, {:http_request, method, {:abs_path, path}, _version}} = :gen_tcp.recv(sock, 0)
    content_length = read_headers(sock, 0)
    :ok = :inet.setopts(sock, packet: :raw)

    body =
      if content_length > 0 do
        {:ok, data} = :gen_tcp.recv(sock, content_length)
        data
      else
        ""
      end

    send(test_pid, {:fake_server_request, method, path, body})

    case handler.(method, path, body) do
      :no_reply -> Process.sleep(:infinity)
      response -> :gen_tcp.send(sock, response)
    end

    :gen_tcp.close(sock)
  end

  defp read_headers(sock, content_length) do
    case :gen_tcp.recv(sock, 0) do
      {:ok, {:http_header, _, :"Content-Length", _, len}} ->
        read_headers(sock, String.to_integer(to_string(len)))

      {:ok, {:http_header, _, _, _, _}} ->
        read_headers(sock, content_length)

      {:ok, :http_eoh} ->
        content_length
    end
  end

  defp http_response(status_line, body) do
    [
      "HTTP/1.1 ",
      status_line,
      "\r\ncontent-type: text/xml\r\ncontent-length: ",
      Integer.to_string(IO.iodata_length(body)),
      "\r\nconnection: close\r\n\r\n",
      body
    ]
  end

  defp jsr309_ok(return_val) do
    XMLRPC.encode!(%XMLRPC.MethodResponse{
      param: %{"returnCode" => 1, "returnVal" => return_val}
    })
  end

  defp jsr309_error(msg) do
    XMLRPC.encode!(%XMLRPC.MethodResponse{
      param: %{"returnCode" => 0, "errorMsg" => msg}
    })
  end

  # ── Tests ──────────────────────────────────────────────────────────────────

  test "successful call returns the returnVal list" do
    base_url =
      start_fake_server(fn :POST, "/jsr309", _body ->
        http_response("200 OK", jsr309_ok([7, "/events/jsr309/7"]))
      end)

    assert {:ok, [7, "/events/jsr309/7"]} = XmlRpc.call(base_url, "EventQueueCreate")
  end

  test "request is a well-formed XML-RPC methodCall posted to /jsr309" do
    base_url =
      start_fake_server(fn :POST, "/jsr309", _body ->
        http_response("200 OK", jsr309_ok([]))
      end)

    assert {:ok, []} =
             XmlRpc.call(base_url, "PlayerOpen", [3, 1, "/tmp/annonce.mp4"])

    assert_receive {:fake_server_request, :POST, "/jsr309", body}

    assert {:ok, %XMLRPC.MethodCall{method_name: "PlayerOpen", params: params}} =
             XMLRPC.decode(body)

    assert params == [3, 1, "/tmp/annonce.mp4"]
  end

  test "map parameters encode as XML-RPC structs (rtpMap)" do
    base_url =
      start_fake_server(fn :POST, "/jsr309", _body ->
        http_response("200 OK", jsr309_ok([22000]))
      end)

    rtp_map = %{"0" => 0, "8" => 8, "101" => 100}

    assert {:ok, [22000]} =
             XmlRpc.call(base_url, "EndpointStartReceiving", [1, 2, 0, rtp_map])

    assert_receive {:fake_server_request, :POST, "/jsr309", body}
    assert {:ok, %XMLRPC.MethodCall{params: [1, 2, 0, decoded_map]}} = XMLRPC.decode(body)
    assert decoded_map == rtp_map
  end

  test "returnCode 0 with HTTP 200 is an applicative error" do
    base_url =
      start_fake_server(fn :POST, "/jsr309", _body ->
        http_response("200 OK", jsr309_error("no such session"))
      end)

    assert {:error, {:jsr309_error, "no such session"}} =
             XmlRpc.call(base_url, "EndpointCreate", [99, "ep", true, false, false])
  end

  test "XML-RPC fault with HTTP 500 is reported as a fault" do
    fault = XMLRPC.encode!(%XMLRPC.Fault{fault_code: -501, fault_string: "bad params"})

    base_url =
      start_fake_server(fn :POST, "/jsr309", _body ->
        http_response("500 Internal Server Error", fault)
      end)

    assert {:error, {:xmlrpc_fault, -501, "bad params"}} =
             XmlRpc.call(base_url, "MediaSessionCreate", [42])
  end

  test "unexpected HTTP status is reported" do
    base_url =
      start_fake_server(fn :POST, "/jsr309", _body ->
        http_response("404 Not Found", "nope")
      end)

    assert {:error, {:http_error, 404}} = XmlRpc.call(base_url, "EventQueueCreate")
  end

  test "garbled response body is a decode error" do
    base_url =
      start_fake_server(fn :POST, "/jsr309", _body ->
        http_response("200 OK", "this is not xml")
      end)

    assert {:error, {:decode_error, _}} = XmlRpc.call(base_url, "EventQueueCreate")
  end

  test "unexpected envelope shape is reported" do
    body = XMLRPC.encode!(%XMLRPC.MethodResponse{param: %{"foo" => "bar"}})

    base_url =
      start_fake_server(fn :POST, "/jsr309", _body ->
        http_response("200 OK", body)
      end)

    assert {:error, {:unexpected_response, %{"foo" => "bar"}}} =
             XmlRpc.call(base_url, "EventQueueCreate")
  end

  test "silent server triggers a timeout" do
    base_url = start_fake_server(fn :POST, "/jsr309", _body -> :no_reply end)

    assert {:error, :timeout} =
             XmlRpc.call(base_url, "EventQueueCreate", [], timeout_ms: 200)
  end

  test "connection refused is reported" do
    # port 1 is never listening
    assert {:error, {:failed_connect, _}} =
             XmlRpc.call("http://127.0.0.1:1", "EventQueueCreate", [], timeout_ms: 500)
  end

  test "UTF-8 strings survive the round trip" do
    base_url =
      start_fake_server(fn :POST, "/jsr309", _body ->
        http_response("200 OK", jsr309_ok(["éléphant à mémé"]))
      end)

    assert {:ok, ["éléphant à mémé"]} =
             XmlRpc.call(base_url, "MediaSessionCreate", ["appel-téléphonique", 1])

    assert_receive {:fake_server_request, :POST, "/jsr309", body}
    assert {:ok, %XMLRPC.MethodCall{params: ["appel-téléphonique", 1]}} = XMLRPC.decode(body)
  end

  describe "created_id/1" do
    test "accepts a non-negative id" do
      assert {:ok, 0} = XmlRpc.created_id({:ok, [0]})
      assert {:ok, 12} = XmlRpc.created_id({:ok, [12, "extra"]})
    end

    test "rejects a negative id" do
      assert {:error, {:create_failed, -1}} = XmlRpc.created_id({:ok, [-1]})
    end

    test "rejects a non-integer or empty returnVal" do
      assert {:error, {:unexpected_return, []}} = XmlRpc.created_id({:ok, []})
      assert {:error, {:unexpected_return, ["x"]}} = XmlRpc.created_id({:ok, ["x"]})
    end

    test "passes errors through" do
      assert {:error, :timeout} = XmlRpc.created_id({:error, :timeout})
    end
  end
end
