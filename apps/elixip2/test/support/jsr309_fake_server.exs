defmodule Jsr309FakeServer do
  @moduledoc """
  Scripted fake Mendooze JSR309 HTTP server for tests.

  Handles both faces of the protocol on one port, one process per accepted
  connection:

  - `POST /jsr309` — decodes the XML-RPC methodCall, notifies the test with
    `{:jsr309_call, method, params}`, replies with the envelope built from
    `rpc_handler.(method, params)` (`{:ok, return_val}` or `{:error, msg}`)
  - `GET <path>` — starts a chunked event stream, notifies the test with
    `{:stream_conn, conn_pid, path}`; the connection then obeys
    `{:chunk, data}`, `:finish` and `:abort` messages

  `stop_listening/1` closes the listen socket to simulate a dead server
  (established streams stay up until aborted).
  """

  def start(test_pid, rpc_handler \\ &default_handler/2) do
    {:ok, lsock} =
      :gen_tcp.listen(0, [:binary, packet: :http_bin, active: false, reuseaddr: true])

    {:ok, port} = :inet.port(lsock)
    Task.start_link(fn -> accept_loop(lsock, test_pid, rpc_handler) end)
    %{url: "http://127.0.0.1:#{port}", host: "127.0.0.1", port: port, lsock: lsock}
  end

  def stop_listening(%{lsock: lsock}), do: :gen_tcp.close(lsock)

  def event_frame(param) do
    XMLRPC.encode!(%XMLRPC.MethodResponse{param: param})
  end

  defp default_handler("EventQueueCreate", _), do: {:ok, [7, "/events/jsr309/7"]}
  defp default_handler(_method, _params), do: {:ok, []}

  # ── Connection handling ─────────────────────────────────────────────────────

  defp accept_loop(lsock, test_pid, handler) do
    case :gen_tcp.accept(lsock) do
      {:ok, sock} ->
        pid =
          spawn_link(fn ->
            receive do
              :go -> serve(sock, test_pid, handler)
            end
          end)

        :ok = :gen_tcp.controlling_process(sock, pid)
        send(pid, :go)
        accept_loop(lsock, test_pid, handler)

      {:error, _} ->
        :ok
    end
  end

  defp serve(sock, test_pid, handler) do
    case :gen_tcp.recv(sock, 0) do
      {:ok, {:http_request, :POST, {:abs_path, "/jsr309"}, _}} ->
        len = read_headers(sock, 0)
        :ok = :inet.setopts(sock, packet: :raw)
        {:ok, body} = :gen_tcp.recv(sock, len)
        {:ok, %XMLRPC.MethodCall{method_name: method, params: params}} = XMLRPC.decode(body)
        send(test_pid, {:jsr309_call, method, params})
        :gen_tcp.send(sock, rpc_response(handler.(method, params)))
        :gen_tcp.close(sock)

      {:ok, {:http_request, :GET, {:abs_path, path}, _}} ->
        read_headers(sock, 0)
        :ok = :inet.setopts(sock, packet: :raw)

        :gen_tcp.send(
          sock,
          "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ncontent-type: text/xml\r\n\r\n"
        )

        send(test_pid, {:stream_conn, self(), path})
        stream_commands(sock)

      {:error, _} ->
        :ok
    end
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

  defp rpc_response(result) do
    param =
      case result do
        {:ok, return_val} -> %{"returnCode" => 1, "returnVal" => return_val}
        {:error, msg} -> %{"returnCode" => 0, "errorMsg" => msg}
      end

    body = XMLRPC.encode!(%XMLRPC.MethodResponse{param: param})

    [
      "HTTP/1.1 200 OK\r\ncontent-type: text/xml\r\ncontent-length: ",
      Integer.to_string(IO.iodata_length(body)),
      "\r\nconnection: close\r\n\r\n",
      body
    ]
  end

  defp stream_commands(sock) do
    receive do
      {:chunk, data} ->
        :gen_tcp.send(sock, [Integer.to_string(byte_size(data), 16), "\r\n", data, "\r\n"])
        stream_commands(sock)

      :finish ->
        :gen_tcp.send(sock, "0\r\n\r\n")
        :gen_tcp.close(sock)

      :abort ->
        :gen_tcp.close(sock)
    end
  end
end
