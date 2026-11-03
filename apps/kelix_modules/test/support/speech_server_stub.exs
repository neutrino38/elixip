defmodule Kelix.Test.SpeechServerStub do
  @moduledoc """
  The control API of a speech-server, as far as `POST /control/token` goes: a Plug
  under Bandit on a free loopback port.

  What it answers is set per test with `answer/2` — `{status, json_body}`, with
  an optional delay — and every request it receives is sent to the test process
  that started it as `{:speech_token_request, decoded_json}`.
  """
  @behaviour Plug

  import Plug.Conn

  @doc """
  Start a stub answering `answer` (`{201, %{…}}` by default: a fresh token).
  Returns `%{url: "http://127.0.0.1:<port>", pid: pid}`.
  """
  def start(answer \\ :token) do
    test = self()
    {:ok, agent} = Agent.start_link(fn -> %{test: test, answer: answer} end)

    {:ok, pid} =
      Bandit.start_link(plug: {__MODULE__, agent}, ip: :loopback, port: 0, startup_log: false)

    {:ok, {_ip, port}} = ThousandIsland.listener_info(pid)
    %{url: "http://127.0.0.1:#{port}", pid: pid, agent: agent}
  end

  @doc """
  What the stub answers from now on: `:token`, `{status, body_map}`,
  `{:raw, status, binary}` or `{:delay, ms, answer}`.
  """
  def answer(%{agent: agent}, answer), do: Agent.update(agent, &%{&1 | answer: answer})

  @doc "A token of the shape the real server mints: 43 base64url characters."
  def token(), do: :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

  @impl Plug
  def init(agent), do: agent

  @impl Plug
  def call(%{method: "POST", request_path: "/control/token"} = conn, agent) do
    {:ok, raw, conn} = read_body(conn)
    %{test: test, answer: answer} = Agent.get(agent, & &1)
    request = Jason.decode!(raw)
    send(test, {:speech_token_request, request})
    respond(conn, answer, request)
  end

  def call(conn, _agent), do: send_resp(conn, 404, ~s({"error":"not found"}))

  defp respond(conn, {:delay, ms, answer}, request) do
    Process.sleep(ms)
    respond(conn, answer, request)
  end

  defp respond(conn, :token, request) do
    body = %{
      "token" => token(),
      "function" => "comp",
      "account" => request["account"] || "-",
      "expiresAt" => "2026-10-14T15:04:05Z"
    }

    json(conn, 201, body)
  end

  defp respond(conn, {:raw, status, binary}, _request) do
    conn |> put_resp_content_type("application/json") |> send_resp(status, binary)
  end

  defp respond(conn, {status, body}, _request), do: json(conn, status, body)

  defp json(conn, status, body) do
    conn |> put_resp_content_type("application/json") |> send_resp(status, Jason.encode!(body))
  end
end
