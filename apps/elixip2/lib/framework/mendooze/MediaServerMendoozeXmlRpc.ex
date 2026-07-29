defmodule MediaServer.Mendooze.XmlRpc do
  @moduledoc """
  Thin XML-RPC client for the Mendooze JSR309 control interface.

  Wraps `:httpc` and the `xmlrpc` package, and handles the common JSR309
  response envelope in one place so higher layers never see it:

      success: %{ "returnCode" => 1, "returnVal" => [...] }
      failure: %{ "returnCode" => 0, "errorMsg" => "..." }   (HTTP 200!)

  A real XML-RPC fault (HTTP 500) only occurs on parameter parsing errors.

  `call/4` returns `{:ok, return_val :: list()}` or `{:error, reason}` with:

  - `{:jsr309_error, msg}` — applicative failure (`returnCode` 0)
  - `{:xmlrpc_fault, code, msg}` — XML-RPC fault
  - `{:http_error, status}` — unexpected HTTP status
  - `{:decode_error, reason}` — response body is not valid XML-RPC
  - any `:httpc` error such as `:timeout` or `{:failed_connect, _}`
  """

  require Logger

  @jsr309_path "/jsr309"
  @default_timeout_ms 10_000

  @type base_url :: String.t()
  @type result :: {:ok, [term()]} | {:error, term()}

  @doc """
  Invoke a JSR309 method. `base_url` is e.g. `"http://127.0.0.1:8080"`.

  Parameters are positional (the API does not name them) and must follow the
  server documentation order. Maps encode as XML-RPC structs (e.g. `rtpMap`),
  strings must be UTF-8.

  Options:
  - `:timeout_ms` — request timeout (default: `:xmlrpc_timeout_ms` from the
    `MediaServer.Mendooze` application config, else #{@default_timeout_ms})
  """
  @spec call(base_url(), String.t(), [term()], keyword()) :: result()
  def call(base_url, method, params \\ [], opts \\ []) do
    timeout = Keyword.get(opts, :timeout_ms, config_timeout())
    body = XMLRPC.encode!(%XMLRPC.MethodCall{method_name: method, params: params})
    url = String.to_charlist(base_url <> @jsr309_path)
    http_opts = [timeout: timeout, connect_timeout: timeout]

    case :httpc.request(:post, {url, [], ~c"text/xml", body}, http_opts, body_format: :binary) do
      {:ok, {{_, 200, _}, _headers, resp_body}} ->
        decode_envelope(resp_body, method)

      # xmlrpc-c sends parameter-parsing faults with HTTP 500
      {:ok, {{_, 500, _}, _headers, resp_body}} ->
        decode_fault(resp_body)

      {:ok, {{_, status, _}, _headers, _resp_body}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
    |> log_error(method)
  end

  @doc """
  Extract a created object id from a `call/4` result.

  The server signals a failed creation with a negative id even when
  `returnCode` is 1, so creation calls must go through this check.
  """
  @spec created_id(result()) :: {:ok, non_neg_integer()} | {:error, term()}
  def created_id({:ok, [id | _]}) when is_integer(id) and id >= 0, do: {:ok, id}
  def created_id({:ok, [id | _]}) when is_integer(id), do: {:error, {:create_failed, id}}
  def created_id({:ok, other}), do: {:error, {:unexpected_return, other}}
  def created_id({:error, _} = err), do: err

  # ── Internals ──────────────────────────────────────────────────────────────

  defp decode_envelope(resp_body, method) do
    case XMLRPC.decode(resp_body) do
      {:ok, %XMLRPC.MethodResponse{param: %{"returnCode" => 1, "returnVal" => vals}}}
      when is_list(vals) ->
        {:ok, vals}

      {:ok, %XMLRPC.MethodResponse{param: %{"returnCode" => 0} = param}} ->
        {:error, {:jsr309_error, Map.get(param, "errorMsg", "unknown error")}}

      {:ok, %XMLRPC.MethodResponse{param: param}} ->
        Logger.warning("XmlRpc: #{method}: unexpected response envelope: #{inspect(param)}")
        {:error, {:unexpected_response, param}}

      {:ok, %XMLRPC.Fault{fault_code: code, fault_string: msg}} ->
        {:error, {:xmlrpc_fault, code, msg}}

      {:error, reason} ->
        {:error, {:decode_error, reason}}
    end
  end

  defp decode_fault(resp_body) do
    case XMLRPC.decode(resp_body) do
      {:ok, %XMLRPC.Fault{fault_code: code, fault_string: msg}} ->
        {:error, {:xmlrpc_fault, code, msg}}

      _ ->
        {:error, {:http_error, 500}}
    end
  end

  defp log_error({:error, reason} = err, method) do
    Logger.error("XmlRpc: #{method} failed: #{inspect(reason)}")
    err
  end

  defp log_error(ok, _method), do: ok

  defp config_timeout() do
    Application.get_env(:elixip2, MediaServer.Mendooze, [])
    |> Keyword.get(:xmlrpc_timeout_ms, @default_timeout_ms)
  end
end
