defmodule Kelix.Mod.Mcu.XmlRpc do
  @moduledoc """
  XML-RPC transport for the Medooze **MCU** control interface
  (`POST /mcu`, design `docs/design/DESIGN-MCU.md`).

  A different endpoint from the JSR-309 one driven by `MediaServer.Mendooze`
  (`/jsr309`): the two are disjoint object models on the same daemon, so this is a
  separate client rather than a flag on that one — and it keeps the module
  self-contained, which is what lets `kelixip-mod-mcu` ship without pulling the
  JSR-309 adapter in.

  The response envelope is shared with JSR-309 and handled here once:

      success  →  %{"returnCode" => 1, "returnVal" => [ … ]}
      error    →  %{"returnCode" => 0, "errorMsg" => "…"}   (HTTP 200!)

  An HTTP `200` carrying `returnCode: 0` is an **application error**, not a
  transport one — only a parameter-parsing failure produces a real XML-RPC fault
  (HTTP 500). `call/4` therefore returns:

  - `{:mcu_error, msg}` — applicative failure (`returnCode` 0)
  - `{:xmlrpc_fault, code, msg}` — parameter parsing refused
  - `{:http_error, status}` — unexpected status
  - `{:decode_error, reason}` — the body is not valid XML-RPC
  - any `:httpc` reason (`:timeout`, `{:failed_connect, _}`) — the MCU is
    unreachable, which is what `Kelix.Mod.Mcu.Client` turns into a `down` entry.
  """

  require Logger

  @mcu_path "/mcu"
  @default_timeout_ms 10_000
  # A profile of our own rather than httpc's default one, because the family
  # option below is set per profile and would otherwise be a node-wide change
  # made from inside a loadable module.
  @httpc_profile :kelix_mcu_rpc

  @type result :: {:ok, [term()]} | {:error, term()}

  @doc """
  The options every MCU `:httpc` profile carries — this one and the event
  queue's long-poll profile.

  `ipfamily` is the reason this is stated once. It defaults to `:inet`, so a
  `base_url` naming an IPv6 literal fails on `{:failed_connect, …, :nxdomain}`
  before a single byte leaves the node: httpc hands the bracketed host to
  `:gen_tcp.connect/3` with an IPv4-only family. `:inet6fb4` tries IPv6 then
  falls back to IPv4, which serves an address literal of either family and a
  hostname that resolves to both (measured).

  The mediaserver's control interface listens on one dual-family socket
  (`mcu/src/xmlrpcserver.cpp`), so what remains to be chosen is on this side.
  """
  @spec profile_options() :: keyword()
  def profile_options(), do: [max_sessions: 100, ipfamily: :inet6fb4]

  @doc """
  Start this module's `:httpc` profile, or re-apply its options if it is up.

  Called by `Kelix.Mod.Mcu.Client` before its first RPC: a profile that is not
  started makes `:httpc.request/5` exit.
  """
  @spec ensure_profile() :: :ok
  def ensure_profile() do
    :inets.start(:httpc, [{:profile, @httpc_profile}])
    :httpc.set_options(profile_options(), @httpc_profile)
  end

  @doc """
  Invoke an MCU method. `base_url` is e.g. `"http://10.0.0.12:8080"`, or
  `"http://[fd00::12]:8080"` for a server reached over IPv6 — an address literal
  goes in brackets, as any HTTP URL (RFC 3986 §3.2.2).

  Parameters are positional and must follow the order documented in §3.2-3.5.
  Maps encode as XML-RPC structs (`rtpMap`, `SetRTPProperties` props).

  Options: `:timeout_ms` (default #{@default_timeout_ms}).
  """
  @spec call(String.t(), String.t(), [term()], keyword) :: result
  def call(base_url, method, params \\ [], opts \\ []) do
    timeout = Keyword.get(opts, :timeout_ms, @default_timeout_ms)
    body = XMLRPC.encode!(%XMLRPC.MethodCall{method_name: method, params: params})
    url = String.to_charlist(base_url <> @mcu_path)
    http_opts = [timeout: timeout, connect_timeout: timeout]

    case :httpc.request(
           :post,
           {url, [], ~c"text/xml", body},
           http_opts,
           [body_format: :binary],
           @httpc_profile
         ) do
      {:ok, {{_, 200, _}, _headers, resp_body}} ->
        decode_envelope(resp_body, method)

      # xmlrpc-c reports parameter-parsing faults with HTTP 500
      {:ok, {{_, 500, _}, _headers, resp_body}} ->
        decode_fault(resp_body)

      {:ok, {{_, status, _}, _headers, _resp_body}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Extract a created object id (conference, participant) from a `call/4` result.

  The server signals a failed creation with a **negative id** even when
  `returnCode` is 1, so every creation goes through this check.
  """
  @spec created_id(result) :: {:ok, non_neg_integer} | {:error, term}
  def created_id({:ok, [id | _]}) when is_integer(id) and id >= 0, do: {:ok, id}
  def created_id({:ok, [id | _]}) when is_integer(id), do: {:error, {:create_failed, id}}
  def created_id({:ok, other}), do: {:error, {:unexpected_return, other}}
  def created_id({:error, _} = err), do: err

  # ── internals ────────────────────────────────────────────────────────────────

  defp decode_envelope(resp_body, method) do
    case XMLRPC.decode(resp_body) do
      {:ok, %XMLRPC.MethodResponse{param: %{"returnCode" => 1, "returnVal" => vals}}}
      when is_list(vals) ->
        {:ok, vals}

      # a void method may answer with the code alone
      {:ok, %XMLRPC.MethodResponse{param: %{"returnCode" => 1}}} ->
        {:ok, []}

      {:ok, %XMLRPC.MethodResponse{param: %{"returnCode" => 0} = param}} ->
        {:error, {:mcu_error, Map.get(param, "errorMsg", "unknown error")}}

      {:ok, %XMLRPC.MethodResponse{param: param}} ->
        Logger.warning("Mcu.XmlRpc: #{method}: unexpected envelope: #{inspect(param)}")
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
end
